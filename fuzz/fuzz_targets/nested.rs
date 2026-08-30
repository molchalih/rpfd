//! `Archive::open_nested` driven down an arbitrary chain of payloads, as far
//! as the archive claims it goes.
//!
//! Nesting is the one structure an input chooses the *depth* of, and depth is
//! what turns a bounded walk into a stack overflow. [`MAX_DEPTH`] is the
//! answer, so this asserts it from the outside: the walk never descends past
//! it, and the step that would is refused as [`Error::TooDeep`] rather than as
//! whatever the payload happens to be.
//!
//! The bound is checked against [`nested_to_the_bound`], once per process,
//! because a generated input cannot reach it: `-max_len` defaults to 4096
//! bytes with no corpus to raise it, and 4096 bytes cannot carry a chain
//! deeper than seven. See [`nested_to_the_bound`]. Every input after that
//! walks its own bytes.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rpf_core::{Archive, Error, MAX_DEPTH};
use rpf_fuzz::{MAX_INPUT, bounded, nested_to_the_bound, watched};
use std::io::{Cursor, Read, Seek};
use std::sync::OnceLock;

/// Where to start looking at each level, and the archive to descend.
#[derive(Debug, Arbitrary)]
struct Input<'a> {
    /// One entry index per level, taken modulo the entry count so that a
    /// mutation of any byte still lands on an entry rather than on nothing.
    steps: Vec<u32>,
    data: &'a [u8],
}

/// The most entries one level is probed for a nested archive.
///
/// The walk starts where the input points and takes the first entry from
/// there that nests, because an index chosen at random is a directory or a
/// payload that is not an archive nearly every time, and a walk that gave up
/// on the first of those would never reach a second level at all. Bounded
/// because probing every entry of a four-thousand-entry table, per level,
/// would be the whole cost of the target.
const PROBE_LIMIT: u32 = 64;

fuzz_target!(|input: Input| {
    // `steps` is input as much as `data` is, and one `u32` of it is four bytes
    // the decoder allocated. `MAX_INPUT`.
    if input.steps.len().saturating_mul(size_of::<u32>()) > MAX_INPUT {
        return;
    }

    // Once per process, outside the watched region. The chain exists so the
    // depth bound is checked without anyone having to pass `-max_len`, and
    // checking it costs 12 µs — worth paying to settle the question, not worth
    // paying again on every input to re-settle it. The descent through it is
    // the same one every time regardless of `steps`, because `probe` finds the
    // one entry that nests whatever it is pointed at first.
    static CHECKED: OnceLock<()> = OnceLock::new();
    CHECKED.get_or_init(|| descend(nested_to_the_bound(), &input.steps));

    watched(|| {
        if let Some(data) = bounded(input.data) {
            descend(data, &input.steps);
        }
    });
});

/// Walks `data` one level at a time, checking the bound at each.
fn descend(data: &[u8], steps: &[u32]) {
    let mut src = Cursor::new(data);
    let Ok(mut archive) = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()) else {
        return;
    };

    // One iteration per level, one more than the bound accepts.
    for depth in 0..=MAX_DEPTH {
        let count = u32::try_from(archive.entries().len()).unwrap_or(u32::MAX);
        if count == 0 {
            return;
        }
        let start = steps.get(depth as usize).copied().unwrap_or(0);

        // The bound is on the descent, not on the payload: at the deepest
        // level the archive is allowed to reach, an entry that has a payload
        // at all is refused for the depth and for nothing else.
        if depth == MAX_DEPTH {
            let Some(index) = probe(count, start, |at| archive.payload_at(at).is_ok()) else {
                return;
            };
            let refused = archive.open_nested(&mut src, index);
            assert!(
                matches!(refused, Err(Error::TooDeep { .. })),
                "at depth {depth} the next level answered {refused:?}, not TooDeep"
            );
            return;
        }

        let Some(index) = probe(count, start, |at| archive.open_nested(&mut src, at).is_ok())
        else {
            return;
        };
        let Ok(nested) = archive.open_nested(&mut src, index) else {
            return;
        };
        read_everything(&nested, &mut src);
        archive = nested;
    }
}

/// The first entry from `start` that `wanted` accepts, wrapping.
///
/// Reduced before the offset is added rather than after, and added in `u64`,
/// so the scan really is the distinct run of indices it reads as: `start`
/// wrapping first gives `0, 0, 1` for three entries starting at `u32::MAX`,
/// which never looks at entry 2 — and if entry 2 is the only one that nests,
/// that input never descends at all.
fn probe(count: u32, start: u32, mut wanted: impl FnMut(u32) -> bool) -> Option<u32> {
    let span = u64::from(count);
    (0..count.min(PROBE_LIMIT))
        .map(|offset| u32::try_from((u64::from(start) + u64::from(offset)) % span).unwrap_or(0))
        .find(|at| wanted(*at))
}

/// Everything a parsed archive answers, at the depth it was reached at.
///
/// A bound on descent is worth nothing if what it descends into goes unread.
fn read_everything<R: Read + Seek>(archive: &Archive, src: &mut R) {
    let _ = archive.check_names();
    let _ = archive.payload_extents();
    let count = u32::try_from(archive.entries().len()).unwrap_or(u32::MAX);
    for at in 0..count {
        let _ = archive.entry(at);
        let _ = archive.path(at);
        let _ = archive.payload_at(at);
        let _ = archive.payload_is_resource(src, at);
    }
}
