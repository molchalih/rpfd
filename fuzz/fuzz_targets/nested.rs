//! `Archive::open_nested` driven down an arbitrary chain of payloads, as far
//! as the archive claims it goes.
//!
//! Nesting is the one structure an input chooses the depth of, and depth turns
//! a bounded walk into a stack overflow: the step past [`MAX_DEPTH`] must be
//! refused as [`Error::TooDeep`] and not as whatever the payload happens to be.
//!
//! A generated input cannot reach the bound, so it is checked once per process
//! against [`nested_to_the_bound`]; every input after that walks its own bytes.

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
/// The walk takes the first entry from where the input points that nests,
/// since a random index is nearly always a directory or a non-archive payload.
/// Bounded because probing a whole table per level would be the target's cost.
const PROBE_LIMIT: u32 = 64;

fuzz_target!(|input: Input| {
    // `steps` is input as much as `data` is, and one `u32` of it is four bytes
    // the decoder allocated.
    if input.steps.len().saturating_mul(size_of::<u32>()) > MAX_INPUT {
        return;
    }

    // Once per process, outside the watched region: the descent through the
    // chain is the same every time regardless of `steps`, because `probe` finds
    // the one entry that nests whatever it is pointed at first.
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
        // level, an entry with a payload at all is refused for the depth and
        // for nothing else.
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
/// so the scan really is the distinct run of indices it reads as: wrapping
/// `start` first gives `0, 0, 1` for three entries starting at `u32::MAX`.
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
