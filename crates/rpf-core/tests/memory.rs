//! R4.13: what a cascading rebuild holds at once.
//!
//! The claim this file exists to keep honest is a **memory** claim, so it is
//! measured rather than asserted. The measurement is peak **live heap bytes**,
//! counted by a global allocator installed for this test binary alone: every
//! `alloc` adds its layout size to a running total and every `dealloc` takes it
//! away, and the high-water mark of that total is what the arms below compare.
//! It is not resident set size — pages the allocator has returned to the
//! process but not to the operating system still count as resident and do not
//! count here — but it is the number the change is about: how many bytes this
//! crate is holding when the rebuild is at its widest.
//!
//! One `#[test]` in the binary on purpose. The counter is process-global, and a
//! second test running beside it would be measured into the first.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test code; a panic is the reporting mechanism. \
              docs/conventions.md §15"
)]
#![allow(
    unsafe_code,
    reason = "a global allocator cannot be written in safe Rust: GlobalAlloc is \
              an unsafe trait and its methods hand out raw pointers. \
              docs/conventions.md §11"
)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    collections::BTreeMap,
    fs,
    io::{Cursor, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use rpf_core::{Archive, FileKind, FileSpec, Scratch, Storage, Unwatched, Version};

/// Live heap bytes, as the counting allocator sees them.
static LIVE: AtomicUsize = AtomicUsize::new(0);
/// The highest value [`LIVE`] has reached since it was last reset.
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// The system allocator with a running total attached.
struct Counting;

// SAFETY: every method forwards to `System`, which is a correct allocator, and
// adds only atomic bookkeeping around it. No pointer is dereferenced, retained
// or derived here, and the layout handed to `dealloc` is the one the caller
// gives, unchanged. `realloc` and `alloc_zeroed` are left as the trait's
// defaults, which are defined in terms of `alloc` and `dealloc`, so they are
// counted by the two below rather than separately. docs/conventions.md §11.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// One stored file.
fn stored(path: &str) -> FileSpec {
    FileSpec {
        path: path.to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Stored,
            encryption: 0,
        },
    }
}

/// How big each entry of the nested archive is.
///
/// Small, and deliberately so: the term being measured is the **ancestor**, not
/// the largest entry. A rebuild reads one entry at a time whatever else it
/// does, so an ancestor made of one huge entry would measure that instead and
/// the arms would not separate.
const ENTRY_LEN: usize = 64 * 1024;

/// An outer archive holding a nested one of `entries` files, and the length of
/// that nested archive.
///
/// The nested archive is stored rather than deflated, so its length in the
/// outer archive is its own.
fn nested(dir: &Path, entries: usize) -> (PathBuf, u64) {
    let inner_path = dir.join(format!("inner-{entries}.rpf"));
    let mut inner_specs: Vec<FileSpec> = (0..entries)
        .map(|index| stored(&format!("bulk/e{index:04}.bin")))
        .collect();
    inner_specs.push(stored("edit.txt"));

    let mut inner = fs::File::create(&inner_path).expect("creatable");
    rpf_core::build(
        &mut inner,
        Version::Rpf7,
        &inner_specs,
        &[],
        |wanted| {
            Ok(Cursor::new(if wanted == "edit.txt" {
                b"before".to_vec()
            } else {
                vec![0x5A_u8; ENTRY_LEN]
            }))
        },
        &mut Unwatched,
    )
    .expect("inner builds");
    inner.flush().expect("flushed");
    drop(inner);

    let inner_len = fs::metadata(&inner_path).expect("stat").len();

    let outer_path = dir.join(format!("outer-{entries}.rpf"));
    let outer_specs = [stored("x64/inner.rpf"), stored("note.txt")];
    let mut outer = fs::File::create(&outer_path).expect("creatable");
    rpf_core::build(
        &mut outer,
        Version::Rpf7,
        &outer_specs,
        &[],
        |wanted| {
            Ok(if wanted == "note.txt" {
                Box::new(Cursor::new(b"a note".to_vec())) as Box<dyn rpf_core::Payload>
            } else {
                Box::new(fs::File::open(&inner_path).expect("inner readable"))
            })
        },
        &mut Unwatched,
    )
    .expect("outer builds");
    outer.flush().expect("flushed");
    drop(outer);

    (outer_path, inner_len)
}

/// Scratch space in a directory, as `rpf`'s own frontends supply it.
///
/// The library's seam, taken here rather than trusted: what the command line
/// and the daemon hand `replace_many` is a `tempfile_in`, and this is the same
/// thing said in a test.
struct OnDisk {
    directory: PathBuf,
}

impl Scratch for OnDisk {
    type Sink = fs::File;

    fn create(&mut self) -> rpf_core::Result<fs::File> {
        tempfile::tempfile_in(&self.directory)
            .map_err(|source| rpf_core::Error::Io { offset: 0, source })
    }
}

/// Runs one cascading rebuild of `outer` and answers the peak live heap bytes
/// it added over what was live when it started.
fn cascade<S: Scratch>(outer: &Path, into: &Path, scratch: &mut S) -> usize {
    let mut src = fs::File::open(outer).expect("opens");
    let archive = Archive::open(&mut src).expect("parses");
    let edits = BTreeMap::from([(
        "x64/inner.rpf/edit.txt".to_owned(),
        b"after, and longer than before".to_vec(),
    )]);
    let mut out = fs::File::create(into).expect("creatable");

    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);

    rpf_core::rewrite(
        &mut src,
        &archive,
        &rpf_core::Changes::writing(edits),
        &mut out,
        scratch,
        &mut Unwatched,
    )
    .expect("cascading rebuild");

    let peak = PEAK.load(Ordering::Relaxed);
    out.flush().expect("flushed");
    peak.saturating_sub(baseline)
}

/// R4.13: the peak of a cascading rebuild does not scale with the ancestor it
/// rebuilds on the way, when the ancestor goes to scratch space.
///
/// Two arms, and the second is not decoration. A test that only showed the
/// file-backed arm staying flat would pass just as well if the measurement were
/// broken, so the in-memory arm — which is the same rebuild, holding the
/// ancestor exactly as this used to — is asserted to grow **with** it. One
/// arm proves the instrument, the other proves the change.
#[test]
fn a_cascading_rebuild_does_not_hold_the_ancestor_it_rebuilt() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut on_disk = OnDisk {
        directory: dir.path().to_path_buf(),
    };

    let (small, small_len) = nested(dir.path(), 32);
    let (large, large_len) = nested(dir.path(), 128);
    let ancestor_growth = large_len - small_len;

    // Once through first, so that anything allocated lazily on the way is
    // already there when the arms are measured.
    let _ = cascade(&small, &dir.path().join("warm.rpf"), &mut on_disk);

    let held_small = cascade(
        &small,
        &dir.path().join("held-small.rpf"),
        &mut rpf_core::InMemory,
    );
    let held_large = cascade(
        &large,
        &dir.path().join("held-large.rpf"),
        &mut rpf_core::InMemory,
    );
    let held = held_large.saturating_sub(held_small);

    let streamed_small = cascade(&small, &dir.path().join("small.rpf"), &mut on_disk);
    let streamed_large = cascade(&large, &dir.path().join("large.rpf"), &mut on_disk);
    let streamed = streamed_large.saturating_sub(streamed_small);

    eprintln!(
        "ancestor {small_len} -> {large_len} (+{ancestor_growth}); \
         peak live heap held in memory {held_small} -> {held_large} (+{held}), \
         streamed to scratch {streamed_small} -> {streamed_large} (+{streamed})"
    );

    // The instrument. An in-memory cascade holds the ancestor, so its peak has
    // to grow by at least the ancestor did; if this fails, nothing below is
    // measuring anything.
    assert!(
        u64::try_from(held).unwrap_or(0) >= ancestor_growth,
        "an in-memory cascade grew by only {held} for an ancestor {ancestor_growth} larger, \
         so the measurement is not seeing the ancestor at all"
    );

    // The claim. An eighth of the ancestor's growth is a wide margin on
    // purpose: what must not happen is the peak tracking the ancestor, and a
    // rebuild that holds it whole grows by the whole of it.
    assert!(
        u64::try_from(streamed).unwrap_or(u64::MAX) < ancestor_growth / 8,
        "peak grew by {streamed} bytes for an ancestor {ancestor_growth} bytes larger"
    );
}
