//! What a walk over a whole archive holds at once, measured as peak live heap
//! bytes by a counting global allocator installed for this test binary alone.
//!
//! One `#[test]` in the binary on purpose: the counter is process-global, and a
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

use rpf_core::{
    Archive, FileKind, FileSpec, Manifest, Scratch, Storage, Unwatched, Verified, Version,
};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;

// SAFETY: every method forwards to `System` and adds only atomic bookkeeping;
// no pointer is dereferenced or retained, and `dealloc` gets the caller's
// layout unchanged.
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

fn stored(path: &str) -> FileSpec {
    FileSpec {
        path: path.to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Stored,
            encryption: 0,
        },
    }
}

/// How big each entry of the nested archive is: small, so that the arm measures
/// the ancestor rather than the largest single entry.
const ENTRY_LEN: usize = 64 * 1024;

/// An outer archive holding a nested one of `entries` files, and the length of
/// that nested archive, which is stored rather than deflated so its length in
/// the outer archive is its own.
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
        |wanted: &str| {
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
        |wanted: &str| {
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

fn cascade<S: Scratch>(outer: &Path, into: &Path, scratch: &mut S) -> usize {
    let mut src = fs::File::open(outer).expect("opens");
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
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

const SMALL_PAYLOAD: usize = 2 * 1024 * 1024;
/// The larger, four times [`SMALL_PAYLOAD`].
const LARGE_PAYLOAD: usize = 8 * 1024 * 1024;

fn carrying(len: usize) -> rpf_core::Changes {
    rpf_core::Changes::one(
        "x64/inner.rpf/edit.txt",
        rpf_core::Change::Write {
            contents: std::sync::Arc::new(rpf_core::Bytes::new(vec![0x33_u8; len])),
            create: false,
            allow_encoding_change: false,
        },
    )
}

/// The change is built before the baseline is taken, so what is measured is
/// what the rebuild adds to the payload the caller already holds.
fn carried<S: Scratch>(outer: &Path, into: &Path, len: usize, scratch: &mut S) -> usize {
    let mut src = fs::File::open(outer).expect("opens");
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
    let changes = carrying(len);
    let mut out = fs::File::create(into).expect("creatable");

    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);

    rpf_core::rewrite(
        &mut src,
        &archive,
        &changes,
        &mut out,
        scratch,
        &mut Unwatched,
    )
    .expect("cascading rebuild");

    let peak = PEAK.load(Ordering::Relaxed);
    out.flush().expect("flushed");
    peak.saturating_sub(baseline)
}

/// As [`carried`], with the payload built inside the measured window: the
/// instrument, whose peak must grow with the payload.
fn carried_and_held<S: Scratch>(outer: &Path, into: &Path, len: usize, scratch: &mut S) -> usize {
    let mut src = fs::File::open(outer).expect("opens");
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
    let mut out = fs::File::create(into).expect("creatable");

    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);

    let changes = carrying(len);
    rpf_core::rewrite(
        &mut src,
        &archive,
        &changes,
        &mut out,
        scratch,
        &mut Unwatched,
    )
    .expect("cascading rebuild");

    let peak = PEAK.load(Ordering::Relaxed);
    out.flush().expect("flushed");
    peak.saturating_sub(baseline)
}

/// An archive holding one entry of `len` bytes and one small one, and that
/// entry's length. Stored rather than deflated, so a compressible payload does
/// not end up measuring the compressor.
fn one_large_entry(dir: &Path, len: usize) -> (PathBuf, u64) {
    let path = dir.join(format!("large-{len}.rpf"));
    let specs = [stored("bulk.bin"), stored("note.txt")];
    let mut out = fs::File::create(&path).expect("creatable");
    rpf_core::build(
        &mut out,
        Version::Rpf7,
        &specs,
        &[],
        |wanted: &str| {
            Ok(Cursor::new(if wanted == "note.txt" {
                b"before".to_vec()
            } else {
                vec![0x5A_u8; len]
            }))
        },
        &mut Unwatched,
    )
    .expect("builds");
    out.flush().expect("flushed");
    drop(out);
    (path, len as u64)
}

fn rebuild(outer: &Path, into: &Path) -> usize {
    let mut src = fs::File::open(outer).expect("opens");
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
    let edits = BTreeMap::from([("note.txt".to_owned(), b"after, and longer".to_vec())]);
    let mut out = fs::File::create(into).expect("creatable");

    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);

    rpf_core::rewrite(
        &mut src,
        &archive,
        &rpf_core::Changes::writing(edits),
        &mut out,
        &mut rpf_core::InMemory,
        &mut Unwatched,
    )
    .expect("rebuild");

    let peak = PEAK.load(Ordering::Relaxed);
    out.flush().expect("flushed");
    peak.saturating_sub(baseline)
}

/// Reads one entry of `outer` into memory, and answers the same peak: the
/// instrument for the entry arm, whose peak must grow with the entry.
fn held_whole(outer: &Path) -> usize {
    let mut src = fs::File::open(outer).expect("opens");
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
    let index = archive.find("bulk.bin").expect("the large entry");

    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);

    let bytes = archive.extract(&mut src, index).expect("extracts");
    let peak = PEAK.load(Ordering::Relaxed);
    assert!(!bytes.is_empty());
    peak.saturating_sub(baseline)
}

fn verified(outer: &Path) -> usize {
    let mut src = fs::File::open(outer).expect("opens");
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");

    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);

    let walked = Verified::of(&mut src, &archive, &mut Unwatched).expect("verifies");
    let peak = PEAK.load(Ordering::Relaxed);
    assert!(walked.problems.is_empty(), "{:?}", walked.problems);
    peak.saturating_sub(baseline)
}

/// The manifest is derived before the peak is reset, so what is measured is the
/// walk rather than the derivation.
fn verified_against(outer: &Path) -> usize {
    let mut src = fs::File::open(outer).expect("opens");
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
    let manifest = Manifest::of_contents(&mut src, &archive, &mut Unwatched).expect("derives");

    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);

    let walked =
        Verified::against(&mut src, &archive, &manifest, &mut Unwatched).expect("verifies");
    let peak = PEAK.load(Ordering::Relaxed);
    assert!(walked.problems.is_empty(), "{:?}", walked.problems);
    assert_eq!(walked.contents_checked, 2, "both entries were digested");
    peak.saturating_sub(baseline)
}

/// Each claim is paired with an instrument arm that must grow with what it
/// reads, so a broken measurement cannot pass as a flat peak.
#[test]
fn a_rebuild_and_a_verify_hold_neither_the_ancestor_nor_the_entry() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut on_disk = OnDisk {
        directory: dir.path().to_path_buf(),
    };

    let (small, small_len) = nested(dir.path(), 32);
    let (large, large_len) = nested(dir.path(), 128);
    let ancestor_growth = large_len - small_len;

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

    // The instrument: an in-memory cascade holds the ancestor, so its peak has
    // to grow by at least as much as the ancestor did.
    assert!(
        u64::try_from(held).unwrap_or(0) >= ancestor_growth,
        "an in-memory cascade grew by only {held} for an ancestor {ancestor_growth} larger, \
         so the measurement is not seeing the ancestor at all"
    );

    // An eighth of the ancestor's growth is a wide margin on purpose: a rebuild
    // that held the ancestor whole would grow by the whole of it.
    assert!(
        u64::try_from(streamed).unwrap_or(u64::MAX) < ancestor_growth / 8,
        "peak grew by {streamed} bytes for an ancestor {ancestor_growth} bytes larger"
    );

    let (small_entry, small_entry_len) = one_large_entry(dir.path(), 2 * 1024 * 1024);
    let (large_entry, large_entry_len) = one_large_entry(dir.path(), 8 * 1024 * 1024);
    let entry_growth = large_entry_len - small_entry_len;

    let _ = rebuild(&small_entry, &dir.path().join("warm-entry.rpf"));

    let whole_small = held_whole(&small_entry);
    let whole_large = held_whole(&large_entry);
    let whole = whole_large.saturating_sub(whole_small);

    let copied_small = rebuild(&small_entry, &dir.path().join("copied-small.rpf"));
    let copied_large = rebuild(&large_entry, &dir.path().join("copied-large.rpf"));
    let copied = copied_large.saturating_sub(copied_small);

    eprintln!(
        "entry {small_entry_len} -> {large_entry_len} (+{entry_growth}); \
         peak live heap held whole {whole_small} -> {whole_large} (+{whole}), \
         streamed through a rebuild {copied_small} -> {copied_large} (+{copied})"
    );

    assert!(
        u64::try_from(whole).unwrap_or(0) >= entry_growth,
        "`extract` grew by only {whole} for an entry {entry_growth} larger, \
         so the measurement is not seeing the entry at all"
    );
    assert!(
        u64::try_from(copied).unwrap_or(u64::MAX) < entry_growth / 8,
        "peak grew by {copied} bytes for an entry {entry_growth} bytes larger"
    );

    let _ = verified(&small_entry);

    let read_small = verified(&small_entry);
    let read_large = verified(&large_entry);
    let read = read_large.saturating_sub(read_small);

    let digested_small = verified_against(&small_entry);
    let digested_large = verified_against(&large_entry);
    let digested = digested_large.saturating_sub(digested_small);

    eprintln!(
        "entry {small_entry_len} -> {large_entry_len} (+{entry_growth}); \
         peak live heap read back by a verify {read_small} -> {read_large} (+{read}), \
         and against a manifest {digested_small} -> {digested_large} (+{digested})"
    );

    assert!(
        u64::try_from(read).unwrap_or(u64::MAX) < entry_growth / 8,
        "peak grew by {read} bytes for an entry {entry_growth} bytes larger"
    );
    assert!(
        u64::try_from(digested).unwrap_or(u64::MAX) < entry_growth / 8,
        "peak grew by {digested} bytes for an entry {entry_growth} bytes larger"
    );

    payload_arm(dir.path(), &small, &mut on_disk);
}

/// The payload a change carries: a cascading rebuild splits a change set at
/// every level, so an owned payload risks being held once per level.
///
/// Its own function only because the test above is at `too_many_lines`.
fn payload_arm(dir: &Path, outer: &Path, scratch: &mut OnDisk) {
    let payload_growth = (LARGE_PAYLOAD - SMALL_PAYLOAD) as u64;

    let _ = carried(outer, &dir.join("warm-carried.rpf"), SMALL_PAYLOAD, scratch);

    let held_small = carried_and_held(
        outer,
        &dir.join("held-payload-small.rpf"),
        SMALL_PAYLOAD,
        scratch,
    );
    let held_large = carried_and_held(
        outer,
        &dir.join("held-payload-large.rpf"),
        LARGE_PAYLOAD,
        scratch,
    );
    let held = held_large.saturating_sub(held_small);

    let added_small = carried(
        outer,
        &dir.join("carried-small.rpf"),
        SMALL_PAYLOAD,
        scratch,
    );
    let added_large = carried(
        outer,
        &dir.join("carried-large.rpf"),
        LARGE_PAYLOAD,
        scratch,
    );
    let added = added_large.saturating_sub(added_small);

    eprintln!(
        "payload {SMALL_PAYLOAD} -> {LARGE_PAYLOAD} (+{payload_growth}); \
         peak live heap with the caller's own copy counted \
         {held_small} -> {held_large} (+{held}), \
         added by the rebuild {added_small} -> {added_large} (+{added})"
    );

    // The instrument: a caller holding the donor grows by the donor.
    assert!(
        u64::try_from(held).unwrap_or(0) >= payload_growth,
        "holding the payload grew the peak by only {held} for a payload \
         {payload_growth} larger, so the measurement is not seeing it at all"
    );

    // A rebuild carries the caller's payload rather than copying it, at any
    // depth, so what it adds does not grow with the payload.
    assert!(
        u64::try_from(added).unwrap_or(u64::MAX) < payload_growth / 8,
        "the rebuild added {added} bytes for a payload {payload_growth} bytes larger"
    );
}
