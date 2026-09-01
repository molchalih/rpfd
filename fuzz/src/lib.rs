//! Scaffolding shared by the fuzz targets.
//!
//! Every target asserts that hostile bytes produce a typed [`rpf_core::Error`],
//! never a panic, an abort, or an input-chosen allocation ([`Counting`] is the
//! witness for the last), and that a writer's `Ok` really is a document.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Cursor;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use quick_xml::{Reader, events::Event};

use rpf_core::{
    MAX_DEPTH, Unwatched, Version,
    build::{FileKind, FileSpec, Storage, build},
    metadata::{hash::Dictionary, rbf},
};

/// The largest input a target accepts, in bytes.
///
/// The allocation bound below is only meaningful against a known input size.
pub const MAX_INPUT: usize = 64 * 1024;

/// The most a target may allocate above its baseline while handling one input.
///
/// Three orders of magnitude above [`MAX_INPUT`]: a header count trusted before
/// it is checked reserves gigabytes and lands well clear of this.
pub const PEAK_LIMIT: usize = 64 * 1024 * 1024;

/// The most of one entry's contents a target drains.
///
/// Deflate expands, and an entry that expands is the format working, so
/// draining every byte of one would only measure `flate2`.
pub const DRAIN_LIMIT: u64 = 4 * 1024 * 1024;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// The system allocator, keeping the high-water mark of live bytes.
#[derive(Debug)]
pub struct Counting;

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn took(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::Relaxed).wrapping_add(size);
    PEAK.fetch_max(live, Ordering::Relaxed);
}

fn gave(size: usize) {
    LIVE.fetch_sub(size, Ordering::Relaxed);
}

// SAFETY: every method forwards its arguments unchanged to `System` and returns
// exactly what it answered; the counters never touch the pointer.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            took(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            took(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        gave(layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let grown = unsafe { System.realloc(ptr, layout, new_size) };
        if !grown.is_null() {
            if new_size >= layout.size() {
                took(new_size - layout.size());
            } else {
                gave(layout.size() - new_size);
            }
        }
        grown
    }
}

/// Runs `body`, and fails if it allocated more than [`PEAK_LIMIT`] above what
/// was live when it started.
///
/// # Panics
///
/// When the bound is exceeded, which is the finding the target exists to make.
pub fn watched<T>(body: impl FnOnce() -> T) -> T {
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let answer = body();
    let peak = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
    assert!(
        peak <= PEAK_LIMIT,
        "allocated {peak} bytes above baseline, over the {PEAK_LIMIT} byte cap"
    );
    answer
}

/// The bytes a target was handed, or `None` if there are more than
/// [`MAX_INPUT`] of them.
#[must_use]
pub fn bounded(data: &[u8]) -> Option<&[u8]> {
    (data.len() <= MAX_INPUT).then_some(data)
}

/// What an `RBF` document that `from_xml` accepts must then satisfy.
///
/// Two claims: `from_xml` and `to_xml` are halves of one build, so neither may
/// refuse what the other wrote; and `to_xml`'s round trip is exact over
/// payloads `from_xml` built.
///
/// Does nothing when `document` is not `RBF` XML at all, which is most inputs
/// and is not a failure.
///
/// # Panics
///
/// If either half refuses what the other wrote, or if the round trip is not
/// exact.
pub fn rbf_law(document: &[u8]) {
    let Ok(payload) = rbf::from_xml(document) else {
        return;
    };

    let written = match rbf::to_xml(&payload) {
        Ok(written) => written,
        Err(failure) => panic!("`to_xml` refuses the payload `from_xml` built: {failure:?}"),
    };
    if let Err(cause) = well_formed(&written) {
        panic!("the XML written for a payload `from_xml` built is not a document: {cause}");
    }

    let back = match rbf::from_xml(&written) {
        Ok(back) => back,
        Err(failure) => panic!("`from_xml` refuses the XML `to_xml` wrote: {failure:?}"),
    };
    assert!(
        back == payload,
        "the round trip changed a payload `from_xml` built: {} bytes in, {} out",
        payload.len(),
        back.len()
    );
}

/// Reads `document` to its end as XML, answering why it is not a document.
///
/// `Ok` from a metadata writer is a claim that what it wrote is XML, and not
/// panicking does not check that claim; it matters most for names, which are
/// spelled from a user-supplied dictionary.
///
/// `check_end_names` is the whole of what this asks — with it off a reader
/// accepts `<a></b>`. `expand_empty_elements` matches `rbf::xml`'s reader.
///
/// # Errors
///
/// The reader's own message, with the position it stopped at.
pub fn well_formed(document: &[u8]) -> Result<(), String> {
    let mut reader = Reader::from_reader(document);
    reader.config_mut().check_end_names = true;
    reader.config_mut().expand_empty_elements = true;
    loop {
        match reader.read_event() {
            Ok(Event::Eof) => return Ok(()),
            Ok(_) => {}
            Err(error) => return Err(format!("at byte {}: {error}", reader.error_position())),
        }
    }
}

/// An archive nested one level deeper than [`MAX_DEPTH`] accepts.
///
/// The depth bound is otherwise out of the mutator's reach: every level moves
/// the nested base a block on, so the chain costs more input than libFuzzer's
/// default `-max_len` allows. Built once per process and shared.
///
/// # Panics
///
/// If this build will not write the chain, or writes one over [`MAX_INPUT`].
/// Deterministic either way — it fails on the first input or on none.
#[must_use]
pub fn nested_to_the_bound() -> &'static [u8] {
    static CHAIN: OnceLock<Vec<u8>> = OnceLock::new();
    CHAIN.get_or_init(build_chain).as_slice()
}

/// [`nested_to_the_bound`], done once.
fn build_chain() -> Vec<u8> {
    let mut chain = pack("leaf.txt", b"leaf");
    for level in 1..=MAX_DEPTH + 1 {
        chain = pack("n.rpf", &chain);
        assert!(
            chain.len() <= MAX_INPUT,
            "the chain passed {MAX_INPUT} bytes at level {level}"
        );
    }
    chain
}

/// One archive holding one stored file, which is the only shape the chain
/// needs.
///
/// Stored rather than deflated because [`rpf_core::Archive::open_nested`]
/// reads the payload where it lies, and a deflated archive is not one there.
fn pack(name: &str, contents: &[u8]) -> Vec<u8> {
    let specs = [FileSpec {
        path: name.to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Stored,
            encryption: 0,
        },
    }];
    let mut out = Cursor::new(Vec::new());
    let mut fetch = |_: &str| Ok(Cursor::new(contents));
    build(
        &mut out,
        Version::Rpf7,
        &specs,
        &[],
        &mut fetch,
        &mut Unwatched,
    )
    .expect("this build writes an archive of one stored file");
    out.into_inner()
}

/// The empty dictionary the metadata targets spell names with, built once per
/// process.
///
/// Setup, not work: a `OnceLock` first touched from the target body charges its
/// whole cost to the first input's clock and reads as a hang, so the `meta`
/// targets build it in `init:` and assert [`names_ready`]. Empty because a
/// dictionary cannot decide whether a payload converts and none ships.
static NAMES: OnceLock<Dictionary> = OnceLock::new();

/// Builds [`NAMES`], for an `init:` block and for nothing else.
pub fn names_setup() {
    let _ = names();
}

/// The dictionary every `meta` target spells hashes with.
#[must_use]
pub fn names() -> &'static Dictionary {
    NAMES.get_or_init(Dictionary::default)
}

/// Whether [`names_setup`] has already run, which the targets assert per input.
///
/// Empty means a per-process answer is being computed on some input's clock.
#[must_use]
pub fn names_ready() -> bool {
    NAMES.get().is_some()
}

/// How many of `payload`'s leading bytes a `meta` target calls system pages.
///
/// A `Meta` payload does not carry its own page boundary: it is a fact about
/// the entry, and it decides where every resource pointer lands. A fuzz target
/// has no entry, so the split is derived from the first four bytes modulo
/// `len + 1`, which keeps every split reachable and none out of range.
///
/// A seeded payload is therefore parsed under a split that is almost never its
/// own, which costs nothing: every property asserted is a claim about a payload
/// the parser accepted, whatever boundary it accepted it under.
#[must_use]
pub fn meta_split(payload: &[u8]) -> usize {
    let word = payload
        .first_chunk::<4>()
        .map_or(0, |head| u32::from_le_bytes(*head));
    usize::try_from(word).unwrap_or(usize::MAX) % (payload.len() + 1)
}
