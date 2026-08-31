//! Scaffolding shared by the fuzz targets.
//!
//! Every target asserts the same thing, which is `docs/conventions.md` §6's
//! claim rather than a new one: hostile bytes produce a typed
//! [`rpf_core::Error`], never a panic, an abort, or an allocation the input
//! chose the size of. The first three the fuzzer observes for itself; the
//! fourth needs a witness, which is what [`Counting`] is.
//!
//! The metadata targets ask one more thing, and it needs its own witness for
//! the same reason: a writer that answers `Ok` has claimed its bytes are a
//! document, and nothing about not panicking checks that claim. [`well_formed`]
//! is that check.

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
/// A cap, not a taste: the allocation bound below is only meaningful against a
/// known input size, and 64 KiB is far more archive than any bound here needs.
pub const MAX_INPUT: usize = 64 * 1024;

/// The most a target may allocate above its baseline while handling one input.
///
/// Three orders of magnitude above [`MAX_INPUT`]. A header field is a `u32` or
/// a `u64`, so a count trusted before it is checked against the archive's
/// declared length reserves gigabytes from a handful of bytes and lands well
/// clear of this.
pub const PEAK_LIMIT: usize = 64 * 1024 * 1024;

/// The most of one entry's contents a target drains.
///
/// Deflate expands, and an entry that expands is the format working rather
/// than a defect, so draining every byte of one would only measure `flate2`.
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

// SAFETY: every method forwards its arguments unchanged to `System`, which is
// a correct `GlobalAlloc`, and returns exactly what it answered. The counters
// are read and written before or after that call and never touch the pointer,
// so nothing here can make a sound allocation unsound.
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
/// One spelling, here, because two targets want it and §4 allows exactly one:
/// `rbf_xml` reaches it from documents the corpus produced, `rbf_built` from
/// documents an `Arbitrary` script wrote, and the claim is the same one.
///
/// Two things, and the first is the one that matters. **`from_xml` writes a
/// token stream and `to_xml` reads one, and they are halves of one build**: a
/// payload this build wrote that this build then refuses is DR-039's shape one
/// layer up from the archive. Then the law `rbf::to_xml` states in its own doc
/// comment — feeding its output back reproduces the input byte for byte — over
/// payloads `from_xml` built, which is a different set from the 391 shipped
/// files that law was measured on.
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
/// **The metadata writers are the only paths here that answer bytes meant to
/// be read by something else**, and `Ok` from one of them is a claim that what
/// it wrote is XML. Nothing in "it did not panic" checks that claim, and for
/// `pso::to_xml` there is no reader on this side to check it with: `RBF` has
/// `from_xml` and gets the round trip instead, which is strictly stronger.
///
/// It matters most for the names. A `PSO` member name is a Jenkins hash, and
/// what it is *spelled* as comes out of a dictionary file the user supplied —
/// so the one thing standing between a hostile line of that file and a
/// document nothing can parse is what `Dictionary::load` refuses. This is that
/// gate, checked from the outside.
///
/// `check_end_names` is set rather than left, because it is the whole of what
/// this asks: with it off a reader accepts `<a></b>` and the check means
/// nothing. `expand_empty_elements` matches `rbf::xml`'s reader, so a document
/// this accepts is one that parser gets the same events from.
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
/// **The depth bound is otherwise out of the mutator's reach.** A nested
/// archive begins at `base + block * 512`, and a payload below its own
/// archive's header is refused, so every level moves the base at least one
/// block on: reaching depth 32 takes 16 KiB of input carrying 32 headers at
/// exactly those offsets. libFuzzer's `-max_len` defaults to 4096 when no
/// corpus raises it, which caps a generated input at depth 7 — so a target
/// that waits for the mutator to build this chain asserts nothing about the
/// bound, whatever its own documentation claims. It is built here instead,
/// where no missing flag can forget it.
///
/// Built once per process and shared: it is the same bytes every time, and 33
/// rounds of `build` per input would be the whole cost of the target.
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
/// **Setup, not work.** DR-055: anything a target computes once belongs in
/// `libfuzzer-sys`'s `init:` block, because a `OnceLock` first touched from the
/// target body charges its whole cost to the first input's clock — which is
/// what reported a 991 ms hang in the campaign of 2026-08-31 and said nothing
/// about the library. This one is cheap today (an empty `BTreeMap`), and that
/// is exactly the kind of fact that stops being true quietly, so the three
/// `meta` targets reach it through [`names_setup`] and assert [`names_ready`].
///
/// Empty because a dictionary cannot decide whether a payload converts (R5.5)
/// and because none ships (DR-006); what the names are *spelled* as is
/// `dictionary.rs`'s subject.
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
/// Empty here means a per-process answer is being computed on some input's
/// clock, which is the defect DR-055 records.
#[must_use]
pub fn names_ready() -> bool {
    NAMES.get().is_some()
}

/// How many of `payload`'s leading bytes a `meta` target calls system pages.
///
/// **A `Meta` payload does not carry its own page boundary and cannot.** It is
/// a fact about the *entry* — `format::resource::size_from_flags` of its system
/// flags — and `meta::parse` takes it as an argument for that reason: a
/// resource pointer's space nibble picks system or graphics pages and its
/// offset is flat within that space, so the split decides where every pointer
/// in the file lands.
///
/// A fuzz target has no entry. Fixing the split at, say, the whole payload
/// would freeze half of the addressing the parser does and leave the graphics
/// space unreachable, so it is derived from the input instead: the first four
/// bytes little-endian, taken modulo `len + 1` so that every split from
/// all-graphics to all-system is reachable and none is out of range. The
/// mutator then explores the boundary as it explores everything else.
///
/// The consequence is worth stating, because it is the one place these targets
/// differ from the corpus test beside them: a payload dumped by
/// `tools/metadata-dump` carries its real boundary **in its file name**
/// (`00002_sys8192_…`, read back by `metadata_dump::system_len_of`), and a
/// corpus seed handed to libFuzzer is bytes with no name. So a seeded payload
/// is parsed under a split that is almost never its own. That costs nothing
/// this asks about: `parse` either refuses the split or accepts it, and every
/// property below is a claim about a payload the parser *accepted*, whatever
/// boundary it accepted it under.
#[must_use]
pub fn meta_split(payload: &[u8]) -> usize {
    let word = payload
        .first_chunk::<4>()
        .map_or(0, |head| u32::from_le_bytes(*head));
    usize::try_from(word).unwrap_or(usize::MAX) % (payload.len() + 1)
}
