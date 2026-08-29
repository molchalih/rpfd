//! Scaffolding shared by the fuzz targets.
//!
//! Every target asserts the same thing, which is `docs/conventions.md` §6's
//! claim rather than a new one: hostile bytes produce a typed
//! [`rpf_core::Error`], never a panic, an abort, or an allocation the input
//! chose the size of. The first three the fuzzer observes for itself; the
//! fourth needs a witness, which is what [`Counting`] is.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

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
