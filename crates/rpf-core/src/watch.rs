//! Seeing a long write happen, and stopping one.
//!
//! A rebuild is unbounded work — the sample is 145 MB and the format document
//! names archives of 2.7 GB — so a caller needs to know it is progressing and
//! needs to be able to give up on it. DR-008.
//!
//! Both are one seam because they are one question, asked at the same moment:
//! how far are we, and should we carry on. A caller that wants neither says so
//! with [`Unwatched`] rather than by leaving an argument out — §4 allows one
//! spelling per operation, and a progress-free second spelling of every write
//! path would be four more.

/// How far a long write has got.
///
/// Reported once per entry written, after that entry is on the sink. A
/// cascading rebuild produces one sequence of these per archive it rebuilds,
/// innermost first, so `done` and `total` count the archive being written now
/// rather than the whole cascade — there is no honest total for the cascade
/// until it is finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step<'a> {
    /// The entry just written, by path within the archive being written.
    pub path: &'a str,
    /// How many entries have been written, this one included.
    pub done: u32,
    /// How many will be written in total.
    pub total: u32,
    /// How many bytes have been written so far, the header and entry table
    /// included.
    pub bytes: u64,
}

/// Whether a long write should carry on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Keep going.
    Continue,
    /// Stop. The write fails with [`crate::Error::Cancelled`] and the sink is
    /// left however far it got, which is why every caller writes to a
    /// temporary file and renames only on success (§8).
    Stop,
}

/// Something watching a long write.
///
/// Implement it to report progress, to cancel, or both. The method is called
/// between entries, so a cancellation lands within one entry's work rather than
/// instantly — and an entry can be a 20 MB payload.
pub trait Watch {
    /// One entry has been written. Returns whether to write the next.
    fn step(&mut self, step: Step<'_>) -> Flow;
}

/// Watches nothing and never stops.
///
/// The spelling of "I do not want progress" at a call site, so that not wanting
/// it is visible rather than being the absence of something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unwatched;

impl Watch for Unwatched {
    fn step(&mut self, _step: Step<'_>) -> Flow {
        Flow::Continue
    }
}

/// So that a caller holding a `&mut W` can pass it on to a nested rebuild
/// without giving it away. `replace_many` needs exactly this.
impl<W: Watch + ?Sized> Watch for &mut W {
    fn step(&mut self, step: Step<'_>) -> Flow {
        (**self).step(step)
    }
}
