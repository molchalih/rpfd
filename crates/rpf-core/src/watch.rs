//! Seeing a long write happen, and stopping one.
//!
//! Progress and cancellation are one seam because they are one question, asked
//! at the same moment: how far are we, and should we carry on.

/// How far a long write has got.
///
/// Reported once per entry written. A cascading rebuild counts the archive
/// being written now rather than the whole cascade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step<'a> {
    /// The entry just written, by path within the archive being written; a
    /// scan over a source that has no entries names the material it seeks.
    pub path: &'a str,
    /// How many units of work are done, this one included: entries written, or
    /// blocks of a source scanned.
    pub done: u32,
    /// How many there are in total; a scan that stops early names fewer.
    pub total: u32,
    /// How many bytes have been written so far, the header and entry table
    /// included — or, for a scan, how many have been read.
    pub bytes: u64,
}

/// Whether a long write should carry on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Keep going.
    Continue,
    /// Stop; the write fails with [`crate::Error::Cancelled`] and the sink is
    /// left however far it got.
    Stop,
}

/// Something watching a long write.
///
/// The method is called between entries, so a cancellation lands only at the
/// end of the entry in flight.
pub trait Watch {
    /// One entry has been written. Returns whether to write the next.
    fn step(&mut self, step: Step<'_>) -> Flow;
}

/// Watches nothing and never stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unwatched;

impl Watch for Unwatched {
    fn step(&mut self, _step: Step<'_>) -> Flow {
        Flow::Continue
    }
}

/// So that a caller holding a `&mut W` can pass it on to a nested rebuild
/// without giving it away.
impl<W: Watch + ?Sized> Watch for &mut W {
    fn step(&mut self, step: Step<'_>) -> Flow {
        (**self).step(step)
    }
}
