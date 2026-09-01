//! Seeing a long write happen, and stopping one.

/// How far a long write has got, reported once per entry written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step<'a> {
    /// The entry just written, or the material a scan is seeking.
    pub path: &'a str,
    /// How many units of work are done so far, this one included.
    pub done: u32,
    /// How many there are in total; a scan that stops early names fewer.
    pub total: u32,
    /// How many bytes have been written, or for a scan, read so far.
    pub bytes: u64,
}

/// Whether a long write should carry on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Keep going.
    Continue,
    /// Stop; the write fails and the sink is left however far it got.
    Stop,
}

/// Something watching a long write, called between entries.
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

/// Lets a caller holding `&mut W` pass it to a nested rebuild without giving it away.
impl<W: Watch + ?Sized> Watch for &mut W {
    fn step(&mut self, step: Step<'_>) -> Flow {
        (**self).step(step)
    }
}
