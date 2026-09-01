//! Where a cascading rebuild puts an ancestor it has rebuilt.

use std::io::{Cursor, Read, Seek, Write};

use crate::error::Result;

/// A source of empty, seekable sinks for a rebuild's intermediates.
pub trait Scratch {
    /// One piece of scratch space, read and written from its start.
    type Sink: Read + Write + Seek + 'static;

    /// A fresh, empty sink.
    /// # Errors
    /// An I/O error if the sink cannot be created.
    fn create(&mut self) -> Result<Self::Sink>;
}

/// Scratch space held in memory; peak cost is the sum of the archives on the edited path.
#[derive(Debug, Default, Clone, Copy)]
pub struct InMemory;

impl Scratch for InMemory {
    type Sink = Cursor<Vec<u8>>;

    fn create(&mut self) -> Result<Self::Sink> {
        Ok(Cursor::new(Vec::new()))
    }
}
