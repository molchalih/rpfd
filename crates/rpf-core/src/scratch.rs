//! Where a cascading rebuild puts an ancestor it has rebuilt.
//!
//! This crate opens no files and resolves no paths, so the frontend supplies
//! the space each rebuilt ancestor is written to.

use std::io::{Cursor, Read, Seek, Write};

use crate::error::Result;

/// A source of empty, seekable sinks for a rebuild's intermediates.
pub trait Scratch {
    /// One piece of scratch space, written from its start and then read back
    /// from its start.
    type Sink: Read + Write + Seek + 'static;

    /// A fresh, empty sink.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Io`] when the sink cannot be made.
    fn create(&mut self) -> Result<Self::Sink>;
}

/// Scratch space held in memory.
///
/// Peak cost is the sum of the archives on the edited path.
#[derive(Debug, Default, Clone, Copy)]
pub struct InMemory;

impl Scratch for InMemory {
    type Sink = Cursor<Vec<u8>>;

    fn create(&mut self) -> Result<Self::Sink> {
        Ok(Cursor::new(Vec::new()))
    }
}
