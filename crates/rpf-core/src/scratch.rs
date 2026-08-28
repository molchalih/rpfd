//! Where a cascading rebuild puts an ancestor it has rebuilt.
//!
//! Rebuilding a file inside a nested archive rebuilds every archive above it,
//! and each of those has to exist somewhere before the one above can write it
//! as a payload. Holding it in memory costs the ancestor's whole length, which
//! is 62 MB of the sample's 145 MB and is unbounded in general.
//!
//! This crate opens no files and resolves no paths — `docs/conventions.md` §7 —
//! so it cannot answer where that space comes from, and does not try to. It
//! asks, and the frontend answers: the command line and the daemon both hand
//! back an unnamed temporary file in the directory the rebuilt archive is going
//! to, which is the same place `persist` already writes. DR-022.

use std::io::{Cursor, Read, Seek, Write};

use crate::error::Result;

/// A source of empty, seekable sinks for a rebuild's intermediates.
///
/// The parameter is not optional, for the reason [`crate::Unwatched`] is not:
/// a caller that wants the intermediates in memory says so at the call site
/// with [`InMemory`], rather than getting it by omission.
pub trait Scratch {
    /// One piece of scratch space.
    ///
    /// Written from its start and then read back from its start, so it is both
    /// halves and seekable. Owned, because a rebuild holds one per level of
    /// nesting it is passing through.
    type Sink: Read + Write + Seek + 'static;

    /// A fresh sink, empty.
    ///
    /// Asked once per nested archive a rebuild has to rewrite, so a cascade
    /// through *n* levels holds at most *n* of them at once.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Io`] when the sink cannot be made.
    fn create(&mut self) -> Result<Self::Sink>;
}

/// Scratch space held in memory.
///
/// The cost is named rather than hidden: a cascade with this holds every
/// ancestor it has rebuilt until the rebuild above it has read it, so its peak
/// is the sum of the archives on the edited path. That is the right answer for
/// a caller with no filesystem to write to, and the wrong one for an archive
/// whose ancestors are gigabytes.
#[derive(Debug, Default, Clone, Copy)]
pub struct InMemory;

impl Scratch for InMemory {
    type Sink = Cursor<Vec<u8>>;

    fn create(&mut self) -> Result<Self::Sink> {
        Ok(Cursor::new(Vec::new()))
    }
}
