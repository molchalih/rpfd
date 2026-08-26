//! The container error type.
//!
//! Variants are structured, not stringly (§10): exit codes are derived from
//! them (R6.3), which makes the variant set part of the public contract. Each
//! carries what a caller needs to act on or report, never a pre-rendered
//! sentence.

use std::io;

/// Anything that can go wrong reading a container.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The underlying source failed. `offset` is where we were reading.
    #[error("i/o failure at offset {offset}")]
    Io {
        /// Absolute offset in the source that was being read.
        offset: u64,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },

    /// The bytes at the archive's base are not an RPF7 header.
    #[error("not an RPF7 archive at offset {base}: magic reads {found:02x?}")]
    NotAnArchive {
        /// Where the archive was expected to begin.
        base: u64,
        /// The four bytes actually found there.
        found: [u8; 4],
    },

    /// The archive is encrypted and no key material is available.
    ///
    /// Distinct from [`Error::Corrupt`] on purpose: the archive is fine, we
    /// simply cannot open it here. R2 and R6.3.
    #[error("archive is encrypted (tag {tag:#010x}); no key material available")]
    NeedsKey {
        /// The encryption tag from the header.
        tag: u32,
    },

    /// A region the header describes does not fit inside the archive.
    #[error("{region} runs from {offset} for {len} bytes, past the archive's {archive_len}")]
    OutOfBounds {
        /// Which region: `"entry table"`, `"names blob"`, `"payload"`.
        region: &'static str,
        /// Where the region claims to start, relative to the archive's base.
        offset: u64,
        /// How long it claims to be.
        len: u64,
        /// The archive's own declared length.
        archive_len: u64,
    },

    /// An entry's name offset does not point at a terminated string inside the
    /// names blob.
    ///
    /// Reading past `namesLength` is how stale names from a previous pack get
    /// mistaken for live ones. `docs/rpf-format.md`, Slack.
    #[error(
        "entry {entry}: name offset {name_offset} is not a terminated string in {names_len} bytes"
    )]
    BadName {
        /// Index of the offending entry.
        entry: u32,
        /// The name offset it carried.
        name_offset: u32,
        /// Length of the names blob.
        names_len: u32,
    },

    /// A directory entry's child range is not inside the entry table.
    #[error("entry {entry}: children {first}..+{count} are outside the {entry_count} entries")]
    BadChildRange {
        /// Index of the offending directory.
        entry: u32,
        /// First child index it claimed.
        first: u32,
        /// How many children it claimed.
        count: u32,
        /// How many entries the archive actually has.
        entry_count: u32,
    },

    /// A resource entry's compressed size cannot hold its own `RSC7` header.
    #[error("entry {entry}: resource of {compressed_len} bytes is smaller than its 16-byte header")]
    ResourceTooSmall {
        /// Index of the offending entry.
        entry: u32,
        /// The compressed size it declared.
        compressed_len: u32,
    },

    /// The payload did not inflate.
    #[error("entry {entry}: payload did not inflate")]
    Inflate {
        /// Index of the offending entry.
        entry: u32,
        /// The underlying decompression failure.
        #[source]
        source: io::Error,
    },

    /// The payload inflated, but not to the length the archive promised.
    ///
    /// Worth its own variant: it means the archive is internally inconsistent
    /// rather than unreadable, and that is a different thing to report.
    #[error("entry {entry}: inflated to {actual} bytes, archive declares {expected}")]
    LengthMismatch {
        /// Index of the offending entry.
        entry: u32,
        /// The length the archive declared.
        expected: u64,
        /// The length actually produced.
        actual: u64,
    },

    /// An entry index does not exist in this archive.
    #[error("no entry with index {index}; the archive has {entry_count}")]
    NoSuchEntry {
        /// The index asked for.
        index: u32,
        /// How many entries exist.
        entry_count: u32,
    },

    /// No entry at the given path.
    ///
    /// `segment` is the component that failed, which is more useful than the
    /// whole path when addressing through several nested archives.
    #[error("no entry at {path:?}: {segment:?} not found")]
    NotFound {
        /// The path that was asked for.
        path: String,
        /// The component of it that did not resolve.
        segment: String,
    },

    /// A value does not fit the field the format stores it in.
    ///
    /// The container's fields are narrow — a compressed size is 24 bits, a
    /// block offset 23, a file's name offset 16 — and exceeding one is a limit
    /// of the format, not a bug in the caller's input.
    #[error("{path:?}: {what} is {len}, over the format's limit of {limit}")]
    FieldOverflow {
        /// The entry being written.
        path: String,
        /// Which field overflowed.
        what: &'static str,
        /// The value that did not fit.
        len: u64,
        /// The largest value that would have.
        limit: u64,
    },

    /// An entry was declared a resource but its payload is not one.
    #[error("{path:?}: declared a resource, but the payload does not begin with RSC7")]
    NotAResource {
        /// The entry being written.
        path: String,
    },

    /// A path cannot be turned into entries.
    #[error("invalid path {path:?}: {reason}")]
    BadPath {
        /// The offending path.
        path: String,
        /// Why it cannot be used.
        reason: &'static str,
    },

    /// The entry exists but is not the kind the operation needs.
    #[error("entry {entry} is a {found}, expected a {wanted}")]
    WrongKind {
        /// Index of the entry.
        entry: u32,
        /// What it actually is.
        found: &'static str,
        /// What the operation needed.
        wanted: &'static str,
    },
}

/// The class of a failure, which is what an exit code is derived from.
///
/// R6.3 wants exit codes that distinguish these, so the mapping lives here
/// rather than in the binary: the variant set is the public contract (§10), and
/// a new variant that forgets to classify itself would otherwise become an
/// exit code silently.
/// Deliberately **not** `#[non_exhaustive]`, unlike [`Error`]: a new category
/// must break every mapping of it at compile time, which is the whole point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// The thing asked for is not in the archive.
    NotFound,
    /// The archive contradicts itself, or does not decompress as it promises.
    Corrupt,
    /// The archive is intact but needs key material we do not have.
    NeedsKey,
    /// The source or sink failed.
    Io,
}

impl Error {
    /// What kind of failure this is.
    #[must_use]
    pub const fn category(&self) -> Category {
        match *self {
            Self::Io { .. } | Self::Inflate { .. } => Category::Io,
            Self::NeedsKey { .. } => Category::NeedsKey,
            Self::NotFound { .. } | Self::NoSuchEntry { .. } => Category::NotFound,
            Self::NotAnArchive { .. }
            | Self::OutOfBounds { .. }
            | Self::BadName { .. }
            | Self::BadChildRange { .. }
            | Self::ResourceTooSmall { .. }
            | Self::LengthMismatch { .. }
            | Self::FieldOverflow { .. }
            | Self::NotAResource { .. }
            | Self::BadPath { .. }
            | Self::WrongKind { .. } => Category::Corrupt,
        }
    }
}

/// Result of a container operation.
pub type Result<T> = std::result::Result<T, Error>;
