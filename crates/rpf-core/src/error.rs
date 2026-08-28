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

    /// The bytes at the archive's base are an RPF header of a version this
    /// build does not read.
    ///
    /// Distinct from [`Error::NotAnArchive`], which is what the version used to
    /// be reported as: nothing here is malformed. The version is in the first
    /// four bytes and throwing it away told a caller the archive was broken.
    /// DR-012, and DR-010's amendment for the category.
    #[error(
        "RPF{version} archive at offset {base}: magic reads {found:02x?}, \
         and this build reads only RPF7 in its 7FPR spelling"
    )]
    UnsupportedVersion {
        /// Where the archive was expected to begin.
        base: u64,
        /// The version number the magic names.
        version: u8,
        /// The four bytes actually found there, which say which of the two
        /// byte orders the archive was written in.
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

    /// A directory claims a child that does not come after it in the entry
    /// table — itself, or an entry above it — so the entries do not form a
    /// tree.
    ///
    /// The entry table is laid out breadth-first, each directory's children in
    /// one run after it (`docs/rpf-format.md`, Table order), so a child index
    /// greater than its parent's is what makes the parent map well founded: a
    /// walk up it strictly decreases and therefore ends. A claim that goes the
    /// other way is what a cycle is made of.
    ///
    /// Distinct from [`Error::BadChildRange`], and worse: every index involved
    /// is inside the entry table, so walking the parent map does not run off
    /// the end — it runs for ever. Refused at parse, because a caller cannot
    /// act on a value it never gets back.
    #[error("entry {entry}: child {child} does not come after it in the entry table")]
    CyclicTree {
        /// Index of the directory that claimed the child.
        entry: u32,
        /// The child it claimed.
        child: u32,
    },

    /// Two directories claim the same entry as a child, so the entries are not
    /// a forest.
    ///
    /// Nothing here is out of range and nothing is a cycle, which is why it
    /// needs saying separately: the children relation can still be a lattice,
    /// and the number of root-to-leaf paths through one doubles per row. A
    /// 512-byte archive of 26 such rows made `ls -R` produce 33,554,431 rows.
    #[error("entry {child} is claimed as a child by both entry {first} and entry {second}")]
    ClaimedTwice {
        /// The entry claimed more than once.
        child: u32,
        /// The first directory to claim it.
        first: u32,
        /// The second.
        second: u32,
    },

    /// A recursive structure is deeper than this container will walk.
    ///
    /// Both directory trees and archives nested inside archives are walked
    /// recursively, by this crate and by everything built on it, and both
    /// depths are the archive's to choose. Nothing about a deep one is
    /// self-contradictory — which is exactly why it is refused at a stated
    /// depth rather than discovered as a stack overflow (§6).
    #[error("{what} is {depth} deep, over the limit of {limit}")]
    TooDeep {
        /// Which structure: `"directory tree"` or `"archive nesting"`.
        what: &'static str,
        /// The depth reached.
        depth: u32,
        /// The deepest that is accepted.
        limit: u32,
    },

    /// An entry's payload begins inside the archive's own header, entry table
    /// or names blob rather than after them.
    ///
    /// Distinct from [`Error::OutOfBounds`]: the region fits inside the
    /// archive, and that is what makes it dangerous. Reading it hands back the
    /// archive's own structure as file contents, and the room reported for
    /// patching it in place covers the header.
    #[error("entry {entry}: payload begins at {offset}, before the first payload offset {floor}")]
    PayloadUnderflow {
        /// Index of the offending entry.
        entry: u32,
        /// Where the payload claims to begin, relative to the archive's base.
        offset: u64,
        /// The lowest offset a payload may occupy in this archive.
        floor: u64,
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
    ///
    /// A fact about the archive's bytes, not about the source they came from:
    /// every byte asked for arrived, and then did not decode. DR-010.
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

    /// The payload's deflate stream ended before the payload did, so the entry
    /// declares bytes that are not part of anything it holds.
    ///
    /// A deflate stream carries its own end, so the bytes after it inflate to
    /// nothing and are silently ignored: the contents come back exactly as the
    /// archive promises them while the payload is longer than what produced
    /// them. That is the archive contradicting itself, which is why it is
    /// `Corrupt` and not a refusal — but it is reported by `verify` rather
    /// than refused by a read, because one producer's archives are not enough
    /// evidence to reject another's. `docs/backlog.md`, R6.10.
    ///
    /// Carries both lengths because both are what a caller acts on: where the
    /// stream ends, and how much the entry claims after it.
    #[error(
        "entry {entry}: the deflate stream ends after {used} bytes, \
         but the payload declares {declared}"
    )]
    TrailingBytes {
        /// Index of the offending entry.
        entry: u32,
        /// How many bytes of payload the entry table declares. For a resource
        /// this is its compressed size with the 16-byte `RSC7` header taken
        /// off, which is the extent of the stream itself.
        declared: u64,
        /// How many of them the deflate stream consumed.
        used: u64,
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

    /// Two children of one directory are one name here, so one of them cannot
    /// be addressed by any spelling of its own path.
    ///
    /// Path components resolve case-insensitively in this container
    /// ([`crate::format::same_name`]), so `A.txt` and `a.txt` in one directory
    /// are one name and the second is unreachable. Reported by the writer,
    /// which will not produce such an archive, and by the reader, which will
    /// not turn one into a tree, rather than "2 files" now and a failure one
    /// command later. R10.4.
    ///
    /// **Two names one reader cannot tell apart is three conditions, not one,
    /// and this variant is the first of them.** The other two are
    /// [`Error::BadPath`]: `"is named twice in one directory"` for one name
    /// carried twice, and `"a file and a directory share one name"` for a
    /// clash of kinds. The writer has always answered all three separately;
    /// the reader answered every one of them with this variant, which rendered
    /// `"aa.txt" and "aa.txt" are one name here` for an exact duplicate — one
    /// string named twice, telling a caller nothing. Both variants are
    /// [`Category::Refused`] and exit 6, so nothing branching on the number
    /// moves; what changes is that the sentence is now the same one either
    /// way.
    ///
    /// **Both are paths from the archive's root, and they are the two names
    /// that collide** — not the request that ran into the collision. For a
    /// directory component that is not the same thing: adding
    /// `X64/alpha.txt` to a tree that already holds `x64` used to render
    /// `"X64/alpha.txt" and its sibling "x64" are one name here`, which is
    /// untrue twice over — those two are neither siblings nor one name. What
    /// the caller has to act on is the pair of directories, and §10 says a
    /// variant carries that rather than what was being attempted when it
    /// surfaced.
    #[error("{path:?} and {other:?} are one name here, so one of them cannot be addressed")]
    NameCollision {
        /// One of the two, by path from the archive's root.
        path: String,
        /// The other, likewise. The two sit in one directory.
        other: String,
    },

    /// A path cannot be turned into entries.
    #[error("invalid path {path:?}: {reason}")]
    BadPath {
        /// The offending path.
        path: String,
        /// Why it cannot be used.
        reason: &'static str,
    },

    /// Two edits in one plan claim the same bytes.
    ///
    /// A nested archive and a file inside it, or two spellings of one path.
    /// Nothing about the archive is wrong, so this is a refusal rather than a
    /// corrupt archive: the caller has to drop one of the two or rebuild.
    #[error("{path:?} and {other:?} cannot be patched together: they claim the same bytes")]
    Overlapping {
        /// The edit that collided.
        path: String,
        /// The edit already planned over those bytes.
        other: String,
    },

    /// A watcher stopped the write. DR-008.
    ///
    /// Not a failure of the archive or of the caller's input — the caller asked
    /// for this — which is why it carries how far it got rather than a reason.
    #[error("cancelled after {done} of {total} entries")]
    Cancelled {
        /// How many entries had been written when it stopped.
        done: u32,
        /// How many there would have been.
        total: u32,
    },

    /// Entries did not read back as the archive describes them.
    ///
    /// What a failing `verify` returns. It is one failure about a set of
    /// entries rather than about any one of them, so it carries the two counts
    /// a caller acts on — how many were read, and how many of those did not
    /// come back as promised — and leaves the per-entry detail to the report
    /// beside it. R6.9. Borrowing [`Error::LengthMismatch`] for this rendered
    /// "entry 0: inflated to 25 bytes, archive declares 26", a sentence about
    /// inflation with nothing to do with what happened.
    #[error("{failed} of {checked} entries did not read back as the archive describes them")]
    VerifyFailed {
        /// How many file entries were read, the failing ones included.
        checked: u32,
        /// How many of them did not come back as the archive promised.
        failed: u32,
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
/// A category names what the caller has to do about the failure rather than
/// what the code was doing when it noticed. DR-010.
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
    /// The archive is intact and this build cannot read it. Nobody who is
    /// holding it can act: the missing part is here. DR-010's amendment.
    Unsupported,
    /// The container declines to carry out the request. Either it is not well
    /// formed, or it is and the container will not do it. DR-010.
    Refused,
    /// The caller stopped it part-way.
    Cancelled,
    /// The source or sink failed. Nobody's input is in question: this is the
    /// disk, the pipe or the handle. DR-010.
    Io,
}

impl Error {
    /// What kind of failure this is.
    #[must_use]
    pub const fn category(&self) -> Category {
        match *self {
            Self::Io { .. } => Category::Io,
            Self::NeedsKey { .. } => Category::NeedsKey,
            Self::UnsupportedVersion { .. } => Category::Unsupported,
            Self::NotFound { .. } | Self::NoSuchEntry { .. } => Category::NotFound,
            Self::Overlapping { .. }
            | Self::FieldOverflow { .. }
            | Self::NotAResource { .. }
            | Self::BadPath { .. }
            | Self::NameCollision { .. }
            | Self::WrongKind { .. } => Category::Refused,
            Self::Cancelled { .. } => Category::Cancelled,
            Self::NotAnArchive { .. }
            | Self::OutOfBounds { .. }
            | Self::BadName { .. }
            | Self::BadChildRange { .. }
            | Self::CyclicTree { .. }
            | Self::ClaimedTwice { .. }
            | Self::TooDeep { .. }
            | Self::PayloadUnderflow { .. }
            | Self::ResourceTooSmall { .. }
            | Self::Inflate { .. }
            | Self::LengthMismatch { .. }
            | Self::TrailingBytes { .. }
            | Self::VerifyFailed { .. } => Category::Corrupt,
        }
    }
}

/// Result of a container operation.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{Category, Error};

    /// How many variants [`Error`] has, which is what the match below counts.
    ///
    /// The match is exhaustive, so a variant added later stops this module
    /// compiling until it is named there — and then this number and the tables
    /// below have to be brought up to date, which is the point.
    const VARIANTS: usize = 25;

    /// The variant's own name, for a test that has to say which one it means.
    fn name(error: &Error) -> &'static str {
        match *error {
            Error::Io { .. } => "Io",
            Error::NotAnArchive { .. } => "NotAnArchive",
            Error::UnsupportedVersion { .. } => "UnsupportedVersion",
            Error::NeedsKey { .. } => "NeedsKey",
            Error::OutOfBounds { .. } => "OutOfBounds",
            Error::BadName { .. } => "BadName",
            Error::BadChildRange { .. } => "BadChildRange",
            Error::CyclicTree { .. } => "CyclicTree",
            Error::ClaimedTwice { .. } => "ClaimedTwice",
            Error::TooDeep { .. } => "TooDeep",
            Error::PayloadUnderflow { .. } => "PayloadUnderflow",
            Error::ResourceTooSmall { .. } => "ResourceTooSmall",
            Error::Inflate { .. } => "Inflate",
            Error::LengthMismatch { .. } => "LengthMismatch",
            Error::TrailingBytes { .. } => "TrailingBytes",
            Error::VerifyFailed { .. } => "VerifyFailed",
            Error::NoSuchEntry { .. } => "NoSuchEntry",
            Error::NotFound { .. } => "NotFound",
            Error::FieldOverflow { .. } => "FieldOverflow",
            Error::NotAResource { .. } => "NotAResource",
            Error::NameCollision { .. } => "NameCollision",
            Error::BadPath { .. } => "BadPath",
            Error::Overlapping { .. } => "Overlapping",
            Error::Cancelled { .. } => "Cancelled",
            Error::WrongKind { .. } => "WrongKind",
        }
    }

    /// A stand-in for whatever the source or the decompressor reported.
    fn io() -> std::io::Error {
        std::io::Error::other("something below us failed")
    }

    /// Every failure that means the archive's own bytes are wrong.
    ///
    /// `Inflate` belongs here and was `Io`: every byte asked for arrived and
    /// then failed to decode. DR-010.
    fn corrupt() -> Vec<Error> {
        vec![
            Error::NotAnArchive {
                base: 0,
                found: [0; 4],
            },
            Error::OutOfBounds {
                region: "payload",
                offset: 0,
                len: 1,
                archive_len: 0,
            },
            Error::BadName {
                entry: 0,
                name_offset: 0,
                names_len: 0,
            },
            Error::BadChildRange {
                entry: 0,
                first: 0,
                count: 0,
                entry_count: 0,
            },
            Error::CyclicTree { entry: 0, child: 0 },
            Error::ClaimedTwice {
                child: 2,
                first: 0,
                second: 1,
            },
            Error::TooDeep {
                what: "directory tree",
                depth: 33,
                limit: 32,
            },
            Error::PayloadUnderflow {
                entry: 0,
                offset: 0,
                floor: 16,
            },
            Error::ResourceTooSmall {
                entry: 0,
                compressed_len: 4,
            },
            Error::Inflate {
                entry: 0,
                source: io(),
            },
            Error::LengthMismatch {
                entry: 0,
                expected: 26,
                actual: 25,
            },
            Error::TrailingBytes {
                entry: 0,
                declared: 200_044,
                used: 44,
            },
            Error::VerifyFailed {
                checked: 27,
                failed: 1,
            },
        ]
    }

    /// Every failure that means the request, or the input it carried, was
    /// wrong. All but `Overlapping` were `Corrupt`, and so blamed the archive
    /// for what the caller passed. DR-010.
    fn refused() -> Vec<Error> {
        vec![
            Error::FieldOverflow {
                path: "big.bin".to_owned(),
                what: "compressed size",
                len: 1 << 24,
                limit: (1 << 24) - 1,
            },
            Error::NotAResource {
                path: "x.ytd".to_owned(),
            },
            Error::BadPath {
                path: "../escape".to_owned(),
                reason: "leaves the archive",
            },
            Error::NameCollision {
                path: "data/NOTES.TXT".to_owned(),
                other: "data/notes.txt".to_owned(),
            },
            Error::Overlapping {
                path: "a".to_owned(),
                other: "b".to_owned(),
            },
            Error::WrongKind {
                entry: 0,
                found: "directory",
                wanted: "file",
            },
        ]
    }

    /// One failure for each of the categories with no group of their own.
    fn the_rest() -> Vec<(Error, Category)> {
        vec![
            (
                Error::Io {
                    offset: 0,
                    source: io(),
                },
                Category::Io,
            ),
            (Error::NeedsKey { tag: 0x0FFF_FFF9 }, Category::NeedsKey),
            (
                Error::UnsupportedVersion {
                    base: 0,
                    version: 2,
                    found: *b"RPF2",
                },
                Category::Unsupported,
            ),
            (
                Error::NoSuchEntry {
                    index: 9,
                    entry_count: 4,
                },
                Category::NotFound,
            ),
            (
                Error::NotFound {
                    path: "x64/nope".to_owned(),
                    segment: "nope".to_owned(),
                },
                Category::NotFound,
            ),
            (Error::Cancelled { done: 1, total: 24 }, Category::Cancelled),
        ]
    }

    /// A failure of each variant, with the category it is contracted to carry.
    fn taxonomy() -> Vec<(Error, Category)> {
        corrupt()
            .into_iter()
            .map(|error| (error, Category::Corrupt))
            .chain(
                refused()
                    .into_iter()
                    .map(|error| (error, Category::Refused)),
            )
            .chain(the_rest())
            .collect()
    }

    #[test]
    fn every_variant_carries_the_category_it_is_contracted_to() {
        // §10 makes the variant set the public contract and R6.3 derives the
        // exit code from it, so a category that moves is a contract that moved.
        for (error, expected) in taxonomy() {
            assert_eq!(
                error.category(),
                expected,
                "{} is classified {:?}",
                name(&error),
                error.category()
            );
        }
    }

    #[test]
    fn the_taxonomy_covers_every_variant_exactly_once() {
        let named: BTreeSet<&str> = taxonomy().iter().map(|(error, _)| name(error)).collect();
        assert_eq!(
            named.len(),
            VARIANTS,
            "the tables name {} of {VARIANTS} variants",
            named.len()
        );
    }
}
