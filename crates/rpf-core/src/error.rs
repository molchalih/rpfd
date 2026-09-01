//! The container error type; exit codes are derived from the variant.

use std::io;

use crate::{
    format::{Version, unsupported_version},
    manifest::Checksum,
};

/// Why an encrypted archive cannot be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NoWrite {
    /// Nothing here derives the archive's forward transform; not a missing key.
    #[error(
        "nothing here derives this archive's forward transform, so it is \
         read and never written"
    )]
    NoInverse,
}

/// Anything that can go wrong reading a container.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The underlying source failed.
    #[error("i/o failure at offset {offset}")]
    Io {
        /// Absolute offset in the source that was being read.
        offset: u64,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },

    /// A source of contents the caller supplied could not be read.
    #[error("{name}: {source}")]
    Contents {
        /// The source, as the frontend that supplied it names it.
        name: String,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },

    /// Not an RPF7 header at the archive's base; `found` decides corrupt vs misdirected.
    #[error("not an RPF7 archive at offset {base}: magic reads {found:02x?}")]
    NotAnArchive {
        /// Where the archive was expected to begin.
        base: u64,
        /// The four bytes found there, which decide the category.
        found: [u8; 4],
    },

    /// The bytes at the archive's base are an RPF header of a version this build does not read.
    #[error(
        "RPF{version} archive at offset {base}: magic reads {found:02x?}, \
         and this build reads only RPF7 in its 7FPR spelling"
    )]
    UnsupportedVersion {
        /// Where the archive was expected to begin.
        base: u64,
        /// The version number the magic names.
        version: u8,
        /// The four bytes found there, which name the byte order used.
        found: [u8; 4],
    },

    /// The archive is encrypted and no key material is available; not a Corrupt archive.
    #[error("archive is encrypted (tag {tag:#010x}); no key material available")]
    NeedsKey {
        /// The encryption tag from the header.
        tag: u32,
    },

    /// The archive is encrypted; available key material does not open it (entry 0 isn't the root).
    #[error(
        "the {scheme} key material available does not open this archive \
         (tag {tag:#010x}, {tried} source(s) tried)"
    )]
    WrongKey {
        /// The encryption tag from the header.
        tag: u32,
        /// Which transform the tag names. Never a key, and never a key index.
        scheme: &'static str,
        /// How many sources' material was tried before this was answered.
        tried: u32,
    },

    /// Encrypted, and this write cannot produce one; not `NeedsKey`, no material closes the gap.
    #[error("archive is encrypted (tag {tag:#010x}); {reason}")]
    CannotWriteEncrypted {
        /// The encryption tag from the header.
        tag: u32,
        /// Which of the two gaps this is.
        reason: NoWrite,
    },

    /// An entry holding a self-keyed archive cannot be renamed (a name-keeping move is fine).
    #[error(
        "{path}: renaming to {to} would leave the {scheme} archive nested there \
         (tag {tag:#010x}) keyed by the name it no longer has"
    )]
    CannotRenameKeyed {
        /// The entry as it stands.
        path: String,
        /// What the rename would call it.
        to: String,
        /// The nested archive's encryption tag.
        tag: u32,
        /// What that tag's transform is called. Never a key.
        scheme: &'static str,
    },

    /// A game executable does not carry the key material this build knows how to find.
    #[error(
        "{what}: {found} of {wanted} values are in this executable; missing {}",
        .missing.join(" and ")
    )]
    UnrecognisedExecutable {
        /// Which material was looked for.
        what: &'static str,
        /// The values not found, by name only — never the material itself.
        missing: &'static [&'static str],
        /// How many of its values were found.
        found: u32,
        /// How many there are to find.
        wanted: u32,
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

    /// An entry's name offset does not point at a terminated string in the names blob.
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

    /// A directory claims a child not after it; an unchecked walk would loop forever.
    #[error("entry {entry}: child {child} does not come after it in the entry table")]
    CyclicTree {
        /// Index of the directory that claimed the child.
        entry: u32,
        /// The child it claimed.
        child: u32,
    },

    /// Two directories claim the same entry as a child, so the entries are not a forest.
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
    #[error("{what} is {depth} deep, over the limit of {limit}")]
    TooDeep {
        /// Which structure: `"directory tree"` or `"archive nesting"`.
        what: &'static str,
        /// The depth reached.
        depth: u32,
        /// The deepest that is accepted.
        limit: u32,
    },

    /// An entry's payload begins before the archive's payload floor, inside internal structure.
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
    #[error("entry {entry}: payload did not inflate")]
    Inflate {
        /// Index of the offending entry.
        entry: u32,
        /// The underlying decompression failure.
        #[source]
        source: io::Error,
    },

    /// The payload inflated, but not to the length the archive promised.
    #[error("entry {entry}: inflated to {actual} bytes, archive declares {expected}")]
    LengthMismatch {
        /// Index of the offending entry.
        entry: u32,
        /// The length the archive declared.
        expected: u64,
        /// The length actually produced.
        actual: u64,
    },

    /// The deflate stream ends before the payload; `verify` reports it, a read does not refuse.
    #[error(
        "entry {entry}: the deflate stream ends after {used} bytes, \
         but the payload declares {declared}"
    )]
    TrailingBytes {
        /// Index of the offending entry.
        entry: u32,
        /// Payload bytes declared; for a resource, compressed size less the 16-byte header.
        declared: u64,
        /// How many of them the deflate stream consumed.
        used: u64,
    },

    /// An entry's contents aren't those recorded; only the manifest checksum catches a stored one.
    #[error("entry {entry}: contents digest {found}, not the recorded {recorded}")]
    ChecksumMismatch {
        /// Index of the offending entry.
        entry: u32,
        /// The digest recorded for it.
        recorded: Checksum,
        /// The digest its contents actually have.
        found: Checksum,
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
    #[error("no entry at {path:?}: {segment:?} not found")]
    NotFound {
        /// The path that was asked for.
        path: String,
        /// The component of it that did not resolve.
        segment: String,
    },

    /// A value doesn't fit its field: compressed size 24 bits, block offset 23, name offset 16.
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

    /// The layout ran past the largest offset this version addresses (RPF7: 4,294,966,784 bytes).
    #[error(
        "the archive is too large: this version addresses {limit} bytes \
         and the layout reached {reached} (at {path:?})"
    )]
    ArchiveTooLarge {
        /// The entry the layout was placing when it ran past the limit.
        path: String,
        /// The offset it reached, in bytes.
        reached: u64,
        /// The largest offset this version addresses, in bytes.
        limit: u64,
    },

    /// A payload cannot fill a resource's row (not for lacking an `RSC7` header, which is normal).
    #[error("{path:?}: cannot be written into a resource entry: {reason}")]
    NotAResource {
        /// The entry being written.
        path: String,
        /// What is missing.
        reason: &'static str,
    },

    /// A payload cannot be written into an entry holding a tokenised metadata encoding.
    #[error(
        "{path:?}: an entry holding {} cannot take a payload of {}",
        held.name(),
        offered.name()
    )]
    WrongEncoding {
        /// The entry being written, by path from the archive that holds it.
        path: String,
        /// What its payload announces itself to be now.
        held: crate::metadata::Encoding,
        /// What the offered payload announces itself to be.
        offered: crate::metadata::Encoding,
    },

    /// An entry was asked for as XML and has no XML view.
    #[error(
        "{path:?}: an entry holding {} has no XML view",
        held.map_or("no encoding this tool converts", crate::metadata::Encoding::name)
    )]
    NoXmlView {
        /// The entry, by path from the archive that holds it.
        path: String,
        /// What its payload announces itself to be, if anything.
        held: Option<crate::metadata::Encoding>,
    },

    /// Two children fold to the same name (case-insensitively); a duplicate is `BadPath` instead.
    #[error("{path:?} and {other:?} are one name here, so one of them cannot be addressed")]
    NameCollision {
        /// One of the two, by path from the archive's root.
        path: String,
        /// The other, likewise. The two sit in one directory.
        other: String,
    },

    /// A path a change would create is already there; a write replaces instead of raising this.
    #[error("{path:?} is already in the archive")]
    AlreadyExists {
        /// The path that is taken, from the archive's root.
        path: String,
    },

    /// A change set already holds a change at this path; a second would silently drop the first.
    #[error("{path:?} already has {held} in this change set, which holds one change per path")]
    Claimed {
        /// The path both changes are at.
        path: String,
        /// What the change already there is: a write, removal, rename, or new directory.
        held: &'static str,
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
    #[error("{path:?} and {other:?} cannot be patched together: they claim the same bytes")]
    Overlapping {
        /// The edit that collided.
        path: String,
        /// The edit already planned over those bytes.
        other: String,
    },

    /// A watcher stopped the write.
    #[error("cancelled after {done} of {total} entries")]
    Cancelled {
        /// How many entries had been written when it stopped.
        done: u32,
        /// How many there would have been.
        total: u32,
    },

    /// Entries are not as they are recorded.
    #[error("{failed} of {checked} entries are not as they are recorded")]
    VerifyFailed {
        /// How many file entries were read, the failing ones included.
        checked: u32,
        /// How many of them did not come back as the archive promised.
        failed: u32,
    },

    /// The entry exists but is not the kind the operation needs.
    #[error("{path:?} is a {found}, expected a {wanted}")]
    WrongKind {
        /// The entry, by path from the archive that holds it.
        path: String,
        /// What it actually is.
        found: &'static str,
        /// What the operation needed.
        wanted: &'static str,
    },

    /// An `RBF` payload's token stream is not well formed.
    #[error("malformed RBF at offset {offset}")]
    BadRbf {
        /// Where in the payload the stream stopped making sense.
        offset: u64,
        /// What was wrong with it.
        cause: crate::metadata::rbf::Malformed,
    },

    /// An `RBF` payload is well formed and says something XML cannot carry.
    #[error("the RBF payload cannot be written as XML")]
    UnrepresentableRbf {
        /// Which thing it says.
        cause: crate::metadata::rbf::Unrepresentable,
    },

    /// A `PSO` payload contradicts itself.
    #[error("malformed PSO at offset {offset}")]
    BadPso {
        /// Where in the payload the file stopped making sense.
        offset: u64,
        /// What was wrong with it.
        cause: crate::metadata::pso::Malformed,
    },

    /// A resource `Meta` payload contradicts itself.
    #[error("malformed Meta at offset {offset}")]
    BadMeta {
        /// Where in the payload the file stopped making sense.
        offset: u64,
        /// What was wrong with it.
        cause: crate::metadata::meta::Malformed,
    },

    /// A `PSO` payload is well formed and carries something this build does not decode.
    #[error("the PSO payload carries something this build does not decode")]
    UnsupportedPso {
        /// Which thing.
        cause: crate::metadata::pso::Unsupported,
    },

    /// A resource `Meta` payload is well formed and carries something this build does not decode.
    #[error("the Meta payload carries something this build does not decode")]
    UnsupportedMeta {
        /// Which thing.
        cause: crate::metadata::meta::Unsupported,
    },

    /// The metadata layer's XML does not describe the resource `Meta` payload beside it.
    #[error("the XML at position {position} does not describe this Meta payload")]
    NotMetaXml {
        /// Where in the XML the reader was, so an editor can jump to the line to change.
        position: u64,
        /// What was wrong with it.
        cause: crate::metadata::meta::NotMetaXml,
    },

    /// The XML handed to the metadata layer does not describe an `RBF` document.
    #[error("the XML at position {position} does not describe an RBF document")]
    NotRbfXml {
        /// Where in the XML the reader was, so an editor can jump to the line to change.
        position: u64,
        /// What was wrong with it.
        cause: crate::metadata::rbf::NotRbf,
    },

    /// The metadata layer's XML does not describe the `PSO` payload beside it.
    #[error("the XML at position {position} does not describe this PSO payload")]
    NotPsoXml {
        /// Where in the XML the reader was, so an editor can jump to the line to change.
        position: u64,
        /// What was wrong with it.
        cause: crate::metadata::pso::NotPsoXml,
    },
}

/// A failure's class, which an exit code is derived from; not `#[non_exhaustive]`, unlike `Error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// The thing asked for is not in the archive.
    NotFound,
    /// The archive contradicts itself, or does not decompress as it promises.
    Corrupt,
    /// The archive is intact but needs key material we do not have.
    NeedsKey,
    /// The archive is intact and this build cannot read it; the missing part is here.
    Unsupported,
    /// The container declines to carry out the request.
    Refused,
    /// The caller stopped it part-way.
    Cancelled,
    /// The source or sink failed: the disk, the pipe or the handle.
    Io,
}

fn claims_a_container(magic: [u8; 4]) -> bool {
    magic == Version::Rpf7.magic() || unsupported_version(magic).is_some()
}

impl Error {
    /// What kind of failure this is.
    #[must_use]
    pub fn category(&self) -> Category {
        match *self {
            Self::Io { .. } | Self::Contents { .. } => Category::Io,
            Self::NeedsKey { .. } | Self::WrongKey { .. } => Category::NeedsKey,
            Self::UnsupportedVersion { .. }
            | Self::UnrecognisedExecutable { .. }
            | Self::CannotWriteEncrypted { .. }
            | Self::CannotRenameKeyed { .. }
            | Self::UnrepresentableRbf { .. }
            | Self::UnsupportedPso { .. }
            | Self::UnsupportedMeta { .. } => Category::Unsupported,
            Self::NotFound { .. } | Self::NoSuchEntry { .. } => Category::NotFound,
            Self::Overlapping { .. }
            | Self::FieldOverflow { .. }
            | Self::ArchiveTooLarge { .. }
            | Self::NotAResource { .. }
            | Self::WrongEncoding { .. }
            | Self::NoXmlView { .. }
            | Self::BadPath { .. }
            | Self::AlreadyExists { .. }
            | Self::Claimed { .. }
            | Self::NameCollision { .. }
            | Self::WrongKind { .. }
            | Self::NotRbfXml { .. }
            | Self::NotPsoXml { .. }
            | Self::NotMetaXml { .. } => Category::Refused,
            Self::Cancelled { .. } => Category::Cancelled,
            // The bytes decide: a payload that never claimed to be an archive
            // was named one by the caller's own path.
            Self::NotAnArchive { found, .. } => {
                if claims_a_container(found) {
                    Category::Corrupt
                } else {
                    Category::Refused
                }
            }
            Self::OutOfBounds { .. }
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
            | Self::ChecksumMismatch { .. }
            | Self::VerifyFailed { .. }
            | Self::BadRbf { .. }
            | Self::BadPso { .. }
            | Self::BadMeta { .. } => Category::Corrupt,
        }
    }

    /// This variant's own name, as a stable symbol; renaming one is breaking, adding one is not.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match *self {
            Self::Io { .. } => "Io",
            Self::Contents { .. } => "Contents",
            Self::NotAnArchive { .. } => "NotAnArchive",
            Self::UnsupportedVersion { .. } => "UnsupportedVersion",
            Self::UnrecognisedExecutable { .. } => "UnrecognisedExecutable",
            Self::NeedsKey { .. } => "NeedsKey",
            Self::WrongKey { .. } => "WrongKey",
            Self::CannotWriteEncrypted { .. } => "CannotWriteEncrypted",
            Self::CannotRenameKeyed { .. } => "CannotRenameKeyed",
            Self::OutOfBounds { .. } => "OutOfBounds",
            Self::BadName { .. } => "BadName",
            Self::BadChildRange { .. } => "BadChildRange",
            Self::CyclicTree { .. } => "CyclicTree",
            Self::ClaimedTwice { .. } => "ClaimedTwice",
            Self::TooDeep { .. } => "TooDeep",
            Self::PayloadUnderflow { .. } => "PayloadUnderflow",
            Self::ResourceTooSmall { .. } => "ResourceTooSmall",
            Self::Inflate { .. } => "Inflate",
            Self::LengthMismatch { .. } => "LengthMismatch",
            Self::TrailingBytes { .. } => "TrailingBytes",
            Self::ChecksumMismatch { .. } => "ChecksumMismatch",
            Self::VerifyFailed { .. } => "VerifyFailed",
            Self::NoSuchEntry { .. } => "NoSuchEntry",
            Self::NotFound { .. } => "NotFound",
            Self::FieldOverflow { .. } => "FieldOverflow",
            Self::ArchiveTooLarge { .. } => "ArchiveTooLarge",
            Self::NotAResource { .. } => "NotAResource",
            Self::WrongEncoding { .. } => "WrongEncoding",
            Self::NoXmlView { .. } => "NoXmlView",
            Self::NameCollision { .. } => "NameCollision",
            Self::AlreadyExists { .. } => "AlreadyExists",
            Self::Claimed { .. } => "Claimed",
            Self::BadPath { .. } => "BadPath",
            Self::Overlapping { .. } => "Overlapping",
            Self::Cancelled { .. } => "Cancelled",
            Self::BadRbf { .. } => "BadRbf",
            Self::BadPso { .. } => "BadPso",
            Self::BadMeta { .. } => "BadMeta",
            Self::UnsupportedPso { .. } => "UnsupportedPso",
            Self::UnsupportedMeta { .. } => "UnsupportedMeta",
            Self::UnrepresentableRbf { .. } => "UnrepresentableRbf",
            Self::NotRbfXml { .. } => "NotRbfXml",
            Self::NotPsoXml { .. } => "NotPsoXml",
            Self::NotMetaXml { .. } => "NotMetaXml",
            Self::WrongKind { .. } => "WrongKind",
        }
    }

    /// The container failure an `io::Error` is carrying, if it is one.
    /// # Errors
    /// The `io::Error` unchanged, when it wasn't carrying one.
    pub fn carried(source: io::Error) -> std::result::Result<Self, io::Error> {
        source.downcast::<Self>()
    }

    pub(crate) fn into_io(self) -> io::Error {
        io::Error::other(self)
    }

    pub(crate) fn recovered(offset: u64, source: io::Error) -> Self {
        Self::carried(source).unwrap_or_else(|source| Self::Io { offset, source })
    }
}

/// Result of a container operation.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{Category, Error, NoWrite};

    const VARIANTS: usize = 45;

    fn name(error: &Error) -> &'static str {
        error.name()
    }

    fn io() -> std::io::Error {
        std::io::Error::other("something below us failed")
    }

    fn corrupt() -> Vec<Error> {
        vec![
            // The other spelling of this variant is in `refused()`.
            Error::NotAnArchive {
                base: 0,
                found: crate::format::Version::Rpf7.magic(),
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
            Error::ChecksumMismatch {
                entry: 0,
                recorded: crate::manifest::Checksum::of(b"as extracted"),
                found: crate::manifest::Checksum::of(b"as it is now"),
            },
            Error::VerifyFailed {
                checked: 27,
                failed: 1,
            },
            Error::BadRbf {
                offset: 7,
                cause: crate::metadata::rbf::Malformed::Truncated,
            },
            Error::BadPso {
                offset: 7,
                cause: crate::metadata::pso::Malformed::NotPso,
            },
            Error::BadMeta {
                offset: 0x10,
                cause: crate::metadata::meta::Malformed::NotMeta,
            },
        ]
    }

    fn refused() -> Vec<Error> {
        vec![
            Error::NotAnArchive {
                base: 512,
                found: *b"hell",
            },
            Error::FieldOverflow {
                path: "big.bin".to_owned(),
                what: "compressed size",
                len: 1 << 24,
                limit: (1 << 24) - 1,
            },
            Error::ArchiveTooLarge {
                path: "data/vehicles.meta".to_owned(),
                reached: 4_294_967_296,
                limit: 4_294_966_784,
            },
            Error::NotAResource {
                path: "x.ytd".to_owned(),
                reason: "the payload is shorter than a resource header",
            },
            Error::WrongEncoding {
                path: "data/vehicles.ymt".to_owned(),
                held: crate::metadata::Encoding::Rbf,
                offered: crate::metadata::Encoding::Xml,
            },
            Error::NoXmlView {
                path: "data/vehicles.ymt".to_owned(),
                held: Some(crate::metadata::Encoding::Text),
            },
            Error::BadPath {
                path: "../escape".to_owned(),
                reason: "leaves the archive",
            },
            Error::AlreadyExists {
                path: "data/notes.txt".to_owned(),
            },
            Error::Claimed {
                path: "data/notes.txt".to_owned(),
                held: "a rename",
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
                path: "data".to_owned(),
                found: "directory",
                wanted: "file",
            },
            Error::NotRbfXml {
                position: 12,
                cause: crate::metadata::rbf::NotRbf::Empty,
            },
            Error::NotPsoXml {
                position: 12,
                cause: crate::metadata::pso::NotPsoXml::Empty,
            },
            Error::NotMetaXml {
                position: 12,
                cause: crate::metadata::meta::NotMetaXml::Empty,
            },
        ]
    }

    fn the_rest() -> Vec<(Error, Category)> {
        vec![
            (
                Error::Io {
                    offset: 0,
                    source: io(),
                },
                Category::Io,
            ),
            (
                Error::Contents {
                    name: "donor.bin".to_owned(),
                    source: io(),
                },
                Category::Io,
            ),
            (Error::NeedsKey { tag: 0x0FFF_FFF9 }, Category::NeedsKey),
            (
                Error::WrongKey {
                    tag: 0x0FEF_FFFF,
                    scheme: "NG",
                    tried: 1,
                },
                Category::NeedsKey,
            ),
            (
                Error::CannotWriteEncrypted {
                    tag: 0x0FEF_FFFF,
                    reason: NoWrite::NoInverse,
                },
                Category::Unsupported,
            ),
            (
                Error::CannotRenameKeyed {
                    path: "dlc.rpf".to_owned(),
                    to: "other.rpf".to_owned(),
                    tag: 0x0FEF_FFFF,
                    scheme: "NG",
                },
                Category::Unsupported,
            ),
            (
                Error::UnsupportedVersion {
                    base: 0,
                    version: 2,
                    found: *b"RPF2",
                },
                Category::Unsupported,
            ),
            (
                Error::UnrecognisedExecutable {
                    what: "AES key and hash lookup table",
                    missing: &["the hash lookup table"],
                    found: 1,
                    wanted: 2,
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
            (
                Error::UnrepresentableRbf {
                    cause: crate::metadata::rbf::Unrepresentable::EmptyBlob,
                },
                Category::Unsupported,
            ),
            (
                Error::UnsupportedPso {
                    cause: crate::metadata::pso::Unsupported::DataType {
                        code: 0xFF,
                        subtype: 0xFF,
                    },
                },
                Category::Unsupported,
            ),
            (
                Error::UnsupportedMeta {
                    cause: crate::metadata::meta::Unsupported::DataType { code: 0xFF },
                },
                Category::Unsupported,
            ),
        ]
    }

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
    fn what_the_bytes_claim_decides_who_has_to_act_on_them() {
        for (found, expected) in [
            (crate::format::Version::Rpf7.magic(), Category::Corrupt),
            (*b"RPF2", Category::Corrupt),
            (*b"hell", Category::Refused),
            ([0; 4], Category::Refused),
            (*b"PK\x03\x04", Category::Refused),
        ] {
            let error = Error::NotAnArchive { base: 0, found };
            assert_eq!(error.category(), expected, "{found:02x?}");
        }
    }

    #[test]
    fn the_taxonomy_covers_every_variant() {
        // `NotAnArchive` is listed twice because its category is decided by
        // the bytes it carries.
        let named: BTreeSet<&str> = taxonomy().iter().map(|(error, _)| name(error)).collect();
        assert_eq!(
            named.len(),
            VARIANTS,
            "the tables name {} of {VARIANTS} variants",
            named.len()
        );
    }

    /// Every variant `Error` declares, read off this source text (four-space, upper-case start).
    fn declared_variants() -> Vec<String> {
        let source = include_str!("error.rs");
        let mut found = Vec::new();
        let mut inside = false;
        for line in source.lines() {
            if line == "pub enum Error {" {
                inside = true;
                continue;
            }
            if !inside {
                continue;
            }
            if line == "}" {
                break;
            }
            let Some(rest) = line.strip_prefix("    ") else {
                continue;
            };
            if !rest.starts_with(|first: char| first.is_ascii_uppercase()) {
                continue;
            }
            found.push(rest.trim_end_matches(" {").to_owned());
        }
        found
    }

    #[test]
    fn the_variant_count_is_the_one_the_enum_declares() {
        // Neither the tables nor `VARIANTS` is the enum: this reads the
        // declaration itself, so a new variant makes the count wrong here.
        let declared = declared_variants();
        assert!(
            declared.len() > 20,
            "the enum was not found in this file: {declared:?}"
        );
        assert_eq!(
            declared.len(),
            VARIANTS,
            "`Error` declares {} variants and `VARIANTS` says {VARIANTS}: {declared:?}",
            declared.len()
        );

        let named: BTreeSet<&str> = taxonomy().iter().map(|(error, _)| name(error)).collect();
        let declared: BTreeSet<&str> = declared.iter().map(String::as_str).collect();
        assert_eq!(
            named, declared,
            "the tables and the enum do not name the same variants"
        );
    }
}
