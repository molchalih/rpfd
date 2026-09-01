//! The container version seam: what varies between container versions, and the
//! pure functions over it. [`rpf7`] is the only encoding this build reads;
//! [`unsupported_version`] recognises the others in order to refuse them.

pub mod crypto;
pub mod resource;
pub mod rpf7;

use serde::{Deserialize, Serialize};

use crate::{
    entry::Entry,
    error::{Error, Result},
};

// Re-exported because `inspect` and the `rpf` binary reach them by this path.
pub use resource::{MAGIC_RSC7, RESOURCE_HEADER_LEN, resource_len};

/// A container version this build reads. Closed on purpose: an unimplemented
/// version is refused by its own name, never parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Version {
    /// GTA V Legacy and Enhanced, and `FiveM`. [`rpf7`].
    Rpf7,
}

/// The compressor a version's payloads are written with, recorded beside the
/// version rather than derived from it: one version number can carry two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Codec {
    /// Raw DEFLATE — a zlib stream with the two-byte header removed, inflated
    /// with a window of -15.
    Deflate,
}

/// A length that is an array bound in one place and a byte offset in another.
/// Widening only, and `const`, which `usize::try_from` is not.
pub(crate) const fn widen(len: usize) -> u64 {
    len as u64
}

/// The most bytes any version's header occupies: a reader fills this much
/// before it knows which version it is looking at.
pub const MAX_HEADER_LEN: usize = rpf7::HEADER_LEN;

/// The fewest bytes any version's header occupies. Short of this, nothing past
/// the magic can be trusted, so the magic is not read either.
const MIN_HEADER_LEN: usize = rpf7::HEADER_LEN;

impl Version {
    /// Every version this build has a codec for.
    pub const ALL: &'static [Self] = &[Self::Rpf7];

    /// The version whose magic these four bytes are, or `None` for every other
    /// four bytes there are.
    #[must_use]
    pub fn of(magic: [u8; 4]) -> Option<Self> {
        match magic {
            rpf7::MAGIC => Some(Self::Rpf7),
            _ => None,
        }
    }

    /// The four bytes an archive of this version begins with, as they appear on
    /// disk.
    #[must_use]
    pub const fn magic(self) -> [u8; 4] {
        match self {
            Self::Rpf7 => rpf7::MAGIC,
        }
    }

    /// The version number, as every error message spells it.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Rpf7 => rpf7::NUMBER,
        }
    }

    /// Length of the header, and therefore the offset the entry table begins
    /// at.
    #[must_use]
    pub const fn header_len(self) -> u64 {
        match self {
            Self::Rpf7 => widen(rpf7::HEADER_LEN),
        }
    }

    /// Length of one row of the entry table, in bytes.
    #[must_use]
    pub const fn row_len(self) -> u64 {
        match self {
            Self::Rpf7 => widen(rpf7::ROW_LEN),
        }
    }

    /// The unit an entry's offset field counts in.
    #[must_use]
    pub const fn block_len(self) -> u64 {
        match self {
            Self::Rpf7 => rpf7::BLOCK_LEN,
        }
    }

    /// Whether a resource payload of this length — or a compressed-size field
    /// carrying this value — leaves the row saying nothing about the payload's
    /// extent. The only spelling of that boundary, asked by both sides.
    pub(crate) const fn size_field_saturates(self, len: u64) -> bool {
        match self {
            Self::Rpf7 => rpf7::size_field_saturates(len),
        }
    }

    /// The length a resource payload's transform is keyed by, given the
    /// payload's length on disk. Both the read and the write side derive it
    /// here and nowhere else; [`rpf7::resource_key_len`] carries the rule.
    pub(crate) const fn resource_key_len(self, len: u64) -> u64 {
        match self {
            Self::Rpf7 => rpf7::resource_key_len(len),
        }
    }

    /// The compressor this version's payloads are written with.
    #[must_use]
    pub const fn codec(self) -> Codec {
        match self {
            Self::Rpf7 => Codec::Deflate,
        }
    }

    /// The encryption tag meaning "not encrypted".
    #[must_use]
    pub const fn open(self) -> u32 {
        match self {
            Self::Rpf7 => rpf7::ENCRYPTION_OPEN,
        }
    }

    /// Whether an archive carrying this tag can be read without a key.
    #[must_use]
    pub const fn is_open(self, tag: u32) -> bool {
        tag == self.open()
    }

    /// Whether a binary entry carrying this value in its own encryption field
    /// is stored in the clear. Asked of the entry's field, not the archive's
    /// tag; both questions have to be asked.
    #[must_use]
    pub const fn entry_is_open(self, encryption: u32) -> bool {
        match self {
            Self::Rpf7 => encryption == rpf7::ENTRY_OPEN,
        }
    }

    /// Which transform an archive carrying this tag is under, and under which
    /// key, or `None` — which covers both "not encrypted", the question
    /// [`Version::is_open`] answers, and a tag with no transform here.
    #[must_use]
    pub const fn scheme(self, tag: u32) -> Option<crypto::Scheme> {
        match self {
            Self::Rpf7 => rpf7::scheme(tag),
        }
    }

    /// The lowest offset, relative to an archive's base, that a payload may
    /// occupy: past the header, the entry table and the names blob. One sum for
    /// the reader that checks against it and the writer that aligns up from it.
    #[must_use]
    pub const fn payload_floor(self, entry_count: u64, names_len: u64) -> u64 {
        self.header_len()
            .saturating_add(entry_count.saturating_mul(self.row_len()))
            .saturating_add(names_len)
    }

    /// Whether one entry row of this version is exactly one cipher block, on a
    /// block boundary of the transform that covers the entry table. True for
    /// `RPF7`, which is what lets an in-place patch rewrite one row.
    #[must_use]
    pub const fn row_is_a_cipher_block(self) -> bool {
        let block = widen(crypto::CIPHER_BLOCK_LEN);
        self.row_len() == block && self.header_len().is_multiple_of(block)
    }

    /// Where one entry's row begins, relative to the archive's base, or `None`
    /// when that offset does not fit a `u64`.
    #[must_use]
    pub fn row_at(self, index: u32) -> Option<u64> {
        u64::from(index)
            .checked_mul(self.row_len())
            .and_then(|by| self.header_len().checked_add(by))
    }

    /// Whether a payload of this length fits the compressed-size field of this
    /// version's row. Asked by the writer before it chooses to deflate.
    #[must_use]
    pub const fn holds_compressed_len(self, len: u64) -> bool {
        match self {
            Self::Rpf7 => rpf7::holds_compressed_len(len),
        }
    }

    /// One entry from one row of the entry table, or `None` when the slice is
    /// shorter than [`Version::row_len`].
    #[must_use]
    pub fn decode_row(self, bytes: &[u8]) -> Option<Entry> {
        match self {
            Self::Rpf7 => rpf7::decode_row(bytes),
        }
    }

    /// One directory's row.
    #[must_use]
    pub fn directory_row(self, name_offset: u32, first_child: u32, child_count: u32) -> Row {
        match self {
            Self::Rpf7 => Row(RowBytes::Rpf7(rpf7::directory_row(
                name_offset,
                first_child,
                child_count,
            ))),
        }
    }

    /// One file's row, with every value checked against the field that has to
    /// hold it.
    ///
    /// # Errors
    ///
    /// [`Error::FieldOverflow`] for a value this version's row cannot
    /// represent, and [`Error::ArchiveTooLarge`] for a payload laid out past
    /// what this version addresses.
    pub fn file_row(self, path: &str, fields: &FileFields) -> Result<Row> {
        match self {
            Self::Rpf7 => Ok(Row(RowBytes::Rpf7(rpf7::file_row(path, fields)?))),
        }
    }

    /// The names blob for a list of names, in entry-table order, and where each
    /// one landed in it.
    ///
    /// # Errors
    ///
    /// [`Error::FieldOverflow`] when the names outgrow what the header can
    /// describe.
    pub fn plan_names<'a, I: IntoIterator<Item = &'a str>>(self, names: I) -> Result<NamesPlan> {
        match self {
            Self::Rpf7 => rpf7::plan_names(names),
        }
    }
}

/// The container version named by the four bytes at an archive's base, when it
/// is a version this build does not read. Both byte orders are recognised: the
/// convention changes at version 6, and PC `RPF7` and `RPF8` are stored
/// reversed as `7FPR` and `8FPR`.
#[must_use]
pub fn unsupported_version(magic: [u8; 4]) -> Option<u8> {
    if Version::of(magic).is_some() {
        return None;
    }
    let ([b'R', b'P', b'F', digit] | [digit, b'F', b'P', b'R']) = magic else {
        return None;
    };
    if !digit.is_ascii_digit() {
        return None;
    }
    digit.checked_sub(b'0')
}

/// What an archive's header says about it. The magic is not a field: a
/// [`Header`] cannot exist without it having matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The version that wrote it.
    pub version: Version,
    /// Entries in the table, the root directory included.
    pub entry_count: u32,
    /// Length of the names blob, in bytes.
    pub names_len: u32,
    /// The archive's encryption tag.
    pub encryption: u32,
}

impl Header {
    /// The header these bytes are, or why they are not one. `bytes` is however
    /// much of the first [`MAX_HEADER_LEN`] there was; `base` is where they
    /// came from, which for a nested archive is its own base.
    ///
    /// # Errors
    ///
    /// [`Error::NotAnArchive`] if the magic is nothing this format uses or the
    /// bytes are too short to hold a header, and [`Error::UnsupportedVersion`]
    /// if the magic names a version this build does not read.
    pub fn read(bytes: &[u8], base: u64) -> Result<Self> {
        let magic: [u8; 4] = bytes
            .get(0..4)
            .and_then(|start| start.try_into().ok())
            .unwrap_or_default();
        // Nothing past the magic can be trusted, so the magic is not worth
        // reading a version out of either.
        if bytes.len() < MIN_HEADER_LEN {
            return Err(Error::NotAnArchive { base, found: magic });
        }
        let Some(version) = Version::of(magic) else {
            // Discarding the version would report a sound archive of another
            // version as a malformed one.
            return Err(match unsupported_version(magic) {
                Some(version) => Error::UnsupportedVersion {
                    base,
                    version,
                    found: magic,
                },
                None => Error::NotAnArchive { base, found: magic },
            });
        };
        match version {
            Version::Rpf7 => rpf7::read_header(bytes),
        }
        .ok_or(Error::NotAnArchive { base, found: magic })
    }

    /// The bytes an archive of this version begins with.
    #[must_use]
    pub fn write(&self) -> Vec<u8> {
        match self.version {
            Version::Rpf7 => rpf7::write_header(self).to_vec(),
        }
    }
}

/// One row of the entry table, in the width its version gives it: an enum over
/// fixed-size arrays, so a writer allocates nothing per entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row(RowBytes);

/// The row's bytes, one variant per version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowBytes {
    /// [`rpf7::ROW_LEN`] bytes.
    Rpf7([u8; rpf7::ROW_LEN]),
}

impl Row {
    /// The row exactly as it goes on disk.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            RowBytes::Rpf7(row) => row,
        }
    }

    /// The same row under `seal`. Sound for one row on its own only where
    /// [`Version::row_is_a_cipher_block`] holds, which is the caller's to ask.
    #[must_use]
    pub fn sealed(self, seal: &crypto::Seal) -> Self {
        match self.0 {
            RowBytes::Rpf7(mut row) => {
                seal.apply(&mut row);
                Self(RowBytes::Rpf7(row))
            }
        }
    }
}

/// The fields of one file's entry row, in the widths the version has yet to
/// narrow them to. Wide on purpose, so [`Version::file_row`] can refuse a
/// value rather than quietly cut it down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFields {
    /// Offset of the entry's name within the names blob.
    pub name_offset: u32,
    /// Payload offset, in the version's block unit.
    pub block: u64,
    /// On-disk length of the payload. Zero is the stored sentinel.
    pub compressed_len: u64,
    /// What the payload is, and the two numbers only that kind has.
    pub content: Content,
}

/// What a file's payload is. Offsets 8 and 12 of an `RPF7` row are an
/// uncompressed size and an encryption word on a binary entry, and two
/// page-flag words on a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Content {
    /// Plain bytes.
    Binary {
        /// Length the payload inflates to, which is also its real length when
        /// it is stored.
        uncompressed_len: u32,
        /// The per-entry encryption field.
        encryption: u32,
    },
    /// An `RSC7` resource, whose length is carried by its flags rather than
    /// stated. [`resource_len`].
    Resource {
        /// System page flags.
        system_flags: u32,
        /// Graphics page flags.
        graphics_flags: u32,
    },
}

/// A names blob laid out for writing, and where each entry's name landed in it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NamesPlan {
    /// The blob as it goes on disk.
    pub blob: Vec<u8>,
    /// One offset per entry, in the order the names came.
    pub offsets: Vec<u32>,
}

/// Where one entry's name lies in the names blob. A span rather than an owned
/// `String`: nothing stops an archive pointing every entry at one long name,
/// which would make opening it cost `entry_count × names_len`.
#[derive(Debug, Clone, Copy)]
struct Span {
    /// Offset into the names blob.
    at: u32,
    /// Length in bytes, up to but not including the terminator.
    len: u32,
}

/// Every entry's name, in the form its version stores them. Names do not
/// universalise — some versions store hashes rather than strings — so the
/// shape stays behind the seam and `Archive` asks this type.
#[derive(Debug, Clone)]
pub struct Names(Stored);

/// How one version's names are held, once resolved.
#[derive(Debug, Clone)]
enum Stored {
    /// A blob of NUL-terminated strings and one span per entry. `RPF7`.
    Blob {
        /// The blob exactly as it appeared on disk, `namesLength` bytes and no
        /// more.
        blob: Vec<u8>,
        /// One span per entry, in entry-table order.
        spans: Vec<Span>,
    },
}

impl Names {
    /// Locates every entry's name, refusing anything the version's encoding
    /// cannot account for. Done once, so [`Names::at`] has nothing left to
    /// find.
    ///
    /// # Errors
    ///
    /// [`Error::BadName`] for a name the encoding does not resolve.
    pub fn parse(version: Version, blob: Vec<u8>, entries: &[Entry]) -> Result<Self> {
        match version {
            Version::Rpf7 => {
                let spans = rpf7::resolve_names(&blob, entries)?;
                Ok(Self(Stored::Blob { blob, spans }))
            }
        }
    }

    /// One entry's own name, without its parents.
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchEntry`] if the index is past the end, and
    /// [`Error::BadName`] if the bytes at the entry's name offset are not
    /// UTF-8.
    pub fn at(&self, index: u32) -> Result<&str> {
        let Stored::Blob { blob, spans } = &self.0;
        let span = usize::try_from(index)
            .ok()
            .and_then(|i| spans.get(i))
            .copied()
            .ok_or(Error::NoSuchEntry {
                index,
                entry_count: u32::try_from(spans.len()).unwrap_or(u32::MAX),
            })?;

        let bad = || Error::BadName {
            entry: index,
            name_offset: span.at,
            names_len: u32::try_from(blob.len()).unwrap_or(u32::MAX),
        };
        let start = usize::try_from(span.at).unwrap_or(usize::MAX);
        let end = start.saturating_add(usize::try_from(span.len).unwrap_or(usize::MAX));
        let raw = blob.get(start..end).ok_or_else(bad)?;
        std::str::from_utf8(raw).map_err(|_| bad())
    }

    /// The names blob exactly as it appears on disk.
    #[must_use]
    pub fn blob(&self) -> &[u8] {
        let Stored::Blob { blob, .. } = &self.0;
        blob
    }
}

/// The little-endian `u16` at `at`, or `None` if `bytes` is too short to hold
/// one there. Every fixed-width field this build reads is little-endian, and
/// only the caller knows whether a short buffer is possible.
#[must_use]
pub fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    let raw: [u8; 2] = bytes.get(at..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(raw))
}

/// The little-endian 24-bit field at `at`, widened, or `None` if `bytes` is too
/// short to hold one there: an `RPF7` entry's compressed size and its block
/// offset are both three bytes wide.
#[must_use]
pub fn u24_at(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(3)?;
    let raw = bytes.get(at..end)?;
    let (low, mid, high) = (*raw.first()?, *raw.get(1)?, *raw.get(2)?);
    Some(u32::from(low) | (u32::from(mid) << 8) | (u32::from(high) << 16))
}

/// The little-endian `u32` at `at`, or `None` if `bytes` is too short to hold
/// one there.
#[must_use]
pub fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let raw: [u8; 4] = bytes.get(at..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

/// Whether two names address the same entry. Path components resolve
/// case-insensitively, so two children of one directory differing only in case
/// are one name and the second is unreachable.
#[must_use]
pub fn same_name(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// The key a name is unique under among its siblings: exactly the equivalence
/// [`same_name`] tests, as a value a writer can put in a map.
#[must_use]
pub fn folded(name: &str) -> String {
    name.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_row_is_a_cipher_block_only_because_three_numbers_agree() {
        // An in-place patch of one row of an encrypted table is sound only
        // while these three constants agree.
        assert_eq!(rpf7::ROW_LEN, crypto::CIPHER_BLOCK_LEN);
        assert_eq!(rpf7::HEADER_LEN % crypto::CIPHER_BLOCK_LEN, 0);
        assert!(Version::Rpf7.row_is_a_cipher_block());
    }

    #[test]
    fn a_field_read_past_the_end_is_none_rather_than_a_panic() {
        // An entry table can end mid-row, and every one of these is a slice
        // index in disguise.
        let row = [0x01_u8, 0x02, 0x03];
        assert_eq!(u16_at(&row, 0), Some(0x0201));
        assert_eq!(u24_at(&row, 0), Some(0x0003_0201));
        assert_eq!(u32_at(&row, 0), None);
        assert_eq!(u16_at(&row, 2), None);
        assert_eq!(u24_at(&row, 1), None);
        assert_eq!(u16_at(&row, usize::MAX), None);
    }

    #[test]
    fn a_binary_entry_is_in_the_clear_only_when_its_own_field_is_zero() {
        // The per-entry encryption field takes two values: 0 in the clear, 1
        // under the archive's transform.
        let version = Version::Rpf7;
        assert_eq!(rpf7::ENTRY_OPEN, 0);
        assert!(version.entry_is_open(rpf7::ENTRY_OPEN));
        assert!(!version.entry_is_open(1), "1 is the value that means keyed");
        for keyed in [2_u32, 0x0FEF_FFFF, u32::MAX] {
            assert!(
                !version.entry_is_open(keyed),
                "{keyed} is not the field's open value"
            );
        }
        // The archive's tag and the entry's field are different questions over
        // different numbers.
        assert!(!version.entry_is_open(version.open()));
    }

    #[test]
    fn the_payload_floor_is_the_three_regions_before_it() {
        // Eleven entries and a 144-byte names blob.
        let version = Version::Rpf7;
        assert_eq!(version.payload_floor(11, 144), 16 + 11 * 16 + 144);
        assert_eq!(version.payload_floor(0, 0), version.header_len());
    }

    /// The writer's guard against choosing a deflated form the row cannot
    /// describe, on the side where it says no as well as the side where it
    /// says yes. The compressed size is three bytes.
    #[test]
    fn the_compressed_size_field_is_three_bytes_wide_in_both_directions() {
        let version = Version::Rpf7;
        assert!(version.holds_compressed_len(0));
        assert!(
            version.holds_compressed_len(0x00FF_FFFF),
            "the largest a 24-bit field holds"
        );
        assert!(
            !version.holds_compressed_len(0x0100_0000),
            "one byte past it does not fit"
        );
        assert!(!version.holds_compressed_len(u64::MAX));
    }

    #[test]
    fn a_row_offset_is_the_header_and_the_rows_before_it() {
        let version = Version::Rpf7;
        assert_eq!(version.row_at(0), Some(version.header_len()));
        assert_eq!(version.row_at(10), Some(16 + 10 * 16));
        // The one arithmetic that could fail: a row past `u64`.
        assert!(version.row_at(u32::MAX).is_some());
    }

    #[test]
    fn folding_a_name_and_comparing_two_are_the_same_rule() {
        // One spelling goes in a map and the other is on the path of every
        // lookup; they must not be able to disagree.
        const NAMES: &[&str] = &[
            "x64",
            "X64",
            "x64/",
            "vehicles.rpf",
            "VEHICLES.RPF",
            "Vehicles.Rpf",
            "",
            "ä",
            "Ä",
        ];
        for &a in NAMES {
            for &b in NAMES {
                assert_eq!(
                    same_name(a, b),
                    folded(a) == folded(b),
                    "{a:?} against {b:?}"
                );
            }
        }
    }

    #[test]
    fn every_other_version_is_recognised_in_both_byte_orders() {
        // The convention changes at version 6, so a reader that sniffs one
        // order reports half of these as "not an archive".
        for (magic, version) in [
            (*b"RPF0", 0_u8),
            (*b"RPF2", 2),
            (*b"RPF3", 3),
            (*b"RPF4", 4),
            (*b"RPF6", 6),
            (*b"8FPR", 8),
            (*b"2FPR", 2),
        ] {
            assert_eq!(unsupported_version(magic), Some(version), "{magic:02x?}");
            assert_eq!(Version::of(magic), None, "{magic:02x?}");
        }
    }

    #[test]
    fn the_console_spelling_of_rpf7_is_a_version_this_build_does_not_read() {
        // `RPF7` on disk is version 7 the other way round; this build reads
        // the `7FPR` spelling.
        assert_eq!(unsupported_version(*b"RPF7"), Some(7));
    }

    #[test]
    fn a_versions_number_is_the_digit_its_own_magic_carries() {
        // One fact spelt twice: the number is what a refusal names and the
        // magic is what it was recognised by, so they must not drift.
        for &version in Version::ALL {
            let magic = version.magic();
            let digit = magic
                .iter()
                .copied()
                .find(u8::is_ascii_digit)
                .expect("every magic carries its version as an ASCII digit");
            assert_eq!(
                Some(version.number()),
                digit.checked_sub(b'0'),
                "{magic:02x?}"
            );
        }
    }

    #[test]
    fn the_version_this_build_reads_is_never_named_as_one_it_does_not() {
        // A magic this answers `Some` for is by construction one that cannot
        // be opened.
        assert_eq!(unsupported_version(Version::Rpf7.magic()), None);
        assert_eq!(Version::of(Version::Rpf7.magic()), Some(Version::Rpf7));
    }

    #[test]
    fn bytes_that_are_no_rpf_magic_at_all_are_not_given_a_version() {
        for magic in [*b"RPFx", *b"xFPR", *b"RSC7", [0_u8; 4], *b"PK\x03\x04"] {
            assert_eq!(unsupported_version(magic), None, "{magic:02x?}");
            assert_eq!(Version::of(magic), None, "{magic:02x?}");
        }
    }

    #[test]
    fn a_header_of_another_version_is_refused_by_its_own_name() {
        // Not `Corrupt`: nothing is malformed.
        let mut bytes = vec![0_u8; MAX_HEADER_LEN];
        bytes.splice(0..4, *b"RPF2");
        assert!(matches!(
            Header::read(&bytes, 512),
            Err(Error::UnsupportedVersion {
                base: 512,
                version: 2,
                ..
            })
        ));
    }

    #[test]
    fn a_file_too_short_to_hold_a_header_is_not_an_archive_of_any_version() {
        let bytes = *b"RPF2";
        assert!(matches!(
            Header::read(&bytes, 0),
            Err(Error::NotAnArchive { base: 0, .. })
        ));
        assert!(matches!(
            Header::read(&[], 0),
            Err(Error::NotAnArchive { base: 0, .. })
        ));
    }

    #[test]
    fn a_header_round_trips_through_the_seam() {
        let header = Header {
            version: Version::Rpf7,
            entry_count: 11,
            names_len: 144,
            encryption: Version::Rpf7.open(),
        };
        let bytes = header.write();
        assert_eq!(
            bytes.len(),
            usize::try_from(header.version.header_len()).ok().unwrap()
        );
        assert_eq!(Header::read(&bytes, 0).expect("its own bytes"), header);
    }

    #[test]
    fn a_row_is_as_wide_as_its_version_says() {
        let row = Version::Rpf7.directory_row(0, 1, 4);
        assert_eq!(
            u64::try_from(row.as_bytes().len()).ok(),
            Some(Version::Rpf7.row_len())
        );
    }

    #[test]
    fn every_name_is_found_where_the_blob_puts_it() {
        let version = Version::Rpf7;
        let plan = version.plan_names(["", "data", "x64"]).expect("fits");
        let entries: Vec<Entry> = plan
            .offsets
            .iter()
            .map(|&at| Entry {
                name_offset: at,
                kind: crate::entry::EntryKind::Directory {
                    first_child: 0,
                    child_count: 0,
                },
            })
            .collect();
        let names = Names::parse(version, plan.blob.clone(), &entries).expect("resolves");
        assert_eq!(names.at(0).expect("root"), "");
        assert_eq!(names.at(1).expect("data"), "data");
        assert_eq!(names.at(2).expect("x64"), "x64");
        assert!(matches!(
            names.at(3),
            Err(Error::NoSuchEntry { index: 3, .. })
        ));
        assert_eq!(names.blob(), plan.blob.as_slice());
    }
}
