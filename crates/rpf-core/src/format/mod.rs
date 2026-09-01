//! The container version seam: what varies between versions, and the pure functions over it.

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

/// A container version this build reads; an unimplemented one is refused by name, never parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Version {
    /// GTA V Legacy and Enhanced, and `FiveM`.
    Rpf7,
}

/// Compressor a version's payloads use, kept beside it since one version number can carry two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Codec {
    /// Raw DEFLATE: a zlib stream with the two-byte header removed, inflated with a window of -15.
    Deflate,
}

pub(crate) const fn widen(len: usize) -> u64 {
    len as u64
}

/// Most bytes any version's header occupies, filled before the version is known.
pub const MAX_HEADER_LEN: usize = rpf7::HEADER_LEN;

const MIN_HEADER_LEN: usize = rpf7::HEADER_LEN;

impl Version {
    /// Every version this build has a codec for.
    pub const ALL: &'static [Self] = &[Self::Rpf7];

    /// Version named by this magic, or `None` for anything else.
    #[must_use]
    pub fn of(magic: [u8; 4]) -> Option<Self> {
        match magic {
            rpf7::MAGIC => Some(Self::Rpf7),
            _ => None,
        }
    }

    /// Four bytes an archive of this version begins with, as they appear on disk.
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

    /// Length of the header, and the offset the entry table begins at.
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

    pub(crate) const fn size_field_saturates(self, len: u64) -> bool {
        match self {
            Self::Rpf7 => rpf7::size_field_saturates(len),
        }
    }

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

    /// Whether a binary entry's encryption field means stored in the clear, not the archive's tag.
    #[must_use]
    pub const fn entry_is_open(self, encryption: u32) -> bool {
        match self {
            Self::Rpf7 => encryption == rpf7::ENTRY_OPEN,
        }
    }

    /// Transform and key an archive's tag names, or `None` for open or unrecognised tags.
    #[must_use]
    pub const fn scheme(self, tag: u32) -> Option<crypto::Scheme> {
        match self {
            Self::Rpf7 => rpf7::scheme(tag),
        }
    }

    /// Lowest offset a payload may occupy: past the header, entry table, and names blob.
    #[must_use]
    pub const fn payload_floor(self, entry_count: u64, names_len: u64) -> u64 {
        self.header_len()
            .saturating_add(entry_count.saturating_mul(self.row_len()))
            .saturating_add(names_len)
    }

    /// Whether one row is exactly one cipher block on a block boundary (true for `RPF7`).
    #[must_use]
    pub const fn row_is_a_cipher_block(self) -> bool {
        let block = widen(crypto::CIPHER_BLOCK_LEN);
        self.row_len() == block && self.header_len().is_multiple_of(block)
    }

    /// Where one entry's row begins, relative to the archive's base, or `None` on overflow.
    #[must_use]
    pub fn row_at(self, index: u32) -> Option<u64> {
        u64::from(index)
            .checked_mul(self.row_len())
            .and_then(|by| self.header_len().checked_add(by))
    }

    /// Whether a payload of this length fits this version's compressed-size field.
    #[must_use]
    pub const fn holds_compressed_len(self, len: u64) -> bool {
        match self {
            Self::Rpf7 => rpf7::holds_compressed_len(len),
        }
    }

    /// One entry from one row of the entry table, or `None` if the slice is too short.
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

    /// One file's row, with every value checked against the field that has to hold it.
    /// # Errors
    /// `FieldOverflow` for an oversized value, `ArchiveTooLarge` for an out-of-range payload.
    pub fn file_row(self, path: &str, fields: &FileFields) -> Result<Row> {
        match self {
            Self::Rpf7 => Ok(Row(RowBytes::Rpf7(rpf7::file_row(path, fields)?))),
        }
    }

    /// The names blob for a list of names, and where each one landed.
    /// # Errors
    /// `FieldOverflow` if the names outgrow what the header can describe.
    pub fn plan_names<'a, I: IntoIterator<Item = &'a str>>(self, names: I) -> Result<NamesPlan> {
        match self {
            Self::Rpf7 => rpf7::plan_names(names),
        }
    }
}

/// Version named by these bytes, when unread; both byte orders are recognised (flips at 6).
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

/// What an archive's header says; the magic is not a field, since a `Header` implies it matched.
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
    /// The header these bytes are, or why not; `base` is a nested archive's own base.
    /// # Errors
    /// `NotAnArchive` for an unrecognised or short header, `UnsupportedVersion` for one not read.
    pub fn read(bytes: &[u8], base: u64) -> Result<Self> {
        let magic: [u8; 4] = bytes
            .get(0..4)
            .and_then(|start| start.try_into().ok())
            .unwrap_or_default();
        // Nothing past the magic can be trusted, so it's not worth reading a version out of.
        if bytes.len() < MIN_HEADER_LEN {
            return Err(Error::NotAnArchive { base, found: magic });
        }
        let Some(version) = Version::of(magic) else {
            // Discarding the version would report a sound archive of another one as malformed.
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

/// One entry-table row, sized per version; a fixed-array enum so nothing is allocated per entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row(RowBytes);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowBytes {
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

    /// The same row under `seal`; sound alone only where `row_is_a_cipher_block` holds.
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

/// Fields of one file's entry row, wide so `Version::file_row` can refuse rather than truncate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFields {
    /// Offset of the entry's name within the names blob.
    pub name_offset: u32,
    /// Payload offset, in the version's block unit.
    pub block: u64,
    /// On-disk length of the payload; zero is the stored sentinel.
    pub compressed_len: u64,
    /// What the payload is, and the two numbers only that kind has.
    pub content: Content,
}

/// What a file's payload is: row offsets 8 and 12 read as two words specific to the kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Content {
    /// Plain bytes.
    Binary {
        /// Length the payload inflates to; also its real length when stored.
        uncompressed_len: u32,
        /// The per-entry encryption field.
        encryption: u32,
    },
    /// An `RSC7` resource; length is carried by its flags rather than stated (see `resource_len`).
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

#[derive(Debug, Clone, Copy)]
struct Span {
    at: u32,
    /// Length in bytes, up to but not including the terminator.
    len: u32,
}

/// Every entry's name; kept behind the seam since some versions store hashes rather than strings.
#[derive(Debug, Clone)]
pub struct Names(Stored);

#[derive(Debug, Clone)]
enum Stored {
    /// A blob of NUL-terminated strings and one span per entry. `RPF7`.
    Blob {
        /// The blob exactly as it appeared on disk, `namesLength` bytes and no more.
        blob: Vec<u8>,
        spans: Vec<Span>,
    },
}

impl Names {
    /// Locates every entry's name once, refusing anything the encoding can't account for.
    /// # Errors
    /// `BadName` for a name the encoding does not resolve.
    pub fn parse(version: Version, blob: Vec<u8>, entries: &[Entry]) -> Result<Self> {
        match version {
            Version::Rpf7 => {
                let spans = rpf7::resolve_names(&blob, entries)?;
                Ok(Self(Stored::Blob { blob, spans }))
            }
        }
    }

    /// One entry's own name, without its parents.
    /// # Errors
    /// `NoSuchEntry` if the index is past the end, `BadName` if the name isn't valid UTF-8.
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

/// Little-endian `u16` at `at`, or `None` if `bytes` is too short.
#[must_use]
pub fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    let raw: [u8; 2] = bytes.get(at..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(raw))
}

/// Little-endian 24-bit field at `at`, widened to `u32`, or `None` if `bytes` is too short.
#[must_use]
pub fn u24_at(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(3)?;
    let raw = bytes.get(at..end)?;
    let (low, mid, high) = (*raw.first()?, *raw.get(1)?, *raw.get(2)?);
    Some(u32::from(low) | (u32::from(mid) << 8) | (u32::from(high) << 16))
}

/// Little-endian `u32` at `at`, or `None` if `bytes` is too short.
#[must_use]
pub fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let raw: [u8; 4] = bytes.get(at..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

/// Whether two names address the same entry; path components resolve case-insensitively.
#[must_use]
pub fn same_name(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Key a name is unique under among siblings: the `same_name` equivalence, as a map-able value.
#[must_use]
pub fn folded(name: &str) -> String {
    name.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_row_is_a_cipher_block_only_because_three_numbers_agree() {
        // An in-place patch of one row is sound only while these agree.
        assert_eq!(rpf7::ROW_LEN, crypto::CIPHER_BLOCK_LEN);
        assert_eq!(rpf7::HEADER_LEN % crypto::CIPHER_BLOCK_LEN, 0);
        assert!(Version::Rpf7.row_is_a_cipher_block());
    }

    #[test]
    fn a_field_read_past_the_end_is_none_rather_than_a_panic() {
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
        // The per-entry field takes two values: 0 in the clear, 1 under the archive's transform.
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
        // The archive's tag and the entry's field are different questions over different numbers.
        assert!(!version.entry_is_open(version.open()));
    }

    #[test]
    fn the_payload_floor_is_the_three_regions_before_it() {
        let version = Version::Rpf7;
        assert_eq!(version.payload_floor(11, 144), 16 + 11 * 16 + 144);
        assert_eq!(version.payload_floor(0, 0), version.header_len());
    }

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
        // One spelling goes in a map, the other on every lookup: they must not disagree.
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
        // `RPF7` on disk is version 7 reversed; this build reads the `7FPR` spelling.
        assert_eq!(unsupported_version(*b"RPF7"), Some(7));
    }

    #[test]
    fn a_versions_number_is_the_digit_its_own_magic_carries() {
        // One fact spelt twice: a refusal names the number, recognition uses the magic.
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
