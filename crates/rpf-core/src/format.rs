//! RPF7 container constants and the arithmetic that reads them.
//!
//! Nothing here does I/O. These are the measured facts of the format and the
//! pure functions over them, so that they can be tested without an archive.
//! A rule that both the reader and the writer have to apply the same way —
//! where a payload may begin, how a field is decoded, when two names are one
//! name — belongs here for that reason: two encodings of it are two chances to
//! drift, and the drift is invisible until an archive does not load (§3).
//!
//! Each item names the row of `docs/rpf-format.md` that established it. A row
//! marked `verified` there was measured against a real archive; do not add a
//! constant here for a row that is not.
//!
//! [`unsupported_version`] is the one exception, and it states why it is
//! allowed to be one: nothing is decoded on the strength of it. Recognising a
//! version there is only ever the difference between a refusal that names the
//! version and one that does not.

/// Archive magic, as it appears on disk.
///
/// Reads `7FPR`, not `RPF7` — the four bytes are the little-endian spelling of
/// the version number. Comparing against `RPF7` finds no archive at all, which
/// is how the two nested archives in the sample were missed on the first walk.
///
/// `docs/rpf-format.md`, RPF7 header, `verified`.
pub const MAGIC_RPF7: [u8; 4] = *b"7FPR";

/// The container version named by the four bytes at an archive's base, when it
/// is a version this build does not read.
///
/// [`MAGIC_RPF7`] is the only version implemented here, so it is never named:
/// a magic this answers `Some` for is by construction one that cannot be
/// opened, which leaves the caller nothing to finish (§4).
///
/// **Both byte orders are recognised**, because the convention changes at
/// version 6. `RPF0` to `RPF4` and console `RPF7` are stored `'R','P','F',n`
/// and read as `RPFn` on disk; PC `RPF7` and `RPF8` are stored reversed and
/// read as `7FPR` and `8FPR`. So an archive reading `RPF7` here is the console
/// spelling of version 7, which is a version this build does not read either.
///
/// `docs/rpf-format.md`, "The magic word changes byte order at version 6" —
/// **`secondary`**, read from reference implementations rather than measured
/// here. That is enough for this and for nothing else: a version recognised
/// wrongly costs a less exact refusal, where a version *decoded* wrongly is the
/// failure `AGENTS.md` records. DR-012.
#[must_use]
pub fn unsupported_version(magic: [u8; 4]) -> Option<u8> {
    if magic == MAGIC_RPF7 {
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

/// Resource payload magic, at the start of the payload of any entry whose
/// [`RESOURCE_FLAG`] is set.
///
/// `docs/rpf-format.md`, Resource entries, `verified`.
pub const MAGIC_RSC7: [u8; 4] = *b"RSC7";

/// Length of the archive header, in bytes. The entry table begins immediately
/// after it — not at 2048.
///
/// `docs/rpf-format.md`, Layout, `verified`.
pub const HEADER_LEN: u64 = 16;

/// Length of one entry in the entry table, in bytes, for every entry kind.
///
/// `docs/rpf-format.md`, Entry table, `verified`.
pub const ENTRY_LEN: u64 = 16;

/// The value at offset 4 of an entry that marks it a directory rather than a
/// file. No file entry can produce it, because it would imply a compressed size
/// and offset that cannot both occur.
///
/// `docs/rpf-format.md`, Entry table, `verified`.
pub const DIRECTORY_MARKER: u32 = 0x7FFF_FF00;

/// The encryption tag meaning "not encrypted", ASCII `OPEN`.
///
/// `docs/rpf-format.md`, RPF7 header, `verified`. The other tags in that table
/// are `secondary` and are deliberately absent here until measured.
pub const ENCRYPTION_OPEN: u32 = 0x4E45_504F;

/// The unit that an entry's offset field counts in.
///
/// Offsets are relative to the base of the archive holding the entry, which for
/// a nested archive is not the base of the file.
///
/// `docs/rpf-format.md`, Entry table, `verified` — all 27 payload offsets in the
/// sample are multiples of this.
pub const BLOCK_LEN: u64 = 512;

/// Bit set within an entry's offset field marking the entry a resource.
///
/// `docs/rpf-format.md`, Entry table, `verified`.
pub const RESOURCE_FLAG: u32 = 0x0080_0000;

/// Length of the `RSC7` header that precedes a resource's deflate stream.
///
/// This is the constant behind the correction in `docs/rpf-format.md`: a
/// resource entry's compressed size *includes* these bytes, so its deflate
/// stream is `compressed_size - RESOURCE_HEADER_LEN` bytes long and starts
/// `RESOURCE_HEADER_LEN` into the payload. Reading the full compressed size
/// still inflates correctly, which is why the mistake survives until a rebuild.
///
/// `docs/rpf-format.md`, Compression, `verified` — 20 of 20 entries.
pub const RESOURCE_HEADER_LEN: u64 = 16;

/// The little-endian `u16` at `at`, or `None` if `bytes` is too short to hold
/// one there.
///
/// Every fixed-width field in this format is little-endian, so every reader of
/// one comes through here or its two siblings. They return an `Option` rather
/// than defaulting, because the caller is the only one that knows whether a
/// short buffer is impossible or is the malformed input §6 is about.
#[must_use]
pub fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    let raw: [u8; 2] = bytes.get(at..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(raw))
}

/// The little-endian 24-bit field at `at`, widened, or `None` if `bytes` is too
/// short to hold one there.
///
/// Three bytes, not four: an entry's compressed size and its block offset are
/// both this width. `docs/rpf-format.md`, Entry table, `verified`.
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

/// The lowest offset, relative to an archive's base, that a payload may occupy:
/// past the header, the entry table and the names blob, and nothing else.
///
/// One sum, two readers. `Archive` checks an entry's payload offset against it
/// so that no payload addresses the archive's own structure, and `build` aligns
/// the first payload up from it. Written twice, the reader and the writer would
/// be free to disagree about where an archive's contents begin.
///
/// Saturating rather than checked, and both callers are why: `Archive::parse`
/// has already fitted all three regions inside the archive's length before it
/// asks, and `build` has already refused an entry count that does not fit a
/// `u32`. There is no second failure left to report.
///
/// `docs/rpf-format.md`, Layout, `verified`.
#[must_use]
pub fn payload_floor(entry_count: u64, names_len: u64) -> u64 {
    HEADER_LEN
        .saturating_add(entry_count.saturating_mul(ENTRY_LEN))
        .saturating_add(names_len)
}

/// Whether two names address the same entry.
///
/// Path components resolve case-insensitively here — `Archive::child_named`
/// folds, and `find`, `locate` and `split_at_file` all go through it — so two
/// children of one directory differing only in case are one name, and the
/// second is unreachable by any spelling of its own path.
///
/// That archives *are* stored in ascending name order is `verified`
/// (`docs/rpf-format.md`, Entry ordering); that the runtime *requires*
/// case-folded resolution is `docs/backlog.md` Q1 and is not measured. What is
/// settled is that this crate resolves that way, which is the whole reason
/// `build` has to refuse a collision it could not address afterwards.
#[must_use]
pub fn same_name(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// The key a name is unique under among its siblings.
///
/// Exactly the equivalence [`same_name`] tests — `folded(a) == folded(b)` if
/// and only if `same_name(a, b)`, and a test below says so — as a value that
/// can go in a map, which is what a writer needs to catch a collision before it
/// writes one. Two spellings of one rule in one place, rather than one spelling
/// in the reader and another in the writer: they were in two places, and the
/// writer packed `X64` and `x64` as separate directories that no reader could
/// tell apart.
#[must_use]
pub fn folded(name: &str) -> String {
    name.to_ascii_lowercase()
}

/// Number of pages described by one of a resource's two flag words.
///
/// A resource entry carries no uncompressed size; offsets 8 and 12 of the entry
/// are both flag words. This decodes one of them to a page count, which
/// [`size_from_flags`] scales to a byte count.
///
/// `docs/rpf-format.md`, Resource page flags, `verified`.
#[must_use]
#[expect(
    clippy::arithmetic_side_effects,
    reason = "every term is a masked bit field shifted by a constant; the sum \
              is bounded above by 1+2+4+8+2032+2016+960+384+256 = 5663, which \
              cannot overflow u32"
)]
pub const fn page_count(flags: u32) -> u32 {
    ((flags >> 27) & 0x1)
        + (((flags >> 26) & 0x1) << 1)
        + (((flags >> 25) & 0x1) << 2)
        + (((flags >> 24) & 0x1) << 3)
        + (((flags >> 17) & 0x7F) << 4)
        + (((flags >> 11) & 0x3F) << 5)
        + (((flags >> 7) & 0xF) << 6)
        + (((flags >> 5) & 0x3) << 7)
        + (((flags >> 4) & 0x1) << 8)
}

/// Byte count described by one of a resource's two flag words.
///
/// The low nibble selects the base page size; the rest gives the page count.
/// A resource's uncompressed length is this applied to the system flags plus
/// this applied to the graphics flags.
///
/// `docs/rpf-format.md`, Resource page flags, `verified` — reproduces the exact
/// inflated length of all 20 resources in the sample.
#[must_use]
#[expect(
    clippy::arithmetic_side_effects,
    reason = "the shift amount is masked to 0..=15 so the base size is at most \
              0x200 << 15; multiplied by a page count of at most 5663 the \
              product is under 2^37 and cannot overflow u64"
)]
pub const fn size_from_flags(flags: u32) -> u64 {
    let base = 0x200_u64 << (flags & 0xF);
    base * page_count(flags) as u64
}

/// Uncompressed length of a resource payload, from its two flag words.
///
/// `docs/rpf-format.md`, Resource page flags, `verified`.
#[must_use]
#[expect(
    clippy::arithmetic_side_effects,
    reason = "each half is bounded under 2^37 by size_from_flags, so the sum \
              cannot overflow u64"
)]
pub const fn resource_len(system_flags: u32, graphics_flags: u32) -> u64 {
    size_from_flags(system_flags) + size_from_flags(graphics_flags)
}

/// The `RSC7` header's version field, derived from the two flag words.
///
/// The version is not independent data: it is the top nibble of each flag word,
/// system in the high position and graphics in the low one. This matters for
/// rebuilding, because it means an entry's flags carry its version — there is
/// nothing extra to preserve.
///
/// `docs/rpf-format.md`, Resource page flags, `verified` — reproduces the
/// header version of all 20 resources in the sample, both distinct values.
#[must_use]
pub const fn resource_version(system_flags: u32, graphics_flags: u32) -> u32 {
    (((system_flags >> 28) & 0xF) << 4) | ((graphics_flags >> 28) & 0xF)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every resource in the sample, as measured on 2026-08-26: the two flag
    /// words from the entry table, and the length its payload actually inflated
    /// to. `docs/rpf-format.md`, Resource page flags.
    const MEASURED: &[(u32, u32, u64)] = &[
        (0xA000_0011, 0x2000_0000, 262_144),
        (0xA000_0091, 0x2000_0000, 327_680),
        (0xA000_0050, 0x2000_0000, 262_144),
        (0xA000_0020, 0x2000_0000, 65_536),
        (0xA002_0020, 0x2000_0000, 73_728),
        (0xA000_0080, 0x2000_0000, 32_768),
        (0xA104_0011, 0x2000_0000, 303_104),
        (0xA000_0880, 0x2000_0000, 49_152),
        (0xA000_00A0, 0x2000_0000, 98_304),
        (0xA000_0042, 0x2000_0000, 524_288),
        (0xA000_0012, 0x2000_0000, 524_288),
        (0xA104_02C6, 0x2000_0000, 20_185_088),
        // The one entry whose graphics half carries the payload. Without it the
        // decode would be untested on the path that matters for textures.
        (0x0002_0000, 0xD102_0008, 3_153_920),
    ];

    #[test]
    fn resource_len_matches_every_measured_inflated_length() {
        for &(system, graphics, expected) in MEASURED {
            assert_eq!(
                resource_len(system, graphics),
                expected,
                "sys={system:#010x} gfx={graphics:#010x}"
            );
        }
    }

    #[test]
    fn graphics_half_of_a_model_is_empty() {
        // 0x20000000 sets no page-count bit, so it describes zero bytes rather
        // than one base-sized page. Every model in the sample carries it.
        assert_eq!(page_count(0x2000_0000), 0);
        assert_eq!(size_from_flags(0x2000_0000), 0);
    }

    #[test]
    fn texture_halves_split_as_measured() {
        assert_eq!(size_from_flags(0x0002_0000), 8_192);
        assert_eq!(size_from_flags(0xD102_0008), 3_145_728);
    }

    #[test]
    fn version_is_carried_by_the_flag_words() {
        // Every model in the sample reads 162, and the one texture reads 13.
        // Both fall out of the top nibbles, so the header's version field is
        // redundant with the flags rather than a third thing to preserve.
        assert_eq!(resource_version(0xA104_02C6, 0x2000_0000), 162);
        assert_eq!(resource_version(0xA000_0011, 0x2000_0000), 162);
        assert_eq!(resource_version(0x0002_0000, 0xD102_0008), 13);
    }

    #[test]
    fn every_measured_resource_version_is_derivable() {
        for &(system, graphics, _) in MEASURED {
            let expected = if graphics == 0x2000_0000 { 162 } else { 13 };
            assert_eq!(resource_version(system, graphics), expected);
        }
    }

    #[test]
    fn a_field_read_past_the_end_is_none_rather_than_a_panic() {
        // §6: the buffer is an archive's bytes, and an entry table can end
        // mid-row. Every one of these is a slice index in disguise.
        let row = [0x01_u8, 0x02, 0x03];
        assert_eq!(u16_at(&row, 0), Some(0x0201));
        assert_eq!(u24_at(&row, 0), Some(0x0003_0201));
        assert_eq!(u32_at(&row, 0), None);
        assert_eq!(u16_at(&row, 2), None);
        assert_eq!(u24_at(&row, 1), None);
        assert_eq!(u16_at(&row, usize::MAX), None);
    }

    #[test]
    fn the_payload_floor_is_the_three_regions_before_it() {
        // The sample: 11 entries and a 144-byte names blob.
        assert_eq!(payload_floor(11, 144), 16 + 11 * 16 + 144);
        assert_eq!(payload_floor(0, 0), HEADER_LEN);
    }

    #[test]
    fn folding_a_name_and_comparing_two_are_the_same_rule() {
        // The two spellings exist because one has to go in a map and the other
        // is on the path of every lookup. They must not be able to disagree.
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
        // The convention changes at version 6: `RPF0`-`RPF4` and console `RPF7`
        // read as `RPFn` on disk, PC `RPF7` and `RPF8` read reversed. A reader
        // that sniffs one order reports half of them as "not an archive".
        // `docs/rpf-format.md`, the magic table, `secondary`.
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
        }
    }

    #[test]
    fn the_console_spelling_of_rpf7_is_a_version_this_build_does_not_read() {
        // `RPF7` on disk is version 7 stored the other way round, and this
        // build reads the `7FPR` spelling. Answering `None` for it would report
        // a sound archive as malformed, which is the whole defect.
        assert_eq!(unsupported_version(*b"RPF7"), Some(7));
    }

    #[test]
    fn the_version_this_build_reads_is_never_named_as_one_it_does_not() {
        // §4: the caller has nothing left to decide. A magic this answers
        // `Some` for is by construction one that cannot be opened.
        assert_eq!(unsupported_version(MAGIC_RPF7), None);
    }

    #[test]
    fn bytes_that_are_no_rpf_magic_at_all_are_not_given_a_version() {
        for magic in [*b"RPFx", *b"xFPR", *b"RSC7", [0_u8; 4], *b"PK\x03\x04"] {
            assert_eq!(unsupported_version(magic), None, "{magic:02x?}");
        }
    }

    #[test]
    fn magic_is_the_little_endian_spelling() {
        // The trap that hid both nested archives on the first walk.
        assert_eq!(MAGIC_RPF7, [0x37, 0x46, 0x50, 0x52]);
        assert_ne!(MAGIC_RPF7, *b"RPF7");
    }
}
