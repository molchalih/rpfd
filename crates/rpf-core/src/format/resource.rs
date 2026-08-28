//! The `RSC7` resource payload, and the arithmetic that reads its flags.
//!
//! A resource is not the container. `RSC7` is what a `.yft` or a `.ytd` *is*,
//! and an entry of an `RPF7` archive carries a copy of its two flag words;
//! `docs/rpf-format.md` records six other resource magics against the versions
//! this build does not read, all `secondary`. So the decode below belongs to
//! the resource rather than beside a block unit or an entry-table stride, and
//! is here for that reason. DR-012.
//!
//! Each item names the row of `docs/rpf-format.md` that established it.

/// Resource payload magic, at the start of the payload of any entry whose
/// resource bit is set.
///
/// `docs/rpf-format.md`, Resource entries, `verified`.
pub const MAGIC_RSC7: [u8; 4] = *b"RSC7";

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
    fn the_magic_is_not_reversed_the_way_its_container_is() {
        // `docs/rpf-format.md`: `RSC7` reads as itself on disk while `RPF7`
        // reads as `7FPR`. Inverting this one finds no resource at all.
        assert_eq!(MAGIC_RSC7, [b'R', b'S', b'C', b'7']);
    }
}
