//! The `RSC7` resource payload, and the arithmetic that reads its two flag words.

/// Magic at the start of a resource payload, present whenever the entry's resource bit is set.
pub const MAGIC_RSC7: [u8; 4] = *b"RSC7";

/// Length of the `RSC7` header, and the shortest header length a resource payload can carry.
pub const RESOURCE_HEADER_LEN: u64 = 16;

/// Header lengths a resource's deflate stream may begin at; the reader probes 16 vs. 24.
pub const RESOURCE_HEADER_LENS: [u64; 2] = [RESOURCE_HEADER_LEN, 24];

/// Page count encoded in one of a resource's two flag words (offsets 8 and 12 are both flags).
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

/// Byte count from a resource flag word: low nibble is the base page size, rest is page count.
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
#[must_use]
#[expect(
    clippy::arithmetic_side_effects,
    reason = "each half is bounded under 2^37 by size_from_flags, so the sum \
              cannot overflow u64"
)]
pub const fn resource_len(system_flags: u32, graphics_flags: u32) -> u64 {
    size_from_flags(system_flags) + size_from_flags(graphics_flags)
}

/// `RSC7` version, derived from the top nibble of each flag word (system high, graphics low).
#[must_use]
pub const fn resource_version(system_flags: u32, graphics_flags: u32) -> u32 {
    (((system_flags >> 28) & 0xF) << 4) | ((graphics_flags >> 28) & 0xF)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    const PAGE_BITS: &[(u32, u32)] = &[
        (0, 0),
        (1, 0),
        (2, 0),
        (3, 0),
        (4, 256),
        (5, 128),
        (6, 256),
        (7, 64),
        (8, 128),
        (9, 256),
        (10, 512),
        (11, 32),
        (12, 64),
        (13, 128),
        (14, 256),
        (15, 512),
        (16, 1_024),
        (17, 16),
        (18, 32),
        (19, 64),
        (20, 128),
        (21, 256),
        (22, 512),
        (23, 1_024),
        (24, 8),
        (25, 4),
        (26, 2),
        (27, 1),
        (28, 0),
        (29, 0),
        (30, 0),
        (31, 0),
    ];

    #[test]
    fn every_page_count_bit_is_worth_what_the_format_says() {
        for &(bit, pages) in PAGE_BITS {
            assert_eq!(page_count(1 << bit), pages, "bit {bit}");
        }
    }

    #[test]
    fn the_page_count_fields_are_disjoint() {
        let mut word = 0_u32;
        let mut pages = 0_u32;
        for &(bit, worth) in PAGE_BITS {
            word |= 1 << bit;
            pages = pages.checked_add(worth).expect("the sum is bounded");
        }
        assert_eq!(word, u32::MAX, "the table is meant to cover the whole word");
        assert_eq!(pages, 5_663, "1+2+4+8+2032+2016+960+384+256");
        assert_eq!(page_count(word), pages, "flags={word:#010x}");
    }

    #[test]
    fn graphics_half_of_a_model_is_empty() {
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
        assert_eq!(MAGIC_RSC7, [b'R', b'S', b'C', b'7']);
    }
}
