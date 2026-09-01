//! The section chain, and reading big-endian words out of one.
//!
//! A file is a concatenation of sections, each a four-character tag and a `u32`
//! length that includes the eight-byte header, summing to the file's length.
//! Everything is big-endian, even on a little-endian build.

use super::model::Malformed;

/// How long a section header is: the tag and the length.
pub(super) const HEADER_LEN: u32 = 8;

/// The data section's tag. Everything else points into it.
pub(super) const PSIN: [u8; 4] = *b"PSIN";
/// The block table's tag.
pub(super) const PMAP: [u8; 4] = *b"PMAP";
/// The embedded schema's tag.
pub(super) const PSCH: [u8; 4] = *b"PSCH";
/// The checksum's tag.
pub(super) const CHKS: [u8; 4] = *b"CHKS";

/// How long a `CHKS` section is: `ident`, `length`, `fileSize`, `checksum`,
/// `unk0`. Writes are bounded by this, so a chain declaring a shorter `CHKS` is
/// refused instead of overwriting the next section's header.
pub(super) const CHKS_LEN: usize = 20;

/// One section of a `PSO` file: its tag, and its bytes, header included.
#[derive(Debug, Clone, Copy)]
pub(super) struct Section<'a> {
    /// Its four-character tag.
    pub(super) tag: [u8; 4],
    /// Where its tag sits in the payload.
    pub(super) at: usize,
    /// Its bytes, from its tag to the byte before the next section.
    pub(super) bytes: &'a [u8],
}

/// Every section of `payload`, in order.
///
/// The chain must land exactly on the end: no slack, no trailer and no padding
/// between sections.
///
/// # Errors
///
/// [`Malformed::NotPso`] if the first tag is not `PSIN`, [`Malformed::Section`]
/// if a header or a length does not fit, and [`Malformed::Trailing`] if the
/// chain stops short of the end.
pub(super) fn chain(payload: &[u8]) -> Result<Vec<Section<'_>>, (u64, Malformed)> {
    let mut sections = Vec::new();
    let mut at: usize = 0;
    while at < payload.len() {
        let at64 = u64::try_from(at).unwrap_or(u64::MAX);
        let header = payload
            .get(at..at.saturating_add(usize::try_from(HEADER_LEN).unwrap_or(usize::MAX)))
            .ok_or((at64, Malformed::Section))?;
        let tag = <[u8; 4]>::try_from(header.get(..4).ok_or((at64, Malformed::Section))?)
            .map_err(|_| (at64, Malformed::Section))?;
        if sections.is_empty() && tag != PSIN {
            return Err((0, Malformed::NotPso));
        }
        let length = u32(header, 4).ok_or((at64, Malformed::Section))?;
        if length < HEADER_LEN {
            return Err((at64, Malformed::Section));
        }
        let end = at
            .checked_add(usize::try_from(length).unwrap_or(usize::MAX))
            .ok_or((at64, Malformed::Section))?;
        let bytes = payload.get(at..end).ok_or((at64, Malformed::Section))?;
        sections.push(Section { tag, at, bytes });
        at = end;
    }
    if sections.is_empty() {
        return Err((0, Malformed::NotPso));
    }
    if at != payload.len() {
        return Err((u64::try_from(at).unwrap_or(u64::MAX), Malformed::Trailing));
    }
    Ok(sections)
}

/// The big-endian `u32` at `at`, or `None` when it does not fit.
pub(super) fn u32(bytes: &[u8], at: usize) -> Option<u32> {
    let word = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes(<[u8; 4]>::try_from(word).ok()?))
}

/// The big-endian `i32` at `at`.
pub(super) fn i32(bytes: &[u8], at: usize) -> Option<i32> {
    u32(bytes, at).map(|word| i32::from_be_bytes(word.to_be_bytes()))
}

/// The big-endian `u16` at `at`.
pub(super) fn u16(bytes: &[u8], at: usize) -> Option<u16> {
    let half = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes(<[u8; 2]>::try_from(half).ok()?))
}

/// The big-endian `i16` at `at`.
pub(super) fn i16(bytes: &[u8], at: usize) -> Option<i16> {
    u16(bytes, at).map(|half| i16::from_be_bytes(half.to_be_bytes()))
}

/// The byte at `at`.
pub(super) fn u8(bytes: &[u8], at: usize) -> Option<u8> {
    bytes.get(at).copied()
}

/// The big-endian `u64` at `at`.
pub(super) fn u64(bytes: &[u8], at: usize) -> Option<u64> {
    let word = bytes.get(at..at.checked_add(8)?)?;
    Some(u64::from_be_bytes(<[u8; 8]>::try_from(word).ok()?))
}

/// The big-endian `f32` at `at`.
pub(super) fn f32(bytes: &[u8], at: usize) -> Option<f32> {
    u32(bytes, at).map(f32::from_bits)
}

/// The big-endian IEEE 754 half at `at`, widened to an `f32`.
///
/// Done by hand because the pinned toolchain has no `f16`; the widening is
/// exact.
pub(super) fn f16(bytes: &[u8], at: usize) -> Option<f32> {
    let bits = u16(bytes, at)?;
    let sign = u32::from(bits & 0x8000) << 16;
    let exponent = u32::from((bits >> 10) & 0x1F);
    let mantissa = u32::from(bits & 0x03FF);
    let widened = match exponent {
        0 if mantissa == 0 => sign,
        // A subnormal half is a normal `f32`: shift the mantissa up until its
        // leading one falls off, taking the exponent down with it.
        0 => {
            let mut exponent: u32 = 127 - 15 + 1;
            let mut mantissa = mantissa;
            while mantissa & 0x0400 == 0 {
                mantissa <<= 1;
                exponent = exponent.saturating_sub(1);
            }
            sign | (exponent << 23) | ((mantissa & 0x03FF) << 13)
        }
        0x1F => sign | 0x7F80_0000 | (mantissa << 13),
        _ => sign | ((exponent.saturating_add(127 - 15)) << 23) | (mantissa << 13),
    };
    Some(f32::from_bits(widened))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_section_chain_must_land_exactly_on_the_end() {
        let mut payload = PSIN.to_vec();
        payload.extend_from_slice(&16u32.to_be_bytes());
        payload.extend_from_slice(&[0; 8]);
        assert_eq!(chain(&payload).map(|s| s.len()), Ok(1));

        payload.push(0);
        assert_eq!(chain(&payload).unwrap_err().1, Malformed::Section);
    }

    #[test]
    fn a_length_shorter_than_its_own_header_is_refused() {
        // Without this the walk does not advance and the loop never ends.
        let mut payload = PSIN.to_vec();
        payload.extend_from_slice(&7u32.to_be_bytes());
        assert_eq!(chain(&payload).unwrap_err().1, Malformed::Section);

        let mut payload = PSIN.to_vec();
        payload.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(chain(&payload).unwrap_err().1, Malformed::Section);
    }

    #[test]
    fn a_length_that_overruns_the_payload_is_refused() {
        let mut payload = PSIN.to_vec();
        payload.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(chain(&payload).unwrap_err().1, Malformed::Section);
    }

    #[test]
    fn a_file_that_does_not_open_with_psin_is_not_one() {
        let mut payload = PMAP.to_vec();
        payload.extend_from_slice(&8u32.to_be_bytes());
        assert_eq!(chain(&payload).unwrap_err().1, Malformed::NotPso);
        assert_eq!(chain(b"").unwrap_err().1, Malformed::NotPso);
        assert_eq!(chain(b"PSI").unwrap_err().1, Malformed::Section);
    }

    #[test]
    fn the_half_float_widens_exactly() {
        for (half, want) in [
            (0x0000u16, 0.0f32),
            (0x8000, -0.0),
            (0x0001, 5.960_464_5e-8),
            (0x3C00, 1.0),
            (0xC000, -2.0),
            (0x7BFF, 65504.0),
            (0x7C00, f32::INFINITY),
        ] {
            let bytes = half.to_be_bytes();
            assert_eq!(f16(&bytes, 0), Some(want), "{half:#06x}");
        }
        assert!(f16(&0x7E00u16.to_be_bytes(), 0).is_some_and(f32::is_nan));
    }

    #[test]
    fn every_read_refuses_rather_than_indexes_past_the_end() {
        let bytes = [1u8, 2, 3];
        assert_eq!(u32(&bytes, 0), None);
        assert_eq!(u32(&bytes, usize::MAX), None);
        assert_eq!(u16(&bytes, 2), None);
        assert_eq!(u64(&bytes, 0), None);
        assert_eq!(u8(&bytes, 3), None);
        assert_eq!(u16(&bytes, 0), Some(0x0102));
    }
}
