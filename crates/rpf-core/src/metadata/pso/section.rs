//! Sections are a four-character tag plus a big-endian `u32` length, header included.

use super::model::Malformed;

pub(super) const HEADER_LEN: u32 = 8;

/// The data section's tag. Everything else points into it.
pub(super) const PSIN: [u8; 4] = *b"PSIN";
pub(super) const PMAP: [u8; 4] = *b"PMAP";
pub(super) const PSCH: [u8; 4] = *b"PSCH";
pub(super) const CHKS: [u8; 4] = *b"CHKS";

/// How long a `CHKS` section is: `ident`, `length`, `fileSize`, `checksum`, `unk0`.
pub(super) const CHKS_LEN: usize = 20;

#[derive(Debug, Clone, Copy)]
pub(super) struct Section<'a> {
    pub(super) tag: [u8; 4],
    pub(super) at: usize,
    pub(super) bytes: &'a [u8],
}

/// Every section of `payload`, in order; the chain must land exactly on the end.
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
        // `at` moves only here, so a turn that leaves it where it was pushes a
        // `Section` for ever. Unreachable while the length guard above holds.
        if end <= at {
            return Err((at64, Malformed::Section));
        }
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

/// The big-endian IEEE 754 half at `at`, widened exactly to an `f32`.
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

    /// `HEADER_LEN` as an offset, for a test that builds payloads by hand.
    fn header() -> usize {
        usize::try_from(HEADER_LEN).expect("a header length fits an offset")
    }

    /// A payload whose sections declare `parts` in order — each header written
    /// at the offset the lengths before it name — cut or zero-padded to `len`.
    fn payload_of(parts: &[([u8; 4], u32)], len: usize) -> Vec<u8> {
        let mut payload = vec![0_u8; len];
        let mut at = 0_usize;
        for (tag, declared) in parts {
            let header = tag.iter().copied().chain(declared.to_be_bytes());
            for (offset, byte) in header.enumerate() {
                if let Some(slot) = payload.get_mut(at.saturating_add(offset)) {
                    *slot = byte;
                }
            }
            at = at.saturating_add(usize::try_from(*declared).unwrap_or(usize::MAX));
        }
        payload
    }

    /// The same chain walked the other way round: a remainder that every turn
    /// takes a prefix off, rather than a cursor that every turn adds to. It
    /// cannot fail to advance — `rest` is strictly shorter each time — which is
    /// what makes it a reference for a walk that can.
    fn tiling_of(payload: &[u8]) -> Result<Vec<(usize, usize)>, Malformed> {
        let mut rest = payload;
        let mut at = 0_usize;
        let mut taken: Vec<(usize, usize)> = Vec::new();
        while !rest.is_empty() {
            if rest.len() < header() {
                return Err(Malformed::Section);
            }
            let tag = [rest[0], rest[1], rest[2], rest[3]];
            if taken.is_empty() && tag != PSIN {
                return Err(Malformed::NotPso);
            }
            let declared = u32::from_be_bytes([rest[4], rest[5], rest[6], rest[7]]);
            let length = usize::try_from(declared).unwrap_or(usize::MAX);
            if length < header() || length > rest.len() {
                return Err(Malformed::Section);
            }
            taken.push((at, length));
            at = at.saturating_add(length);
            rest = &rest[length..];
        }
        if taken.is_empty() {
            return Err(Malformed::NotPso);
        }
        Ok(taken)
    }

    /// What `chain` makes of `payload`, as `(at, length)` pairs — checked
    /// against the reference walk, and against the law the bound states: every
    /// section takes a non-empty bite, and the chain tiles the payload with no
    /// gap, no overlap and nothing left over.
    fn agreed(payload: &[u8]) -> Result<Vec<(usize, usize)>, Malformed> {
        let walked = chain(payload).map(|sections| {
            sections
                .iter()
                .map(|section| (section.at, section.bytes.len()))
                .collect::<Vec<_>>()
        });
        let reference = tiling_of(payload);
        assert_eq!(
            walked.as_ref().map_err(|(_, cause)| cause),
            reference.as_ref(),
            "{payload:02x?}: the two walks disagree"
        );
        if let Ok(taken) = &walked {
            assert!(!taken.is_empty(), "{payload:02x?}: an empty chain");
            let mut at = 0_usize;
            for (start, length) in taken {
                assert_eq!(*start, at, "{payload:02x?}: a gap or an overlap");
                assert!(*length > 0, "{payload:02x?}: a turn that stood still");
                assert!(
                    *length >= header(),
                    "{payload:02x?}: a section without a header"
                );
                at = at.saturating_add(*length);
            }
            assert_eq!(
                at,
                payload.len(),
                "{payload:02x?}: the chain missed the end"
            );
        }
        walked.map_err(|(_, cause)| cause)
    }

    #[test]
    fn a_section_that_is_exactly_its_own_header_is_a_section() {
        // The boundary the length guard draws, from both sides. A section may
        // be all header and no body; one byte less is not a section at all,
        // because the walk would then step by less than it just read.
        let empty = payload_of(&[(PSIN, HEADER_LEN)], header());
        assert_eq!(agreed(&empty), Ok(vec![(0, header())]));

        let short = payload_of(&[(PSIN, HEADER_LEN - 1)], header());
        assert_eq!(agreed(&short), Err(Malformed::Section));

        // And a chain of them: three header-only sections tile twenty-four bytes.
        let three = payload_of(
            &[(PSIN, HEADER_LEN), (PMAP, HEADER_LEN), (PSCH, HEADER_LEN)],
            header().saturating_mul(3),
        );
        assert_eq!(
            agreed(&three),
            Ok(vec![
                (0, header()),
                (header(), header()),
                (header().saturating_mul(2), header())
            ])
        );
    }

    #[test]
    fn every_declared_length_is_refused_or_moves_the_walk() {
        // Exhaustive over the declared `u32`, covered the way `leading_bit`'s
        // test covers a word: each sixteen-bit half in turn, both halves at
        // once, and the complement. 262,144 draws, every one of them either
        // refused or walked in a chain whose every turn moved.
        for half in 0..=u32::from(u16::MAX) {
            for declared in [half, half << 16, (half << 16) | 0xFFFF, !half] {
                let payload = payload_of(&[(PSIN, declared)], header());
                let want = if declared == HEADER_LEN {
                    Ok(vec![(0, header())])
                } else {
                    Err(Malformed::Section)
                };
                assert_eq!(agreed(&payload), want, "{declared:#010x}");
            }
        }

        // The same lengths again where the payload is exactly as long as the
        // section says, so the accepting branch is the one under test.
        for declared in HEADER_LEN..=4096 {
            let len = usize::try_from(declared).unwrap_or(usize::MAX);
            let payload = payload_of(&[(PSIN, declared)], len);
            assert_eq!(agreed(&payload), Ok(vec![(0, len)]), "{declared}");
        }
    }

    #[test]
    fn the_walk_tiles_the_payload_over_every_short_shape() {
        // Exhaustive over every declared length and every payload length up to
        // eight headers' worth — 4,225 payloads, each checked both ways.
        let ceiling = header().saturating_mul(8);
        for declared in 0..=u32::try_from(ceiling).unwrap_or(u32::MAX) {
            for len in 0..=ceiling {
                let payload = payload_of(&[(PSIN, declared)], len);
                let _ = agreed(&payload);
            }
        }

        // And every two-section shape in the same range, so the second turn of
        // the walk is exercised at each of its own boundaries too.
        for first in 0..=u32::try_from(ceiling).unwrap_or(u32::MAX) {
            for second in 0..=u32::try_from(ceiling).unwrap_or(u32::MAX) {
                let len = usize::try_from(first.saturating_add(second)).unwrap_or(usize::MAX);
                let payload = payload_of(&[(PSIN, first), (PMAP, second)], len);
                let walked = agreed(&payload);
                // Below the guard the two headers overlap and the shape stops
                // meaning anything; `agreed` still holds the walk to its law
                // there. The exact answer is stated where the shape is one.
                if first >= HEADER_LEN && second >= HEADER_LEN {
                    let head = usize::try_from(first).unwrap_or(usize::MAX);
                    let tail = usize::try_from(second).unwrap_or(usize::MAX);
                    assert_eq!(
                        walked,
                        Ok(vec![(0, head), (head, tail)]),
                        "{first}/{second}"
                    );
                }
            }
        }
    }

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
