//! Finding an anchored value in an executable.

use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom},
};

use sha1::{Digest, Sha1};

use super::{ANCHOR_ALIGN, ANCHOR_DIGEST_LEN};
use crate::error::{Error, Result};

/// A value to be found by the SHA-1 of its exact bytes.
#[derive(Clone, Copy, Debug)]
pub(super) struct Anchor {
    /// How many bytes the value occupies.
    pub(super) len: usize,
    /// SHA-1 of those bytes.
    pub(super) digest: [u8; ANCHOR_DIGEST_LEN],
}

/// A value that was found, and where.
#[derive(Debug)]
pub(super) struct Sighting {
    /// Offset in the source, from its start.
    pub(super) offset: u64,
    /// The bytes themselves.
    pub(super) bytes: Vec<u8>,
}

/// How far the window advances between reads, in bytes.
const STRIDE: usize = 1 << 20;

/// Finds each of `anchors`, returning a slot per anchor in the same order.
///
/// A slot is `None` when nothing in the source hashed to that anchor. Where one
/// value occurs more than once — measured: the NG hash lookup table occurs
/// three times in `GTA5_Enhanced.exe` — the lowest offset is the one reported,
/// and every anchor carrying that digest is filled from it.
///
/// # Errors
///
/// [`Error::Io`] if the source cannot be read, naming the offset reached.
pub(super) fn find<S: Read + Seek>(
    source: &mut S,
    anchors: &[Anchor],
) -> Result<Vec<Option<Sighting>>> {
    let mut found: Vec<Option<Sighting>> = anchors.iter().map(|_| None).collect();

    let mut wanted: HashMap<[u8; ANCHOR_DIGEST_LEN], Vec<usize>> = HashMap::new();
    let mut lengths: Vec<usize> = Vec::new();
    for (slot, anchor) in anchors.iter().enumerate() {
        if anchor.len == 0 {
            continue;
        }
        wanted.entry(anchor.digest).or_default().push(slot);
        if !lengths.contains(&anchor.len) {
            lengths.push(anchor.len);
        }
    }
    let Some(longest) = lengths.iter().copied().max() else {
        return Ok(found);
    };

    let end = source
        .seek(SeekFrom::End(0))
        .map_err(|source| Error::Io { offset: 0, source })?;

    let step = u64::try_from(ANCHOR_ALIGN).unwrap_or(u64::MAX);
    let stride = u64::try_from(STRIDE).unwrap_or(u64::MAX);
    let mut buffer = vec![0_u8; STRIDE.saturating_add(longest)];
    let mut base: u64 = 0;
    while base < end && !wanted.is_empty() {
        source
            .seek(SeekFrom::Start(base))
            .map_err(|source| Error::Io {
                offset: base,
                source,
            })?;
        let filled = fill(source, &mut buffer, base)?;
        let Some(view) = buffer.get(..filled) else {
            break;
        };

        for &len in &lengths {
            if filled < len || wanted.is_empty() {
                continue;
            }
            let mut offset = base;
            for window in view.windows(len).step_by(ANCHOR_ALIGN) {
                let digest: [u8; ANCHOR_DIGEST_LEN] = Sha1::digest(window).into();
                if let Some(slots) = wanted.remove(&digest) {
                    for slot in slots {
                        if let Some(cell) = found.get_mut(slot) {
                            *cell = Some(Sighting {
                                offset,
                                bytes: window.to_vec(),
                            });
                        }
                    }
                }
                offset = offset.saturating_add(step);
            }
        }

        base = base.saturating_add(stride);
    }

    Ok(found)
}

/// Reads until `buffer` is full or the source ends, and says how much arrived.
fn fill<S: Read>(source: &mut S, buffer: &mut [u8], base: u64) -> Result<usize> {
    let mut filled = 0_usize;
    while filled < buffer.len() {
        let Some(rest) = buffer.get_mut(filled..) else {
            break;
        };
        match source.read(rest) {
            Ok(0) => break,
            Ok(read) => filled = filled.saturating_add(read),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                let reached = u64::try_from(filled).unwrap_or(u64::MAX);
                return Err(Error::Io {
                    offset: base.saturating_add(reached),
                    source: error,
                });
            }
        }
    }
    Ok(filled)
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test code; clippy.toml's allow-*-in-tests settings have no \
              equivalent for this lint. docs/conventions.md §15"
)]
mod tests {
    use std::io::Cursor;

    use sha1::{Digest, Sha1};

    use super::{Anchor, STRIDE, find};
    use crate::keys::ANCHOR_DIGEST_LEN;

    /// A block of bytes that will not occur by accident.
    fn planted(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| {
                let i = u8::try_from(i % 251).unwrap_or(0);
                seed.wrapping_mul(31).wrapping_add(i.wrapping_mul(97))
            })
            .collect()
    }

    fn anchor(bytes: &[u8]) -> Anchor {
        let digest: [u8; ANCHOR_DIGEST_LEN] = Sha1::digest(bytes).into();
        Anchor {
            len: bytes.len(),
            digest,
        }
    }

    fn haystack(len: usize) -> Vec<u8> {
        (0..len).map(|i| u8::try_from(i % 7).unwrap_or(0)).collect()
    }

    fn plant(haystack: &mut [u8], at: usize, value: &[u8]) {
        haystack[at..at + value.len()].copy_from_slice(value);
    }

    #[test]
    fn a_value_on_the_alignment_is_found_with_its_offset() {
        let value = planted(3, 32);
        let mut hay = haystack(4096);
        plant(&mut hay, 2048, &value);

        let found = find(&mut Cursor::new(hay), &[anchor(&value)]).unwrap();
        let sighting = found[0].as_ref().expect("the planted value is found");
        assert_eq!(sighting.offset, 2048);
        assert_eq!(sighting.bytes, value);
    }

    #[test]
    fn a_value_off_the_alignment_is_not_found() {
        // The reference steps eight bytes at a time, so a value not beginning
        // on an eight-byte boundary is invisible to it. Pinned rather than
        // fixed: the stride is what makes the scan affordable, and every value
        // measured so far sits on it.
        let value = planted(5, 32);
        let mut hay = haystack(4096);
        plant(&mut hay, 2044, &value);

        let found = find(&mut Cursor::new(hay), &[anchor(&value)]).unwrap();
        assert!(found[0].is_none(), "an unaligned value was reported found");
    }

    #[test]
    fn the_lowest_offset_of_a_repeated_value_is_the_one_reported() {
        let value = planted(7, 256);
        let mut hay = haystack(8192);
        plant(&mut hay, 1024, &value);
        plant(&mut hay, 4096, &value);

        let found = find(&mut Cursor::new(hay), &[anchor(&value)]).unwrap();
        assert_eq!(found[0].as_ref().expect("found").offset, 1024);
    }

    #[test]
    fn a_value_straddling_a_read_boundary_is_found() {
        // Reads advance by a stride and the buffer is a stride plus the longest
        // anchor, so consecutive reads overlap. A value beginning near the end
        // of one read and ending in the next is what that overlap is for.
        let value = planted(11, 1024);
        let at = STRIDE - 512;
        let mut hay = haystack(STRIDE * 2);
        plant(&mut hay, at, &value);

        let found = find(&mut Cursor::new(hay), &[anchor(&value)]).unwrap();
        assert_eq!(
            found[0].as_ref().expect("found across the boundary").offset,
            u64::try_from(at).unwrap()
        );
    }

    #[test]
    fn an_absent_value_leaves_its_slot_empty_and_a_present_one_does_not() {
        let present = planted(13, 32);
        let absent = planted(17, 32);
        let mut hay = haystack(4096);
        plant(&mut hay, 512, &present);

        let found = find(&mut Cursor::new(hay), &[anchor(&present), anchor(&absent)]).unwrap();
        assert!(found[0].is_some());
        assert!(found[1].is_none());
    }

    #[test]
    fn two_anchors_of_one_value_are_both_filled() {
        // 188 of the 272 NG decrypt-table anchors repeat an earlier one, so one
        // sighting has to fill every slot that asked for it.
        let value = planted(19, 1024);
        let mut hay = haystack(8192);
        plant(&mut hay, 2048, &value);

        let found = find(&mut Cursor::new(hay), &[anchor(&value), anchor(&value)]).unwrap();
        assert_eq!(found[0].as_ref().expect("first").offset, 2048);
        assert_eq!(found[1].as_ref().expect("second").offset, 2048);
    }

    #[test]
    fn a_source_shorter_than_the_value_finds_nothing() {
        let value = planted(23, 1024);
        let found = find(&mut Cursor::new(haystack(64)), &[anchor(&value)]).unwrap();
        assert!(found[0].is_none());
    }
}
