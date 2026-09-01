//! Finding an anchored value in an executable.

use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom},
};

use sha1::{Digest, Sha1};

use super::{ANCHOR_ALIGN, ANCHOR_DIGEST_LEN};
use crate::{
    error::{Error, Result},
    watch::{Flow, Step, Watch},
};

#[derive(Clone, Copy, Debug)]
pub(super) struct Anchor {
    pub(super) len: usize,
    pub(super) digest: [u8; ANCHOR_DIGEST_LEN],
}

#[derive(Debug)]
pub(super) struct Sighting {
    pub(super) offset: u64,
    pub(super) bytes: Vec<u8>,
}

const STRIDE: usize = 1 << 20;

/// Finds each of `anchors`, returning a slot per anchor in the same order.
pub(super) fn find<S: Read + Seek, W: Watch>(
    source: &mut S,
    anchors: &[Anchor],
    what: &'static str,
    watch: &mut W,
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
    let stride = u64::try_from(STRIDE).unwrap_or(u64::MAX).max(1);
    let total = u32::try_from(
        end.div_euclid(stride)
            .saturating_add(u64::from(end.rem_euclid(stride) != 0)),
    )
    .unwrap_or(u32::MAX);
    let mut done = 0_u32;
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
        done = done.saturating_add(1);
        if watch.step(Step {
            path: what,
            done,
            total,
            bytes: base.min(end),
        }) == Flow::Stop
        {
            return Err(Error::Cancelled { done, total });
        }
    }

    Ok(found)
}

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

    use super::{Anchor, STRIDE, Sighting, fill, find};
    use crate::{
        Error, Result, Unwatched,
        keys::ANCHOR_DIGEST_LEN,
        watch::{Flow, Step, Watch},
    };

    const SEARCHING: &str = "a planted value";

    fn look<S: std::io::Read + std::io::Seek>(
        source: &mut S,
        anchors: &[Anchor],
    ) -> Result<Vec<Option<Sighting>>> {
        find(source, anchors, SEARCHING, &mut Unwatched)
    }

    #[derive(Default)]
    struct Seen(Vec<(String, u32, u32, u64)>);

    impl Watch for Seen {
        fn step(&mut self, step: Step<'_>) -> Flow {
            self.0
                .push((step.path.to_owned(), step.done, step.total, step.bytes));
            Flow::Continue
        }
    }

    struct Stops {
        after: u32,
        seen: u32,
    }

    impl Watch for Stops {
        fn step(&mut self, _step: Step<'_>) -> Flow {
            self.seen += 1;
            if self.seen >= self.after {
                Flow::Stop
            } else {
                Flow::Continue
            }
        }
    }

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

        let found = look(&mut Cursor::new(hay), &[anchor(&value)]).unwrap();
        let sighting = found[0].as_ref().expect("the planted value is found");
        assert_eq!(sighting.offset, 2048);
        assert_eq!(sighting.bytes, value);
    }

    #[test]
    fn a_value_off_the_alignment_is_not_found() {
        let value = planted(5, 32);
        let mut hay = haystack(4096);
        plant(&mut hay, 2044, &value);

        let found = look(&mut Cursor::new(hay), &[anchor(&value)]).unwrap();
        assert!(found[0].is_none(), "an unaligned value was reported found");
    }

    #[test]
    fn the_lowest_offset_of_a_repeated_value_is_the_one_reported() {
        let value = planted(7, 256);
        let mut hay = haystack(8192);
        plant(&mut hay, 1024, &value);
        plant(&mut hay, 4096, &value);

        let found = look(&mut Cursor::new(hay), &[anchor(&value)]).unwrap();
        assert_eq!(found[0].as_ref().expect("found").offset, 1024);
    }

    #[test]
    fn a_value_straddling_a_read_boundary_is_found() {
        let value = planted(11, 1024);
        let at = STRIDE - 512;
        let mut hay = haystack(STRIDE * 2);
        plant(&mut hay, at, &value);

        let found = look(&mut Cursor::new(hay), &[anchor(&value)]).unwrap();
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

        let found = look(&mut Cursor::new(hay), &[anchor(&present), anchor(&absent)]).unwrap();
        assert!(found[0].is_some());
        assert!(found[1].is_none());
    }

    #[test]
    fn two_anchors_of_one_value_are_both_filled() {
        let value = planted(19, 1024);
        let mut hay = haystack(8192);
        plant(&mut hay, 2048, &value);

        let found = look(&mut Cursor::new(hay), &[anchor(&value), anchor(&value)]).unwrap();
        assert_eq!(found[0].as_ref().expect("first").offset, 2048);
        assert_eq!(found[1].as_ref().expect("second").offset, 2048);
    }

    #[test]
    fn a_source_shorter_than_the_value_finds_nothing() {
        let value = planted(23, 1024);
        let found = look(&mut Cursor::new(haystack(64)), &[anchor(&value)]).unwrap();
        assert!(found[0].is_none());
    }

    #[test]
    fn a_source_that_is_exactly_the_value_finds_it() {
        let value = planted(53, 32);
        let found = look(&mut Cursor::new(value.clone()), &[anchor(&value)]).unwrap();
        let sighting = found[0]
            .as_ref()
            .expect("a source that is exactly the value holds it");
        assert_eq!(sighting.offset, 0);
        assert_eq!(sighting.bytes, value);

        let mut short = value.clone();
        short.pop();
        assert!(
            look(&mut Cursor::new(short), &[anchor(&value)]).unwrap()[0].is_none(),
            "a source one byte short of the value reported it found"
        );
    }

    #[test]
    fn a_scan_reports_one_step_per_block_and_counts_bytes_read() {
        let absent = planted(29, 32);
        let mut watching = Seen::default();
        let end = STRIDE * 3 + 17;
        find(
            &mut Cursor::new(haystack(end)),
            &[anchor(&absent)],
            SEARCHING,
            &mut watching,
        )
        .unwrap();

        assert_eq!(watching.0.len(), 4, "{:?}", watching.0);
        for (index, &(ref path, done, total, bytes)) in watching.0.iter().enumerate() {
            assert_eq!(path, SEARCHING, "the step names something else");
            assert_eq!(done, u32::try_from(index).unwrap() + 1);
            assert_eq!(total, 4);
            assert_eq!(
                bytes,
                (u64::try_from(STRIDE).unwrap() * u64::from(done)).min(u64::try_from(end).unwrap())
            );
        }
    }

    #[test]
    fn a_scan_that_finds_everything_stops_before_the_end() {
        let value = planted(31, 32);
        let mut hay = haystack(STRIDE * 3);
        plant(&mut hay, 512, &value);
        let mut watching = Seen::default();
        find(
            &mut Cursor::new(hay),
            &[anchor(&value)],
            SEARCHING,
            &mut watching,
        )
        .unwrap();

        assert_eq!(watching.0.len(), 1, "{:?}", watching.0);
        assert_eq!(watching.0[0].1, 1, "done");
        assert_eq!(watching.0[0].2, 3, "total");
    }

    #[test]
    fn a_scan_told_to_stop_stops_and_says_where() {
        let absent = planted(37, 32);
        let mut stopping = Stops { after: 2, seen: 0 };
        let refused = find(
            &mut Cursor::new(haystack(STRIDE * 4)),
            &[anchor(&absent)],
            SEARCHING,
            &mut stopping,
        );
        match refused {
            Err(Error::Cancelled { done, total }) => {
                assert_eq!(done, 2);
                assert_eq!(total, 4);
            }
            other => panic!("expected Cancelled, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_source_reports_no_steps_at_all() {
        let absent = planted(41, 32);
        let mut watching = Seen::default();
        find(
            &mut Cursor::new(Vec::new()),
            &[anchor(&absent)],
            SEARCHING,
            &mut watching,
        )
        .unwrap();
        assert!(watching.0.is_empty(), "{:?}", watching.0);
    }

    struct Interrupting {
        inner: Cursor<Vec<u8>>,
        left: usize,
    }

    impl std::io::Read for Interrupting {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.left > 0 {
                self.left -= 1;
                return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
            }
            self.inner.read(buf)
        }
    }

    impl std::io::Seek for Interrupting {
        fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(to)
        }
    }

    struct Failing {
        head: Vec<u8>,
        at: usize,
        failed: bool,
    }

    impl std::io::Read for Failing {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if let Some(rest) = self.head.get(self.at..)
                && !rest.is_empty()
            {
                let want = rest.len().min(buf.len());
                buf[..want].copy_from_slice(&rest[..want]);
                self.at += want;
                return Ok(want);
            }
            if self.failed {
                return Ok(0);
            }
            self.failed = true;
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        }
    }

    impl std::io::Seek for Failing {
        fn seek(&mut self, _to: std::io::SeekFrom) -> std::io::Result<u64> {
            Ok(u64::try_from(self.head.len()).unwrap())
        }
    }

    #[test]
    fn a_read_interrupted_part_way_through_still_finds_the_value() {
        let value = planted(43, 32);
        let mut hay = haystack(4096);
        plant(&mut hay, 1024, &value);

        let mut source = Interrupting {
            inner: Cursor::new(hay),
            left: 3,
        };
        let found = look(&mut source, &[anchor(&value)]).unwrap();
        let sighting = found[0].as_ref().expect("an interruption is not an end");
        assert_eq!(sighting.offset, 1024);
        assert_eq!(sighting.bytes, value);
    }

    #[test]
    fn a_read_that_actually_fails_is_reported_with_how_far_it_got() {
        let value = planted(47, 32);
        let head = haystack(512);
        let mut source = Failing {
            head,
            at: 0,
            failed: false,
        };
        match find(&mut source, &[anchor(&value)], SEARCHING, &mut Unwatched) {
            Err(Error::Io { offset, source }) => {
                assert_eq!(offset, 512, "the offset reached is not where it stopped");
                assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
            }
            other => panic!("expected the read failure to be reported, got {other:?}"),
        }
    }

    struct FillsOnceAndRefusesAnEmptyAsk;

    impl std::io::Read for FillsOnceAndRefusesAnEmptyAsk {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if buf.is_empty() {
                return Err(std::io::Error::other("asked to read into an empty buffer"));
            }
            buf.fill(0x5A);
            Ok(buf.len())
        }
    }

    #[test]
    fn fill_stops_asking_once_the_buffer_is_full() {
        let mut buffer = [0_u8; 4];
        let filled = fill(&mut FillsOnceAndRefusesAnEmptyAsk, &mut buffer, 0)
            .expect("a source that filled the buffer in one call must not be asked again");
        assert_eq!(filled, 4);
        assert_eq!(buffer, [0x5A; 4]);
    }
}
