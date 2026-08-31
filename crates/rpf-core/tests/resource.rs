//! Where a resource's deflate stream begins, and where its entry's flag words
//! come from.
//!
//! Both are the same question asked from the two sides: nothing in an RPF7
//! entry declares either, because offsets 8 and 12 of a resource row are both
//! page flags. `docs/rpf-format.md`, Compression and Resource entries.
//! DR-045 is where the stream's boundary comes from and DR-046 is where the
//! entry's flag words come from.
//!
//! Corpus-free. Every archive here is assembled byte by byte, so the facts are
//! pinned on a machine with no game installed.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "an integration test is its own crate with no cfg(test), so the \
              exception docs/conventions.md §15 grants test code is spelled \
              here. A panic is the reporting mechanism, and these run on \
              64-bit hosts against buffers the test itself created"
)]

use std::{
    collections::BTreeMap,
    io::{Cursor, Write},
};

use rpf_core::{
    Archive, FileKind, FileSpec, ResourceFlags, Unlock, Unwatched,
    format::{
        resource::{RESOURCE_HEADER_LEN, RESOURCE_HEADER_LENS, resource_len},
        rpf7::{RESOURCE_FLAG, ROW_LEN},
    },
};

mod common;

/// Flags describing one 512-byte system page and no graphics pages.
///
/// `docs/rpf-format.md`, Resource page flags. Spelled as flags rather than as
/// the number 512 because that is what an entry carries, and `resource_len` is
/// asked for the number below rather than told it.
const SYSTEM_FLAGS: u32 = 0xA800_0000;
const GRAPHICS_FLAGS: u32 = 0x2000_0000;

/// Bytes that cannot begin a raw deflate stream: the low three bits are
/// `BFINAL = 1` and `BTYPE = 11`, which RFC 1951 reserves and no decoder
/// accepts. A header of these is a header no candidate boundary can mistake for
/// the stream, which is what makes the recovery below a measurement rather than
/// a coincidence.
const OPAQUE: u8 = 0xFF;

/// The header lengths measured in the corpus, spelled out here rather than
/// imported.
///
/// A test that took the widths from the code it checks would agree with
/// whatever that code came to believe — `crates/rpf-core/tests/patch.rs` says
/// the same about `MAX_SIZE_24`. These two are the measurement:
/// `docs/rpf-format.md`, Compression, `verified` — 7,050 resources of
/// `x64f.rpf` at 16 and 22 at 24.
const MEASURED: [usize; 2] = [16, 24];

/// A resource payload as a Rockstar archive holds one: an opaque header of
/// `header_len` bytes that is not an `RSC7` header, then the deflate stream.
///
/// `docs/backlog.md` Q7: 696,578 of 696,578 Rockstar resource payloads do not
/// begin with `RSC7`.
fn opaque_resource(header_len: usize) -> Vec<u8> {
    let mut payload = vec![OPAQUE; header_len];
    payload.extend_from_slice(&deflated_page());
    payload
}

/// One 512-byte page of zeroes, deflated — the contents every resource here
/// inflates to.
fn deflated_page() -> Vec<u8> {
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&vec![0_u8; 512]).expect("deflates");
    encoder.finish().expect("finishes")
}

/// An archive holding one resource per header length in `headers`, named
/// `r0`, `r1` and so on in ascending order, each one payload of
/// [`opaque_resource`].
fn archive_of(headers: &[usize]) -> Vec<u8> {
    let mut names = vec![0_u8];
    let mut rows = vec![common::directory_row(0, 1, headers.len() as u32)];
    let mut payloads = Vec::new();
    for (which, &header_len) in headers.iter().enumerate() {
        let name = format!("r{which}.ydr");
        let name_offset = names.len() as u16;
        names.extend_from_slice(name.as_bytes());
        names.push(0);
        let payload = opaque_resource(header_len);
        // One payload per block, in entry order, starting at block 1.
        let block = (which + 1) as u32;
        rows.push(common::file_row(
            name_offset,
            payload.len() as u32,
            block | RESOURCE_FLAG,
            SYSTEM_FLAGS,
            GRAPHICS_FLAGS,
        ));
        payloads.push((block, payload));
    }

    let len = (headers.len() + 1) * common::BLOCK_LEN as usize;
    let mut out = common::archive_bytes(&rows, &names, len);
    for (block, payload) in payloads {
        let at = block as usize * common::BLOCK_LEN as usize;
        out[at..at + payload.len()].copy_from_slice(&payload);
    }
    out
}

/// The contents of every entry of an archive, by name.
fn contents_of(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut src = Cursor::new(bytes.to_vec());
    let archive = Archive::open(&mut src, &Unlock::unkeyed()).expect("parses");
    (1..archive.entries().len() as u32)
        .map(|index| {
            let name = archive.path(index).expect("named");
            let read = archive
                .read(&mut src, index)
                .unwrap_or_else(|error| panic!("{name} did not read back: {error}"));
            (name, read)
        })
        .collect()
}

/// The measurement this file exists for: the header length is not one value,
/// and the boundary is found rather than assumed.
///
/// `x64f.rpf` holds 7,050 resources whose stream begins 16 bytes into the
/// payload and 22 whose stream begins 24 bytes in, and two of them carry
/// identical flag words — so no field and no derivation separates the cases.
/// `docs/rpf-format.md`, Compression.
#[test]
fn a_resource_stream_is_found_at_whichever_boundary_its_payload_uses() {
    let bytes = archive_of(&MEASURED);

    let expected = vec![0_u8; 512];
    for (name, read) in contents_of(&bytes) {
        assert_eq!(
            read,
            expected,
            "{name} inflated to {} bytes, not the 512 its flags declare",
            read.len()
        );
    }
    assert_eq!(
        resource_len(SYSTEM_FLAGS, GRAPHICS_FLAGS),
        512,
        "the flags above are what declares the length, not the number 512"
    );
}

/// A `verify` over the same archive reports nothing, at either boundary.
///
/// The half a read alone cannot see: the stream's length is the payload's
/// extent **less the header it actually carries**, so a boundary recovered at
/// 24 while the length was still taken from 16 would leave eight bytes
/// unaccounted for and `verify` would report [`rpf_core::Error::TrailingBytes`]
/// on an archive that is perfectly sound. R6.10, DR-033.
#[test]
fn a_resource_at_any_boundary_accounts_for_its_whole_payload() {
    let bytes = archive_of(&MEASURED);
    let mut src = Cursor::new(bytes);
    let archive = Archive::open(&mut src, &Unlock::unkeyed()).expect("parses");
    let walked = rpf_core::Verified::of(&mut src, &archive, &mut Unwatched).expect("walks");

    assert_eq!(
        walked.checked as usize,
        MEASURED.len(),
        "every resource was read back"
    );
    assert!(
        walked.problems.is_empty(),
        "a sound archive reported {:?}",
        walked.problems
    );
}

/// The payload comes out of `extract` whole whatever its header length.
///
/// Passthrough is a commitment (`docs/approach.md`) and it is what makes the
/// round trip possible at all: an entry this build cannot interpret still
/// leaves and re-enters the archive byte for byte. DR-023's checksum is over
/// exactly these bytes.
#[test]
fn extract_hands_back_the_payload_whole_at_any_boundary() {
    for &header in &MEASURED {
        let bytes = archive_of(&[header]);
        let mut src = Cursor::new(bytes);
        let archive = Archive::open(&mut src, &Unlock::unkeyed()).expect("parses");
        assert_eq!(
            archive.extract(&mut src, 1).expect("extracts"),
            opaque_resource(header),
            "a {header}-byte header must survive extraction"
        );
    }
}

/// The constant says what was measured, and says the shortest of them is the
/// floor a payload has to clear.
#[test]
fn the_boundaries_the_code_carries_are_the_ones_that_were_measured() {
    let carried: Vec<usize> = RESOURCE_HEADER_LENS
        .iter()
        .map(|&len| usize::try_from(len).expect("a header length fits"))
        .collect();
    assert_eq!(
        carried, MEASURED,
        "the boundaries are 16 and 24, in that order"
    );
    assert_eq!(
        u64::try_from(MEASURED[0]).expect("fits"),
        RESOURCE_HEADER_LEN,
        "the shortest boundary is the `RSC7` header, and the floor a payload \
         must clear"
    );
}

/// A payload that begins no stream at any boundary is reported as the first
/// boundary's failure, not the last one's.
///
/// `docs/backlog.md` Q14's populations 2 and 3 are exactly this, 3,190 entries
/// of them, and the answer a caller gets about them must not change with the
/// length of the candidate list.
#[test]
fn a_payload_that_begins_no_stream_reports_the_first_boundarys_failure() {
    // A near miss at the *second* boundary: a whole deflate stream lives 24
    // bytes in, and it inflates to half of what the flags declare. At the first
    // boundary there is no stream at all. So the two boundaries fail
    // differently, and which failure comes back says which one is reported.
    let mut short = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    short.write_all(&vec![0_u8; 256]).expect("deflates");
    let short = short.finish().expect("finishes");
    let mut payload = vec![OPAQUE; 24];
    payload.extend_from_slice(&short);

    let mut bytes = archive_of(&[16]);
    let at = common::BLOCK_LEN as usize;
    for byte in &mut bytes[at..at + common::BLOCK_LEN as usize] {
        *byte = 0;
    }
    bytes[at..at + payload.len()].copy_from_slice(&payload);
    // The row is rebuilt rather than poked at, so the field offsets stay
    // `common`'s and this test carries no copy of the layout.
    let row = common::HEADER_LEN as usize + ROW_LEN;
    bytes[row..row + ROW_LEN].copy_from_slice(&common::file_row(
        1,
        payload.len() as u32,
        1 | RESOURCE_FLAG,
        SYSTEM_FLAGS,
        GRAPHICS_FLAGS,
    ));

    let mut src = Cursor::new(bytes);
    let archive = Archive::open(&mut src, &Unlock::unkeyed()).expect("parses");
    let refused = archive.read(&mut src, 1);
    assert!(
        matches!(refused, Err(rpf_core::Error::Inflate { entry: 1, .. })),
        "the first boundary's failure is the one reported; got {refused:?}"
    );
}

/// A resource whose stream is whole and stops short of what its flags declare
/// is **named**, and no candidate rescues it.
///
/// This is the shape of the only two entries in the corpus that do not read
/// back — `x64a.rpf/textures/parachute_decals.ytd`, in both installs and
/// differently: the Enhanced copy is a clean stream that terminates 68,056
/// bytes short of the 794,624 its flags declare, and the Legacy copy is a
/// different payload that breaks mid-stream. `docs/corpus.md`. They are damaged
/// in the archive Rockstar ships, and what the tool does about them is report
/// them against the entry they belong to and offer no bytes for them.
///
/// It is pinned because the candidate list grew: a boundary and a transform are
/// now recovered by trying, and a payload that satisfies no candidate must
/// still come back as the failure it is rather than as whichever attempt got
/// furthest. DR-045 §1a, DR-051.
#[test]
fn a_resource_that_inflates_short_of_its_flags_is_reported_against_its_entry() {
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&vec![0_u8; 256]).expect("deflates");
    let mut payload = vec![OPAQUE; MEASURED[0]];
    payload.extend_from_slice(&encoder.finish().expect("finishes"));

    let mut bytes = archive_of(&[MEASURED[0]]);
    let at = common::BLOCK_LEN as usize;
    for byte in &mut bytes[at..at + common::BLOCK_LEN as usize] {
        *byte = 0;
    }
    bytes[at..at + payload.len()].copy_from_slice(&payload);
    let row = common::HEADER_LEN as usize + ROW_LEN;
    bytes[row..row + ROW_LEN].copy_from_slice(&common::file_row(
        1,
        payload.len() as u32,
        1 | RESOURCE_FLAG,
        SYSTEM_FLAGS,
        GRAPHICS_FLAGS,
    ));

    let mut src = Cursor::new(bytes);
    let archive = Archive::open(&mut src, &Unlock::unkeyed()).expect("parses");
    let refused = archive.read(&mut src, 1);
    assert!(
        matches!(
            refused,
            Err(rpf_core::Error::LengthMismatch {
                entry: 1,
                expected: 512,
                actual: 256
            })
        ),
        "a stream that stops short is the entry's own failure; got {refused:?}"
    );

    let walked = rpf_core::Verified::of(&mut src, &archive, &mut Unwatched).expect("walks");
    assert_eq!(
        walked
            .problems
            .iter()
            .map(|problem| problem.path.as_str())
            .collect::<Vec<_>>(),
        ["r0.ydr"],
        "the walk names the one entry that did not read back and no other"
    );

    // Passthrough is untouched by any of it: the payload still leaves the
    // archive byte for byte, which is what makes the damaged pair rebuildable.
    assert_eq!(
        archive.extract(&mut src, 1).expect("extracts")[..payload.len()],
        payload[..],
        "the payload comes out whole even though its contents do not"
    );
}

/// A resource written into an entry that declares its flag words keeps them,
/// and the archive that results reads back.
///
/// This is the round trip Q7 forbids doing any other way: the payload carries
/// no `RSC7` header, so its flags exist only in the row it is going into.
#[test]
fn a_resource_write_takes_its_flag_words_from_the_entry_when_the_payload_has_none() {
    let payload = opaque_resource(MEASURED[1]);
    let built = build_one(
        FileKind::Resource {
            declared: Some(ResourceFlags {
                system: SYSTEM_FLAGS,
                graphics: GRAPHICS_FLAGS,
            }),
        },
        &payload,
    )
    .expect("a declared resource is written");

    assert_eq!(
        contents_of(&built)[0].1,
        vec![0_u8; 512],
        "the row's flags must describe the payload that was written"
    );
}

/// With nothing declaring them and no header to read them out of, the write is
/// refused rather than guessed at.
#[test]
fn a_resource_write_with_no_flag_words_anywhere_is_refused() {
    let payload = opaque_resource(MEASURED[1]);
    let refused = build_one(FileKind::Resource { declared: None }, &payload);
    match refused {
        Err(rpf_core::Error::NotAResource { ref path, reason }) => {
            assert_eq!(path, "r0.ydr");
            assert_eq!(
                reason,
                "the payload carries no RSC7 header and no entry declares its \
                 page flags"
            );
        }
        other => panic!("expected a refusal naming what is missing, got {other:?}"),
    }
}

/// A payload that *does* carry a header states its own flags, and they beat the
/// entry's — the header describes the payload, and the row is being replaced.
#[test]
fn a_payload_with_its_own_header_beats_the_flag_words_the_entry_declares() {
    let mut payload = b"RSC7".to_vec();
    payload.extend_from_slice(&162_u32.to_le_bytes());
    payload.extend_from_slice(&SYSTEM_FLAGS.to_le_bytes());
    payload.extend_from_slice(&GRAPHICS_FLAGS.to_le_bytes());
    payload.extend_from_slice(&deflated_page());

    // Flags declaring 128 KB, which the payload is not. If the entry's were
    // taken the read below would be a length mismatch.
    let built = build_one(
        FileKind::Resource {
            declared: Some(ResourceFlags {
                system: 0xA000_0011,
                graphics: GRAPHICS_FLAGS,
            }),
        },
        &payload,
    )
    .expect("a resource carrying its own header is written");

    assert_eq!(contents_of(&built)[0].1, vec![0_u8; 512]);
}

/// The rule DR-046 puts in the library, pinned **in the library**: an in-place
/// write into a resource entry takes its flag words from the entry it lands on.
///
/// `docs/conventions.md` §1 is why this test is here rather than only on a
/// frontend. Until it was, the only thing that failed when `build::kind_of`
/// stopped carrying the row's flags was a subprocess test of the command line —
/// the whole of `rpf-core` stayed green, because `patch.rs`, `roundtrip.rs` and
/// `stream.rs` each build their specs by hand and never ask an entry what it
/// declares.
///
/// The payload written carries no `RSC7` header, which is the case Q7 measured
/// at 696,578 of 696,578: the row is the only record of its length and version
/// there is, so a write that did not take it from there would produce an entry
/// declaring something else.
#[test]
fn a_patch_of_a_resource_that_carries_no_header_takes_the_entrys_flag_words() {
    let mut file = Cursor::new(archive_of(&[MEASURED[0]]));
    let archive = Archive::open(&mut file, &Unlock::unkeyed()).expect("parses");
    let index = archive.find("r0.ydr").expect("resolves");
    let (payload_at, _) = archive.payload_at(index).expect("span");

    // The same contents behind a header of the other measured length, so the
    // bytes on disk really change and the row really is rewritten.
    let replacement = opaque_resource(MEASURED[1]);
    let plan = rpf_core::plan(
        &mut file,
        &archive,
        &rpf_core::Changes::writing(BTreeMap::from([("r0.ydr".to_owned(), replacement.clone())])),
    )
    .expect("a resource entry accepts a payload with no header of its own");
    let rpf_core::Plan::Fits(patches) = plan else {
        panic!("expected the patch to fit, got {plan:?}")
    };
    patches.apply(&mut file).expect("applies");

    let after = file.into_inner();
    assert_eq!(
        &after[payload_at as usize..payload_at as usize + replacement.len()],
        &replacement[..],
        "the payload written is the payload offered, byte for byte"
    );
    assert_eq!(
        contents_of(&after)[0].1,
        vec![0_u8; 512],
        "the row must still declare the 512 bytes its flags declared before"
    );
}

/// A source that counts the bytes read out of it.
///
/// The only way to observe how many times a payload was inflated: an inflate
/// reads its input, so two inflates read it twice.
struct Counting<S> {
    inner: S,
    read: u64,
}

impl<S> Counting<S> {
    const fn over(inner: S) -> Self {
        Self { inner, read: 0 }
    }
}

impl<S: std::io::Read> std::io::Read for Counting<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.read += read as u64;
        Ok(read)
    }
}

impl<S: std::io::Seek> std::io::Seek for Counting<S> {
    fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(to)
    }
}

/// DR-046's loosening, pinned as a loosening: a payload that is nothing like a
/// resource is **accepted** into a resource entry and **caught by `verify`**.
///
/// The guard that used to refuse this at the moment it was offered was
/// measuring the wrong thing — `docs/backlog.md` Q7 — so it went, and §8's rule
/// that every write path has a read path that checks it is what is left. Both
/// halves are the record's claim and both are asserted here, because a
/// refusal that came back would look like a fix and is the defect being
/// undone.
#[test]
fn a_text_payload_written_into_a_resource_entry_is_taken_and_then_caught() {
    let mut file = Cursor::new(archive_of(&[MEASURED[0]]));
    let archive = Archive::open(&mut file, &Unlock::unkeyed()).expect("parses");

    // Longer than a resource header, so the one content test that survives —
    // the floor — has nothing to say about it.
    let text = b"plain text, not a resource at all".to_vec();
    assert!(text.len() as u64 > RESOURCE_HEADER_LEN);
    let plan = rpf_core::plan(
        &mut file,
        &archive,
        &rpf_core::Changes::writing(BTreeMap::from([("r0.ydr".to_owned(), text.clone())])),
    )
    .expect("the write is not refused at the moment it is offered");
    let rpf_core::Plan::Fits(patches) = plan else {
        panic!("expected the patch to fit, got {plan:?}")
    };
    patches.apply(&mut file).expect("applies");

    let mut file = Cursor::new(file.into_inner());
    let archive = Archive::open(&mut file, &Unlock::unkeyed()).expect("re-parses");
    let walked = rpf_core::Verified::of(&mut file, &archive, &mut Unwatched).expect("walks");
    assert_eq!(walked.checked, 1, "the entry was read back");
    match walked.problems.as_slice() {
        [problem] => {
            assert_eq!(problem.path, "r0.ydr");
            assert!(
                matches!(problem.error, rpf_core::Error::Inflate { entry: 1, .. }),
                "expected the text to fail to inflate, got {:?}",
                problem.error
            );
        }
        other => panic!("expected verify to catch exactly this entry, got {other:?}"),
    }
    assert!(
        walked.outcome().is_err(),
        "and to report the archive as failing"
    );
}

/// Flags declaring 128 pages of the base 512 bytes — 65,536 bytes.
///
/// `docs/rpf-format.md`, Resource page flags: bit 5 is worth 128 pages. The
/// cost test below needs contents large enough that one pass over them is not
/// lost in the head a walk peeks at.
const SYSTEM_FLAGS_64K: u32 = 0xA000_0020;

/// Bytes that compress poorly, so the stream deflated from them is long rather
/// than a handful of bytes of run-length.
fn noise(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i as u32).wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect()
}

/// DR-045 §3, pinned: a `verify` settles a resource's boundary and reports what
/// it found from **one** inflate, where a per-entry `Archive::read` pays for
/// two.
///
/// The claim is a cost decision over a walk measured in hundreds of gigabytes,
/// and nothing failed when `Archive::read_back` stopped short-circuiting into
/// `Archive::resource_stream` and went through `opened` instead — the answers
/// are identical, so only what the source is asked for tells them apart. An
/// inflate reads its input, so a second inflate reads the stream a second time.
#[test]
fn a_verify_inflates_a_resource_once_where_a_read_of_it_pays_twice() {
    let plain = noise(65_536);
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&plain).expect("deflates");
    let stream = encoder.finish().expect("finishes");
    let mut payload = vec![OPAQUE; MEASURED[0]];
    payload.extend_from_slice(&stream);

    let bytes = build_one(
        FileKind::Resource {
            declared: Some(ResourceFlags {
                system: SYSTEM_FLAGS_64K,
                graphics: GRAPHICS_FLAGS,
            }),
        },
        &payload,
    )
    .expect("builds");
    assert_eq!(
        resource_len(SYSTEM_FLAGS_64K, GRAPHICS_FLAGS) as usize,
        plain.len(),
        "the row must declare exactly what the stream inflates to"
    );

    let mut walking = Counting::over(Cursor::new(bytes.clone()));
    let archive = Archive::open(&mut walking, &Unlock::unkeyed()).expect("parses");
    let parsing = walking.read;
    rpf_core::Verified::of(&mut walking, &archive, &mut Unwatched).expect("walks");
    let walked = walking.read - parsing;

    let mut reading = Counting::over(Cursor::new(bytes));
    let archive = Archive::open(&mut reading, &Unlock::unkeyed()).expect("parses");
    let parsing = reading.read;
    archive.read(&mut reading, 1).expect("reads");
    let read = reading.read - parsing;

    let once = stream.len() as u64;
    assert!(
        read >= once * 2,
        "a read of a resource inflates it twice, so it asks its source for at \
         least two passes over the {once}-byte stream; it asked for {read}"
    );
    assert!(
        walked < once * 2,
        "a walk inflates it once, so it asks for one pass and the head it \
         peeks at for a nested archive; it asked for {walked} against a \
         {once}-byte stream"
    );
}

/// Builds a one-entry archive holding `payload` at `r0.ydr`.
fn build_one(kind: FileKind, payload: &[u8]) -> rpf_core::Result<Vec<u8>> {
    let files = vec![FileSpec {
        path: "r0.ydr".to_owned(),
        kind,
    }];
    let owned = payload.to_vec();
    let mut out = Cursor::new(Vec::new());
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(owned.clone())),
        &mut Unwatched,
    )?;
    Ok(out.into_inner())
}
