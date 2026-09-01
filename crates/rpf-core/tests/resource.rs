//! Where a resource's deflate stream begins, and where its entry's flag words
//! come from. Nothing in an RPF7 entry declares either: offsets 8 and 12 of a
//! resource row are both page flags.
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
    Archive, EntryKind, FileKind, FileSpec, Manifest, ResourceFlags, Unlock, Unwatched,
    format::{
        resource::{RESOURCE_HEADER_LEN, RESOURCE_HEADER_LENS, resource_len},
        rpf7::{RESOURCE_FLAG, ROW_LEN},
    },
};

mod common;

/// Flags describing one 512-byte system page and no graphics pages.
const SYSTEM_FLAGS: u32 = 0xA800_0000;
const GRAPHICS_FLAGS: u32 = 0x2000_0000;

/// Bytes that cannot begin a raw deflate stream: the low three bits are
/// `BFINAL = 1` and `BTYPE = 11`, which RFC 1951 reserves.
const OPAQUE: u8 = 0xFF;

/// The header lengths measured in the corpus, spelled out here rather than
/// imported from the code under test.
const MEASURED: [usize; 2] = [16, 24];

/// A resource payload as a Rockstar archive holds one: an opaque header of
/// `header_len` bytes that is not an `RSC7` header, then the deflate stream.
fn opaque_resource(header_len: usize) -> Vec<u8> {
    let mut payload = vec![OPAQUE; header_len];
    payload.extend_from_slice(&deflated_page());
    payload
}

/// One 512-byte page of zeroes, deflated.
fn deflated_page() -> Vec<u8> {
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&vec![0_u8; 512]).expect("deflates");
    encoder.finish().expect("finishes")
}

/// An archive holding one resource per header length in `headers`, named `r0`,
/// `r1` and so on in ascending order, each one payload of [`opaque_resource`].
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

/// The stream's length is the payload's extent less the header it actually
/// carries, so a boundary and a length taken from different candidates would
/// leave bytes unaccounted for.
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

#[test]
fn a_payload_that_begins_no_stream_reports_the_first_boundarys_failure() {
    // A near miss at the second boundary: a whole stream 24 bytes in inflating
    // to half of what the flags declare, where the first boundary has none.
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

/// A payload that satisfies no candidate comes back as the failure it is,
/// rather than as whichever attempt got furthest.
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

    // Passthrough is untouched: the payload leaves the archive byte for byte.
    assert_eq!(
        archive.extract(&mut src, 1).expect("extracts")[..payload.len()],
        payload[..],
        "the payload comes out whole even though its contents do not"
    );
}

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

#[test]
fn a_payload_with_its_own_header_beats_the_flag_words_the_entry_declares() {
    let mut payload = b"RSC7".to_vec();
    payload.extend_from_slice(&162_u32.to_le_bytes());
    payload.extend_from_slice(&SYSTEM_FLAGS.to_le_bytes());
    payload.extend_from_slice(&GRAPHICS_FLAGS.to_le_bytes());
    payload.extend_from_slice(&deflated_page());

    // Flags declaring 128 KB, which the payload is not: taking the entry's
    // would make the read below a length mismatch.
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

/// The payload written carries no `RSC7` header, so the row is the only record
/// of its length and version there is.
#[test]
fn a_patch_of_a_resource_that_carries_no_header_takes_the_entrys_flag_words() {
    let mut file = Cursor::new(archive_of(&[MEASURED[0]]));
    let archive = Archive::open(&mut file, &Unlock::unkeyed()).expect("parses");
    let index = archive.find("r0.ydr").expect("resolves");
    let (payload_at, _) = archive.payload_at(index).expect("span");

    // The other measured header length, so the bytes on disk really change.
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

/// The write is not refused when it is offered; the read path is what catches
/// it.
#[test]
fn a_text_payload_written_into_a_resource_entry_is_taken_and_then_caught() {
    let mut file = Cursor::new(archive_of(&[MEASURED[0]]));
    let archive = Archive::open(&mut file, &Unlock::unkeyed()).expect("parses");

    // Longer than a resource header, so the floor has nothing to say about it.
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

/// Flags declaring 128 pages of the base 512 bytes — 65,536 bytes; bit 5 is
/// worth 128 pages.
const SYSTEM_FLAGS_64K: u32 = 0xA000_0020;

/// Bytes that compress poorly, so the deflated stream is long.
fn noise(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i as u32).wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect()
}

/// An inflate reads its input, so the bytes asked of the source are what
/// separates one pass over the stream from two.
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

/// The flag words of every resource entry of an archive, by path.
fn rows_of(bytes: &[u8]) -> BTreeMap<String, (u32, u32)> {
    let mut src = Cursor::new(bytes.to_vec());
    let archive = Archive::open(&mut src, &Unlock::unkeyed()).expect("parses");
    (1..archive.entries().len() as u32)
        .filter_map(|index| match archive.entry(index).expect("in range").kind {
            EntryKind::Resource {
                system_flags,
                graphics_flags,
                ..
            } => Some((
                archive.path(index).expect("named"),
                (system_flags, graphics_flags),
            )),
            _ => None,
        })
        .collect()
}

/// Every entry of an archive as the file `extract` writes into a tree, by path.
fn extracted_of(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let mut src = Cursor::new(bytes.to_vec());
    let archive = Archive::open(&mut src, &Unlock::unkeyed()).expect("parses");
    (1..archive.entries().len() as u32)
        .map(|index| {
            let name = archive.path(index).expect("named");
            (name, archive.extract(&mut src, index).expect("extracts"))
        })
        .collect()
}

/// Packs the tree `manifest` describes, taking each payload from `contents`.
fn pack(manifest: &Manifest, contents: &BTreeMap<String, Vec<u8>>) -> rpf_core::Result<Vec<u8>> {
    let held = contents.clone();
    let mut out = Cursor::new(Vec::new());
    manifest.pack_into(
        &mut out,
        &Unlock::unkeyed(),
        move |wanted: &str| Ok(Cursor::new(held.get(wanted).cloned().unwrap_or_default())),
        &mut Unwatched,
    )?;
    Ok(out.into_inner())
}

#[test]
fn a_resource_packs_from_the_flag_words_its_manifest_records() {
    let bytes = archive_of(&[MEASURED[0]]);
    let mut src = Cursor::new(bytes.clone());
    let archive = Archive::open(&mut src, &Unlock::unkeyed()).expect("parses");
    let manifest = Manifest::of(&archive).expect("derives");
    assert_eq!(
        manifest.entries.first().and_then(|entry| entry.flags),
        Some(ResourceFlags {
            system: SYSTEM_FLAGS,
            graphics: GRAPHICS_FLAGS,
        }),
        "the words the row declared are what the manifest records"
    );

    let extracted = extracted_of(&bytes);
    let packed = pack(&manifest, &extracted).expect("the tree packs back");

    assert_eq!(
        rows_of(&packed),
        rows_of(&bytes),
        "the rebuilt row must declare what the one it came from declared"
    );
    assert_eq!(
        extracted_of(&packed),
        extracted,
        "and the payload goes through untouched"
    );
}

/// Flag words that were not recorded are never guessed at: a guess produces an
/// archive that parses, packs and verifies but does not load.
#[test]
fn a_tree_whose_manifest_records_no_flag_words_is_refused_at_the_entry_that_lacks_them() {
    let bytes = archive_of(&[MEASURED[0]]);
    let mut src = Cursor::new(bytes.clone());
    let archive = Archive::open(&mut src, &Unlock::unkeyed()).expect("parses");
    let mut manifest = Manifest::of(&archive).expect("derives");
    manifest.schema = 3;
    for entry in &mut manifest.entries {
        entry.flags = None;
    }

    let extracted = extracted_of(&bytes);
    match pack(&manifest, &extracted) {
        Err(rpf_core::Error::NotAResource { ref path, reason }) => {
            assert_eq!(path, "r0.ydr", "the refusal names the entry that lacks it");
            assert_eq!(
                reason,
                "the payload carries no RSC7 header and no entry declares its \
                 page flags"
            );
        }
        other => panic!("expected a refusal naming the entry, got {other:?}"),
    }
}

#[test]
fn a_resource_that_carries_its_own_header_packs_from_a_manifest_that_records_none() {
    let mut payload = b"RSC7".to_vec();
    payload.extend_from_slice(&162_u32.to_le_bytes());
    payload.extend_from_slice(&SYSTEM_FLAGS.to_le_bytes());
    payload.extend_from_slice(&GRAPHICS_FLAGS.to_le_bytes());
    payload.extend_from_slice(&deflated_page());
    let bytes = build_one(
        FileKind::Resource {
            declared: Some(ResourceFlags {
                system: SYSTEM_FLAGS,
                graphics: GRAPHICS_FLAGS,
            }),
        },
        &payload,
    )
    .expect("builds");

    let mut src = Cursor::new(bytes.clone());
    let archive = Archive::open(&mut src, &Unlock::unkeyed()).expect("parses");
    let mut manifest = Manifest::of(&archive).expect("derives");
    manifest.schema = 3;
    for entry in &mut manifest.entries {
        entry.flags = None;
    }

    let extracted = extracted_of(&bytes);
    let packed = pack(&manifest, &extracted).expect("a header-carrying resource packs");
    assert_eq!(rows_of(&packed), rows_of(&bytes));
    assert_eq!(extracted_of(&packed), extracted);
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
