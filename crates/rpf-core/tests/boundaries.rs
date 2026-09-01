//! Every limit in this crate, at the value it is a limit on. Corpus-free:
//! every archive is either built or assembled byte by byte.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "test code; a panic is the reporting mechanism, and these run on \
              64-bit hosts against buffers the test itself created. \
              docs/conventions.md §15"
)]

use std::{
    collections::BTreeMap,
    io::{Cursor, Read as _, Write as _},
};

use rpf_core::{
    Archive, EntryKind, FileKind, FileSpec, MAX_DEPTH, Plan, Storage, Unwatched,
    format::rpf7::RESOURCE_FLAG,
    name::{MAX_COMPONENT_LEN, MAX_PATH_LEN, check_host},
};

mod common;

use common::{BLOCK_LEN, ENTRY_LEN, HEADER_LEN, V, archive_bytes, directory_row, stored_row};

fn built(files: &[FileSpec], contents: &[u8]) -> Vec<u8> {
    let mut out = Cursor::new(Vec::new());
    rpf_core::build(
        &mut out,
        V,
        files,
        &[],
        |_: &str| Ok(Cursor::new(contents.to_vec())),
        &mut Unwatched,
    )
    .expect("builds");
    out.into_inner()
}

fn spec(path: &str, storage: Storage) -> FileSpec {
    FileSpec {
        path: path.to_owned(),
        kind: FileKind::Binary {
            storage,
            encryption: 0,
        },
    }
}

/// A path of exactly `len` bytes in five components, each within
/// [`MAX_COMPONENT_LEN`] so no other rule refuses it.
fn path_of(len: usize) -> String {
    let each = (len - 4) / 5;
    let last = len - 4 - each * 4;
    assert!(each <= MAX_COMPONENT_LEN, "{each} would not be a component");
    assert!(last <= MAX_COMPONENT_LEN, "{last} would not be a component");
    let path = [
        "n".repeat(each),
        "n".repeat(each),
        "n".repeat(each),
        "n".repeat(each),
        "n".repeat(last),
    ]
    .join("/");
    assert_eq!(path.len(), len);
    path
}

#[test]
fn a_path_of_exactly_the_longest_a_path_may_be_is_accepted() {
    check_host(&path_of(MAX_PATH_LEN)).expect("the longest legal path is legal");

    // `check_host` carries several reasons; only this one is about this limit.
    let refused = check_host(&path_of(MAX_PATH_LEN + 1)).expect_err("one byte past it is not");
    match refused {
        rpf_core::Error::BadPath { reason, .. } => {
            assert_eq!(reason, "is longer than a path may be");
        }
        other => panic!("expected a bad path, got {other:?}"),
    }
}

#[test]
fn a_tree_of_exactly_the_deepest_a_tree_may_be_is_packed_and_read_back() {
    let deepest = (0..MAX_DEPTH)
        .map(|level| format!("d{level}"))
        .collect::<Vec<_>>()
        .join("/");
    let bytes = built(&[spec(&deepest, Storage::Stored)], b"deep");

    let mut src = Cursor::new(bytes);
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed())
        .expect("the deepest legal tree parses");
    let index = archive.find(&deepest).expect("resolves");
    assert_eq!(archive.read(&mut src, index).expect("reads"), b"deep");
}

#[test]
fn a_tree_one_component_deeper_than_a_reader_will_walk_is_refused() {
    let too_deep = (0..=MAX_DEPTH)
        .map(|level| format!("d{level}"))
        .collect::<Vec<_>>()
        .join("/");

    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::build(
        &mut out,
        V,
        &[spec(&too_deep, Storage::Stored)],
        &[],
        |_: &str| Ok(Cursor::new(b"deep".to_vec())),
        &mut Unwatched,
    );

    match refused {
        Err(rpf_core::Error::TooDeep { what, depth, limit }) => {
            assert_eq!(what, "directory tree");
            assert_eq!(depth, MAX_DEPTH + 1);
            assert_eq!(limit, MAX_DEPTH);
        }
        other => panic!("expected the tree to be refused as too deep, got {other:?}"),
    }
    assert!(out.into_inner().is_empty(), "a refused build wrote bytes");
}

/// An allocation is the bytes a caller may write into, ends included.
#[test]
fn a_payload_of_exactly_its_allocation_fits_in_place() {
    let source = built(&[spec("raw.bin", Storage::Stored)], &[3_u8; 200]);
    let mut file = Cursor::new(source.clone());
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");

    let index = archive.find("raw.bin").expect("resolves");
    let allocation = archive.allocation(index).expect("allocation");
    assert!(allocation > 0, "the entry has no room to fill");

    // Stored, so the payload's on-disk length is exactly its byte count.
    let exact: Vec<u8> = (0..allocation as u32).map(|i| (i % 251) as u8).collect();
    let plan = rpf_core::plan(
        &mut file,
        &archive,
        &rpf_core::Changes::writing(
            [("raw.bin".to_owned(), exact.clone())]
                .into_iter()
                .collect(),
        ),
    )
    .expect("decides");

    let Plan::Fits(patches) = plan else {
        panic!("a payload of exactly its allocation should fit, got {plan:?}")
    };
    let planned: Vec<_> = patches.planned().collect();
    assert_eq!(planned[0].len, allocation);
    patches.apply(&mut file).expect("applies");

    let after = file.into_inner();
    assert_eq!(after.len(), source.len(), "an in-place patch resized it");
    let mut file = Cursor::new(after);
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("re-parses");
    let index = archive.find("raw.bin").expect("resolves");
    assert_eq!(archive.read(&mut file, index).expect("reads"), exact);
}

#[test]
fn an_entry_table_ending_exactly_at_the_end_of_the_file_is_not_what_overran() {
    let rows = [directory_row(0, 0, 0)];
    let len = HEADER_LEN + ENTRY_LEN;
    let mut bytes = archive_bytes(&rows, &[0u8; 8], len as usize);
    bytes.truncate(len as usize);
    assert_eq!(
        bytes.len() as u64,
        len,
        "the table is meant to end the file"
    );

    let error = Archive::open(&mut Cursor::new(bytes), &rpf_core::Unlock::unkeyed())
        .expect_err("the names blob does not fit");
    assert!(
        matches!(
            error,
            rpf_core::Error::OutOfBounds {
                region: "names blob",
                archive_len,
                ..
            } if archive_len == len
        ),
        "expected the names blob to be named, got {error:?}"
    );
}

/// The floor is the first byte after the names blob, sized here to land on a
/// block boundary — the only way a block offset reaches it exactly.
#[test]
fn a_payload_beginning_exactly_at_the_floor_is_read_rather_than_refused() {
    let rows = [directory_row(0, 1, 1), stored_row(1, 1, 4)];
    let names_len = BLOCK_LEN - HEADER_LEN - 2 * ENTRY_LEN;
    let mut names = vec![0u8; names_len as usize];
    names[1..7].copy_from_slice(b"f.txt\0");

    let mut bytes = archive_bytes(&rows, &names, BLOCK_LEN as usize);
    assert_eq!(
        bytes.len() as u64,
        BLOCK_LEN,
        "the floor is meant to land on a block boundary"
    );
    bytes.extend_from_slice(b"here");

    let mut src = Cursor::new(bytes);
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
    let index = archive.find("f.txt").expect("resolves");
    assert_eq!(archive.payload_at(index).expect("span").0, BLOCK_LEN);
    assert_eq!(archive.read(&mut src, index).expect("reads"), b"here");
}

/// `allocation` stops at the first byte another payload claims from this one's
/// start onwards.
#[test]
fn a_neighbour_ending_exactly_where_a_payload_begins_leaves_it_its_room() {
    let rows = [
        directory_row(0, 1, 2),
        stored_row(1, 1, BLOCK_LEN as u32),
        stored_row(7, 2, 4),
    ];
    let names = b"\0first\0second\0".to_vec();
    let len = (3 * BLOCK_LEN) as usize;
    let bytes = archive_bytes(&rows, &names, len);

    let mut src = Cursor::new(bytes);
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");

    let first = archive.find("first").expect("resolves");
    let second = archive.find("second").expect("resolves");
    let (first_at, first_len) = archive.payload_at(first).expect("span");
    let (second_at, _) = archive.payload_at(second).expect("span");
    assert_eq!(
        first_at + first_len,
        second_at,
        "the neighbour is meant to end exactly where this one begins"
    );

    assert_eq!(
        archive.allocation(second).expect("allocation"),
        len as u64 - second_at,
        "the room after the second payload is the rest of the file"
    );
}

#[test]
fn a_payload_that_deflates_to_exactly_its_own_length_is_stored() {
    let payload = breaks_even();
    let bytes = built(&[spec("even.bin", Storage::Deflate)], &payload);

    let mut src = Cursor::new(bytes);
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
    let index = archive.find("even.bin").expect("resolves");
    match archive.entry(index).expect("entry").kind {
        EntryKind::Binary {
            compressed_len,
            uncompressed_len,
            ..
        } => {
            assert_eq!(compressed_len, 0, "a break-even payload was deflated");
            assert_eq!(uncompressed_len as usize, payload.len());
        }
        other => panic!("expected a binary entry, got {other:?}"),
    }
    assert_eq!(archive.read(&mut src, index).expect("reads"), payload);
}

/// Bytes whose raw deflate stream is exactly as long as they are; which bytes
/// those are is the linked compressor's business.
fn breaks_even() -> Vec<u8> {
    for len in 16_u32..4_096 {
        for modulus in 2_u32..=256 {
            let bytes: Vec<u8> = (0..len)
                .map(|i| ((i.wrapping_mul(2_654_435_761) >> 13) % modulus) as u8)
                .collect();
            let mut encoder =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(&bytes).expect("deflates");
            if encoder.finish().expect("finishes").len() == bytes.len() {
                return bytes;
            }
        }
    }
    panic!(
        "the fixture failed, not the code under test: no payload in this \
         search space deflates to exactly its own length under the deflate \
         backend now linked, so the break-even case cannot be reached. Widen \
         the search or choose a payload by hand — `build` has not been \
         exercised at all"
    )
}

/// `0xFD` is the blob record's marker, so a 254th name would be written as an
/// index a reader cannot tell from a blob.
#[test]
fn a_descriptor_table_of_exactly_its_largest_index_is_written_and_one_more_is_not() {
    fn document(names: usize) -> Vec<u8> {
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<n0>\n");
        for each in 1..names {
            use std::fmt::Write as _;
            let _ = writeln!(xml, "  <n{each}/>");
        }
        xml.push_str("</n0>\n");
        xml.into_bytes()
    }

    // 253 distinct names: indices 0x00 through 0xFC, with `0xFD` and `0xFF`
    // reserved.
    let written = rpf_core::metadata::rbf::from_xml(&document(253))
        .expect("a table of exactly 253 names is representable");
    assert_eq!(
        rpf_core::metadata::rbf::to_xml(&written).expect("reads back"),
        document(253),
        "the table at its own boundary does not round-trip"
    );

    let refused = rpf_core::metadata::rbf::from_xml(&document(254))
        .expect_err("a 254th name would be written as the blob marker");
    assert_eq!(refused.name(), "NotRbfXml", "{refused}");
}

#[test]
fn a_payload_is_judged_by_the_head_length_and_by_no_more_of_it() {
    let head = rpf_core::Encoding::HEAD_LEN;
    let text_then = |bytes: usize, tail: &[u8]| {
        let mut payload = vec![b'a'; bytes];
        payload.extend_from_slice(tail);
        payload
    };
    let cases = [
        (
            "one byte short of the head, all of it text",
            true,
            text_then(head - 1, &[]),
        ),
        (
            "exactly the head, and its last byte is not text",
            false,
            text_then(head - 1, &[0x00]),
        ),
        (
            "one byte past the head, and that byte is not text",
            true,
            text_then(head, &[0x00]),
        ),
    ];
    for (what, refuses, offered) in cases {
        let source = built(
            &[spec("thing.ymt", Storage::Stored)],
            b"RBF0\x01\x02\x03\x04",
        );
        let mut file = Cursor::new(source);
        let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");
        let outcome = rpf_core::plan(
            &mut file,
            &archive,
            &rpf_core::Changes::writing(BTreeMap::from([("thing.ymt".to_owned(), offered)])),
        );
        if !refuses {
            outcome.unwrap_or_else(|error| {
                panic!("a payload of {what} announces nothing, and is taken: {error:?}")
            });
            continue;
        }
        let refused = outcome.err().unwrap_or_else(|| {
            panic!("a payload of {what} is text, and an RBF entry does not take it")
        });
        assert!(
            matches!(
                refused,
                rpf_core::Error::WrongEncoding {
                    held: rpf_core::Encoding::Rbf,
                    offered: rpf_core::Encoding::Text,
                    ..
                }
            ),
            "a payload of {what} is text: {refused:?}"
        );
    }
}

/// The name hash of the one structure [`chained_pso`] defines.
const PSO_ROOT: u32 = 0xD98B_B561;

/// The name hash of its one member.
const PSO_MEMBER: u32 = 0x1234_5678;

/// How deeply a `PSO` walk nests before it refuses: `pso::model::MAX_DEPTH`.
const PSO_MAX_DEPTH: usize = 128;

/// The smallest document any payload may be edited by: `pso::model::MIN_OUTPUT`.
const PSO_MIN_OUTPUT: usize = 16 * 1024 * 1024;

/// A chain of `levels` structures: one element per structure, plus the
/// `pso:null` leaf the last one becomes.
fn chained_pso(levels: usize) -> Vec<u8> {
    let count = u32::try_from(levels).expect("a test level count fits");
    let mut psin = Vec::new();
    psin.extend_from_slice(&rpf_core::metadata::pso::MAGIC);
    psin.extend_from_slice(&(16 + 8 * count).to_be_bytes());
    psin.extend_from_slice(b"pppppppp");
    for level in 0..count {
        // A pointer is the block id in the low 12 bits and the item offset in
        // the next 20; the last block's is null.
        let next = if level + 1 < count { level + 2 } else { 0 };
        psin.extend_from_slice(&next.to_be_bytes());
        psin.extend_from_slice(&0x1234_5678u32.to_be_bytes());
    }

    let mut pmap = Vec::new();
    pmap.extend_from_slice(b"PMAP");
    pmap.extend_from_slice(&(16 + 16 * count).to_be_bytes());
    pmap.extend_from_slice(&1i32.to_be_bytes());
    pmap.extend_from_slice(&i16::try_from(levels).expect("fits").to_be_bytes());
    pmap.extend_from_slice(&0x7070u16.to_be_bytes());
    for level in 0..count {
        pmap.extend_from_slice(&PSO_ROOT.to_be_bytes());
        pmap.extend_from_slice(&(16 + 8 * level).to_be_bytes());
        pmap.extend_from_slice(&0u32.to_be_bytes());
        pmap.extend_from_slice(&8u32.to_be_bytes());
    }

    let mut psch = Vec::new();
    psch.extend_from_slice(b"PSCH");
    psch.extend_from_slice(&44u32.to_be_bytes());
    psch.extend_from_slice(&1u32.to_be_bytes());
    psch.extend_from_slice(&PSO_ROOT.to_be_bytes());
    psch.extend_from_slice(&20i32.to_be_bytes());
    psch.extend_from_slice(&1u32.to_be_bytes()); // structure, one member
    psch.extend_from_slice(&8i32.to_be_bytes()); // structureLength
    psch.extend_from_slice(&0u32.to_be_bytes());
    psch.extend_from_slice(&PSO_MEMBER.to_be_bytes());
    psch.extend_from_slice(&[0x0C, 0x03]); // STRUCT, POINTER
    psch.extend_from_slice(&0u16.to_be_bytes());
    psch.extend_from_slice(&0u32.to_be_bytes());

    let mut payload = psin;
    payload.extend_from_slice(&pmap);
    payload.extend_from_slice(&psch);
    payload
}

#[test]
fn a_pso_walk_of_exactly_the_deepest_a_walk_may_be_converts_and_applies_back() {
    use rpf_core::metadata::{hash::Dictionary, pso};

    let names = Dictionary::default();
    let payload = chained_pso(PSO_MAX_DEPTH);
    let xml = pso::to_xml(&payload, &names).expect("a walk of exactly the limit converts");
    assert_eq!(
        String::from_utf8_lossy(&xml).matches("<hash_").count(),
        PSO_MAX_DEPTH + 1,
        "one element per structure, and the null leaf the last pointer becomes"
    );
    assert_eq!(
        pso::from_xml(&payload, &xml, &names).expect("and applies back"),
        payload,
        "unedited in, unedited out, at the boundary"
    );
}

#[test]
fn a_pso_walk_one_level_deeper_than_the_limit_is_refused_by_both_directions() {
    use rpf_core::metadata::{hash::Dictionary, pso};

    let names = Dictionary::default();
    let payload = chained_pso(PSO_MAX_DEPTH + 1);
    match pso::to_xml(&payload, &names) {
        Err(rpf_core::Error::BadPso { cause, .. }) => {
            assert_eq!(cause, pso::Malformed::TooDeep);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    // The same limit from the document side: one more level of nesting by hand.
    let shallower = chained_pso(PSO_MAX_DEPTH);
    let xml = String::from_utf8(pso::to_xml(&shallower, &names).expect("converts")).expect("UTF-8");
    let deeper = xml.replace(
        "<hash_12345678 pso:null=\"struct\"/>",
        "<hash_12345678 pso:struct=\"hash_D98BB561\">\
         <hash_12345678 pso:null=\"struct\"/></hash_12345678>",
    );
    match pso::from_xml(&shallower, deeper.as_bytes(), &names) {
        Err(rpf_core::Error::NotPsoXml { cause, .. }) => {
            assert_eq!(cause, pso::NotPsoXml::TooDeep);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_pso_document_of_exactly_its_payloads_budget_is_applied_and_one_byte_more_is_not() {
    use rpf_core::metadata::{hash::Dictionary, pso};

    let names = Dictionary::default();
    let payload = chained_pso(1);
    let xml = pso::to_xml(&payload, &names).expect("converts");
    assert!(
        payload.len() * 256 < PSO_MIN_OUTPUT,
        "this payload is small enough that the floor is what bounds it"
    );

    // Indentation is whitespace the mapping skips, so the document pads to any
    // length without describing anything else.
    let mut exact = xml.clone();
    exact.resize(PSO_MIN_OUTPUT, b' ');
    assert_eq!(exact.len(), PSO_MIN_OUTPUT);
    assert_eq!(
        pso::from_xml(&payload, &exact, &names).expect("a document of exactly the budget applies"),
        payload
    );

    let mut over = exact.clone();
    over.push(b' ');
    match pso::from_xml(&payload, &over, &names) {
        Err(rpf_core::Error::NotPsoXml { cause, .. }) => assert_eq!(
            cause,
            pso::NotPsoXml::TooLarge {
                budget: PSO_MIN_OUTPUT,
                len: PSO_MIN_OUTPUT + 1,
            }
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// The second member's name hash, so the two strings are distinct elements.
const PSO_SECOND: u32 = 0x1111_2222;

/// A `PSO` whose root holds both string forms: a fixed inline `char[8]`, and
/// the counted one — a pointer, `count1:u16be`, `count2:u16be`, a dead word.
fn strings_pso(count1: u16, count2: u16) -> Vec<u8> {
    let mut psin = Vec::new();
    psin.extend_from_slice(&rpf_core::metadata::pso::MAGIC);
    psin.extend_from_slice(&48u32.to_be_bytes());
    psin.extend_from_slice(b"pppppppp");
    // The root at 16: eight bytes of fixed inline string, then the counted form.
    psin.extend_from_slice(b"abcdefg\0");
    psin.extend_from_slice(&2u32.to_be_bytes()); // block 2, offset 0
    psin.extend_from_slice(&0x1234_5678u32.to_be_bytes());
    psin.extend_from_slice(&count1.to_be_bytes());
    psin.extend_from_slice(&count2.to_be_bytes());
    psin.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    // Block 2 at 40: the string, its NUL, and filler that has to survive.
    psin.extend_from_slice(b"GTA V\0");
    psin.extend_from_slice(&[0xA7, 0xA7]);

    let mut pmap = Vec::new();
    pmap.extend_from_slice(b"PMAP");
    pmap.extend_from_slice(&48u32.to_be_bytes());
    pmap.extend_from_slice(&1i32.to_be_bytes());
    pmap.extend_from_slice(&2i16.to_be_bytes());
    pmap.extend_from_slice(&0x7070u16.to_be_bytes());
    pmap.extend_from_slice(&PSO_ROOT.to_be_bytes());
    pmap.extend_from_slice(&16i32.to_be_bytes());
    pmap.extend_from_slice(&0i32.to_be_bytes());
    pmap.extend_from_slice(&24i32.to_be_bytes());
    pmap.extend_from_slice(&0x1u32.to_be_bytes()); // a CHAR block
    pmap.extend_from_slice(&40i32.to_be_bytes());
    pmap.extend_from_slice(&0i32.to_be_bytes());
    pmap.extend_from_slice(&8i32.to_be_bytes());

    let mut psch = Vec::new();
    psch.extend_from_slice(b"PSCH");
    psch.extend_from_slice(&56u32.to_be_bytes());
    psch.extend_from_slice(&1u32.to_be_bytes());
    psch.extend_from_slice(&PSO_ROOT.to_be_bytes());
    psch.extend_from_slice(&20i32.to_be_bytes());
    psch.extend_from_slice(&2u32.to_be_bytes()); // structure, two members
    psch.extend_from_slice(&24i32.to_be_bytes()); // structureLength
    psch.extend_from_slice(&0u32.to_be_bytes());
    psch.extend_from_slice(&PSO_MEMBER.to_be_bytes());
    psch.extend_from_slice(&[0x0B, 0x00]); // STRING, MEMBER
    psch.extend_from_slice(&0u16.to_be_bytes());
    psch.extend_from_slice(&(8u32 << 16).to_be_bytes()); // char[8]
    psch.extend_from_slice(&PSO_SECOND.to_be_bytes());
    psch.extend_from_slice(&[0x0B, 0x03]); // STRING, ATSTRING
    psch.extend_from_slice(&8u16.to_be_bytes());
    psch.extend_from_slice(&0u32.to_be_bytes());

    let mut payload = psin;
    payload.extend_from_slice(&pmap);
    payload.extend_from_slice(&psch);
    payload
}

/// The document [`strings_pso`] renders, with one of its two strings replaced.
fn with_string(payload: &[u8], was: &str, now: &str) -> Vec<u8> {
    let xml = String::from_utf8(
        rpf_core::metadata::pso::to_xml(payload, &rpf_core::metadata::hash::Dictionary::default())
            .expect("converts"),
    )
    .expect("UTF-8");
    assert!(xml.contains(was), "the document says {was}: {xml}");
    xml.replace(was, now).into_bytes()
}

/// The room is the member's length less one: the terminator is one of its own
/// bytes.
#[test]
fn a_fixed_inline_string_of_exactly_its_room_is_written_and_one_byte_more_is_not() {
    use rpf_core::metadata::{hash::Dictionary, pso};

    let names = Dictionary::default();
    let payload = strings_pso(5, 6);
    let exact = with_string(&payload, "pso:string=\"abcdefg\"", "pso:string=\"1234567\"");
    let edited = pso::from_xml(&payload, &exact, &names).expect("seven bytes of eight fit");
    assert_eq!(
        &edited[16..24],
        b"1234567\0",
        "and the terminator is still one of the eight"
    );

    let over = with_string(
        &payload,
        "pso:string=\"abcdefg\"",
        "pso:string=\"12345678\"",
    );
    match pso::from_xml(&payload, &over, &names) {
        Err(rpf_core::Error::NotPsoXml { cause, .. }) => assert_eq!(
            cause,
            pso::NotPsoXml::TooLong {
                name: "hash_12345678".to_owned(),
                room: 7,
                len: 8,
            }
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// The characters number `min(count1, count2)`; the terminator is the byte
/// after.
#[test]
fn a_counted_string_of_exactly_its_room_is_written_and_one_byte_more_is_not() {
    use rpf_core::metadata::{hash::Dictionary, pso};

    let names = Dictionary::default();
    for (count1, count2) in [(5u16, 6u16), (6, 5)] {
        let payload = strings_pso(count1, count2);
        let unedited = with_string(&payload, "\"GTA V\"", "\"GTA V\"");
        assert_eq!(
            pso::from_xml(&payload, &unedited, &names).expect("unedited applies"),
            payload,
            "count1 {count1}, count2 {count2}: unedited in, unedited out"
        );

        let exact = with_string(&payload, "\"GTA V\"", "\"12345\"");
        let edited = pso::from_xml(&payload, &exact, &names).expect("five bytes of five fit");
        assert_eq!(
            &edited[40..46],
            b"12345\0",
            "count1 {count1}, count2 {count2}: the terminator survives the edit"
        );

        let over = with_string(&payload, "\"GTA V\"", "\"123456\"");
        match pso::from_xml(&payload, &over, &names) {
            Err(rpf_core::Error::NotPsoXml { cause, .. }) => assert_eq!(
                cause,
                pso::NotPsoXml::TooLong {
                    name: "hash_11112222".to_owned(),
                    room: 5,
                    len: 6,
                },
                "count1 {count1}, count2 {count2}"
            ),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}

/// The largest a 24-bit compressed-size field holds; on a resource it is the
/// sentinel written when the payload is longer.
const SATURATED: u32 = 0x00FF_FFFF;

/// Flags describing one 512-byte system page and no graphics pages.
const RESOURCE_SYSTEM_FLAGS: u32 = 0xA800_0000;
const RESOURCE_GRAPHICS_FLAGS: u32 = 0x2000_0000;

/// Two resources, the first at block 1 declaring `compressed_len` and the
/// second bounding it at `second_block`; each payload is a 16-byte header and
/// one deflated 512-byte page.
fn saturating_archive(compressed_len: u32, second_block: u32) -> Vec<u8> {
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&vec![0_u8; 512]).expect("deflates");
    let mut payload = vec![0xFF_u8; 16];
    payload.extend_from_slice(&encoder.finish().expect("finishes"));

    let mut names = vec![0_u8];
    let mut rows = vec![directory_row(0, 1, 2)];
    for (which, block) in [(0_u32, 1_u32), (1, second_block)] {
        let name_offset = names.len() as u16;
        names.extend_from_slice(format!("r{which}.ydr").as_bytes());
        names.push(0);
        let declared = if which == 0 {
            compressed_len
        } else {
            payload.len() as u32
        };
        rows.push(common::file_row(
            name_offset,
            declared,
            block | RESOURCE_FLAG,
            RESOURCE_SYSTEM_FLAGS,
            RESOURCE_GRAPHICS_FLAGS,
        ));
    }

    let mut out = archive_bytes(
        &rows,
        &names,
        (second_block as usize + 1) * BLOCK_LEN as usize,
    );
    for block in [1_usize, second_block as usize] {
        let at = block * BLOCK_LEN as usize;
        out[at..at + payload.len()].copy_from_slice(&payload);
    }
    out
}

/// The extent is then the room to the next payload.
#[test]
fn a_resource_size_field_at_exactly_its_largest_value_is_a_sentinel() {
    let mut src = Cursor::new(saturating_archive(SATURATED, 3));
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
    let index = archive.find("r0.ydr").expect("resolves");

    assert_eq!(
        archive.payload_at(index).expect("span").1,
        2 * BLOCK_LEN,
        "the room to the next payload, not the 16,777,215 the field reads"
    );
    assert_eq!(archive.read(&mut src, index).expect("reads").len(), 512);

    // The slack past the stream is not a shortfall: the field declared nothing.
    let walked = rpf_core::Verified::of(&mut src, &archive, &mut Unwatched).expect("walks");
    assert!(
        walked.problems.is_empty(),
        "a sound archive reported {:?}",
        walked.problems
    );
}

#[test]
fn a_resource_size_field_one_below_its_largest_value_is_a_length() {
    let mut src = Cursor::new(saturating_archive(SATURATED - 1, 3));
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
    let index = archive.find("r0.ydr").expect("resolves");

    let refused = archive.payload_at(index);
    assert!(
        matches!(
            refused,
            Err(rpf_core::Error::OutOfBounds {
                region: "payload",
                len,
                ..
            }) if len == u64::from(SATURATED - 1)
        ),
        "the field is a length one below the sentinel; got {refused:?}"
    );
}

/// The first payload length past the field, and a whole number of blocks, so
/// the payload after it leaves no alignment slack.
const OVER_THE_FIELD: usize = SATURATED as usize + 1;

/// The block a roomy [`saturating_archive`]'s second payload sits at, leaving
/// the first 16,777,728 bytes of room: past the field.
const ROOMY_SECOND_BLOCK: u32 = 32_770;

/// `write_payloads` lays payloads out in entry-table order, so the room to the
/// next payload is this one's extent.
#[test]
fn a_resource_longer_than_its_size_field_writes_the_sentinel_and_reads_back() {
    // A 16-byte opaque head, as every resource payload has, then a pattern
    // that is not a run.
    let mut payload = vec![0xFF_u8; 16];
    payload.extend((16..OVER_THE_FIELD).map(|at| (at % 251) as u8));
    assert_eq!(payload.len(), OVER_THE_FIELD);

    let files = [
        FileSpec {
            path: "big.ydr".to_owned(),
            kind: FileKind::Resource {
                declared: Some(rpf_core::ResourceFlags {
                    system: RESOURCE_SYSTEM_FLAGS,
                    graphics: RESOURCE_GRAPHICS_FLAGS,
                }),
            },
        },
        spec("z.bin", Storage::Stored),
    ];
    let mut out = Cursor::new(Vec::new());
    rpf_core::build(
        &mut out,
        V,
        &files,
        &[],
        |path: &str| {
            Ok(Cursor::new(if path == "big.ydr" {
                payload.clone()
            } else {
                b"after".to_vec()
            }))
        },
        &mut Unwatched,
    )
    .expect("a resource past the field is written, not refused");

    let mut src = Cursor::new(out.into_inner());
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");

    let index = archive.find("big.ydr").expect("resolves");
    let EntryKind::Resource { compressed_len, .. } = archive.entry(index).expect("an entry").kind
    else {
        panic!("big.ydr is not a resource");
    };
    assert_eq!(
        compressed_len, SATURATED,
        "the field carries the sentinel, not a truncation of the real length"
    );
    assert_eq!(
        archive.payload_at(index).expect("span").1,
        OVER_THE_FIELD as u64,
        "the extent recovered from the next payload's start is the payload"
    );

    let mut back = Vec::new();
    archive
        .extracted(&mut src, index)
        .expect("opens")
        .read_to_end(&mut back)
        .expect("reads");
    assert!(
        back == payload,
        "the payload did not survive the round trip"
    );

    let after = archive.find("z.bin").expect("resolves");
    assert_eq!(archive.read(&mut src, after).expect("reads"), b"after");
}

/// The extent is the room to the next payload and every payload is
/// block-aligned, so the two differ by up to 511 bytes.
#[test]
fn a_saturated_resource_that_is_not_block_aligned_reads_back_with_its_padding() {
    // One byte past the aligned case above: a block of padding less one byte
    // separates it from the payload after it.
    let len = OVER_THE_FIELD + 1;
    let mut payload = vec![0xFF_u8; 16];
    payload.extend((16..len).map(|at| (at % 251) as u8));
    assert_eq!(payload.len(), len);

    let files = [
        FileSpec {
            path: "big.ydr".to_owned(),
            kind: FileKind::Resource {
                declared: Some(rpf_core::ResourceFlags {
                    system: RESOURCE_SYSTEM_FLAGS,
                    graphics: RESOURCE_GRAPHICS_FLAGS,
                }),
            },
        },
        spec("z.bin", Storage::Stored),
    ];
    let mut out = Cursor::new(Vec::new());
    rpf_core::build(
        &mut out,
        V,
        &files,
        &[],
        |path: &str| {
            Ok(Cursor::new(if path == "big.ydr" {
                payload.clone()
            } else {
                b"after".to_vec()
            }))
        },
        &mut Unwatched,
    )
    .expect("a resource past the field is written, not refused");

    let mut src = Cursor::new(out.into_inner());
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
    let index = archive.find("big.ydr").expect("resolves");

    // The room is this payload rounded up to a block: 511 bytes more.
    let slack = usize::try_from(BLOCK_LEN).expect("fits") - 1;
    assert_eq!(
        archive.payload_at(index).expect("span").1,
        u64::try_from(len + slack).expect("fits"),
    );

    let mut back = Vec::new();
    archive
        .extracted(&mut src, index)
        .expect("opens")
        .read_to_end(&mut back)
        .expect("reads");
    assert_eq!(
        back.len(),
        len + slack,
        "the extent is the room, not the len"
    );
    assert!(
        back.get(..len) == Some(payload.as_slice()),
        "the payload did not survive the round trip"
    );
    assert!(
        back.get(len..)
            .is_some_and(|tail| tail.iter().all(|b| *b == 0)),
        "the slack this writer leaves is its own alignment padding"
    );

    let after = archive.find("z.bin").expect("resolves");
    assert_eq!(archive.read(&mut src, after).expect("reads"), b"after");
}

#[test]
fn an_archive_holding_a_saturated_resource_rebuilds_for_an_unrelated_edit() {
    let mut src = Cursor::new(saturating_archive(SATURATED, ROOMY_SECOND_BLOCK));
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
    let room = archive
        .payload_at(archive.find("r0.ydr").expect("resolves"))
        .expect("span")
        .1;
    assert!(
        room > u64::from(SATURATED),
        "the room {room} does not exceed the field, so nothing is exercised"
    );

    let mut out = Cursor::new(Vec::new());
    rpf_core::rebuild(
        &mut src,
        &archive,
        &rpf_core::Changes::new(),
        &mut out,
        BTreeMap::new(),
        &mut Unwatched,
    )
    .expect("an archive holding a saturated resource rebuilds");

    let mut after = Cursor::new(out.into_inner());
    let rebuilt = Archive::open(&mut after, &rpf_core::Unlock::unkeyed()).expect("re-parses");
    let index = rebuilt.find("r0.ydr").expect("resolves");
    let EntryKind::Resource { compressed_len, .. } = rebuilt.entry(index).expect("an entry").kind
    else {
        panic!("r0.ydr is not a resource");
    };
    assert_eq!(compressed_len, SATURATED);
    assert_eq!(rebuilt.payload_at(index).expect("span").1, room);
    assert_eq!(
        rebuilt.read(&mut after, index).expect("reads").len(),
        512,
        "the deflate stream in the rebuilt payload no longer inflates"
    );
}

/// The name hash of the one structure the `Meta` payloads below define.
const META_ROOT: u32 = 0xD98B_B561;

/// The name hash of its one member.
const META_MEMBER: u32 = 0x1234_5678;

/// How deeply a `Meta` walk nests before it refuses: `meta::kind::MAX_DEPTH`.
const META_MAX_DEPTH: usize = 128;

/// The smallest document any `Meta` payload may be edited by.
const META_MIN_OUTPUT: usize = 16 * 1024 * 1024;

/// A little-endian `u64` at `at` of `bytes`.
fn meta_put(bytes: &mut [u8], at: usize, value: u64, width: usize) {
    bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
}

/// A system-space resource pointer at `offset`.
fn meta_system(offset: u32) -> u64 {
    (5u64 << 28) | u64::from(offset)
}

/// The header, one structure of one member, and a block table of `blocks` rows.
fn meta_frame(len: usize, blocks: u16, length: u32, code: u8) -> Vec<u8> {
    let mut payload = vec![0u8; len];
    meta_put(&mut payload, 0x00, 0xDEAD_BEEF, 4);
    meta_put(&mut payload, 0x04, 1, 4);
    meta_put(
        &mut payload,
        0x10,
        u64::from(rpf_core::metadata::meta::MAGIC),
        4,
    );
    meta_put(
        &mut payload,
        0x14,
        u64::from(rpf_core::metadata::meta::VERSION_TWO),
        4,
    );
    meta_put(&mut payload, 0x1C, 1, 4);
    meta_put(&mut payload, 0x20, meta_system(0x50), 8);
    meta_put(&mut payload, 0x30, meta_system(0x100), 8);
    meta_put(&mut payload, 0x48, 1, 2);
    meta_put(&mut payload, 0x4C, u64::from(blocks), 2);
    // The structure: name, name2, kind, membersPtr, length, one member.
    meta_put(&mut payload, 0x50, u64::from(META_ROOT), 4);
    meta_put(&mut payload, 0x54, u64::from(META_ROOT), 4);
    meta_put(&mut payload, 0x58, 0x300, 4);
    meta_put(&mut payload, 0x60, meta_system(0x70), 8);
    meta_put(&mut payload, 0x68, u64::from(length), 4);
    meta_put(&mut payload, 0x6E, 1, 2);
    // Its member, at offset 0 of the structure.
    meta_put(&mut payload, 0x70, u64::from(META_MEMBER), 4);
    meta_put(&mut payload, 0x78, u64::from(code), 1);
    payload
}

/// A chain of `levels` structures: one element per structure, plus the
/// `meta:null` leaf the last one becomes.
fn chained_meta(levels: usize) -> Vec<u8> {
    let data = 0x100 + 16 * levels;
    let mut payload = meta_frame(
        data + 8 * levels,
        u16::try_from(levels).expect("a test level count fits"),
        8,
        0x59,
    );
    for level in 0..levels {
        let at = data + 8 * level;
        meta_put(&mut payload, 0x100 + 16 * level, u64::from(META_ROOT), 4);
        meta_put(&mut payload, 0x100 + 16 * level + 4, 8, 4);
        meta_put(
            &mut payload,
            0x100 + 16 * level + 8,
            meta_system(u32::try_from(at).expect("fits")),
            8,
        );
        // A `Meta` pointer is the block id in the low twelve bits and the
        // item offset above them; the last block's is null.
        let next = if level + 1 < levels { level + 2 } else { 0 };
        meta_put(&mut payload, at, next as u64, 8);
    }
    payload
}

#[test]
fn a_meta_walk_of_exactly_the_deepest_a_walk_may_be_converts_and_applies_back() {
    use rpf_core::metadata::{hash::Dictionary, meta};

    let names = Dictionary::default();
    let payload = chained_meta(META_MAX_DEPTH);
    let xml = meta::to_xml(&payload, payload.len(), &names)
        .expect("a walk of exactly the limit converts");
    assert_eq!(
        String::from_utf8_lossy(&xml).matches("<hash_").count(),
        META_MAX_DEPTH + 1,
        "one element per structure, and the null leaf the last pointer becomes"
    );
    assert_eq!(
        meta::from_xml(&payload, payload.len(), &xml, &names).expect("and applies back"),
        payload,
        "unedited in, unedited out, at the boundary"
    );
}

#[test]
fn a_meta_walk_one_level_deeper_than_the_limit_is_refused_by_both_directions() {
    use rpf_core::metadata::{hash::Dictionary, meta};

    let names = Dictionary::default();
    let payload = chained_meta(META_MAX_DEPTH + 1);
    match meta::to_xml(&payload, payload.len(), &names) {
        Err(rpf_core::Error::BadMeta { cause, .. }) => {
            assert_eq!(cause, meta::Malformed::TooDeep);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    // The same limit from the document side: one more level of nesting by hand.
    let shallower = chained_meta(META_MAX_DEPTH);
    let xml =
        String::from_utf8(meta::to_xml(&shallower, shallower.len(), &names).expect("converts"))
            .expect("UTF-8");
    let deeper = xml.replace(
        "<hash_12345678 meta:null=\"struct\"/>",
        "<hash_12345678 meta:struct=\"hash_D98BB561\">\
         <hash_12345678 meta:null=\"struct\"/></hash_12345678>",
    );
    match meta::from_xml(&shallower, shallower.len(), deeper.as_bytes(), &names) {
        Err(rpf_core::Error::NotMetaXml { cause, .. }) => {
            assert_eq!(cause, meta::NotMetaXml::TooDeep);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A chain of `levels` structures, the deepest with no members at all: its
/// elements sit at depths 0 through `levels - 1`, ending on a structure rather
/// than [`chained_meta`]'s null leaf.
fn capped_meta(levels: usize) -> Vec<u8> {
    let blocks = 0x200;
    let data = blocks + 16 * levels;
    let mut payload = vec![0u8; data + 8 * levels];
    let system = |at: usize| meta_system(u32::try_from(at).expect("a test offset fits"));
    meta_put(&mut payload, 0x00, 0xDEAD_BEEF, 4);
    meta_put(&mut payload, 0x04, 1, 4);
    meta_put(
        &mut payload,
        0x10,
        u64::from(rpf_core::metadata::meta::MAGIC),
        4,
    );
    meta_put(
        &mut payload,
        0x14,
        u64::from(rpf_core::metadata::meta::VERSION_TWO),
        4,
    );
    meta_put(&mut payload, 0x1C, 1, 4);
    meta_put(&mut payload, 0x20, meta_system(0x50), 8);
    meta_put(&mut payload, 0x30, system(blocks), 8);
    meta_put(&mut payload, 0x48, 2, 2);
    meta_put(
        &mut payload,
        0x4C,
        u64::try_from(levels).expect("a test level count fits"),
        2,
    );
    // The chained structure: one structure-pointer member at offset 0.
    meta_put(&mut payload, 0x50, u64::from(META_ROOT), 4);
    meta_put(&mut payload, 0x54, u64::from(META_ROOT), 4);
    meta_put(&mut payload, 0x58, 0x300, 4);
    meta_put(&mut payload, 0x60, meta_system(0x90), 8);
    meta_put(&mut payload, 0x68, 8, 4);
    meta_put(&mut payload, 0x6E, 1, 2);
    // The one the chain ends on: no members, and so no element below it.
    meta_put(&mut payload, 0x70, u64::from(META_LEAF), 4);
    meta_put(&mut payload, 0x74, u64::from(META_LEAF), 4);
    meta_put(&mut payload, 0x78, 0x300, 4);
    meta_put(&mut payload, 0x80, meta_system(0x90), 8);
    meta_member(&mut payload, 0x90, META_MEMBER, 0, 0x59);
    for level in 0..levels {
        let at = data + 8 * level;
        let last = level + 1 == levels;
        let tag = if last { META_LEAF } else { META_ROOT };
        meta_put(&mut payload, blocks + 16 * level, u64::from(tag), 4);
        meta_put(&mut payload, blocks + 16 * level + 4, 8, 4);
        meta_put(&mut payload, blocks + 16 * level + 8, system(at), 8);
        if !last {
            meta_put(
                &mut payload,
                at,
                u64::try_from(level + 2).expect("a test block id fits"),
                8,
            );
        }
    }
    payload
}

/// [`chained_meta`] does not reach this: its deepest structure sits one level
/// above [`META_MAX_DEPTH`].
#[test]
fn a_meta_structure_at_exactly_the_deepest_a_structure_may_sit_is_applied() {
    use rpf_core::metadata::{hash::Dictionary, meta};

    let names = Dictionary::default();
    let payload = capped_meta(META_MAX_DEPTH + 1);
    let xml = meta::to_xml(&payload, payload.len(), &names)
        .expect("a structure at exactly the limit converts");
    assert_eq!(
        String::from_utf8_lossy(&xml).matches("<hash_").count(),
        META_MAX_DEPTH + 1,
        "one element per structure, the deepest of them at exactly the limit"
    );
    assert_eq!(
        meta::from_xml(&payload, payload.len(), &xml, &names).expect("and applies back"),
        payload,
        "unedited in, unedited out, at the boundary"
    );
}

#[test]
fn a_meta_structure_one_level_deeper_than_a_structure_may_sit_is_refused() {
    use rpf_core::metadata::{hash::Dictionary, meta};

    let payload = capped_meta(META_MAX_DEPTH + 2);
    match meta::to_xml(&payload, payload.len(), &Dictionary::default()) {
        Err(rpf_core::Error::BadMeta { cause, .. }) => {
            assert_eq!(cause, meta::Malformed::TooDeep);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_meta_document_of_exactly_its_payloads_budget_is_applied_and_one_byte_more_is_not() {
    use rpf_core::metadata::{hash::Dictionary, meta};

    let names = Dictionary::default();
    let payload = chained_meta(1);
    let xml = meta::to_xml(&payload, payload.len(), &names).expect("converts");
    assert!(
        payload.len() * 256 < META_MIN_OUTPUT,
        "this payload is small enough that the floor is what bounds it"
    );

    let mut exact = xml.clone();
    exact.resize(META_MIN_OUTPUT, b' ');
    assert_eq!(
        meta::from_xml(&payload, payload.len(), &exact, &names)
            .expect("a document of exactly the budget applies"),
        payload
    );

    let mut over = exact.clone();
    over.push(b' ');
    match meta::from_xml(&payload, payload.len(), &over, &names) {
        Err(rpf_core::Error::NotMetaXml { cause, .. }) => assert_eq!(
            cause,
            meta::NotMetaXml::TooLarge {
                budget: META_MIN_OUTPUT,
                len: META_MIN_OUTPUT + 1,
            }
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A `Meta` whose root holds one counted string, both counts the caller's.
fn string_meta(count1: u16, count2: u16) -> Vec<u8> {
    let mut payload = meta_frame(0x200, 2, 16, 0x44);
    meta_put(&mut payload, 0x100, u64::from(META_ROOT), 4);
    meta_put(&mut payload, 0x104, 16, 4);
    meta_put(&mut payload, 0x108, meta_system(0x140), 8);
    meta_put(&mut payload, 0x110, 0x11, 4);
    meta_put(&mut payload, 0x114, 8, 4);
    meta_put(&mut payload, 0x118, meta_system(0x160), 8);
    // The counted form: the pointer, `count1`, `count2` and a dead word.
    meta_put(&mut payload, 0x140, 2, 8);
    meta_put(&mut payload, 0x148, u64::from(count1), 2);
    meta_put(&mut payload, 0x14A, u64::from(count2), 2);
    meta_put(&mut payload, 0x14C, 0xDEAD_BEEF, 4);
    payload[0x160..0x168].copy_from_slice(b"GTA V\0\xA7\xA7");
    payload
}

/// Nothing here moves a block, so a string never lengthens past its own store,
/// whose last byte is the terminator.
#[test]
fn a_meta_counted_string_of_exactly_its_room_is_written_and_one_byte_more_is_not() {
    use rpf_core::metadata::{hash::Dictionary, meta};

    let names = Dictionary::default();
    for (count1, count2) in [(6u16, 6u16), (6, 5)] {
        let payload = string_meta(count1, count2);
        let xml =
            String::from_utf8(meta::to_xml(&payload, payload.len(), &names).expect("converts"))
                .expect("UTF-8");
        assert!(xml.contains("meta:string=\"GTA V\""), "{xml}");
        assert_eq!(
            meta::from_xml(&payload, payload.len(), xml.as_bytes(), &names)
                .expect("unedited applies"),
            payload,
            "count1 {count1}, count2 {count2}: unedited in, unedited out"
        );

        // The room is `min(count1, count2) - 1`, floored at the five bytes
        // already there.
        let room = 5;
        let exact = xml.replace("\"GTA V\"", &format!("\"{}\"", "1".repeat(room)));
        let edited = meta::from_xml(&payload, payload.len(), exact.as_bytes(), &names)
            .expect("a string of exactly its room fits");
        assert_eq!(
            &edited[0x160..=(0x160 + room)],
            format!("{}\0", "1".repeat(room)).as_bytes(),
            "count1 {count1}, count2 {count2}: the terminator survives the edit"
        );

        let over = xml.replace("\"GTA V\"", &format!("\"{}\"", "1".repeat(room + 1)));
        match meta::from_xml(&payload, payload.len(), over.as_bytes(), &names) {
            Err(rpf_core::Error::NotMetaXml { cause, .. }) => assert_eq!(
                cause,
                meta::NotMetaXml::TooLong {
                    name: "hash_12345678".to_owned(),
                    room: u32::try_from(room).expect("fits"),
                    len: u32::try_from(room + 1).expect("fits"),
                },
                "count1 {count1}, count2 {count2}"
            ),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}

/// A `Meta` whose root holds one counted array of `count` `UINT`s.
fn array_meta(count: u16) -> Vec<u8> {
    let items = usize::from(count) * 4;
    let mut payload = meta_frame(0x180 + items, 2, 16, 0x52);
    // The array's element type is the second member, an `ARRAYINFO` `UINT`.
    meta_put(&mut payload, 0x6E, 2, 2);
    meta_put(&mut payload, 0x7A, 1, 2);
    meta_put(&mut payload, 0x80, 0x0000_0100, 4);
    meta_put(&mut payload, 0x88, 0x15, 1);
    meta_put(&mut payload, 0x100, u64::from(META_ROOT), 4);
    meta_put(&mut payload, 0x104, 16, 4);
    meta_put(&mut payload, 0x108, meta_system(0x140), 8);
    meta_put(&mut payload, 0x110, 0x15, 4);
    meta_put(&mut payload, 0x114, u64::try_from(items).expect("fits"), 4);
    meta_put(&mut payload, 0x118, meta_system(0x180), 8);
    meta_put(&mut payload, 0x140, 2, 8);
    meta_put(&mut payload, 0x148, u64::from(count), 2);
    meta_put(&mut payload, 0x14A, u64::from(count), 2);
    for item in 0..usize::from(count) {
        meta_put(&mut payload, 0x180 + 4 * item, item as u64, 4);
    }
    payload
}

/// An array's length is an allocation, and an edit in place moves none.
#[test]
fn a_meta_array_of_exactly_its_own_length_is_applied_and_one_item_more_is_not() {
    use rpf_core::metadata::{hash::Dictionary, meta};

    let names = Dictionary::default();
    let payload = array_meta(3);
    let xml = String::from_utf8(meta::to_xml(&payload, payload.len(), &names).expect("converts"))
        .expect("UTF-8");
    assert_eq!(xml.matches("<meta:item").count(), 3);
    assert_eq!(
        meta::from_xml(&payload, payload.len(), xml.as_bytes(), &names)
            .expect("exactly its own length applies"),
        payload
    );

    for (what, document) in [
        (
            "one item more",
            xml.replace(
                "    <meta:item meta:uint=\"2\"/>\n",
                "    <meta:item meta:uint=\"2\"/>\n    <meta:item meta:uint=\"3\"/>\n",
            ),
        ),
        (
            "one item fewer",
            xml.replace("    <meta:item meta:uint=\"2\"/>\n", ""),
        ),
    ] {
        match meta::from_xml(&payload, payload.len(), document.as_bytes(), &names) {
            Err(rpf_core::Error::NotMetaXml { cause, .. }) => assert!(
                matches!(cause, meta::NotMetaXml::Children { wanted: 3, .. }),
                "{what}: {cause:?}"
            ),
            other => panic!("expected a refusal for {what}, got {other:?}"),
        }
    }
}

/// How many elements one byte of `Meta` payload may write.
const META_MAX_NODES_RATIO: usize = 8;

/// The `ARRAYINFO` sentinel a member carries when it describes another member's
/// elements.
const META_ARRAYINFO: u32 = 0x0000_0100;

/// One structure member, written at `at`.
fn meta_member(payload: &mut [u8], at: usize, name: u32, offset: u32, code: u8) {
    meta_put(payload, at, u64::from(name), 4);
    meta_put(payload, at + 4, u64::from(offset), 4);
    meta_put(payload, at + 8, u64::from(code), 1);
}

/// How many elements a document holds: every one opens with a `<`, less the
/// declaration and the closing tags.
fn meta_elements(document: &str) -> usize {
    document.matches('<').count() - document.matches("</").count() - 1
}

/// A `Meta` whose root holds `arrays` counted arrays, every one of them the
/// same `items` `UINT`s, padded to `len` bytes. Every array names the same
/// block, and `len` moves the ceiling without moving the walk.
fn arrayed_meta(arrays: u16, items: u16, len: usize) -> Vec<u8> {
    let members = 0x70;
    let root_data = members + 16 * (usize::from(arrays) + 1);
    let blocks = root_data + 16 * usize::from(arrays);
    let item_data = blocks + 32;
    let root_len = 16 * u32::from(arrays);
    let mut payload = vec![0u8; len.max(item_data + 4 * usize::from(items))];
    let system = |at: usize| meta_system(u32::try_from(at).expect("a test offset fits"));
    meta_put(&mut payload, 0x00, 0xDEAD_BEEF, 4);
    meta_put(&mut payload, 0x04, 1, 4);
    meta_put(
        &mut payload,
        0x10,
        u64::from(rpf_core::metadata::meta::MAGIC),
        4,
    );
    meta_put(
        &mut payload,
        0x14,
        u64::from(rpf_core::metadata::meta::VERSION_TWO),
        4,
    );
    meta_put(&mut payload, 0x1C, 1, 4);
    meta_put(&mut payload, 0x20, meta_system(0x50), 8);
    meta_put(&mut payload, 0x30, system(blocks), 8);
    meta_put(&mut payload, 0x48, 1, 2);
    meta_put(&mut payload, 0x4C, 2, 2);
    // The root structure: one counted-array member per array, and the
    // `ARRAYINFO` member they read their element type from.
    meta_put(&mut payload, 0x50, u64::from(META_ROOT), 4);
    meta_put(&mut payload, 0x54, u64::from(META_ROOT), 4);
    meta_put(&mut payload, 0x58, 0x300, 4);
    meta_put(&mut payload, 0x60, system(members), 8);
    meta_put(&mut payload, 0x68, u64::from(root_len), 4);
    meta_put(&mut payload, 0x6E, u64::from(arrays) + 1, 2);
    for array in 0..usize::from(arrays) {
        let at = members + 16 * array;
        meta_member(
            &mut payload,
            at,
            META_MEMBER,
            16 * u32::try_from(array).expect("a test array count fits"),
            0x52,
        );
        meta_put(&mut payload, at + 10, u64::from(arrays), 2);
    }
    meta_member(
        &mut payload,
        members + 16 * usize::from(arrays),
        META_ARRAYINFO,
        0,
        0x15,
    );

    meta_put(&mut payload, blocks, u64::from(META_ROOT), 4);
    meta_put(&mut payload, blocks + 4, u64::from(root_len), 4);
    meta_put(&mut payload, blocks + 8, system(root_data), 8);
    meta_put(&mut payload, blocks + 16, 0x15, 4);
    meta_put(&mut payload, blocks + 20, u64::from(items) * 4, 4);
    meta_put(&mut payload, blocks + 24, system(item_data), 8);
    for array in 0..usize::from(arrays) {
        let at = root_data + 16 * array;
        meta_put(&mut payload, at, 2, 8);
        meta_put(&mut payload, at + 8, u64::from(items), 2);
        meta_put(&mut payload, at + 10, u64::from(items), 2);
    }
    payload
}

/// How many elements [`arrayed_meta`] writes.
fn arrayed_elements(arrays: u16, items: u16) -> usize {
    1 + usize::from(arrays) * (1 + usize::from(items))
}

/// The ceiling is a ratio, so padding tunes the payload to the byte.
#[test]
fn a_meta_walk_of_exactly_the_elements_its_payload_allows_converts() {
    use rpf_core::metadata::{hash::Dictionary, meta};

    let (arrays, items) = (49u16, 1022u16);
    let elements = arrayed_elements(arrays, items);
    assert_eq!(elements % META_MAX_NODES_RATIO, 0, "{elements}");
    let payload = arrayed_meta(arrays, items, elements / META_MAX_NODES_RATIO);
    assert_eq!(
        payload.len() * META_MAX_NODES_RATIO,
        elements,
        "the payload is exactly the length its own element count allows"
    );

    let xml = String::from_utf8(
        meta::to_xml(&payload, payload.len(), &Dictionary::default())
            .expect("a walk of exactly the ceiling converts"),
    )
    .expect("UTF-8");
    assert_eq!(meta_elements(&xml), elements);
    assert!(
        xml.len() < meta_budget(payload.len()),
        "the byte budget is not what this payload is bounded by"
    );
}

#[test]
fn a_meta_walk_past_the_node_ceiling_is_refused() {
    use rpf_core::metadata::{hash::Dictionary, meta};

    let (arrays, items) = (49u16, 1022u16);
    let elements = arrayed_elements(arrays, items);
    let payload = arrayed_meta(arrays, items, elements / META_MAX_NODES_RATIO - 1);
    match meta::to_xml(&payload, payload.len(), &Dictionary::default()) {
        Err(rpf_core::Error::BadMeta { cause, .. }) => {
            assert_eq!(cause, meta::Malformed::TooManyNodes);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// How many bytes of document one byte of `Meta` payload may write.
const META_MAX_OUTPUT_RATIO: usize = 256;

/// The name hash of the structure every pointer below lands on.
const META_LEAF: u32 = 0x0FEE_1DAD;

/// How many bytes of document a `Meta` payload of `payload` bytes may write.
fn meta_budget(payload: usize) -> usize {
    (payload * META_MAX_OUTPUT_RATIO).max(META_MIN_OUTPUT)
}

/// A `Meta` whose root holds a counted string of `text` characters and
/// `pointers` pointers, every one at the same structure of `fields` `UINT`s.
/// The payload's length does not depend on `text`, so the budget is one number
/// for the family and the string tunes the document to the byte.
fn amplified_meta(pointers: u16, fields: u16, store: u32, text: u32) -> Vec<u8> {
    let leaf_members = 0x200;
    let leaf_data = leaf_members + 16 * usize::from(fields);
    let string_at = leaf_data + 16 * usize::from(fields);
    let root_members = string_at + usize::try_from(store).expect("a test store fits");
    let root_data = root_members + 16 * (usize::from(pointers) + 1);
    let root_len = 16 + 8 * u32::from(pointers);
    let mut payload = vec![0u8; root_data + usize::try_from(root_len).expect("fits")];
    let system = |at: usize| meta_system(u32::try_from(at).expect("a test offset fits"));
    meta_put(&mut payload, 0x00, 0xDEAD_BEEF, 4);
    meta_put(&mut payload, 0x04, 1, 4);
    meta_put(
        &mut payload,
        0x10,
        u64::from(rpf_core::metadata::meta::MAGIC),
        4,
    );
    meta_put(
        &mut payload,
        0x14,
        u64::from(rpf_core::metadata::meta::VERSION_TWO),
        4,
    );
    meta_put(&mut payload, 0x1C, 1, 4);
    meta_put(&mut payload, 0x20, meta_system(0x50), 8);
    meta_put(&mut payload, 0x30, meta_system(0x100), 8);
    meta_put(&mut payload, 0x48, 2, 2);
    meta_put(&mut payload, 0x4C, 3, 2);
    // The root structure: the string, then one pointer member per subtree.
    meta_put(&mut payload, 0x50, u64::from(META_ROOT), 4);
    meta_put(&mut payload, 0x54, u64::from(META_ROOT), 4);
    meta_put(&mut payload, 0x58, 0x300, 4);
    meta_put(&mut payload, 0x60, system(root_members), 8);
    meta_put(&mut payload, 0x68, u64::from(root_len), 4);
    meta_put(&mut payload, 0x6E, u64::from(pointers) + 1, 2);
    // The leaf structure: `fields` `Float_XYZW`s, whose four lanes cost enough
    // that the node ceiling is not reached first.
    meta_put(&mut payload, 0x70, u64::from(META_LEAF), 4);
    meta_put(&mut payload, 0x74, u64::from(META_LEAF), 4);
    meta_put(&mut payload, 0x78, 0x300, 4);
    meta_put(&mut payload, 0x80, system(leaf_members), 8);
    meta_put(&mut payload, 0x88, u64::from(fields) * 16, 4);
    meta_put(&mut payload, 0x8E, u64::from(fields), 2);

    meta_member(&mut payload, root_members, META_MEMBER, 0, 0x44);
    for pointer in 0..usize::from(pointers) {
        let at = root_members + 16 * (pointer + 1);
        meta_member(
            &mut payload,
            at,
            META_MEMBER,
            16 + 8 * u32::try_from(pointer).expect("a test pointer count fits"),
            0x59,
        );
    }
    for field in 0..usize::from(fields) {
        let at = leaf_members + 16 * field;
        meta_member(
            &mut payload,
            at,
            META_MEMBER,
            16 * u32::try_from(field).expect("a test field count fits"),
            0x34,
        );
    }

    meta_put(&mut payload, 0x100, u64::from(META_ROOT), 4);
    meta_put(&mut payload, 0x104, u64::from(root_len), 4);
    meta_put(&mut payload, 0x108, system(root_data), 8);
    meta_put(&mut payload, 0x110, u64::from(META_LEAF), 4);
    meta_put(&mut payload, 0x114, u64::from(fields) * 16, 4);
    meta_put(&mut payload, 0x118, system(leaf_data), 8);
    meta_put(&mut payload, 0x120, 0x11, 4);
    meta_put(&mut payload, 0x124, u64::from(store), 4);
    meta_put(&mut payload, 0x128, system(string_at), 8);

    // The counted string: a pointer to the third block, and the two counts.
    meta_put(&mut payload, root_data, 3, 8);
    meta_put(&mut payload, root_data + 8, u64::from(text) + 1, 2);
    meta_put(&mut payload, root_data + 10, u64::from(text) + 1, 2);
    for pointer in 0..usize::from(pointers) {
        meta_put(&mut payload, root_data + 16 + 8 * pointer, 2, 8);
    }
    for character in 0..usize::try_from(text).expect("fits") {
        payload[string_at + character] = b'a';
    }
    payload
}

#[test]
fn a_meta_document_of_exactly_the_bytes_its_payload_may_write_is_the_largest_written() {
    use rpf_core::metadata::{hash::Dictionary, meta};

    let names = Dictionary::default();
    let (pointers, fields, store) = (1192u16, 400u16, 59_000u32);
    let empty = amplified_meta(pointers, fields, store, 0);
    let budget = meta_budget(empty.len());
    let shortest = meta::to_xml(&empty, empty.len(), &names)
        .expect("a document under the budget converts")
        .len();
    let room = budget - shortest;
    assert!(
        room < usize::try_from(store).expect("fits"),
        "the string has to be able to tune the document to the byte: {room} of {store}"
    );

    let exact = amplified_meta(
        pointers,
        fields,
        store,
        u32::try_from(room).expect("the room fits"),
    );
    assert_eq!(
        meta_budget(exact.len()),
        budget,
        "the same family, the same budget"
    );
    assert_eq!(
        meta::to_xml(&exact, exact.len(), &names)
            .expect("a document of exactly the budget is written")
            .len(),
        budget
    );

    let over = amplified_meta(
        pointers,
        fields,
        store,
        u32::try_from(room + 1).expect("the room fits"),
    );
    match meta::to_xml(&over, over.len(), &names) {
        Err(rpf_core::Error::BadMeta { cause, .. }) => {
            assert_eq!(cause, meta::Malformed::TooLarge);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }

    // Far past the budget: refused by the per-element charge, not by a check
    // after the walk.
    let far = amplified_meta(pointers * 2, fields, store, 0);
    assert!(meta_budget(far.len()) >= budget);
    match meta::to_xml(&far, far.len(), &names) {
        Err(rpf_core::Error::BadMeta { cause, .. }) => {
            assert_eq!(cause, meta::Malformed::TooLarge);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}
