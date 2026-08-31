//! Every limit in this crate, at the value it is a limit on.
//!
//! A mutation sweep found the same gap in seven places: each limit is compared
//! with `<` or `>`, every one of them is exercised on values well clear of the
//! boundary, and **not one of them on the boundary itself**. So moving any of
//! the seven by exactly one — `>` to `>=`, `<` to `<=` — changed no test's
//! answer, while the mutations that move a boundary further than that all died.
//! A path of exactly the longest a path may be, a payload of exactly its own
//! allocation, a payload starting exactly at the floor, an entry table ending
//! exactly at the end of the file: none of them appeared anywhere in the suite.
//!
//! **A limit added later belongs here, at its own boundary value**, on both
//! sides where both sides are reachable. The far side of each is tested
//! wherever it already was; what this file adds is the near one, which is the
//! case a reader reasons about and gets wrong. One far side was tested nowhere
//! either, and is here beside its own near side.
//!
//! Six of the seven err towards refusal, which is the less dangerous direction
//! — an off-by-one here declines something legal rather than accepting
//! something illegal. It is still the direction that turns a patchable edit
//! into a full rebuild, or refuses a name a real archive holds.
//!
//! Corpus-free: every archive here is either built or assembled byte by byte.
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
    io::{Cursor, Write as _},
};

use rpf_core::{
    Archive, EntryKind, FileKind, FileSpec, MAX_DEPTH, Plan, Storage, Unwatched,
    name::{MAX_COMPONENT_LEN, MAX_PATH_LEN, check_host},
};

mod common;

use common::{BLOCK_LEN, ENTRY_LEN, HEADER_LEN, V, archive_bytes, directory_row, stored_row};

/// Builds an archive from specs and hands back its bytes.
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

/// A binary file spec at `path`.
fn spec(path: &str, storage: Storage) -> FileSpec {
    FileSpec {
        path: path.to_owned(),
        kind: FileKind::Binary {
            storage,
            encryption: 0,
        },
    }
}

/// A path of exactly `len` bytes, in five components, every one of them
/// legal on its own.
///
/// Both bounds are asserted rather than assumed. A component past
/// [`MAX_COMPONENT_LEN`] is refused by a *different* rule, and a path built
/// that way would still be refused — for the wrong reason, leaving the test
/// below green and measuring nothing. At `MAX_PATH_LEN` of 1,024 each
/// component is 204 bytes, and five components carry the limit as far as
/// 5 × 255 + 4 = 1,279 before that stops being true.
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

/// `name.rs`: a path of exactly [`MAX_PATH_LEN`] bytes is a path.
///
/// The limit is what a path may be, not what it must be under, and a real
/// archive is free to hold a name of exactly that length.
#[test]
fn a_path_of_exactly_the_longest_a_path_may_be_is_accepted() {
    check_host(&path_of(MAX_PATH_LEN)).expect("the longest legal path is legal");

    // The reason, not merely a refusal: `check_host` carries several, and a
    // path one byte too long is only evidence about *this* limit if it is
    // this limit that turned it away.
    let refused = check_host(&path_of(MAX_PATH_LEN + 1)).expect_err("one byte past it is not");
    match refused {
        rpf_core::Error::BadPath { reason, .. } => {
            assert_eq!(reason, "is longer than a path may be");
        }
        other => panic!("expected a bad path, got {other:?}"),
    }
}

/// `build.rs`: a tree of exactly [`MAX_DEPTH`] components packs and parses.
///
/// §8 pairs this write-path check with `Archive::parse`'s read-path one, and
/// the two agree only if they refuse at the same depth. A build that stopped
/// one level early would refuse a tree its own reader opens.
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

/// `build.rs`: one component past [`MAX_DEPTH`] is refused before anything is
/// written.
///
/// The far side of the limit above, and the one far side that was tested
/// nowhere at all: **nothing in the repository packed a tree deeper than a
/// reader will walk**, so deleting the guard outright changed no test's
/// answer. What it guards is §8's pairing — `Archive::parse` refuses a tree
/// past this depth, so a `build` that did not would write an archive this
/// build's own reader declines to open, which is the stated top risk with the
/// failure moved one step later.
#[test]
fn a_tree_one_component_deeper_than_a_reader_will_walk_is_refused() {
    let too_deep = (0..=MAX_DEPTH)
        .map(|level| format!("d{level}"))
        .collect::<Vec<_>>()
        .join("/");

    // A cursor is the right sink because nothing should reach it: what is
    // asserted is the refusal, not what was written.
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

/// `patch.rs`: a payload of exactly its allocation fits.
///
/// An allocation is the bytes a caller may write into, ends included. Refusing
/// the payload that exactly fills one turns a patch into a whole rebuild of a
/// 2.7 GB archive for the sake of one byte that was never needed.
#[test]
fn a_payload_of_exactly_its_allocation_fits_in_place() {
    let source = built(&[spec("raw.bin", Storage::Stored)], &[3_u8; 200]);
    let mut file = Cursor::new(source.clone());
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");

    let index = archive.find("raw.bin").expect("resolves");
    let allocation = archive.allocation(index).expect("allocation");
    assert!(allocation > 0, "the entry has no room to fill");

    // Stored, so the payload's on-disk length is exactly its byte count and
    // the fit is decided by the comparison this test is about.
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

/// `archive.rs`: an entry table ending exactly at the end of the file has
/// itself fitted, and it is the names blob that did not.
///
/// The check is deliberately asked before the names blob's, so that a header
/// claiming more entries than the file can hold names the entry table rather
/// than the blob that never got a chance to start (§10). Moving it by one
/// takes the last table that does fit and blames it for the blob's overrun,
/// which sends a caller looking at the wrong field. Both readings refuse the
/// archive; only one of them says where to look.
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

/// `archive.rs`: a payload beginning exactly at the floor is not underflow.
///
/// The floor is the first byte after the names blob, so a payload *at* it is
/// the tightest legal layout rather than one reaching back into the table of
/// contents. The names blob is sized here to put the floor on a block
/// boundary, which is the only way a block offset can land on it exactly.
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

/// `archive.rs`: a payload ending exactly where the next one begins claims
/// none of its bytes.
///
/// `allocation` stops at the first byte another payload claims from this one's
/// start onwards. A neighbour that ends *at* the start claims nothing here, so
/// the room is real; counting it would report zero room and refuse every patch
/// to an entry that happens to sit immediately after another.
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

/// `build.rs`: a deflated form exactly the size of the plain one is not worth
/// deflating.
///
/// Deflating has to *pay* for itself, and breaking even is not paying: an
/// entry the same size either way is stored, because stored costs nothing to
/// read. Which bytes deflate to exactly their own length is the compressor's
/// business and may change, so the payload is searched for rather than
/// written down; that such a payload exists is what the boundary needs.
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

/// Bytes whose raw deflate stream is exactly as long as they are.
///
/// Searched rather than written down, because *which* bytes those are is the
/// compressor's business: `flate2`'s `rust_backend` decides it, and a
/// semver-compatible `miniz_oxide` release may decide it differently. What the
/// boundary needs is only that such a payload exists, and the search finds
/// whichever one the linked compressor agrees with today. It is a fixture, so
/// its failure is a fixture's failure and says so — a message blaming `build`
/// would send the next reader after a regression that is not there.
///
/// The space is wide enough that the crossing is found many times over: the
/// first hit today is 16 bytes long, and each length between 16 and 4,096 is
/// tried against 255 alphabet sizes, which is around a million candidates.
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

/// `RBF`'s descriptor table, at the last index the one-byte field can carry.
///
/// The far side of this limit is the dangerous direction, which is unusual
/// here — the other seven err towards refusal. `0xFD` is the blob record's
/// marker, so a 254th name would be written as an index a reader cannot tell
/// from a blob, and this build would emit metadata it cannot read back.
/// A mutation sweep found `count < MAX_NAMES` surviving as `<=` at every gate
/// tier, with the signature that names the gap: `<` to `==` and `<` to `>`
/// both die, `<` to `<=` lives. `docs/metadata-encodings.md`, The token stream.
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

    // 253 distinct names: indices 0x00 through 0xFC, the last one the field
    // holds with `0xFD` and `0xFF` reserved.
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

/// `metadata/mod.rs`: an offered payload is judged by `Encoding::HEAD_LEN`
/// bytes of it, by however many fewer there are, and by no more.
///
/// R6.6's guard reads the payload being written through a sixteen-byte window
/// and asks [`rpf_core::Encoding::of`] what it announces. Three payloads, one
/// per mistake, and each is refused or taken according to which:
///
/// - **fifteen bytes of text** — refused. The buffer's sixteenth byte is a zero
///   the payload never had, and judging the buffer rather than what was read
///   calls plain text unknown binary and takes a write this refuses;
/// - **sixteen, whose last byte is not text** — taken. Every byte of the head
///   is judged, so a window one byte short would call it text and refuse it;
/// - **seventeen, whose last byte is not text** — refused. Nothing past the
///   head is judged, so a longer window would call it unknown binary and take
///   it.
///
/// The two either side of the limit fail in opposite directions, which is what
/// makes the pair a boundary rather than one assertion written twice.
/// `Archive::classify` records the same trap for the entry's side of the
/// comparison. This is the payload's side, at the value it is a limit on.
/// DR-050.
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

// ---------------------------------------------------------------------------
// `PSO` — the ceilings both directions of the conversion obey
// ---------------------------------------------------------------------------

/// The name hash of the one structure [`chained_pso`] defines, and of every
/// block it lays out.
const PSO_ROOT: u32 = 0xD98B_B561;

/// The name hash of its one member.
const PSO_MEMBER: u32 = 0x1234_5678;

/// How deeply a `PSO` walk nests before it refuses.
///
/// `pso::model::MAX_DEPTH`, which is `pub(super)`: the ceiling is the metadata
/// layer's and is not part of the crate's public contract, so it is pinned here
/// at the value rather than imported. DR-011 — a stated depth limit rather than
/// a stack overflow.
const PSO_MAX_DEPTH: usize = 128;

/// The smallest document any payload may be edited by, whatever its size.
///
/// `pso::model::MIN_OUTPUT`, the floor under the output ratio, pinned here for
/// the same reason.
const PSO_MIN_OUTPUT: usize = 16 * 1024 * 1024;

/// A `PSO` of `levels` structures, each pointing at the next and the last one
/// null.
///
/// Every block carries the same structure — one `STRUCT` subtype 3 member at
/// offset 0 — so `levels` blocks are a chain `levels` long, and the walk writes
/// elements at depths 0 through `levels`: one per structure, plus the `pso:null`
/// leaf the last one's pointer becomes.
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

/// `pso`: a walk exactly as deep as a walk may be is written **and read back**.
///
/// The two directions were a level apart. `render` refuses at
/// `depth > MAX_DEPTH` and `Applier::structure` at the same, but `read_tree`
/// refused at `stack.len() >= MAX_DEPTH` — one level earlier. So a payload
/// whose walk is exactly this deep was rendered by `to_xml` and then refused by
/// `from_xml`, breaking R5.7's round-trip law at exactly its boundary and
/// blaming the document for a property of the payload.
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

/// `pso`: one level past it is refused, and refused as a fact about the payload.
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
    // And the document for a payload one level shallower, given one more level
    // of nesting by hand, is too deep for `read_tree` as well — the far side of
    // the same limit, on the direction that owns it.
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

/// `pso`: a document of exactly the bytes a payload allows is applied, and one
/// byte more is refused before it is parsed.
///
/// The write direction materialises the whole document into a tree before its
/// first comparison against the payload, so an unbounded document is an
/// unbounded allocation: 4,000,000 elements against a 172-byte payload reached
/// 652 MB resident and were then refused at the first child. The ceiling is
/// `render`'s own, in bytes rather than in elements — `docs/backlog.md`'s
/// recorded lesson that a budget in the wrong unit is not a budget — so a
/// document `to_xml` wrote always fits and one that describes no payload of
/// this size never has to be read.
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

    // Indentation is whitespace text, which the mapping already skips, so the
    // document can be padded to any length without describing anything else.
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

/// A `PSO` whose root holds the two string forms an edit has room to argue
/// about: a fixed inline `char[8]`, and a counted pointer whose two counts are
/// the caller's to choose.
///
/// `docs/metadata-encodings.md`, Pointers: the counted form is the pointer, then
/// `count1:u16be`, `count2:u16be` and a dead word, and the corpus carries both
/// orders of the two counts.
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

/// `pso`: a fixed inline string of exactly its room is written, and one byte
/// more is refused.
///
/// The room is the member's length **less one**, because the terminator is one
/// of the member's own bytes: `docs/metadata-encodings.md`, Pointers —
/// 116,507 of 116,507 shipped fixed inline strings end inside their member.
/// Bounding the write by the member's length instead let a document fill all
/// eight bytes of a `char[8]`, leaving a string that runs on into whatever
/// member follows. DR-052.
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

/// `pso`: a counted string of exactly its room is written, and one byte more is
/// refused — with the room taken from the **smaller** of the two counts.
///
/// Measured over all 39,469 counted strings the corpus reaches: the characters
/// number `min(count1, count2)` in every one, and the terminator is the byte
/// after. 786 of them carry the smaller count second, and bounding the write by
/// `count1` alone wrote a character over the terminator of each. DR-052.
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
