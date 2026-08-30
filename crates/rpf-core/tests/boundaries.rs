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

use std::io::{Cursor, Write as _};

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
