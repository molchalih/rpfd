//! In-place patching: what it writes, what it leaves alone, and what it
//! refuses before writing anything.
//!
//! The assertion a rebuild cannot make is that **nothing else changed**. These
//! compare the whole file before and after, byte for byte, and require every
//! difference to fall inside the payload being replaced or its own entry row.
//!
//! The other assertion here is the one planning exists for: a set of edits is
//! decided in full before any of it is written, so a plan that cannot be
//! carried out leaves the archive exactly as it was.
//!
//! Corpus-free: each test builds the archive it needs.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "test code; a panic is the reporting mechanism, and these run on \
              64-bit hosts against buffers the test itself created"
)]

use std::io::{Cursor, Write as _};

use rpf_core::{Archive, FileKind, FileSpec, Plan, Storage, Unwatched};

/// A resource payload: an RSC7 header describing one 512-byte system page,
/// followed by a deflate stream of exactly that.
fn resource(fill: u8) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"RSC7");
    out.extend_from_slice(&162_u32.to_le_bytes());
    out.extend_from_slice(&0x8000_0010_u32.to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes());
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&vec![fill; 512]).expect("deflates");
    out.extend_from_slice(&encoder.finish().expect("finishes"));
    out
}

/// An archive with a stored file, a deflated file and a resource.
fn archive_bytes() -> Vec<u8> {
    let files = vec![
        FileSpec {
            path: "data/notes.txt".to_owned(),
            kind: FileKind::Binary {
                storage: Storage::Deflate,
                encryption: 0,
            },
        },
        FileSpec {
            path: "art.yft".to_owned(),
            kind: FileKind::Resource { declared: None },
        },
        FileSpec {
            path: "raw.bin".to_owned(),
            kind: FileKind::Binary {
                storage: Storage::Stored,
                encryption: 0,
            },
        },
    ];
    let mut out = Cursor::new(Vec::new());
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |wanted: &str| {
            Ok(Cursor::new(match wanted {
                "art.yft" => resource(0xAA),
                "raw.bin" => vec![3_u8; 200],
                _ => b"the quick brown fox jumps over the lazy dog. ".repeat(4),
            }))
        },
        &mut Unwatched,
    )
    .expect("builds");
    out.into_inner()
}

/// The edits a plan is asked for, in the shape the daemon holds them.
fn edits(pairs: &[(&str, Vec<u8>)]) -> rpf_core::Changes {
    rpf_core::Changes::writing(
        pairs
            .iter()
            .map(|(path, bytes)| ((*path).to_owned(), bytes.clone()))
            .collect(),
    )
}

/// Bytes that do not compress, so they cannot be squeezed into a block.
fn incompressible(len: u32) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect()
}

/// Every byte position at which two buffers differ.
fn differences(before: &[u8], after: &[u8]) -> Vec<usize> {
    assert_eq!(
        before.len(),
        after.len(),
        "an in-place patch must not resize the archive"
    );
    (0..before.len())
        .filter(|&i| before[i] != after[i])
        .collect()
}

#[test]
fn a_patch_writes_only_its_own_payload_and_row() {
    let before = archive_bytes();
    let mut file = Cursor::new(before.clone());
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");

    let index = archive.find("data/notes.txt").expect("resolves");
    let (payload_at, _) = archive.payload_at(index).expect("span");
    let row_at = archive.row_at(index).expect("row");
    let allocation = archive.allocation(index).expect("allocation");
    assert!(
        allocation >= 512,
        "expected a block of room, got {allocation}"
    );

    // Shorter than the original, so the entry's sizes genuinely change and the
    // row has to be rewritten.
    let replacement = b"short".to_vec();
    let plan = rpf_core::plan(
        &mut file,
        &archive,
        &edits(&[("data/notes.txt", replacement.clone())]),
    )
    .expect("plans");
    let Plan::Fits(patches) = plan else {
        panic!("expected a patch to fit, got {plan:?}")
    };

    let planned: Vec<_> = patches.planned().collect();
    assert_eq!(planned.len(), 1);
    assert_eq!(planned[0].at, payload_at);
    assert_eq!(planned[0].path, "data/notes.txt");
    assert!(planned[0].len <= allocation);

    patches.apply(&mut file).expect("applies");

    let after = file.into_inner();
    for position in differences(&before, &after) {
        let in_payload =
            position >= payload_at as usize && position < (payload_at + allocation) as usize;
        let in_row = position >= row_at as usize && position < (row_at + 16) as usize;
        assert!(
            in_payload || in_row,
            "byte {position} changed, and it is neither the payload nor the row",
        );
    }

    // The row really was rewritten: the new contents read back.
    let mut file = Cursor::new(after);
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("re-parses");
    let index = archive.find("data/notes.txt").expect("resolves");
    assert_eq!(archive.read(&mut file, index).expect("reads"), replacement);

    // And nothing else moved.
    let raw = archive.find("raw.bin").expect("resolves");
    assert_eq!(
        archive.read(&mut file, raw).expect("reads"),
        vec![3_u8; 200]
    );
}

#[test]
fn a_patch_that_does_not_fit_writes_nothing_at_all() {
    let before = archive_bytes();
    let mut file = Cursor::new(before.clone());
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");

    let plan = rpf_core::plan(
        &mut file,
        &archive,
        &edits(&[("data/notes.txt", incompressible(200_000))]),
    )
    .expect("decides");

    match plan {
        Plan::DoesNotFit(ref rejected) => {
            assert_eq!(rejected.len(), 1);
            assert_eq!(rejected[0].path, "data/notes.txt");
            assert!(rejected[0].needed > rejected[0].allocation);
        }
        other => panic!("that should not have fitted, got {other:?}"),
    }
    assert_eq!(
        file.into_inner(),
        before,
        "planning a patch wrote something"
    );
}

#[test]
fn one_edit_that_does_not_fit_holds_back_the_ones_that_do() {
    // The reason planning exists. Patching a set one at a time can apply two
    // and then discover the third will not fit, which is not what a commit
    // promises. R4.14.
    let before = archive_bytes();
    let mut file = Cursor::new(before.clone());
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");

    let plan = rpf_core::plan(
        &mut file,
        &archive,
        &edits(&[
            ("data/notes.txt", b"short".to_vec()),
            ("raw.bin", incompressible(200_000)),
            ("art.yft", resource(0xBB)),
        ]),
    )
    .expect("decides");

    match plan {
        Plan::DoesNotFit(ref rejected) => {
            let paths: Vec<&str> = rejected.iter().map(|r| r.path.as_str()).collect();
            assert_eq!(
                paths,
                vec!["raw.bin"],
                "only the edit that does not fit should be named"
            );
        }
        other => panic!("one of those cannot fit, got {other:?}"),
    }
    assert_eq!(
        file.into_inner(),
        before,
        "an edit that fitted was written despite one that did not"
    );
}

#[test]
fn several_edits_are_applied_together() {
    let before = archive_bytes();
    let mut file = Cursor::new(before.clone());
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");

    let plan = rpf_core::plan(
        &mut file,
        &archive,
        &edits(&[
            ("data/notes.txt", b"rewritten".to_vec()),
            ("raw.bin", vec![7_u8; 64]),
            ("art.yft", resource(0xBB)),
        ]),
    )
    .expect("decides");
    let Plan::Fits(patches) = plan else {
        panic!("all three should fit: {plan:?}")
    };
    assert_eq!(patches.planned().count(), 3);
    patches.apply(&mut file).expect("applies");

    let after = file.into_inner();
    let mut file = Cursor::new(after);
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("re-parses");
    for (path, expected) in [
        ("data/notes.txt", b"rewritten".to_vec()),
        ("raw.bin", vec![7_u8; 64]),
    ] {
        let index = archive.find(path).expect("resolves");
        assert_eq!(
            archive.read(&mut file, index).expect("reads"),
            expected,
            "{path} did not take"
        );
    }
    // `extract` for the resource, which is the form it takes outside the
    // archive — the same one `cat` writes and `put` accepts.
    let index = archive.find("art.yft").expect("resolves");
    assert_eq!(
        archive.extract(&mut file, index).expect("extracts"),
        resource(0xBB),
        "the resource did not take"
    );
}

#[test]
fn two_edits_that_claim_the_same_bytes_are_refused() {
    // A nested archive and a file inside it. Patching both would write the
    // inner edit into a nested archive that the outer edit has just replaced
    // wholesale, and the two writes overlap. Nothing about the bytes on disk
    // is wrong, so this is a refusal rather than a corrupt archive.
    let inner = archive_bytes();
    let files = vec![FileSpec {
        path: "x64/inner.rpf".to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Stored,
            encryption: 0,
        },
    }];
    let mut outer = Cursor::new(Vec::new());
    rpf_core::build(
        &mut outer,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(inner.clone())),
        &mut Unwatched,
    )
    .expect("outer builds");
    let before = outer.into_inner();

    let mut file = Cursor::new(before.clone());
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");

    let refused = rpf_core::plan(
        &mut file,
        &archive,
        &edits(&[
            ("x64/inner.rpf", inner.clone()),
            ("x64/inner.rpf/raw.bin", vec![9_u8; 200]),
        ]),
    );
    assert!(
        matches!(refused, Err(rpf_core::Error::Overlapping { .. })),
        "got {refused:?}",
    );
    assert_eq!(
        file.into_inner(),
        before,
        "a refused plan still wrote something"
    );
}

#[test]
fn patching_through_nesting_leaves_every_ancestor_untouched() {
    let inner = archive_bytes();
    let files = vec![FileSpec {
        path: "x64/inner.rpf".to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Stored,
            encryption: 0,
        },
    }];
    let mut outer = Cursor::new(Vec::new());
    rpf_core::build(
        &mut outer,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(inner.clone())),
        &mut Unwatched,
    )
    .expect("outer builds");
    let before = outer.into_inner();

    let mut file = Cursor::new(before.clone());
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");

    // Where the nested archive sits in the outer file.
    let nested_index = archive.find("x64/inner.rpf").expect("resolves");
    let (nested_at, nested_len) = archive.payload_at(nested_index).expect("span");
    let nested_row = archive.row_at(nested_index).expect("row");

    let plan = rpf_core::plan(
        &mut file,
        &archive,
        &edits(&[("x64/inner.rpf/raw.bin", vec![9_u8; 200])]),
    )
    .expect("plans");
    let Plan::Fits(patches) = plan else {
        panic!("expected a patch to fit, got {plan:?}")
    };
    patches.apply(&mut file).expect("applies");

    let after = file.into_inner();
    // Every change is inside the nested archive's own payload. The outer
    // archive's header, entry table, names blob and that entry's row are all
    // untouched — there was nothing above to rebuild.
    for position in differences(&before, &after) {
        assert!(
            position >= nested_at as usize && position < (nested_at + nested_len) as usize,
            "byte {position} changed outside the nested archive's payload",
        );
        assert!(
            !(position >= nested_row as usize && position < (nested_row + 16) as usize),
            "the outer entry row was rewritten, and it should not have been",
        );
    }

    let mut file = Cursor::new(after);
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("re-parses");
    let (holder, index) = archive
        .locate(&mut file, "x64/inner.rpf/raw.bin")
        .expect("resolves");
    assert_eq!(
        holder.read(&mut file, index).expect("reads"),
        vec![9_u8; 200]
    );
}

#[test]
fn a_resource_entry_refuses_a_payload_that_is_not_one() {
    let before = archive_bytes();
    let mut file = Cursor::new(before.clone());
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");

    let refused = rpf_core::plan(
        &mut file,
        &archive,
        &edits(&[("art.yft", b"plain text".to_vec())]),
    );
    assert!(
        matches!(refused, Err(rpf_core::Error::NotAResource { .. })),
        "got {refused:?}",
    );
    assert_eq!(
        file.get_ref(),
        &before,
        "a refused plan still wrote something"
    );

    // A real resource is accepted, and its flags come from the payload.
    let plan =
        rpf_core::plan(&mut file, &archive, &edits(&[("art.yft", resource(0xBB))])).expect("plans");
    assert!(matches!(plan, Plan::Fits(_)), "got {plan:?}");
}

/// Largest value the entry table's 24-bit compressed-size field holds.
/// `docs/rpf-format.md`, Entry table.
///
/// Spelled out here rather than imported from the writer on purpose. A test
/// that took the limit from the code it is checking would agree with whatever
/// the code came to believe; this one fails if the writer stops refusing at
/// the width the format actually has.
const MAX_SIZE_24: u64 = 0x00FF_FFFF;

/// An `RSC7` payload one byte too large for that field.
///
/// Only the first sixteen bytes have to be a header; the size check comes
/// before anything looks at the deflate stream, and a real one of this length
/// would make the test cost twenty seconds to prove a comparison.
fn oversized_resource() -> Vec<u8> {
    let mut out = resource(0xAA);
    out.resize(usize::try_from(MAX_SIZE_24).expect("64-bit host") + 1, 0);
    out
}

/// An archive holding one resource, with room after it for a payload far
/// larger than the entry can describe.
///
/// The room is the point. An oversized payload in a cramped entry is refused
/// for not fitting, which hides the bug: the sample's `.yft` entries have
/// megabytes of slack, so the size check is the only thing standing between a
/// 20 MB payload and an entry row that records 3 MB of it.
fn roomy_resource_archive() -> Vec<u8> {
    let files = vec![FileSpec {
        path: "art.yft".to_owned(),
        kind: FileKind::Resource { declared: None },
    }];
    let mut out = Cursor::new(Vec::new());
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(resource(0xAA))),
        &mut Unwatched,
    )
    .expect("builds");
    let mut bytes = out.into_inner();
    bytes.resize(
        bytes.len() + usize::try_from(MAX_SIZE_24).expect("64-bit host") + 4096,
        0,
    );
    bytes
}

#[test]
fn a_resource_too_large_for_its_size_field_is_refused_rather_than_truncated() {
    // The entry table stores a compressed size in three bytes. A payload over
    // that limit used to be written whole while its row recorded the low 24
    // bits of the length, which is an archive that parses, verifies, and hands
    // the runtime a fraction of a resource.
    let payload = oversized_resource();
    let before = roomy_resource_archive();
    let mut file = Cursor::new(before.clone());
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");
    assert!(
        archive
            .allocation(archive.find("art.yft").expect("resolves"))
            .expect("allocation")
            > payload.len() as u64,
        "the entry needs room for the payload, or this tests the wrong refusal"
    );

    let refused = rpf_core::plan(&mut file, &archive, &edits(&[("art.yft", payload.clone())]));
    match refused {
        Err(rpf_core::Error::FieldOverflow { len, limit, .. }) => {
            assert_eq!(limit, MAX_SIZE_24, "the limit reported");
            assert_eq!(len, payload.len() as u64, "the length reported");
        }
        other => panic!("expected the size field to refuse it, got {other:?}"),
    }
    assert_eq!(
        file.into_inner(),
        before,
        "a refused plan still wrote something"
    );
}

#[test]
fn a_build_and_a_patch_refuse_the_same_oversized_resource() {
    // The two write paths apply one rule — the entry's storage rule — to new
    // contents, and they used to be two implementations of it that disagreed.
    let payload = oversized_resource();
    let files = vec![FileSpec {
        path: "art.yft".to_owned(),
        kind: FileKind::Resource { declared: None },
    }];
    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(payload.clone())),
        &mut Unwatched,
    );
    match refused {
        Err(rpf_core::Error::FieldOverflow { len, limit, .. }) => {
            assert_eq!(limit, MAX_SIZE_24, "the limit reported");
            assert_eq!(len, payload.len() as u64, "the length reported");
        }
        other => panic!("expected the size field to refuse it, got {other:?}"),
    }
}

/// Largest a resource's `RSC7` header is, and the least a resource payload can
/// be. `docs/rpf-format.md`, Compression.
///
/// Spelled out here rather than imported for `MAX_SIZE_24`'s reason: a test
/// that took the width from the code it checks would agree with whatever the
/// code came to believe.
const RESOURCE_HEADER_LEN: usize = 16;

/// A payload with the right magic and a truncated header is not a resource.
///
/// The magic check catches a payload that is not a resource at all; this one
/// is refused a step earlier, for being shorter than the header whose two flag
/// words the entry duplicates. The read is a `take(16)`, so its length can
/// never be *above* sixteen — which means the guard goes inert if the
/// comparison is turned around, and nothing noticed: no test offered either
/// write path a resource payload shorter than its own header, and one that
/// begins `RSC7` walks straight past the magic check behind it.
///
/// `docs/rpf-format.md`, Resource entries: the flags at offsets 8 and 12 of
/// the header are the ones the entry row carries, so a header that is not all
/// there is an entry whose flags would be invented.
#[test]
fn a_build_and_a_patch_refuse_a_resource_shorter_than_its_header() {
    let mut truncated = b"RSC7".to_vec();
    truncated.extend_from_slice(&162_u32.to_le_bytes());
    truncated.extend_from_slice(&0x8000_0010_u32.to_le_bytes());
    assert!(
        truncated.len() < RESOURCE_HEADER_LEN,
        "the payload is meant to be short of a whole header"
    );

    let files = vec![FileSpec {
        path: "art.yft".to_owned(),
        kind: FileKind::Resource { declared: None },
    }];
    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(truncated.clone())),
        &mut Unwatched,
    );
    match refused {
        Err(rpf_core::Error::NotAResource { ref path, reason }) => {
            assert_eq!(path, "art.yft");
            assert_eq!(reason, "the payload is shorter than a resource header");
        }
        other => panic!("expected a truncated header to be refused, got {other:?}"),
    }
    assert!(
        out.into_inner().is_empty(),
        "nothing may be written for a refused resource"
    );

    // And the patch path, which applies the same rule through `store`.
    let before = archive_bytes();
    let mut file = Cursor::new(before.clone());
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");
    let refused = rpf_core::plan(&mut file, &archive, &edits(&[("art.yft", truncated)]));
    assert!(
        matches!(refused, Err(rpf_core::Error::NotAResource { .. })),
        "got {refused:?}",
    );
    assert_eq!(
        file.get_ref(),
        &before,
        "a refused plan still wrote something"
    );
}

/// A plan prints what it will do and never the bytes it will write.
///
/// `Patches` carries a hand-written `Debug` for one reason, stated in its own
/// comment: a payload is megabytes and this type appears in test failures. That
/// is a contract, and nothing asserted it — the impl could have been replaced
/// by one that prints nothing, or by the derived one that prints every byte,
/// and the suite stayed green either way. The second is the expensive
/// direction: a `--json` payload or a panic message carrying a whole entry.
#[test]
fn a_plan_prints_what_it_will_do_and_never_the_bytes() {
    let before = archive_bytes();
    let mut file = Cursor::new(before);
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");

    // A payload of one repeated byte, so that finding it in the rendering is
    // unambiguous: `Debug` for a byte slice writes decimal, and 0xC7 is 199.
    let replacement = vec![0xC7_u8; 400];
    let plan = rpf_core::plan(
        &mut file,
        &archive,
        &edits(&[("raw.bin", replacement.clone())]),
    )
    .expect("decides");
    let Plan::Fits(patches) = plan else {
        panic!("expected the patch to fit")
    };

    let rendered = format!("{patches:?}");
    assert!(
        rendered.contains("raw.bin"),
        "a plan that says nothing about what it will do: {rendered}"
    );
    assert!(
        !rendered.contains("199, 199"),
        "the payload reached the rendering: {rendered}"
    );
    assert!(
        rendered.len() < replacement.len(),
        "the rendering grows with the payload: {} bytes",
        rendered.len()
    );
}
