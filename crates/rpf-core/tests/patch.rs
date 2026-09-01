//! In-place patching: what it writes, what it leaves alone, and what it
//! refuses before writing anything. The files are compared byte for byte
//! before and after, and every difference must fall inside the payload being
//! replaced or its own entry row.
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

use std::io::{Cursor, Read as _, Write as _};

use rpf_core::{Archive, FileKind, FileSpec, Plan, Storage, Unwatched};

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

fn edits(pairs: &[(&str, Vec<u8>)]) -> rpf_core::Changes {
    rpf_core::Changes::writing(
        pairs
            .iter()
            .map(|(path, bytes)| ((*path).to_owned(), bytes.clone()))
            .collect(),
    )
}

fn incompressible(len: u32) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect()
}

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

    let mut file = Cursor::new(after);
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("re-parses");
    let index = archive.find("data/notes.txt").expect("resolves");
    assert_eq!(archive.read(&mut file, index).expect("reads"), replacement);

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
    // Patching a set one at a time can apply two and then discover the third
    // will not fit, which is not what a commit promises.
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
    let index = archive.find("art.yft").expect("resolves");
    assert_eq!(
        archive.extract(&mut file, index).expect("extracts"),
        resource(0xBB),
        "the resource did not take"
    );
}

#[test]
fn two_edits_that_claim_the_same_bytes_are_refused() {
    // The inner edit would land in a nested archive the outer edit has just
    // replaced wholesale, so the two writes overlap: a refusal, not corruption.
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
    // Every change is inside the nested archive's own payload; the outer
    // header, entry table, names blob and row are untouched.
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

    let plan =
        rpf_core::plan(&mut file, &archive, &edits(&[("art.yft", resource(0xBB))])).expect("plans");
    assert!(matches!(plan, Plan::Fits(_)), "got {plan:?}");
}

/// Largest value the entry table's 24-bit compressed-size field holds. Spelled
/// out rather than imported: a test that took the limit from the code it checks
/// would agree with whatever that code came to believe.
const MAX_SIZE_24: u64 = 0x00FF_FFFF;

/// An `RSC7` payload one byte too large for that field. Only the first sixteen
/// bytes have to be a header: the size check comes before anything looks at the
/// deflate stream.
fn oversized_resource() -> Vec<u8> {
    let mut out = resource(0xAA);
    out.resize(usize::try_from(MAX_SIZE_24).expect("64-bit host") + 1, 0);
    out
}

/// An archive holding one resource, with room after it for a payload far larger
/// than the entry can describe: in a cramped entry the payload would be refused
/// for not fitting, hiding whether the size check ran at all.
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

/// The field a saturated resource's row carries; the payload's extent is the
/// room to the next payload, not this value.
fn saturated_field(archive: &Archive, path: &str) -> Option<u64> {
    let index = archive.find(path).ok()?;
    match archive.entry(index).ok()?.kind {
        rpf_core::EntryKind::Resource { compressed_len, .. } => Some(u64::from(compressed_len)),
        _ => None,
    }
}

#[test]
fn a_resource_too_large_for_its_size_field_writes_the_sentinel_rather_than_truncating() {
    // A payload past the 24-bit field is written whole with the row carrying
    // `MAX_SIZE_24`, the saturation sentinel; the low 24 bits of this length
    // are zero, which would read back as a stored entry.
    let payload = oversized_resource();
    let before = roomy_resource_archive();
    let mut file = Cursor::new(before.clone());
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");
    let allocation = archive
        .allocation(archive.find("art.yft").expect("resolves"))
        .expect("allocation");
    assert!(
        allocation > payload.len() as u64,
        "the entry needs room for the payload, or this tests the wrong write"
    );

    let plan = rpf_core::plan(&mut file, &archive, &edits(&[("art.yft", payload.clone())]))
        .expect("a resource past the field is written, not refused");
    let Plan::Fits(patches) = plan else {
        panic!("expected the patch to fit, got {plan:?}")
    };
    patches.apply(&mut file).expect("applies");

    let mut after = Cursor::new(file.into_inner());
    let archive = Archive::open(&mut after, &rpf_core::Unlock::unkeyed()).expect("re-parses");
    assert_eq!(
        saturated_field(&archive, "art.yft").expect("a resource row"),
        MAX_SIZE_24,
        "the row carries the sentinel, not a truncation of the real length"
    );
    // A saturated row means nothing of its own: the extent is the entry's room.
    assert_eq!(
        archive
            .payload_at(archive.find("art.yft").expect("resolves"))
            .expect("span")
            .1,
        allocation
    );
    // The extent runs past the payload into the entry's room, so the payload is
    // the prefix of what `extract` hands back.
    let index = archive.find("art.yft").expect("resolves");
    let mut back = Vec::new();
    archive
        .extracted(&mut after, index)
        .expect("opens")
        .read_to_end(&mut back)
        .expect("reads");
    assert_eq!(back.len(), allocation as usize);
    assert!(
        back[..payload.len()] == payload[..],
        "the payload did not survive the patch"
    );
}

#[test]
fn a_build_and_a_patch_write_the_same_sentinel_for_an_oversized_resource() {
    // The two write paths apply one rule to new contents; what matters here is
    // that they agree, not the verdict itself.
    let payload = oversized_resource();
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
        |_: &str| Ok(Cursor::new(payload.clone())),
        &mut Unwatched,
    )
    .expect("a resource past the field is written, not refused");

    let mut built = Cursor::new(out.into_inner());
    let archive = Archive::open(&mut built, &rpf_core::Unlock::unkeyed()).expect("parses");
    assert_eq!(
        saturated_field(&archive, "art.yft").expect("a resource row"),
        MAX_SIZE_24
    );
}

/// Largest a resource's `RSC7` header is, and the least a resource payload can
/// be. Spelled out rather than imported, for [`MAX_SIZE_24`]'s reason.
const RESOURCE_HEADER_LEN: usize = 16;

/// A payload with the right magic and a truncated header is not a resource: the
/// flags at offsets 8 and 12 are the ones the entry row carries, so a short
/// header is an entry whose flags would be invented. The read is a `take(16)`,
/// so the guard goes inert if its comparison is turned around.
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

/// A plan prints what it will do and never the bytes it will write: `Patches`
/// has a hand-written `Debug` because a payload is megabytes and the type shows
/// up in failure messages.
#[test]
fn a_plan_prints_what_it_will_do_and_never_the_bytes() {
    let before = archive_bytes();
    let mut file = Cursor::new(before);
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");

    // One repeated byte: `Debug` for a byte slice writes decimal, and 0xC7 is
    // 199.
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
