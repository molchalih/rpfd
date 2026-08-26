//! Differential test: our reader against the committed oracle fixture.
//!
//! The fixture was produced by the reference implementation (`tools/oracle`)
//! and cross-checked against an independent reading before it was committed.
//! Agreeing with it is not proof an archive is understood — only an in-game
//! load is that, R0.5 — but disagreeing with it is proof something is wrong.
//!
//! `clippy.toml`'s `allow-*-in-tests` settings reach `#[cfg(test)]` modules and
//! not this directory — an integration test is compiled as its own crate, with
//! no `cfg(test)`. The exception in `docs/conventions.md` §15 is therefore
//! spelled out here instead: in a test a panic is the reporting mechanism, not
//! a crash, and a counter that overflows would be a bug in the test itself.
#![allow(
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    reason = "test code; see the note above"
)]
//!
//! No game data is tracked. Archives are located through `RPF_CORPUS`. With it
//! unset, or the archive absent, these tests **skip and say so**. They never
//! pass quietly, because a green suite that tested nothing is the most
//! expensive outcome available here. R0.2, R8.4.

use std::{
    collections::BTreeMap,
    env, fs,
    io::{Read, Seek},
    path::PathBuf,
};

use rpf_core::{Archive, EntryKind, format::resource_len};
use serde_json::Value;
use sha2::{Digest, Sha256};

const FIXTURE: &str = "../../fixtures/rmrp_bp16_meringls63amg24.json";
const RELATIVE_ARCHIVE: &str = "rmrp_bp16_meringls63amg24/dlc.rpf";

/// Whether a name is a nested archive.
///
/// `name` is already lower-cased by both callers, so the suffix comparison is
/// exact rather than case-sensitive-by-accident.
#[allow(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "name is lower-cased"
)]
fn is_nested_archive(name: &str) -> bool {
    name.ends_with(".rpf")
}

fn sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Reports a skip, and refuses to be quiet about it when the caller has said
/// the corpus must be there.
///
/// `cargo test` swallows a passing test's output, so an unconditional skip
/// reads as a pass — the outcome `docs/conventions.md` §12 calls the most
/// expensive one available. `RPF_REQUIRE_CORPUS` is the mechanical answer: set
/// it and a skip becomes a failure, so "the suite was green" and "the suite ran"
/// stop being different claims.
fn skip<T>(reason: &str) -> Option<T> {
    assert!(
        env::var_os("RPF_REQUIRE_CORPUS").is_none(),
        "RPF_REQUIRE_CORPUS is set, but this test would have skipped: {reason}",
    );
    eprintln!("SKIP: {reason}");
    None
}

/// The archive this fixture describes, or `None` with a reason on stderr.
fn corpus_archive() -> Option<(PathBuf, Value)> {
    let Some(root) = env::var_os("RPF_CORPUS") else {
        return skip(&format!(
            "RPF_CORPUS is not set, so {RELATIVE_ARCHIVE} cannot be located"
        ));
    };
    let path = PathBuf::from(root).join(RELATIVE_ARCHIVE);
    if !path.is_file() {
        return skip(&format!("{} is not a file", path.display()));
    }
    let fixture: Value =
        serde_json::from_str(&fs::read_to_string(FIXTURE).expect("fixture readable"))
            .expect("fixture parses");
    Some((path, fixture))
}

/// One entry, in the shape the oracle wrote it, so the two can be compared
/// field by field rather than by a summary.
fn row(archive: &Archive, index: u32) -> BTreeMap<String, Value> {
    let entry = archive.entry(index).expect("index came from this archive");
    let mut out = BTreeMap::new();
    out.insert(
        "name".into(),
        Value::from(archive.name(index).expect("name resolved at parse")),
    );
    let kind = match entry.kind {
        EntryKind::Directory {
            first_child,
            child_count,
        } => {
            out.insert("entries_index".into(), Value::from(first_child));
            out.insert("entries_count".into(), Value::from(child_count));
            "directory"
        }
        EntryKind::Binary {
            block,
            compressed_len,
            uncompressed_len,
            encryption,
        } => {
            out.insert("file_offset".into(), Value::from(block));
            out.insert("file_size".into(), Value::from(compressed_len));
            out.insert("uncompressed_size".into(), Value::from(uncompressed_len));
            out.insert(
                "is_encrypted".into(),
                Value::from(u32::from(encryption != 0)),
            );
            "binary"
        }
        EntryKind::Resource {
            block,
            compressed_len,
            system_flags,
            graphics_flags,
        } => {
            out.insert("file_offset".into(), Value::from(block));
            out.insert("file_size".into(), Value::from(compressed_len));
            out.insert("system_flags".into(), Value::from(system_flags));
            out.insert("graphics_flags".into(), Value::from(graphics_flags));
            out.insert("is_encrypted".into(), Value::from(0u32));
            "resource"
        }
    };
    out.insert("kind".into(), Value::from(kind));
    out
}

/// Walks this archive and every archive nested in it, collecting entry tables
/// and leaf-file checksums.
///
/// The path shapes deliberately mirror the oracle's, including its quirk: it
/// iterates entries linearly and skips directory records rather than descending
/// them, so a file's path carries no directory component. Reproduced here only
/// so the checksums line up. Real path construction is tested separately,
/// against the entry tables, which do carry the directory records.
fn collect<R: Read + Seek>(
    src: &mut R,
    archive: &Archive,
    archive_path: &str,
    prefix: &str,
    archives: &mut BTreeMap<String, Vec<BTreeMap<String, Value>>>,
    files: &mut BTreeMap<String, (usize, String)>,
) {
    let rows = (0..u32::try_from(archive.entries().len()).expect("entry count fits"))
        .map(|i| row(archive, i))
        .collect();
    archives.insert(archive_path.to_owned(), rows);

    for index in 0..u32::try_from(archive.entries().len()).expect("entry count fits") {
        let entry = archive.entry(index).expect("index in range");
        if entry.is_directory() {
            continue;
        }
        let name = archive
            .name(index)
            .expect("name resolved at parse")
            .to_lowercase();
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };

        if is_nested_archive(&name) {
            let nested = archive
                .open_nested(src, index)
                .expect("nested archive parses");
            let nested_path = format!("{archive_path}/{name}");
            collect(src, &nested, &nested_path, &path, archives, files);
        } else {
            let bytes = archive.extract(src, index).expect("entry extracts");
            files.insert(path, (bytes.len(), sha256(&bytes)));
        }
    }
}

#[test]
fn reader_agrees_with_the_oracle() {
    let Some((path, fixture)) = corpus_archive() else {
        return;
    };

    let raw = fs::read(&path).expect("archive readable");
    assert_eq!(
        sha256(&raw),
        fixture["source"]["sha256"]
            .as_str()
            .expect("fixture records a checksum"),
        "the archive at {} is not the one this fixture describes",
        path.display(),
    );

    let mut file = fs::File::open(&path).expect("archive opens");
    let archive = Archive::open(&mut file).expect("archive parses");

    let mut archives = BTreeMap::new();
    let mut files = BTreeMap::new();
    collect(
        &mut file,
        &archive,
        "dlc.rpf",
        "",
        &mut archives,
        &mut files,
    );

    // Entry tables, field by field.
    let expected_archives = fixture["archives"]
        .as_array()
        .expect("fixture lists archives");
    assert_eq!(archives.len(), expected_archives.len(), "archive count");
    for expected in expected_archives {
        let key = expected["path"].as_str().expect("archive has a path");
        let ours = archives
            .get(key)
            .unwrap_or_else(|| panic!("we did not find archive {key}"));
        let theirs = expected["entries"].as_array().expect("archive has entries");
        assert_eq!(ours.len(), theirs.len(), "{key}: entry count");
        for (index, (ours, theirs)) in ours.iter().zip(theirs).enumerate() {
            for (field, value) in ours {
                assert_eq!(
                    Some(value),
                    theirs.get(field),
                    "{key} entry {index}: field {field}",
                );
            }
        }
    }

    // Leaf files, by length and checksum of the extracted bytes.
    let expected_files = fixture["files"].as_array().expect("fixture lists files");
    assert_eq!(files.len(), expected_files.len(), "leaf file count");
    for expected in expected_files {
        let key = expected["path"].as_str().expect("file has a path");
        let (len, digest) = files
            .get(key)
            .unwrap_or_else(|| panic!("we did not extract {key}"));
        assert_eq!(
            u64::try_from(*len).expect("length fits"),
            expected["len"].as_u64().expect("file has a length"),
            "{key}: length",
        );
        assert_eq!(
            digest.as_str(),
            expected["sha256"].as_str().expect("checksum"),
            "{key}: checksum"
        );
    }
}

#[test]
fn paths_carry_their_directories() {
    let Some((path, _)) = corpus_archive() else {
        return;
    };
    let mut file = fs::File::open(&path).expect("archive opens");
    let archive = Archive::open(&mut file).expect("archive parses");

    let paths: Vec<String> = (0..u32::try_from(archive.entries().len()).expect("fits"))
        .map(|i| archive.path(i).expect("path builds"))
        .collect();

    // The root is the empty string; everything else is rooted at it. These are
    // the directory components the oracle's own walk throws away.
    assert_eq!(paths.first().map(String::as_str), Some(""));
    assert!(paths.iter().any(|p| p == "data/vehicles.meta"), "{paths:?}");
    assert!(
        paths
            .iter()
            .any(|p| p == "x64/vehiclemods/meringls63amg24_mods.rpf"),
        "{paths:?}"
    );
    assert!(paths.iter().any(|p| p == "content.xml"), "{paths:?}");
}

#[test]
fn the_resource_bit_agrees_with_the_payload_magic() {
    // Q7, against every entry we can reach. One producer's archive does not
    // settle it, but a mismatch here would settle it the other way at once.
    let Some((path, _)) = corpus_archive() else {
        return;
    };
    let mut file = fs::File::open(&path).expect("archive opens");
    let archive = Archive::open(&mut file).expect("archive parses");

    let mut checked = 0u32;
    for index in 0..u32::try_from(archive.entries().len()).expect("fits") {
        let entry = archive.entry(index).expect("index in range");
        if entry.is_directory() {
            continue;
        }
        let flagged = matches!(entry.kind, EntryKind::Resource { .. });
        let magic = archive
            .payload_is_resource(&mut file, index)
            .expect("payload readable");
        assert_eq!(
            flagged, magic,
            "entry {index}: resource bit disagrees with payload magic"
        );
        checked += 1;
    }
    assert!(checked > 0, "no entries were checked");
}

/// Every file entry, read as **contents** rather than as an extracted file.
///
/// This is the path `extract` short-circuits for resources, so without this
/// test the header-stripping and the page-flag length check are never run. A
/// negative control found exactly that hole: setting `RESOURCE_HEADER_LEN` to
/// zero left the differential test green.
#[test]
fn contents_inflate_to_the_declared_lengths() {
    let Some((path, _)) = corpus_archive() else {
        return;
    };
    let mut file = fs::File::open(&path).expect("archive opens");
    let archive = Archive::open(&mut file).expect("archive parses");

    let mut binaries = 0u32;
    let mut resources = 0u32;
    read_all(&mut file, &archive, &mut binaries, &mut resources);

    // The sample: 5 plain files and 2 stored nested archives, 20 resources.
    assert_eq!(binaries, 7, "binary entries read");
    assert_eq!(resources, 20, "resource entries read");
}

fn read_all<R: Read + Seek>(
    src: &mut R,
    archive: &Archive,
    binaries: &mut u32,
    resources: &mut u32,
) {
    for index in 0..u32::try_from(archive.entries().len()).expect("fits") {
        let entry = archive.entry(index).expect("index in range");
        let name = archive.name(index).expect("name resolved").to_lowercase();

        match entry.kind {
            EntryKind::Directory { .. } => {}

            EntryKind::Binary {
                uncompressed_len, ..
            } => {
                let bytes = archive.read(src, index).expect("binary entry reads");
                assert_eq!(
                    u64::try_from(bytes.len()).expect("fits"),
                    u64::from(uncompressed_len),
                    "entry {index} ({name}): inflated length",
                );
                *binaries += 1;
                if is_nested_archive(&name) {
                    let nested = archive.open_nested(src, index).expect("nested parses");
                    read_all(src, &nested, binaries, resources);
                }
            }

            EntryKind::Resource {
                system_flags,
                graphics_flags,
                ..
            } => {
                let bytes = archive.read(src, index).expect("resource entry reads");
                assert_eq!(
                    u64::try_from(bytes.len()).expect("fits"),
                    resource_len(system_flags, graphics_flags),
                    "entry {index} ({name}): inflated length against the page flags",
                );
                *resources += 1;
            }
        }
    }
}

/// R3.5a: one string addresses through the nesting.
#[test]
fn a_single_path_addresses_through_nested_archives() {
    let Some((path, fixture)) = corpus_archive() else {
        return;
    };
    let mut file = fs::File::open(&path).expect("archive opens");
    let archive = Archive::open(&mut file).expect("archive parses");

    // Within this archive only.
    let meta = archive.find("data/vehicles.meta").expect("meta resolves");
    assert_eq!(
        archive.path(meta).expect("path builds"),
        "data/vehicles.meta"
    );
    assert!(archive.find("").is_ok(), "the empty path is the root");

    // Through one level of nesting, in a single lookup.
    let (holder, index) = archive
        .locate(&mut file, "x64/vehicles.rpf/meringls63amg24.ytd")
        .expect("nested entry resolves");
    assert_eq!(holder.name(index).expect("name"), "meringls63amg24.ytd");

    // And it is the same bytes the fixture recorded for that file.
    let bytes = holder.extract(&mut file, index).expect("extracts");
    let expected = fixture["files"]
        .as_array()
        .expect("files")
        .iter()
        .find(|f| f["path"] == "vehicles.rpf/meringls63amg24.ytd")
        .expect("fixture has the nested texture");
    assert_eq!(
        sha256(&bytes),
        expected["sha256"].as_str().expect("checksum")
    );

    // Case folding, and the failure modes.
    assert!(
        archive
            .locate(&mut file, "X64/Vehicles.RPF/MeringLS63AMG24.ytd")
            .is_ok()
    );
    assert!(matches!(
        archive.find("data/nope.meta"),
        Err(rpf_core::Error::NotFound { .. })
    ));
    // content.xml is a file, not an archive, so descending into it says so.
    assert!(matches!(
        archive.locate(&mut file, "content.xml/whatever"),
        Err(rpf_core::Error::NotAnArchive { .. })
    ));
}
