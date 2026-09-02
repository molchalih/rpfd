//! What the sample archive says about the reader, over and above the fixture.
//! `tests/oracle.rs` owns the differential against the committed oracle
//! fixtures — it rebuilds each one and compares bytes — so nothing here walks
//! an entry table to restate it. No game data is tracked: archives are located
//! through `RPF_CORPUS`, and with it unset every test is `#[ignore]`d.
#![allow(
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    reason = "test code; see the note above"
)]

use std::{
    collections::BTreeMap,
    env, fs,
    io::{Cursor, Read, Seek},
    path::PathBuf,
};

use rpf_core::{
    Archive, EntryKind, Manifest, Summary, Unwatched, Verified, format::resource::resource_len,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const FIXTURE: &str = "../../fixtures/rmrp_bp16_meringls63amg24.json";
const RELATIVE_ARCHIVE: &str = "rmrp_bp16_meringls63amg24/dlc.rpf";

/// Whether a name is a nested archive; `name` is already lower-cased.
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

/// Reports a skip; `RPF_REQUIRE_CORPUS` turns a skip into a failure.
fn skip<T>(test: &str, reason: &str) -> Option<T> {
    assert!(
        env::var_os("RPF_REQUIRE_CORPUS").is_none(),
        "RPF_REQUIRE_CORPUS is set, but {test} would have skipped: {reason}",
    );
    eprintln!("SKIP {test}: {reason}");
    None
}

fn corpus_archive(test: &str) -> Option<(PathBuf, Value)> {
    let Some(root) = env::var_os("RPF_CORPUS") else {
        return skip(
            test,
            &format!("RPF_CORPUS is not set, so {RELATIVE_ARCHIVE} cannot be located"),
        );
    };
    let path = PathBuf::from(root).join(RELATIVE_ARCHIVE);
    if !path.is_file() {
        return skip(test, &format!("{} is not a file", path.display()));
    }
    let fixture: Value =
        serde_json::from_str(&fs::read_to_string(FIXTURE).expect("fixture readable"))
            .expect("fixture parses");
    Some((path, fixture))
}

#[test]
#[cfg_attr(no_corpus, ignore = "no RPF_CORPUS: the sample archive is not tracked")]
fn paths_carry_their_directories() {
    let Some((path, _)) = corpus_archive("paths_carry_their_directories") else {
        return;
    };
    let mut file = fs::File::open(&path).expect("archive opens");
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("archive parses");

    let paths: Vec<String> = (0..u32::try_from(archive.entries().len()).expect("fits"))
        .map(|i| archive.path(i).expect("path builds"))
        .collect();

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
#[cfg_attr(no_corpus, ignore = "no RPF_CORPUS: the sample archive is not tracked")]
fn the_resource_bit_agrees_with_the_payload_magic() {
    let Some((path, _)) = corpus_archive("the_resource_bit_agrees_with_the_payload_magic") else {
        return;
    };
    let mut file = fs::File::open(&path).expect("archive opens");
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("archive parses");

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

/// Reads contents rather than extracting: the only path that runs the
/// header-stripping and the page-flag length check.
#[test]
#[cfg_attr(no_corpus, ignore = "no RPF_CORPUS: the sample archive is not tracked")]
fn contents_inflate_to_the_declared_lengths() {
    let Some((path, _)) = corpus_archive("contents_inflate_to_the_declared_lengths") else {
        return;
    };
    let mut file = fs::File::open(&path).expect("archive opens");
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("archive parses");

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

/// All 20 carry their own `RSC7` header, so this says nothing about whether the
/// manifest field carried the flag words.
#[test]
#[cfg_attr(no_corpus, ignore = "no RPF_CORPUS: the sample archive is not tracked")]
fn every_resource_of_the_sample_packs_back_with_the_row_it_had() {
    let Some((path, _)) =
        corpus_archive("every_resource_of_the_sample_packs_back_with_the_row_it_had")
    else {
        return;
    };
    let mut file = fs::File::open(&path).expect("archive opens");
    let outer = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("archive parses");

    let mut resources = 0_u32;
    for index in 1..u32::try_from(outer.entries().len()).expect("fits") {
        let name = outer.name(index).expect("name resolved").to_lowercase();
        if !is_nested_archive(&name) {
            continue;
        }
        let bytes = outer
            .read(&mut file, index)
            .expect("the nested archive reads");
        resources += packs_back_unchanged(&bytes);
    }
    assert_eq!(resources, 20, "the sample's resources");
}

fn packs_back_unchanged(bytes: &[u8]) -> u32 {
    let unlock = rpf_core::Unlock::unkeyed();
    let mut source = Cursor::new(bytes.to_vec());
    let archive = Archive::open(&mut source, &unlock).expect("the nested archive parses");
    let manifest = Manifest::of(&archive).expect("the manifest derives");

    let mut tree = BTreeMap::new();
    for (spec, index) in rpf_core::specs_of(&archive).expect("specs") {
        let extracted = archive.extract(&mut source, index).expect("extracts");
        tree.insert(spec.path, extracted);
    }

    let held = tree.clone();
    let mut out = Cursor::new(Vec::new());
    manifest
        .pack_into(
            &mut out,
            &unlock,
            move |wanted: &str| Ok(Cursor::new(held.get(wanted).cloned().unwrap_or_default())),
            &mut Unwatched,
        )
        .expect("the extracted tree packs back");

    let packed = out.into_inner();
    let mut source = Cursor::new(packed);
    let repacked = Archive::open(&mut source, &unlock).expect("the packed archive opens");

    let mut seen = 0_u32;
    for (path, expected) in &tree {
        let index = repacked.find(path).expect("the entry resolves");
        let extracted = repacked.extract(&mut source, index).expect("extracts");
        assert_eq!(&extracted, expected, "{path} changed across the round trip");

        let mut original = Cursor::new(bytes.to_vec());
        let before = Archive::open(&mut original, &unlock).expect("parses");
        let was = before
            .entry(before.find(path).expect("resolves"))
            .expect("in range")
            .kind;
        let now = repacked.entry(index).expect("in range").kind;
        if let EntryKind::Resource {
            system_flags,
            graphics_flags,
            ..
        } = was
        {
            assert!(
                matches!(
                    now,
                    EntryKind::Resource {
                        system_flags: system,
                        graphics_flags: graphics,
                        ..
                    } if (system, graphics) == (system_flags, graphics_flags)
                ),
                "{path}: the rebuilt row declares something else: {now:?}"
            );
            seen += 1;
        }
    }
    seen
}

#[test]
#[cfg_attr(no_corpus, ignore = "no RPF_CORPUS: the sample archive is not tracked")]
fn a_single_path_addresses_through_nested_archives() {
    let Some((path, fixture)) = corpus_archive("a_single_path_addresses_through_nested_archives")
    else {
        return;
    };
    let mut file = fs::File::open(&path).expect("archive opens");
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("archive parses");

    let meta = archive.find("data/vehicles.meta").expect("meta resolves");
    assert_eq!(
        archive.path(meta).expect("path builds"),
        "data/vehicles.meta"
    );
    assert!(archive.find("").is_ok(), "the empty path is the root");

    let (holder, index) = archive
        .locate(&mut file, "x64/vehicles.rpf/meringls63amg24.ytd")
        .expect("nested entry resolves");
    assert_eq!(holder.name(index).expect("name"), "meringls63amg24.ytd");

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

    assert!(
        archive
            .locate(&mut file, "X64/Vehicles.RPF/MeringLS63AMG24.ytd")
            .is_ok()
    );
    assert!(matches!(
        archive.find("data/nope.meta"),
        Err(rpf_core::Error::NotFound { .. })
    ));
    assert!(matches!(
        archive.locate(&mut file, "content.xml/whatever"),
        Err(rpf_core::Error::NotAnArchive { .. })
    ));
}

#[test]
#[cfg_attr(no_corpus, ignore = "no RPF_CORPUS: the sample archive is not tracked")]
fn the_summary_reproduces_the_measured_slack() {
    // Header, entry table, names blob and every payload subtracted from
    // `dlc.rpf`'s own length leave 79,345,460 bytes.
    let Some((path, _)) = corpus_archive("the_summary_reproduces_the_measured_slack") else {
        return;
    };
    let mut file = fs::File::open(&path).expect("archive opens");
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("archive parses");
    let summary = Summary::of(&mut file, &archive, "").expect("summarises");

    assert_eq!(summary.len, 144_504_832);
    assert_eq!(summary.entries, 11);
    assert_eq!(summary.directories, 4);
    assert_eq!(summary.nested_archives, 2);
    assert_eq!(summary.unreferenced_bytes, 79_345_460);
}

#[test]
#[cfg_attr(no_corpus, ignore = "no RPF_CORPUS: the sample archive is not tracked")]
fn every_entry_of_the_sample_reads_back() {
    // 27 files over the 3 archives.
    let Some((path, _)) = corpus_archive("every_entry_of_the_sample_reads_back") else {
        return;
    };
    let mut file = fs::File::open(&path).expect("archive opens");
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("archive parses");
    let verified = Verified::of(&mut file, &archive, &mut Unwatched).expect("reads back");

    let named: Vec<&str> = verified
        .problems
        .iter()
        .map(|problem| problem.path.as_str())
        .collect();
    assert!(named.is_empty(), "entries did not read back: {named:?}");
    assert_eq!(verified.checked, 27);
    assert!(verified.outcome().is_ok());
    assert_eq!(
        verified.contents_checked, 0,
        "read back is not checked against anything: there is no manifest here",
    );
}

#[test]
#[cfg_attr(no_corpus, ignore = "no RPF_CORPUS: the sample archive is not tracked")]
fn the_sample_verifies_against_a_manifest_of_itself() {
    // The manifest describes the outer archive — 7 files of the 11 entries —
    // while `verify` walks 27 across the three; a nested `.rpf` is one entry.
    let Some((path, _)) = corpus_archive("the_sample_verifies_against_a_manifest_of_itself") else {
        return;
    };
    let mut file = fs::File::open(&path).expect("archive opens");
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("archive parses");

    let manifest =
        Manifest::of_contents(&mut file, &archive, &mut Unwatched).expect("digests every entry");
    assert_eq!(manifest.entries.len(), 7);
    assert_eq!(
        manifest.checksums().len(),
        7,
        "every one records a checksum"
    );

    let verified = Verified::against(&mut file, &archive, &manifest, &mut Unwatched)
        .expect("reads back against its own record");
    let named: Vec<&str> = verified
        .problems
        .iter()
        .map(|problem| problem.path.as_str())
        .collect();
    assert!(named.is_empty(), "entries did not read back: {named:?}");
    assert_eq!((verified.checked, verified.contents_checked), (27, 7));

    // The recorded value is what `sha256sum` prints for the extracted file.
    let (spec, index) = rpf_core::specs_of(&archive)
        .expect("specs")
        .into_iter()
        .next()
        .expect("the sample holds files");
    let extracted = archive.extract(&mut file, index).expect("extracts");
    assert_eq!(
        manifest
            .checksums()
            .get(spec.path.as_str())
            .expect("recorded")
            .to_string(),
        sha256(&extracted),
    );
}
