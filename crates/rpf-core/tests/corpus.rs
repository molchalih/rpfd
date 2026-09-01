//! Differential test: our reader against the committed oracle fixture, which
//! the reference implementation produced. Agreeing with it does not prove an
//! archive is understood; disagreeing proves something is wrong.
//!
//! No game data is tracked: archives are located through `RPF_CORPUS`, and with
//! it unset every test here is `#[ignore]`d rather than passing quietly.
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

/// Whether a name is a nested archive; `name` is already lower-cased by both
/// callers.
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

/// Reports a skip, naming the test that is skipping and what it would have
/// read; `RPF_REQUIRE_CORPUS` turns a skip into a failure.
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
/// Paths mirror the oracle's quirk: it walks entries linearly and skips
/// directory records, so a file's path carries no directory component.
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
#[cfg_attr(no_corpus, ignore = "no RPF_CORPUS: the sample archive is not tracked")]
fn reader_agrees_with_the_oracle() {
    let Some((path, fixture)) = corpus_archive("reader_agrees_with_the_oracle") else {
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
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("archive parses");

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

/// Every file entry, read as contents rather than as an extracted file — the
/// path `extract` short-circuits for resources, and the only one that runs the
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

/// Every resource of the sample, extracted and packed back, keeps the row it
/// had. All 20 carry their own `RSC7` header, so this says nothing about
/// whether the manifest field carried the flag words.
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
    // Subtracting the header, the entry table, the names blob and every payload
    // from `dlc.rpf`'s own length leaves 79,345,460 bytes; counting only the
    // header and the payloads overstates it by 320.
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
    // 27 files over the 3 archives. Also where a resource whose deflate stream
    // did not end exactly at its payload would surface.
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
    // while `verify` walks 27 across the three. The other 20 are covered
    // transitively: a nested `.rpf` is one entry, checksummed whole.
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

    // The recorded value is what `sha256sum` prints for the file `extract`
    // writes, not an internal encoding of it.
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
