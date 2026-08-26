//! R0.4: unpack, pack, unpack, and compare.
//!
//! The rebuilt archive is not expected to be byte-identical to the original —
//! a different deflate implementation makes different, equally valid streams,
//! and this rebuilder packs tightly where the original carries 82.7% slack.
//! What must survive is every entry's **contents**, and the checksums the
//! oracle recorded for them.
//!
//! Green here means the archive is self-consistent and reads back. It does not
//! mean the game will load it. Only R0.5 means that, and there is no machine
//! for it yet.
#![allow(
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "test code; a panic is the reporting mechanism, and an entry count \
              that does not fit u32 could not have been read in the first place"
)]

use std::{
    collections::BTreeMap,
    env, fs,
    io::{Read, Seek, Write},
    path::PathBuf,
};

use rpf_core::{Archive, EntryKind, FileKind, FileSpec, Storage};
use serde_json::Value;
use sha2::{Digest, Sha256};

const FIXTURE: &str = "../../fixtures/rmrp_bp16_meringls63amg24.json";
const RELATIVE_ARCHIVE: &str = "rmrp_bp16_meringls63amg24/dlc.rpf";

/// Whether a name is a nested archive. `name` is already lower-cased, so the
/// suffix comparison is exact rather than case-sensitive by accident.
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

fn corpus_archive() -> Option<(PathBuf, Value)> {
    let reason = match env::var_os("RPF_CORPUS") {
        None => "RPF_CORPUS is not set".to_owned(),
        Some(root) => {
            let path = PathBuf::from(root).join(RELATIVE_ARCHIVE);
            if path.is_file() {
                let fixture =
                    serde_json::from_str(&fs::read_to_string(FIXTURE).expect("fixture readable"))
                        .expect("fixture parses");
                return Some((path, fixture));
            }
            format!("{} is not a file", path.display())
        }
    };
    assert!(
        env::var_os("RPF_REQUIRE_CORPUS").is_none(),
        "RPF_REQUIRE_CORPUS is set, but this test would have skipped: {reason}",
    );
    eprintln!("SKIP: {reason}");
    None
}

/// Turns an archive we can read into the specification for one we can write.
///
/// The storage choice is taken from the original rather than guessed: an entry
/// that was stored stays stored, and one that was deflated is offered to the
/// compressor again. That is the manifest's job (R4.1) and this is it in
/// miniature.
fn specs_for(archive: &Archive) -> Vec<(FileSpec, u32)> {
    let mut out = Vec::new();
    for index in 0..u32::try_from(archive.entries().len()).expect("fits") {
        let entry = archive.entry(index).expect("in range");
        let kind = match entry.kind {
            EntryKind::Directory { .. } => continue,
            EntryKind::Resource { .. } => FileKind::Resource,
            EntryKind::Binary {
                compressed_len,
                encryption,
                ..
            } => FileKind::Binary {
                storage: if compressed_len == 0 {
                    Storage::Stored
                } else {
                    Storage::Deflate
                },
                encryption,
            },
        };
        let path = archive.path(index).expect("path builds");
        out.push((FileSpec { path, kind }, index));
    }
    out
}

/// Every leaf file in an archive, keyed the way the fixture keys them: name
/// only, prefixed by any nested archive it lives in.
fn leaf_checksums<R: Read + Seek>(
    src: &mut R,
    archive: &Archive,
    prefix: &str,
    out: &mut BTreeMap<String, String>,
) {
    for index in 0..u32::try_from(archive.entries().len()).expect("fits") {
        let entry = archive.entry(index).expect("in range");
        if entry.is_directory() {
            continue;
        }
        let name = archive.name(index).expect("name").to_lowercase();
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };

        if is_nested_archive(&name) {
            let nested = archive.open_nested(src, index).expect("nested parses");
            leaf_checksums(src, &nested, &path, out);
        } else {
            let bytes = archive.extract(src, index).expect("extracts");
            out.insert(path, sha256(&bytes));
        }
    }
}

#[test]
fn a_rebuilt_archive_holds_the_same_contents() {
    let Some((path, fixture)) = corpus_archive() else {
        return;
    };

    let mut source = fs::File::open(&path).expect("archive opens");
    let original = Archive::open(&mut source).expect("archive parses");
    let specs = specs_for(&original);
    let by_path: BTreeMap<String, u32> = specs.iter().map(|(s, i)| (s.path.clone(), *i)).collect();
    let files: Vec<FileSpec> = specs.into_iter().map(|(s, _)| s).collect();
    let directories = rpf_core::directories_of(&original).expect("directories");

    let mut rebuilt = tempfile::NamedTempFile::new().expect("temp file");
    let report = rpf_core::build(rebuilt.as_file_mut(), &files, &directories, |wanted| {
        let index = *by_path.get(wanted).expect("path came from this archive");
        original.extract(&mut source, index)
    })
    .expect("archive builds");

    assert_eq!(
        report.entry_count,
        original.entries().len() as u32,
        "entry count"
    );
    rebuilt.as_file_mut().flush().expect("flushed");

    // Read the rebuild back with the same reader.
    let mut handle = fs::File::open(rebuilt.path()).expect("rebuild opens");
    let round = Archive::open(&mut handle).expect("rebuild parses");

    // Same tree, by full path.
    let original_paths: Vec<String> = (0..original.entries().len() as u32)
        .map(|i| original.path(i).expect("path"))
        .collect();
    let round_paths: Vec<String> = (0..round.entries().len() as u32)
        .map(|i| round.path(i).expect("path"))
        .collect();
    let mut a = original_paths.clone();
    let mut b = round_paths.clone();
    a.sort();
    b.sort();
    assert_eq!(a, b, "the rebuilt tree differs");

    // Same contents, against the oracle's own record of the original.
    let mut round_sums = BTreeMap::new();
    leaf_checksums(&mut handle, &round, "", &mut round_sums);

    let expected: BTreeMap<String, String> = fixture["files"]
        .as_array()
        .expect("files")
        .iter()
        .map(|f| {
            (
                f["path"].as_str().expect("path").to_owned(),
                f["sha256"].as_str().expect("sha").to_owned(),
            )
        })
        .collect();
    assert_eq!(
        round_sums, expected,
        "contents changed across the round trip"
    );

    // Children come out in ascending name order, which is what every directory
    // in every observed archive does. Whether the runtime requires it is Q1;
    // until that is settled the rebuilder follows the observation.
    let mut directories = 0_u32;
    for index in 0..round.entries().len() as u32 {
        let Ok(range) = round.children(index) else {
            continue;
        };
        let names: Vec<&str> = range.map(|c| round.name(c).expect("name")).collect();
        assert!(
            names.windows(2).all(|pair| pair[0] <= pair[1]),
            "entry {index} children are not sorted: {names:?}",
        );
        directories += 1;
    }
    assert_eq!(
        directories, 4,
        "directories in the rebuilt top-level archive"
    );

    // Keeping the rebuild lets a different implementation read it, which is a
    // stronger check than our reader reading our writer. tools/oracle/README.md
    if let Some(dest) = env::var_os("RPF_REBUILD_OUT") {
        fs::copy(rebuilt.path(), PathBuf::from(dest)).expect("rebuild is copyable");
    }

    // Packing tightly is the visible difference. The original is 82.7% slack.
    let original_len = fs::metadata(&path).expect("stat").len();
    assert!(
        report.len < original_len,
        "rebuilt {} is not smaller than the original {original_len}",
        report.len,
    );
    eprintln!(
        "rebuilt {} bytes from {original_len} ({:.1}%)",
        report.len,
        100.0 * report.len as f64 / original_len as f64
    );
}

#[test]
fn an_injected_corruption_is_caught() {
    let Some((path, _)) = corpus_archive() else {
        return;
    };

    let mut source = fs::File::open(&path).expect("archive opens");
    let original = Archive::open(&mut source).expect("archive parses");
    let specs = specs_for(&original);
    let by_path: BTreeMap<String, u32> = specs.iter().map(|(s, i)| (s.path.clone(), *i)).collect();
    let files: Vec<FileSpec> = specs.into_iter().map(|(s, _)| s).collect();
    let directories = rpf_core::directories_of(&original).expect("directories");

    let mut rebuilt = tempfile::NamedTempFile::new().expect("temp file");
    rpf_core::build(rebuilt.as_file_mut(), &files, &directories, |wanted| {
        let index = *by_path.get(wanted).expect("known path");
        original.extract(&mut source, index)
    })
    .expect("archive builds");
    rebuilt.as_file_mut().flush().expect("flushed");

    // Flip a byte inside the first payload, which is a deflate stream.
    let mut bytes = fs::read(rebuilt.path()).expect("rebuild readable");
    let mut handle = fs::File::open(rebuilt.path()).expect("opens");
    let round = Archive::open(&mut handle).expect("parses");
    let victim = round.find("content.xml").expect("content.xml is there");
    let EntryKind::Binary { block, .. } = round.entry(victim).expect("in range").kind else {
        panic!("content.xml should be a binary entry");
    };
    let at = (block as usize) * 512 + 8;
    bytes[at] ^= 0xFF;
    fs::write(rebuilt.path(), &bytes).expect("writable");

    let mut damaged = fs::File::open(rebuilt.path()).expect("opens");
    let archive = Archive::open(&mut damaged).expect("the table of contents is intact");
    let result = archive.read(&mut damaged, victim);
    assert!(
        result.is_err(),
        "a corrupted deflate stream read back as {:?}",
        result.map(|b| b.len()),
    );
}

/// R4.9: changing an entry inside a nested archive rebuilds every ancestor.
///
/// The swap is deliberate — a texture's payload replaced by a model's. The two
/// carry different page flags (`0x00020000`/`0xD1020008` against
/// `0xA10402C6`/`0x20000000`), so if the rebuilt entry ends up with the flags
/// it had rather than the flags its new payload carries, this fails.
#[test]
fn replacing_a_nested_entry_cascades() {
    const TARGET: &str = "x64/vehicles.rpf/meringls63amg24.ytd";
    const DONOR: &str = "x64/vehicles.rpf/meringls63amg24.yft";

    let Some((path, fixture)) = corpus_archive() else {
        return;
    };

    let mut source = fs::File::open(&path).expect("archive opens");
    let original = Archive::open(&mut source).expect("archive parses");

    let (holder, donor_index) = original.locate(&mut source, DONOR).expect("donor resolves");
    let donor_bytes = holder
        .extract(&mut source, donor_index)
        .expect("donor extracts");
    let donor_sum = sha256(&donor_bytes);
    let EntryKind::Resource {
        system_flags,
        graphics_flags,
        ..
    } = holder.entry(donor_index).expect("in range").kind
    else {
        panic!("the donor should be a resource")
    };

    let mut rebuilt = tempfile::NamedTempFile::new().expect("temp file");
    rpf_core::replace_at(
        &mut source,
        &original,
        TARGET,
        donor_bytes,
        rebuilt.as_file_mut(),
    )
    .expect("cascading rebuild");
    rebuilt.as_file_mut().flush().expect("flushed");

    let mut handle = fs::File::open(rebuilt.path()).expect("rebuild opens");
    let round = Archive::open(&mut handle).expect("rebuild parses");

    // The target now holds the donor's bytes.
    let (holder, index) = round.locate(&mut handle, TARGET).expect("target resolves");
    let bytes = holder.extract(&mut handle, index).expect("target extracts");
    assert_eq!(sha256(&bytes), donor_sum, "the replacement did not take");

    // And the entry describing it carries the payload's flags, not the old
    // entry's. This is the assertion the swap exists for.
    let EntryKind::Resource {
        system_flags: got_system,
        graphics_flags: got_graphics,
        ..
    } = holder.entry(index).expect("in range").kind
    else {
        panic!("the rebuilt entry should still be a resource")
    };
    assert_eq!(
        (got_system, got_graphics),
        (system_flags, graphics_flags),
        "flags"
    );

    // Every other leaf file is untouched.
    let mut sums = BTreeMap::new();
    leaf_checksums(&mut handle, &round, "", &mut sums);
    let expected: BTreeMap<String, String> = fixture["files"]
        .as_array()
        .expect("files")
        .iter()
        .map(|f| {
            (
                f["path"].as_str().expect("path").to_owned(),
                f["sha256"].as_str().expect("sha").to_owned(),
            )
        })
        .collect();
    for (leaf, sum) in &expected {
        if leaf == "vehicles.rpf/meringls63amg24.ytd" {
            continue;
        }
        assert_eq!(
            sums.get(leaf),
            Some(sum),
            "{leaf} changed but should not have"
        );
    }
    assert_eq!(sums.len(), expected.len(), "leaf count changed");

    if let Some(dest) = env::var_os("RPF_CASCADE_OUT") {
        fs::copy(rebuilt.path(), PathBuf::from(dest)).expect("copyable");
    }
}
