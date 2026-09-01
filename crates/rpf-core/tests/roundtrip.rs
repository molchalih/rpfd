//! Unpack, pack, unpack, and compare. A rebuild is not byte-identical to its
//! original: what must survive is every entry's contents and the checksums the
//! oracle recorded for them.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "test code; a panic is the reporting mechanism, and an entry count \
              that does not fit u32 could not have been read in the first place. \
              clippy.toml's allow-panic-in-tests reaches #[test] functions and \
              not the plain ones they call, which is what the crate-level allow \
              is for. docs/conventions.md §15"
)]

use std::{
    collections::BTreeMap,
    env, fs,
    io::{Cursor, Read, Seek, Write},
    path::PathBuf,
};

use rpf_core::{Archive, EntryKind, Error, FileKind, FileSpec, Storage, Unwatched};
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

/// Scratch space on disk, unnamed so an interrupted rebuild leaves nothing.
struct OnDisk;

impl rpf_core::Scratch for OnDisk {
    type Sink = fs::File;

    fn create(&mut self) -> Result<fs::File, Error> {
        tempfile::tempfile().map_err(|source| Error::Io { offset: 0, source })
    }
}

fn sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Asserts a build was refused for two names in one directory, naming both.
fn collision<T: std::fmt::Debug>(refused: Result<T, Error>, path: &str, against: &str) {
    match refused {
        Err(Error::NameCollision {
            path: refused,
            other,
        }) => {
            assert_eq!(refused, path, "the wrong path was refused");
            assert_eq!(other, against, "refused against the wrong path");
        }
        other => panic!("expected {path:?} to collide with {against:?}, got {other:?}"),
    }
}

/// Asserts that a build was refused for `path`, for `reason` and no other.
fn refusal<T: std::fmt::Debug>(refused: Result<T, Error>, path: &str, reason: &str) {
    match refused {
        Err(Error::BadPath {
            path: refused,
            reason: why,
        }) => {
            assert_eq!(refused, path, "the wrong path was refused");
            assert_eq!(why, reason, "refused for the wrong reason");
        }
        other => panic!("expected {path} to be refused as {reason:?}, got {other:?}"),
    }
}

/// The archive this fixture describes, or `None` with a reason on stderr. No
/// `RPF_CORPUS` at all is turned into `#[ignore]` by `build.rs`.
fn corpus_archive(test: &str) -> Option<(PathBuf, Value)> {
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
        "RPF_REQUIRE_CORPUS is set, but {test} would have skipped: {reason}",
    );
    eprintln!("SKIP {test}: {reason}");
    None
}

/// The specification for rewriting `archive`, each entry's storage choice taken
/// from the original rather than guessed.
fn specs_for(archive: &Archive) -> Vec<(FileSpec, u32)> {
    let mut out = Vec::new();
    for index in 0..u32::try_from(archive.entries().len()).expect("fits") {
        let entry = archive.entry(index).expect("in range");
        let kind = match entry.kind {
            EntryKind::Directory { .. } => continue,
            EntryKind::Resource { .. } => FileKind::Resource { declared: None },
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

/// Every leaf file, keyed the way the fixture keys them: name only, prefixed by
/// any nested archive it lives in.
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
#[cfg_attr(no_corpus, ignore = "no RPF_CORPUS: the sample archive is not tracked")]
fn a_rebuilt_archive_holds_the_same_contents() {
    let Some((path, fixture)) = corpus_archive("a_rebuilt_archive_holds_the_same_contents") else {
        return;
    };

    let mut source = fs::File::open(&path).expect("archive opens");
    let original =
        Archive::open(&mut source, &rpf_core::Unlock::unkeyed()).expect("archive parses");
    let specs = specs_for(&original);
    let by_path: BTreeMap<String, u32> = specs.iter().map(|(s, i)| (s.path.clone(), *i)).collect();
    let files: Vec<FileSpec> = specs.into_iter().map(|(s, _)| s).collect();
    let directories = rpf_core::directories_of(&original).expect("directories");

    let mut rebuilt = tempfile::NamedTempFile::new().expect("temp file");
    let report = rpf_core::build(
        rebuilt.as_file_mut(),
        rpf_core::Version::Rpf7,
        &files,
        &directories,
        |wanted: &str| {
            let index = *by_path.get(wanted).expect("path came from this archive");
            original.extract(&mut source, index).map(Cursor::new)
        },
        &mut Unwatched,
    )
    .expect("archive builds");

    assert_eq!(
        report.entry_count,
        original.entries().len() as u32,
        "entry count"
    );
    rebuilt.as_file_mut().flush().expect("flushed");

    let mut handle = fs::File::open(rebuilt.path()).expect("rebuild opens");
    let round = Archive::open(&mut handle, &rpf_core::Unlock::unkeyed()).expect("rebuild parses");

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

    // Ascending name order, which is what every observed directory does.
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

    if let Some(dest) = env::var_os("RPF_REBUILD_OUT") {
        fs::copy(rebuilt.path(), PathBuf::from(dest)).expect("rebuild is copyable");
    }

    // The original carries slack; a rebuild packs tightly.
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
#[cfg_attr(no_corpus, ignore = "no RPF_CORPUS: the sample archive is not tracked")]
fn an_injected_corruption_is_caught() {
    let Some((path, _)) = corpus_archive("an_injected_corruption_is_caught") else {
        return;
    };

    let mut source = fs::File::open(&path).expect("archive opens");
    let original =
        Archive::open(&mut source, &rpf_core::Unlock::unkeyed()).expect("archive parses");
    let specs = specs_for(&original);
    let by_path: BTreeMap<String, u32> = specs.iter().map(|(s, i)| (s.path.clone(), *i)).collect();
    let files: Vec<FileSpec> = specs.into_iter().map(|(s, _)| s).collect();
    let directories = rpf_core::directories_of(&original).expect("directories");

    let mut rebuilt = tempfile::NamedTempFile::new().expect("temp file");
    rpf_core::build(
        rebuilt.as_file_mut(),
        rpf_core::Version::Rpf7,
        &files,
        &directories,
        |wanted: &str| {
            let index = *by_path.get(wanted).expect("known path");
            original.extract(&mut source, index).map(Cursor::new)
        },
        &mut Unwatched,
    )
    .expect("archive builds");
    rebuilt.as_file_mut().flush().expect("flushed");

    // Flip a byte inside the first payload, which is a deflate stream.
    let mut bytes = fs::read(rebuilt.path()).expect("rebuild readable");
    let mut handle = fs::File::open(rebuilt.path()).expect("opens");
    let round = Archive::open(&mut handle, &rpf_core::Unlock::unkeyed()).expect("parses");
    let victim = round.find("content.xml").expect("content.xml is there");
    let EntryKind::Binary { block, .. } = round.entry(victim).expect("in range").kind else {
        panic!("content.xml should be a binary entry");
    };
    let at = (block as usize) * 512 + 8;
    bytes[at] ^= 0xFF;
    fs::write(rebuilt.path(), &bytes).expect("writable");

    let mut damaged = fs::File::open(rebuilt.path()).expect("opens");
    let archive = Archive::open(&mut damaged, &rpf_core::Unlock::unkeyed())
        .expect("the table of contents is intact");
    let result = archive.read(&mut damaged, victim);
    assert!(
        result.is_err(),
        "a corrupted deflate stream read back as {:?}",
        result.map(|b| b.len()),
    );
}

/// A texture's payload is replaced by a model's: the two carry different page
/// flags, so an entry keeping its old flags fails here.
#[test]
#[cfg_attr(no_corpus, ignore = "no RPF_CORPUS: the sample archive is not tracked")]
fn replacing_a_nested_entry_cascades() {
    const TARGET: &str = "x64/vehicles.rpf/meringls63amg24.ytd";
    const DONOR: &str = "x64/vehicles.rpf/meringls63amg24.yft";

    let Some((path, fixture)) = corpus_archive("replacing_a_nested_entry_cascades") else {
        return;
    };

    let mut source = fs::File::open(&path).expect("archive opens");
    let original =
        Archive::open(&mut source, &rpf_core::Unlock::unkeyed()).expect("archive parses");

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
    let edits = BTreeMap::from([(TARGET.to_owned(), donor_bytes)]);
    rpf_core::rewrite(
        &mut source,
        &original,
        &rpf_core::Changes::writing(edits),
        rebuilt.as_file_mut(),
        // A 62 MB ancestor, rebuilt into scratch on disk rather than memory.
        &mut OnDisk,
        &mut Unwatched,
    )
    .expect("cascading rebuild");
    rebuilt.as_file_mut().flush().expect("flushed");

    let mut handle = fs::File::open(rebuilt.path()).expect("rebuild opens");
    let round = Archive::open(&mut handle, &rpf_core::Unlock::unkeyed()).expect("rebuild parses");

    let (holder, index) = round.locate(&mut handle, TARGET).expect("target resolves");
    let bytes = holder.extract(&mut handle, index).expect("target extracts");
    assert_eq!(sha256(&bytes), donor_sum, "the replacement did not take");

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

/// An entry added, one removed and one renamed inside a nested archive, all in
/// one change set.
#[test]
#[cfg_attr(no_corpus, ignore = "no RPF_CORPUS: the sample archive is not tracked")]
fn a_structural_change_to_the_sample_reads_back() {
    const INSIDE: &str = "x64/vehicles.rpf";

    let Some((path, _)) = corpus_archive("a_structural_change_to_the_sample_reads_back") else {
        return;
    };

    let mut source = fs::File::open(&path).expect("archive opens");
    let original =
        Archive::open(&mut source, &rpf_core::Unlock::unkeyed()).expect("archive parses");
    let before = rpf_core::Listed::at(&mut source, &original, INSIDE, false)
        .expect("lists")
        .len();

    let mut changes = rpf_core::Changes::new();
    changes.set(
        format!("{INSIDE}/added.meta"),
        rpf_core::Change::Write {
            contents: std::sync::Arc::new(rpf_core::Bytes::new(b"<added/>".to_vec())),
            create: true,
            allow_encoding_change: false,
        },
    );
    changes.set(
        format!("{INSIDE}/meringls63amg24.ytd"),
        rpf_core::Change::Remove { recursive: false },
    );
    changes.set(
        format!("{INSIDE}/meringls63amg24.yft"),
        rpf_core::Change::RenameTo(format!("{INSIDE}/renamed.yft")),
    );

    let mut rebuilt = tempfile::NamedTempFile::new().expect("temp file");
    rpf_core::rewrite(
        &mut source,
        &original,
        &changes,
        rebuilt.as_file_mut(),
        &mut OnDisk,
        &mut Unwatched,
    )
    .expect("rewrites");
    rebuilt.as_file_mut().flush().expect("flushed");

    let mut handle = fs::File::open(rebuilt.path()).expect("rebuild opens");
    let round = Archive::open(&mut handle, &rpf_core::Unlock::unkeyed()).expect("rebuild parses");

    let after: Vec<String> = rpf_core::Listed::at(&mut handle, &round, INSIDE, false)
        .expect("lists")
        .into_iter()
        .map(|row| row.path)
        .collect();
    assert_eq!(
        after.len(),
        before,
        "one added, one removed: the count should not have moved"
    );
    assert!(
        after.contains(&format!("{INSIDE}/added.meta")),
        "the addition is not there: {after:?}"
    );
    assert!(
        !after.contains(&format!("{INSIDE}/meringls63amg24.ytd")),
        "the removal is still there: {after:?}"
    );
    assert!(
        after.contains(&format!("{INSIDE}/renamed.yft")),
        "the rename did not take: {after:?}"
    );

    let (holder, index) = round
        .locate(&mut handle, &format!("{INSIDE}/added.meta"))
        .expect("the added entry resolves");
    assert_eq!(
        holder.extract(&mut handle, index).expect("extracts"),
        b"<added/>".to_vec(),
    );

    rpf_core::Verified::of(&mut handle, &round, &mut Unwatched)
        .expect("verifies")
        .outcome()
        .expect("reads back clean");
}

/// Bytes that do not compress, so a deflate of them is larger than they are.
fn incompressible(len: usize) -> Vec<u8> {
    let mut state = 0x1234_5678_u32;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

/// The deflate stream is written into the sink before its length is known, so a
/// fallback to stored must zero the tail it reached past. Two entries: one with
/// a payload after it, one last in the archive.
#[test]
fn a_deflate_that_does_not_pay_for_itself_is_stored_and_nothing_stale_is_left() {
    let deflated = |path: &str| FileSpec {
        path: path.to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Deflate,
            encryption: 0,
        },
    };
    // 511 bytes: one short of a block, so the padding left is not wide enough
    // to absorb what deflate added.
    let bulk = incompressible(511);
    let files = [deflated("first.bin"), deflated("last.bin")];
    let (report, bytes) = build_on_disk(&files, &[], |_| Ok(bulk.clone()));

    let mut src = Cursor::new(bytes.clone());
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
    for path in ["first.bin", "last.bin"] {
        let index = archive.find(path).expect("resolves");
        let EntryKind::Binary { compressed_len, .. } = archive.entry(index).expect("in range").kind
        else {
            panic!("{path} should be binary")
        };
        assert_eq!(
            compressed_len, 0,
            "{path} should have fallen back to stored"
        );
        assert_eq!(
            archive.extract(&mut src, index).expect("extracts"),
            bulk,
            "{path} did not read back"
        );
    }

    // Past the last payload is the padding the archive claims, not a stale tail.
    let last = archive.find("last.bin").expect("resolves");
    let EntryKind::Binary { block, .. } = archive.entry(last).expect("in range").kind else {
        panic!("last.bin should be binary")
    };
    let at = u64::from(block) * 512 + u64::from(bulk.len() as u32);
    assert!(
        bytes[at as usize..].iter().all(|byte| *byte == 0),
        "the slack after the last payload is not zero"
    );
    assert_eq!(bytes.len() as u64, report.len, "length");
}

/// The version reaching the header is the parameter, not a constant.
#[test]
fn an_archive_is_written_at_the_version_it_was_asked_for() {
    for &version in rpf_core::Version::ALL {
        let mut sink = tempfile::NamedTempFile::new().expect("temp file");
        rpf_core::build(
            sink.as_file_mut(),
            version,
            &[stored("a.txt")],
            &[],
            |_: &str| Ok(Cursor::new(b"contents".to_vec())),
            &mut Unwatched,
        )
        .expect("builds");
        sink.as_file_mut().flush().expect("flushed");
        let bytes = fs::read(sink.path()).expect("readable");

        assert_eq!(
            bytes.get(0..4),
            Some(&version.magic()[..]),
            "{version:?} was not written with its own magic"
        );
        let mut src = Cursor::new(bytes);
        assert_eq!(
            Archive::open(&mut src, &rpf_core::Unlock::unkeyed())
                .expect("parses")
                .version(),
            version,
            "{version:?} did not read back as itself"
        );
    }
}

#[test]
fn a_rebuild_writes_the_version_the_original_was_read_at() {
    for &version in rpf_core::Version::ALL {
        let mut sink = tempfile::NamedTempFile::new().expect("temp file");
        rpf_core::build(
            sink.as_file_mut(),
            version,
            &[stored("a.txt")],
            &[],
            |_: &str| Ok(Cursor::new(b"contents".to_vec())),
            &mut Unwatched,
        )
        .expect("builds");
        sink.as_file_mut().flush().expect("flushed");

        let mut src = Cursor::new(fs::read(sink.path()).expect("readable"));
        let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
        let edits = BTreeMap::from([("a.txt".to_owned(), b"replaced".to_vec())]);
        let mut out = tempfile::NamedTempFile::new().expect("temp file");
        rpf_core::rewrite(
            &mut src,
            &archive,
            &rpf_core::Changes::writing(edits),
            out.as_file_mut(),
            &mut rpf_core::InMemory,
            &mut Unwatched,
        )
        .expect("rebuilds");
        out.as_file_mut().flush().expect("flushed");

        let mut round = Cursor::new(fs::read(out.path()).expect("readable"));
        assert_eq!(
            Archive::open(&mut round, &rpf_core::Unlock::unkeyed())
                .expect("parses")
                .version(),
            version,
            "a rebuild changed the version"
        );
    }
}

fn stored(path: &str) -> FileSpec {
    FileSpec {
        path: path.to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Stored,
            encryption: 0,
        },
    }
}

/// Builds into a real file, not a cursor: `Cursor::write_all(&[])` past the end
/// resizes the vector, so a build writing fewer bytes than it reports would stay
/// invisible.
fn build_on_disk<F>(
    files: &[FileSpec],
    directories: &[String],
    mut fetch: F,
) -> (rpf_core::Report, Vec<u8>)
where
    F: FnMut(&str) -> Result<Vec<u8>, Error>,
{
    let mut sink = tempfile::NamedTempFile::new().expect("temp file");
    let report = rpf_core::build(
        sink.as_file_mut(),
        rpf_core::Version::Rpf7,
        files,
        directories,
        |wanted: &str| fetch(wanted).map(Cursor::new),
        &mut Unwatched,
    )
    .expect("builds");
    sink.as_file_mut().flush().expect("flushed");
    let bytes = fs::read(sink.path()).expect("the rebuild is readable");
    assert_eq!(
        bytes.len() as u64,
        report.len,
        "the file on disk is not the length the report claims"
    );
    (report, bytes)
}

fn replaced_on_disk(source: &[u8], edits: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut src = Cursor::new(source.to_vec());
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");

    let mut sink = tempfile::NamedTempFile::new().expect("temp file");
    let report = rpf_core::rewrite(
        &mut src,
        &archive,
        &rpf_core::Changes::writing(edits.clone()),
        sink.as_file_mut(),
        &mut rpf_core::InMemory,
        &mut Unwatched,
    )
    .expect("rebuilds");
    sink.as_file_mut().flush().expect("flushed");
    let bytes = fs::read(sink.path()).expect("the rebuild is readable");
    assert_eq!(
        bytes.len() as u64,
        report.len,
        "the file on disk is not the length the report claims"
    );
    bytes
}

fn built(files: &[FileSpec], contents: &[u8]) -> Vec<u8> {
    build_on_disk(files, &[], |_| Ok(contents.to_vec())).1
}

/// An archive holding one file, `f.txt`.
fn inner_archive(contents: &[u8]) -> Vec<u8> {
    built(&[stored("f.txt")], contents)
}

/// An archive holding `inner` at `sub/inner.rpf`.
fn outer_archive(inner: &[u8]) -> Vec<u8> {
    built(&[stored("sub/inner.rpf")], inner)
}

/// Padding to the block boundary must not overwrite a payload ending on one.
#[test]
fn a_payload_ending_on_a_block_boundary_keeps_its_last_byte() {
    let files = [stored("raw.bin")];
    let mut corrupted = Vec::new();

    for len in 1..=4096_usize {
        let contents = vec![0xAA_u8; len];
        let (_, bytes) = build_on_disk(&files, &[], |_| Ok(contents.clone()));

        let mut file = Cursor::new(bytes);
        let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");
        let index = archive.find("raw.bin").expect("resolves");
        if archive.read(&mut file, index).expect("reads") != contents {
            corrupted.push(len);
        }
    }

    assert!(
        corrupted.is_empty(),
        "payloads of these lengths read back changed: {corrupted:?}",
    );
}

#[test]
fn an_archive_with_no_files_is_still_a_whole_number_of_blocks() {
    let (report, bytes) = build_on_disk(&[], &[], |_| Ok(Vec::new()));
    assert_eq!(report.len % 512, 0, "not a whole number of blocks");

    let mut file = Cursor::new(bytes);
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");
    assert_eq!(archive.entries().len(), 1, "the root, and nothing else");
}

/// Padding forward from where a zero-byte last payload ended anchors on its own
/// start, leaving the file short of the previous payload's last byte.
#[test]
fn a_zero_length_last_payload_does_not_truncate_the_archive() {
    let files = [stored("a.txt"), stored("z-empty.txt")];
    let (report, bytes) = build_on_disk(&files, &[], |wanted: &str| {
        Ok(if wanted == "a.txt" {
            b"abcd".to_vec()
        } else {
            Vec::new()
        })
    });
    assert_eq!(report.len % 512, 0, "not a whole number of blocks");

    let mut file = Cursor::new(bytes);
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");
    for (path, expected) in [("a.txt", b"abcd".to_vec()), ("z-empty.txt", Vec::new())] {
        let index = archive.find(path).expect("resolves");
        assert_eq!(
            archive.read(&mut file, index).expect("reads"),
            expected,
            "{path} did not read back"
        );
    }
}

/// `Storage::Deflate` on empty contents deflates to two bytes, which is not
/// smaller than nothing, so the stored branch wins and zero bytes go out.
#[test]
fn deflating_an_empty_file_does_not_truncate_the_archive() {
    let deflated = |path: &str| FileSpec {
        path: path.to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Deflate,
            encryption: 0,
        },
    };
    let files = [deflated("a.txt"), deflated("z-empty.txt")];
    let (report, bytes) = build_on_disk(&files, &[], |wanted: &str| {
        Ok(if wanted == "a.txt" {
            vec![b'x'; 4096]
        } else {
            Vec::new()
        })
    });
    assert_eq!(report.len % 512, 0, "not a whole number of blocks");

    let mut file = Cursor::new(bytes);
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");
    let index = archive.find("z-empty.txt").expect("resolves");
    assert!(
        archive.read(&mut file, index).expect("reads").is_empty(),
        "the empty entry did not read back"
    );
}

#[test]
fn emptying_the_last_payload_of_a_rebuild_does_not_truncate_it() {
    let source = built(&[stored("a.txt"), stored("z.txt")], b"contents");
    let edits = BTreeMap::from([("z.txt".to_owned(), Vec::new())]);
    let bytes = replaced_on_disk(&source, &edits);

    let mut file = Cursor::new(bytes);
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("rebuild parses");
    let index = archive.find("z.txt").expect("resolves");
    assert!(
        archive.read(&mut file, index).expect("reads").is_empty(),
        "the emptied entry did not read back"
    );
    let index = archive.find("a.txt").expect("resolves");
    assert_eq!(
        archive.read(&mut file, index).expect("reads"),
        b"contents".to_vec(),
        "the entry before it changed"
    );
}

/// A file entry's name offset is sixteen bits, so a name sitting past 65,535
/// bytes into the names blob would silently be somebody else's.
#[test]
fn a_file_name_offset_past_sixteen_bits_is_refused() {
    // Each name costs 19 bytes in the blob and the root's empty name takes the
    // first, so file `k` sits at 1 + 19k and 3450 is the first that will not fit.
    let files: Vec<FileSpec> = (0..=3450).map(|index| stored(&name_of(index))).collect();

    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(b"x".to_vec())),
        &mut Unwatched,
    );

    match refused {
        Err(Error::FieldOverflow {
            path,
            what,
            len,
            limit,
        }) => {
            assert_eq!(what, "file name offset");
            assert_eq!(len, 65_551, "the offset of the first name past the field");
            assert_eq!(limit, 65_535, "the largest a 16-bit field holds");
            assert_eq!(path, name_of(3450), "the entry that could not be described");
        }
        other => panic!("expected the name offset to be refused, got {other:?}"),
    }
}

/// The other side of the same limit: the last name here lands four bytes inside
/// the field, at 65,532, which is where an off-by-one would show.
#[test]
fn every_file_name_below_sixteen_bits_reads_back() {
    let files: Vec<FileSpec> = (0..=3449).map(|index| stored(&name_of(index))).collect();
    let (report, bytes) = build_on_disk(&files, &[], |_| Ok(b"x".to_vec()));
    assert_eq!(report.names_len, 65_532 + 19, "the whole blob");

    let mut file = Cursor::new(bytes);
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");
    for index in 0..=3449_u32 {
        // Entry 0 is the root; the files follow in generation order.
        assert_eq!(
            archive.name(index + 1).expect("named"),
            name_of(index),
            "entry {index} carries the wrong name"
        );
    }
}

/// The `index`th generated name: 18 bytes, so byte order and generation order
/// are the same thing.
fn name_of(index: u32) -> String {
    format!("{index:04}-file-name.bin")
}

/// The outer build's last payload is whatever the inner build produced.
#[test]
fn a_nested_rebuild_keeps_the_last_byte_of_its_last_payload() {
    let contents = vec![0xAA_u8; 512];
    let inner = inner_archive(&contents);
    let source = outer_archive(&inner);
    let edits = BTreeMap::from([("sub/inner.rpf/f.txt".to_owned(), contents.clone())]);

    let mut file = Cursor::new(replaced_on_disk(&source, &edits));
    let round = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("rebuild parses");
    let (holder, index) = round
        .locate(&mut file, "sub/inner.rpf/f.txt")
        .expect("resolves");
    assert_eq!(
        holder.read(&mut file, index).expect("reads"),
        contents,
        "the innermost payload lost a byte to the outer archive's padding"
    );
}

/// Replacing a nested archive wholesale and editing a file inside it are the
/// same bytes twice.
#[test]
fn replacing_an_archive_and_a_file_inside_it_is_refused() {
    let inner = inner_archive(b"original");
    let replacement = inner_archive(b"a different archive entirely");
    let mut src = Cursor::new(outer_archive(&inner));
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");

    let edits = BTreeMap::from([
        ("sub/inner.rpf".to_owned(), replacement),
        ("sub/inner.rpf/f.txt".to_owned(), b"DEEP-EDIT".to_vec()),
    ]);
    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::rewrite(
        &mut src,
        &archive,
        &rpf_core::Changes::writing(edits),
        &mut out,
        &mut rpf_core::InMemory,
        &mut Unwatched,
    );
    match refused {
        Err(Error::Overlapping { path, other }) => {
            assert_eq!(path, "sub/inner.rpf/f.txt");
            assert_eq!(other, "sub/inner.rpf");
        }
        other => panic!("expected the pair to be refused, got {other:?}"),
    }
}

/// A reader folds case and ignores empty components, so all three spellings
/// resolve to one entry.
#[test]
fn several_spellings_of_one_edit_are_refused() {
    let inner = inner_archive(b"original");
    let mut src = Cursor::new(outer_archive(&inner));
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");

    let edits = BTreeMap::from([
        ("sub/inner.rpf/f.txt".to_owned(), b"first".to_vec()),
        ("sub//inner.rpf//f.txt".to_owned(), b"second".to_vec()),
        ("SUB/INNER.RPF/F.TXT".to_owned(), b"third".to_vec()),
    ]);
    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::rewrite(
        &mut src,
        &archive,
        &rpf_core::Changes::writing(edits),
        &mut out,
        &mut rpf_core::InMemory,
        &mut Unwatched,
    );
    // The edits are visited in sorted order, so the third spelling is named
    // against the second.
    match refused {
        Err(Error::Overlapping { path, other }) => {
            assert_eq!(path, "sub/inner.rpf/f.txt");
            assert_eq!(other, "sub//inner.rpf//f.txt");
        }
        other => panic!("expected the pair to be refused, got {other:?}"),
    }
}

#[test]
fn two_spellings_of_one_entry_are_refused_at_the_top_level() {
    let mut src = Cursor::new(built(&[stored("f.txt")], b"original"));
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");

    let edits = BTreeMap::from([
        ("f.txt".to_owned(), b"first".to_vec()),
        ("F.TXT".to_owned(), b"second".to_vec()),
    ]);
    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::rewrite(
        &mut src,
        &archive,
        &rpf_core::Changes::writing(edits),
        &mut out,
        &mut rpf_core::InMemory,
        &mut Unwatched,
    );
    match refused {
        Err(Error::Overlapping { path, other }) => {
            assert_eq!(path, "f.txt");
            assert_eq!(other, "F.TXT");
        }
        other => panic!("expected the pair to be refused, got {other:?}"),
    }
}

#[test]
fn edits_in_one_nested_archive_still_rebuild_it_once() {
    let inner = built(&[stored("f.txt"), stored("g.txt")], b"original");
    let mut src = Cursor::new(outer_archive(&inner));
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");

    let edits = BTreeMap::from([
        ("sub//inner.rpf/f.txt".to_owned(), b"one".to_vec()),
        ("SUB/inner.rpf/g.txt".to_owned(), b"two".to_vec()),
    ]);
    let mut out = Cursor::new(Vec::new());
    rpf_core::rewrite(
        &mut src,
        &archive,
        &rpf_core::Changes::writing(edits),
        &mut out,
        &mut rpf_core::InMemory,
        &mut Unwatched,
    )
    .expect("rebuilds");

    let mut file = Cursor::new(out.into_inner());
    let round = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");
    for (path, expected) in [
        ("sub/inner.rpf/f.txt", b"one".to_vec()),
        ("sub/inner.rpf/g.txt", b"two".to_vec()),
    ] {
        let (holder, index) = round.locate(&mut file, path).expect("resolves");
        assert_eq!(
            holder.read(&mut file, index).expect("reads"),
            expected,
            "{path} did not take"
        );
    }
}

/// `Archive::child_named` resolves with `eq_ignore_ascii_case`, so the two are
/// one directory to every reader.
#[test]
fn two_directories_differing_only_in_case_are_refused() {
    let files = [stored("X64/alpha.txt"), stored("x64/beta.txt")];
    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(b"contents".to_vec())),
        &mut Unwatched,
    );
    // The names that collided are the directories, not the files under them.
    collision(refused, "x64", "X64");
}

#[test]
fn two_files_in_one_directory_differing_only_in_case_are_refused() {
    let files = [stored("data/notes.txt"), stored("data/NOTES.TXT")];
    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(b"contents".to_vec())),
        &mut Unwatched,
    );
    collision(refused, "data/NOTES.TXT", "data/notes.txt");
}

#[test]
fn a_named_directory_colliding_with_a_path_is_refused() {
    let files = [stored("X64/alpha.txt")];
    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &["x64".to_owned()],
        |_: &str| Ok(Cursor::new(b"contents".to_vec())),
        &mut Unwatched,
    );
    // The named directories are claimed first, so `x64` is the spelling that
    // took the name and `X64` is the one that could not have it.
    collision(refused, "X64", "x64");
}

/// One path listed twice is not a case collision, and gets its own reason.
#[test]
fn one_path_listed_twice_is_refused_as_a_duplicate() {
    let files = [stored("data/notes.txt"), stored("data/notes.txt")];
    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(b"contents".to_vec())),
        &mut Unwatched,
    );
    refusal(refused, "data/notes.txt", "is named twice in one directory");
}

#[test]
fn a_file_and_a_directory_sharing_one_name_are_refused() {
    let files = [stored("x64"), stored("x64/alpha.txt")];
    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(b"contents".to_vec())),
        &mut Unwatched,
    );
    refusal(
        refused,
        "x64/alpha.txt",
        "a file and a directory share one name",
    );
}

/// `build` derives parents from file paths only, so a `..` in a directory list
/// would otherwise reach the entry table unexamined.
#[test]
fn a_named_directory_that_climbs_out_of_the_tree_is_refused() {
    for directory in ["..", "../escaped", "a/../..", "/etc", "a\\b"] {
        let mut out = Cursor::new(Vec::new());
        let refused = rpf_core::build(
            &mut out,
            rpf_core::Version::Rpf7,
            &[],
            &[directory.to_owned()],
            |_: &str| Ok(Cursor::new(b"contents".to_vec())),
            &mut Unwatched,
        );
        assert!(
            matches!(refused, Err(Error::BadPath { ref path, .. }) if path == directory),
            "expected {directory:?} to be refused as itself, got {refused:?}",
        );
        assert!(
            out.into_inner().is_empty(),
            "{directory:?}: nothing may be written for a refused tree",
        );
    }
}

#[test]
fn one_directory_is_reachable_under_any_case() {
    let mut file = Cursor::new(built(
        &[stored("X64/alpha.txt"), stored("X64/beta.txt")],
        b"contents",
    ));
    let archive = Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("parses");
    for path in ["X64/alpha.txt", "x64/ALPHA.TXT", "x64/beta.txt"] {
        assert!(archive.find(path).is_ok(), "{path} does not resolve");
    }
}
