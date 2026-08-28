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
//!
//! The tests at the end are corpus-free and build the archive they need. They
//! are here rather than beside the corpus ones because they check the same
//! thing from the other side: what a build writes, and what it refuses to write
//! at all.
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

/// Asserts that a build was refused because two names in one directory are one
/// name, naming both of them by path.
///
/// Names both, because which two collided is the whole of what a caller acts
/// on: matching the variant alone accepts any pair against any archive.
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
///
/// [`Error::BadPath`] carries several distinct reasons and the path each is
/// about, and both are what a caller acts on: matching the variant alone
/// accepts any reason against any path, which is every one of these tests
/// passing for the wrong archive.
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

/// The archive this fixture describes, or `None` with `test` and a reason on
/// stderr.
///
/// The ordinary case — no `RPF_CORPUS` at all — never reaches here: `build.rs`
/// turns that into `#[ignore]`, which the harness reports by name whether or
/// not output is captured. What is left is a corpus that was pointed at and
/// does not hold this archive, and the one thing a reader needs then is which
/// test went unrun.
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
#[cfg_attr(no_corpus, ignore = "no RPF_CORPUS: the sample archive is not tracked")]
fn a_rebuilt_archive_holds_the_same_contents() {
    let Some((path, fixture)) = corpus_archive("a_rebuilt_archive_holds_the_same_contents") else {
        return;
    };

    let mut source = fs::File::open(&path).expect("archive opens");
    let original = Archive::open(&mut source).expect("archive parses");
    let specs = specs_for(&original);
    let by_path: BTreeMap<String, u32> = specs.iter().map(|(s, i)| (s.path.clone(), *i)).collect();
    let files: Vec<FileSpec> = specs.into_iter().map(|(s, _)| s).collect();
    let directories = rpf_core::directories_of(&original).expect("directories");

    let mut rebuilt = tempfile::NamedTempFile::new().expect("temp file");
    let report = rpf_core::build(
        rebuilt.as_file_mut(),
        &files,
        &directories,
        |wanted| {
            let index = *by_path.get(wanted).expect("path came from this archive");
            original.extract(&mut source, index)
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
#[cfg_attr(no_corpus, ignore = "no RPF_CORPUS: the sample archive is not tracked")]
fn an_injected_corruption_is_caught() {
    let Some((path, _)) = corpus_archive("an_injected_corruption_is_caught") else {
        return;
    };

    let mut source = fs::File::open(&path).expect("archive opens");
    let original = Archive::open(&mut source).expect("archive parses");
    let specs = specs_for(&original);
    let by_path: BTreeMap<String, u32> = specs.iter().map(|(s, i)| (s.path.clone(), *i)).collect();
    let files: Vec<FileSpec> = specs.into_iter().map(|(s, _)| s).collect();
    let directories = rpf_core::directories_of(&original).expect("directories");

    let mut rebuilt = tempfile::NamedTempFile::new().expect("temp file");
    rpf_core::build(
        rebuilt.as_file_mut(),
        &files,
        &directories,
        |wanted| {
            let index = *by_path.get(wanted).expect("known path");
            original.extract(&mut source, index)
        },
        &mut Unwatched,
    )
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
#[cfg_attr(no_corpus, ignore = "no RPF_CORPUS: the sample archive is not tracked")]
fn replacing_a_nested_entry_cascades() {
    const TARGET: &str = "x64/vehicles.rpf/meringls63amg24.ytd";
    const DONOR: &str = "x64/vehicles.rpf/meringls63amg24.yft";

    let Some((path, fixture)) = corpus_archive("replacing_a_nested_entry_cascades") else {
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
        &mut Unwatched,
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

// --- Corpus-free: what a build writes, and what it refuses ------------------

/// One stored file. Stored, because a stored payload is the case with nothing
/// to check it against — a deflate stream that lost its last byte fails to
/// inflate, and a resource's page flags disagree with what it inflates to, but
/// a stored entry reads back whatever is there and calls it correct.
fn stored(path: &str) -> FileSpec {
    FileSpec {
        path: path.to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Stored,
            encryption: 0,
        },
    }
}

/// Builds an archive into a **real file**, and hands back the report with the
/// bytes that ended up on disk.
///
/// Deliberately not a `Cursor<Vec<u8>>`, and the difference is not a detail.
/// `Cursor::write_all(&[])` at a seek position past the end of the vector
/// **resizes the vector to that position**; `std::fs::File` writing nothing
/// past the end of a file leaves the file exactly as long as it was. Every
/// build test in this suite used a cursor, which made the suite structurally
/// unable to see a build that wrote fewer bytes than it reported — the vector
/// came back the right length because the cursor had grown it for free. It cost
/// us a zero-length last payload truncating the archive, reachable from `pack`,
/// from `put --rebuild` and from the daemon's commit, with `Report::len`
/// claiming 1024 for a file of 516 bytes.
///
/// The length assertion lives here rather than in each caller so that every
/// build that goes through it is checked against the file it wrote.
fn build_on_disk<F>(
    files: &[FileSpec],
    directories: &[String],
    fetch: F,
) -> (rpf_core::Report, Vec<u8>)
where
    F: FnMut(&str) -> Result<Vec<u8>, Error>,
{
    let mut sink = tempfile::NamedTempFile::new().expect("temp file");
    let report = rpf_core::build(
        sink.as_file_mut(),
        files,
        directories,
        fetch,
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

/// Rebuilds an archive into a real file, for the reason [`build_on_disk`]
/// exists, and hands back what landed there.
fn replaced_on_disk(source: &[u8], edits: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut src = Cursor::new(source.to_vec());
    let archive = Archive::open(&mut src).expect("parses");

    let mut sink = tempfile::NamedTempFile::new().expect("temp file");
    let report = rpf_core::replace_many(
        &mut src,
        &archive,
        edits,
        sink.as_file_mut(),
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

/// Builds an archive from `files`, serving `contents` for each.
fn built(files: &[FileSpec], contents: &[u8]) -> Vec<u8> {
    build_on_disk(files, &[], |_| Ok(contents.to_vec())).1
}

/// An archive holding one file, `f.txt`, with the given contents.
fn inner_archive(contents: &[u8]) -> Vec<u8> {
    built(&[stored("f.txt")], contents)
}

/// An archive holding `sub/inner.rpf`, which is `inner`.
fn outer_archive(inner: &[u8]) -> Vec<u8> {
    built(&[stored("sub/inner.rpf")], inner)
}

/// The last payload of an archive keeps its last byte.
///
/// `build` used to extend the file to the block boundary by writing a zero at
/// `length - 1`. Whenever the last payload ended exactly on a boundary that
/// byte **was** the payload's last one, so the archive still parsed, the entry
/// row still read right, and one byte of the file was quietly zero. The sweep
/// is the point: the suite had no stored file of exactly 512 bytes, which is
/// why this shipped.
#[test]
fn a_payload_ending_on_a_block_boundary_keeps_its_last_byte() {
    let files = [stored("raw.bin")];
    let mut corrupted = Vec::new();

    for len in 1..=4096_usize {
        let contents = vec![0xAA_u8; len];
        // On disk: `build_on_disk` also checks the file against the report, so
        // the sweep covers both halves of the padding arithmetic at once.
        let (_, bytes) = build_on_disk(&files, &[], |_| Ok(contents.clone()));

        let mut file = Cursor::new(bytes);
        let archive = Archive::open(&mut file).expect("parses");
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

/// An archive with no payloads at all is still padded to a block, from the end
/// of its names blob. The other side of the same arithmetic.
#[test]
fn an_archive_with_no_files_is_still_a_whole_number_of_blocks() {
    let (report, bytes) = build_on_disk(&[], &[], |_| Ok(Vec::new()));
    assert_eq!(report.len % 512, 0, "not a whole number of blocks");

    let mut file = Cursor::new(bytes);
    let archive = Archive::open(&mut file).expect("parses");
    assert_eq!(archive.entries().len(), 1, "the root, and nothing else");
}

/// A last payload of zero bytes must not shorten the archive.
///
/// `build` padded forward from where the last payload ended, and a zero-length
/// payload moved that anchor to its own start while writing nothing at all. So
/// nothing ever extended the file past the *previous* payload's last byte: the
/// archive was truncated and its last entry addressed past the end of it.
/// Reproduced here — `a.txt` of 4 bytes and `z-empty.txt` of none reported a
/// length of 1024 for a file of 516 bytes — and reachable from `rpf pack`, from
/// `put --rebuild`, which then persists the truncated file over a good archive,
/// and from the daemon's commit.
#[test]
fn a_zero_length_last_payload_does_not_truncate_the_archive() {
    let files = [stored("a.txt"), stored("z-empty.txt")];
    let (report, bytes) = build_on_disk(&files, &[], |wanted| {
        Ok(if wanted == "a.txt" {
            b"abcd".to_vec()
        } else {
            Vec::new()
        })
    });
    assert_eq!(report.len % 512, 0, "not a whole number of blocks");

    let mut file = Cursor::new(bytes);
    let archive = Archive::open(&mut file).expect("parses");
    for (path, expected) in [("a.txt", b"abcd".to_vec()), ("z-empty.txt", Vec::new())] {
        let index = archive.find(path).expect("resolves");
        assert_eq!(
            archive.read(&mut file, index).expect("reads"),
            expected,
            "{path} did not read back"
        );
    }
}

/// The same, reached without asking for it. `Storage::Deflate` on empty
/// contents deflates to two bytes, which is not smaller than nothing, so the
/// stored branch wins and zero bytes go out — a zero-length last payload from a
/// caller who never wrote one.
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
    let (report, bytes) = build_on_disk(&files, &[], |wanted| {
        Ok(if wanted == "a.txt" {
            vec![b'x'; 4096]
        } else {
            Vec::new()
        })
    });
    assert_eq!(report.len % 512, 0, "not a whole number of blocks");

    let mut file = Cursor::new(bytes);
    let archive = Archive::open(&mut file).expect("parses");
    let index = archive.find("z-empty.txt").expect("resolves");
    assert!(
        archive.read(&mut file, index).expect("reads").is_empty(),
        "the empty entry did not read back"
    );
}

/// And through the write path an editor actually uses: emptying the entry that
/// happens to be written last.
#[test]
fn emptying_the_last_payload_of_a_rebuild_does_not_truncate_it() {
    let source = built(&[stored("a.txt"), stored("z.txt")], b"contents");
    let edits = BTreeMap::from([("z.txt".to_owned(), Vec::new())]);
    let bytes = replaced_on_disk(&source, &edits);

    let mut file = Cursor::new(bytes);
    let archive = Archive::open(&mut file).expect("rebuild parses");
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

/// R4's stated top risk, on the one narrow field of [`file_row`] that had no
/// test at all: a file entry's name offset is sixteen bits.
///
/// Deleting that check leaves the whole suite green. The archive it then builds
/// parses, `Archive::open` succeeds and `verify` passes — and every entry whose
/// name sits past 65,535 bytes into the names blob carries somebody else's
/// name. Measured with the check removed: 4,000 files of 18-byte names, a
/// `names_len` of 88,001, and 1,021 of the 4,000 names wrong. An archive that
/// parses, packs, and fails to load, with no error anywhere.
#[test]
fn a_file_name_offset_past_sixteen_bits_is_refused() {
    // Each name is 18 bytes and costs 19 in the blob with its terminator; the
    // root's empty name takes the first. So file `k` sits at 1 + 19k, and 3450
    // is the first that will not fit: 1 + 19 × 3450 = 65,551.
    let files: Vec<FileSpec> = (0..=3450).map(|index| stored(&name_of(index))).collect();

    // A cursor is the right sink here precisely because nothing should reach
    // it: this asserts the refusal, not what was written.
    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::build(&mut out, &files, &[], |_| Ok(b"x".to_vec()), &mut Unwatched);

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

/// The other side of the same limit: every name below it comes back exact.
///
/// Without this a limit set one too low would look as green as a correct one,
/// and the last name here lands four bytes inside the field — at 65,532 — which
/// is where an off-by-one would show.
#[test]
fn every_file_name_below_sixteen_bits_reads_back() {
    let files: Vec<FileSpec> = (0..=3449).map(|index| stored(&name_of(index))).collect();
    let (report, bytes) = build_on_disk(&files, &[], |_| Ok(b"x".to_vec()));
    assert_eq!(report.names_len, 65_532 + 19, "the whole blob");

    let mut file = Cursor::new(bytes);
    let archive = Archive::open(&mut file).expect("parses");
    for index in 0..=3449_u32 {
        // Entry 0 is the root; the files follow in ascending name order, which
        // is the order they were generated in.
        assert_eq!(
            archive.name(index + 1).expect("named"),
            name_of(index),
            "entry {index} carries the wrong name"
        );
    }
}

/// The `index`th generated name: four digits and fourteen more bytes, 18 in
/// all, so that byte order and generation order are the same thing.
fn name_of(index: u32) -> String {
    format!("{index:04}-file-name.bin")
}

/// The same, one level down: a rebuild through nesting writes the inner
/// archive as a payload of the outer one, so the outer build's last payload is
/// whatever the inner build produced.
#[test]
fn a_nested_rebuild_keeps_the_last_byte_of_its_last_payload() {
    let contents = vec![0xAA_u8; 512];
    let inner = inner_archive(&contents);
    let source = outer_archive(&inner);
    let edits = BTreeMap::from([("sub/inner.rpf/f.txt".to_owned(), contents.clone())]);

    let mut file = Cursor::new(replaced_on_disk(&source, &edits));
    let round = Archive::open(&mut file).expect("rebuild parses");
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
/// same bytes twice. `plan` refuses the pair with `Overlapping`; the rebuild
/// path used to accept it, drop the whole-archive edit on the floor and return
/// `Ok`, so a caller falling back from one write path to the other got a
/// different archive with no error anywhere.
#[test]
fn replacing_an_archive_and_a_file_inside_it_is_refused() {
    let inner = inner_archive(b"original");
    let replacement = inner_archive(b"a different archive entirely");
    let mut src = Cursor::new(outer_archive(&inner));
    let archive = Archive::open(&mut src).expect("parses");

    let edits = BTreeMap::from([
        ("sub/inner.rpf".to_owned(), replacement),
        ("sub/inner.rpf/f.txt".to_owned(), b"DEEP-EDIT".to_vec()),
    ]);
    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::replace_many(&mut src, &archive, &edits, &mut out, &mut Unwatched);
    // Which two collided, not merely that two did: the caller has to drop one
    // of them or rebuild, and it can do neither without being told which.
    match refused {
        Err(Error::Overlapping { path, other }) => {
            assert_eq!(path, "sub/inner.rpf/f.txt");
            assert_eq!(other, "sub/inner.rpf");
        }
        other => panic!("expected the pair to be refused, got {other:?}"),
    }
}

/// Three spellings of one path resolve to one entry, because a reader folds
/// case and ignores empty components. Keyed by the string they were written
/// as, they used to collapse to whichever came last, silently.
#[test]
fn several_spellings_of_one_edit_are_refused() {
    let inner = inner_archive(b"original");
    let mut src = Cursor::new(outer_archive(&inner));
    let archive = Archive::open(&mut src).expect("parses");

    let edits = BTreeMap::from([
        ("sub/inner.rpf/f.txt".to_owned(), b"first".to_vec()),
        ("sub//inner.rpf//f.txt".to_owned(), b"second".to_vec()),
        ("SUB/INNER.RPF/F.TXT".to_owned(), b"third".to_vec()),
    ]);
    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::replace_many(&mut src, &archive, &edits, &mut out, &mut Unwatched);
    // The edits are visited in sorted order, so the pair named is the third
    // spelling against the second — the two that reached one path within the
    // nested archive.
    match refused {
        Err(Error::Overlapping { path, other }) => {
            assert_eq!(path, "sub/inner.rpf/f.txt");
            assert_eq!(other, "sub//inner.rpf//f.txt");
        }
        other => panic!("expected the pair to be refused, got {other:?}"),
    }
}

/// The same collision without any nesting, so the refusal is not an artefact
/// of how the descent groups edits.
#[test]
fn two_spellings_of_one_entry_are_refused_at_the_top_level() {
    let mut src = Cursor::new(built(&[stored("f.txt")], b"original"));
    let archive = Archive::open(&mut src).expect("parses");

    let edits = BTreeMap::from([
        ("f.txt".to_owned(), b"first".to_vec()),
        ("F.TXT".to_owned(), b"second".to_vec()),
    ]);
    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::replace_many(&mut src, &archive, &edits, &mut out, &mut Unwatched);
    match refused {
        Err(Error::Overlapping { path, other }) => {
            assert_eq!(path, "f.txt");
            assert_eq!(other, "F.TXT");
        }
        other => panic!("expected the pair to be refused, got {other:?}"),
    }
}

/// One edit per entry still rebuilds, spelled loosely. The refusals above must
/// not have cost the ordinary case.
#[test]
fn edits_in_one_nested_archive_still_rebuild_it_once() {
    let inner = built(&[stored("f.txt"), stored("g.txt")], b"original");
    let mut src = Cursor::new(outer_archive(&inner));
    let archive = Archive::open(&mut src).expect("parses");

    let edits = BTreeMap::from([
        ("sub//inner.rpf/f.txt".to_owned(), b"one".to_vec()),
        ("SUB/inner.rpf/g.txt".to_owned(), b"two".to_vec()),
    ]);
    let mut out = Cursor::new(Vec::new());
    rpf_core::replace_many(&mut src, &archive, &edits, &mut out, &mut Unwatched).expect("rebuilds");

    let mut file = Cursor::new(out.into_inner());
    let round = Archive::open(&mut file).expect("parses");
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

/// Two directories differing only in case are one directory to every reader:
/// `Archive::child_named` resolves with `eq_ignore_ascii_case`. Build used to
/// write both, and everything under the second was then unreachable by any
/// spelling of its own path.
#[test]
fn two_directories_differing_only_in_case_are_refused() {
    let files = [stored("X64/alpha.txt"), stored("x64/beta.txt")];
    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::build(
        &mut out,
        &files,
        &[],
        |_| Ok(b"contents".to_vec()),
        &mut Unwatched,
    );
    // Matching only the variant would accept any pair against any archive, and
    // the whole value of this refusal to a caller is which two names collided.
    // Those are the two directories, not the file whose path ran into them.
    collision(refused, "x64", "X64");
}

/// The same for two files in one directory.
#[test]
fn two_files_in_one_directory_differing_only_in_case_are_refused() {
    let files = [stored("data/notes.txt"), stored("data/NOTES.TXT")];
    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::build(
        &mut out,
        &files,
        &[],
        |_| Ok(b"contents".to_vec()),
        &mut Unwatched,
    );
    collision(refused, "data/NOTES.TXT", "data/notes.txt");
}

/// And an explicit directory list collides with a directory a path created.
#[test]
fn a_named_directory_colliding_with_a_path_is_refused() {
    let files = [stored("X64/alpha.txt")];
    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::build(
        &mut out,
        &files,
        &["x64".to_owned()],
        |_| Ok(b"contents".to_vec()),
        &mut Unwatched,
    );
    // The named directories are claimed first, so `x64` is the spelling that
    // took the name and `X64` is the one that could not have it. What used to
    // be reported here was `"X64/alpha.txt" and its sibling "x64"`, which named
    // two things that are neither siblings nor one name.
    collision(refused, "X64", "x64");
}

/// One path listed twice is not a case collision, and `build` has always said
/// so with its own reason. Nothing pinned the sentence, and the reader now
/// gives the same one — `crates/rpf-core/tests/malformed.rs`.
#[test]
fn one_path_listed_twice_is_refused_as_a_duplicate() {
    let files = [stored("data/notes.txt"), stored("data/notes.txt")];
    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::build(
        &mut out,
        &files,
        &[],
        |_| Ok(b"contents".to_vec()),
        &mut Unwatched,
    );
    refusal(refused, "data/notes.txt", "is named twice in one directory");
}

/// A file and a directory of one name are not two things a reader can tell
/// apart, and the file used to lose: `descend` replaced its tree entry, so its
/// contents were never fetched and never written, and `build` returned `Ok`.
#[test]
fn a_file_and_a_directory_sharing_one_name_are_refused() {
    let files = [stored("x64"), stored("x64/alpha.txt")];
    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::build(
        &mut out,
        &files,
        &[],
        |_| Ok(b"contents".to_vec()),
        &mut Unwatched,
    );
    refusal(
        refused,
        "x64/alpha.txt",
        "a file and a directory share one name",
    );
}

/// A directory named outright is checked as a path in its own right, and
/// nothing else checks it: `build` derives parents from file paths, so a
/// directory list holding `..` reaches `descend` with nothing between it and
/// the entry table. Deleting the check left the whole suite green while a
/// hostile manifest produced an archive with a `..` directory entry — which
/// `extract` then creates above the target on the way to writing into it.
#[test]
fn a_named_directory_that_climbs_out_of_the_tree_is_refused() {
    for directory in ["..", "../escaped", "a/../..", "/etc", "a\\b"] {
        let mut out = Cursor::new(Vec::new());
        let refused = rpf_core::build(
            &mut out,
            &[],
            &[directory.to_owned()],
            |_| Ok(b"contents".to_vec()),
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

/// One spelling of a directory is not a collision with itself, and the reader
/// finds it under any case. This is what the refusals above must not break.
#[test]
fn one_directory_is_reachable_under_any_case() {
    let mut file = Cursor::new(built(
        &[stored("X64/alpha.txt"), stored("X64/beta.txt")],
        b"contents",
    ));
    let archive = Archive::open(&mut file).expect("parses");
    for path in ["X64/alpha.txt", "x64/ALPHA.TXT", "x64/beta.txt"] {
        assert!(archive.find(path).is_ok(), "{path} does not resolve");
    }
}
