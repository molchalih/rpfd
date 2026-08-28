//! R2.6: every unencrypted path works with no key material present at all.
//!
//! This is the item that keeps continuous integration possible, and the primary
//! workflow — a third-party server asset, unencrypted, edited in a loop — never
//! needs a key either. So it is not enough for the unencrypted paths to happen
//! to work on a machine that has a game installed. They have to work on one
//! that does not, and something has to fail when that stops being true.
//!
//! What is asserted, in order:
//!
//! - the whole cycle runs — build, open, resolve, read, verify, patch in place,
//!   rebuild, describe as a manifest, and read the result back — with no
//!   executable anywhere and no cache to read;
//! - the key cache that would have been consulted is still **not there**
//!   afterwards, so no unencrypted path quietly created or populated one;
//! - and an archive that *is* encrypted still answers [`Error::NeedsKey`],
//!   which is the seam. A reader that tried to find a key would fail here
//!   rather than silently working on the machine that happens to have one.
//!
//! `clippy.toml`'s `allow-*-in-tests` settings reach `#[cfg(test)]` modules and
//! not this directory: an integration test is its own crate with no
//! `cfg(test)`. `docs/conventions.md` §15's exception is spelled out here.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; a panic is the reporting mechanism. See the note above"
)]

use std::{
    collections::BTreeMap,
    fs,
    io::{Cursor, Seek, Write},
};

use rpf_core::{
    Archive, Category, Error, FileKind, FileSpec, Manifest, Plan, Storage, Summary, Unwatched,
    Verified,
    format::Version,
    keys::{Cache, SourceDigest},
};

/// One stored file.
fn stored(path: &str) -> FileSpec {
    FileSpec {
        path: path.to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Stored,
            encryption: 0,
        },
    }
}

/// One deflated file.
fn deflated(path: &str) -> FileSpec {
    FileSpec {
        path: path.to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Deflate,
            encryption: 0,
        },
    }
}

/// Builds an archive into a real file and hands back its bytes.
fn built(files: &[FileSpec], contents: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut sink = tempfile::NamedTempFile::new().expect("temp file");
    rpf_core::build(
        sink.as_file_mut(),
        rpf_core::Version::Rpf7,
        files,
        &[],
        |path| {
            Ok(Cursor::new(
                contents
                    .get(path)
                    .cloned()
                    .unwrap_or_else(|| path.as_bytes().to_vec()),
            ))
        },
        &mut Unwatched,
    )
    .expect("builds with no key material");
    sink.as_file_mut().flush().expect("flushed");
    fs::read(sink.path()).expect("readable")
}

/// A header whose encryption tag is not `OPEN`, and nothing else.
///
/// Nothing past the tag is read: the refusal happens before any layout is
/// believed, which is the whole point of it being a refusal.
fn encrypted_header(tag: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(b"7FPR");
    out.extend_from_slice(&1_u32.to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes());
    out.extend_from_slice(&tag.to_le_bytes());
    out
}

#[test]
fn the_whole_unencrypted_cycle_runs_and_leaves_no_key_cache_behind() {
    let scratch = tempfile::tempdir().expect("a temporary directory");
    let cache_directory = scratch.path().join("config").join("rpf");
    let cache = Cache::at(&cache_directory);
    let nothing = SourceDigest::of(&mut Cursor::new(Vec::new())).expect("digests");

    assert!(
        cache
            .load(&nothing)
            .expect("a cache miss is not a failure")
            .is_none(),
        "there is no key material here, and the cache said there was"
    );

    // Build.
    let mut contents = BTreeMap::new();
    contents.insert("data/notes.meta".to_owned(), b"<notes/>".repeat(4));
    contents.insert("x64/raw.bin".to_owned(), vec![0xAB; 600]);
    let files = [deflated("data/notes.meta"), stored("x64/raw.bin")];
    let bytes = built(&files, &contents);

    // Open, resolve, read.
    let mut source = Cursor::new(bytes.clone());
    let archive = Archive::open(&mut source).expect("opens with no key material");
    assert!(archive.version().is_open(archive.encryption()));
    for (path, expected) in &contents {
        let index = archive.find(path).expect("resolves");
        let read = archive.read(&mut source, index).expect("reads");
        assert_eq!(&read, expected, "{path} did not read back");
    }

    // Summarise and verify.
    let summary = Summary::of(&mut source, &archive, "").expect("summarises");
    assert!(summary.entries > 0);
    Verified::of(&mut source, &archive, &mut Unwatched)
        .expect("verifies")
        .outcome()
        .expect("every entry reads back");

    // Patch in place.
    let mut edits = BTreeMap::new();
    edits.insert("x64/raw.bin".to_owned(), vec![0xCD; 600]);
    let mut in_place = tempfile::NamedTempFile::new().expect("temp file");
    in_place.write_all(&bytes).expect("written");
    in_place.as_file_mut().rewind().expect("rewound");
    let plan = rpf_core::plan(
        in_place.as_file_mut(),
        &archive,
        &rpf_core::Changes::writing(edits),
    )
    .expect("plans");
    match plan {
        Plan::Fits(ready) => ready
            .apply(in_place.as_file_mut())
            .expect("patches with no key material"),
        other => panic!("expected a patch, got {other:?}"),
    }
    in_place.as_file_mut().flush().expect("flushed");
    let after = fs::read(in_place.path()).expect("readable");
    let mut after_source = Cursor::new(after);
    let after_archive = Archive::open(&mut after_source).expect("the patched archive opens");
    let patched_index = after_archive.find("x64/raw.bin").expect("resolves");
    assert_eq!(
        after_archive
            .read(&mut after_source, patched_index)
            .expect("reads"),
        vec![0xCD; 600],
        "the patch did not land"
    );

    // Rebuild.
    let mut grew = BTreeMap::new();
    grew.insert("data/notes.meta".to_owned(), vec![0x5A; 40_000]);
    let mut sink = tempfile::NamedTempFile::new().expect("temp file");
    let mut again = Cursor::new(bytes.clone());
    let reopened = Archive::open(&mut again).expect("opens");
    rpf_core::rewrite(
        &mut again,
        &reopened,
        &rpf_core::Changes::writing(grew),
        sink.as_file_mut(),
        &mut rpf_core::InMemory,
        &mut Unwatched,
    )
    .expect("rebuilds with no key material");
    sink.as_file_mut().flush().expect("flushed");

    // Describe, and read the rebuild back.
    let rebuilt = fs::read(sink.path()).expect("readable");
    let mut rebuilt_source = Cursor::new(rebuilt);
    let rebuilt_archive = Archive::open(&mut rebuilt_source).expect("the rebuild opens");
    let manifest = Manifest::of(&rebuilt_archive).expect("describes");
    assert_eq!(manifest.specs().len(), files.len());
    // R11.3: the tree records what it came out of, so it cannot be packed as
    // another container without saying so. The manifest round-trips through
    // its own JSON with both fields intact.
    assert_eq!(manifest.version, rebuilt_archive.version());
    assert_eq!(manifest.codec, rebuilt_archive.version().codec());
    assert_eq!(manifest.schema, rpf_core::manifest::SCHEMA_VERSION);
    let text = manifest.to_json().expect("renders");
    assert_eq!(
        rpf_core::Manifest::from_json(&text).expect("reads back"),
        manifest
    );
    let index = rebuilt_archive.find("data/notes.meta").expect("resolves");
    assert_eq!(
        rebuilt_archive
            .read(&mut rebuilt_source, index)
            .expect("reads"),
        vec![0x5A; 40_000]
    );

    assert!(
        !cache_directory.exists(),
        "an unencrypted cycle created the key cache at {}",
        cache_directory.display()
    );
}

#[test]
fn an_encrypted_archive_asks_for_a_key_rather_than_being_opened_or_refused() {
    // The seam R2.6 protects, from the other side. `0x0FFFFFF9` is the AES tag
    // and `0x0FEFFFFF` the NG one — both `secondary`, `docs/rpf-format.md` —
    // and what is asserted is not which tag means what, but that a tag naming
    // encryption produces a demand for key material rather than a parse.
    //
    // Only those two. The same row claims at `secondary` that `0` and `CFXP`
    // also mean unencrypted, which this build does not implement; pinning what
    // it currently answers for them would turn implementing it into a failing
    // test. R1.5 owns that question.
    for tag in [0x0FFF_FFF9_u32, 0x0FEF_FFFF] {
        assert!(!Version::Rpf7.is_open(tag));
        let error = Archive::open(&mut Cursor::new(encrypted_header(tag)))
            .expect_err("an archive that is not OPEN cannot be opened here");
        assert!(
            matches!(error, Error::NeedsKey { tag: found } if found == tag),
            "tag {tag:#010x} gave {error:?}"
        );
        assert_eq!(error.category(), Category::NeedsKey);
    }
}

#[test]
fn the_key_cache_is_never_consulted_by_opening_an_archive() {
    // `Archive::open` takes a source and nothing else — no cache, no path, no
    // key. That is the structural half of R2.6: there is no argument through
    // which key material could reach the reader, so an unencrypted archive
    // cannot come to depend on one by accident.
    //
    // Asserted the only way a test can assert a negative here: a cache in a
    // directory that does not exist, untouched by a full open-and-read.
    let scratch = tempfile::tempdir().expect("a temporary directory");
    let absent = scratch.path().join("no-such-cache");
    let cache = Cache::at(&absent);

    let bytes = built(&[stored("a.txt")], &BTreeMap::new());
    let mut source = Cursor::new(bytes);
    let archive = Archive::open(&mut source).expect("opens");
    let index = archive.find("a.txt").expect("resolves");
    archive.read(&mut source, index).expect("reads");

    assert!(
        !cache.directory().exists(),
        "{} was created by a read that needed no key",
        cache.directory().display()
    );
}
