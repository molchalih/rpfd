//! Every unencrypted path with no key material present: the cycle runs, no key
//! cache is created, and an encrypted archive answers [`Error::NeedsKey`].
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
    Archive, Category, Error, FileKind, FileSpec, Manifest, Plan, Storage, Summary, Unlock,
    Unwatched, Verified,
    format::Version,
    keys::{Cache, SourceDigest},
};

/// No key material, and no cache named to look for any in.
fn unkeyed() -> Unlock {
    Unlock::unkeyed()
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

fn deflated(path: &str) -> FileSpec {
    FileSpec {
        path: path.to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Deflate,
            encryption: 0,
        },
    }
}

fn built(files: &[FileSpec], contents: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut sink = tempfile::NamedTempFile::new().expect("temp file");
    rpf_core::build(
        sink.as_file_mut(),
        rpf_core::Version::Rpf7,
        files,
        &[],
        |path: &str| {
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

/// Magic, version, entry count, encryption tag: nothing past the tag is read
/// before the refusal.
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

    let mut contents = BTreeMap::new();
    contents.insert("data/notes.meta".to_owned(), b"<notes/>".repeat(4));
    contents.insert("x64/raw.bin".to_owned(), vec![0xAB; 600]);
    let files = [deflated("data/notes.meta"), stored("x64/raw.bin")];
    let bytes = built(&files, &contents);

    let mut source = Cursor::new(bytes.clone());
    let archive = Archive::open(&mut source, &unkeyed()).expect("opens with no key material");
    assert!(archive.version().is_open(archive.encryption()));
    for (path, expected) in &contents {
        let index = archive.find(path).expect("resolves");
        let read = archive.read(&mut source, index).expect("reads");
        assert_eq!(&read, expected, "{path} did not read back");
    }

    let summary = Summary::of(&mut source, &archive, "").expect("summarises");
    assert!(summary.entries > 0);
    Verified::of(&mut source, &archive, &mut Unwatched)
        .expect("verifies")
        .outcome()
        .expect("every entry reads back");

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
    let after_archive = Archive::open(&mut after_source, &unkeyed()).expect("the patch opens");
    let patched_index = after_archive.find("x64/raw.bin").expect("resolves");
    assert_eq!(
        after_archive
            .read(&mut after_source, patched_index)
            .expect("reads"),
        vec![0xCD; 600],
        "the patch did not land"
    );

    let mut grew = BTreeMap::new();
    grew.insert("data/notes.meta".to_owned(), vec![0x5A; 40_000]);
    let mut sink = tempfile::NamedTempFile::new().expect("temp file");
    let mut again = Cursor::new(bytes.clone());
    let reopened = Archive::open(&mut again, &unkeyed()).expect("opens");
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

    let rebuilt = fs::read(sink.path()).expect("readable");
    let mut rebuilt_source = Cursor::new(rebuilt);
    let rebuilt_archive =
        Archive::open(&mut rebuilt_source, &unkeyed()).expect("the rebuild opens");
    let manifest = Manifest::of(&rebuilt_archive).expect("describes");
    assert_eq!(manifest.specs().len(), files.len());
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
    // `0x0FFFFFF9` is the AES tag, `0x0FEFFFFF` the NG one. `0` and `CFXP` are
    // left out: pinning them would turn implementing them into a failure.
    for tag in [0x0FFF_FFF9_u32, 0x0FEF_FFFF] {
        assert!(!Version::Rpf7.is_open(tag));
        let error = Archive::open(&mut Cursor::new(encrypted_header(tag)), &unkeyed())
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
    let scratch = tempfile::tempdir().expect("a temporary directory");
    let absent = scratch.path().join("no-such-cache");
    let cache = Cache::at(&absent);

    let bytes = built(&[stored("a.txt")], &BTreeMap::new());
    let mut source = Cursor::new(bytes);
    let archive = Archive::open(&mut source, &unkeyed()).expect("opens");
    let index = archive.find("a.txt").expect("resolves");
    archive.read(&mut source, index).expect("reads");

    assert!(
        !cache.directory().exists(),
        "{} was created by a read that needed no key",
        cache.directory().display()
    );
}

#[test]
fn an_encrypted_archive_nested_in_a_plain_one_is_counted_locked_and_says_why() {
    // Sixteen bytes of header suffice: nothing past the encryption tag is read.
    const TAG: u32 = 0x0FEF_FFFF;

    let mut contents = BTreeMap::new();
    contents.insert("inner.rpf".to_owned(), encrypted_header(TAG));
    let bytes = built(&[stored("inner.rpf"), stored("a.txt")], &contents);

    let mut source = Cursor::new(bytes);
    let archive = Archive::open(&mut source, &unkeyed()).expect("the outer archive is plain");

    let summary = Summary::of(&mut source, &archive, "").expect("summarises");
    assert_eq!(
        summary.locked_archives, 1,
        "the nested encrypted archive was not counted as locked"
    );
    // `nested_archives` counts what the sniff found; `locked_archives` those of
    // them that did not open.
    assert_eq!(summary.nested_archives, 1);

    let verified = Verified::of(&mut source, &archive, &mut Unwatched).expect("walks");
    let locked: Vec<_> = verified
        .problems
        .iter()
        .filter(|problem| matches!(problem.error, Error::NeedsKey { .. }))
        .collect();
    assert_eq!(locked.len(), 1, "{:?}", verified.problems);
    assert_eq!(locked[0].path, "inner.rpf");
    assert!(
        matches!(locked[0].error, Error::NeedsKey { tag } if tag == TAG),
        "{:?}",
        locked[0].error
    );
    assert_eq!(locked[0].error.category(), Category::NeedsKey);

    // The verdict is the key failure, not `VerifyFailed`: the bytes are not
    // wrong, this machine has no key for part of them.
    let refused = verified
        .outcome()
        .expect_err("an archive this build cannot open did not read back whole");
    assert!(
        matches!(refused, Error::NeedsKey { tag } if tag == TAG),
        "expected the key failure itself, got {refused:?}"
    );
    assert_eq!(refused.category(), Category::NeedsKey);
}
