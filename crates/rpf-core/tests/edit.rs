//! Adding, deleting and renaming an entry.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; a panic is the reporting mechanism. clippy.toml's \
              allow-panic-in-tests reaches #[test] functions and not the plain \
              ones they call, which is what the crate-level allow is for. \
              docs/conventions.md §15"
)]

use std::{
    collections::BTreeMap,
    fs,
    io::{Cursor, Write},
};

use rpf_core::{
    Archive, Change, Changes, EntryKind, Error, FileKind, FileSpec, Plan, Storage, Unwatched,
    format::rpf7,
};

/// A stored binary file at `path`.
fn stored(path: &str) -> FileSpec {
    FileSpec {
        path: path.to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Stored,
            encryption: 0,
        },
    }
}

/// Builds an archive into a real file and hands back its bytes — a cursor grows
/// on a write past its end and a file does not, hiding truncation.
fn built(files: &[FileSpec], directories: &[String], contents: &[u8]) -> Vec<u8> {
    let mut sink = tempfile::NamedTempFile::new().expect("temp file");
    rpf_core::build(
        sink.as_file_mut(),
        rpf_core::Version::Rpf7,
        files,
        directories,
        |_: &str| Ok(Cursor::new(contents.to_vec())),
        &mut Unwatched,
    )
    .expect("builds");
    sink.as_file_mut().flush().expect("flushed");
    fs::read(sink.path()).expect("readable")
}

/// Applies `changes` to an archive and hands back the archive that came out.
fn rewritten(source: &[u8], changes: &Changes) -> Vec<u8> {
    rewriting(source, changes).expect("rewrites")
}

/// The same, without deciding whether it should have worked.
fn rewriting(source: &[u8], changes: &Changes) -> Result<Vec<u8>, Error> {
    let mut src = Cursor::new(source.to_vec());
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");

    let mut sink = tempfile::NamedTempFile::new().expect("temp file");
    let report = rpf_core::rewrite(
        &mut src,
        &archive,
        changes,
        sink.as_file_mut(),
        &mut rpf_core::InMemory,
        &mut Unwatched,
    )?;
    sink.as_file_mut().flush().expect("flushed");
    let bytes = fs::read(sink.path()).expect("readable");
    assert_eq!(
        u64::try_from(bytes.len()).expect("fits"),
        report.len,
        "the file on disk is not the length the report claims"
    );
    Ok(bytes)
}

/// Every path in an archive, files and directories alike, in listing order.
fn paths(bytes: &[u8]) -> Vec<String> {
    let mut src = Cursor::new(bytes.to_vec());
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
    rpf_core::Listed::at(&mut src, &archive, "", true)
        .expect("lists")
        .into_iter()
        .map(|row| row.path)
        .collect()
}

/// One entry's contents, by path, addressed through nesting.
fn contents(bytes: &[u8], path: &str) -> Vec<u8> {
    let mut src = Cursor::new(bytes.to_vec());
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
    let (holder, index) = archive.locate(&mut src, path).expect("resolves");
    holder.extract(&mut src, index).expect("extracts")
}

/// A write that creates the path it names.
fn adding(contents: &[u8]) -> Change {
    Change::Write {
        contents: std::sync::Arc::new(rpf_core::Bytes::new(contents.to_vec())),
        create: true,
        allow_encoding_change: false,
    }
}

/// An `RSC7` payload of `len` bytes past its header, which is the smallest
/// thing `build` will accept as a resource.
fn resource(len: usize) -> Vec<u8> {
    let mut bytes = b"RSC7".to_vec();
    bytes.extend_from_slice(&7_u32.to_le_bytes());
    bytes.extend_from_slice(&0x8000_0000_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend(std::iter::repeat_n(0xAB_u8, len));
    bytes
}

#[test]
fn an_added_entry_reads_back() {
    let source = built(&[stored("a.txt")], &[], b"first");
    let changes = Changes::one("b.txt", adding(b"second"));
    let rebuilt = rewritten(&source, &changes);

    assert_eq!(paths(&rebuilt), vec!["a.txt", "b.txt"]);
    assert_eq!(contents(&rebuilt, "b.txt"), b"second".to_vec());
    assert_eq!(contents(&rebuilt, "a.txt"), b"first".to_vec());
}

#[test]
fn an_added_entry_brings_its_parents_with_it() {
    let source = built(&[stored("a.txt")], &[], b"first");
    let changes = Changes::one("data/deep/b.txt", adding(b"second"));
    let rebuilt = rewritten(&source, &changes);

    assert_eq!(
        paths(&rebuilt),
        vec!["a.txt", "data", "data/deep", "data/deep/b.txt"]
    );
    assert_eq!(contents(&rebuilt, "data/deep/b.txt"), b"second".to_vec());
}

/// The payload decides whether a new entry is a resource, because there is no
/// entry yet to ask.
#[test]
fn a_payload_that_is_a_resource_becomes_a_resource_entry() {
    let source = built(&[stored("a.txt")], &[], b"first");
    let payload = resource(64);
    let changes = Changes::one("t.ytd", adding(&payload));
    let rebuilt = rewritten(&source, &changes);

    let mut src = Cursor::new(rebuilt.clone());
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
    let index = archive.find("t.ytd").expect("resolves");
    assert!(
        matches!(
            archive.entry(index).expect("in range").kind,
            EntryKind::Resource { .. }
        ),
        "a payload beginning RSC7 was not written as a resource"
    );
    assert_eq!(contents(&rebuilt, "t.ytd"), payload);
}

#[test]
fn a_payload_that_is_not_a_resource_becomes_a_binary_entry() {
    let source = built(&[stored("a.txt")], &[], b"first");
    let changes = Changes::one("b.txt", adding(&vec![b'z'; 4096]));
    let rebuilt = rewritten(&source, &changes);

    let mut src = Cursor::new(rebuilt.clone());
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
    let index = archive.find("b.txt").expect("resolves");
    match archive.entry(index).expect("in range").kind {
        EntryKind::Binary { compressed_len, .. } => assert!(
            compressed_len > 0,
            "a new binary entry should be offered to the compressor"
        ),
        other => panic!("expected a binary entry, got {other:?}"),
    }
}

/// Creating an entry a caller merely misspelled is the failure this guards.
#[test]
fn a_write_that_did_not_ask_to_create_is_still_not_found() {
    let source = built(&[stored("a.txt")], &[], b"first");
    let changes = Changes::one(
        "b.txt",
        Change::Write {
            contents: std::sync::Arc::new(rpf_core::Bytes::new(b"second".to_vec())),
            create: false,
            allow_encoding_change: false,
        },
    );
    match rewriting(&source, &changes) {
        Err(Error::NotFound { path, .. }) => assert_eq!(path, "b.txt"),
        other => panic!("expected not found, got {:?}", other.map(|b| b.len())),
    }
}

#[test]
fn a_removed_entry_is_gone() {
    let source = built(&[stored("a.txt"), stored("b.txt")], &[], b"same");
    let changes = Changes::one("a.txt", Change::Remove { recursive: false });
    let rebuilt = rewritten(&source, &changes);

    assert_eq!(paths(&rebuilt), vec!["b.txt"]);
    assert_eq!(contents(&rebuilt, "b.txt"), b"same".to_vec());
}

#[test]
fn removing_a_directory_takes_its_children() {
    let source = built(
        &[
            stored("data/a.txt"),
            stored("data/deep/b.txt"),
            stored("c.txt"),
        ],
        &[],
        b"same",
    );
    let changes = Changes::one("data", Change::Remove { recursive: true });
    let rebuilt = rewritten(&source, &changes);

    assert_eq!(paths(&rebuilt), vec!["c.txt"]);
}

#[test]
fn removing_a_directory_that_holds_something_needs_saying_so() {
    let source = built(&[stored("data/a.txt"), stored("c.txt")], &[], b"same");
    let changes = Changes::one("data", Change::Remove { recursive: false });
    match rewriting(&source, &changes) {
        Err(Error::BadPath { path, reason }) => {
            assert_eq!(path, "data");
            assert_eq!(reason, "is a directory that is not empty");
        }
        other => panic!("expected a refusal, got {:?}", other.map(|b| b.len())),
    }
}

#[test]
fn removing_an_empty_directory_needs_nothing_said() {
    let source = built(&[stored("c.txt")], &["data".to_owned()], b"same");
    assert_eq!(paths(&source), vec!["c.txt", "data"]);

    let changes = Changes::one("data", Change::Remove { recursive: false });
    assert_eq!(paths(&rewritten(&source, &changes)), vec!["c.txt"]);
}

#[test]
fn a_renamed_entry_keeps_its_contents() {
    let source = built(&[stored("a.txt"), stored("b.txt")], &[], b"same");
    let changes = Changes::one("a.txt", Change::RenameTo("data/z.txt".to_owned()));
    let rebuilt = rewritten(&source, &changes);

    assert_eq!(paths(&rebuilt), vec!["b.txt", "data", "data/z.txt"]);
    assert_eq!(contents(&rebuilt, "data/z.txt"), b"same".to_vec());
}

#[test]
fn renaming_a_directory_moves_its_children() {
    let source = built(
        &[stored("data/a.txt"), stored("data/deep/b.txt")],
        &[],
        b"same",
    );
    let changes = Changes::one("data", Change::RenameTo("moved".to_owned()));
    let rebuilt = rewritten(&source, &changes);

    assert_eq!(
        paths(&rebuilt),
        vec!["moved", "moved/a.txt", "moved/deep", "moved/deep/b.txt"]
    );
}

/// An `RPF7` archive whose header claims the encryption tag `tag`, holding one
/// stored entry. The tag is the header's fourth word, at bytes 12 through 16.
fn tagged(tag: u32) -> Vec<u8> {
    let mut bytes = built(&[stored("note.txt")], &[], b"held inside");
    bytes
        .get_mut(12..16)
        .expect("a whole header")
        .copy_from_slice(&tag.to_le_bytes());
    bytes
}

/// An NG archive's every region is keyed by `(hash(name) + length + 61) % 101`,
/// so what it is called is part of what it is; an AES archive takes its key
/// from the tag alone and is the same archive under any name.
#[test]
fn a_nested_aes_archive_is_renamed_and_a_nested_ng_one_is_not() {
    let renaming = Changes::one("inner.rpf", Change::RenameTo("other.rpf".to_owned()));

    // The AES half: what lands under the new name is the payload byte for byte.
    let aes = tagged(rpf7::ENCRYPTION_AES);
    let rebuilt = rewritten(&built(&[stored("inner.rpf")], &[], &aes), &renaming);
    assert_eq!(paths(&rebuilt), vec!["other.rpf"]);
    assert_eq!(contents(&rebuilt, "other.rpf"), aes);

    // The NG half, on a fixture differing only in those four bytes.
    let ng = tagged(rpf7::ENCRYPTION_NG);
    let refused = rewriting(&built(&[stored("inner.rpf")], &[], &ng), &renaming)
        .expect_err("renaming a nested NG archive is refused");
    assert_eq!(refused.name(), "CannotRenameKeyed", "{refused:?}");
}

/// The caller says what it means by removing the target in the same change set.
#[test]
fn renaming_onto_an_existing_path_is_refused() {
    let source = built(&[stored("a.txt"), stored("b.txt")], &[], b"same");
    let changes = Changes::one("a.txt", Change::RenameTo("b.txt".to_owned()));
    match rewriting(&source, &changes) {
        Err(Error::AlreadyExists { path }) => assert_eq!(path, "b.txt"),
        other => panic!("expected a refusal, got {:?}", other.map(|b| b.len())),
    }
}

/// Removals are applied before renames, which is what lets this go through.
#[test]
fn removing_the_target_first_lets_a_rename_take_its_place() {
    let source = built(&[stored("a.txt"), stored("b.txt")], &[], b"same");
    let mut changes = Changes::new();
    changes.set("b.txt", Change::Remove { recursive: false });
    changes.set("a.txt", Change::RenameTo("b.txt".to_owned()));
    let rebuilt = rewritten(&source, &changes);

    assert_eq!(paths(&rebuilt), vec!["b.txt"]);
}

/// The two are different archives; moving bytes between them is not one
/// rebuild.
#[test]
fn renaming_into_a_nested_archive_is_refused() {
    let inner = built(&[stored("f.txt")], &[], b"inner");
    let source = built(&[stored("a.txt"), stored("sub/inner.rpf")], &[], &inner);
    let changes = Changes::one("a.txt", Change::RenameTo("sub/inner.rpf/a.txt".to_owned()));
    match rewriting(&source, &changes) {
        Err(Error::BadPath { path, reason }) => {
            assert_eq!(path, "sub/inner.rpf/a.txt");
            assert_eq!(reason, "is inside another archive");
        }
        other => panic!("expected a refusal, got {:?}", other.map(|b| b.len())),
    }
}

/// `build` derives parents from file paths and cannot see an empty directory.
#[test]
fn a_created_directory_survives_with_nothing_in_it() {
    let source = built(&[stored("a.txt")], &[], b"first");
    let changes = Changes::one("empty", Change::MakeDirectory);
    let rebuilt = rewritten(&source, &changes);

    assert_eq!(paths(&rebuilt), vec!["a.txt", "empty"]);
}

#[test]
fn creating_a_directory_that_is_already_there_is_refused() {
    let source = built(&[stored("data/a.txt")], &[], b"first");
    let changes = Changes::one("data", Change::MakeDirectory);
    match rewriting(&source, &changes) {
        Err(Error::AlreadyExists { path }) => assert_eq!(path, "data"),
        other => panic!("expected a refusal, got {:?}", other.map(|b| b.len())),
    }
}

#[test]
fn a_structural_change_inside_a_nested_archive_cascades() {
    let inner = built(&[stored("f.txt")], &[], b"inner");
    // Only the nested archive, because `built` serves one payload to every file
    // it is given: a second entry would hold the inner archive's bytes too.
    let source = built(&[stored("sub/inner.rpf")], &[], &inner);

    let mut changes = Changes::new();
    changes.set("sub/inner.rpf/new.txt", adding(b"added"));
    changes.set("sub/inner.rpf/f.txt", Change::Remove { recursive: false });
    let rebuilt = rewritten(&source, &changes);

    assert_eq!(
        paths(&rebuilt),
        vec!["sub", "sub/inner.rpf", "sub/inner.rpf/new.txt"]
    );
    assert_eq!(
        contents(&rebuilt, "sub/inner.rpf/new.txt"),
        b"added".to_vec()
    );
}

#[test]
fn a_rename_inside_a_nested_archive_lands_at_the_path_it_named() {
    let inner = built(&[stored("f.txt")], &[], b"inner");
    let source = built(&[stored("sub/inner.rpf")], &[], &inner);

    let changes = Changes::one(
        "sub/inner.rpf/f.txt",
        Change::RenameTo("sub/inner.rpf/moved.txt".to_owned()),
    );
    let rebuilt = rewritten(&source, &changes);

    assert_eq!(
        paths(&rebuilt),
        vec!["sub", "sub/inner.rpf", "sub/inner.rpf/moved.txt"]
    );
    assert_eq!(contents(&rebuilt, "sub/inner.rpf/moved.txt"), b"inner");
}

#[test]
fn a_rename_into_a_directory_of_a_nested_archive_keeps_the_whole_path() {
    let inner = built(&[stored("f.txt")], &["data".to_owned()], b"inner");
    let source = built(&[stored("sub/inner.rpf")], &[], &inner);

    let changes = Changes::one(
        "sub/inner.rpf/f.txt",
        Change::RenameTo("sub/inner.rpf/data/moved.txt".to_owned()),
    );
    let rebuilt = rewritten(&source, &changes);

    assert!(
        paths(&rebuilt).contains(&"sub/inner.rpf/data/moved.txt".to_owned()),
        "{:?}",
        paths(&rebuilt)
    );
    assert_eq!(contents(&rebuilt, "sub/inner.rpf/data/moved.txt"), b"inner");
}

/// The plan says so before anything is written, rather than entry by entry.
#[test]
fn a_structural_change_cannot_be_patched_in_place() {
    let source = built(&[stored("a.txt")], &[], b"first");
    let mut src = Cursor::new(source);
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");

    for (path, change, what) in [
        ("b.txt", adding(b"second"), "adds an entry"),
        (
            "a.txt",
            Change::Remove { recursive: false },
            "removes an entry",
        ),
        (
            "a.txt",
            Change::RenameTo("z.txt".to_owned()),
            "renames an entry",
        ),
        ("d", Change::MakeDirectory, "adds a directory"),
    ] {
        let changes = Changes::one(path, change);
        match rpf_core::plan(&mut src, &archive, &changes).expect("plans") {
            Plan::Structural(structural) => {
                assert_eq!(structural.len(), 1, "{path}");
                let first = structural.first().expect("one");
                assert_eq!(first.path, path);
                assert_eq!(first.what, what);
            }
            other => panic!("expected {path} to be structural, got {other:?}"),
        }
    }
}

#[test]
fn replacing_an_entry_that_exists_is_still_patched_in_place() {
    let source = built(&[stored("a.txt")], &[], b"first");
    let mut src = Cursor::new(source);
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");

    let changes = Changes::writing(BTreeMap::from([("a.txt".to_owned(), b"other".to_vec())]));
    match rpf_core::plan(&mut src, &archive, &changes).expect("plans") {
        Plan::Fits(patches) => assert_eq!(patches.planned().count(), 1),
        other => panic!("expected a patch, got {other:?}"),
    }
}

#[test]
fn a_change_is_refused_when_it_is_offered() {
    let source = built(&[stored("data/a.txt")], &[], b"first");
    let mut src = Cursor::new(source);
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");

    let nothing = Changes::new();
    rpf_core::allows(
        &mut src,
        &archive,
        &nothing,
        "data/a.txt",
        &Change::Remove { recursive: false },
    )
    .expect("removing a file is allowed");

    match rpf_core::allows(&mut src, &archive, &nothing, "data", &Change::MakeDirectory) {
        Err(Error::AlreadyExists { path }) => assert_eq!(path, "data"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    match rpf_core::allows(
        &mut src,
        &archive,
        &nothing,
        "nowhere",
        &Change::Remove { recursive: false },
    ) {
        Err(Error::NotFound { path, .. }) => assert_eq!(path, "nowhere"),
        other => panic!("expected not found, got {other:?}"),
    }
}

#[test]
fn a_change_is_judged_against_the_changes_already_buffered() {
    let source = built(&[stored("data/a.txt"), stored("readme.txt")], &[], b"first");
    let mut src = Cursor::new(source);
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");

    // A caller that means to replace the target removes it in the same set.
    let mut buffered = Changes::new();
    buffered.set("readme.txt", Change::Remove { recursive: false });
    rpf_core::allows(
        &mut src,
        &archive,
        &buffered,
        "data/a.txt",
        &Change::RenameTo("readme.txt".to_owned()),
    )
    .expect("a buffered removal frees the path a rename moves onto");

    // And the other direction: a rename has already claimed the path.
    let mut buffered = Changes::new();
    buffered.set("readme.txt", Change::RenameTo("moved.txt".to_owned()));
    match rpf_core::allows(
        &mut src,
        &archive,
        &buffered,
        "moved.txt",
        &adding(b"second"),
    ) {
        Err(Error::AlreadyExists { path }) => assert_eq!(path, "moved.txt"),
        other => panic!("expected a refusal, got {other:?}"),
    }

    // A rename of a directory takes what is inside it with it, so a change
    // addressing through the old name no longer resolves.
    let mut buffered = Changes::new();
    buffered.set("data", Change::RenameTo("info".to_owned()));
    match rpf_core::allows(
        &mut src,
        &archive,
        &buffered,
        "data/a.txt",
        &Change::RenameTo("data/b.txt".to_owned()),
    ) {
        Err(Error::NotFound { path, .. }) => assert_eq!(path, "data/a.txt"),
        other => panic!("expected not found, got {other:?}"),
    }

    // A buffered write has nothing to write to once what holds it is removed.
    let mut buffered = Changes::new();
    buffered.set(
        "data/a.txt",
        Change::Write {
            contents: std::sync::Arc::new(rpf_core::Bytes::new(b"second".to_vec())),
            create: false,
            allow_encoding_change: false,
        },
    );
    match rpf_core::allows(
        &mut src,
        &archive,
        &buffered,
        "data",
        &Change::Remove { recursive: true },
    ) {
        Err(Error::NotFound { path, .. }) => assert_eq!(path, "data/a.txt"),
        other => panic!("expected not found, got {other:?}"),
    }

    // A change reaching none of the buffered ones is decided by the archive.
    let mut buffered = Changes::new();
    buffered.set("readme.txt", Change::Remove { recursive: false });
    rpf_core::allows(
        &mut src,
        &archive,
        &buffered,
        "data/a.txt",
        &Change::RenameTo("data/b.txt".to_owned()),
    )
    .expect("an unrelated removal decides nothing about this rename");
}

/// A set holds one change per path. Two writes are not a second change —
/// saving one file twice is what an editor does.
#[test]
fn a_second_change_of_another_kind_at_one_path_is_refused() {
    let mut buffered = Changes::new();
    buffered.set("readme.txt", Change::RenameTo("moved.txt".to_owned()));

    match buffered.admits("readme.txt", &adding(b"second")) {
        Err(Error::Claimed { path, held }) => {
            assert_eq!(path, "readme.txt");
            assert_eq!(held, "a rename");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }

    buffered
        .admits("readme.txt", &Change::RenameTo("moved.txt".to_owned()))
        .expect("the same change offered again is not a second change");

    let mut writes = Changes::new();
    writes.set("readme.txt", adding(b"first"));
    writes
        .admits("readme.txt", &adding(b"second"))
        .expect("saving one file twice is what an editor does");

    writes
        .admits("elsewhere.txt", &Change::MakeDirectory)
        .expect("another path is not claimed");
}

#[test]
fn the_changes_that_restructure_are_the_ones_no_patch_expresses() {
    let mut changes = Changes::new();
    changes.set(
        "plain.txt",
        Change::Write {
            contents: std::sync::Arc::new(rpf_core::Bytes::new(b"x".to_vec())),
            create: false,
            allow_encoding_change: false,
        },
    );
    assert!(
        !changes.bears_on("plain.txt"),
        "a plain write cannot move anything"
    );

    changes.set("data", Change::Remove { recursive: true });
    assert!(changes.bears_on("data/a.txt"), "a removal reaches below it");
    assert!(changes.bears_on("data"), "and reaches itself");
    assert!(
        !changes.bears_on("elsewhere.txt"),
        "and reaches nothing else"
    );

    // Replaced by a plain write, the removal is no longer in the index.
    changes.set(
        "data",
        Change::Write {
            contents: std::sync::Arc::new(rpf_core::Bytes::new(b"x".to_vec())),
            create: false,
            allow_encoding_change: false,
        },
    );
    assert!(!changes.bears_on("data/a.txt"));

    // A rename reaches the path it moves onto as well as the one it moves.
    changes.set("readme.txt", Change::RenameTo("moved.txt".to_owned()));
    assert!(changes.bears_on("moved.txt"));

    changes.forget("readme.txt");
    assert!(
        !changes.bears_on("moved.txt"),
        "a forgotten change reaches nothing"
    );
    assert_eq!(changes.len(), 2);
}

/// An archive without its root directory is not an archive.
#[test]
fn the_root_cannot_be_removed_or_renamed() {
    let source = built(&[stored("a.txt")], &[], b"first");
    for change in [
        Change::Remove { recursive: true },
        Change::RenameTo("z".to_owned()),
    ] {
        let changes = Changes::one("", change);
        match rewriting(&source, &changes) {
            Err(Error::BadPath { path, reason }) => {
                assert_eq!(path, "");
                assert_eq!(reason, "is the archive's root");
            }
            other => panic!("expected a refusal, got {:?}", other.map(|b| b.len())),
        }
    }
}

#[test]
fn the_entry_count_and_names_blob_follow_the_change() {
    let source = built(&[stored("a.txt")], &[], b"first");
    let mut src = Cursor::new(source.clone());
    let before = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
    let names_before = before.names_blob().len();

    let changes = Changes::one("bbbbbbbb.txt", adding(b"second"));
    let rebuilt = rewritten(&source, &changes);
    let mut handle = Cursor::new(rebuilt);
    let after = Archive::open(&mut handle, &rpf_core::Unlock::unkeyed()).expect("parses");

    assert_eq!(
        after.entries().len(),
        before.entries().len() + 1,
        "an added entry did not change the entry count"
    );
    assert_eq!(
        after.names_blob().len(),
        names_before + "bbbbbbbb.txt".len() + 1,
        "an added entry did not change the names blob"
    );
    let verified = rpf_core::Verified::of(&mut handle, &after, &mut Unwatched).expect("verifies");
    verified.outcome().expect("reads back clean");
}

/// `Change::Write` holds a trait object, which is `Send + Sync` only if the
/// trait asks for them.
#[test]
fn a_change_set_is_still_send_and_sync() {
    const fn assert_send<T: Send>() {}
    const fn assert_sync<T: Sync>() {}

    assert_send::<rpf_core::Changes>();
    assert_sync::<rpf_core::Changes>();
    assert_send::<rpf_core::Change>();
    assert_sync::<rpf_core::Change>();
}

/// `tree_of` applies removals before writes, so without this the removal takes
/// the empty directory out and the write implies it back holding a file.
#[test]
fn a_directory_the_set_writes_into_is_not_empty_either() {
    let source = built(&[stored("c.txt")], &["empty".to_owned()], b"same");
    assert_eq!(paths(&source), vec!["c.txt", "empty"]);

    let mut changes = Changes::new();
    changes.set(
        "empty/fresh.txt",
        Change::Write {
            contents: std::sync::Arc::new(rpf_core::Bytes::new(b"new".to_vec())),
            create: true,
            allow_encoding_change: false,
        },
    );
    changes.set("empty", Change::Remove { recursive: false });

    match rewriting(&source, &changes) {
        Err(Error::BadPath { path, reason }) => {
            assert_eq!(path, "empty");
            assert_eq!(reason, "is a directory that is not empty");
        }
        other => panic!("expected a refusal, got {:?}", other.map(|b| b.len())),
    }
}

/// The combination itself is not refused: `recursive` is how a caller says it
/// wants the old directory gone and a new one implied by the write.
#[test]
fn saying_recursive_allows_the_directory_to_be_rebuilt_by_the_write() {
    let source = built(&[stored("c.txt")], &["empty".to_owned()], b"same");

    let mut changes = Changes::new();
    changes.set(
        "empty/fresh.txt",
        Change::Write {
            contents: std::sync::Arc::new(rpf_core::Bytes::new(b"new".to_vec())),
            create: true,
            allow_encoding_change: false,
        },
    );
    changes.set("empty", Change::Remove { recursive: true });

    let rebuilt = rewritten(&source, &changes);
    assert_eq!(paths(&rebuilt), vec!["c.txt", "empty", "empty/fresh.txt"]);
}

/// `allows` resolves the offered change against the buffered set through
/// `tree_of`, so the rule lands in one place and both frontends get it.
#[test]
fn the_wire_refuses_the_removal_the_set_has_already_filled() {
    let source = built(&[stored("c.txt")], &["empty".to_owned()], b"same");
    let mut src = std::io::Cursor::new(source.clone());
    let archive = rpf_core::Archive::open(&mut src, &rpf_core::Unlock::unkeyed())
        .expect("the archive parses");

    let mut buffered = Changes::new();
    buffered.set(
        "empty/fresh.txt",
        Change::Write {
            contents: std::sync::Arc::new(rpf_core::Bytes::new(b"new".to_vec())),
            create: true,
            allow_encoding_change: false,
        },
    );

    let offered = Change::Remove { recursive: false };
    match rpf_core::allows(&mut src, &archive, &buffered, "empty", &offered) {
        Err(Error::BadPath { path, reason }) => {
            assert_eq!(path, "empty");
            assert_eq!(reason, "is a directory that is not empty");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }

    // And with `recursive`, which is how a caller says it meant both.
    let said = Change::Remove { recursive: true };
    rpf_core::allows(&mut src, &archive, &buffered, "empty", &said).expect("recursive is allowed");
}

/// `tree_of` removes before it renames, so the removal alone would take the
/// empty directory out and the rename imply it back holding the moved file.
#[test]
fn a_directory_the_set_renames_into_is_not_empty_either() {
    let source = built(&[stored("a.txt")], &["empty".to_owned()], b"same");
    assert_eq!(paths(&source), vec!["a.txt", "empty"]);

    let mut changes = Changes::new();
    changes.set("a.txt", Change::RenameTo("empty/moved.txt".to_owned()));
    changes.set("empty", Change::Remove { recursive: false });

    match rewriting(&source, &changes) {
        Err(Error::BadPath { path, reason }) => {
            assert_eq!(path, "empty");
            assert_eq!(reason, "is a directory that is not empty");
        }
        other => panic!("expected a refusal, got {:?}", other.map(|b| b.len())),
    }

    // The destination is what makes the rename bear on the removal at all.
    let mut src = std::io::Cursor::new(source.clone());
    let archive = rpf_core::Archive::open(&mut src, &rpf_core::Unlock::unkeyed())
        .expect("the archive parses");
    let mut buffered = Changes::new();
    buffered.set("a.txt", Change::RenameTo("empty/moved.txt".to_owned()));
    let offered = Change::Remove { recursive: false };
    match rpf_core::allows(&mut src, &archive, &buffered, "empty", &offered) {
        Err(Error::BadPath { path, reason }) => {
            assert_eq!(path, "empty");
            assert_eq!(reason, "is a directory that is not empty");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// "Arrives under this directory" is not "exists anywhere": conflating them
/// makes an empty directory undeletable while any creation is buffered.
#[test]
fn a_creation_outside_the_directory_leaves_it_empty() {
    let source = built(&[stored("a.txt")], &["empty".to_owned()], b"same");

    let mut changes = Changes::new();
    changes.set("elsewhere/new.txt", adding(b"new"));
    changes.set("empty", Change::Remove { recursive: false });

    let rebuilt = rewritten(&source, &changes);
    assert_eq!(
        paths(&rebuilt),
        vec!["a.txt", "elsewhere", "elsewhere/new.txt"],
        "the empty directory outlived a removal that named it"
    );

    // A new directory named outside it is no more of an arrival than a file is.
    let mut changes = Changes::new();
    changes.set("elsewhere", Change::MakeDirectory);
    changes.set("empty", Change::Remove { recursive: false });
    let rebuilt = rewritten(&source, &changes);
    assert_eq!(paths(&rebuilt), vec!["a.txt", "elsewhere"]);
}

/// Two changes with no path in common decide nothing about each other, so
/// `bearing_on` resolves the offered change against the subset that could
/// reach it and leaves the rest out.
#[test]
fn a_removal_is_answered_against_the_changes_that_reach_it() {
    let source = built(
        &[stored("a.txt"), stored("other.txt")],
        &["empty".to_owned()],
        b"same",
    );
    let mut src = std::io::Cursor::new(source);
    let archive = rpf_core::Archive::open(&mut src, &rpf_core::Unlock::unkeyed())
        .expect("the archive parses");

    // `forget` puts the freed path back, leaving the rename in the set claiming
    // a path that exists again.
    let mut buffered = Changes::new();
    buffered.set("other.txt", Change::Remove { recursive: false });
    buffered.set("a.txt", Change::RenameTo("other.txt".to_owned()));
    assert!(
        buffered.forget("other.txt").is_some(),
        "nothing was buffered"
    );

    let unrelated = Change::Remove { recursive: false };
    rpf_core::allows(&mut src, &archive, &buffered, "empty", &unrelated)
        .expect("an empty directory is still empty");

    // The rename really has gone stale, which makes the answer above an answer.
    let again = Change::RenameTo("other.txt".to_owned());
    assert!(
        matches!(
            rpf_core::allows(&mut src, &archive, &buffered, "a.txt", &again),
            Err(Error::AlreadyExists { .. })
        ),
        "the rename should now be refused on its own account"
    );

    // `allows` would not have admitted this write, so the set is built
    // directly; the removal is still decided without it.
    let mut buffered = Changes::new();
    buffered.set(
        "missing.txt",
        Change::Write {
            contents: std::sync::Arc::new(rpf_core::Bytes::new(b"new".to_vec())),
            create: false,
            allow_encoding_change: false,
        },
    );
    rpf_core::allows(&mut src, &archive, &buffered, "empty", &unrelated)
        .expect("a write elsewhere does not decide this removal");
}

/// `at_or_under` folds case, so the path *at* the directory — the replacing
/// case — has to be recognised however the caller spells it.
#[test]
fn a_replacing_rename_holds_however_the_caller_spells_it() {
    for spelling in ["empty", "EMPTY", "Empty"] {
        let source = built(&[stored("a.txt")], &["empty".to_owned()], b"same");
        let mut changes = Changes::new();
        changes.set("empty", Change::Remove { recursive: false });
        changes.set("a.txt", Change::RenameTo((*spelling).to_owned()));

        let rebuilt = rewriting(&source, &changes)
            .unwrap_or_else(|error| panic!("{spelling} was refused: {error:?}"));
        let mut src = std::io::Cursor::new(rebuilt);
        let archive = rpf_core::Archive::open(&mut src, &rpf_core::Unlock::unkeyed())
            .expect("the archive parses");
        assert_eq!(archive.entries().len(), 2, "root and the renamed entry");
    }
}

/// The names blob is NUL-terminated, so `a\0b` would be written and read back
/// as `a`, and two paths differing only after the NUL would collide where the
/// collision check — comparing the names asked for — cannot see it.
#[test]
fn a_nul_inside_a_path_is_refused_rather_than_silently_truncating_it() {
    let source = built(&[stored("a.txt")], &[], b"same");

    let mut changes = Changes::new();
    changes.set("dir\u{0}b", Change::MakeDirectory);
    changes.set("dir\u{0}c", Change::MakeDirectory);

    match rewriting(&source, &changes) {
        Err(Error::BadPath { path, .. }) => assert!(path.contains('\u{0}'), "{path:?}"),
        other => panic!("expected a refusal, got {:?}", other.map(|b| b.len())),
    }
}

/// `Bytes::len`, `Contents::is_empty` and `Changes::iter` are surface a caller
/// is offered and no code in this crate calls.
#[test]
fn the_accessors_a_caller_is_offered_answer_what_they_promise() {
    use rpf_core::Contents as _;

    let empty = rpf_core::Bytes::new(Vec::new());
    assert_eq!(empty.len().expect("a length"), 0);
    assert!(empty.is_empty().expect("emptiness"));

    let three = rpf_core::Bytes::new(vec![1, 2, 3]);
    assert_eq!(three.len().expect("a length"), 3);
    assert!(!three.is_empty().expect("emptiness"));

    // `iter` and the `IntoIterator` twin are the same iteration.
    let mut changes = Changes::new();
    changes.set("a.txt", Change::Remove { recursive: false });
    changes.set("b.txt", Change::MakeDirectory);
    let by_method: Vec<&str> = changes.iter().map(|(path, _)| path).collect();
    let by_trait: Vec<&str> = (&changes).into_iter().map(|(path, _)| path).collect();
    assert_eq!(by_method, vec!["a.txt", "b.txt"]);
    assert_eq!(by_method, by_trait);
}

/// Contents whose reader answers [`std::io::ErrorKind::Interrupted`] before
/// each of its first reads, which the loop reading a new entry's first four
/// bytes has to tolerate.
#[derive(Debug)]
struct Interrupted {
    bytes: Vec<u8>,
    interruptions: usize,
}

impl rpf_core::Contents for Interrupted {
    fn open(&self) -> Result<Box<dyn rpf_core::Payload + '_>, Error> {
        Ok(Box::new(Stutters {
            inner: Cursor::new(self.bytes.clone()),
            left: self.interruptions,
        }))
    }

    fn len(&self) -> Result<u64, Error> {
        Ok(self.bytes.len() as u64)
    }
}

/// The reader [`Interrupted`] hands out.
struct Stutters {
    inner: Cursor<Vec<u8>>,
    left: usize,
}

impl std::io::Read for Stutters {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.left > 0 {
            self.left -= 1;
            return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
        }
        self.inner.read(buf)
    }
}

impl std::io::Seek for Stutters {
    fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(to)
    }
}

#[test]
fn a_new_entry_whose_reader_is_interrupted_is_still_written_whole() {
    let source = built(&[stored("a.txt")], &[], b"same");
    let payload = b"the contents of a brand new entry".to_vec();

    let changes = Changes::one(
        "new.bin",
        Change::Write {
            contents: std::sync::Arc::new(Interrupted {
                bytes: payload.clone(),
                interruptions: 2,
            }),
            create: true,
            allow_encoding_change: false,
        },
    );

    let rebuilt = rewritten(&source, &changes);
    let mut src = Cursor::new(rebuilt);
    let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
    let index = archive.find("new.bin").expect("the new entry is there");
    assert_eq!(archive.read(&mut src, index).expect("reads"), payload);
}
