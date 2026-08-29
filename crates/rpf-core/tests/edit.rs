//! R4.10: adding, deleting and renaming an entry.
//!
//! What is proven here is that this crate's own reader reads back what these
//! changes produce, and that the round trip is stable across them. What is
//! **not** proven is that the runtime accepts an archive whose entry count is
//! not the one its producer wrote — that is Q8, it needs a machine running the
//! game, and DR-026 says so rather than leaving it to be assumed.
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

/// Builds an archive into a real file and hands back its bytes.
///
/// A real file rather than a `Cursor<Vec<u8>>` for `roundtrip.rs`'s reason: a
/// cursor grows on a write past its end and a file does not, which is what made
/// a whole class of truncation invisible.
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
    let archive = Archive::open(&mut src).expect("parses");

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
    let archive = Archive::open(&mut src).expect("parses");
    rpf_core::Listed::at(&mut src, &archive, "", true)
        .expect("lists")
        .into_iter()
        .map(|row| row.path)
        .collect()
}

/// One entry's contents, by path, addressed through nesting.
fn contents(bytes: &[u8], path: &str) -> Vec<u8> {
    let mut src = Cursor::new(bytes.to_vec());
    let archive = Archive::open(&mut src).expect("parses");
    let (holder, index) = archive.locate(&mut src, path).expect("resolves");
    holder.extract(&mut src, index).expect("extracts")
}

/// A write that creates the path it names.
fn adding(contents: &[u8]) -> Change {
    Change::Write {
        contents: std::sync::Arc::new(contents.to_vec()),
        create: true,
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

/// An entry the archive did not hold is created, and reads back.
#[test]
fn an_added_entry_reads_back() {
    let source = built(&[stored("a.txt")], &[], b"first");
    let changes = Changes::one("b.txt", adding(b"second"));
    let rebuilt = rewritten(&source, &changes);

    assert_eq!(paths(&rebuilt), vec!["a.txt", "b.txt"]);
    assert_eq!(contents(&rebuilt, "b.txt"), b"second".to_vec());
    assert_eq!(contents(&rebuilt, "a.txt"), b"first".to_vec());
}

/// An addition creates whatever directories above it are missing, because a
/// path is the only thing that says a directory should be there.
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
/// entry yet to ask. DR-026.
#[test]
fn a_payload_that_is_a_resource_becomes_a_resource_entry() {
    let source = built(&[stored("a.txt")], &[], b"first");
    let payload = resource(64);
    let changes = Changes::one("t.ytd", adding(&payload));
    let rebuilt = rewritten(&source, &changes);

    let mut src = Cursor::new(rebuilt.clone());
    let archive = Archive::open(&mut src).expect("parses");
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

/// And a payload that is not one becomes a binary entry, deflated.
#[test]
fn a_payload_that_is_not_a_resource_becomes_a_binary_entry() {
    let source = built(&[stored("a.txt")], &[], b"first");
    let changes = Changes::one("b.txt", adding(&vec![b'z'; 4096]));
    let rebuilt = rewritten(&source, &changes);

    let mut src = Cursor::new(rebuilt.clone());
    let archive = Archive::open(&mut src).expect("parses");
    let index = archive.find("b.txt").expect("resolves");
    match archive.entry(index).expect("in range").kind {
        EntryKind::Binary { compressed_len, .. } => assert!(
            compressed_len > 0,
            "a new binary entry should be offered to the compressor"
        ),
        other => panic!("expected a binary entry, got {other:?}"),
    }
}

/// A write to a path the archive does not hold is still not found unless the
/// caller asked for it to be created. The old behaviour, kept on purpose:
/// creating an entry a caller merely misspelled is the failure this guards.
#[test]
fn a_write_that_did_not_ask_to_create_is_still_not_found() {
    let source = built(&[stored("a.txt")], &[], b"first");
    let changes = Changes::one(
        "b.txt",
        Change::Write {
            contents: std::sync::Arc::new(b"second".to_vec()),
            create: false,
        },
    );
    match rewriting(&source, &changes) {
        Err(Error::NotFound { path, .. }) => assert_eq!(path, "b.txt"),
        other => panic!("expected not found, got {:?}", other.map(|b| b.len())),
    }
}

/// A removed entry is gone, and nothing else moves.
#[test]
fn a_removed_entry_is_gone() {
    let source = built(&[stored("a.txt"), stored("b.txt")], &[], b"same");
    let changes = Changes::one("a.txt", Change::Remove { recursive: false });
    let rebuilt = rewritten(&source, &changes);

    assert_eq!(paths(&rebuilt), vec!["b.txt"]);
    assert_eq!(contents(&rebuilt, "b.txt"), b"same".to_vec());
}

/// Removing a directory takes its children with it, when the caller said so.
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

/// And will not, when it did not: a directory that holds anything is refused
/// rather than emptied silently.
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

/// An empty directory is removed without asking, because there is nothing to
/// take with it.
#[test]
fn removing_an_empty_directory_needs_nothing_said() {
    let source = built(&[stored("c.txt")], &["data".to_owned()], b"same");
    assert_eq!(paths(&source), vec!["c.txt", "data"]);

    let changes = Changes::one("data", Change::Remove { recursive: false });
    assert_eq!(paths(&rewritten(&source, &changes)), vec!["c.txt"]);
}

/// A renamed entry keeps its contents and loses its old name.
#[test]
fn a_renamed_entry_keeps_its_contents() {
    let source = built(&[stored("a.txt"), stored("b.txt")], &[], b"same");
    let changes = Changes::one("a.txt", Change::RenameTo("data/z.txt".to_owned()));
    let rebuilt = rewritten(&source, &changes);

    assert_eq!(paths(&rebuilt), vec!["b.txt", "data", "data/z.txt"]);
    assert_eq!(contents(&rebuilt, "data/z.txt"), b"same".to_vec());
}

/// Renaming a directory moves everything under it.
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

/// A rename onto a path the archive already holds is refused rather than
/// silently destroying it. DR-026: the caller says what it means by removing
/// the target in the same change set.
#[test]
fn renaming_onto_an_existing_path_is_refused() {
    let source = built(&[stored("a.txt"), stored("b.txt")], &[], b"same");
    let changes = Changes::one("a.txt", Change::RenameTo("b.txt".to_owned()));
    match rewriting(&source, &changes) {
        Err(Error::AlreadyExists { path }) => assert_eq!(path, "b.txt"),
        other => panic!("expected a refusal, got {:?}", other.map(|b| b.len())),
    }
}

/// And removing the target in the same set is what makes it go through, which
/// is the whole reason removals are applied before renames.
#[test]
fn removing_the_target_first_lets_a_rename_take_its_place() {
    let source = built(&[stored("a.txt"), stored("b.txt")], &[], b"same");
    let mut changes = Changes::new();
    changes.set("b.txt", Change::Remove { recursive: false });
    changes.set("a.txt", Change::RenameTo("b.txt".to_owned()));
    let rebuilt = rewritten(&source, &changes);

    assert_eq!(paths(&rebuilt), vec!["b.txt"]);
}

/// A rename into a nested archive is refused: the two are different archives
/// and moving bytes between them is not one rebuild.
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

/// A directory asked for outright survives the rebuild even though nothing is
/// in it — `build` derives parents from file paths and cannot see one.
#[test]
fn a_created_directory_survives_with_nothing_in_it() {
    let source = built(&[stored("a.txt")], &[], b"first");
    let changes = Changes::one("empty", Change::MakeDirectory);
    let rebuilt = rewritten(&source, &changes);

    assert_eq!(paths(&rebuilt), vec!["a.txt", "empty"]);
}

/// Creating a directory that is already there is refused, because the caller
/// asked for something that cannot be done twice.
#[test]
fn creating_a_directory_that_is_already_there_is_refused() {
    let source = built(&[stored("data/a.txt")], &[], b"first");
    let changes = Changes::one("data", Change::MakeDirectory);
    match rewriting(&source, &changes) {
        Err(Error::AlreadyExists { path }) => assert_eq!(path, "data"),
        other => panic!("expected a refusal, got {:?}", other.map(|b| b.len())),
    }
}

/// Every one of them works inside a nested archive, cascading the rebuild the
/// way replacing an entry always has.
#[test]
fn a_structural_change_inside_a_nested_archive_cascades() {
    let inner = built(&[stored("f.txt")], &[], b"inner");
    // Only the nested archive, because `built` serves one payload to every file
    // it is given: a second entry would hold the inner archive's bytes too, and
    // a recursive listing descends into anything that is one.
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

/// Nothing structural can be patched in place, and the plan says so before
/// anything is written rather than discovering it entry by entry.
#[test]
fn a_structural_change_cannot_be_patched_in_place() {
    let source = built(&[stored("a.txt")], &[], b"first");
    let mut src = Cursor::new(source);
    let archive = Archive::open(&mut src).expect("parses");

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

/// Replacing an entry that exists is still patched in place, so gaining the
/// three structural changes did not cost the operation the whole design is
/// built around.
#[test]
fn replacing_an_entry_that_exists_is_still_patched_in_place() {
    let source = built(&[stored("a.txt")], &[], b"first");
    let mut src = Cursor::new(source);
    let archive = Archive::open(&mut src).expect("parses");

    let changes = Changes::writing(BTreeMap::from([("a.txt".to_owned(), b"other".to_vec())]));
    match rpf_core::plan(&mut src, &archive, &changes).expect("plans") {
        Plan::Fits(patches) => assert_eq!(patches.planned().count(), 1),
        other => panic!("expected a patch, got {other:?}"),
    }
}

/// A change is checked before it is buffered, so a client is told now rather
/// than at the commit that decided nothing else.
#[test]
fn a_change_is_refused_when_it_is_offered() {
    let source = built(&[stored("data/a.txt")], &[], b"first");
    let mut src = Cursor::new(source);
    let archive = Archive::open(&mut src).expect("parses");

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

/// A change is resolved against the changes already buffered, not only against
/// the archive on disk — so a set the commit accepts can be assembled one
/// request at a time, and a set it does not is refused at the request that
/// makes it so.
///
/// Every arm here is one row of DR-030's table, measured against a live daemon
/// on 2026-08-29 and answered by DR-032.
#[test]
fn a_change_is_judged_against_the_changes_already_buffered() {
    let source = built(&[stored("data/a.txt"), stored("readme.txt")], &[], b"first");
    let mut src = Cursor::new(source);
    let archive = Archive::open(&mut src).expect("parses");

    // DR-026 §5: a caller that means to replace the target removes it in the
    // same set, and removals are applied before renames for exactly that
    // reason. Resolved against the archive alone this was `AlreadyExists`, so
    // no order of requests could assemble the set the library accepts.
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

    // And the other direction: a rename has claimed the path, so a creation
    // there is refused now rather than at the commit.
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
    // addressing through the old name no longer resolves. The commit answered
    // this and the offer did not.
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

    // A buffered write is left with nothing to write to when what holds it is
    // removed.
    let mut buffered = Changes::new();
    buffered.set(
        "data/a.txt",
        Change::Write {
            contents: std::sync::Arc::new(b"second".to_vec()),
            create: false,
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

    // And a change that reaches none of the buffered ones is decided by the
    // archive alone, exactly as before.
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

/// A set holds one change per path, so a second change of another kind at one
/// path is refused rather than quietly replacing the first.
///
/// Measured over the wire on 2026-08-29: `rename readme.txt -> moved.txt`
/// followed by `write readme.txt` answered `pending: 1` and the commit renamed
/// nothing. Two writes are not this — saving one file twice is what an editor
/// does. DR-032.
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

/// The index of changes that restructure is an index over the set and never a
/// second fact about it.
#[test]
fn the_changes_that_restructure_are_the_ones_no_patch_expresses() {
    let mut changes = Changes::new();
    changes.set(
        "plain.txt",
        Change::Write {
            contents: std::sync::Arc::new(b"x".to_vec()),
            create: false,
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
            contents: std::sync::Arc::new(b"x".to_vec()),
            create: false,
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

/// The root is not an entry a caller may remove or rename: an archive without
/// its root directory is not an archive.
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

/// The entry count and the names blob follow from the paths, which is what
/// makes a structural change a rebuild rather than a patch. R4.10, and the half
/// of Q8 that can be settled here.
#[test]
fn the_entry_count_and_names_blob_follow_the_change() {
    let source = built(&[stored("a.txt")], &[], b"first");
    let mut src = Cursor::new(source.clone());
    let before = Archive::open(&mut src).expect("parses");
    let names_before = before.names_blob().len();

    let changes = Changes::one("bbbbbbbb.txt", adding(b"second"));
    let rebuilt = rewritten(&source, &changes);
    let mut handle = Cursor::new(rebuilt);
    let after = Archive::open(&mut handle).expect("parses");

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
    // And the archive is self-consistent afterwards, which is the only thing
    // this repository can prove about it. DR-026.
    let verified = rpf_core::Verified::of(&mut handle, &after, &mut Unwatched).expect("verifies");
    verified.outcome().expect("reads back clean");
}
