//! Command-line behaviour: exit codes, the round trip, and the write guard.
//!
//! These build their own archive with `rpf_core::build`, so they need no
//! corpus and run everywhere. R8.4 wants the suite to mean something on a
//! machine with no game data, and this is most of what that means.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code; a panic is the reporting mechanism"
)]

use std::{collections::BTreeMap, fs, path::Path, process::Command};

use rpf_core::{FileKind, FileSpec, Storage};

/// The binary under test, as cargo built it.
const RPF: &str = env!("CARGO_BIN_EXE_rpf");

/// A small archive: two files, one in a directory, one stored and one deflated.
fn make_archive(at: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut contents = BTreeMap::new();
    contents.insert(
        "data/greeting.txt".to_owned(),
        b"hello, and here is enough text that deflate is worth it. ".repeat(8),
    );
    contents.insert("stored.bin".to_owned(), vec![7_u8; 300]);

    let files = vec![
        FileSpec {
            path: "data/greeting.txt".to_owned(),
            kind: FileKind::Binary {
                storage: Storage::Deflate,
                encryption: 0,
            },
        },
        FileSpec {
            path: "stored.bin".to_owned(),
            kind: FileKind::Binary {
                storage: Storage::Stored,
                encryption: 0,
            },
        },
    ];

    let mut out = fs::File::create(at).expect("archive is creatable");
    rpf_core::build(&mut out, &files, &[], |wanted| {
        Ok(contents.get(wanted).cloned().unwrap_or_default())
    })
    .expect("archive builds");
    contents
}

/// Runs the binary, returning its exit code and standard output.
fn run(args: &[&str]) -> (i32, Vec<u8>) {
    let output = Command::new(RPF).args(args).output().expect("binary runs");
    (output.status.code().unwrap_or(-1), output.stdout)
}

#[test]
fn exit_codes_distinguish_the_failures() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive = archive.display().to_string();

    assert_eq!(run(&["info", &archive]).0, 0, "a good archive");
    assert_eq!(run(&["cat", &archive, "nope/missing"]).0, 3, "not found");

    // Both shapes of "not an archive": long enough to have a header and the
    // magic is wrong, and too short to have one at all. Neither is an i/o
    // failure — nothing failed, the bytes are simply not an archive.
    let wrong_magic = dir.path().join("plain.txt");
    fs::write(&wrong_magic, b"this is definitely not an archive at all").expect("writable");
    assert_eq!(
        run(&["info", &wrong_magic.display().to_string()]).0,
        4,
        "wrong magic"
    );

    let too_short = dir.path().join("stub.rpf");
    fs::write(&too_short, b"7FPR").expect("writable");
    assert_eq!(
        run(&["info", &too_short.display().to_string()]).0,
        4,
        "too short"
    );

    let empty = dir.path().join("empty.rpf");
    fs::write(&empty, b"").expect("writable");
    assert_eq!(run(&["info", &empty.display().to_string()]).0, 4, "empty");

    let missing = dir.path().join("absent.rpf").display().to_string();
    assert_eq!(run(&["info", &missing]).0, 7, "i/o");
    assert_eq!(run(&["not-a-command"]).0, 2, "usage");
}

#[test]
fn cat_edit_put_round_trips() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    let contents = make_archive(&archive);
    let archive = archive.display().to_string();

    // What comes out is what went in.
    let (code, out) = run(&["cat", &archive, "data/greeting.txt"]);
    assert_eq!(code, 0);
    assert_eq!(
        out, contents["data/greeting.txt"],
        "cat returned something else"
    );

    // Change it, put it back, read it again.
    let edited = dir.path().join("edited.txt");
    fs::write(&edited, b"replaced").expect("writable");
    assert_eq!(
        run(&[
            "put",
            &archive,
            "data/greeting.txt",
            &edited.display().to_string()
        ])
        .0,
        0,
    );

    let (code, out) = run(&["cat", &archive, "data/greeting.txt"]);
    assert_eq!(code, 0);
    assert_eq!(out, b"replaced", "the edit did not survive");

    // The other entry is untouched, and the archive still verifies.
    let (_, out) = run(&["cat", &archive, "stored.bin"]);
    assert_eq!(out, contents["stored.bin"], "an unrelated entry changed");
    assert_eq!(run(&["verify", &archive]).0, 0, "verify");
}

#[test]
fn writing_into_a_game_installation_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().join("Grand Theft Auto V");
    let deep = root.join("mods/update/x64/dlcpacks");
    fs::create_dir_all(&deep).expect("directories");
    fs::write(root.join("GTA5.exe"), b"not really").expect("writable");

    let archive = deep.join("dlc.rpf");
    make_archive(&archive);
    let archive = archive.display().to_string();

    let replacement = dir.path().join("replacement.txt");
    fs::write(&replacement, b"replaced").expect("writable");
    let replacement = replacement.display().to_string();

    assert_eq!(
        run(&["put", &archive, "data/greeting.txt", &replacement]).0,
        6,
        "should refuse to write into a detected installation",
    );
    assert_eq!(
        run(&[
            "put",
            "--force",
            &archive,
            "data/greeting.txt",
            &replacement
        ])
        .0,
        0,
        "--force should override the refusal",
    );
}

#[cfg(unix)]
#[test]
fn put_keeps_the_archives_permissions() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    fs::set_permissions(&archive, fs::Permissions::from_mode(0o644)).expect("chmod");

    let replacement = dir.path().join("replacement.txt");
    fs::write(&replacement, b"replaced").expect("writable");

    let code = run(&[
        "put",
        &archive.display().to_string(),
        "data/greeting.txt",
        &replacement.display().to_string(),
    ])
    .0;
    assert_eq!(code, 0);

    // A temporary file is created 0600. Replacing a file must not tighten it.
    let mode = fs::metadata(&archive).expect("stat").permissions().mode() & 0o777;
    assert_eq!(mode, 0o644, "permissions changed to {mode:o}");
}

#[test]
fn ls_of_a_nested_archive_lists_what_is_inside_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let inner_path = dir.path().join("inner.rpf");
    make_archive(&inner_path);
    let inner = fs::read(&inner_path).expect("readable");

    // An archive holding an archive, stored rather than deflated.
    let outer_path = dir.path().join("outer.rpf");
    let files = vec![FileSpec {
        path: "x64/inner.rpf".to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Stored,
            encryption: 0,
        },
    }];
    let mut out = fs::File::create(&outer_path).expect("creatable");
    rpf_core::build(&mut out, &files, &[], |_| Ok(inner.clone())).expect("outer builds");
    let outer = outer_path.display().to_string();

    let (code, listing) = run(&["ls", &outer, "x64/inner.rpf"]);
    assert_eq!(code, 0);
    let listing = String::from_utf8_lossy(&listing);
    assert!(listing.contains("stored.bin"), "listing was: {listing}");
    assert!(listing.contains("data"), "listing was: {listing}");

    // And a path straight through the nesting reaches the leaf.
    let (code, out) = run(&["cat", &outer, "x64/inner.rpf/stored.bin"]);
    assert_eq!(code, 0);
    assert_eq!(out.len(), 300, "cat through nesting");
}

#[test]
fn extract_then_pack_preserves_the_tree() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    let contents = make_archive(&archive);
    let archive = archive.display().to_string();

    let tree = dir.path().join("tree");
    assert_eq!(
        run(&["extract", &archive, &tree.display().to_string()]).0,
        0,
        "extract"
    );

    // Every entry is on disk, and the manifest is beside them.
    assert!(tree.join(rpf_core::MANIFEST_NAME).is_file(), "no manifest");
    for (path, bytes) in &contents {
        let on_disk = fs::read(tree.join(path)).expect("extracted file");
        assert_eq!(&on_disk, bytes, "{path} came out different");
    }

    let packed = dir.path().join("packed.rpf");
    assert_eq!(
        run(&[
            "pack",
            &tree.display().to_string(),
            &packed.display().to_string()
        ])
        .0,
        0,
        "pack",
    );
    let packed = packed.display().to_string();
    assert_eq!(run(&["verify", &packed]).0, 0, "verify");

    for (path, bytes) in &contents {
        let (code, out) = run(&["cat", &packed, path]);
        assert_eq!(code, 0, "cat {path}");
        assert_eq!(&out, bytes, "{path} changed across extract and pack");
    }
}

#[test]
fn an_empty_directory_survives_extract_and_pack() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");

    // A directory holding no files cannot be inferred from any file path, which
    // is the whole reason the manifest records directories at all.
    let files = vec![FileSpec {
        path: "data/greeting.txt".to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Deflate,
            encryption: 0,
        },
    }];
    let mut out = fs::File::create(&archive).expect("creatable");
    rpf_core::build(&mut out, &files, &["x64/empty".to_owned()], |_| {
        Ok(b"hello".to_vec())
    })
    .expect("builds");
    drop(out);

    let tree = dir.path().join("tree");
    assert_eq!(
        run(&[
            "extract",
            &archive.display().to_string(),
            &tree.display().to_string()
        ])
        .0,
        0
    );
    assert!(
        tree.join("x64/empty").is_dir(),
        "the empty directory was not extracted"
    );

    let packed = dir.path().join("packed.rpf");
    assert_eq!(
        run(&[
            "pack",
            &tree.display().to_string(),
            &packed.display().to_string()
        ])
        .0,
        0,
    );

    let (code, listing) = run(&["ls", "-R", &packed.display().to_string()]);
    assert_eq!(code, 0);
    let listing = String::from_utf8_lossy(&listing);
    assert!(listing.contains("x64/empty"), "listing was: {listing}");
}

#[test]
fn packing_says_which_file_is_missing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);

    let tree = dir.path().join("tree");
    assert_eq!(
        run(&[
            "extract",
            &archive.display().to_string(),
            &tree.display().to_string()
        ])
        .0,
        0
    );

    // Remove one file the manifest still lists.
    fs::remove_file(tree.join("stored.bin")).expect("removable");

    let packed = dir.path().join("packed.rpf");
    let output = Command::new(RPF)
        .args([
            "pack",
            &tree.display().to_string(),
            &packed.display().to_string(),
        ])
        .output()
        .expect("binary runs");
    assert_eq!(output.status.code(), Some(7), "should be an i/o failure");
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("stored.bin"), "message was: {message}");
}

#[test]
fn packing_without_a_manifest_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let empty = dir.path().join("nothing");
    fs::create_dir_all(&empty).expect("directories");
    let packed = dir.path().join("packed.rpf");
    assert_eq!(
        run(&[
            "pack",
            &empty.display().to_string(),
            &packed.display().to_string()
        ])
        .0,
        7,
        "a tree with no manifest is not a tree we can pack",
    );
}
