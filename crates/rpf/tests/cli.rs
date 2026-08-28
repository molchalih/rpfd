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

use std::{collections::BTreeMap, fs, io::Cursor, path::Path, process::Command};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rpf_core::{FileKind, FileSpec, Storage, Unwatched};

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
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |wanted| {
            Ok(Cursor::new(
                contents.get(wanted).cloned().unwrap_or_default(),
            ))
        },
        &mut Unwatched,
    )
    .expect("archive builds");
    contents
}

/// Runs the binary, returning its exit code and standard output.
fn run(args: &[&str]) -> (i32, Vec<u8>) {
    let output = Command::new(RPF).args(args).output().expect("binary runs");
    (output.status.code().unwrap_or(-1), output.stdout)
}

/// Runs the binary, returning its exit code and standard error.
fn run_err(args: &[&str]) -> (i32, String) {
    run_err_in(Path::new("."), args)
}

/// Runs the binary from inside `directory`, returning its exit code and
/// standard error.
///
/// A child process rather than `set_current_dir`, which is process-global and
/// would race every other test in this binary.
fn run_err_in(directory: &Path, args: &[&str]) -> (i32, String) {
    let output = Command::new(RPF)
        .current_dir(directory)
        .args(args)
        .output()
        .expect("binary runs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Where one entry's payload sits, how much room it has, and where its entry
/// row is — read from the archive, so a report about them can be checked
/// against something other than itself.
fn spans(at: &Path, inside: &str) -> (u64, u64, u64) {
    let mut file = fs::File::open(at).expect("archive opens");
    let archive = rpf_core::Archive::open(&mut file).expect("archive parses");
    let index = archive.find(inside).expect("entry resolves");
    let (payload_at, _) = archive.payload_at(index).expect("payload span");
    (
        payload_at,
        archive.allocation(index).expect("allocation"),
        archive.row_at(index).expect("entry row"),
    )
}

/// Which byte positions differ, refusing a pair that is not the same length.
///
/// The same shape as `rpf-core`'s own `differences`; an integration test is its
/// own crate, so the two cannot be one function.
fn differences(before: &[u8], after: &[u8]) -> Vec<usize> {
    assert_eq!(
        before.len(),
        after.len(),
        "an in-place patch must not resize the archive"
    );
    before
        .iter()
        .zip(after)
        .enumerate()
        .filter_map(|(at, (before, after))| (before != after).then_some(at))
        .collect()
}

/// `offset` as an index into the archive's bytes.
fn index_of(offset: u64) -> usize {
    usize::try_from(offset).expect("an offset within a test archive fits a usize")
}

#[test]
fn exit_codes_distinguish_the_failures() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive = archive.display().to_string();

    assert_eq!(run(&["info", &archive]).0, 0, "a good archive");
    assert_eq!(run(&["cat", &archive, "nope/missing"]).0, 3, "not found");

    // Both shapes of "not an archive". Neither is an i/o failure — nothing
    // failed, the bytes are simply not an archive — and the two are not one
    // exit code either: what the four bytes claim decides who has to act on
    // them. DR-019.
    let wrong_magic = dir.path().join("plain.txt");
    fs::write(&wrong_magic, b"this is definitely not an archive at all").expect("writable");
    assert_eq!(
        run(&["info", &wrong_magic.display().to_string()]).0,
        6,
        "bytes that never claimed to be an archive"
    );

    let too_short = dir.path().join("stub.rpf");
    fs::write(&too_short, b"7FPR").expect("writable");
    assert_eq!(
        run(&["info", &too_short.display().to_string()]).0,
        4,
        "an archive that says so and does not hold a header"
    );

    let empty = dir.path().join("empty.rpf");
    fs::write(&empty, b"").expect("writable");
    assert_eq!(run(&["info", &empty.display().to_string()]).0, 6, "empty");

    // The case DR-019 is about: an entry that is an ordinary file, named as an
    // archive by the caller's own path. Nothing in `test.rpf` is wrong.
    assert_eq!(
        run(&["info", &archive, "stored.bin"]).0,
        6,
        "an ordinary entry named as a nested archive"
    );

    // An RPF of a version with no codec here is not the same failure as either
    // of those: nothing is malformed and the caller's request was fine. It used
    // to report `not an RPF7 archive` and exit 4. R11.1, DR-010's amendment.
    let other_version = dir.path().join("rpf2.rpf");
    let mut header = b"RPF2".to_vec();
    header.extend_from_slice(&1_u32.to_le_bytes());
    header.extend_from_slice(&0_u32.to_le_bytes());
    header.extend_from_slice(&rpf_core::Version::Rpf7.open().to_le_bytes());
    fs::write(&other_version, &header).expect("writable");
    let (code, stderr) = run_err(&["info", &other_version.display().to_string()]);
    assert_eq!(code, 9, "another container version: {stderr}");
    assert!(
        stderr.contains("RPF2"),
        "the version must be named: {stderr}"
    );

    let missing = dir.path().join("absent.rpf").display().to_string();
    assert_eq!(run(&["info", &missing]).0, 7, "i/o");
    assert_eq!(run(&["not-a-command"]).0, 2, "usage");
}

#[test]
fn a_payload_that_does_not_inflate_is_a_corrupt_archive_and_not_a_disk_failure() {
    // DR-010. Every byte asked for arrived and then failed to decode, which is
    // a fact about the archive. Reported as exit 7 it read as "the disk
    // misbehaved, try again", and an agent consumer that retries on i/o retried
    // for ever.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let (at, _, _) = spans(&archive, "data/greeting.txt");

    // 0xFF opens a deflate block with the reserved type, so the stream is
    // refused rather than inflating to the wrong length — which is
    // LengthMismatch, a different variant that was already classified right.
    let mut bytes = fs::read(&archive).expect("readable");
    let start = index_of(at);
    bytes[start..start + 8].fill(0xFF);
    fs::write(&archive, &bytes).expect("writable");

    let archive = archive.display().to_string();
    assert_eq!(run(&["cat", &archive, "data/greeting.txt"]).0, 4, "cat");
    assert_eq!(run(&["verify", &archive]).0, 4, "verify");
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

/// An archive holding an archive at `x64/inner.rpf`, stored rather than
/// deflated, returning the outer path and the inner one it was built from.
fn make_nested(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let inner_path = dir.join("inner.rpf");
    make_archive(&inner_path);
    let inner = fs::read(&inner_path).expect("readable");

    let outer_path = dir.join("outer.rpf");
    let files = vec![FileSpec {
        path: "x64/inner.rpf".to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Stored,
            encryption: 0,
        },
    }];
    let mut out = fs::File::create(&outer_path).expect("creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_| Ok(Cursor::new(inner.clone())),
        &mut Unwatched,
    )
    .expect("outer builds");
    (outer_path, inner_path)
}

#[test]
fn ls_of_a_nested_archive_lists_what_is_inside_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (outer_path, _) = make_nested(dir.path());
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

/// R11.4: `pack` writes the version the manifest names, and holds no default
/// of its own.
///
/// Walked over [`rpf_core::Version::ALL`], which has one member: today this
/// says the version reaching the header came through the manifest rather than
/// from a constant in `build`, and on the day a second codec lands it says the
/// same of that one without anybody editing this. DR-018 is the record that
/// asked for it — a tree extracted from one version must not pack as another.
#[test]
fn pack_writes_the_version_the_manifest_names() {
    for &version in rpf_core::Version::ALL {
        let dir = tempfile::tempdir().expect("temp dir");
        let archive = dir.path().join("test.rpf");
        make_archive(&archive);

        let tree = dir.path().join("tree");
        assert_eq!(
            run(&[
                "extract",
                &archive.display().to_string(),
                &tree.display().to_string(),
            ])
            .0,
            0,
            "extract",
        );

        // Rewritten through `Manifest` rather than as text, so the test does
        // not encode how the field is spelled on disk twice.
        let at = tree.join(rpf_core::MANIFEST_NAME);
        let text = fs::read_to_string(&at).expect("manifest readable");
        let mut manifest = rpf_core::Manifest::from_json(&text).expect("manifest parses");
        manifest.version = version;
        manifest.codec = version.codec();
        manifest.encryption = version.open();
        fs::write(&at, manifest.to_json().expect("manifest renders")).expect("manifest writable");

        let packed = dir.path().join("packed.rpf");
        assert_eq!(
            run(&[
                "pack",
                &tree.display().to_string(),
                &packed.display().to_string(),
            ])
            .0,
            0,
            "pack",
        );
        let bytes = fs::read(&packed).expect("packed readable");
        assert_eq!(
            bytes.get(0..4),
            Some(&version.magic()[..]),
            "packed at the wrong version",
        );
    }
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
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &["x64/empty".to_owned()],
        |_| Ok(Cursor::new(b"hello".to_vec())),
        &mut Unwatched,
    )
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

#[test]
fn a_dry_run_reports_the_patch_it_would_make_and_writes_nothing() {
    // R6.7. The primary consumer is automation deciding whether to go ahead;
    // what it needs is the decision, not the write.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    // Read from the archive, not from the report: "an offset, and room enough"
    // is true of every archive ever written, so a report saying only that says
    // nothing. R6.7 promises the caller the offset it would be written at.
    let (at, allocation, _) = spans(&archive, "data/greeting.txt");
    let archive = archive.display().to_string();
    let before = fs::read(&archive).expect("readable");

    let edited = dir.path().join("edited.txt");
    fs::write(&edited, b"replaced").expect("writable");

    let (code, out) = run(&[
        "--json",
        "put",
        &archive,
        "data/greeting.txt",
        &edited.display().to_string(),
        "--dry-run",
    ]);
    assert_eq!(code, 0);

    let report: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(report["method"], serde_json::json!("patch"));
    assert_eq!(report["dry_run"], serde_json::json!(true));
    assert_eq!(report["path"], serde_json::json!("data/greeting.txt"));
    assert_eq!(report["at"], serde_json::json!(at), "{report}");
    // Eight bytes deflate to more than eight, so the stored form wins and what
    // would be written is the file itself.
    assert_eq!(report["len"], serde_json::json!(8));
    assert_eq!(
        report["allocation"],
        serde_json::json!(allocation),
        "{report}"
    );

    assert_eq!(
        fs::read(&archive).expect("readable"),
        before,
        "a dry run wrote to the archive"
    );
}

#[test]
fn a_put_that_fits_patches_in_place_rather_than_rebuilding() {
    // The claim `docs/approach.md` makes for `put`: an edit that fits costs the
    // bytes of the edit, not the bytes of the archive. Nothing else here can
    // tell the two apart — a rebuild round-trips just as well, and the dry runs
    // that report `"patch"` never write — so this is the only test that fails
    // when every `put` quietly rebuilds.
    //
    // `big.bin` is eight blocks of payload replaced by eight bytes, so the two
    // answers differ in length as well as in content: a patch leaves the seven
    // spare blocks where they are, and a rebuild packs them out.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    let stored = |path: &str| FileSpec {
        path: path.to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Stored,
            encryption: 0,
        },
    };
    let mut out = fs::File::create(&archive).expect("creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &[stored("big.bin"), stored("tail.bin")],
        &[],
        |wanted| {
            Ok(Cursor::new(if wanted == "big.bin" {
                vec![0xAB_u8; 4096]
            } else {
                vec![7_u8; 300]
            }))
        },
        &mut Unwatched,
    )
    .expect("builds");
    drop(out);

    let before = fs::read(&archive).expect("readable");
    let (at, allocation, row_at) = spans(&archive, "big.bin");
    let archive = archive.display().to_string();

    let edited = dir.path().join("edited.bin");
    fs::write(&edited, b"replaced").expect("writable");
    assert_eq!(
        run(&["put", &archive, "big.bin", &edited.display().to_string()]).0,
        0,
    );

    // `differences` refuses a pair of different lengths, which is where a
    // rebuild is caught; the loop is what catches one that came out the same
    // size anyway.
    let after = fs::read(&archive).expect("readable");
    let payload = index_of(at)..index_of(at.saturating_add(allocation));
    let row = index_of(row_at)..index_of(row_at.saturating_add(rpf_core::Version::Rpf7.row_len()));
    for position in differences(&before, &after) {
        assert!(
            payload.contains(&position) || row.contains(&position),
            "byte {position} changed, and it is neither the payload nor its entry row",
        );
    }

    // And the edit did land, so the archive was not simply left alone.
    let (code, out) = run(&["cat", &archive, "big.bin"]);
    assert_eq!(code, 0);
    assert_eq!(out, b"replaced", "the patch did not take");
    let (_, out) = run(&["cat", &archive, "tail.bin"]);
    assert_eq!(out, vec![7_u8; 300], "an unrelated entry changed");
}

#[test]
fn a_dry_run_told_to_rebuild_says_so_and_writes_nothing() {
    // `--rebuild --dry-run` is the one dry run that answers without calling
    // `plan`: the rebuild was asked for rather than forced by a payload that
    // will not fit, so there is no allocation to report against and nothing
    // computes the answer. An answer nothing computes is an answer nothing
    // checks.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive = archive.display().to_string();
    let before = fs::read(&archive).expect("readable");

    let edited = dir.path().join("edited.txt");
    fs::write(&edited, b"replaced").expect("writable");
    let edited = edited.display().to_string();

    let (code, out) = run(&[
        "--json",
        "put",
        &archive,
        "data/greeting.txt",
        &edited,
        "--rebuild",
        "--dry-run",
    ]);
    assert_eq!(code, 0);

    let report: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(report["method"], serde_json::json!("rebuild"), "{report}");
    assert_eq!(report["dry_run"], serde_json::json!(true), "{report}");
    assert_eq!(report["path"], serde_json::json!("data/greeting.txt"));
    assert_eq!(
        fs::read(&archive).expect("readable"),
        before,
        "a dry run wrote to the archive"
    );

    // The same edit, not told to rebuild, would have been patched. So this
    // answer is the flag being obeyed rather than the edit not fitting.
    let (code, out) = run(&[
        "--json",
        "put",
        &archive,
        "data/greeting.txt",
        &edited,
        "--dry-run",
    ]);
    assert_eq!(code, 0);
    let report: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(report["method"], serde_json::json!("patch"), "{report}");
}

#[test]
fn a_dry_run_says_when_it_would_have_to_rebuild() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive = archive.display().to_string();
    let before = fs::read(&archive).expect("readable");

    // Bytes that do not compress, so no spare block will hold them.
    let big: Vec<u8> = (0..200_000_u32)
        .map(|i| u8::try_from((i.wrapping_mul(2_654_435_761) >> 13) & 0xFF).unwrap_or_default())
        .collect();
    let edited = dir.path().join("big.bin");
    fs::write(&edited, &big).expect("writable");

    let (code, out) = run(&[
        "--json",
        "put",
        &archive,
        "data/greeting.txt",
        &edited.display().to_string(),
        "--dry-run",
    ]);
    assert_eq!(code, 0);

    let report: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(report["method"], serde_json::json!("rebuild"));
    assert_eq!(report["dry_run"], serde_json::json!(true));
    // `needed` is what would actually be written — the payload after the
    // entry's own storage rule has been applied, not the size of the file on
    // disk. Reporting the latter would explain the wrong number.
    let needed = report["needed"].as_u64().unwrap_or_default();
    let allocation = report["allocation"].as_u64().unwrap_or_default();
    assert!(
        needed > allocation,
        "that is not why it would rebuild: {report}"
    );
    assert!(
        needed <= big.len() as u64,
        "more is reported than was given: {report}"
    );

    assert_eq!(
        fs::read(&archive).expect("readable"),
        before,
        "a dry run wrote to the archive"
    );
}

#[test]
fn a_dry_run_needs_no_write_permission() {
    // It decides and reports; asking for write access to do that would make it
    // useless on exactly the archives worth asking about.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);

    let mut permissions = fs::metadata(&archive).expect("stat").permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&archive, permissions).expect("chmod");

    let edited = dir.path().join("edited.txt");
    fs::write(&edited, b"replaced").expect("writable");

    let (code, _) = run(&[
        "put",
        &archive.display().to_string(),
        "data/greeting.txt",
        &edited.display().to_string(),
        "--dry-run",
    ]);
    assert_eq!(code, 0, "a dry run should not need to open for writing");
}

#[test]
fn verify_counts_every_entry_it_read_and_says_what_went_wrong() {
    // R6.9. `checked` counted only the entries that passed, so a two-entry
    // archive with one bad payload reported "1 of 1 entries failed"; and the
    // non-zero exit was carried by LengthMismatch, which renders as a sentence
    // about inflation that has nothing to do with what happened.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let (at, _, _) = spans(&archive, "data/greeting.txt");

    let mut bytes = fs::read(&archive).expect("readable");
    let start = index_of(at);
    bytes[start..start + 8].fill(0xFF);
    fs::write(&archive, &bytes).expect("writable");
    let archive = archive.display().to_string();

    let (code, out) = run(&["--json", "verify", &archive]);
    assert_eq!(code, 4, "a payload that does not read back");
    let report: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(
        report["entries_checked"],
        serde_json::json!(2),
        "both entries were read: {report}"
    );
    assert_eq!(
        report["problems"].as_array().map(Vec::len),
        Some(1),
        "{report}"
    );

    let (code, plain) = run(&["verify", &archive]);
    assert_eq!(code, 4);
    let plain = String::from_utf8_lossy(&plain);
    assert!(
        plain.contains("1 of 2 entries failed"),
        "the count was: {plain}"
    );

    let (_, message) = run_err(&["verify", &archive]);
    assert!(
        message.contains("1 of 2 entries are not as they are recorded"),
        "the failure was reported as: {message}"
    );
    assert!(
        !message.contains("inflated to"),
        "verify still borrows a length mismatch to carry its exit: {message}"
    );
}

#[test]
fn info_subtracts_the_entry_table_and_the_names_blob_from_the_slack() {
    // `docs/rpf-format.md`, Slack: unreferenced is the archive's length less
    // the header, the entry table, the names blob and every payload. It counted
    // only the header and the payloads, so it over-reported by the two regions
    // in between — 320 bytes on the sample, and it disagreed with the verified
    // row it derives from.
    //
    // The three sizes are written out here rather than taken from `format`, so
    // that this checks the arithmetic against the format document instead of
    // against the same constants the code uses.
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("test.rpf");
    make_archive(&path);

    let len = fs::metadata(&path).expect("stat").len();
    let mut file = fs::File::open(&path).expect("archive opens");
    let archive = rpf_core::Archive::open(&mut file).expect("archive parses");
    let entries = u64::try_from(archive.entries().len()).expect("a test archive is small");
    let names = u64::try_from(archive.names_blob().len()).expect("a test names blob is small");

    let mut payloads = 0_u64;
    for (index, entry) in archive.entries().iter().enumerate() {
        if entry.is_directory() {
            continue;
        }
        let index = u32::try_from(index).expect("a test archive is small");
        let (_, on_disk) = archive
            .payload_at(index)
            .expect("a file entry has a payload");
        payloads += on_disk;
    }
    let expected = len - (16 + 16 * entries + names) - payloads;

    let (code, out) = run(&["--json", "info", &path.display().to_string()]);
    assert_eq!(code, 0);
    let report: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(
        report["unreferenced_bytes"],
        serde_json::json!(expected),
        "{report}"
    );
    // And the regions really are there to subtract, so the test would fail if
    // the two agreed only because both were zero.
    assert!(entries > 0 && names > 0, "{entries} entries, {names} names");
}

/// Builds an archive of `names`, then rewrites `placeholder` in its names blob
/// to `actual`.
///
/// `build` refuses the names these tests need — that refusal is the write half
/// of the same rules — so the archive is made with a legal name of equal length
/// and edited afterwards. The two must be the same length so that nothing in
/// the archive moves, and the substitution asserts the placeholder occurs
/// exactly once, so what is edited is the name and nothing else.
fn archive_named(at: &Path, names: &[&str], placeholder: &str, actual: &str) {
    assert_eq!(
        placeholder.len(),
        actual.len(),
        "substituting a different length would move the payloads"
    );
    let files: Vec<FileSpec> = names
        .iter()
        .map(|name| FileSpec {
            path: (*name).to_owned(),
            kind: FileKind::Binary {
                storage: Storage::Stored,
                encryption: 0,
            },
        })
        .collect();

    let mut out = Vec::new();
    rpf_core::build(
        &mut std::io::Cursor::new(&mut out),
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_| Ok(Cursor::new(b"payload".to_vec())),
        &mut Unwatched,
    )
    .expect("legal names build");

    let occurrences = out
        .windows(placeholder.len())
        .filter(|window| *window == placeholder.as_bytes())
        .count();
    assert_eq!(
        occurrences, 1,
        "the name must appear only in the names blob"
    );
    let at_offset = out
        .windows(placeholder.len())
        .position(|window| window == placeholder.as_bytes())
        .expect("the placeholder is in the blob");
    out.get_mut(at_offset..at_offset.saturating_add(placeholder.len()))
        .expect("the placeholder is in the blob")
        .copy_from_slice(actual.as_bytes());

    fs::write(at, &out).expect("archive is writable");
}

#[test]
fn extract_refuses_a_name_that_climbs_out_of_the_target() {
    // Reproduced before this was refused: the file landed one level above the
    // target and the command reported `1 files and 1 directories into <target>`
    // with exit 0. R10.3.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    archive_named(
        &archive,
        &["xx_escaped.txt"],
        "xx_escaped.txt",
        "../escaped.txt",
    );
    let target = dir.path().join("tree");

    let (code, stderr) = run_err(&[
        "extract",
        &archive.display().to_string(),
        &target.display().to_string(),
    ]);
    assert_eq!(code, 6, "a hostile name is a refusal: {stderr}");
    assert!(
        stderr.contains("../escaped.txt"),
        "the refusal must name the path it is about: {stderr}"
    );
    assert!(
        !dir.path().join("escaped.txt").exists(),
        "nothing may be written above the target"
    );

    // Only extraction is refused. The archive is not malformed and listing it
    // is how a caller finds out what is wrong with it.
    assert_eq!(run(&["ls", &archive.display().to_string()]).0, 0);
}

#[test]
fn pack_refuses_a_manifest_name_that_climbs_out_of_the_tree() {
    // Reproduced before this was refused: `pack` read a file from above the
    // tree it was given and exited 0. R10.3.
    let dir = tempfile::tempdir().expect("temp dir");
    let tree = dir.path().join("tree");
    fs::create_dir(&tree).expect("tree");
    fs::write(dir.path().join("escaped.txt"), b"above the tree").expect("writable");

    let manifest = serde_json::json!({
        "schema": 1,
        "encryption": rpf_core::Version::Rpf7.open(),
        "directories": [],
        "entries": [{
            "path": "../escaped.txt",
            "class": "binary",
            "storage": "stored",
            "encryption": 0,
        }],
    });
    fs::write(
        tree.join(rpf_core::MANIFEST_NAME),
        serde_json::to_vec_pretty(&manifest).expect("json"),
    )
    .expect("writable");

    let archive = dir.path().join("packed.rpf");
    let (code, stderr) = run_err(&[
        "pack",
        &tree.display().to_string(),
        &archive.display().to_string(),
    ]);
    assert_eq!(code, 6, "a hostile name is a refusal: {stderr}");
    assert!(
        stderr.contains("../escaped.txt"),
        "the refusal must name the path it is about: {stderr}"
    );
    assert!(
        !archive.exists(),
        "nothing may be produced from a manifest that reaches outside its tree"
    );
}

#[test]
fn an_entry_named_like_the_sidecar_manifest_is_refused_both_ways() {
    // Reproduced: `extract` writes every entry and then writes the manifest
    // over the top of it, so the file on disk held the manifest rather than the
    // entry's bytes and the report said "2 files", exit 0. `pack` read the same
    // name as the manifest *and* as an entry payload, also exit 0.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    let name = rpf_core::MANIFEST_NAME;
    assert_eq!(name.len(), "zzzzzzzzzzzzzzzzzz".len());
    archive_named(
        &archive,
        &["b.txt", "zzzzzzzzzzzzzzzzzz"],
        "zzzzzzzzzzzzzzzzzz",
        name,
    );

    let target = dir.path().join("tree");
    let (code, stderr) = run_err(&[
        "extract",
        &archive.display().to_string(),
        &target.display().to_string(),
    ]);
    assert_eq!(code, 6, "the manifest's own name is a refusal: {stderr}");
    assert!(
        stderr.contains(name),
        "the refusal must name the path it is about: {stderr}"
    );
    assert!(!target.exists(), "nothing may be written");

    // And the other direction: a manifest that names itself as an entry.
    let tree = dir.path().join("packable");
    fs::create_dir(&tree).expect("tree");
    let manifest = serde_json::json!({
        "schema": 1,
        "encryption": rpf_core::Version::Rpf7.open(),
        "directories": [],
        "entries": [{
            "path": name,
            "class": "binary",
            "storage": "stored",
            "encryption": 0,
        }],
    });
    fs::write(
        tree.join(name),
        serde_json::to_vec_pretty(&manifest).expect("json"),
    )
    .expect("writable");

    let packed = dir.path().join("packed.rpf");
    let (code, stderr) = run_err(&[
        "pack",
        &tree.display().to_string(),
        &packed.display().to_string(),
    ]);
    assert_eq!(
        code, 6,
        "one file read as two things is a refusal: {stderr}"
    );
    assert!(!packed.exists(), "nothing may be produced from it");
}

#[test]
fn pack_refuses_a_manifest_name_that_climbs_out_of_the_tree_with_a_backslash() {
    // R10.3's refusal split on the separator: `name::check` divided on `/`
    // only, so `..\escaped.txt` was one legal component and `pack` exited 0.
    // On Windows `Path::join` reads it as two and the tree is escaped at
    // whatever depth the name asks for.
    let dir = tempfile::tempdir().expect("temp dir");
    let tree = dir.path().join("tree");
    fs::create_dir(&tree).expect("tree");
    fs::write(dir.path().join("escaped.txt"), b"above the tree").expect("writable");

    let manifest = serde_json::json!({
        "schema": 1,
        "encryption": rpf_core::Version::Rpf7.open(),
        "directories": [],
        "entries": [{
            "path": "..\\escaped.txt",
            "class": "binary",
            "storage": "stored",
            "encryption": 0,
        }],
    });
    fs::write(
        tree.join(rpf_core::MANIFEST_NAME),
        serde_json::to_vec_pretty(&manifest).expect("json"),
    )
    .expect("writable");

    let archive = dir.path().join("packed.rpf");
    let (code, stderr) = run_err(&[
        "pack",
        &tree.display().to_string(),
        &archive.display().to_string(),
    ]);
    assert_eq!(code, 6, "a hostile name is a refusal: {stderr}");
    assert!(
        stderr.contains("escaped.txt"),
        "the refusal must name the path it is about: {stderr}"
    );
    assert!(!archive.exists(), "nothing may be produced from it");
}

#[test]
fn an_archive_a_host_cannot_hold_is_still_repairable() {
    // The cost DR-013 recorded, and its second amendment removes: an archive
    // holding `aux.ytd` could be read and could not be rebuilt, so `put` on any
    // other entry in it printed `rebuilding` and then refused. The host rules
    // are `extract`'s and `pack`'s; the tree rules are everyone's.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    archive_named(&archive, &["b.txt", "zzz.ytd"], "zzz.ytd", "aux.ytd");

    let replacement = dir.path().join("replacement.bin");
    fs::write(&replacement, vec![9_u8; 4_000]).expect("writable");
    let (code, stderr) = run_err(&[
        "put",
        &archive.display().to_string(),
        "b.txt",
        &replacement.display().to_string(),
    ]);
    assert_eq!(
        code, 0,
        "a rebuild must not be refused a host name: {stderr}"
    );

    let mut file = fs::File::open(&archive).expect("archive opens");
    let rebuilt = rpf_core::Archive::open(&mut file).expect("the rebuild parses");
    let index = rebuilt
        .find("aux.ytd")
        .expect("the name survived the rebuild");
    assert_eq!(
        rebuilt.extract(&mut file, index).expect("payload"),
        b"payload",
        "the entry no host can hold came through untouched"
    );

    // And it is still not extractable, which is the half that stands.
    let target = dir.path().join("tree");
    let (code, stderr) = run_err(&[
        "extract",
        &archive.display().to_string(),
        &target.display().to_string(),
    ]);
    assert_eq!(code, 6, "a device name is a refusal: {stderr}");
    assert!(
        stderr.contains("aux.ytd"),
        "the refusal must name the path it is about: {stderr}"
    );
    assert!(!target.exists(), "nothing may be written");
}

#[test]
fn extract_refuses_two_siblings_it_cannot_tell_apart() {
    // Measured on macOS before this was refused: `extract` reported "2 files",
    // wrote one — holding the second entry's bytes — and `pack` of that tree
    // then failed one command later. On Linux the same archive round-tripped,
    // so one archive was two trees. R10.4.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    archive_named(&archive, &["A.txt", "b.txt"], "b.txt", "a.txt");
    let target = dir.path().join("tree");

    let (code, stderr) = run_err(&[
        "extract",
        &archive.display().to_string(),
        &target.display().to_string(),
    ]);
    assert_eq!(code, 6, "one name for two entries is a refusal: {stderr}");
    for named in ["a.txt", "A.txt"] {
        assert!(
            stderr.contains(named),
            "the refusal must name both: {stderr}"
        );
    }
    assert!(!target.exists(), "nothing may be written");

    // Only turning it into a tree is refused. The archive is not malformed and
    // listing it is how a caller finds out which two names collided.
    assert_eq!(run(&["ls", &archive.display().to_string()]).0, 0, "ls");
}

#[test]
fn put_refuses_a_name_two_entries_answer_to() {
    // Reproduced before this was refused: `rpf put … a.txt` against an archive
    // holding `A.txt` beside `a.txt` reported `patched 8 bytes in place`, exit
    // 0, and `A.txt` is what changed. `Archive::check_names` is reached only by
    // whoever turns the archive into a tree; the patch-in-place path resolves
    // through `locate`, which folded case and took the first match.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    archive_named(&archive, &["A.txt", "b.txt"], "b.txt", "a.txt");
    let before = fs::read(&archive).expect("readable");

    let replacement = dir.path().join("replacement.txt");
    fs::write(&replacement, b"changed").expect("writable");

    let (code, stderr) = run_err(&[
        "put",
        &archive.display().to_string(),
        "a.txt",
        &replacement.display().to_string(),
    ]);
    assert_eq!(code, 6, "a name with two answers is a refusal: {stderr}");
    for named in ["a.txt", "A.txt"] {
        assert!(
            stderr.contains(named),
            "the refusal must name both: {stderr}"
        );
    }
    assert_eq!(
        fs::read(&archive).expect("readable"),
        before,
        "a refused put must leave every entry as it was"
    );

    // Only the resolution is refused. Listing is still how a caller finds out
    // which two names collided.
    assert_eq!(run(&["ls", &archive.display().to_string()]).0, 0, "ls");
}

#[test]
fn a_bare_archive_name_inside_an_installation_is_still_refused() {
    // `Path::new("dlc.rpf").parent()` is the empty path, so the guard ascended
    // exactly once and stopped: it never saw the installation it was standing
    // in, and it fails open. R10.10.
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().join("Grand Theft Auto V");
    let deep = root.join("mods/update/x64/dlcpacks");
    fs::create_dir_all(&deep).expect("directories");
    fs::write(root.join("GTA5.exe"), b"not really").expect("writable");
    make_archive(&deep.join("dlc.rpf"));

    let replacement = dir.path().join("replacement.txt");
    fs::write(&replacement, b"replaced").expect("writable");
    let replacement = replacement.display().to_string();

    let (code, stderr) = run_err_in(
        &deep,
        &["put", "dlc.rpf", "data/greeting.txt", &replacement],
    );
    assert_eq!(code, 6, "a bare name is the same archive: {stderr}");
    assert!(
        stderr.contains("Grand Theft Auto V"),
        "the refusal must name the installation: {stderr}"
    );
}

#[test]
fn a_path_spelled_with_backslashes_is_not_found_and_the_message_respells_it() {
    // DR-016: `\` is an ordinary character in an entry name, so this addresses
    // an entry the archive does not hold rather than `data/greeting.txt`. The
    // not-found is where a caller who spells paths the Windows way finds out.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive = archive.display().to_string();

    let (code, stderr) = run_err(&["cat", &archive, "data\\greeting.txt"]);
    assert_eq!(code, 3, "not an entry of this archive: {stderr}");
    assert!(
        stderr.contains("data/greeting.txt"),
        "the message must respell the path with the separator: {stderr}"
    );

    // And the spelling it points at is the one that resolves.
    assert_eq!(run(&["cat", &archive, "data/greeting.txt"]).0, 0);
}

#[test]
fn a_not_found_holding_no_backslash_is_reported_as_it_was() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);

    let (code, stderr) = run_err(&["cat", &archive.display().to_string(), "data/absent.txt"]);
    assert_eq!(code, 3, "{stderr}");
    assert!(
        !stderr.contains("separates with"),
        "there is nothing to say about a separator here: {stderr}"
    );
}

#[test]
fn info_summarises_a_nested_archive() {
    // R6.11. `ls`, `cat`, `put` and `verify` all take an in-archive path and
    // descend through nesting; `info` took the archive alone, so the entry
    // count, size and slack of `x64/vehicles.rpf` could not be asked for at
    // all. R6's exit criterion is an agent working inside a nested archive
    // using only documented output, and this was the one reporting command
    // that could not address one.
    let dir = tempfile::tempdir().expect("temp dir");
    let (outer_path, inner_path) = make_nested(dir.path());
    let outer = outer_path.display().to_string();

    // What the inner archive says about itself, read as a file of its own, is
    // what `info` through the nesting has to say about it.
    let (code, alone) = run(&["--json", "info", &inner_path.display().to_string()]);
    assert_eq!(code, 0);
    let alone: serde_json::Value = serde_json::from_slice(&alone).expect("json");

    let (code, nested) = run(&["--json", "info", &outer, "x64/inner.rpf"]);
    assert_eq!(code, 0);
    let nested: serde_json::Value = serde_json::from_slice(&nested).expect("json");

    for field in [
        "entries",
        "directories",
        "binary_files",
        "resource_files",
        "len",
    ] {
        assert_eq!(nested[field], alone[field], "{field}: {nested}");
    }
    assert_eq!(
        nested["path"],
        serde_json::json!(outer),
        "the file that was opened"
    );
    assert_eq!(
        nested["inside"],
        serde_json::json!("x64/inner.rpf"),
        "the archive within it"
    );

    // And the archive itself is still the default.
    let (code, whole) = run(&["--json", "info", &outer]);
    assert_eq!(code, 0);
    let whole: serde_json::Value = serde_json::from_slice(&whole).expect("json");
    assert_eq!(whole["inside"], serde_json::json!(""), "{whole}");
    assert_ne!(whole["len"], nested["len"], "the outer is not the inner");
}

#[test]
fn info_of_something_that_is_not_an_archive_is_refused_rather_than_summarised() {
    // A directory inside the archive is a well-formed request for something
    // `info` cannot answer: it summarises an archive, and a directory is not
    // one. The caller has to change what it asked for, which DR-010 puts under
    // exit 6.
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("test.rpf");
    make_archive(&path);
    let archive = path.display().to_string();

    let (code, message) = run_err(&["info", &archive, "data"]);
    assert_eq!(code, 6, "{message}");
    assert!(message.contains("directory"), "{message}");
    // Naming the path the caller gave, not the index the archive happens to
    // hold it at: an entry index is a fact about this archive's table and not
    // something a caller asked with or can act on.
    assert!(
        message.contains("\"data\""),
        "the refusal names the path: {message}",
    );
    assert!(
        !message.contains("entry 1"),
        "the refusal should not name an entry index: {message}",
    );

    // And through nesting, where the two spellings genuinely differ: the entry
    // is `data` inside `x64/inner.rpf`, and what the caller typed is the whole
    // path. Naming the entry's own path would send the caller looking in the
    // wrong archive.
    let (outer_path, _) = make_nested(dir.path());
    let outer = outer_path.display().to_string();
    let (code, message) = run_err(&["info", &outer, "x64/inner.rpf/data"]);
    assert_eq!(code, 6, "{message}");
    assert!(
        message.contains("\"x64/inner.rpf/data\""),
        "the refusal names the whole path: {message}",
    );
}

#[test]
fn a_path_that_continues_past_the_archive_is_refused_rather_than_blamed_on_the_disk() {
    // R6.11. `rpf info outer.rpf/x64/inner.rpf` is an in-archive path spelled
    // as a filesystem one. The open failed with "Not a directory (os error
    // 20)" and exit 7 — an i/o failure, which tells an agent consumer that the
    // disk misbehaved and retrying is reasonable. Nothing on the disk failed;
    // the request named something the tool does not accept, and DR-010 puts
    // that under exit 6.
    let dir = tempfile::tempdir().expect("temp dir");
    let (outer_path, _) = make_nested(dir.path());
    let through = outer_path.join("x64").join("inner.rpf");

    let (code, message) = run_err(&["info", &through.display().to_string()]);
    assert_eq!(code, 6, "{message}");
    assert!(
        message.contains(&outer_path.display().to_string()),
        "the refusal names the archive the path runs past: {message}"
    );

    // Every command that opens an archive says the same thing about it.
    let (code, message) = run_err(&["ls", &through.display().to_string()]);
    assert_eq!(code, 6, "{message}");

    // And a path that simply is not there is still an ordinary i/o failure.
    let absent = dir.path().join("absent.rpf").display().to_string();
    let (code, message) = run_err(&["info", &absent]);
    assert_eq!(code, 7, "{message}");
}

#[test]
fn an_extraction_that_would_write_over_the_archive_it_is_reading_is_refused() {
    // `rpf extract test.rpf .` where the archive holds an entry of its own
    // name: `write_file` truncated and rewrote the file the extraction was
    // reading from, and every remaining entry then came out of a file that had
    // been replaced part-way through. Refused before anything is created, so a
    // refusal leaves nothing behind — a tree cannot be renamed into place the
    // way a rebuilt archive can. DR-009's shape, and `pack` already had it.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    let files = [FileSpec {
        path: "test.rpf".to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Stored,
            encryption: 0,
        },
    }];
    let mut out = fs::File::create(&archive).expect("creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_| {
            Ok(Cursor::new(
                b"an entry that shares the archive's own name".to_vec(),
            ))
        },
        &mut Unwatched,
    )
    .expect("builds");
    drop(out);
    let before = fs::read(&archive).expect("readable");

    let (code, message) = run_err(&[
        "extract",
        &archive.display().to_string(),
        &dir.path().display().to_string(),
    ]);
    assert_eq!(code, 6, "{message}");
    assert!(message.contains("test.rpf"), "{message}");
    assert_eq!(
        fs::read(&archive).expect("readable"),
        before,
        "the archive being read was written over"
    );
    assert!(
        !dir.path().join(".rpf-manifest.json").exists(),
        "a refused extraction left part of a tree behind"
    );
}

// Key material — R2.7. Everything below asserts on offsets, lengths, digests
// and paths. Nothing asserts on a key, and one test asserts that nothing the
// binary writes could be one. DR-006, DR-020.

/// A source that carries none of the anchored values.
fn carries_nothing(at: &Path) {
    fs::write(at, vec![0_u8; 1 << 16]).expect("writable");
}

/// Reports a skip, naming the test and what it would have read.
///
/// `RPF_REQUIRE_GAME_EXE` turns the skip into a failure, the way
/// `RPF_REQUIRE_CORPUS` does for archives: a green suite and a suite that ran
/// must not be different claims.
fn skip<T>(test: &str, reason: &str) -> Option<T> {
    assert!(
        std::env::var_os("RPF_REQUIRE_GAME_EXE").is_none(),
        "RPF_REQUIRE_GAME_EXE is set, but {test} would have skipped: {reason}",
    );
    eprintln!("SKIP {test}: {reason}");
    None
}

/// One of the game executables, or `None` with a reason on standard error.
fn executable(test: &str, name: &str) -> Option<std::path::PathBuf> {
    let Some(root) = std::env::var_os("RPF_GAME_EXE") else {
        return skip(test, "RPF_GAME_EXE is not set");
    };
    let path = Path::new(&root).join(name);
    if path.is_file() {
        Some(path)
    } else {
        skip(test, &format!("{} is not a file", path.display()))
    }
}

/// Runs the binary, returning its exit code and everything it wrote to either
/// stream.
fn run_output(args: &[&str]) -> (i32, Vec<u8>) {
    let output = Command::new(RPF).args(args).output().expect("binary runs");
    let mut both = output.stdout;
    both.extend_from_slice(&output.stderr);
    (output.status.code().unwrap_or(-1), both)
}

/// Whether `haystack` holds `needle` anywhere in it.
fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// `bytes` as lower-case hexadecimal.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Whether the permission bits on a directory are enforced for this process.
///
/// They are not for `root`, and a test that reads a refusal out of them would
/// pass there for the wrong reason.
#[cfg(unix)]
fn writes_are_refused(directory: &Path) -> bool {
    let probe = directory.join("probe");
    if fs::write(&probe, b"").is_ok() {
        let _ = fs::remove_file(&probe);
        return false;
    }
    true
}

#[test]
fn an_executable_carrying_nothing_is_this_build_s_problem_rather_than_the_caller_s() {
    // A file that is intact and holds none of the anchored values is the same
    // shape as an RPF version with no codec here: nothing the caller supplies
    // opens it. DR-010's fifth category, exit 9. The counts are in the message
    // because "1 of 2" and "0 of 2" are different situations to be in.
    let dir = tempfile::tempdir().expect("temp dir");
    let source = dir.path().join("not-a-game.exe");
    carries_nothing(&source);
    let cache = dir.path().join("cache");

    let (code, message) = run_err(&[
        "keys",
        "extract",
        &source.display().to_string(),
        "--cache-dir",
        &cache.display().to_string(),
    ]);
    assert_eq!(code, 9, "{message}");
    assert!(message.contains("0 of 2"), "{message}");
    assert!(message.contains("AES key"), "{message}");
    assert!(
        !cache.exists(),
        "a failed extraction created a cache directory; R2.6 says a command \
         that never got a key leaves nothing behind"
    );
}

#[test]
fn an_executable_that_is_not_there_is_an_i_o_failure_naming_it() {
    // The same answer `rpf info` gives an absent archive: a filesystem path
    // that leads nowhere is the source failing, and exit 3 is reserved for a
    // path that is not in an archive.
    let dir = tempfile::tempdir().expect("temp dir");
    let absent = dir.path().join("GTA5.exe").display().to_string();

    let (code, message) = run_err(&["keys", "extract", &absent]);
    assert_eq!(code, 7, "{message}");
    assert!(message.contains(&absent), "{message}");
}

#[test]
fn the_cache_command_says_where_the_material_is_kept_and_how_much_is_there() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cache = dir.path().join("cache");
    let at = cache.display().to_string();

    // A cache that was never written is empty rather than missing: nothing on
    // this machine has needed a key yet, which is not a failure.
    let (code, out) = run(&["--json", "keys", "cache", "--cache-dir", &at]);
    assert_eq!(code, 0);
    let reported: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(reported["cache"], serde_json::json!(at), "{reported}");
    assert_eq!(reported["entries"], serde_json::json!(0), "{reported}");
    assert!(!cache.exists(), "asking where the cache is created one");

    fs::create_dir_all(&cache).expect("creatable");
    fs::write(cache.join(format!("{}.keys", "a".repeat(64))), b"x").expect("writable");
    fs::write(cache.join(format!("{}.keys", "b".repeat(64))), b"y").expect("writable");

    let (code, out) = run(&["--json", "keys", "cache", "--cache-dir", &at]);
    assert_eq!(code, 0);
    let reported: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(reported["entries"], serde_json::json!(2), "{reported}");
}

#[test]
fn invalidate_removes_every_entry_at_once_and_says_how_many() {
    // Whole rather than per entry, and DR-020 says why: re-extraction already
    // replaces the entry for one executable, so the only thing a per-entry
    // removal could do that extraction does not is leave the other entries'
    // key material on the machine.
    let dir = tempfile::tempdir().expect("temp dir");
    let cache = dir.path().join("cache");
    fs::create_dir_all(cache.join("held")).expect("creatable");
    for name in [
        &format!("{}.keys", "a".repeat(64)),
        &format!("{}.keys", "b".repeat(64)),
        &format!("{}.keys", "c".repeat(64)),
    ] {
        fs::write(cache.join(name), b"x").expect("writable");
    }
    let at = cache.display().to_string();

    let (code, out) = run(&["--json", "keys", "invalidate", "--cache-dir", &at]);
    assert_eq!(code, 0);
    let reported: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(reported["removed"], serde_json::json!(3), "{reported}");
    assert_eq!(reported["cache"], serde_json::json!(at), "{reported}");
    assert!(
        cache.join("held").is_dir(),
        "a directory inside the cache was removed; only its entries are ours"
    );

    // Idempotent: invalidating a cache with nothing in it is a success, so
    // automation does not have to ask first.
    let (code, out) = run(&["--json", "keys", "invalidate", "--cache-dir", &at]);
    assert_eq!(code, 0);
    let reported: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(reported["removed"], serde_json::json!(0), "{reported}");
}

#[test]
#[cfg(unix)]
fn a_cache_that_cannot_be_written_is_an_i_o_failure_naming_the_directory() {
    // The sink failed and nobody's input is in question, which is exactly what
    // DR-010 narrows exit 7 to. The directory is named because fixing its
    // permissions is what the caller has to do.
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().expect("temp dir");
    let cache = dir.path().join("cache");
    fs::create_dir_all(&cache).expect("creatable");
    fs::write(cache.join(format!("{}.keys", "a".repeat(64))), b"x").expect("writable");
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o500)).expect("chmod");

    let refused = writes_are_refused(&cache);
    let at = cache.display().to_string();
    let (code, message) = run_err(&["keys", "invalidate", "--cache-dir", &at]);
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).expect("chmod");

    if !refused {
        eprintln!(
            "SKIP a_cache_that_cannot_be_written_is_an_i_o_failure_naming_the_directory: \
             this process writes into a directory it has no write permission on"
        );
        return;
    }
    assert_eq!(code, 7, "{message}");
    assert!(message.contains(&at), "{message}");
}

#[test]
#[cfg_attr(no_executables, ignore = "RPF_GAME_EXE is not set")]
fn a_game_executable_reports_offsets_and_never_a_key() {
    // The only test here that proves the surface against a real executable,
    // and the only one that can check DR-006 end to end: the key is read in
    // this process, and what the binary printed is searched for it in every
    // encoding an output path could have used. Nothing is written anywhere the
    // repository can reach, and no assertion names a byte of it.
    let test = "a_game_executable_reports_offsets_and_never_a_key";
    let Some(path) = executable(test, "GTA5.exe") else {
        return;
    };
    let mut file = fs::File::open(&path).expect("the executable is readable");
    let keys = rpf_core::keys::Keys::extract(&mut file, &mut rpf_core::Unwatched)
        .expect("carries the material");

    let dir = tempfile::tempdir().expect("temp dir");
    let at = dir.path().join("cache").display().to_string();
    let source = path.display().to_string();
    let (code, out) = run(&["--json", "keys", "extract", &source, "--cache-dir", &at]);
    assert_eq!(code, 0);
    let reported: serde_json::Value = serde_json::from_slice(&out).expect("json");

    assert_eq!(reported["executable"], serde_json::json!(source));
    assert_eq!(reported["from"], serde_json::json!("executable"));
    assert_eq!(reported["cache"], serde_json::json!(at));
    assert_eq!(
        reported["values"][0]["at"],
        serde_json::json!(keys.aes_key_offset()),
        "{reported}"
    );
    assert_eq!(
        reported["values"][1]["at"],
        serde_json::json!(keys.hash_lut_offset()),
        "{reported}"
    );
    assert_eq!(
        reported["sha256"].as_str().map(str::len),
        Some(64),
        "{reported}"
    );

    // The whole point. Raw, hexadecimal in either case, and base64, because
    // those are the ways bytes reach a JSON document.
    let (_, printed) = run_output(&["--json", "keys", "extract", &source, "--cache-dir", &at]);
    for value in [keys.aes_key().as_slice(), keys.hash_lut().as_slice()] {
        assert!(!holds(&printed, value), "key material was printed raw");
        assert!(
            !holds(&printed, hex(value).as_bytes()),
            "key material was printed as hexadecimal"
        );
        assert!(
            !holds(&printed, hex(value).to_uppercase().as_bytes()),
            "key material was printed as hexadecimal"
        );
        assert!(
            !holds(&printed, BASE64.encode(value).as_bytes()),
            "key material was printed as base64"
        );
    }

    // The second run is the cache doing its job, and it says which it was.
    let (code, out) = run(&["--json", "keys", "extract", &source, "--cache-dir", &at]);
    assert_eq!(code, 0);
    let cached: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(cached["from"], serde_json::json!("cache"), "{cached}");
    assert_eq!(cached["values"], reported["values"], "{cached}");

    let (code, out) = run(&["--json", "keys", "cache", "--cache-dir", &at]);
    assert_eq!(code, 0);
    let state: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(state["entries"], serde_json::json!(1), "{state}");

    let (code, out) = run(&["--json", "keys", "invalidate", "--cache-dir", &at]);
    assert_eq!(code, 0);
    let emptied: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(emptied["removed"], serde_json::json!(1), "{emptied}");
}

#[test]
#[cfg(unix)]
#[cfg_attr(no_executables, ignore = "RPF_GAME_EXE is not set")]
fn a_cache_directory_that_cannot_be_created_fails_the_extraction_that_needed_it() {
    // Four situations, and this is the third: the material was found and the
    // sink failed. Reported rather than swallowed, because a silent exit 0
    // leaves every later command rescanning and nobody told why. Exit 7.
    use std::os::unix::fs::PermissionsExt as _;

    let test = "a_cache_directory_that_cannot_be_created_fails_the_extraction_that_needed_it";
    let Some(path) = executable(test, "GTA5.exe") else {
        return;
    };
    let dir = tempfile::tempdir().expect("temp dir");
    let closed = dir.path().join("closed");
    fs::create_dir_all(&closed).expect("creatable");
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o500)).expect("chmod");
    let refused = writes_are_refused(&closed);
    let at = closed.join("cache").display().to_string();

    let (code, message) = run_err(&[
        "keys",
        "extract",
        &path.display().to_string(),
        "--cache-dir",
        &at,
    ]);
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o700)).expect("chmod");

    if !refused {
        eprintln!("SKIP {test}: this process writes where it has no permission to");
        return;
    }
    assert_eq!(code, 7, "{message}");
    assert!(message.contains(&at), "{message}");
}

/// A second archive, sharing no path with [`make_archive`]'s.
///
/// So that a manifest of one names nothing in the other, which is the mistake a
/// caller who has two extracted trees on disk will make.
fn make_other_archive(at: &Path) {
    let files = vec![FileSpec {
        path: "elsewhere.bin".to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Stored,
            encryption: 0,
        },
    }];
    let mut out = fs::File::create(at).expect("archive is creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_| Ok(Cursor::new(vec![3_u8; 64])),
        &mut Unwatched,
    )
    .expect("archive builds");
}

/// The binary's `--json` answer to one reporting command.
fn cli_json(args: &[&str]) -> serde_json::Value {
    let (_, out) = run(&[&["--json"], args].concat());
    serde_json::from_slice(&out).expect("json on stdout")
}

#[test]
fn a_byte_changed_inside_a_stored_entry_is_caught_only_against_a_tree() {
    // The whole reason DR-023's checksum exists, from outside the library for
    // the first time. A stored entry declares no inflated length and carries no
    // deflate stream that ends, so nothing in the archive says what its bytes
    // should be and a `verify` given the archive alone reads it back clean.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let tree = dir.path().join("tree");
    let tree_str = tree.display().to_string();
    assert_eq!(run(&["extract", &archive_str, &tree_str]).0, 0, "extract");

    let (at, _, _) = spans(&archive, "stored.bin");
    let mut bytes = fs::read(&archive).expect("readable");
    let start = index_of(at);
    bytes[start] ^= 0xFF;
    fs::write(&archive, &bytes).expect("writable");

    assert_eq!(
        run(&["verify", &archive_str]).0,
        0,
        "the archive on its own says nothing about a stored entry's bytes",
    );

    let (code, out) = run(&["--json", "verify", &archive_str, "--against", &tree_str]);
    assert_eq!(code, 4, "the same archive against the tree it came from");
    let report: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(report["entries_checked"], serde_json::json!(2), "{report}");
    assert_eq!(report["contents_checked"], serde_json::json!(2), "{report}");
    assert_eq!(
        report["contents_recorded"],
        serde_json::json!(2),
        "{report}"
    );
    assert_eq!(report["against"], serde_json::json!(tree_str), "{report}");
    // One object per problem, the same shape the daemon answers: a reason
    // carries colons of its own — "entry 0: payload did not inflate" — so a
    // consumer cannot split "path: reason" back apart. DR-027.
    let problems = report["problems"].as_array().expect("an array");
    assert_eq!(problems.len(), 1, "{report}");
    assert_eq!(
        problems[0]["path"],
        serde_json::json!("stored.bin"),
        "{report}",
    );
    assert!(
        problems[0]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("digest")),
        "{report}",
    );
}

#[test]
fn a_verify_with_no_manifest_does_not_report_a_zero_as_a_pass() {
    // `contents_checked` is zero without a manifest, and a report that prints
    // the number without saying why reads as "nothing was wrong with the
    // contents" rather than "the contents were not looked at". DR-023.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let (code, out) = run(&["verify", &archive_str]);
    assert_eq!(code, 0);
    let plain = String::from_utf8_lossy(&out);
    assert!(
        plain.contains("contents not checked"),
        "the report was: {plain}",
    );
    assert!(
        !plain.contains("0 contents checked"),
        "a zero printed as though it were a result: {plain}",
    );

    let report = cli_json(&["verify", &archive_str]);
    assert_eq!(report["contents_checked"], serde_json::json!(0), "{report}");
    assert_eq!(
        report["contents_recorded"],
        serde_json::json!(0),
        "{report}"
    );
    assert_eq!(report["against"], serde_json::Value::Null, "{report}");
}

#[test]
fn a_tree_extracted_from_another_archive_is_refused_rather_than_checking_nothing() {
    // A manifest is joined to entries by path, so one describing a different
    // archive matches nothing and `Verified::against` reports no failure at all
    // — deliberately, because inventing one would be a confident lie about a
    // sound archive. Reporting nothing is the other half of the mistake, so the
    // frontend refuses the pairing instead: exit 6, which is the caller's to
    // fix, rather than exit 4, which would blame the archive.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let other = dir.path().join("other.rpf");
    make_other_archive(&other);

    let tree = dir.path().join("other-tree");
    let tree_str = tree.display().to_string();
    assert_eq!(
        run(&["extract", &other.display().to_string(), &tree_str]).0,
        0,
        "extract",
    );

    let (code, message) = run_err(&[
        "verify",
        &archive.display().to_string(),
        "--against",
        &tree_str,
    ]);
    assert_eq!(code, 6, "{message}");
    assert!(message.contains(&tree_str), "{message}");
    assert!(
        message.contains("nothing was checked"),
        "the refusal was: {message}",
    );
}

#[test]
fn a_tree_with_no_manifest_in_it_is_reported_as_the_missing_file_it_is() {
    // Not the archive's fault, and not a checksum mismatch: the caller named a
    // tree that has no manifest in it, and `pack` answers the same way for the
    // same file.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let empty = dir.path().join("empty-tree");
    fs::create_dir_all(&empty).expect("creatable");

    let (code, message) = run_err(&[
        "verify",
        &archive.display().to_string(),
        "--against",
        &empty.display().to_string(),
    ]);
    assert_eq!(code, 7, "{message}");
    assert!(
        message.contains(rpf_core::MANIFEST_NAME),
        "the failure names what was looked for: {message}",
    );
}

#[test]
fn a_tree_whose_manifest_records_no_checksum_is_refused_rather_than_passed() {
    // The other way a manifest can check nothing, and it is not the same
    // mistake: every schema-1 and schema-2 manifest recorded none, which
    // `Manifest::from_json` reads rather than refuses (DR-023's migration
    // rule). A caller who asked for a contents check and got a tree that
    // cannot answer one is told so, rather than told that nothing was wrong.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let tree = dir.path().join("tree");
    let tree_str = tree.display().to_string();
    assert_eq!(
        run(&["extract", &archive.display().to_string(), &tree_str]).0,
        0,
        "extract",
    );

    let manifest_path = tree.join(rpf_core::MANIFEST_NAME);
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest")).expect("json");
    manifest["schema"] = serde_json::json!(2);
    for entry in manifest["entries"].as_array_mut().expect("entries") {
        entry.as_object_mut().expect("an object").remove("checksum");
    }
    fs::write(&manifest_path, manifest.to_string()).expect("writable");

    let (code, message) = run_err(&[
        "verify",
        &archive.display().to_string(),
        "--against",
        &tree_str,
    ]);
    assert_eq!(code, 6, "{message}");
    assert!(
        message.contains("records no checksum"),
        "the refusal was: {message}",
    );
    assert!(message.contains("nothing was checked"), "{message}");
}

// --- R4.10: adding, deleting and renaming an entry --------------------------

/// Every path an archive holds, as `ls -R` reports them.
fn listing(archive: &Path) -> Vec<String> {
    let (code, out) = run(&["--json", "ls", &archive.display().to_string(), "", "-R"]);
    assert_eq!(code, 0, "ls -R");
    let rows: serde_json::Value = serde_json::from_slice(&out).expect("json");
    rows.as_array()
        .expect("an array")
        .iter()
        .map(|row| row["path"].as_str().expect("path").to_owned())
        .collect()
}

#[test]
fn put_creates_an_entry_when_it_is_asked_to() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let source = dir.path().join("added.txt");
    fs::write(&source, b"brand new").expect("writable");
    let source = source.display().to_string();

    // Without --create it is still not found, which is exit 3.
    let (code, message) = run_err(&["put", &archive_str, "data/added.txt", &source]);
    assert_eq!(code, 3, "{message}");

    let (code, out) = run(&[
        "--json",
        "put",
        &archive_str,
        "data/added.txt",
        &source,
        "--create",
    ]);
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&out));
    let report: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(report["method"], serde_json::json!("rebuild"), "{report}");

    assert!(
        listing(&archive).contains(&"data/added.txt".to_owned()),
        "{:?}",
        listing(&archive),
    );
    let (code, bytes) = run(&["cat", &archive_str, "data/added.txt"]);
    assert_eq!(code, 0);
    assert_eq!(bytes, b"brand new".to_vec());
    assert_eq!(run(&["verify", &archive_str]).0, 0, "verify");
}

#[test]
fn rm_removes_an_entry_and_refuses_a_directory_that_holds_something() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let (code, message) = run_err(&["rm", &archive_str, "data"]);
    assert_eq!(code, 6, "{message}");
    assert!(message.contains("not empty"), "{message}");

    let (code, out) = run(&["--json", "rm", &archive_str, "data", "--recursive"]);
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&out));
    assert_eq!(listing(&archive), vec!["stored.bin".to_owned()]);
    assert_eq!(run(&["verify", &archive_str]).0, 0, "verify");
}

#[test]
fn mv_renames_an_entry_and_refuses_an_occupied_name() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    let contents = make_archive(&archive);
    let archive_str = archive.display().to_string();

    let (code, message) = run_err(&["mv", &archive_str, "stored.bin", "data/greeting.txt"]);
    assert_eq!(code, 6, "{message}");
    assert!(message.contains("already in the archive"), "{message}");

    assert_eq!(
        run(&["mv", &archive_str, "stored.bin", "data/moved.bin"]).0,
        0,
    );
    assert_eq!(
        listing(&archive),
        vec![
            "data".to_owned(),
            "data/greeting.txt".to_owned(),
            "data/moved.bin".to_owned(),
        ],
    );
    let (code, bytes) = run(&["cat", &archive_str, "data/moved.bin"]);
    assert_eq!(code, 0);
    assert_eq!(bytes, contents["stored.bin"]);
    assert_eq!(run(&["verify", &archive_str]).0, 0, "verify");
}

#[test]
fn mkdir_adds_a_directory_that_holds_nothing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    assert_eq!(run(&["mkdir", &archive_str, "empty"]).0, 0);
    assert!(
        listing(&archive).contains(&"empty".to_owned()),
        "{:?}",
        listing(&archive),
    );

    let (code, message) = run_err(&["mkdir", &archive_str, "empty"]);
    assert_eq!(code, 6, "{message}");
    assert!(message.contains("already in the archive"), "{message}");
}

#[test]
fn a_structural_dry_run_says_what_it_would_do_and_writes_nothing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();
    let before = fs::read(&archive).expect("readable");

    let (code, out) = run(&["--json", "rm", &archive_str, "stored.bin", "--dry-run"]);
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&out));
    let report: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(report["method"], serde_json::json!("rebuild"), "{report}");
    assert_eq!(report["path"], serde_json::json!("stored.bin"), "{report}");
    assert_eq!(
        report["structural"],
        serde_json::json!("removes an entry"),
        "{report}"
    );
    assert_eq!(report["dry_run"], serde_json::json!(true), "{report}");
    assert_eq!(fs::read(&archive).expect("readable"), before, "it wrote");
}

#[test]
fn every_structural_command_refuses_a_game_installation() {
    // The invariant `AGENTS.md` states, asked of each new verb rather than of
    // one of them: a tool refuses to write into a detected install unless it is
    // told to. Each is a separate entry point and each has to ask.
    let dir = tempfile::tempdir().expect("temp dir");
    let install = dir.path().join("Grand Theft Auto V");
    fs::create_dir_all(&install).expect("creatable");
    fs::write(install.join("GTA5.exe"), b"not really").expect("writable");
    let archive = install.join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    for args in [
        vec!["rm", archive_str.as_str(), "stored.bin"],
        vec!["mv", archive_str.as_str(), "stored.bin", "moved.bin"],
        vec!["mkdir", archive_str.as_str(), "made"],
    ] {
        let (code, message) = run_err(&args);
        assert_eq!(code, 6, "{args:?}: {message}");
        assert!(message.contains("--force"), "{args:?}: {message}");
    }
}

/// `extract` refuses a target that already holds something, and `--overwrite`
/// is the way through. DR-029.
#[test]
fn extract_refuses_a_target_that_already_holds_something() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let tree = dir.path().join("tree");
    let tree_str = tree.display().to_string();

    // A target that is not there yet is created, as it always was.
    assert_eq!(run(&["extract", &archive_str, &tree_str]).0, 0, "first");

    // A second extraction into the same tree is refused, and names what is
    // already there.
    let (code, message) = run_err(&["extract", &archive_str, &tree_str]);
    assert_eq!(code, 6, "{message}");
    assert!(message.contains("already holds"), "{message}");
    assert!(message.contains("--overwrite"), "{message}");

    // And `--overwrite` is the way through.
    assert_eq!(
        run(&["extract", &archive_str, &tree_str, "--overwrite"]).0,
        0,
        "--overwrite",
    );

    // An empty directory is not "already holding something".
    let empty = dir.path().join("empty");
    fs::create_dir(&empty).expect("creatable");
    assert_eq!(
        run(&["extract", &archive_str, &empty.display().to_string()]).0,
        0,
        "an empty directory",
    );
}

/// The refusal happens before anything is written, so a target that was refused
/// is exactly as it was.
#[test]
fn a_refused_extraction_writes_nothing_at_all() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);

    let tree = dir.path().join("tree");
    fs::create_dir(&tree).expect("creatable");
    fs::write(tree.join("mine.txt"), b"not the archive's").expect("writable");

    let (code, _) = run_err(&[
        "extract",
        &archive.display().to_string(),
        &tree.display().to_string(),
    ]);
    assert_eq!(code, 6);

    let mut left: Vec<String> = fs::read_dir(&tree)
        .expect("readable")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    left.sort();
    assert_eq!(left, vec!["mine.txt".to_owned()], "it wrote something");
}
