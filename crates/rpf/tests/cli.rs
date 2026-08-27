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
        &files,
        &[],
        |wanted| Ok(contents.get(wanted).cloned().unwrap_or_default()),
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
    let output = Command::new(RPF).args(args).output().expect("binary runs");
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
    rpf_core::build(&mut out, &files, &[], |_| Ok(inner.clone()), &mut Unwatched)
        .expect("outer builds");
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
    rpf_core::build(
        &mut out,
        &files,
        &["x64/empty".to_owned()],
        |_| Ok(b"hello".to_vec()),
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
        &[stored("big.bin"), stored("tail.bin")],
        &[],
        |wanted| {
            Ok(if wanted == "big.bin" {
                vec![0xAB_u8; 4096]
            } else {
                vec![7_u8; 300]
            })
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
    let row = index_of(row_at)..index_of(row_at.saturating_add(rpf_core::format::ENTRY_LEN));
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
        message.contains("1 of 2 entries did not read back"),
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
