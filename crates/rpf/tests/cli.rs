//! Command-line behaviour: exit codes, the round trip, and the write guard.
//! These build their own archive, so they need no corpus.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code; a panic is the reporting mechanism"
)]

use std::{
    collections::BTreeMap,
    fs,
    io::{Cursor, Write as _},
    path::Path,
    process::Command,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rpf_core::{FileKind, FileSpec, Storage, Unwatched};

mod common;

/// The binary under test, as cargo built it.
const RPF: &str = env!("CARGO_BIN_EXE_rpf");

/// How long a wait on a thread of this file's own may take before it is a failure.
#[cfg(unix)]
const PATIENCE: std::time::Duration = std::time::Duration::from_secs(60);

/// Joins `handle` within [`PATIENCE`], failing rather than waiting for ever on
/// the thread `what` names.
#[cfg(unix)]
#[track_caller]
fn join_within<T>(handle: std::thread::JoinHandle<T>, what: &str) -> T {
    let started = std::time::Instant::now();
    while !handle.is_finished() {
        assert!(
            started.elapsed() < PATIENCE,
            "waited {PATIENCE:?} for {what}, and it never finished"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    handle.join().expect("the thread did not panic")
}

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
        |wanted: &str| {
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
/// standard error. A child process, since `set_current_dir` would race.
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

/// One entry's raw payload, through `cat --out`, since a pipe takes text only.
fn payload_of(dir: &Path, archive: &str, inside: &str) -> Vec<u8> {
    let destination = dir.join("cat.out");
    let at = destination.display().to_string();
    let (code, said) = run(&["cat", "--out", &at, archive, inside]);
    assert_eq!(code, 0, "cat --out {inside}");
    let said = String::from_utf8_lossy(&said).into_owned();
    assert!(
        said.contains(&at),
        "the confirmation names the file: {said}"
    );
    fs::read(&destination).expect("the payload was written")
}

/// Where one entry's payload sits, how much room it has, and where its row is.
fn spans(at: &Path, inside: &str) -> (u64, u64, u64) {
    let mut file = fs::File::open(at).expect("archive opens");
    let archive =
        rpf_core::Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("archive parses");
    let index = archive.find(inside).expect("entry resolves");
    let (payload_at, _) = archive.payload_at(index).expect("payload span");
    (
        payload_at,
        archive.allocation(index).expect("allocation"),
        archive.row_at(index).expect("entry row"),
    )
}

/// Which byte positions differ, refusing a pair that is not the same length.
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

    assert_eq!(
        run(&["info", &archive, "stored.bin"]).0,
        6,
        "an ordinary entry named as a nested archive"
    );

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
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let (at, _, _) = spans(&archive, "data/greeting.txt");

    // 0xFF opens a deflate block with the reserved type, so the stream is refused.
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

    let (code, out) = run(&["cat", &archive, "data/greeting.txt"]);
    assert_eq!(code, 0);
    assert_eq!(
        out, contents["data/greeting.txt"],
        "cat returned something else"
    );

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

    let (_, out) = run(&["cat", &archive, "stored.bin"]);
    assert_eq!(out, contents["stored.bin"], "an unrelated entry changed");
    assert_eq!(run(&["verify", &archive]).0, 0, "verify");
}

/// An archive whose one resource is an opaque header that is not `RSC7`,
/// followed by the deflate stream.
fn make_rockstar_archive(at: &Path) -> Vec<u8> {
    // 24 bytes of 0xFF: not `RSC7`, and not the start of a deflate stream
    // either — the low three bits are BFINAL = 1 with the reserved BTYPE = 11.
    let mut resource = vec![0xFF_u8; 24];
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(&vec![0_u8; 512])
        .expect("the page deflates");
    resource.extend_from_slice(&encoder.finish().expect("the encoder finishes"));

    let files = vec![FileSpec {
        path: "art.ydr".to_owned(),
        kind: FileKind::Resource {
            declared: Some(rpf_core::ResourceFlags {
                system: 0xA800_0000,
                graphics: 0x2000_0000,
            }),
        },
    }];
    let payload = resource.clone();
    let mut out = fs::File::create(at).expect("archive is creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(payload.clone())),
        &mut Unwatched,
    )
    .expect("archive builds");
    resource
}

/// An archive holding one resource entry at `data/thing.ymt` whose contents are
/// a `Meta` behind an opaque prefix, with `flags` as the row's two flag words.
fn make_meta_archive(at: &Path, flags: rpf_core::ResourceFlags) {
    let payload = common::meta_resource();
    let mut out = fs::File::create(at).expect("archive is creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &[FileSpec {
            path: "data/thing.ymt".to_owned(),
            kind: FileKind::Resource {
                declared: Some(flags),
            },
        }],
        &[],
        |_: &str| Ok(Cursor::new(payload.clone())),
        &mut Unwatched,
    )
    .expect("archive builds");
}

#[test]
fn cat_put_round_trips_a_resource_that_carries_no_header() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    let resource = make_rockstar_archive(&archive);
    let archive = archive.display().to_string();

    let same = dir.path().join("art.ydr");
    let (code, err) = run_err(&[
        "cat",
        "--out",
        &same.display().to_string(),
        &archive,
        "art.ydr",
    ]);
    assert_eq!(code, 0, "cat --out: {err}");
    assert_eq!(
        fs::read(&same).expect("the payload was written"),
        resource,
        "cat wrote something else"
    );

    let (code, err) = run_err(&["put", &archive, "art.ydr", &same.display().to_string()]);
    assert_eq!(code, 0, "writing it back was refused: {err}");

    assert_eq!(
        payload_of(dir.path(), &archive, "art.ydr"),
        resource,
        "the bytes did not survive the round trip"
    );
    // The flag words are the only record of the resource's length there is.
    assert_eq!(run(&["verify", &archive]).0, 0, "verify");
}

/// An archive holding one stored entry at `data/thing.ymt` holding `contents`.
fn make_metadata_archive(at: &Path, contents: &[u8]) {
    let payload = contents.to_vec();
    let mut out = fs::File::create(at).expect("archive is creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &[FileSpec {
            path: "data/thing.ymt".to_owned(),
            kind: FileKind::Binary {
                storage: Storage::Stored,
                encryption: 0,
            },
        }],
        &[],
        |_: &str| Ok(Cursor::new(payload.clone())),
        &mut Unwatched,
    )
    .expect("archive builds");
}

/// The five `"encoding"` values are spelled out rather than derived from
/// `Encoding::name`, so a rename cannot quietly change the wire contract.
#[test]
fn a_listing_spells_every_encoding_the_wire_contract_names() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    let payloads: [(&str, &[u8]); 5] = [
        ("xml.ymt", b"<CVehicleModelInfo />"),
        ("text.ymt", b"a plain line of text\n"),
        ("rbf.ymt", b"RBF0\x01\x02\x03\x04tokens"),
        ("pso.ymt", b"PSIN\x01\x02\x03\x04sect"),
        ("unknown.ymt", &[0x00_u8; 32]),
    ];
    let held: BTreeMap<String, Vec<u8>> = payloads
        .iter()
        .map(|(path, bytes)| ((*path).to_owned(), (*bytes).to_vec()))
        .collect();
    let mut out = fs::File::create(&archive).expect("archive is creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &payloads
            .iter()
            .map(|(path, _)| FileSpec {
                path: (*path).to_owned(),
                kind: FileKind::Binary {
                    storage: Storage::Stored,
                    encryption: 0,
                },
            })
            .collect::<Vec<_>>(),
        &[],
        |path: &str| Ok(Cursor::new(held[path].clone())),
        &mut Unwatched,
    )
    .expect("archive builds");

    let (code, listed) = run(&["--json", "ls", &archive.display().to_string(), "", "-R"]);
    assert_eq!(code, 0);
    let rows: serde_json::Value = serde_json::from_slice(&listed).expect("an array");
    let row = |path: &str| {
        rows.as_array()
            .expect("an array")
            .iter()
            .find(|row| row["path"] == serde_json::json!(path))
            .unwrap_or_else(|| panic!("{path} is not in {rows}"))
            .clone()
    };
    for (path, spelt) in [
        ("xml.ymt", serde_json::json!("xml")),
        ("text.ymt", serde_json::json!("text")),
        ("rbf.ymt", serde_json::json!("rbf")),
        ("pso.ymt", serde_json::json!("pso")),
        ("unknown.ymt", serde_json::Value::Null),
    ] {
        assert_eq!(row(path)["encoding"], spelt, "{path} is spelled wrong");
    }
}

/// Both targets and both payloads: a guard written for one lets the other through.
#[test]
fn put_refuses_text_into_a_tokenised_metadata_entry() {
    let dir = tempfile::tempdir().expect("temp dir");
    for (held, holds) in [
        (&b"RBF0\x01\x02\x03\x04tokens"[..], "rbf"),
        (&b"PSIN\x01\x02\x03\x04sect"[..], "pso"),
    ] {
        for (offered, offers) in [
            (&b"<CVehicleModelInfo />"[..], "xml"),
            (&b"a plain line of text\n"[..], "text"),
        ] {
            // Every fixture fits in place, so the rebuild path needs `--rebuild`.
            for way in [&[][..], &["--rebuild"][..]] {
                let archive = dir.path().join("test.rpf");
                make_metadata_archive(&archive, held);
                let archive = archive.display().to_string();
                let donor = dir.path().join("donor");
                fs::write(&donor, offered).expect("writable");
                let donor = donor.display().to_string();

                let mut args = vec!["put", &archive, "data/thing.ymt", &donor];
                args.extend_from_slice(way);
                let (code, err) = run_err(&args);
                assert_eq!(code, 6, "expected the refusal DR-010 numbers 6: {err}");
                for wanted in ["data/thing.ymt", holds, offers, "--allow-encoding-change"] {
                    assert!(
                        err.contains(wanted),
                        "the refusal must name {wanted:?}: {err}"
                    );
                }

                assert_eq!(run(&["cat", &archive, "data/thing.ymt"]).1, held);

                let mut args = vec![
                    "put",
                    &archive,
                    "data/thing.ymt",
                    &donor,
                    "--allow-encoding-change",
                ];
                args.extend_from_slice(way);
                let (code, err) = run_err(&args);
                assert_eq!(code, 0, "the override was not honoured: {err}");
                assert_eq!(
                    run(&["cat", &archive, "data/thing.ymt"]).1,
                    offered,
                    "the override wrote something else"
                );
                assert_eq!(run(&["verify", &archive]).0, 0, "verify");
            }
        }
    }
}

#[test]
fn a_dry_run_reports_the_refusal_the_real_call_makes() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    let held = &b"RBF0\x01\x02\x03\x04tokens"[..];
    make_metadata_archive(&archive, held);
    let archive = archive.display().to_string();
    let donor = dir.path().join("donor");
    fs::write(&donor, b"<CVehicleModelInfo />").expect("writable");
    let donor = donor.display().to_string();

    for extra in [&["--dry-run"][..], &["--rebuild", "--dry-run"][..]] {
        let mut args = vec!["put", &archive, "data/thing.ymt", &donor];
        args.extend_from_slice(extra);
        let (code, err) = run_err(&args);
        assert_eq!(code, 6, "a dry run of {extra:?} reported success: {err}");
        assert!(err.contains("cannot take"), "{err}");
    }

    assert_eq!(run(&["cat", &archive, "data/thing.ymt"]).1, held);
    let (code, err) = run_err(&[
        "put",
        &archive,
        "data/thing.ymt",
        &donor,
        "--rebuild",
        "--dry-run",
        "--allow-encoding-change",
    ]);
    assert_eq!(code, 0, "the override was not honoured by a dry run: {err}");
    assert_eq!(
        run(&["cat", &archive, "data/thing.ymt"]).1,
        held,
        "a dry run wrote"
    );
}

/// `--force` is the game-install override, not an encoding one.
#[test]
fn force_does_not_let_text_into_a_tokenised_metadata_entry() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_metadata_archive(&archive, b"RBF0\x01\x02\x03\x04tokens");
    let archive = archive.display().to_string();
    let donor = dir.path().join("donor");
    fs::write(&donor, b"<CVehicleModelInfo />").expect("writable");

    let (code, err) = run_err(&[
        "put",
        &archive,
        "data/thing.ymt",
        &donor.display().to_string(),
        "--force",
    ]);
    assert_eq!(code, 6, "--force must not carry a second meaning: {err}");
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
/// deflated; returns the outer path and the inner one.
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
        |_: &str| Ok(Cursor::new(inner.clone())),
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

    let (code, out) = run(&["cat", &outer, "x64/inner.rpf/stored.bin"]);
    assert_eq!(code, 0);
    assert_eq!(out.len(), 300, "cat through nesting");
}

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

        // Through `Manifest` rather than as text, so the spelling is not encoded twice.
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

/// A tag this build can write forwards but has no material for is exit 5; one
/// whose algorithm it lacks is exit 9. Neither writes an archive.
#[test]
fn an_encrypted_tree_packs_for_material_or_refuses_for_the_algorithm() {
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
        "extract"
    );
    let at = tree.join(rpf_core::MANIFEST_NAME);
    // A cache of this test's own, so the answer does not depend on the machine.
    let cache = dir.path().join("keys").display().to_string();

    // Through `Manifest` rather than as text, so the spelling is not encoded twice.
    let extracted =
        rpf_core::Manifest::from_json(&fs::read_to_string(&at).expect("manifest readable"))
            .expect("manifest parses");

    for (tag, code, says) in [
        (0x0FFF_FFF9_u32, 5, "no key material available"),
        (0x0FEF_FFFF, 9, "derives this archive's forward transform"),
    ] {
        let mut manifest = extracted.clone();
        manifest.encryption = tag;
        fs::write(&at, manifest.to_json().expect("renders")).expect("manifest writable");

        let packed = dir.path().join(format!("packed-{tag:#x}.rpf"));
        let (answered, message) = run_err(&[
            "pack",
            &tree.display().to_string(),
            &packed.display().to_string(),
            "--cache-dir",
            &cache,
        ]);
        assert_eq!(answered, code, "{tag:#010x}: {message}");
        assert!(message.contains(says), "{tag:#010x}: {message}");
        assert!(
            !packed.exists(),
            "{tag:#010x}: a refused pack wrote an archive"
        );
    }

    // The plain tag still packs with the same empty cache.
    fs::write(&at, extracted.to_json().expect("renders")).expect("manifest writable");
    let packed = dir.path().join("packed-open.rpf");
    let (code, message) = run_err(&[
        "pack",
        &tree.display().to_string(),
        &packed.display().to_string(),
    ]);
    assert_eq!(code, 0, "{message}");
    assert_eq!(run(&["verify", &packed.display().to_string()]).0, 0);
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
fn a_binary_payload_into_a_pipe_is_refused_and_names_the_way_through() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("binary.rpf");
    make_rockstar_archive(&archive);
    let archive = archive.display().to_string();

    let (code, message) = run_err(&["cat", &archive, "art.ydr"]);
    assert_eq!(code, 6, "a pipe took bytes that are not text: {message}");
    assert!(message.contains("--out"), "no way through: {message}");
    assert!(
        run(&["cat", &archive, "art.ydr"]).1.is_empty(),
        "the payload went out anyway"
    );
}

#[test]
fn a_binary_payload_still_goes_to_a_redirected_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("redirect.rpf");
    let resource = make_rockstar_archive(&archive);
    let destination = dir.path().join("art.ydr");

    let status = Command::new(RPF)
        .args(["cat", &archive.display().to_string(), "art.ydr"])
        .stdout(fs::File::create(&destination).expect("creatable"))
        .status()
        .expect("binary runs");
    assert_eq!(status.code(), Some(0), "a redirect was refused");
    assert_eq!(
        fs::read(&destination).expect("readable"),
        resource,
        "the redirect did not receive the payload"
    );
}

#[test]
fn cat_out_writes_the_payload_and_reports_it_instead_of_printing_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("out.rpf");
    let resource = make_rockstar_archive(&archive);
    let archive = archive.display().to_string();
    let destination = dir.path().join("art.ydr");
    let at = destination.display().to_string();

    let (code, printed) = run(&["cat", "--out", &at, &archive, "art.ydr"]);
    assert_eq!(code, 0, "cat --out");
    assert!(
        !printed.contains(&0xFF),
        "the payload went out as well as into the file"
    );
    let said = String::from_utf8_lossy(&printed).into_owned();
    assert!(
        said.contains(&at) && said.contains(&resource.len().to_string()),
        "the confirmation says neither where nor how much: {said}"
    );
    assert_eq!(
        fs::read(&destination).expect("readable"),
        resource,
        "the file did not receive the payload"
    );

    let report = cli_json(&["cat", "--out", &at, &archive, "art.ydr"]);
    assert_eq!(report["path"], serde_json::json!(at));
    assert_eq!(report["len"], serde_json::json!(resource.len()));
}

#[test]
fn a_failure_under_json_is_an_object_on_standard_error() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("failing.rpf");
    make_archive(&archive);
    let archive = archive.display().to_string();

    let output = Command::new(RPF)
        .args(["--json", "cat", &archive, "data/absent.txt"])
        .output()
        .expect("binary runs");
    assert_eq!(output.status.code(), Some(3), "not found");
    assert!(
        output.stdout.is_empty(),
        "standard output carried a failure"
    );

    let object: serde_json::Value =
        serde_json::from_slice(&output.stderr).expect("one JSON object on standard error");
    assert_eq!(object["code"], serde_json::json!(3), "{object}");
    assert_eq!(object["data"]["reason"], serde_json::json!("NotFound"));
    assert!(
        object["message"]
            .as_str()
            .unwrap_or_default()
            .contains("data/absent.txt"),
        "the message says nothing about what failed: {object}"
    );

    let (code, message) = run_err(&["cat", &archive, "data/absent.txt"]);
    assert_eq!(code, 3);
    assert!(message.starts_with("rpf: "), "{message}");
}

#[test]
fn extract_then_pack_preserves_a_resources_page_flags() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    let resource = make_rockstar_archive(&archive);
    let archive = archive.display().to_string();

    let tree = dir.path().join("tree");
    let (code, err) = run_err(&["extract", &archive, &tree.display().to_string()]);
    assert_eq!(code, 0, "extract: {err}");

    // The manifest spells the flag words the way `docs/rpf-format.md` does.
    let manifest = fs::read_to_string(tree.join(rpf_core::MANIFEST_NAME)).expect("manifest");
    assert!(
        manifest.contains("\"system\": \"0xa8000000\""),
        "{manifest}"
    );
    assert!(
        manifest.contains("\"graphics\": \"0x20000000\""),
        "{manifest}"
    );

    let packed = dir.path().join("packed.rpf");
    let (code, err) = run_err(&[
        "pack",
        &tree.display().to_string(),
        &packed.display().to_string(),
    ]);
    assert_eq!(code, 0, "pack: {err}");
    assert_eq!(
        run(&["verify", &packed.display().to_string()]).0,
        0,
        "verify"
    );

    assert_eq!(
        payload_of(dir.path(), &packed.display().to_string(), "art.ydr"),
        resource,
        "the resource changed across extract and pack"
    );
    let mut file = fs::File::open(&packed).expect("the packed archive opens");
    let opened =
        rpf_core::Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("it parses");
    let index = opened.find("art.ydr").expect("resolves");
    let kind = opened.entry(index).expect("in range").kind;
    assert!(
        matches!(
            kind,
            rpf_core::EntryKind::Resource {
                system_flags: 0xA800_0000,
                graphics_flags: 0x2000_0000,
                ..
            }
        ),
        "the packed row declares something else: {kind:?}"
    );
}

#[test]
fn an_empty_directory_survives_extract_and_pack() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");

    // A directory holding no files cannot be inferred from any file path.
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
        |_: &str| Ok(Cursor::new(b"hello".to_vec())),
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

/// The text entry is deflated, so a classifier reading the payload where it
/// sits would answer `-`; neither entry is decided by its extension.
#[test]
fn a_listing_says_what_each_payload_announces_itself_to_be() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let at = archive.display().to_string();

    let (code, out) = run(&["--json", "ls", &at, "", "-R"]);
    assert_eq!(code, 0);
    let rows: serde_json::Value = serde_json::from_slice(&out).expect("--json ls answers an array");
    let row = |path: &str| {
        rows.as_array()
            .expect("an array")
            .iter()
            .find(|row| row["path"] == serde_json::json!(path))
            .unwrap_or_else(|| panic!("{path} is not in {rows}"))
            .clone()
    };
    assert_eq!(
        row("data/greeting.txt")["encoding"],
        serde_json::json!("text")
    );
    assert_eq!(row("stored.bin")["encoding"], serde_json::Value::Null);
    assert_eq!(row("data")["encoding"], serde_json::Value::Null);
    assert_eq!(
        row("data/greeting.txt")["kind"],
        serde_json::json!("binary"),
        "the kind a caller has always matched on is unchanged"
    );

    // The human listing carries `-` where the JSON carries null.
    let (code, listing) = run(&["ls", "-R", &at]);
    assert_eq!(code, 0);
    let listing = String::from_utf8_lossy(&listing);
    assert!(listing.contains("binary    text"), "listing was: {listing}");
    assert!(listing.contains("binary    -"), "listing was: {listing}");
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
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    // Read from the archive, not from the report it is checking.
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
    // Nothing else here tells a patch from a rebuild: a rebuild round-trips
    // just as well. `big.bin` is eight blocks replaced by eight bytes.
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
        |wanted: &str| {
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

    // `differences` refuses a resize; the loop catches a same-size rebuild.
    let after = fs::read(&archive).expect("readable");
    let payload = index_of(at)..index_of(at.saturating_add(allocation));
    let row = index_of(row_at)..index_of(row_at.saturating_add(rpf_core::Version::Rpf7.row_len()));
    for position in differences(&before, &after) {
        assert!(
            payload.contains(&position) || row.contains(&position),
            "byte {position} changed, and it is neither the payload nor its entry row",
        );
    }

    let (code, out) = run(&["cat", &archive, "big.bin"]);
    assert_eq!(code, 0);
    assert_eq!(out, b"replaced", "the patch did not take");
    let (_, out) = run(&["cat", &archive, "tail.bin"]);
    assert_eq!(out, vec![7_u8; 300], "an unrelated entry changed");
}

#[test]
fn a_dry_run_told_to_rebuild_says_so_and_writes_nothing() {
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

    // The same edit, not told to rebuild, would have been patched.
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
    // `needed` is the payload after the entry's storage rule, not the file's size.
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
    // Unreferenced is the archive's length less the header, the entry table,
    // the names blob and every payload; the sizes are stated, not derived.
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("test.rpf");
    make_archive(&path);

    let len = fs::metadata(&path).expect("stat").len();
    let mut file = fs::File::open(&path).expect("archive opens");
    let archive =
        rpf_core::Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("archive parses");
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
    // Both regions are non-zero, so they cannot agree by both being zero.
    assert!(entries > 0 && names > 0, "{entries} entries, {names} names");
}

/// Builds an archive of `names`, then rewrites `placeholder` in its names blob
/// to `actual` — equal lengths, so nothing else in the archive moves.
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
        |_: &str| Ok(Cursor::new(b"payload".to_vec())),
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

    // Only extraction is refused; listing is how a caller finds out what is wrong.
    assert_eq!(run(&["ls", &archive.display().to_string()]).0, 0);
}

#[test]
fn pack_refuses_a_manifest_name_that_climbs_out_of_the_tree() {
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
    // The refusal splits on both separators: on Windows `Path::join` reads
    // `..\escaped.txt` as two components and the tree is escaped.
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
    let rebuilt = rpf_core::Archive::open(&mut file, &rpf_core::Unlock::unkeyed())
        .expect("the rebuild parses");
    let index = rebuilt
        .find("aux.ytd")
        .expect("the name survived the rebuild");
    assert_eq!(
        rebuilt.extract(&mut file, index).expect("payload"),
        b"payload",
        "the entry no host can hold came through untouched"
    );

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
    // These names collide on macOS and not on Linux, so it is refused everywhere.
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

    // Only tree conversion is refused; listing is how a caller finds the collision.
    assert_eq!(run(&["ls", &archive.display().to_string()]).0, 0, "ls");
}

#[test]
fn put_refuses_a_name_two_entries_answer_to() {
    // The patch-in-place path resolves through `locate`, which folded case and
    // took the first match; `check_names` is reached only by tree conversion.
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

    // Only the resolution is refused; listing still finds the collision.
    assert_eq!(run(&["ls", &archive.display().to_string()]).0, 0, "ls");
}

#[test]
fn a_bare_archive_name_inside_an_installation_is_still_refused() {
    // `Path::new("dlc.rpf").parent()` is the empty path, so a guard that
    // ascends from the archive's path alone never sees the installation.
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
    // `\` is an ordinary character in an entry name, so this names no entry.
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
    let dir = tempfile::tempdir().expect("temp dir");
    let (outer_path, inner_path) = make_nested(dir.path());
    let outer = outer_path.display().to_string();

    // The inner archive read as a file of its own is the answer to check against.
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

    let (code, whole) = run(&["--json", "info", &outer]);
    assert_eq!(code, 0);
    let whole: serde_json::Value = serde_json::from_slice(&whole).expect("json");
    assert_eq!(whole["inside"], serde_json::json!(""), "{whole}");
    assert_ne!(whole["len"], nested["len"], "the outer is not the inner");
}

#[test]
fn info_of_something_that_is_not_an_archive_is_refused_rather_than_summarised() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("test.rpf");
    make_archive(&path);
    let archive = path.display().to_string();

    let (code, message) = run_err(&["info", &archive, "data"]);
    assert_eq!(code, 6, "{message}");
    assert!(message.contains("directory"), "{message}");
    // The path the caller gave, not the entry index, which they cannot act on.
    assert!(
        message.contains("\"data\""),
        "the refusal names the path: {message}",
    );
    assert!(
        !message.contains("entry 1"),
        "the refusal should not name an entry index: {message}",
    );

    // Through nesting the two spellings differ: naming the entry's own path
    // would send the caller looking in the wrong archive.
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
    let dir = tempfile::tempdir().expect("temp dir");
    let (outer_path, _) = make_nested(dir.path());
    let through = outer_path.join("x64").join("inner.rpf");

    let (code, message) = run_err(&["info", &through.display().to_string()]);
    assert_eq!(code, 6, "{message}");
    assert!(
        message.contains(&outer_path.display().to_string()),
        "the refusal names the archive the path runs past: {message}"
    );

    let (code, message) = run_err(&["ls", &through.display().to_string()]);
    assert_eq!(code, 6, "{message}");

    // And a path that simply is not there is still an ordinary i/o failure.
    let absent = dir.path().join("absent.rpf").display().to_string();
    let (code, message) = run_err(&["info", &absent]);
    assert_eq!(code, 7, "{message}");
}

#[test]
fn an_extraction_that_would_write_over_the_archive_it_is_reading_is_refused() {
    // Refused before anything is created, so a refusal leaves nothing behind.
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
        |_: &str| {
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

// Key material: nothing below asserts on a key.

/// A source that carries none of the anchored values.
fn carries_nothing(at: &Path) {
    fs::write(at, vec![0_u8; 1 << 16]).expect("writable");
}

/// Reports a skip; `RPF_REQUIRE_<GATE>` makes that gate's absence a failure.
fn skip_gated<T>(test: &str, gate: &str, reason: &str) -> Option<T> {
    let required = format!("RPF_REQUIRE_{}", gate.trim_start_matches("RPF_"));
    assert!(
        std::env::var_os(&required).is_none(),
        "{required} is set, but {test} would have skipped: {reason}",
    );
    eprintln!("SKIP {test}: {reason}");
    None
}

/// One of the game executables, or `None` with a reason on standard error.
fn executable(test: &str, name: &str) -> Option<std::path::PathBuf> {
    let Some(root) = std::env::var_os("RPF_GAME_EXE") else {
        return skip_gated(test, "RPF_GAME_EXE", "RPF_GAME_EXE is not set");
    };
    let path = Path::new(&root).join(name);
    if path.is_file() {
        Some(path)
    } else {
        skip_gated(
            test,
            "RPF_GAME_EXE",
            &format!("{} is not a file", path.display()),
        )
    }
}

/// The memory image the NG material is extracted from, or a loud skip.
fn game_image(test: &str) -> Option<std::path::PathBuf> {
    let Some(named) = std::env::var_os("RPF_GAME_IMAGE") else {
        return skip_gated(test, "RPF_GAME_IMAGE", "RPF_GAME_IMAGE is not set");
    };
    let path = std::path::PathBuf::from(named);
    if path.is_file() {
        Some(path)
    } else {
        skip_gated(
            test,
            "RPF_GAME_IMAGE",
            &format!("{} is not a file", path.display()),
        )
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
/// Not for `root`, where a refusal test would pass for the wrong reason.
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
    // Intact, but carrying none of the anchored values, which is exit 9.
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
    // A filesystem path that leads nowhere is the source failing; exit 3 is
    // reserved for a path that is not in an archive.
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

    // A cache that was never written is empty rather than missing.
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

    // Invalidating a cache with nothing in it is a success.
    let (code, out) = run(&["--json", "keys", "invalidate", "--cache-dir", &at]);
    assert_eq!(code, 0);
    let reported: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(reported["removed"], serde_json::json!(0), "{reported}");
}

#[test]
#[cfg(unix)]
fn a_cache_that_cannot_be_written_is_an_i_o_failure_naming_the_directory() {
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
    // The key is read in this process and searched for in every encoding.
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

    // Raw, hexadecimal in either case, and base64: the ways bytes reach JSON.
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
#[cfg_attr(no_executables, ignore = "RPF_GAME_EXE is not set")]
fn the_launcher_executable_reports_one_more_offset_and_never_that_key() {
    let test = "the_launcher_executable_reports_one_more_offset_and_never_that_key";
    let Some(path) = executable(test, "Launcher.exe") else {
        return;
    };
    let mut file = fs::File::open(&path).expect("the executable is readable");
    let material = rpf_core::keys::Material::extract(&mut file, &mut rpf_core::Unwatched)
        .expect("carries the material");
    let launcher = material.launcher().expect("carries the launcher key");

    let dir = tempfile::tempdir().expect("temp dir");
    let at = dir.path().join("cache").display().to_string();
    let source = path.display().to_string();
    let (code, out) = run(&["--json", "keys", "extract", &source, "--cache-dir", &at]);
    assert_eq!(code, 0);
    let reported: serde_json::Value = serde_json::from_slice(&out).expect("json");

    let values = reported["values"].as_array().expect("an array");
    assert_eq!(values.len(), 3, "{reported}");
    assert_eq!(values[2]["name"], serde_json::json!("launcher_aes_key"));
    assert_eq!(
        values[2]["at"],
        serde_json::json!(launcher.offset()),
        "{reported}"
    );

    let (_, printed) = run_output(&["--json", "keys", "extract", &source, "--cache-dir", &at]);
    for value in [
        launcher.key().as_slice(),
        material.keys().aes_key().as_slice(),
    ] {
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

    // The human output is a second rendering, and a second place to lose it.
    let (_, human) = run_output(&["keys", "extract", &source, "--cache-dir", &at]);
    assert!(
        holds(&human, format!("{:#x}", launcher.offset()).as_bytes()),
        "the offset is not reported"
    );
    for value in [
        launcher.key().as_slice(),
        material.keys().aes_key().as_slice(),
    ] {
        assert!(!holds(&human, value));
        assert!(!holds(&human, hex(value).as_bytes()));
        assert!(!holds(&human, BASE64.encode(value).as_bytes()));
    }
}

#[test]
#[cfg(unix)]
#[cfg_attr(no_executables, ignore = "RPF_GAME_EXE is not set")]
fn a_cache_directory_that_cannot_be_created_fails_the_extraction_that_needed_it() {
    // The material was found and the sink failed: reported rather than
    // swallowed, because a silent exit 0 leaves every later command rescanning.
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

/// A second archive, sharing no path with [`make_archive`]'s, so that a
/// manifest of one names nothing in the other.
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
        |_: &str| Ok(Cursor::new(vec![3_u8; 64])),
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
    // A stored entry declares no inflated length and carries no deflate stream
    // that ends, so a `verify` given the archive alone reads it back clean.
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
    // One object per problem: a reason carries colons of its own, so a consumer
    // cannot split "path: reason" back apart.
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
    // A manifest is joined to entries by path, so one describing another archive
    // matches nothing; the frontend refuses the pairing rather than the archive.
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
    // Every schema-1 and schema-2 manifest records no contents, which is read
    // rather than refused; a caller who asked for a contents check is told so.
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

/// An archive holding one resource whose payload carries four bytes past the
/// end of its deflate stream, as a zlib stream stripped of its header does.
fn make_trailing_resource(at: &Path) {
    let mut resource = Vec::new();
    resource.extend_from_slice(b"RSC7");
    resource.extend_from_slice(&162_u32.to_le_bytes());
    resource.extend_from_slice(&0xA800_0000_u32.to_le_bytes());
    resource.extend_from_slice(&0x2000_0000_u32.to_le_bytes());
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&vec![0_u8; 512]).expect("deflates");
    resource.extend_from_slice(&encoder.finish().expect("finishes"));
    resource.extend_from_slice(&[1_u8, 2, 3, 4]);

    let files = vec![FileSpec {
        path: "tiny.yft".to_owned(),
        kind: FileKind::Resource { declared: None },
    }];
    let mut out = fs::File::create(at).expect("archive is creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(resource.clone())),
        &mut Unwatched,
    )
    .expect("archive builds");
}

/// The lines `verify --against` printed for an archive and the tree it was
/// extracted to, with the exit code.
fn verified_against(archive: &Path, tree: &Path) -> (i32, String) {
    let (code, out) = run(&[
        "verify",
        &archive.display().to_string(),
        "--against",
        &tree.display().to_string(),
    ]);
    (code, String::from_utf8_lossy(&out).into_owned())
}

/// Extracts `archive` to a tree, which writes the manifest `--against` reads.
fn extracted_to(archive: &Path, tree: &Path) {
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
}

#[test]
fn an_entry_that_did_not_read_back_is_not_counted_as_two_kinds_of_gap() {
    // Its contents were never checked, so it is missing from `contents_checked`.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("tiny.rpf");
    make_trailing_resource(&archive);
    let tree = dir.path().join("tree");
    extracted_to(&archive, &tree);

    let (code, report) = verified_against(&archive, &tree);
    assert_eq!(
        code, 4,
        "the entry does not read back as described: {report}"
    );
    assert!(
        report.contains("the deflate stream ends after"),
        "the report was: {report}",
    );
    assert!(
        report.contains("0 of 1 recorded checksums checked"),
        "the report was: {report}",
    );
    assert!(
        !report.contains("carry no recorded checksum"),
        "there is no nested archive here: {report}",
    );
    assert!(
        !report.contains("name nothing this archive holds"),
        "the manifest's one checksum does name this entry: {report}",
    );
    assert!(
        report.contains("1 entries did not read back"),
        "the gap is explained by the entry that failed: {report}",
    );
}

#[test]
fn a_checksum_that_was_checked_and_failed_is_not_a_gap_in_the_coverage() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let tree = dir.path().join("tree");
    extracted_to(&archive, &tree);

    let (at, _, _) = spans(&archive, "stored.bin");
    let mut bytes = fs::read(&archive).expect("readable");
    let start = index_of(at);
    bytes[start] ^= 0xFF;
    fs::write(&archive, &bytes).expect("writable");

    let (code, report) = verified_against(&archive, &tree);
    assert_eq!(code, 4, "{report}");
    assert!(
        report.contains("2 of 2 recorded checksums checked"),
        "the report was: {report}",
    );
    assert!(
        !report.contains("carry no recorded checksum"),
        "the report was: {report}",
    );
    assert!(
        !report.contains("name nothing this archive holds"),
        "the report was: {report}",
    );
    assert!(
        !report.contains("did not read back"),
        "a mismatch was read back and checked: {report}",
    );
}

#[test]
fn an_entry_inside_a_nested_archive_is_the_one_with_no_recorded_checksum() {
    // A manifest records the nested archive as the one file it is.
    let dir = tempfile::tempdir().expect("temp dir");
    let (outer, _) = make_nested(dir.path());
    let tree = dir.path().join("tree");
    extracted_to(&outer, &tree);

    let (code, report) = verified_against(&outer, &tree);
    assert_eq!(code, 0, "the archive reads back clean: {report}");
    assert!(
        report.contains("3 entries read back; 1 of 1 recorded checksums checked"),
        "the report was: {report}",
    );
    assert!(
        report.contains("2 entries carry no recorded checksum"),
        "the two entries inside the nested archive: {report}",
    );
    assert!(
        !report.contains("name nothing this archive holds"),
        "the report was: {report}",
    );
}

// --- adding, deleting and renaming an entry --------------------------------

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
fn put_creates_an_entry_through_a_view_as_the_daemon_does() {
    // A path being created has no entry to convert against, so `--as` has
    // nothing to read an encoding from; the daemon accepts that case.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let source = dir.path().join("new.xml");
    fs::write(&source, b"<?xml version=\"1.0\"?>\n<root>\n</root>\n").expect("writable");
    let source = source.display().to_string();

    // `auto` takes the bytes as they are, exactly as `raw` does.
    let (code, out) = run(&[
        "--json",
        "put",
        &archive_str,
        "data/new.xml",
        &source,
        "--create",
        "--as",
        "auto",
    ]);
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&out));
    assert!(
        listing(&archive).contains(&"data/new.xml".to_owned()),
        "{:?}",
        listing(&archive),
    );

    // An entry that is not there holds no encoding for a document to adopt.
    let (code, message) = run_err(&[
        "put",
        &archive_str,
        "data/second.xml",
        &source,
        "--create",
        "--as",
        "xml",
    ]);
    assert_eq!(code, 6, "{message}");

    let (code, message) = run_err(&[
        "put",
        &archive_str,
        "data/third.xml",
        &source,
        "--as",
        "auto",
    ]);
    assert_eq!(code, 3, "{message}");
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

#[test]
fn extract_refuses_a_target_that_already_holds_something() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let tree = dir.path().join("tree");
    let tree_str = tree.display().to_string();

    assert_eq!(run(&["extract", &archive_str, &tree_str]).0, 0, "first");

    let (code, message) = run_err(&["extract", &archive_str, &tree_str]);
    assert_eq!(code, 6, "{message}");
    assert!(message.contains("already holds"), "{message}");
    assert!(message.contains("--overwrite"), "{message}");

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

/// A rebuild replaces an archive this process still holds open, which Windows
/// refuses unless the read handle is closed before the replace.
#[test]
fn a_rebuild_replaces_an_archive_something_holds_open() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let source = dir.path().join("added.txt");
    fs::write(&source, b"brand new").expect("writable");

    let held = fs::File::open(&archive).expect("the archive opens");
    let (code, message) = run(&[
        "put",
        &archive_str,
        "data/added.txt",
        &source.display().to_string(),
        "--create",
    ]);
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&message));
    drop(held);

    assert!(
        listing(&archive).contains(&"data/added.txt".to_owned()),
        "{:?}",
        listing(&archive),
    );
    assert_eq!(run(&["verify", &archive_str]).0, 0, "verify");
}

/// The failure comes out of the library rather than off an `fs::read`.
#[test]
fn a_donor_that_is_not_there_is_named_and_so_is_the_reason() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let missing = dir.path().join("nope.txt");

    let (code, message) = run_err(&[
        "put",
        &archive.display().to_string(),
        "data/greeting.txt",
        &missing.display().to_string(),
    ]);
    assert_eq!(code, 7, "{message}");
    assert!(message.contains("nope.txt"), "{message}");
    assert!(
        message.contains("No such file") || message.contains("cannot find"),
        "{message}",
    );
}

/// A donor that cannot be reopened or seeked is still accepted: a FIFO cannot
/// answer twice, so a donor that is not a regular file is read once and held.
#[test]
#[cfg(unix)]
fn a_donor_that_cannot_be_reopened_is_read_once_and_still_written() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let fifo = dir.path().join("pipe");

    let made = Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "mkfifo");

    let writing = fifo.clone();
    let (wrote, written) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        let mut pipe = fs::OpenOptions::new()
            .write(true)
            .open(&writing)
            .expect("the pipe opens");
        let took = pipe.write_all(b"through a pipe");
        // Sent while the write end is still open, so a test that sees nothing
        // knows the thread is not past the pipe and reading it can only help.
        let _ = wrote.send(());
        took.expect("the pipe takes it");
    });

    let (code, out) = run(&[
        "put",
        &archive.display().to_string(),
        "data/greeting.txt",
        &fifo.display().to_string(),
    ]);
    if written.try_recv().is_err() {
        // A `put` that gave up before opening the donor leaves the writing thread
        // waiting in `open` for a reader that is never coming.
        let releasing = fifo.clone();
        std::thread::spawn(move || {
            let _ = fs::read(&releasing);
        });
    }
    join_within(writer, "the writer");
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&out));

    let (code, bytes) = run(&["cat", &archive.display().to_string(), "data/greeting.txt"]);
    assert_eq!(code, 0);
    assert_eq!(bytes, b"through a pipe".to_vec());
}

/// The AES-encrypted archive in the corpus, by its relative path.
const AES_ARCHIVE: &str = "gtav_aes/des_canister.rpf";

/// The NG-encrypted archive in the corpus, whose **file name is load-bearing**:
/// an NG key is chosen by the archive's own name, so a copy does not open.
const NG_ARCHIVE: &str = "gtav_ng/dlc.rpf";

/// The Rockstar Games Launcher's own archive, likewise: the only kind here
/// under the launcher key rather than the RAGE one.
const LAUNCHER_ARCHIVE: &str = "rockstar_launcher/Launcher.rpf";

/// One corpus archive by its fixed relative path.
fn corpus(test: &str, relative: &str) -> Option<std::path::PathBuf> {
    let missing = |reason: String| -> Option<std::path::PathBuf> {
        assert!(
            std::env::var_os("RPF_REQUIRE_CORPUS").is_none(),
            "RPF_REQUIRE_CORPUS is set, but {test} would have skipped: {reason}",
        );
        eprintln!("SKIP {test}: {reason}");
        None
    };
    let Some(root) = std::env::var_os("RPF_CORPUS") else {
        return missing("RPF_CORPUS is not set".to_owned());
    };
    let path = Path::new(&root).join(relative);
    if path.is_file() {
        Some(path)
    } else {
        missing(format!("{} is not a file", path.display()))
    }
}

/// Runs the binary with a configuration directory of its own, returning its
/// exit code and standard error: the key cache lives under that root.
fn run_err_homed(home: &Path, args: &[&str]) -> (i32, String) {
    let output = Command::new(RPF)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("APPDATA", home.join("appdata"))
        .args(args)
        .output()
        .expect("binary runs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
#[cfg_attr(
    any(no_corpus, no_game_image),
    ignore = "RPF_CORPUS and RPF_GAME_IMAGE must both be set"
)]
fn an_ng_archive_is_written_back_through_the_command_line_and_opens_again() {
    let test = "an_ng_archive_is_written_back_through_the_command_line_and_opens_again";
    let Some(archive) = corpus(test, NG_ARCHIVE) else {
        return;
    };
    // A memory image, not an executable: no executable carries the NG material.
    let Some(source) = game_image(test) else {
        return;
    };

    let dir = tempfile::tempdir().expect("temp dir");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    // Not compressible and not a whole number of cipher blocks, so the tail
    // rule is exercised; and not the length the entry had.
    let donor = dir.path().join("payload.bin");
    let bytes: Vec<u8> = (0..401_u32)
        .map(|n| u8::try_from(n % 251).unwrap_or(0))
        .collect();
    fs::write(&donor, &bytes).expect("donor");
    let from = donor.display().to_string();

    let (code, message) = run_err_homed(&home, &["keys", "extract", &source.display().to_string()]);
    assert_eq!(code, 0, "{message}");

    // Each copy keeps the file name `dlc.rpf`: the NG key for a table of
    // contents is a function of the archive's own name.
    for (what, extra) in [("patch", None), ("rebuild", Some("--rebuild"))] {
        let at_dir = dir.path().join(what);
        fs::create_dir_all(&at_dir).expect("a directory per write path");
        let copy = at_dir.join("dlc.rpf");
        fs::copy(&archive, &copy).expect("the archive is copyable");
        let at = copy.display().to_string();
        let mut args = vec!["put"];
        args.extend(extra);
        args.extend(["--force", &at, "content.xml", &from]);
        let (code, message) = run_err_homed(&home, &args);
        assert_eq!(code, 0, "{what}: {message}");

        let (code, message) = run_err_homed(&home, &["verify", &at]);
        assert_eq!(
            code, 0,
            "{what}: the written NG archive does not verify: {message}"
        );

        let output = Command::new(RPF)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("APPDATA", home.join("appdata"))
            .args(["cat", &at, "content.xml"])
            .output()
            .expect("binary runs");
        assert_eq!(output.status.code(), Some(0), "{what}");
        assert_eq!(
            output.stdout,
            fs::read(&donor).expect("donor"),
            "{what}: the entry did not come back out"
        );
    }

    // `pack` opens no archive, so it reaches the same cache `keys extract` filled.
    let tree = dir.path().join("tree");
    let (code, message) = run_err_homed(
        &home,
        &[
            "extract",
            &archive.display().to_string(),
            &tree.display().to_string(),
        ],
    );
    assert_eq!(code, 0, "{message}");
    let packed = dir.path().join("packed.rpf");
    let at = packed.display().to_string();
    let (code, message) = run_err_homed(&home, &["pack", &tree.display().to_string(), &at]);
    assert_eq!(code, 0, "{message}");
    let (code, message) = run_err_homed(&home, &["verify", &at]);
    assert_eq!(code, 0, "the packed NG archive does not verify: {message}");

    // The same tree, from a home with nothing in it: exit 9, naming material
    // rather than an algorithm. `--force` does not reach it.
    let bare = dir.path().join("no-keys");
    fs::create_dir_all(&bare).expect("home");
    let unpacked = dir.path().join("unkeyed.rpf");
    let (code, message) = run_err_homed(
        &bare,
        &[
            "pack",
            &tree.display().to_string(),
            &unpacked.display().to_string(),
        ],
    );
    assert_eq!(code, 9, "{message}");
    assert!(
        message.contains("derives this archive's forward transform"),
        "{message}"
    );
    assert!(
        !message.contains("Edit through the archive"),
        "a walled-off remedy was offered: {message}"
    );
    assert!(!unpacked.exists(), "a refused pack wrote an archive");
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn an_aes_archive_is_written_back_through_the_command_line_and_opens_again() {
    // A rebuild that wrote the table of contents in the clear fails at the `cat`.
    let test = "an_aes_archive_is_written_back_through_the_command_line_and_opens_again";
    let Some(archive) = corpus(test, AES_ARCHIVE) else {
        return;
    };
    let Some(source) = executable(test, "GTA5.exe") else {
        return;
    };

    let dir = tempfile::tempdir().expect("temp dir");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    // Not text and not a whole number of cipher blocks: a textual payload is
    // refused before this, and a multiple of sixteen leaves the tail untested.
    let donor = dir.path().join("payload.bin");
    let bytes: Vec<u8> = (0..401_u32)
        .map(|n| u8::try_from(n % 251).unwrap_or(0))
        .collect();
    fs::write(&donor, &bytes).expect("donor");
    let from = donor.display().to_string();

    let (code, message) = run_err_homed(&home, &["keys", "extract", &source.display().to_string()]);
    assert_eq!(code, 0, "{message}");

    for (what, extra) in [("patch", None), ("rebuild", Some("--rebuild"))] {
        let copy = dir.path().join(format!("{what}.rpf"));
        fs::copy(&archive, &copy).expect("the archive is copyable");
        let at = copy.display().to_string();
        let mut args = vec!["put"];
        args.extend(extra);
        args.extend(["--force", &at, "_manifest.ymf", &from]);
        let (code, message) = run_err_homed(&home, &args);
        assert_eq!(code, 0, "{what}: {message}");

        let (code, message) = run_err_homed(&home, &["ls", &at]);
        assert_eq!(
            code, 0,
            "{what}: the written archive does not list: {message}"
        );

        let output = Command::new(RPF)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("APPDATA", home.join("appdata"))
            .args(["cat", &at, "_manifest.ymf"])
            .output()
            .expect("binary runs");
        assert_eq!(output.status.code(), Some(0), "{what}");
        assert_eq!(
            output.stdout,
            fs::read(&donor).expect("donor"),
            "{what}: the entry did not come back out"
        );
    }

    // And the third write path: these resources carry no `RSC7` header of their
    // own, so the manifest is what records the words their rows declare.
    let tree = dir.path().join("tree");
    let (code, message) = run_err_homed(
        &home,
        &[
            "extract",
            &archive.display().to_string(),
            &tree.display().to_string(),
        ],
    );
    assert_eq!(code, 0, "{message}");
    let packed = dir.path().join("packed.rpf");
    let at = packed.display().to_string();
    let (code, message) = run_err_homed(&home, &["pack", &tree.display().to_string(), &at]);
    assert_eq!(code, 0, "{message}");
    let (code, message) = run_err_homed(&home, &["ls", &at]);
    assert_eq!(code, 0, "the packed archive does not list: {message}");
    let output = Command::new(RPF)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("APPDATA", home.join("appdata"))
        .args(["cat", &at, "_manifest.ymf"])
        .output()
        .expect("binary runs");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        fs::read(tree.join("_manifest.ymf")).expect("the extracted file"),
        "the entry did not survive extract and pack"
    );

    // No material anywhere is exit 5, answered before a payload is read.
    let bare = dir.path().join("no-keys");
    fs::create_dir_all(&bare).expect("home");
    let unpacked = dir.path().join("unkeyed.rpf");
    let (code, message) = run_err_homed(
        &bare,
        &[
            "pack",
            &tree.display().to_string(),
            &unpacked.display().to_string(),
        ],
    );
    assert_eq!(code, 5, "{message}");
    assert!(message.contains("no key material available"), "{message}");
    assert!(!unpacked.exists(), "a refused pack wrote an archive");
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn the_launcher_archive_opens_once_the_launcher_key_is_extracted() {
    let test = "the_launcher_archive_opens_once_the_launcher_key_is_extracted";
    let Some(archive) = corpus(test, LAUNCHER_ARCHIVE) else {
        return;
    };
    let Some(launcher) = executable(test, "Launcher.exe") else {
        return;
    };
    let Some(game) = executable(test, "GTA5.exe") else {
        return;
    };
    let at = archive.display().to_string();

    let dir = tempfile::tempdir().expect("temp dir");
    let without = dir.path().join("game-only");
    fs::create_dir_all(&without).expect("home");
    let (code, message) =
        run_err_homed(&without, &["keys", "extract", &game.display().to_string()]);
    assert_eq!(code, 0, "{message}");
    let (code, message) = run_err_homed(&without, &["ls", &at]);
    assert_eq!(code, 5, "{message}");
    assert!(message.contains("no key material available"), "{message}");
    assert!(message.contains("0x0ffffff7"), "{message}");

    let home = dir.path().join("with-launcher");
    fs::create_dir_all(&home).expect("home");
    let (code, message) =
        run_err_homed(&home, &["keys", "extract", &launcher.display().to_string()]);
    assert_eq!(code, 0, "{message}");
    let (code, message) = run_err_homed(&home, &["ls", "-R", &at]);
    assert_eq!(code, 0, "{message}");

    // `Launcher.rpf` is the one corpus archive with no resource entry, so an
    // extracted tree of it is one this packer can rebuild entirely.
    let tree = dir.path().join("tree");
    let (code, message) = run_err_homed(&home, &["extract", &at, &tree.display().to_string()]);
    assert_eq!(code, 0, "{message}");
    let packed = dir.path().join("packed.rpf");
    let to = packed.display().to_string();
    let (code, message) = run_err_homed(&home, &["pack", &tree.display().to_string(), &to]);
    assert_eq!(code, 0, "{message}");
    let (code, message) = run_err_homed(&home, &["ls", "-R", &to]);
    assert_eq!(code, 0, "the packed archive does not list: {message}");
    let (code, message) = run_err_homed(&home, &["verify", &to]);
    assert_eq!(code, 0, "the packed archive does not verify: {message}");

    // A separate process with no cache at all is what says it was written sealed.
    let bare = dir.path().join("no-keys");
    fs::create_dir_all(&bare).expect("home");
    let (code, message) = run_err_homed(&bare, &["ls", &to]);
    assert_eq!(code, 5, "the packed archive is in the clear: {message}");
    assert!(message.contains("no key material available"), "{message}");
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn a_named_cache_opens_the_archive_the_platform_one_would_not() {
    // `--cache-dir` has to reach opening as well as extraction.
    let test = "a_named_cache_opens_the_archive_the_platform_one_would_not";
    let Some(archive) = corpus(test, AES_ARCHIVE) else {
        return;
    };
    let Some(source) = executable(test, "GTA5.exe") else {
        return;
    };

    let dir = tempfile::tempdir().expect("temp dir");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let named = dir.path().join("keys").display().to_string();
    let at = archive.display().to_string();

    let (code, message) = run_err_homed(
        &home,
        &[
            "keys",
            "extract",
            &source.display().to_string(),
            "--cache-dir",
            &named,
        ],
    );
    assert_eq!(code, 0, "{message}");

    let (code, message) = run_err_homed(&home, &["ls", &at, "--cache-dir", &named]);
    assert_eq!(code, 0, "{message}");

    // The platform cache, which nothing was put in, still says "needs a key".
    let (code, message) = run_err_homed(&home, &["ls", &at]);
    assert_eq!(code, 5, "{message}");
    assert!(message.contains("no key material available"), "{message}");

    let tree = dir.path().join("tree");
    let (code, message) = run_err_homed(
        &home,
        &[
            "extract",
            &at,
            &tree.display().to_string(),
            "--cache-dir",
            &named,
        ],
    );
    assert_eq!(code, 0, "{message}");
    let from = tree.display().to_string();
    let packed = dir.path().join("packed.rpf").display().to_string();
    let (code, message) = run_err_homed(&home, &["pack", &from, &packed, "--cache-dir", &named]);
    assert_eq!(code, 0, "{message}");
    let (code, message) = run_err_homed(&home, &["ls", &packed, "--cache-dir", &named]);
    assert_eq!(code, 0, "the packed archive does not list: {message}");

    let without = dir.path().join("no-flag.rpf").display().to_string();
    let (code, message) = run_err_homed(&home, &["pack", &from, &without]);
    assert_eq!(code, 5, "{message}");
    assert!(message.contains("no key material available"), "{message}");
    assert!(
        !Path::new(&without).exists(),
        "a refused pack wrote an archive"
    );
}

/// Both encodings: `RBF` converts from the document, `PSO` edits the file.
#[test]
fn a_metadata_entry_is_read_as_xml_and_an_edited_document_is_written_back() {
    let dir = tempfile::tempdir().expect("temp dir");
    for (payload, document, edited, encoding) in common::tokenised() {
        let archive = dir.path().join(format!("{encoding}.rpf"));
        make_metadata_archive(&archive, &payload);
        let at = archive.display().to_string();

        let (code, shown) = run(&["cat", &at, "data/thing.ymt", "--as", "xml"]);
        assert_eq!(code, 0, "{encoding}: cat --as xml");
        assert_eq!(
            String::from_utf8_lossy(&shown),
            document,
            "{encoding}: the view is the document"
        );
        assert_eq!(
            run(&["cat", &at, "data/thing.ymt", "--as", "auto"]).1,
            shown,
            "{encoding}: auto"
        );

        let donor = dir.path().join(format!("{encoding}.xml"));
        fs::write(&donor, edited).expect("writable");
        let (code, message) = run_err(&[
            "put",
            &at,
            "data/thing.ymt",
            &donor.display().to_string(),
            "--as",
            "xml",
        ]);
        assert_eq!(code, 0, "{encoding}: put --as xml said {message}");

        let (code, listed) = run(&["--json", "ls", &at, "", "-R"]);
        assert_eq!(code, 0);
        let rows: serde_json::Value = serde_json::from_slice(&listed).expect("an array");
        let row = rows
            .as_array()
            .expect("an array")
            .iter()
            .find(|row| row["path"] == serde_json::json!("data/thing.ymt"))
            .expect("the entry is listed")
            .clone();
        assert_eq!(
            row["encoding"],
            serde_json::json!(encoding),
            "{encoding}: the entry changed encoding: {rows}"
        );
        assert_eq!(
            String::from_utf8_lossy(&run(&["cat", &at, "data/thing.ymt", "--as", "xml"]).1),
            edited,
            "{encoding}: the edit did not land"
        );
        assert_ne!(
            run(&["cat", &at, "data/thing.ymt"]).1,
            payload,
            "{encoding}: the payload was not touched at all"
        );
    }
}

#[test]
fn a_document_written_back_unedited_leaves_the_entry_identical() {
    let dir = tempfile::tempdir().expect("temp dir");
    for (payload, document, _, encoding) in common::tokenised() {
        let archive = dir.path().join(format!("{encoding}-same.rpf"));
        make_metadata_archive(&archive, &payload);
        let at = archive.display().to_string();

        let (code, shown) = run(&["cat", &at, "data/thing.ymt", "--as", "xml"]);
        assert_eq!(code, 0);
        assert_eq!(String::from_utf8_lossy(&shown), document);
        let donor = dir.path().join(format!("{encoding}-same.xml"));
        fs::write(&donor, &shown).expect("writable");
        let (code, message) = run_err(&[
            "put",
            &at,
            "data/thing.ymt",
            &donor.display().to_string(),
            "--as",
            "xml",
        ]);
        assert_eq!(code, 0, "{encoding}: {message}");
        assert_eq!(
            payload_of(dir.path(), &at, "data/thing.ymt"),
            payload,
            "{encoding}: an unedited round trip changed the payload"
        );
    }
}

/// A resource's payload is not read at all, so it has no view however
/// XML-looking it is.
#[test]
fn an_entry_with_no_xml_view_is_refused_with_its_own_reason() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("plain.rpf");
    make_metadata_archive(&archive, b"a plain line of text\n");
    let (code, message) = run_err(&[
        "cat",
        &archive.display().to_string(),
        "data/thing.ymt",
        "--as",
        "xml",
    ]);
    assert_eq!(code, 6, "{message}");
    assert!(
        message.contains("no XML view") && message.contains("text"),
        "must name what it holds: {message}"
    );

    let resource = dir.path().join("resource.rpf");
    let held = make_rockstar_archive(&resource);
    assert!(!held.is_empty());
    let (code, message) = run_err(&[
        "cat",
        &resource.display().to_string(),
        "art.ydr",
        "--as",
        "xml",
    ]);
    assert_eq!(code, 6, "{message}");
    assert!(
        message.contains("no XML view"),
        "must be the same refusal: {message}"
    );
}

/// What is written as a document is the `RBF` the entry held.
#[test]
fn a_document_is_refused_as_bytes_and_taken_as_a_document() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("guard.rpf");
    let payload = common::rbf_payload(common::RBF_DOCUMENT);
    make_metadata_archive(&archive, &payload);
    let at = archive.display().to_string();
    let donor = dir.path().join("edited.xml");
    fs::write(&donor, common::RBF_EDITED).expect("writable");
    let from = donor.display().to_string();

    let (code, message) = run_err(&["put", &at, "data/thing.ymt", &from]);
    assert_eq!(code, 6, "the bytes are still refused: {message}");
    assert!(
        message.contains("--allow-encoding-change"),
        "the way through is still named: {message}"
    );
    assert_eq!(
        payload_of(dir.path(), &at, "data/thing.ymt"),
        payload,
        "a refused put wrote something"
    );

    let (code, message) = run_err(&["put", &at, "data/thing.ymt", &from, "--as", "xml"]);
    assert_eq!(code, 0, "a converted write needs no switch: {message}");
    assert_eq!(
        payload_of(dir.path(), &at, "data/thing.ymt"),
        common::rbf_payload(common::RBF_EDITED),
        "what was written is not the payload the document describes"
    );
}

#[test]
fn a_document_the_entry_cannot_take_is_refused_at_the_conversion() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("bad.rpf");
    let payload = common::rbf_payload(common::RBF_DOCUMENT);
    make_metadata_archive(&archive, &payload);
    let donor = dir.path().join("not-rbf.xml");
    fs::write(
        &donor,
        "<?xml version=\"1.0\"?><Root><x rbf:notatype=\"1\"/></Root>",
    )
    .expect("writable");
    let (code, message) = run_err(&[
        "put",
        &archive.display().to_string(),
        "data/thing.ymt",
        &donor.display().to_string(),
        "--as",
        "xml",
    ]);
    assert_eq!(code, 6, "{message}");
    // The refusal is the converter's, not the guardrail's: only the guardrail
    // names `--allow-encoding-change`, and only the codec names the position.
    assert!(
        message.contains("does not describe an RBF document"),
        "must be the codec's own refusal: {message}"
    );
    assert!(
        !message.contains("--allow-encoding-change"),
        "the document reached the entry as bytes: {message}"
    );
    assert_eq!(
        payload_of(dir.path(), &archive.display().to_string(), "data/thing.ymt"),
        payload,
        "a refused conversion wrote something"
    );
}

/// The page boundary is the row's flag words and appears in no byte of the
/// payload.
#[test]
fn a_resource_meta_is_read_as_xml_and_an_edited_document_is_written_back() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("meta.rpf");
    make_meta_archive(&archive, common::META_FLAGS);
    let at = archive.display().to_string();

    let (code, shown) = run(&["cat", &at, "data/thing.ymt", "--as", "xml"]);
    assert_eq!(code, 0, "cat --as xml");
    assert_eq!(
        String::from_utf8_lossy(&shown),
        common::META_DOCUMENT,
        "the view is the document"
    );
    // `.ymt` is a resource here and metadata elsewhere, so `auto` may not guess
    // from the extension.
    assert_eq!(
        run(&["cat", &at, "data/thing.ymt", "--as", "auto"]).1,
        shown,
        "auto"
    );

    let donor = dir.path().join("meta.xml");
    fs::write(&donor, common::META_EDITED).expect("writable");
    let (code, message) = run_err(&[
        "put",
        &at,
        "data/thing.ymt",
        &donor.display().to_string(),
        "--as",
        "xml",
    ]);
    assert_eq!(code, 0, "put --as xml said {message}");

    assert_eq!(
        String::from_utf8_lossy(&run(&["cat", &at, "data/thing.ymt", "--as", "xml"]).1),
        common::META_EDITED,
        "the edit did not land"
    );
    // A listing reads no resource payload, so the encoding is `null` either way.
    let (code, listed) = run(&["--json", "ls", &at, "", "-R"]);
    assert_eq!(code, 0);
    let rows: serde_json::Value = serde_json::from_slice(&listed).expect("an array");
    let row = rows
        .as_array()
        .expect("an array")
        .iter()
        .find(|row| row["path"] == serde_json::json!("data/thing.ymt"))
        .expect("the entry is listed")
        .clone();
    assert_eq!(row["encoding"], serde_json::Value::Null, "{rows}");
    assert_eq!(run(&["verify", &at]).0, 0, "verify");
}

/// Value for value, not byte for byte: a converted write deflates at this
/// build's own level.
#[test]
fn a_meta_written_back_unedited_reads_back_as_the_same_document() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("meta-same.rpf");
    make_meta_archive(&archive, common::META_FLAGS);
    let at = archive.display().to_string();

    let (code, shown) = run(&["cat", &at, "data/thing.ymt", "--as", "xml"]);
    assert_eq!(code, 0);
    let donor = dir.path().join("meta-same.xml");
    fs::write(&donor, &shown).expect("writable");
    let (code, message) = run_err(&[
        "put",
        &at,
        "data/thing.ymt",
        &donor.display().to_string(),
        "--as",
        "xml",
    ]);
    assert_eq!(code, 0, "{message}");
    assert_eq!(
        run(&["cat", &at, "data/thing.ymt", "--as", "xml"]).1,
        shown,
        "an unedited round trip changed what the entry says"
    );
    assert_eq!(run(&["verify", &at]).0, 0, "verify");
}

/// The write is idempotent from the second time on.
#[test]
fn a_converted_meta_write_keeps_the_payloads_opaque_prefix_byte_for_byte() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("meta-prefix.rpf");
    make_meta_archive(&archive, common::META_FLAGS);
    let at = archive.display().to_string();
    let before = payload_of(dir.path(), &at, "data/thing.ymt");
    assert_eq!(before.get(..24), Some(&[0xFF_u8; 24][..]), "the fixture");

    let donor = dir.path().join("meta-prefix.xml");
    fs::write(&donor, common::META_EDITED).expect("writable");
    let put = [
        "put",
        &at,
        "data/thing.ymt",
        &donor.display().to_string(),
        "--as",
        "xml",
    ];
    let (code, message) = run_err(&put);
    assert_eq!(code, 0, "{message}");

    let after = payload_of(dir.path(), &at, "data/thing.ymt");
    assert_eq!(
        after.get(..24),
        before.get(..24),
        "the payload's opaque prefix was rewritten"
    );
    let (code, message) = run_err(&put);
    assert_eq!(code, 0, "{message}");
    assert_eq!(
        payload_of(dir.path(), &at, "data/thing.ymt"),
        after,
        "a converted write is not idempotent"
    );
    assert_eq!(run(&["verify", &at]).0, 0, "verify");
}

/// The archive checks only the sum, so nothing else catches it.
#[test]
fn a_meta_read_against_a_boundary_its_row_does_not_declare_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("meta-elsewhere.rpf");
    make_meta_archive(&archive, common::META_ELSEWHERE);
    let at = archive.display().to_string();

    // The entry itself is sound: it inflates to the length its row declares.
    assert_eq!(run(&["verify", &at]).0, 0, "verify");
    let before = run(&["cat", &at, "data/thing.ymt"]).1;

    let (code, message) = run_err(&["cat", &at, "data/thing.ymt", "--as", "xml"]);
    assert_eq!(code, 4, "{message}");
    assert!(message.contains("malformed Meta"), "{message}");

    let donor = dir.path().join("elsewhere.xml");
    fs::write(&donor, common::META_EDITED).expect("writable");
    let (code, message) = run_err(&[
        "put",
        &at,
        "data/thing.ymt",
        &donor.display().to_string(),
        "--as",
        "xml",
    ]);
    assert_eq!(code, 4, "{message}");
    assert!(message.contains("malformed Meta"), "{message}");
    assert_eq!(
        run(&["cat", &at, "data/thing.ymt"]).1,
        before,
        "a refused conversion wrote something"
    );
}

#[test]
fn a_document_the_meta_cannot_take_is_refused_at_the_conversion() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("meta-bad.rpf");
    make_meta_archive(&archive, common::META_FLAGS);
    let at = archive.display().to_string();
    let before = run(&["cat", &at, "data/thing.ymt"]).1;

    let donor = dir.path().join("not-meta.xml");
    fs::write(&donor, "<?xml version=\"1.0\"?><SomethingElse/>").expect("writable");
    let (code, message) = run_err(&[
        "put",
        &at,
        "data/thing.ymt",
        &donor.display().to_string(),
        "--as",
        "xml",
    ]);
    assert_eq!(code, 6, "{message}");
    assert!(
        message.contains("does not describe this Meta payload"),
        "must be the codec's own refusal: {message}"
    );
    assert!(
        !message.contains("--allow-encoding-change"),
        "the document reached the entry as bytes: {message}"
    );
    assert_eq!(
        run(&["cat", &at, "data/thing.ymt"]).1,
        before,
        "a refused conversion wrote something"
    );
}

/// The assertion is over the bytes `cat` gives back, not their length.
#[test]
fn put_as_auto_refuses_a_document_into_a_resource_that_is_not_a_meta() {
    use std::io::Write as _;

    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("rockstar.rpf");
    let payload = {
        let mut bytes = vec![0xFF_u8; 24];
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&[0_u8; 512]).expect("deflates");
        bytes.extend_from_slice(&encoder.finish().expect("the encoder finishes"));
        bytes
    };
    let held = payload.clone();
    let mut out = fs::File::create(&archive).expect("archive is creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &[FileSpec {
            path: "art.ydr".to_owned(),
            kind: FileKind::Resource {
                declared: Some(common::META_FLAGS),
            },
        }],
        &[],
        |_: &str| Ok(Cursor::new(held.clone())),
        &mut Unwatched,
    )
    .expect("archive builds");
    drop(out);
    let at = archive.display().to_string();
    assert_eq!(
        payload_of(dir.path(), &at, "art.ydr"),
        payload,
        "the fixture"
    );

    let donor = dir.path().join("doc.xml");
    fs::write(&donor, common::META_DOCUMENT).expect("writable");
    let (code, message) = run_err(&[
        "put",
        &at,
        "art.ydr",
        &donor.display().to_string(),
        "--as",
        "auto",
    ]);
    assert_ne!(code, 0, "a resource took a document: {message}");
    assert!(
        message.contains("has no XML view"),
        "the refusal does not name the view: {message}"
    );
    let after = payload_of(dir.path(), &at, "art.ydr");
    assert_eq!(after, payload, "the document landed as the entry's payload");
    assert_ne!(after.get(..5), Some(&b"<?xml"[..]));
    assert_eq!(run(&["verify", &at]).0, 0, "verify");

    // `--as raw` still writes genuine resource bytes, the write this must not
    // take away.
    let other = dir.path().join("other.ydr");
    let mut swapped = payload.clone();
    swapped[0] = 0xAA;
    fs::write(&other, &swapped).expect("writable");
    let (code, message) = run_err(&[
        "put",
        &at,
        "art.ydr",
        &other.display().to_string(),
        "--as",
        "raw",
    ]);
    assert_eq!(code, 0, "raw no longer writes a resource: {message}");
    assert_eq!(payload_of(dir.path(), &at, "art.ydr"), swapped);
}
