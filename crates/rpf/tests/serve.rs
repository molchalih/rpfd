//! The stdio daemon: warm state, buffered edits, one rebuild per commit.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; a panic is the reporting mechanism. The crate-level \
              allow is what covers the helpers here: clippy.toml's \
              allow-panic-in-tests reaches #[test] functions and not the \
              plain ones they call. docs/conventions.md §15"
)]

use std::{
    fs,
    io::{BufRead as _, Cursor, Read as _, Write as _},
    path::Path,
    process::{Command, Stdio},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rpf_core::{FileKind, FileSpec, Storage, Unwatched};
use serde_json::{Value, json};

mod common;

use crate::common::deadline::{Deadline, PATIENCE};

const RPF: &str = env!("CARGO_BIN_EXE_rpf");

/// A budget for a wait on a scan of `file`, end to end: [`PATIENCE`], and a
/// second for every 4 MiB of it. A `keys.extract` over a 10,263,234,184-byte
/// image took ~1,050 s on the reference box with four of them at once — 9.32
/// MiB/s across the two passes it makes over the image, the digest and the
/// scan — against the 2,507 s this budgets, which is 2.39x.
fn scanning(file: &Path) -> std::time::Duration {
    let bytes = fs::metadata(file).map_or(0, |it| it.len());
    let scan = std::time::Duration::from_secs(bytes)
        .checked_div(4 * 1024 * 1024)
        .unwrap_or_default();
    PATIENCE.saturating_add(scan)
}

/// A budget for a wait on a daemon repeating work a fixture already did:
/// [`PATIENCE`], or eight times what building the fixture cost where longer.
fn repeating(building: std::time::Duration) -> std::time::Duration {
    PATIENCE.max(building.saturating_mul(8))
}

/// An archive with one deflated file and one resource.
fn make_archive(at: &Path) -> Vec<u8> {
    // An RSC7 header whose flags describe one 512-byte system page and no
    // graphics pages, then a deflate stream of exactly that; version field 162.
    let mut resource = Vec::new();
    resource.extend_from_slice(b"RSC7");
    resource.extend_from_slice(&162_u32.to_le_bytes());
    resource.extend_from_slice(&0xA800_0000_u32.to_le_bytes());
    resource.extend_from_slice(&0x2000_0000_u32.to_le_bytes());
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&vec![0_u8; 512]).expect("deflates");
    resource.extend_from_slice(&encoder.finish().expect("finishes"));

    let files = vec![
        FileSpec {
            path: "data/greeting.txt".to_owned(),
            kind: FileKind::Binary {
                storage: Storage::Deflate,
                encryption: 0,
            },
        },
        FileSpec {
            path: "art.yft".to_owned(),
            kind: FileKind::Resource { declared: None },
        },
    ];
    let payload = resource.clone();
    let mut out = fs::File::create(at).expect("creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |wanted: &str| {
            Ok(Cursor::new(if wanted == "art.yft" {
                payload.clone()
            } else {
                b"hello there".to_vec()
            }))
        },
        &mut Unwatched,
    )
    .expect("builds");
    resource
}

/// An archive whose one resource is shaped the way a Rockstar archive holds
/// one: an opaque header that is not `RSC7`, then the deflate stream.
fn make_rockstar_archive(at: &Path) -> Vec<u8> {
    // 24 bytes of 0xFF: not `RSC7`, and not a deflate stream either — the low
    // three bits are BFINAL = 1 with the reserved BTYPE = 11.
    let mut resource = vec![0xFF_u8; 24];
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&vec![0_u8; 512]).expect("deflates");
    resource.extend_from_slice(&encoder.finish().expect("finishes"));

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
    let mut out = fs::File::create(at).expect("creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(payload.clone())),
        &mut Unwatched,
    )
    .expect("builds");
    resource
}

/// An archive holding two entries that fold to one name, returning its bytes:
/// `build` will not write one, so the second name is edited in the names blob.
fn make_colliding_archive(at: &Path) -> Vec<u8> {
    let files = ["A.txt", "b.txt"].map(|name| FileSpec {
        path: name.to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Stored,
            encryption: 0,
        },
    });

    let mut out = Vec::new();
    rpf_core::build(
        &mut std::io::Cursor::new(&mut out),
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(b"payload".to_vec())),
        &mut Unwatched,
    )
    .expect("two distinct names build");

    let written = b"b.txt";
    let wanted = b"a.txt";
    let occurrences = out.windows(written.len()).filter(|w| w == written).count();
    assert_eq!(
        occurrences, 1,
        "the name must appear only in the names blob"
    );
    let offset = out
        .windows(written.len())
        .position(|w| w == written)
        .expect("the name is in the blob");
    out.get_mut(offset..offset.saturating_add(written.len()))
        .expect("the name is in the blob")
        .copy_from_slice(wanted);

    fs::write(at, &out).expect("archive is writable");
    out
}

/// Where one entry's payload sits and how much room it has.
fn spans(at: &Path, inside: &str) -> (u64, u64) {
    let mut file = fs::File::open(at).expect("archive opens");
    let archive =
        rpf_core::Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("archive parses");
    let index = archive.find(inside).expect("entry resolves");
    let (payload_at, _) = archive.payload_at(index).expect("payload span");
    (payload_at, archive.allocation(index).expect("allocation"))
}

/// Feeds every request in, and returns the responses.
fn talk(requests: &[Value]) -> Vec<Value> {
    narrated(requests).0
}

/// The response carrying an id. By id rather than by position: `cancel` is
/// answered by the reading thread and can overtake an earlier response.
fn answer(responses: &[Value], id: u64) -> &Value {
    responses
        .iter()
        .find(|response| response["id"] == json!(id))
        .unwrap_or_else(|| panic!("no response for {id} in {responses:?}"))
}

/// As [`talk`], but keeping the notifications too: responses first.
fn narrated(requests: &[Value]) -> (Vec<Value>, Vec<Value>) {
    drive(daemon(), requests)
}

/// As [`talk`], with the daemon started in `cwd`.
fn talk_in(cwd: &Path, requests: &[Value]) -> Vec<Value> {
    let mut daemon = daemon();
    daemon.current_dir(cwd);
    drive(daemon, requests).0
}

/// The daemon, not yet started.
fn daemon() -> Command {
    let mut daemon = Command::new(RPF);
    daemon.args(["serve", "--stdio"]);
    daemon
}

/// `daemon` started under `deadline`, its two pipes handed back so a test can
/// state when each is read and closed. The pipes come off the child and the
/// child goes to the deadline before a byte is written, because the write is
/// itself a wait: a daemon that stops reading fills the pipe, and only a
/// deadline holding the child can end it.
fn started(
    deadline: &Deadline,
    mut daemon: Command,
) -> (std::process::ChildStdin, std::process::ChildStdout) {
    let mut child = daemon
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("daemon starts");
    let requesting = child.stdin.take().expect("stdin");
    let answers = child.stdout.take().expect("stdout");
    deadline.watching(child);
    (requesting, answers)
}

/// As [`started`], with `requests` written to it and standard input still open.
fn asking(
    deadline: &Deadline,
    daemon: Command,
    requests: &[Value],
) -> (std::process::ChildStdin, std::process::ChildStdout) {
    let (mut requesting, answers) = started(deadline, daemon);
    for request in requests {
        writeln!(requesting, "{request}").expect("writable");
    }
    (requesting, answers)
}

/// Feeds every request in and sorts what came back: responses first.
fn drive(daemon: Command, requests: &[Value]) -> (Vec<Value>, Vec<Value>) {
    drive_within(daemon, requests, PATIENCE)
}

/// As [`drive`], with `patience` on the answer rather than [`PATIENCE`].
fn drive_within(
    daemon: Command,
    requests: &[Value],
    patience: std::time::Duration,
) -> (Vec<Value>, Vec<Value>) {
    let deadline = Deadline::within("the daemon to answer every request and exit", patience);
    let (requesting, mut answers) = asking(&deadline, daemon, requests);
    // The daemon reads to the end of its input, so the write end goes before
    // anything waits on the answers.
    drop(requesting);
    let mut out = Vec::new();
    let read = answers.read_to_end(&mut out);
    let _ = deadline.reap();
    deadline.check();
    read.expect("the daemon's output is readable");
    String::from_utf8_lossy(&out)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).expect("a JSON object per line"))
        .partition(|object| object.get("id").is_some())
}

#[test]
fn edits_are_buffered_until_commit_and_then_applied_at_once() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();
    let before = fs::read(&archive).expect("readable");

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(b"replaced")}}),
        json!({"jsonrpc":"2.0","id":3,"method":"pending","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":4,"method":"read","params":{
            "handle":1,"path":"data/greeting.txt"}}),
        json!({"jsonrpc":"2.0","id":5,"method":"commit","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":6,"method":"read","params":{
            "handle":1,"path":"data/greeting.txt"}}),
    ]);

    let by_id = |id: u64| -> Value {
        responses
            .iter()
            .find(|r| r["id"] == json!(id))
            .cloned()
            .unwrap_or_else(|| panic!("no response for {id}"))
    };

    assert_eq!(by_id(1)["result"]["handle"], json!(1));
    assert_eq!(by_id(3)["result"]["paths"], json!(["data/greeting.txt"]));

    let buffered = by_id(4);
    assert_eq!(
        buffered["result"]["pending"],
        json!(true),
        "a read should see the buffer"
    );
    let bytes = BASE64
        .decode(buffered["result"]["bytes"].as_str().expect("bytes"))
        .expect("base64");
    assert_eq!(bytes, b"replaced", "the buffer held something else");

    assert_eq!(by_id(5)["result"]["committed"], json!(1));

    let after_commit = by_id(6);
    assert_eq!(after_commit["result"]["pending"], json!(false));
    let bytes = BASE64
        .decode(after_commit["result"]["bytes"].as_str().expect("bytes"))
        .expect("base64");
    assert_eq!(bytes, b"replaced", "the commit did not take");

    assert_ne!(
        fs::read(&archive).expect("readable"),
        before,
        "the file did not change"
    );
}

#[test]
fn nothing_reaches_disk_before_commit() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();
    let before = fs::read(&archive).expect("readable");

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(b"replaced")}}),
        json!({"jsonrpc":"2.0","id":3,"method":"discard","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":4,"method":"commit","params":{"handle":1}}),
    ]);

    assert_eq!(responses[2]["result"]["discarded"], json!(1));
    assert_eq!(
        responses[3]["result"]["unchanged"],
        json!(true),
        "nothing to commit"
    );
    assert_eq!(
        fs::read(&archive).expect("readable"),
        before,
        "the file changed anyway"
    );
}

#[test]
fn a_resource_entry_takes_a_payload_its_own_archive_produced() {
    // A Rockstar resource payload does not begin with `RSC7`, so refusing an
    // incoming one that does not refuses every resource the reader hands out.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    let resource = make_rockstar_archive(&archive);
    let archive_str = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"read","params":{"handle":1,"path":"art.ydr"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"write","params":{
            "handle":1,"path":"art.ydr","bytes": BASE64.encode(&resource)}}),
        json!({"jsonrpc":"2.0","id":4,"method":"commit","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":5,"method":"verify","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":6,"method":"read","params":{"handle":1,"path":"art.ydr"}}),
    ]);

    let read = BASE64
        .decode(
            answer(&responses, 2)["result"]["bytes"]
                .as_str()
                .expect("bytes"),
        )
        .expect("base64");
    assert_eq!(
        read, resource,
        "the payload comes out as the archive holds it"
    );
    assert!(
        answer(&responses, 3).get("result").is_some(),
        "writing it back was refused: {:?}",
        answer(&responses, 3)
    );
    assert_eq!(answer(&responses, 4)["result"]["committed"], json!(1));

    // The row still declares what the payload is, which a byte comparison cannot
    // see: the flag words are the only record of its length.
    let verified = &answer(&responses, 5)["result"];
    assert_eq!(
        verified["problems"].as_array().map(Vec::len),
        Some(0),
        "the rebuilt archive does not read back: {verified}"
    );
    let again = BASE64
        .decode(
            answer(&responses, 6)["result"]["bytes"]
                .as_str()
                .expect("bytes"),
        )
        .expect("base64");
    assert_eq!(again, resource, "the bytes did not survive the round trip");
}

#[test]
fn a_resource_entry_refuses_a_payload_too_short_to_be_one() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_rockstar_archive(&archive);
    let archive_str = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"art.ydr","bytes": BASE64.encode(b"short")}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1}}),
    ]);

    assert_eq!(
        answer(&responses, 3)["error"]["code"],
        json!(6),
        "should have been refused: {:?}",
        answer(&responses, 3)
    );

    let short = dir.path().join("short.bin");
    fs::write(&short, b"short").expect("writable");
    let refused = Command::new(RPF)
        .args(["put", &archive_str, "art.ydr"])
        .arg(&short)
        .output()
        .expect("runs");
    assert_eq!(
        refused.status.code(),
        Some(6),
        "the command line disagreed: {}",
        String::from_utf8_lossy(&refused.stderr)
    );
}

#[test]
fn unknown_methods_and_handles_are_refused_not_ignored() {
    // Negative is JSON-RPC's own: the request did not follow the protocol.
    // Positive is the exit code the same failure has on the command line.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"nonsense","params":{}}),
        json!({"jsonrpc":"2.0","id":2,"method":"read","params":{"handle":99,"path":"x"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"open","params":{}}),
        json!({"jsonrpc":"2.0","id":4,"method":"read","params":{"handle":"one","path":"x"}}),
    ]);

    assert_eq!(answer(&responses, 1)["error"]["code"], json!(-32601));
    assert_eq!(answer(&responses, 2)["error"]["code"], json!(6));
    assert_eq!(answer(&responses, 3)["error"]["code"], json!(-32602));
    assert_eq!(answer(&responses, 4)["error"]["code"], json!(-32602));
    for response in &responses {
        assert!(
            response["error"]["message"].is_string(),
            "an error with nothing to act on: {response}"
        );
    }
}

#[test]
fn a_line_that_is_not_a_request_is_answered_with_a_null_id() {
    let responses = talk(&[
        json!("not an object at all"),
        json!({"jsonrpc":"2.0","id":2,"params":{}}),
    ]);

    assert_eq!(responses[0]["id"], json!(null));
    assert_eq!(responses[0]["error"]["code"], json!(-32600));
    assert_eq!(responses[1]["id"], json!(null));
    assert_eq!(responses[1]["error"]["code"], json!(-32600));
}

/// Feeds raw lines in, and returns the responses. [`talk`] can only send what
/// is JSON, and a line that is not is exactly what this wire has to classify.
fn talk_in_lines(lines: &[&str]) -> Vec<Value> {
    let deadline = Deadline::on("the daemon to answer every line and exit");
    let (mut requesting, mut answers) = started(&deadline, daemon());
    for line in lines {
        writeln!(requesting, "{line}").expect("writable");
    }
    drop(requesting);
    let mut out = Vec::new();
    let read = answers.read_to_end(&mut out);
    let _ = deadline.reap();
    deadline.check();
    read.expect("the daemon's output is readable");
    String::from_utf8_lossy(&out)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("a JSON object per line"))
        .collect()
}

/// The sign is the classification: negative is JSON-RPC's own protocol failure,
/// positive is the exit code the same failure has on the command line (DR-010),
/// and `data.reason` tells two protocol failures apart without the sentence.
#[test]
fn a_malformed_line_is_classified_by_which_protocol_rule_it_broke() {
    let responses = talk_in_lines(&[
        "not json at all",
        r#"[{"jsonrpc":"2.0","id":1,"method":"info"},{"jsonrpc":"2.0","id":2,"method":"info"}]"#,
        r#"{"jsonrpc":"2.0","id":1}"#,
    ]);

    assert_eq!(responses.len(), 3, "one answer per line: {responses:?}");
    let expected = [
        (-32700_i64, "ParseError"),
        (-32600, "InvalidRequest"),
        (-32600, "InvalidRequest"),
    ];
    for (answered, (code, reason)) in responses.iter().zip(expected) {
        assert_eq!(answered["error"]["code"], json!(code), "{answered}");
        assert_eq!(
            answered["error"]["data"]["reason"],
            json!(reason),
            "{answered}"
        );
        assert!(
            answered["error"]["code"]
                .as_i64()
                .is_some_and(|code| code < 0),
            "a protocol refusal is negative, and a positive one reads as an exit code: {answered}"
        );
    }
}

/// Bytes that do not compress, so no edit of them fits a spare block.
fn incompressible(len: u32) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i.wrapping_mul(2_654_435_761) >> 13) & 0xFF).unwrap_or_default())
        .collect()
}

#[test]
fn a_commit_that_fits_patches_in_place() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();
    let before = fs::read(&archive).expect("readable");

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(b"replaced")}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":4,"method":"read","params":{
            "handle":1,"path":"data/greeting.txt"}}),
    ]);

    assert_eq!(
        responses[2]["result"]["method"],
        json!("patch"),
        "{responses:?}"
    );
    assert_eq!(responses[2]["result"]["committed"], json!(1));

    let after = fs::read(&archive).expect("readable");
    assert_eq!(
        after.len(),
        before.len(),
        "a patch must not resize the archive"
    );

    let bytes = BASE64
        .decode(responses[3]["result"]["bytes"].as_str().expect("bytes"))
        .expect("base64");
    assert_eq!(bytes, b"replaced", "the commit did not take");
}

#[test]
fn a_commit_that_cannot_fit_rebuilds_instead() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let big = incompressible(200_000);
    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(&big)}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":4,"method":"read","params":{
            "handle":1,"path":"data/greeting.txt"}}),
    ]);

    assert_eq!(
        responses[2]["result"]["method"],
        json!("rebuild"),
        "{responses:?}"
    );
    let bytes = BASE64
        .decode(responses[3]["result"]["bytes"].as_str().expect("bytes"))
        .expect("base64");
    assert_eq!(bytes, big, "the rebuild did not take");
}

#[test]
fn an_edit_that_does_not_fit_holds_back_one_that_does() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    let resource = make_archive(&archive);
    let archive_str = archive.display().to_string();

    let big = incompressible(200_000);
    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(&big)}}),
        json!({"jsonrpc":"2.0","id":3,"method":"write","params":{
            "handle":1,"path":"art.yft","bytes": BASE64.encode(&resource)}}),
        json!({"jsonrpc":"2.0","id":4,"method":"commit","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":5,"method":"read","params":{
            "handle":1,"path":"data/greeting.txt"}}),
        json!({"jsonrpc":"2.0","id":6,"method":"read","params":{"handle":1,"path":"art.yft"}}),
    ]);

    assert_eq!(responses[3]["result"]["method"], json!("rebuild"));
    assert_eq!(responses[3]["result"]["committed"], json!(2));
    let greeting = BASE64
        .decode(responses[4]["result"]["bytes"].as_str().expect("bytes"))
        .expect("base64");
    assert_eq!(greeting, big);
    let art = BASE64
        .decode(responses[5]["result"]["bytes"].as_str().expect("bytes"))
        .expect("base64");
    assert_eq!(art, resource);
}

#[test]
fn a_commit_can_be_told_to_rebuild_even_when_it_could_patch() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(b"replaced")}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1,"rebuild":true}}),
    ]);

    assert_eq!(responses[2]["result"]["method"], json!("rebuild"));
}

#[test]
fn a_dry_run_commit_reports_what_it_would_do_and_keeps_the_edits() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();
    let before = fs::read(&archive).expect("readable");
    // Read from the archive rather than believed from the answer.
    let (at, allocation) = spans(&archive, "data/greeting.txt");

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(b"replaced")}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1,"dry_run":true}}),
        json!({"jsonrpc":"2.0","id":4,"method":"pending","params":{"handle":1}}),
    ]);

    let dry = &responses[2]["result"];
    assert_eq!(dry["method"], json!("patch"), "{dry}");
    assert_eq!(dry["dry_run"], json!(true));
    assert_eq!(dry["committed"], json!(0), "a dry run committed something");
    let planned = &dry["planned"][0];
    assert_eq!(planned["path"], json!("data/greeting.txt"), "{dry}");
    assert_eq!(planned["at"], json!(at), "{dry}");
    // Eight bytes deflate to more than eight, so the stored form wins and what
    // would be written is the edit itself.
    assert_eq!(planned["len"], json!(8), "{dry}");
    assert_eq!(planned["allocation"], json!(allocation), "{dry}");

    assert_eq!(
        responses[3]["result"]["paths"],
        json!(["data/greeting.txt"]),
        "the dry run dropped the buffered edit"
    );
    assert_eq!(
        fs::read(&archive).expect("readable"),
        before,
        "a dry run wrote to the archive"
    );
}

#[test]
fn a_dry_run_commit_says_when_it_would_rebuild_and_why() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let big = incompressible(200_000);
    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(&big)}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1,"dry_run":true}}),
    ]);

    let dry = &responses[2]["result"];
    assert_eq!(dry["method"], json!("rebuild"), "{dry}");
    assert_eq!(dry["dry_run"], json!(true));
    let rejected = &dry["rejected"][0];
    assert_eq!(rejected["path"], json!("data/greeting.txt"), "{dry}");
    assert!(
        rejected["needed"].as_u64().unwrap_or_default()
            > rejected["allocation"].as_u64().unwrap_or_default(),
        "that is not why it would rebuild: {dry}"
    );
}

#[test]
fn a_rebuild_reports_progress_as_notifications() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let (responses, notifications) = narrated(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(b"replaced")}}),
        // Rebuild rather than patch: a patch has nothing worth reporting.
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1,"rebuild":true}}),
    ]);

    assert_eq!(responses[2]["result"]["method"], json!("rebuild"));
    assert!(
        !notifications.is_empty(),
        "a rebuild reported nothing: {responses:?}"
    );
    for notification in &notifications {
        assert_eq!(notification["method"], json!("progress"), "{notification}");
        assert!(notification.get("id").is_none(), "{notification}");
        let params = &notification["params"];
        assert_eq!(params["handle"], json!(1));
        assert_eq!(params["total"], json!(2), "{notification}");
        assert_eq!(params["skipped"], json!(0), "{notification}");
    }

    let steps: Vec<(u64, &str)> = notifications
        .iter()
        .map(|n| {
            (
                n["params"]["done"].as_u64().unwrap_or_default(),
                n["params"]["path"].as_str().unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(
        steps,
        vec![(1, "art.yft"), (2, "data/greeting.txt")],
        "two files, so two steps, in entry order",
    );
}

#[test]
fn a_dry_run_commit_told_to_rebuild_says_so_and_keeps_the_edits() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();
    let before = fs::read(&archive).expect("readable");

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(b"replaced")}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{
            "handle":1,"rebuild":true,"dry_run":true}}),
        json!({"jsonrpc":"2.0","id":4,"method":"pending","params":{"handle":1}}),
    ]);

    let dry = &responses[2]["result"];
    assert_eq!(dry["method"], json!("rebuild"), "{dry}");
    assert_eq!(dry["dry_run"], json!(true), "{dry}");
    assert_eq!(dry["committed"], json!(0), "a dry run committed something");
    assert_eq!(
        responses[3]["result"]["paths"],
        json!(["data/greeting.txt"]),
        "the dry run dropped the buffered edit"
    );
    assert_eq!(
        fs::read(&archive).expect("readable"),
        before,
        "a dry run wrote to the archive"
    );
}

#[test]
fn a_cancel_with_nothing_running_is_answered_not_stored() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"cancel","params":{}}),
        json!({"jsonrpc":"2.0","id":3,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(b"replaced")}}),
        json!({"jsonrpc":"2.0","id":4,"method":"commit","params":{"handle":1,"rebuild":true}}),
    ]);

    let cancelled = answer(&responses, 2);
    assert_eq!(
        cancelled["result"]["cancelling"],
        json!(false),
        "there was nothing to cancel: {cancelled}"
    );
    let committed = answer(&responses, 4);
    assert_eq!(
        committed["result"]["committed"],
        json!(1),
        "a stored cancel took out the next commit: {committed}"
    );
}

#[test]
fn a_rebuild_can_be_cancelled_while_it_is_running() {
    // The whole reason standard input is read on its own thread: a cancel sent
    // while it is useful has to arrive then, not after.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("big.rpf");

    // Big enough, and incompressible enough, that the rebuild outlasts the
    // interval the cancels are sent at.
    let files: Vec<FileSpec> = (0..16)
        .map(|i| FileSpec {
            path: format!("bulk/{i:02}.bin"),
            kind: FileKind::Binary {
                storage: Storage::Deflate,
                encryption: 0,
            },
        })
        .collect();
    let bulk = incompressible(512 * 1024);
    let mut out = fs::File::create(&archive).expect("creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(bulk.clone())),
        &mut Unwatched,
    )
    .expect("builds");
    drop(out);
    let before = fs::read(&archive).expect("readable");

    let deadline = Deadline::on("the cancelled commit to answer");
    let (mut stdin, stdout) = started(&deadline, daemon());

    // Read on another thread: progress fills the pipe, and a daemon blocked
    // writing it would never reach the cancel.
    let (lines, received) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if lines.send(line).is_err() {
                break;
            }
        }
    });

    for request in [
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": archive.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"bulk/00.bin","bytes": BASE64.encode(b"replaced")}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1,"rebuild":true}}),
    ] {
        writeln!(stdin, "{request}").expect("writable");
    }

    // Short enough that the flag is set within one entry of the rebuild starting.
    let mut commit = None;
    while commit.is_none() {
        deadline.check();
        let cancel = json!({"jsonrpc":"2.0","id":900,"method":"cancel","params":{}});
        if writeln!(stdin, "{cancel}").is_err() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));

        while let Ok(line) = received.try_recv() {
            let object: Value = serde_json::from_str(&line).expect("a JSON object per line");
            if object["id"] == json!(3) {
                commit = Some(object);
            }
        }
    }
    drop(stdin);
    let commit = commit.expect("the commit answered");
    let _ = deadline.reap();
    let _ = reader.join();

    assert_eq!(
        commit["error"]["code"],
        json!(8),
        "a cancelled rebuild should report itself as one: {commit}"
    );
    assert_eq!(
        fs::read(&archive).expect("readable"),
        before,
        "a cancelled rebuild left something behind"
    );
}

/// An archive of `entries` files, each of `payload` zero bytes — enough
/// notifications on a rebuild to fill the 64 KB a pipe holds.
fn make_bulk_archive(at: &Path, entries: u32, payload: usize) {
    let files: Vec<FileSpec> = (0..entries)
        .map(|i| FileSpec {
            path: format!("bulk/{i:04}.bin"),
            kind: FileKind::Binary {
                storage: Storage::Deflate,
                encryption: 0,
            },
        })
        .collect();
    let bytes = vec![0_u8; payload];
    let mut out = fs::File::create(at).expect("creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(bytes.clone())),
        &mut Unwatched,
    )
    .expect("builds");
}

#[test]
fn a_change_that_collides_only_with_a_buffered_one_is_refused_when_it_is_offered() {
    let dir = tempfile::tempdir().expect("temp dir");

    let claimed = dir.path().join("claimed.rpf");
    make_archive(&claimed);
    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": claimed.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"rename","params":{
            "handle":1,"from":"art.yft","to":"moved.yft"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"write","params":{
            "handle":1,"path":"moved.yft","bytes": BASE64.encode(b"anything"),"create":true}}),
        json!({"jsonrpc":"2.0","id":4,"method":"pending","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":5,"method":"commit","params":{"handle":1}}),
    ]);
    assert_eq!(answer(&responses, 3)["error"]["code"], json!(6));
    assert_eq!(
        answer(&responses, 3)["error"]["data"]["reason"],
        json!("AlreadyExists"),
    );
    assert_eq!(answer(&responses, 4)["result"]["paths"], json!(["art.yft"]));
    assert_eq!(
        answer(&responses, 5)["result"]["committed"],
        json!(1),
        "the rename that was accepted did not commit: {:?}",
        answer(&responses, 5),
    );

    // Renaming a directory and then something inside it: `tree_of` applies
    // renames in path order, and the directory's runs first.
    let inside = dir.path().join("inside.rpf");
    make_archive(&inside);
    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": inside.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"rename","params":{
            "handle":1,"from":"data","to":"info"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"rename","params":{
            "handle":1,"from":"data/greeting.txt","to":"data/hello.txt"}}),
        json!({"jsonrpc":"2.0","id":4,"method":"commit","params":{"handle":1}}),
    ]);
    assert_eq!(
        answer(&responses, 3)["error"]["code"],
        json!(3),
        "the second rename was accepted: {:?}",
        answer(&responses, 3),
    );
    assert_eq!(answer(&responses, 4)["result"]["committed"], json!(1));
    let listed = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": inside.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"list","params":{"handle":1,"recursive":true}}),
    ]);
    let paths: Vec<&str> = answer(&listed, 2)["result"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|row| row["path"].as_str().expect("a path"))
        .collect();
    assert!(paths.contains(&"info/greeting.txt"), "{paths:?}");
}

/// Removals are applied before renames, so a replacing rename can be assembled.
#[test]
fn a_removal_in_the_same_session_frees_the_path_a_rename_moves_onto() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("replace.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"delete","params":{
            "handle":1,"path":"art.yft"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"rename","params":{
            "handle":1,"from":"data/greeting.txt","to":"art.yft"}}),
        json!({"jsonrpc":"2.0","id":4,"method":"commit","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":5,"method":"read","params":{"handle":1,"path":"art.yft"}}),
    ]);

    assert!(
        answer(&responses, 3)["error"].is_null(),
        "the rename onto the removed path was refused: {:?}",
        answer(&responses, 3),
    );
    assert_eq!(answer(&responses, 4)["result"]["committed"], json!(2));
    let bytes = BASE64
        .decode(
            answer(&responses, 5)["result"]["bytes"]
                .as_str()
                .expect("bytes"),
        )
        .expect("base64");
    assert_eq!(
        bytes, b"hello there",
        "the renamed entry did not land on the removed path"
    );
}

/// A change set holds one change per path.
#[test]
fn a_second_change_of_another_kind_at_one_path_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("claimed.rpf");
    let resource = make_archive(&archive);
    let archive_str = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"rename","params":{
            "handle":1,"from":"art.yft","to":"moved.yft"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"write","params":{
            "handle":1,"path":"art.yft","bytes": BASE64.encode(&resource)}}),
        json!({"jsonrpc":"2.0","id":4,"method":"pending","params":{"handle":1}}),
        // Two writes at one path are not this: an editor saves one file twice.
        json!({"jsonrpc":"2.0","id":5,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(b"once")}}),
        json!({"jsonrpc":"2.0","id":6,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(b"twice")}}),
        json!({"jsonrpc":"2.0","id":7,"method":"read","params":{
            "handle":1,"path":"data/greeting.txt"}}),
    ]);

    assert_eq!(answer(&responses, 3)["error"]["code"], json!(6));
    assert_eq!(
        answer(&responses, 3)["error"]["data"]["reason"],
        json!("Claimed"),
    );
    assert_eq!(
        answer(&responses, 4)["result"]["paths"],
        json!(["art.yft"]),
        "the rename was replaced by the write it refused",
    );
    assert!(
        answer(&responses, 6)["error"].is_null(),
        "a re-save was refused"
    );
    let bytes = BASE64
        .decode(
            answer(&responses, 7)["result"]["bytes"]
                .as_str()
                .expect("bytes"),
        )
        .expect("base64");
    assert_eq!(bytes, b"twice", "the second save is what the buffer holds");
}

#[test]
fn one_buffered_change_can_be_taken_back_without_discarding_the_rest() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("forget.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();
    let before = fs::read(&archive).expect("readable");

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(b"kept")}}),
        json!({"jsonrpc":"2.0","id":3,"method":"write","params":{
            "handle":1,"path":"scratch.txt","bytes": BASE64.encode(b"gone"),"create":true}}),
        json!({"jsonrpc":"2.0","id":4,"method":"forget","params":{
            "handle":1,"path":"scratch.txt"}}),
        // A path nothing is buffered at is not a failure, and says so.
        json!({"jsonrpc":"2.0","id":5,"method":"forget","params":{
            "handle":1,"path":"scratch.txt"}}),
        json!({"jsonrpc":"2.0","id":6,"method":"pending","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":7,"method":"commit","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":8,"method":"list","params":{"handle":1,"recursive":true}}),
    ]);

    assert_eq!(answer(&responses, 4)["result"]["forgotten"], json!(true));
    assert_eq!(answer(&responses, 4)["result"]["pending"], json!(1));
    assert_eq!(
        answer(&responses, 4)["result"]["paths"],
        json!(["data/greeting.txt"]),
    );
    assert_eq!(answer(&responses, 5)["result"]["forgotten"], json!(false));
    assert_eq!(
        answer(&responses, 6)["result"]["paths"],
        json!(["data/greeting.txt"]),
    );
    // The creation is gone, so the commit is a patch rather than a rebuild.
    assert_eq!(answer(&responses, 7)["result"]["method"], json!("patch"));
    assert_eq!(answer(&responses, 7)["result"]["committed"], json!(1));
    let paths: Vec<&str> = answer(&responses, 8)["result"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|row| row["path"].as_str().expect("a path"))
        .collect();
    assert!(!paths.contains(&"scratch.txt"), "{paths:?}");
    assert_ne!(fs::read(&archive).expect("readable"), before);
}

#[test]
fn a_rename_taken_back_frees_the_path_for_another_change() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("again.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"rename","params":{
            "handle":1,"from":"art.yft","to":"first.yft"}}),
        // Without taking the first back, this is one change replacing another.
        json!({"jsonrpc":"2.0","id":3,"method":"rename","params":{
            "handle":1,"from":"art.yft","to":"second.yft"}}),
        json!({"jsonrpc":"2.0","id":4,"method":"forget","params":{
            "handle":1,"path":"art.yft"}}),
        json!({"jsonrpc":"2.0","id":5,"method":"rename","params":{
            "handle":1,"from":"art.yft","to":"second.yft"}}),
        json!({"jsonrpc":"2.0","id":6,"method":"commit","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":7,"method":"list","params":{"handle":1,"recursive":true}}),
    ]);

    assert_eq!(answer(&responses, 3)["error"]["code"], json!(6));
    assert_eq!(
        answer(&responses, 3)["error"]["data"]["reason"],
        json!("Claimed"),
    );
    assert_eq!(answer(&responses, 4)["result"]["pending"], json!(0));
    assert!(
        answer(&responses, 5)["error"].is_null(),
        "{:?}",
        answer(&responses, 5)
    );
    assert_eq!(answer(&responses, 6)["result"]["committed"], json!(1));
    let paths: Vec<&str> = answer(&responses, 7)["result"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|row| row["path"].as_str().expect("a path"))
        .collect();
    assert!(paths.contains(&"second.yft"), "{paths:?}");
}

/// Over thousands of buffered writes, a walk of the entry table per write is quadratic.
#[test]
fn writes_beside_a_buffered_removal_do_not_each_walk_the_entry_table() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("many.rpf");
    make_bulk_archive(&archive, 4000, 512);

    let mut requests = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": archive.display().to_string()}}),
        // One structural change buffered, which is what makes every write
        // afterwards a candidate for the whole-set resolution.
        json!({"jsonrpc":"2.0","id":2,"method":"delete","params":{
            "handle":1,"path":"bulk/3999.bin"}}),
    ];
    for index in 0..3999_u64 {
        requests.push(
            json!({"jsonrpc":"2.0","id": 100 + index,"method":"write","params":{
            "handle":1,"path": format!("bulk/{index:04}.bin"),
            "bytes": BASE64.encode(vec![9_u8; 512])}}),
        );
    }
    requests.push(json!({"jsonrpc":"2.0","id":9,"method":"pending","params":{"handle":1}}));

    let responses = talk(&requests);
    assert!(answer(&responses, 2)["error"].is_null());
    assert_eq!(
        answer(&responses, 9)["result"]["paths"]
            .as_array()
            .expect("paths")
            .len(),
        4000,
        "not every write was buffered",
    );
    let reached = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": archive.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"delete","params":{
            "handle":1,"path":"bulk","recursive":true}}),
        json!({"jsonrpc":"2.0","id":3,"method":"write","params":{
            "handle":1,"path":"bulk/0000.bin","bytes": BASE64.encode(b"late")}}),
    ]);
    assert_eq!(
        answer(&reached, 3)["error"]["code"],
        json!(3),
        "{:?}",
        answer(&reached, 3),
    );
}

#[test]
fn an_error_names_the_failure_beside_the_number() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("named.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        // Two refusals that share exit 6 and have nothing else in common.
        json!({"jsonrpc":"2.0","id":2,"method":"mkdir","params":{"handle":1,"path":"data"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"delete","params":{"handle":1,"path":"data"}}),
        json!({"jsonrpc":"2.0","id":4,"method":"read","params":{"handle":1,"path":"nowhere"}}),
        json!({"jsonrpc":"2.0","id":5,"method":"nonesuch","params":{}}),
    ]);

    for (id, code, reason) in [
        (2_u64, 6_i64, "AlreadyExists"),
        (3, 6, "BadPath"),
        (4, 3, "NotFound"),
        (5, -32601, "MethodNotFound"),
    ] {
        let object = answer(&responses, id);
        assert_eq!(object["error"]["code"], json!(code), "{object}");
        assert_eq!(object["error"]["data"]["reason"], json!(reason), "{object}");
    }
}

#[test]
fn a_failure_is_the_same_object_on_both_frontends() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("agreeing.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"read","params":{"handle":1,"path":"nowhere"}}),
    ]);
    let daemon = answer(&responses, 2)["error"].clone();

    let output = Command::new(RPF)
        .args(["--json", "cat", &archive_str, "nowhere"])
        .output()
        .expect("binary runs");
    let command_line: Value =
        serde_json::from_slice(&output.stderr).expect("one JSON object on standard error");

    assert_eq!(command_line, daemon, "the frontends have drifted");
    assert_eq!(
        output.status.code(),
        Some(3),
        "and the code is the object's"
    );
}

#[test]
fn a_second_session_on_one_archive_is_refused_rather_than_detected_later() {
    // Two sessions on one archive: the first rebuilds and every offset moves,
    // while the second still holds the entry table it parsed at open.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();
    let big = incompressible(200_000);

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":3,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(&big)}}),
        json!({"jsonrpc":"2.0","id":4,"method":"commit","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":5,"method":"close","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":6,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":7,"method":"read","params":{
            "handle":2,"path":"data/greeting.txt"}}),
    ]);

    let refused = answer(&responses, 2);
    assert_eq!(refused["error"]["code"], json!(6), "{refused}");
    let message = refused["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("handle 1"),
        "the refusal must name the handle holding it: {message}"
    );

    let rebuilt = answer(&responses, 4);
    assert_eq!(rebuilt["result"]["method"], json!("rebuild"), "{rebuilt}");
    assert_eq!(answer(&responses, 5)["result"]["closed"], json!(true));

    // A refused open takes no handle with it: the next one is 2, not 3.
    let reopened = answer(&responses, 6);
    assert_eq!(reopened["result"]["handle"], json!(2), "{reopened}");
    let fresh = answer(&responses, 7);
    let bytes = BASE64
        .decode(fresh["result"]["bytes"].as_str().expect("bytes"))
        .expect("base64");
    assert_eq!(bytes, big, "the commit did not take");
}

#[test]
fn a_claim_is_on_the_archive_and_not_on_the_spelling_of_its_path() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("canonical temp dir");
    make_archive(&root.join("test.rpf"));
    fs::create_dir(root.join("sub")).expect("subdirectory");
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.join("test.rpf"), root.join("link.rpf")).expect("symlink");

    let mut spellings = vec![
        "test.rpf".to_owned(),
        "./test.rpf".to_owned(),
        "sub/../test.rpf".to_owned(),
        root.join("test.rpf").display().to_string(),
        root.join(".").join("test.rpf").display().to_string(),
    ];
    // `cfg!` rather than `#[cfg]`: an attribute removes the push outright, which
    // leaves the binding needlessly mutable on Windows.
    if cfg!(unix) {
        spellings.push("link.rpf".to_owned());
    }

    let mut requests =
        vec![json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path":"test.rpf"}})];
    for (offset, spelling) in spellings.iter().enumerate() {
        let id = 2 + u64::try_from(offset).unwrap_or_default();
        requests.push(json!({"jsonrpc":"2.0","id":id,"method":"open","params":{"path":spelling}}));
    }
    let responses = talk_in(&root, &requests);

    let opened = answer(&responses, 1);
    assert_eq!(opened["result"]["handle"], json!(1), "{opened}");
    assert_eq!(
        opened["result"]["path"],
        json!(root.join("test.rpf").display().to_string()),
        "open reports the path it resolved and claimed: {opened}"
    );
    for (offset, spelling) in spellings.iter().enumerate() {
        let id = 2 + u64::try_from(offset).unwrap_or_default();
        let refused = answer(&responses, id);
        assert_eq!(
            refused["error"]["code"],
            json!(6),
            "{spelling} was not recognised as the archive already open: {refused}"
        );
        let message = refused["error"]["message"].as_str().unwrap_or_default();
        // Every spelling here resolves to the one path the session claimed, the
        // symlink included, so the refusal names one name and not two.
        assert!(
            message.contains(&format!(
                "{} is already open on handle 1",
                root.join("test.rpf").display()
            )),
            "{spelling}: {message}"
        );
        assert!(
            !message.contains("another name for"),
            "one spelling was reported as two: {spelling}: {message}"
        );
    }
}

#[test]
fn an_archive_that_cannot_be_resolved_is_an_ordinary_open_failure() {
    let dir = tempfile::tempdir().expect("temp dir");
    let missing = dir.path().join("nowhere.rpf").display().to_string();

    let responses =
        talk(&[json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": missing}})]);

    let refused = answer(&responses, 1);
    assert_eq!(refused["error"]["code"], json!(7), "{refused}");
    let message = refused["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("nowhere.rpf"), "{message}");
}

#[test]
fn a_cancel_that_names_another_operation_does_not_stop_this_one() {
    // Sessions are per-handle, so a cancel names what it is cancelling: the
    // request that started it, or the handle it is running against.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("big.rpf");
    let files: Vec<FileSpec> = (0..16)
        .map(|i| FileSpec {
            path: format!("bulk/{i:02}.bin"),
            kind: FileKind::Binary {
                storage: Storage::Deflate,
                encryption: 0,
            },
        })
        .collect();
    let bulk = incompressible(512 * 1024);
    let mut out = fs::File::create(&archive).expect("creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(bulk.clone())),
        &mut Unwatched,
    )
    .expect("builds");
    drop(out);

    let deadline = Deadline::on("the commit to answer past the cancels aimed elsewhere");
    let (mut stdin, stdout) = started(&deadline, daemon());

    let (lines, received) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if lines.send(line).is_err() {
                break;
            }
        }
    });

    for request in [
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": archive.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"bulk/00.bin","bytes": BASE64.encode(b"replaced")}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1,"rebuild":true}}),
    ] {
        writeln!(stdin, "{request}").expect("writable");
    }

    let mut commit = None;
    let mut answers = Vec::new();
    while commit.is_none() {
        deadline.check();
        // Request 2 finished long ago, and handle 2 was never opened. Neither
        // names the rebuild that is running.
        let aimed_elsewhere = [
            json!({"jsonrpc":"2.0","id":900,"method":"cancel","params":{"request":2}}),
            json!({"jsonrpc":"2.0","id":901,"method":"cancel","params":{"handle":2}}),
        ];
        if aimed_elsewhere
            .iter()
            .any(|cancel| writeln!(stdin, "{cancel}").is_err())
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));

        while let Ok(line) = received.try_recv() {
            let object: Value = serde_json::from_str(&line).expect("a JSON object per line");
            if object["id"] == json!(3) {
                commit = Some(object);
            } else if object["id"] == json!(900) || object["id"] == json!(901) {
                answers.push(object);
            }
        }
    }
    drop(stdin);
    let commit = commit.expect("the commit answered");
    let _ = deadline.reap();
    let _ = reader.join();

    assert_eq!(
        commit["result"]["method"],
        json!("rebuild"),
        "a cancel aimed elsewhere stopped this commit: {commit}"
    );
    for object in &answers {
        assert_eq!(
            object["result"]["cancelling"],
            json!(false),
            "a cancel naming something else claimed to be cancelling: {object}"
        );
    }
    assert!(
        answers
            .iter()
            .any(|object| object["result"]["running"] == json!("rebuild")),
        "no cancel arrived while the rebuild was running: {answers:?}"
    );
}

#[test]
fn a_cancel_after_a_commit_has_answered_finds_nothing_running() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);

    // The cancel goes out only once the commit has answered, so it cannot race
    // the rebuild it would otherwise be naming.
    let deadline = Deadline::on("the rebuilding commit to answer");
    let (mut stdin, answers) = asking(
        &deadline,
        daemon(),
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
                "path": archive.display().to_string()}}),
            json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
                "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(b"replaced")}}),
            json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{
                "handle":1,"rebuild":true}}),
        ],
    );
    let mut lines = std::io::BufReader::new(answers).lines();
    let mut committed = None;
    while committed.is_none() {
        deadline.check();
        let line = lines.next().expect("the daemon answered").expect("a line");
        let object: Value = serde_json::from_str(&line).expect("a JSON object per line");
        if object["id"] == json!(3) {
            committed = Some(object);
        }
    }
    assert_eq!(
        committed.unwrap_or_default()["result"]["method"],
        json!("rebuild")
    );

    writeln!(
        stdin,
        "{}",
        json!({"jsonrpc":"2.0","id":4,"method":"cancel","params":{}})
    )
    .expect("writable");
    drop(stdin);

    let mut answered = None;
    for line in lines {
        let Ok(line) = line else { break };
        let object: Value = serde_json::from_str(&line).expect("a JSON object per line");
        if object["id"] == json!(4) {
            answered = Some(object);
        }
    }
    let answered = answered.expect("the cancel was answered");
    assert_eq!(
        answered["result"],
        json!({ "cancelling": false, "running": Value::Null }),
        "a finished commit was still registered as the thing to cancel: {answered}"
    );
    let _ = deadline.reap();
}

/// How many entries the rebuild in the drop test walks. The gate is half the
/// archive's bytes, which is past what any of the three platforms' pipes hold.
const BULK_ENTRIES: u32 = 3000;

/// What an atomic replacement changes about the file it replaces: another file
/// of the same length still carries the moment it was written.
fn stamp(file: &Path) -> (u64, Option<std::time::SystemTime>) {
    fs::metadata(file).map_or((0, None), |it| (it.len(), it.modified().ok()))
}

/// Waits until the rebuild writing beside `archive` has put `bytes` into its
/// scratch file — entries go in order — or until it has finished, which is the
/// stronger of the two: nothing was read while all of it was written.
fn written_past(directory: &Path, archive: &Path, bytes: u64, deadline: &Deadline) {
    let before = stamp(archive);
    let mut seen = false;
    loop {
        deadline.check();
        // Asked of the path, not of the directory entry: Windows answers the
        // entry from a size it does not update while the writer holds the file.
        let scratch = fs::read_dir(directory)
            .expect("the directory is readable")
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.as_path() != archive)
            .map(|path| fs::metadata(path).map_or(0, |it| it.len()))
            .max()
            .unwrap_or_default();
        if scratch >= bytes {
            return;
        }
        // The rebuild is over: either it landed, or its scratch went away
        // unwritten. The first is a stronger pass than the wait asked for, the
        // second is a failure the daemon's own answer will name.
        if stamp(archive) != before || (seen && scratch == 0) {
            return;
        }
        seen |= scratch > 0;
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

#[test]
fn a_client_that_is_behind_is_told_how_many_notifications_it_missed() {
    // Progress is dropped rather than queued without bound, so `skipped` counts
    // what was dropped since the last notification that got through.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("many.rpf");
    let building = std::time::Instant::now();
    make_bulk_archive(&archive, BULK_ENTRIES, 1024);
    let len = fs::metadata(&archive).expect("readable").len();

    // Started once the archive is, and paced by it: the rebuild walks the same
    // entries again, so building them measured this box's rate for the work.
    let deadline = Deadline::within(
        "the daemon to exit after its notifications",
        repeating(building.elapsed()),
    );
    let (mut stdin, mut stdout) = started(&deadline, daemon());
    for request in [
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": archive.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"bulk/0000.bin","bytes": BASE64.encode(b"replaced")}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1,"rebuild":true}}),
    ] {
        writeln!(stdin, "{request}").expect("writable");
    }
    drop(stdin);

    // Nothing is read until the rebuild is half written, so the drop is this
    // test's doing rather than a race a loaded machine decides.
    written_past(dir.path(), &archive, len / 2, &deadline);
    let mut read = Vec::new();
    stdout.read_to_end(&mut read).expect("readable");

    let status = deadline.reap().expect("the daemon exits");
    assert!(status.success(), "the daemon exited with {status}");

    let text = String::from_utf8_lossy(&read).into_owned();
    let steps: Vec<(u64, u64)> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("a JSON object per line"))
        .filter(|object| object["method"] == json!("progress"))
        .map(|object| {
            let params = &object["params"];
            (
                params["done"].as_u64().expect("a step number"),
                params["skipped"].as_u64().expect("a dropped count"),
            )
        })
        .collect();

    let mut previous = 0_u64;
    let mut dropped = 0_u64;
    for (done, skipped) in &steps {
        assert_eq!(
            *skipped,
            done.saturating_sub(previous).saturating_sub(1),
            "step {done} followed step {previous} but claims {skipped} dropped: {steps:?}",
        );
        dropped = dropped.saturating_add(*skipped);
        previous = *done;
    }
    assert!(
        dropped > 0,
        "the rebuild was half written into a pipe nobody had read, and nothing \
         was dropped: {} of {BULK_ENTRIES} arrived",
        steps.len(),
    );
}

#[test]
fn a_broken_standard_output_is_reported_rather_than_swallowed() {
    let deadline = Deadline::on("the daemon to exit on its broken standard output");
    // Enough cancels that the answers cannot all have been written into a pipe
    // nobody is reading, so the reading end closes on a write still in flight.
    // Hand-rolled rather than `started`, because the complaint is a third pipe
    // and the reading end of the second is closed part way through.
    let mut child = daemon()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("daemon starts");
    let mut stdin = child.stdin.take().expect("stdin");
    let answers = child.stdout.take().expect("stdout");
    let mut complained = child.stderr.take().expect("stderr");
    deadline.watching(child);
    let feeding = std::thread::spawn(move || {
        let cancel = json!({"jsonrpc":"2.0","id":1,"method":"cancel","params":{}});
        for _ in 0..4000 {
            if writeln!(stdin, "{cancel}").is_err() {
                break;
            }
        }
    });
    std::thread::sleep(std::time::Duration::from_millis(300));
    drop(answers);

    let status = deadline.reap().expect("the daemon exits");
    let _ = feeding.join();
    let mut complaint = String::new();
    let _ = std::io::Read::read_to_string(&mut complained, &mut complaint);

    assert_eq!(
        status.code(),
        Some(7),
        "a broken standard output is an i/o failure, not a success: {complaint}"
    );
    assert!(
        complaint.contains("<stdout>"),
        "the daemon said nothing about why it stopped: {complaint}"
    );
    assert!(
        !complaint.contains("cancelled"),
        "a broken pipe was reported as a cancellation: {complaint}"
    );
}

#[test]
fn a_rebuild_whose_output_breaks_is_an_io_failure_and_not_a_cancellation() {
    let deadline = Deadline::on("the rebuild to give up on its broken output");
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("many.rpf");
    make_bulk_archive(&archive, 4000, 1024);

    // Hand-rolled rather than `started`, for the same two reasons as the test
    // above: a third pipe, and a second one closed part way through.
    let mut child = daemon()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("daemon starts");
    let mut stdin = child.stdin.take().expect("stdin");
    let answers = child.stdout.take().expect("stdout");
    let mut complained = child.stderr.take().expect("stderr");
    deadline.watching(child);
    for request in [
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": archive.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"bulk/0000.bin","bytes": BASE64.encode(b"replaced")}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1,"rebuild":true}}),
    ] {
        writeln!(stdin, "{request}").expect("writable");
    }
    // The pipe holds the first notifications; closing the reading end turns the
    // next write into a broken pipe, which is the moment the rebuild gives up.
    std::thread::sleep(std::time::Duration::from_millis(50));
    drop(answers);
    // And standard input ends, because nothing more is coming: what is under
    // test is what the daemon exits with, not when.
    drop(stdin);

    let status = deadline.reap().expect("the daemon exits");
    let mut complaint = String::new();
    let _ = std::io::Read::read_to_string(&mut complained, &mut complaint);

    assert_eq!(
        status.code(),
        Some(7),
        "a rebuild that lost its output is an i/o failure, not a cancellation: {complaint}"
    );
    assert!(
        complaint.contains("<stdout>"),
        "the daemon said nothing about why it stopped: {complaint}"
    );
    assert!(
        !complaint.contains("cancelled"),
        "a broken pipe was reported as a cancellation nobody asked for: {complaint}"
    );
}

#[test]
fn a_request_with_no_id_is_a_notification_and_is_not_answered() {
    // JSON-RPC forbids answering one, and `"id": null` is what a parse error means.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let (responses, notifications) = narrated(&[
        json!({"jsonrpc":"2.0","method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"pending","params":{"handle":1}}),
    ]);

    assert_eq!(
        responses.len(),
        1,
        "the notification was answered: {responses:?}"
    );
    assert_eq!(responses[0]["id"], json!(2));
    assert_eq!(
        responses[0]["result"]["paths"],
        json!([]),
        "the notification was not acted on: {responses:?}"
    );
    assert!(notifications.is_empty(), "{notifications:?}");
}

#[test]
fn progress_can_be_turned_off_for_one_commit() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let (responses, notifications) = narrated(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(b"replaced")}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{
            "handle":1,"rebuild":true,"progress":false}}),
    ]);

    assert_eq!(responses[2]["result"]["method"], json!("rebuild"));
    assert!(
        notifications.is_empty(),
        "progress was reported to a caller that asked for none: {notifications:?}"
    );
}

#[test]
fn a_cancel_parameter_that_is_ill_typed_is_refused_not_read_as_absent() {
    // `cancel` with no parameters means "whatever is running", the destructive
    // default, so a parameter given but not read must not degrade to it.
    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"cancel","params":{"handle":"2"}}),
        json!({"jsonrpc":"2.0","id":2,"method":"cancel","params":{"handle":2.0}}),
        json!({"jsonrpc":"2.0","id":3,"method":"cancel","params":{"handle":-1}}),
        json!({"jsonrpc":"2.0","id":4,"method":"cancel","params":{"handle":null}}),
        json!({"jsonrpc":"2.0","id":5,"method":"cancel","params":{"handel":2}}),
        json!({"jsonrpc":"2.0","id":6,"method":"cancel","params":"not-an-object"}),
        json!({"jsonrpc":"2.0","id":7,"method":"cancel","params":{"handle":[2]}}),
        json!({"jsonrpc":"2.0","id":8,"method":"cancel","params":{"handle":2}}),
        json!({"jsonrpc":"2.0","id":9,"method":"cancel","params":{}}),
        json!({"jsonrpc":"2.0","id":10,"method":"cancel"}),
    ]);

    for id in 1..=7 {
        let refused = answer(&responses, id);
        assert_eq!(
            refused["error"]["code"],
            json!(-32602),
            "an ill-typed cancel was acted on: {refused}"
        );
        assert!(
            refused.get("result").is_none(),
            "a refused cancel answered as though it had acted: {refused}"
        );
    }
    for id in 8..=10 {
        let answered = answer(&responses, id);
        assert_eq!(answered["result"]["cancelling"], json!(false), "{answered}");
        assert_eq!(answered["result"]["running"], json!(null), "{answered}");
    }
}

#[test]
fn an_ill_typed_cancel_does_not_stop_the_rebuild_it_failed_to_name() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("big.rpf");
    let files: Vec<FileSpec> = (0..16)
        .map(|i| FileSpec {
            path: format!("bulk/{i:02}.bin"),
            kind: FileKind::Binary {
                storage: Storage::Deflate,
                encryption: 0,
            },
        })
        .collect();
    let bulk = incompressible(512 * 1024);
    let mut out = fs::File::create(&archive).expect("creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(bulk.clone())),
        &mut Unwatched,
    )
    .expect("builds");
    drop(out);

    let deadline = Deadline::on("the commit to answer past the ill-typed cancels");
    let (mut stdin, stdout) = started(&deadline, daemon());

    let (lines, received) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if lines.send(line).is_err() {
                break;
            }
        }
    });

    for request in [
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": archive.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"bulk/00.bin","bytes": BASE64.encode(b"replaced")}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1,"rebuild":true}}),
    ] {
        writeln!(stdin, "{request}").expect("writable");
    }

    let mut commit = None;
    let mut answers = Vec::new();
    while commit.is_none() {
        deadline.check();
        // Each of these names handle 2, in a way the daemon did not read.
        let ill_typed = [
            json!({"jsonrpc":"2.0","id":900,"method":"cancel","params":{"handle":"2"}}),
            json!({"jsonrpc":"2.0","id":901,"method":"cancel","params":{"handle":2.0}}),
            json!({"jsonrpc":"2.0","id":902,"method":"cancel","params":{"handle":-1}}),
            json!({"jsonrpc":"2.0","id":903,"method":"cancel","params":{"handle":null}}),
            json!({"jsonrpc":"2.0","id":904,"method":"cancel","params":{"handel":2}}),
            json!({"jsonrpc":"2.0","id":905,"method":"cancel","params":"not-an-object"}),
        ];
        if ill_typed
            .iter()
            .any(|cancel| writeln!(stdin, "{cancel}").is_err())
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));

        while let Ok(line) = received.try_recv() {
            let object: Value = serde_json::from_str(&line).expect("a JSON object per line");
            if object["id"] == json!(3) {
                commit = Some(object);
            } else if (900..=905).contains(&object["id"].as_u64().unwrap_or_default()) {
                answers.push(object);
            }
        }
    }
    drop(stdin);
    let commit = commit.expect("the commit answered");
    let _ = deadline.reap();
    let _ = reader.join();

    assert_eq!(
        commit["result"]["method"],
        json!("rebuild"),
        "an ill-typed cancel stopped a commit it had not named: {commit}"
    );
    assert!(!answers.is_empty(), "no cancel was answered at all");
    for object in &answers {
        assert_eq!(
            object["error"]["code"],
            json!(-32602),
            "an ill-typed cancel was acted on: {object}"
        );
    }
}

/// Reads everything on `stdout`, taking `piece` bytes and then pausing — an
/// ordinary client, reading at an ordinary rate.
fn read_slowly(
    stdout: &mut std::process::ChildStdout,
    piece: usize,
    pause: std::time::Duration,
    deadline: &Deadline,
) -> Vec<u8> {
    use std::io::Read as _;
    let mut all = Vec::new();
    let mut buffer = vec![0_u8; piece];
    loop {
        deadline.check();
        match stdout.read(&mut buffer) {
            Ok(0) | Err(_) => return all,
            Ok(taken) => all.extend_from_slice(buffer.get(..taken).unwrap_or_default()),
        }
        std::thread::sleep(pause);
    }
}

#[test]
fn an_answer_bigger_than_the_grace_survives_standard_input_ending() {
    let deadline = Deadline::on("the answer that outlasts standard input ending");
    // Standard input ends long before the answer to the last request is written.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("one.rpf");
    make_bulk_archive(&archive, 1, 512 * 1024);

    let (requesting, mut answers) = asking(
        &deadline,
        daemon(),
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
                "path": archive.display().to_string()}}),
            json!({"jsonrpc":"2.0","id":2,"method":"read","params":{
                "handle":1,"path":"bulk/0000.bin"}}),
        ],
    );
    // And standard input ends here, with the answer not yet written.
    drop(requesting);
    let taken = read_slowly(
        &mut answers,
        8 * 1024,
        std::time::Duration::from_millis(40),
        &deadline,
    );
    let status = deadline.reap().expect("the daemon exits");

    assert!(
        status.success(),
        "the daemon reported a failure delivering an answer to a client that was reading: {status}"
    );
    assert_eq!(
        taken.last().copied(),
        Some(b'\n'),
        "the last line was cut off with no terminating newline: {} bytes",
        taken.len()
    );
    let text = String::from_utf8(taken).expect("utf-8");
    let objects: Vec<Value> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("a JSON object per line"))
        .collect();
    let answered = answer(&objects, 2);
    assert_eq!(
        answered["result"]["len"],
        json!(512 * 1024),
        "the answer arrived, but not whole"
    );
    let bytes = BASE64
        .decode(answered["result"]["bytes"].as_str().expect("bytes"))
        .expect("base64");
    assert_eq!(bytes, vec![0_u8; 512 * 1024], "the entry came back wrong");
}

/// The resident size of a running process, in kilobytes.
#[cfg(unix)]
fn resident_kilobytes(pid: u32) -> u64 {
    let reported = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .expect("ps runs");
    String::from_utf8_lossy(&reported.stdout)
        .trim()
        .parse()
        .expect("ps reports a resident size")
}

#[test]
fn answers_do_not_pile_up_for_a_client_that_is_not_reading() {
    // A queued response the worker never waits on grows without bound while the
    // client is behind. Zero-byte payloads, so each answer is still megabytes.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("bulk.rpf");
    let entry = 2 * 1024 * 1024;
    let building = std::time::Instant::now();
    make_bulk_archive(&archive, 64, entry);

    // Started once the archive is, and paced by it: answering these reads is
    // those same bytes again, so building them measured this box's rate.
    let deadline = Deadline::within(
        "the daemon to exit once its answers are drained",
        repeating(building.elapsed()),
    );
    let (mut stdin, stdout) = started(&deadline, daemon());

    writeln!(
        stdin,
        "{}",
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": archive.display().to_string()}})
    )
    .expect("writable");
    for i in 0..64_u64 {
        let request = json!({"jsonrpc":"2.0","id": 100 + i,"method":"read","params":{
            "handle":1,"path": format!("bulk/{i:04}.bin")}});
        writeln!(stdin, "{request}").expect("writable");
    }
    // Nothing has read a byte of standard output, and nothing will for three
    // seconds — far longer than answering all sixty-four takes.
    std::thread::sleep(std::time::Duration::from_secs(3));
    #[cfg(unix)]
    {
        let resident = resident_kilobytes(deadline.pid().expect("the daemon is running"));
        assert!(
            resident < 96 * 1024,
            "the daemon is holding {resident} KB of answers for a client that is not reading"
        );
    }

    // An answer may wait, and may never be dropped.
    let drain = std::thread::spawn(move || {
        let mut objects = Vec::new();
        for line in std::io::BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() {
                continue;
            }
            objects.push(serde_json::from_str::<Value>(&line).expect("a JSON object per line"));
        }
        objects
    });
    drop(stdin);
    let status = deadline.reap().expect("the daemon exits");
    let objects = drain.join().expect("the draining thread finished");
    assert!(status.success(), "the daemon exited with {status}");

    for i in 0..64_u64 {
        let answered = answer(&objects, 100 + i);
        assert_eq!(
            answered["result"]["len"],
            json!(entry),
            "answer {i} was dropped or truncated: {answered}"
        );
    }
}

#[test]
#[cfg(any(unix, windows))]
fn a_second_name_for_one_file_is_the_same_archive() {
    // Both spellings of a hard link canonicalise to themselves, so a path-keyed
    // claim accepts both: it needs a volume that gives its files an identity.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let alias = dir.path().join("alias.rpf");
    fs::hard_link(&archive, &alias).expect("hard link");

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": archive.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"open","params":{
            "path": alias.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":3,"method":"close","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":4,"method":"open","params":{
            "path": alias.display().to_string()}}),
    ]);

    let refused = answer(&responses, 2);
    assert_eq!(
        refused["error"]["code"],
        json!(6),
        "a second name for one file opened a second session: {refused}"
    );
    let message = refused["error"]["message"].as_str().unwrap_or_default();
    // Two names for one file, and the refusal names both: the one asked for and
    // the one the holder claimed.
    assert!(
        message.contains(&format!(
            "{} is another name for {}, which is already open on handle 1",
            alias.canonicalize().expect("canonical").display(),
            archive.canonicalize().expect("canonical").display(),
        )),
        "the refusal must name both spellings and the handle holding it: {message}"
    );
    assert_eq!(answer(&responses, 3)["result"]["closed"], json!(true));
    assert_eq!(
        answer(&responses, 4)["result"]["handle"],
        json!(2),
        "closing the claim did not release it"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn a_firmlink_spelling_is_the_same_archive() {
    // Every macOS since Catalina gives every writable file a second true
    // canonical path under `/System/Volumes/Data`, on the same device and inode.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let resolved = archive.canonicalize().expect("canonical");
    let firmlinked =
        Path::new("/System/Volumes/Data").join(resolved.strip_prefix("/").expect("absolute"));
    if !firmlinked.exists() {
        eprintln!(
            "skipped: {} has no firmlink spelling under /System/Volumes/Data",
            resolved.display()
        );
        return;
    }
    assert_ne!(
        firmlinked.canonicalize().expect("canonical"),
        resolved,
        "both spellings resolve alike here, so the path alone would have caught it"
    );

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": resolved.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"open","params":{
            "path": firmlinked.display().to_string()}}),
    ]);

    let refused = answer(&responses, 2);
    assert_eq!(
        refused["error"]["code"],
        json!(6),
        "the firmlink spelling opened a second session on one archive: {refused}"
    );
    let message = refused["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("handle 1"), "{message}");
}

#[test]
#[cfg(any(unix, windows))]
fn a_session_still_holds_its_archive_after_its_own_rebuild() {
    // A rebuild replaces the archive by rename, so the file the session holds
    // afterwards is a different inode: a claim must follow identity, not keep it.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();
    let big = incompressible(200_000);

    let deadline = Deadline::on("the commit that precedes the second name to answer");
    let (mut stdin, answers) = asking(
        &deadline,
        daemon(),
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
            json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
                "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(&big)}}),
            json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1}}),
        ],
    );
    // The commit is read before the second name is made, so the link is made
    // against the inode the rebuild left rather than the one it replaced.
    let mut lines = std::io::BufReader::new(answers);
    let committed = loop {
        deadline.check();
        let mut line = String::new();
        assert!(
            lines.read_line(&mut line).expect("readable") > 0,
            "the commit never answered"
        );
        let object: Value = serde_json::from_str(line.trim()).expect("a JSON object per line");
        if object["id"] == json!(3) {
            break object;
        }
    };
    assert_eq!(
        committed["result"]["method"],
        json!("rebuild"),
        "{committed}"
    );

    let alias = dir.path().join("alias.rpf");
    fs::hard_link(&archive, &alias).expect("hard link");
    for request in [
        json!({"jsonrpc":"2.0","id":4,"method":"open","params":{
            "path": alias.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":5,"method":"read","params":{
            "handle":1,"path":"data/greeting.txt"}}),
    ] {
        writeln!(stdin, "{request}").expect("writable");
    }
    drop(stdin);

    let mut rest = Vec::new();
    for line in lines.lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        rest.push(serde_json::from_str::<Value>(&line).expect("a JSON object per line"));
    }
    let _ = deadline.reap();

    let refused = answer(&rest, 4);
    assert_eq!(
        refused["error"]["code"],
        json!(6),
        "the session stopped recognising the archive its own rebuild left: {refused}"
    );
    assert!(
        refused["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("handle 1"),
        "{refused}"
    );
    let bytes = BASE64
        .decode(answer(&rest, 5)["result"]["bytes"].as_str().expect("bytes"))
        .expect("base64");
    assert_eq!(bytes, big, "the session lost its own archive");
}

#[test]
fn close_on_a_handle_that_was_never_open_is_refused() {
    // Every other method answers code 6 for the same handle.
    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"close","params":{"handle":99}}),
        json!({"jsonrpc":"2.0","id":2,"method":"pending","params":{"handle":99}}),
    ]);

    let refused = answer(&responses, 1);
    assert_eq!(refused["error"]["code"], json!(6), "{refused}");
    assert_eq!(
        refused["error"]["message"],
        answer(&responses, 2)["error"]["message"],
        "close says something else about a handle that was never open"
    );
    assert_eq!(
        refused["error"]["message"],
        json!("refusing: no open archive with handle 99"),
        "{refused}"
    );
}

#[test]
#[cfg(unix)]
fn a_cancel_answer_does_not_amplify_what_the_client_wrote() {
    // A cancel answer echoing the running job's `request` — an arbitrary value the
    // client wrote once — into an unbounded queue grows the daemon without bound.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("many.rpf");
    // Incompressible, so that deflating it takes long enough for the cancels
    // below to arrive while the rebuild they name is still running.
    let files: Vec<FileSpec> = (0..256)
        .map(|i| FileSpec {
            path: format!("bulk/{i:04}.bin"),
            kind: FileKind::Binary {
                storage: Storage::Deflate,
                encryption: 0,
            },
        })
        .collect();
    let bulk = incompressible(512 * 1024);
    let building = std::time::Instant::now();
    let mut out = fs::File::create(&archive).expect("creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(bulk.clone())),
        &mut Unwatched,
    )
    .expect("builds");
    drop(out);

    // Started once the archive is, and paced by it: the rebuild deflates these
    // same bytes, so building them measured this box's rate for the work.
    let deadline = Deadline::within(
        "the rebuild to start and the daemon to exit after it",
        repeating(building.elapsed()),
    );
    let (mut stdin, stdout) = started(&deadline, daemon());

    let huge = "i".repeat(256 * 1024);
    for request in [
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": archive.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"bulk/0000.bin","bytes": BASE64.encode(b"replaced")}}),
        json!({"jsonrpc":"2.0","id": huge,"method":"commit","params":{
            "handle":1,"rebuild":true,"progress":false}}),
    ] {
        writeln!(stdin, "{request}").expect("writable");
    }
    // The rebuild writes into a temporary file beside the archive, so a second
    // file there is the rebuild having started; waited for rather than timed.
    while fs::read_dir(dir.path())
        .into_iter()
        .flatten()
        .flatten()
        .count()
        < 2
    {
        deadline.check();
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    // Aimed at a handle that was never opened, so the rebuild goes on running
    // and every one of these is answered rather than acted on.
    let cancel = json!({"jsonrpc":"2.0","id":9,"method":"cancel","params":{"handle":99}});
    for _ in 0..2000 {
        writeln!(stdin, "{cancel}").expect("writable");
    }
    // Nothing has read a byte of standard output, and standard input holds 64 KiB
    // against 2000 lines of some 70, so most were answered before the last write.
    std::thread::sleep(std::time::Duration::from_millis(500));
    let resident = resident_kilobytes(deadline.pid().expect("the daemon is running"));

    let drain = std::thread::spawn(move || {
        let mut objects = Vec::new();
        for line in std::io::BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() {
                continue;
            }
            objects.push(serde_json::from_str::<Value>(&line).expect("a JSON object per line"));
        }
        objects
    });
    drop(stdin);
    let status = deadline.reap().expect("the daemon exits");
    let objects = drain.join().expect("the draining thread finished");

    assert!(
        resident < 96 * 1024,
        "the daemon is holding {resident} KB of cancel answers echoing an id written once"
    );
    assert!(status.success(), "the daemon exited with {status}");
    let committed = objects
        .iter()
        .find(|object| object["id"] == json!(huge))
        .unwrap_or_else(|| panic!("the commit was never answered"));
    assert_eq!(
        committed["result"]["method"],
        json!("rebuild"),
        "a cancel aimed elsewhere landed here"
    );
    let answers: Vec<&Value> = objects
        .iter()
        .filter(|object| object["id"] == json!(9))
        .collect();
    assert_eq!(answers.len(), 2000, "a cancel answer was dropped");
    assert!(
        answers
            .iter()
            .any(|object| object["result"]["running"] == json!("rebuild")),
        "no cancel arrived while the rebuild was running, so nothing was echoed"
    );
}

/// Reads everything on `stdout` at full speed, pausing once after `after`
/// bytes — a client that hiccups for longer than the daemon's grace.
fn read_with_one_pause(
    stdout: &mut std::process::ChildStdout,
    after: usize,
    pause: std::time::Duration,
    deadline: &Deadline,
) -> Vec<u8> {
    use std::io::Read as _;
    let mut all = Vec::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut paused = false;
    loop {
        deadline.check();
        match stdout.read(&mut buffer) {
            Ok(0) | Err(_) => return all,
            Ok(taken) => all.extend_from_slice(buffer.get(..taken).unwrap_or_default()),
        }
        if !paused && all.len() >= after {
            paused = true;
            std::thread::sleep(pause);
        }
    }
}

#[test]
fn a_client_that_pauses_once_still_gets_every_answer_whole() {
    // The grace is an idle grace: sampled against a counter that moves only once
    // a whole piece has cleared, one long pause reads as a client that has gone.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("one.rpf");
    let entry = 512 * 1024;
    make_bulk_archive(&archive, 1, entry);

    let deadline = Deadline::on("the daemon to finish writing its answer past the pause");
    let (requesting, mut answers) = asking(
        &deadline,
        daemon(),
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
                "path": archive.display().to_string()}}),
            json!({"jsonrpc":"2.0","id":2,"method":"read","params":{
                "handle":1,"path":"bulk/0000.bin"}}),
            json!({"jsonrpc":"2.0","id":3,"method":"read","params":{
                "handle":1,"path":"bulk/0000.bin"}}),
        ],
    );
    // And standard input ends here, which is all
    // `rpf serve --stdio < requests.jsonl` does.
    drop(requesting);
    let taken = read_with_one_pause(
        &mut answers,
        200 * 1024,
        std::time::Duration::from_secs(3),
        &deadline,
    );
    let status = deadline.reap().expect("the daemon exits");

    assert!(
        status.success(),
        "one pause cost a client that is reading its answers: {status}"
    );
    assert_eq!(
        taken.last().copied(),
        Some(b'\n'),
        "the last line was cut off with no terminating newline: {} bytes",
        taken.len()
    );
    let text = String::from_utf8(taken).expect("utf-8");
    let objects: Vec<Value> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("a JSON object per line"))
        .collect();
    assert_eq!(objects.len(), 3, "an answer never arrived: {objects:?}");
    for id in [2, 3] {
        let answered = answer(&objects, id);
        assert_eq!(
            answered["result"]["len"],
            json!(entry),
            "answer {id} arrived, but not whole"
        );
        let bytes = BASE64
            .decode(answered["result"]["bytes"].as_str().expect("bytes"))
            .expect("base64");
        assert_eq!(bytes, vec![0_u8; entry], "answer {id} came back wrong");
    }
}

#[test]
fn a_client_that_never_reads_does_not_hold_the_daemon_open_for_ever() {
    // The reason the wait is bounded at all: a client that holds standard output
    // open and never takes a byte cannot be told from one that has gone.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("one.rpf");
    make_bulk_archive(&archive, 1, 512 * 1024);

    let mut child = daemon()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("daemon starts");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        for request in [
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
                "path": archive.display().to_string()}}),
            json!({"jsonrpc":"2.0","id":2,"method":"read","params":{
                "handle":1,"path":"bulk/0000.bin"}}),
        ] {
            writeln!(stdin, "{request}").expect("writable");
        }
    }
    let started = std::time::Instant::now();
    let mut exited = false;
    while started.elapsed() < std::time::Duration::from_secs(60) {
        if child.try_wait().expect("the daemon is running").is_some() {
            exited = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if !exited {
        let _ = child.kill();
    }
    let status = child.wait().expect("the daemon exits");

    assert!(
        exited,
        "the daemon never exited: a client that never reads held it open"
    );
    assert_eq!(
        status.code(),
        Some(7),
        "giving up on a client that never read is an i/o failure, not a success"
    );
}

/// An entry whose `read` answers one line longer than the published 8 MB
/// backlog: 8,388,926 bytes of JSON for 6,291,600 bytes of payload.
const OVER_THE_BACKLOG: usize = 6_291_600;

/// An entry whose `read` answers 4,194,126 bytes, so that two of them are
/// 8,388,252 — inside the published backlog, and only just.
const HALF_THE_BACKLOG: usize = 3_145_500;

/// Reads everything on `stdout`, taking exactly `piece` bytes every `every`, so
/// that the rate a test states is the rate and not whatever the pipe hands over.
fn read_at_a_rate(
    stdout: &mut std::process::ChildStdout,
    piece: usize,
    every: std::time::Duration,
    deadline: &Deadline,
) -> Vec<u8> {
    let mut all = Vec::new();
    let mut buffer = vec![0_u8; piece];
    loop {
        deadline.check();
        let mut got = 0_usize;
        while got < piece {
            match stdout.read(buffer.get_mut(got..).unwrap_or_default()) {
                Ok(0) | Err(_) => {
                    all.extend_from_slice(buffer.get(..got).unwrap_or_default());
                    return all;
                }
                Ok(taken) => got = got.saturating_add(taken),
            }
        }
        all.extend_from_slice(buffer.get(..got).unwrap_or_default());
        std::thread::sleep(every);
    }
}

/// The objects on `stdout`, and the length of the line each arrived on.
fn objects_and_line_lengths(taken: &[u8]) -> Vec<(Value, usize)> {
    String::from_utf8_lossy(taken)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            (
                serde_json::from_str::<Value>(line).expect("a JSON object per line"),
                line.len(),
            )
        })
        .collect()
}

/// The far end is measured in bytes it takes in a five-second window, and 256
/// KiB every 500 ms is two and a half megabytes of them — a client keeping up.
/// Inverting the comparison declares it starved and cuts it off with 7.
#[test]
fn a_client_that_keeps_up_is_not_cut_off_part_way_through_an_answer() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("one.rpf");
    make_bulk_archive(&archive, 1, OVER_THE_BACKLOG);

    let deadline = Deadline::on("the daemon to write a whole answer to a client that is reading");
    let (requesting, mut answers) = asking(
        &deadline,
        daemon(),
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
                "path": archive.display().to_string()}}),
            json!({"jsonrpc":"2.0","id":2,"method":"read","params":{
                "handle":1,"path":"bulk/0000.bin"}}),
            // Queued behind an answer already over the backlog, so the worker is
            // waiting on room for the whole time the client is reading.
            json!({"jsonrpc":"2.0","id":3,"method":"info","params":{"handle":1}}),
        ],
    );
    drop(requesting);
    let taken = read_at_a_rate(
        &mut answers,
        256 * 1024,
        std::time::Duration::from_millis(500),
        &deadline,
    );
    let status = deadline.reap().expect("the daemon exits");
    deadline.check();

    assert_eq!(
        status.code(),
        Some(0),
        "a client reading 256 KiB every 500 ms was cut off as starved"
    );
    assert_eq!(
        taken.last().copied(),
        Some(b'\n'),
        "the last line was cut off with no terminating newline: {} bytes",
        taken.len()
    );
    let objects: Vec<Value> = objects_and_line_lengths(&taken)
        .into_iter()
        .map(|(object, _)| object)
        .collect();
    let answered = answer(&objects, 2);
    assert_eq!(
        answered["result"]["len"],
        json!(OVER_THE_BACKLOG),
        "the answer arrived, but not whole"
    );
    assert!(
        answer(&objects, 3)["result"]["entries"].as_u64().is_some(),
        "the answer queued behind it never arrived: {objects:?}"
    );
}

/// The mirror, and the half the shutdown path does not cover: a client that
/// takes nothing is given up on **while the request is still being answered**,
/// so the worker cannot wait on room that will never come back.
#[test]
fn a_client_that_takes_nothing_is_given_up_on_mid_answer() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("one.rpf");
    make_bulk_archive(&archive, 1, OVER_THE_BACKLOG);

    let deadline = Deadline::within(
        "the daemon to give up on a client taking nothing",
        std::time::Duration::from_secs(40),
    );
    let (requesting, answers) = asking(
        &deadline,
        daemon(),
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
                "path": archive.display().to_string()}}),
            json!({"jsonrpc":"2.0","id":2,"method":"read","params":{
                "handle":1,"path":"bulk/0000.bin"}}),
            json!({"jsonrpc":"2.0","id":3,"method":"info","params":{"handle":1}}),
        ],
    );
    // Standard input ends, and standard output is held open and never read: the
    // wait inside the request is the only thing that can end this.
    drop(requesting);
    let status = deadline.reap().expect("the daemon exits");
    deadline.check();
    drop(answers);

    assert_eq!(
        status.code(),
        Some(7),
        "giving up on a client that takes nothing is an i/o failure, not a success"
    );
}

/// The published floor is 20 KiB in a five-second window. A client taking about
/// five, which is above every smaller figure the constant could be misread as,
/// is below the floor and is given up on.
#[test]
fn a_client_below_the_published_floor_is_given_up_on() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("one.rpf");
    make_bulk_archive(&archive, 1, 512 * 1024);

    let deadline = Deadline::within(
        "the daemon to give up on a client reading a kilobyte a second",
        std::time::Duration::from_secs(45),
    );
    let (requesting, mut answers) = asking(
        &deadline,
        daemon(),
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
                "path": archive.display().to_string()}}),
            json!({"jsonrpc":"2.0","id":2,"method":"read","params":{
                "handle":1,"path":"bulk/0000.bin"}}),
        ],
    );
    drop(requesting);
    // 1,024 bytes a second is about 5,120 in a window: below 20,480 and well
    // above any of the smaller numbers the floor could be mistaken for. It reads
    // on its own thread, because how long the answer left in the pipe takes to
    // drain at that rate is not what this test is waiting for.
    let stopping = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop = std::sync::Arc::clone(&stopping);
    let reading = std::thread::spawn(move || {
        let mut buffer = [0_u8; 1024];
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            match answers.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(_) => std::thread::sleep(std::time::Duration::from_secs(1)),
            }
        }
    });
    let status = deadline.reap().expect("the daemon exits");
    deadline.check();
    stopping.store(true, std::sync::atomic::Ordering::Relaxed);
    reading.join().expect("the reading thread finished");

    assert_eq!(
        status.code(),
        Some(7),
        "a client below the published floor held the daemon open"
    );
}

/// Whether `marker` turned up inside `patience`, asked without waiting on it.
fn appeared(marker: &Path, patience: std::time::Duration) -> bool {
    let started = std::time::Instant::now();
    while started.elapsed() < patience {
        if marker.exists() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

/// The bound in bytes rather than in symbols: two answers that together come to
/// 8,388,252 do not make the worker wait, so the queue takes at least that many.
/// A later request's own side effect on disk is what says the worker ran on.
#[test]
fn two_answers_inside_the_published_backlog_do_not_stop_the_worker() {
    let dir = tempfile::tempdir().expect("temp dir");
    let bulk = dir.path().join("bulk.rpf");
    make_bulk_archive(&bulk, 2, HALF_THE_BACKLOG);
    let side = dir.path().join("side.rpf");
    make_archive(&side);
    let marker = dir.path().join("marker");

    let deadline = Deadline::on("the worker to run on past two answers inside the backlog");
    let (requesting, mut answers) = asking(
        &deadline,
        daemon(),
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
                "path": bulk.display().to_string()}}),
            json!({"jsonrpc":"2.0","id":2,"method":"open","params":{
                "path": side.display().to_string()}}),
            json!({"jsonrpc":"2.0","id":3,"method":"read","params":{
                "handle":1,"path":"bulk/0000.bin"}}),
            json!({"jsonrpc":"2.0","id":4,"method":"read","params":{
                "handle":1,"path":"bulk/0001.bin"}}),
            json!({"jsonrpc":"2.0","id":5,"method":"extract","params":{
                "handle":2,"into": marker.display().to_string(),"progress":false}}),
        ],
    );
    // Nothing is read, and standard input stays open, so the only thing that can
    // stop the worker reaching the extraction is the backlog.
    let ran = appeared(&marker, std::time::Duration::from_secs(20));
    drop(requesting);
    let taken = read_at_a_rate(
        &mut answers,
        1024 * 1024,
        std::time::Duration::ZERO,
        &deadline,
    );
    let status = deadline.reap().expect("the daemon exits");
    deadline.check();

    assert!(
        ran,
        "two answers inside the published backlog stopped the worker"
    );
    assert_eq!(status.code(), Some(0), "the daemon exited with {status}");
    let objects = objects_and_line_lengths(&taken);
    let queued: usize = objects
        .iter()
        .filter(|(object, _)| object["id"] == json!(3) || object["id"] == json!(4))
        .map(|&(_, len)| len)
        .sum();
    assert_eq!(
        queued, 8_388_252,
        "the fixture no longer sizes the queue it means"
    );
    assert!(
        queued <= 8_388_608,
        "the two answers this test queues are over the published bound: {queued}"
    );
}

/// The other side of the same number, and the rule the constant's own comment
/// makes: one answer goes through however big it is, and the next one waits.
#[test]
fn one_answer_over_the_backlog_goes_through_and_the_next_one_waits() {
    let dir = tempfile::tempdir().expect("temp dir");
    let bulk = dir.path().join("bulk.rpf");
    make_bulk_archive(&bulk, 1, OVER_THE_BACKLOG);
    let side = dir.path().join("side.rpf");
    make_archive(&side);
    let marker = dir.path().join("marker");

    let deadline = Deadline::on("the worker to wait behind an answer over the backlog");
    let (requesting, mut answers) = asking(
        &deadline,
        daemon(),
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
                "path": bulk.display().to_string()}}),
            json!({"jsonrpc":"2.0","id":2,"method":"open","params":{
                "path": side.display().to_string()}}),
            json!({"jsonrpc":"2.0","id":3,"method":"read","params":{
                "handle":1,"path":"bulk/0000.bin"}}),
            json!({"jsonrpc":"2.0","id":4,"method":"info","params":{"handle":1}}),
            json!({"jsonrpc":"2.0","id":5,"method":"extract","params":{
                "handle":2,"into": marker.display().to_string(),"progress":false}}),
        ],
    );
    let ran = appeared(&marker, std::time::Duration::from_secs(10));
    drop(requesting);
    let taken = read_at_a_rate(
        &mut answers,
        1024 * 1024,
        std::time::Duration::ZERO,
        &deadline,
    );
    let status = deadline.reap().expect("the daemon exits");
    deadline.check();

    assert!(
        !ran,
        "an answer already over the backlog did not make the next request wait"
    );
    assert_eq!(status.code(), Some(0), "the daemon exited with {status}");
    let objects = objects_and_line_lengths(&taken);
    let over = objects
        .iter()
        .find(|(object, _)| object["id"] == json!(3))
        .map_or(0, |&(_, len)| len);
    assert_eq!(
        over, 8_388_926,
        "the fixture no longer sizes the answer it means"
    );
    assert!(
        over > 8_388_608,
        "the one answer this test queues is inside the published bound: {over}"
    );
    // And the room came back: the extraction the client's reading released ran.
    let objects: Vec<Value> = objects.into_iter().map(|(object, _)| object).collect();
    assert!(
        answer(&objects, 5)["result"]["files"].as_u64().is_some(),
        "the request behind the backlog never ran once there was room: {objects:?}"
    );
}

/// The binary's `--json` answer to one reporting command.
fn cli_json(args: &[&str]) -> Value {
    let output = Command::new(RPF)
        .arg("--json")
        .args(args)
        .output()
        .expect("binary runs");
    serde_json::from_slice(&output.stdout).expect("json on stdout")
}

#[test]
fn the_daemon_answers_info_and_verify_as_the_command_line_does() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"info","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":3,"method":"verify","params":{"handle":1}}),
    ]);

    let info = &answer(&responses, 2)["result"];
    let from_cli = cli_json(&["info", &archive_str]);
    for field in [
        "len",
        "encryption",
        "entries",
        "directories",
        "binary_files",
        "resource_files",
        "nested_archives",
        "locked_archives",
        "unreferenced_bytes",
    ] {
        assert_eq!(info[field], from_cli[field], "info disagrees about {field}");
    }
    // The resolved path the session claimed, which is what `open` reported.
    assert_eq!(info["path"], answer(&responses, 1)["result"]["path"]);

    let verified = &answer(&responses, 3)["result"];
    assert_eq!(
        verified["entries_checked"],
        cli_json(&["verify", &archive_str])["entries_checked"],
    );
    assert_eq!(verified["problems"], json!([]), "{verified}");
}

#[test]
fn verify_names_the_entry_that_did_not_read_back_and_still_answers() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    // The resource, because it is the entry that is actually deflated: the
    // greeting deflates to more than it is, so `build` stores it.
    let (at, _) = spans(&archive, "art.yft");

    // Past the RSC7 header, where the deflate stream begins. 0xFF opens a block
    // with the reserved type, so the stream is refused rather than inflating.
    let header = usize::try_from(rpf_core::format::resource::RESOURCE_HEADER_LEN).expect("16 fits");
    let mut bytes = fs::read(&archive).expect("readable");
    let start = usize::try_from(at).expect("a test offset fits") + header;
    bytes[start..start + 8].fill(0xFF);
    fs::write(&archive, &bytes).expect("writable");
    let archive_str = archive.display().to_string();

    let (responses, notifications) = narrated(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"verify","params":{"handle":1}}),
    ]);

    let verified = &answer(&responses, 2)["result"];
    assert_eq!(
        verified["entries_checked"],
        json!(2),
        "both entries were read: {verified}"
    );
    let problems = verified["problems"].as_array().expect("an array");
    assert_eq!(problems.len(), 1, "{verified}");
    assert_eq!(problems[0]["path"], json!("art.yft"));
    assert!(
        problems[0]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("did not inflate")),
        "{verified}"
    );

    // `done` counts the failing entry too, or the client's count has a gap.
    let named: Vec<&str> = notifications
        .iter()
        .filter_map(|n| n["params"]["path"].as_str())
        .collect();
    assert_eq!(named, vec!["art.yft", "data/greeting.txt"], "{named:?}");
}

#[test]
fn verify_reports_no_progress_to_a_caller_that_asked_for_none() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let (responses, notifications) = narrated(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"verify","params":{"handle":1,"progress":false}}),
    ]);

    assert_eq!(answer(&responses, 2)["result"]["entries_checked"], json!(2));
    assert!(
        notifications.is_empty(),
        "progress was reported to a caller that asked for none: {notifications:?}"
    );
}

#[test]
fn a_write_to_a_name_two_entries_answer_to_is_refused() {
    // The daemon resolves a write through `locate` exactly as `put` does, so a
    // folded-case spelling could buffer an edit against the other entry.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    let before = make_colliding_archive(&archive);
    let archive_str = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"a.txt","bytes": BASE64.encode(b"changed")}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1}}),
    ]);

    let refusal = answer(&responses, 2);
    assert_eq!(refusal["error"]["code"], json!(6), "{responses:?}");
    let message = refusal["error"]["message"].as_str().expect("a message");
    for named in ["a.txt", "A.txt"] {
        assert!(
            message.contains(named),
            "the refusal must name both: {message}"
        );
    }

    assert_eq!(
        answer(&responses, 3)["result"]["unchanged"],
        json!(true),
        "{responses:?}"
    );
    assert_eq!(
        fs::read(&archive).expect("readable"),
        before,
        "a refused write must leave every entry as it was"
    );
}

#[test]
fn the_daemon_respells_a_backslashed_path_exactly_as_the_command_line_does() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"read","params":{
            "handle":1,"path":"data\\greeting.txt"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"read","params":{
            "handle":1,"path":"data/absent.txt"}}),
    ]);

    let refusal = answer(&responses, 2);
    assert_eq!(refusal["error"]["code"], json!(3), "{responses:?}");
    let message = refusal["error"]["message"].as_str().expect("a message");
    assert!(
        message.contains("data/greeting.txt"),
        "the message must respell the path with the separator: {message}"
    );

    let plain = answer(&responses, 3)["error"]["message"]
        .as_str()
        .expect("a message");
    assert!(
        !plain.contains("separates with"),
        "there is nothing to say about a separator here: {plain}"
    );
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
        |_: &str| Ok(Cursor::new(inner.clone())),
        &mut Unwatched,
    )
    .expect("outer builds");
    (outer_path, inner_path)
}

#[test]
fn info_addresses_a_nested_archive_as_the_command_line_does() {
    // The daemon names the archive by handle, so `path` here means what it means
    // to `list`: a path inside the archive the handle holds.
    let dir = tempfile::tempdir().expect("temp dir");
    let (outer_path, _) = make_nested(dir.path());
    let outer = outer_path.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": outer}}),
        json!({"jsonrpc":"2.0","id":2,"method":"info","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":3,"method":"info","params":{
            "handle":1,"path":"x64/inner.rpf"}}),
        json!({"jsonrpc":"2.0","id":4,"method":"info","params":{"handle":1,"path":"x64"}}),
    ]);

    let whole = &answer(&responses, 2)["result"];
    assert_eq!(whole["inside"], json!(""), "{whole}");

    let nested = &answer(&responses, 3)["result"];
    let from_cli = cli_json(&["info", &outer, "x64/inner.rpf"]);
    for field in [
        "inside",
        "len",
        "encryption",
        "entries",
        "directories",
        "binary_files",
        "resource_files",
        "nested_archives",
        "locked_archives",
        "unreferenced_bytes",
    ] {
        assert_eq!(
            nested[field], from_cli[field],
            "info disagrees about {field}"
        );
    }
    // The resolved path the session claimed, which is what `open` reported.
    assert_eq!(nested["path"], answer(&responses, 1)["result"]["path"]);
    assert_ne!(nested["len"], whole["len"], "the outer is not the inner");

    // A directory is not an archive, and saying so is a refusal.
    let refusal = answer(&responses, 4);
    assert_eq!(refusal["error"]["code"], json!(6), "{refusal}");
}

#[test]
fn opening_a_path_that_continues_past_an_archive_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (outer_path, _) = make_nested(dir.path());
    let through = outer_path.join("x64").join("inner.rpf");

    let responses = talk(&[json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
        "path": through.display().to_string()}})]);
    let refusal = answer(&responses, 1);
    assert_eq!(refusal["error"]["code"], json!(6), "{refusal}");
    let message = refusal["error"]["message"].as_str().expect("a message");
    assert!(
        message.contains(&outer_path.display().to_string()),
        "the refusal names the archive the path runs past: {message}"
    );
}

#[test]
fn list_and_ls_report_the_same_rows_through_the_same_nesting() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (outer_path, _) = make_nested(dir.path());
    let outer = outer_path.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": outer}}),
        json!({"jsonrpc":"2.0","id":2,"method":"list","params":{"handle":1,"recursive":true}}),
        json!({"jsonrpc":"2.0","id":3,"method":"list","params":{
            "handle":1,"path":"x64/inner.rpf"}}),
    ]);

    assert_eq!(
        answer(&responses, 2)["result"],
        cli_json(&["ls", "-R", &outer]),
        "a recursive listing of the whole archive"
    );
    assert_eq!(
        answer(&responses, 3)["result"],
        cli_json(&["ls", &outer, "x64/inner.rpf"]),
        "and one addressed through the nesting"
    );

    // The rows really do reach inside the nested archive, so the two are not
    // agreeing only because both are empty.
    let rows = answer(&responses, 2)["result"]
        .as_array()
        .expect("an array")
        .clone();
    assert!(
        rows.iter()
            .any(|row| row["path"] == json!("x64/inner.rpf/art.yft")
                && row["kind"] == json!("resource")),
        "{rows:?}"
    );
}

#[test]
fn the_daemon_extracts_and_packs_as_the_command_line_does() {
    // A tree is a path on the daemon's own filesystem, as `open`'s path is.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let from_cli = dir.path().join("cli-tree").display().to_string();
    let cli_extract = cli_json(&["extract", &archive_str, &from_cli]);
    let cli_packed = dir.path().join("cli.rpf").display().to_string();
    let cli_pack = cli_json(&["pack", &from_cli, &cli_packed]);

    let from_daemon = dir.path().join("daemon-tree").display().to_string();
    let daemon_packed = dir.path().join("daemon.rpf").display().to_string();
    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"extract","params":{
            "handle":1,"into": from_daemon, "progress": false}}),
        json!({"jsonrpc":"2.0","id":3,"method":"pack","params":{
            "from": from_daemon, "archive": daemon_packed, "progress": false}}),
    ]);

    let extracted = &answer(&responses, 2)["result"];
    for field in ["files", "directories"] {
        assert_eq!(
            extracted[field], cli_extract[field],
            "extract disagrees about {field}: {extracted}"
        );
    }
    assert_eq!(
        extracted["manifest"],
        json!(
            Path::new(&from_daemon)
                .join(".rpf-manifest.json")
                .display()
                .to_string()
        ),
        "{extracted}"
    );

    let packed = &answer(&responses, 3)["result"];
    for field in ["entries", "len"] {
        assert_eq!(
            packed[field], cli_pack[field],
            "pack disagrees about {field}: {packed}"
        );
    }

    assert_eq!(
        fs::read(&daemon_packed).expect("readable"),
        fs::read(&cli_packed).expect("readable"),
        "the two frontends packed different archives"
    );
}

/// A `pack` destination that is not there yet is resolved through its parent,
/// and a bare name has none: the working directory stands in for it. Reading
/// that filter the other way round leaves the empty parent to resolve, which
/// nothing can, and an ordinary `pack` into the working directory fails.
#[test]
fn pack_resolves_a_destination_that_is_not_there_yet_from_a_bare_name() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("canonical temp dir");
    let archive = root.join("test.rpf");
    make_archive(&archive);
    let tree = root.join("tree");

    let responses = talk_in(
        &root,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
                "path": archive.display().to_string()}}),
            json!({"jsonrpc":"2.0","id":2,"method":"extract","params":{
                "handle":1,"into": tree.display().to_string(),"progress":false}}),
            json!({"jsonrpc":"2.0","id":3,"method":"pack","params":{
                "from": tree.display().to_string(),"archive":"new.rpf","progress":false}}),
        ],
    );

    let packed = answer(&responses, 3);
    assert!(
        packed["result"]["entries"].as_u64().is_some(),
        "a bare destination name was not resolved: {packed}"
    );
    assert!(
        root.join("new.rpf").is_file(),
        "the archive was reported packed and is not in the working directory: {packed}"
    );
}

/// The other half of the same resolution: a named parent is the one the archive
/// lands in, and not the working directory.
#[test]
fn pack_writes_the_archive_where_it_was_asked_and_not_beside_the_daemon() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("canonical temp dir");
    let archive = root.join("test.rpf");
    make_archive(&archive);
    let tree = root.join("tree");
    fs::create_dir(root.join("out")).expect("the destination's parent");

    let responses = talk_in(
        &root,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
                "path": archive.display().to_string()}}),
            json!({"jsonrpc":"2.0","id":2,"method":"extract","params":{
                "handle":1,"into": tree.display().to_string(),"progress":false}}),
            json!({"jsonrpc":"2.0","id":3,"method":"pack","params":{
                "from": tree.display().to_string(),"archive":"out/new.rpf","progress":false}}),
        ],
    );

    let packed = answer(&responses, 3);
    assert!(
        packed["result"]["entries"].as_u64().is_some(),
        "the pack did not run: {packed}"
    );
    assert!(
        root.join("out").join("new.rpf").is_file(),
        "the archive was reported packed and is not where it was asked for: {packed}"
    );
    assert!(
        !root.join("new.rpf").exists(),
        "the archive landed beside the working directory instead of in out/"
    );
}

#[test]
fn packing_over_an_archive_a_session_holds_is_refused() {
    // `pack` is the one method that names its output by path, and writing over an
    // archive a session holds moves every offset that session works from.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();
    let before = fs::read(&archive).expect("readable");

    let tree = dir.path().join("tree").display().to_string();
    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"extract","params":{
            "handle":1,"into": tree, "progress": false}}),
        json!({"jsonrpc":"2.0","id":3,"method":"pack","params":{
            "from": tree, "archive": archive_str, "progress": false}}),
        json!({"jsonrpc":"2.0","id":4,"method":"close","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":5,"method":"pack","params":{
            "from": tree, "archive": archive_str, "progress": false}}),
    ]);

    let refusal = answer(&responses, 3);
    assert_eq!(refusal["error"]["code"], json!(6), "{refusal}");
    let message = refusal["error"]["message"].as_str().expect("a message");
    assert!(message.contains("handle 1"), "{message}");
    assert_eq!(
        fs::read(&archive).expect("readable"),
        before,
        "a refused pack must leave the archive it was aimed at alone"
    );

    assert!(
        answer(&responses, 5)["result"]["entries"]
            .as_u64()
            .is_some(),
        "closing the handle releases the claim: {:?}",
        answer(&responses, 5)
    );
}

#[test]
fn extract_and_pack_report_progress_as_notifications() {
    // A `pack` has no handle, so its notifications carry none.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let tree = dir.path().join("tree").display().to_string();
    let packed = dir.path().join("packed.rpf").display().to_string();
    let (_, notifications) = narrated(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"extract","params":{
            "handle":1,"into": tree}}),
        json!({"jsonrpc":"2.0","id":3,"method":"pack","params":{
            "from": tree, "archive": packed}}),
    ]);

    let steps = |request: u64| -> Vec<Value> {
        notifications
            .iter()
            .filter(|n| n["params"]["request"] == json!(request))
            .cloned()
            .collect()
    };

    let extracting = steps(2);
    assert!(!extracting.is_empty(), "extract reported nothing");
    for step in &extracting {
        assert_eq!(step["method"], json!("progress"), "{step}");
        assert_eq!(step["params"]["handle"], json!(1), "{step}");
        assert_eq!(step["params"]["total"], json!(2), "{step}");
    }

    let packing = steps(3);
    assert!(!packing.is_empty(), "pack reported nothing");
    for step in &packing {
        assert_eq!(step["method"], json!("progress"), "{step}");
        assert_eq!(
            step["params"]["handle"],
            json!(null),
            "a pack is not a session: {step}"
        );
    }
}

#[test]
fn extracting_from_a_session_with_buffered_edits_is_refused_and_names_them() {
    // `read` prefers a buffered edit; `extract` reads the archive off disk, so a
    // tree with buffered edits outstanding is refused rather than merged.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive = archive.display().to_string();
    let tree = dir.path().join("tree");
    let into = tree.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(b"edited")}}),
        json!({"jsonrpc":"2.0","id":3,"method":"extract","params":{"handle":1,"into": into}}),
    ]);

    let refused = answer(&responses, 3);
    assert_eq!(refused["error"]["code"], json!(6), "{refused}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("data/greeting.txt")),
        "the refusal must name what has to be committed first: {refused}"
    );
    assert!(
        !tree.exists(),
        "a refused extraction created part of a tree"
    );

    let recovered = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(b"edited")}}),
        json!({"jsonrpc":"2.0","id":3,"method":"discard","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":4,"method":"extract","params":{"handle":1,"into": into}}),
    ]);
    assert_eq!(answer(&recovered, 4)["result"]["files"], json!(2));
    assert!(tree.is_dir());
}

#[test]
fn extracting_over_an_archive_an_open_session_holds_is_refused() {
    // A session's offsets are true only of the bytes it parsed, and an extraction
    // writing an entry over that file moves all of them.
    let dir = tempfile::tempdir().expect("temp dir");
    let held = dir.path().join("held.rpf");
    make_archive(&held);
    let before = fs::read(&held).expect("readable");

    // An archive whose one entry is named after the archive beside it.
    let source = dir.path().join("source.rpf");
    let files = [FileSpec {
        path: "held.rpf".to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Stored,
            encryption: 0,
        },
    }];
    let mut out = fs::File::create(&source).expect("creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(b"not an archive".to_vec())),
        &mut Unwatched,
    )
    .expect("builds");
    drop(out);

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": held.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"open","params":{
            "path": source.display().to_string()}}),
        // `overwrite` because the directory being extracted into is the one the
        // archives sit in, which is refused on its own and is not what is tested.
        json!({"jsonrpc":"2.0","id":3,"method":"extract","params":{
            "handle":2,"into": dir.path().display().to_string(),"overwrite":true}}),
    ]);

    let refused = answer(&responses, 3);
    assert_eq!(refused["error"]["code"], json!(6), "{refused}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("handle 1")),
        "the refusal must name the handle holding it: {refused}"
    );
    assert_eq!(
        fs::read(&held).expect("readable"),
        before,
        "an archive an open session holds was written over"
    );
}

#[test]
#[cfg(any(unix, windows))]
fn neither_pack_nor_extract_may_write_over_a_second_name_for_a_held_archive() {
    // DR-009: the claim is on the file, not on the spelling. A hard link is the
    // spelling a path comparison cannot see through — both names canonicalise to
    // themselves — so it is the only one that tells the identity check from a
    // path check. A symlink would not: `open` and `pack` both canonicalise, and
    // the two spellings arrive as one path.
    let dir = tempfile::tempdir().expect("temp dir");
    let held = dir.path().join("held.rpf");
    make_archive(&held);
    let alias = dir.path().join("alias.rpf");
    fs::hard_link(&held, &alias).expect("hard link");
    let before = fs::read(&held).expect("readable");

    // An archive whose one entry is named after the second name for the held one.
    let source = dir.path().join("source.rpf");
    let files = [FileSpec {
        path: "alias.rpf".to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Stored,
            encryption: 0,
        },
    }];
    let mut out = fs::File::create(&source).expect("creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(b"not an archive".to_vec())),
        &mut Unwatched,
    )
    .expect("builds");
    drop(out);

    let tree = dir.path().join("tree").display().to_string();
    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": held.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"extract","params":{
            "handle":1,"into": tree,"progress":false}}),
        json!({"jsonrpc":"2.0","id":3,"method":"pack","params":{
            "from": tree,"archive": alias.display().to_string(),"progress":false}}),
        json!({"jsonrpc":"2.0","id":4,"method":"open","params":{
            "path": source.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":5,"method":"extract","params":{
            "handle":2,"into": dir.path().display().to_string(),"overwrite":true}}),
    ]);

    for id in [3, 5] {
        let refused = answer(&responses, id);
        assert_eq!(
            refused["error"]["code"],
            json!(6),
            "a second name for the held archive was written over: {refused}"
        );
        assert_eq!(
            refused["error"]["data"]["reason"],
            json!("Refused"),
            "{refused}"
        );
        assert!(
            refused["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("handle 1")),
            "the refusal must name the handle holding it: {refused}"
        );
    }
    assert_eq!(
        fs::read(&held).expect("readable"),
        before,
        "every offset handle 1 holds moved: the archive it parsed was written over \
         under its other name"
    );
}

// Key material: three methods with no handle, because there is no archive open.

/// Reports a skip; `RPF_REQUIRE_<GATE>` makes that gate's absence a failure.
fn skip<T>(test: &str, gate: &str, reason: &str) -> Option<T> {
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
        return skip(test, "RPF_GAME_EXE", "RPF_GAME_EXE is not set");
    };
    let path = Path::new(&root).join(name);
    if path.is_file() {
        Some(path)
    } else {
        skip(
            test,
            "RPF_GAME_EXE",
            &format!("{} is not a file", path.display()),
        )
    }
}

/// The memory image the NG material is extracted from, or a loud skip.
fn game_image(test: &str) -> Option<std::path::PathBuf> {
    let Some(named) = std::env::var_os("RPF_GAME_IMAGE") else {
        return skip(test, "RPF_GAME_IMAGE", "RPF_GAME_IMAGE is not set");
    };
    let path = std::path::PathBuf::from(named);
    if path.is_file() {
        Some(path)
    } else {
        skip(
            test,
            "RPF_GAME_IMAGE",
            &format!("{} is not a file", path.display()),
        )
    }
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

#[test]
fn the_daemon_answers_every_keys_command_the_binary_does() {
    let dir = tempfile::tempdir().expect("temp dir");
    let source = dir.path().join("not-a-game.exe");
    fs::write(&source, vec![0_u8; 1 << 16]).expect("writable");
    let cache = dir.path().join("cache");
    fs::create_dir_all(&cache).expect("creatable");
    for name in [
        &format!("{}.keys", "a".repeat(64)),
        &format!("{}.keys", "b".repeat(64)),
    ] {
        fs::write(cache.join(name), b"x").expect("writable");
    }
    let at = cache.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"keys.extract","params":{
            "executable": source.display().to_string(), "cache": at}}),
        json!({"jsonrpc":"2.0","id":2,"method":"keys.cache","params":{"cache": at}}),
        json!({"jsonrpc":"2.0","id":3,"method":"keys.invalidate","params":{"cache": at}}),
        json!({"jsonrpc":"2.0","id":4,"method":"keys.cache","params":{"cache": at}}),
    ]);

    let refused = answer(&responses, 1);
    assert_eq!(refused["error"]["code"], json!(9), "{refused}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("0 of 2")),
        "{refused}"
    );

    assert_eq!(answer(&responses, 2)["result"]["entries"], json!(2));
    assert_eq!(answer(&responses, 3)["result"]["removed"], json!(2));
    assert_eq!(answer(&responses, 3)["result"]["cache"], json!(at));
    assert_eq!(answer(&responses, 4)["result"]["entries"], json!(0));
}

#[test]
fn a_keys_method_says_which_parameter_it_wanted() {
    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"keys.extract","params":{}}),
        json!({"jsonrpc":"2.0","id":2,"method":"keys.cache","params":{"cache": 7}}),
    ]);
    for id in [1, 2] {
        let refused = answer(&responses, id);
        assert_eq!(refused["error"]["code"], json!(-32602), "{refused}");
    }
}

#[test]
#[cfg_attr(no_executables, ignore = "RPF_GAME_EXE is not set")]
fn the_daemon_reports_offsets_and_never_a_key() {
    let test = "the_daemon_reports_offsets_and_never_a_key";
    let Some(path) = executable(test, "GTA5.exe") else {
        return;
    };
    let mut file = fs::File::open(&path).expect("the executable is readable");
    let keys = rpf_core::keys::Keys::extract(&mut file, &mut rpf_core::Unwatched)
        .expect("carries the material");

    let dir = tempfile::tempdir().expect("temp dir");
    let at = dir.path().join("cache").display().to_string();
    let source = path.display().to_string();
    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"keys.extract","params":{
            "executable": source, "cache": at}}),
        json!({"jsonrpc":"2.0","id":2,"method":"keys.extract","params":{
            "executable": source, "cache": at}}),
    ]);

    let found = answer(&responses, 1);
    assert_eq!(found["result"]["from"], json!("executable"), "{found}");
    assert_eq!(
        found["result"]["values"][0]["at"],
        json!(keys.aes_key_offset()),
        "{found}"
    );
    assert_eq!(
        found["result"]["values"][1]["at"],
        json!(keys.hash_lut_offset()),
        "{found}"
    );
    assert_eq!(
        answer(&responses, 2)["result"]["from"],
        json!("cache"),
        "the second call rescanned rather than reading the cache"
    );

    let written = responses
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<String>();
    for value in [keys.aes_key().as_slice(), keys.hash_lut().as_slice()] {
        assert!(!holds(written.as_bytes(), value), "a key went on the wire");
        assert!(
            !holds(written.as_bytes(), hex(value).as_bytes()),
            "a key went on the wire as hexadecimal"
        );
        assert!(
            !holds(written.as_bytes(), hex(value).to_uppercase().as_bytes()),
            "a key went on the wire as hexadecimal"
        );
        assert!(
            !holds(written.as_bytes(), BASE64.encode(value).as_bytes()),
            "a key went on the wire as base64"
        );
    }
}

#[test]
fn the_daemon_verifies_against_a_tree_as_the_command_line_does() {
    // `against` is a path on the daemon's own filesystem, as `open`'s `path` is.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let tree = dir.path().join("tree").display().to_string();
    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"extract","params":{
            "handle":1,"into": tree, "progress": false}}),
        json!({"jsonrpc":"2.0","id":3,"method":"verify","params":{
            "handle":1,"against": tree, "progress": false}}),
    ]);

    let verified = &answer(&responses, 3)["result"];
    let from_cli = cli_json(&["verify", &archive_str, "--against", &tree]);
    for field in ["entries_checked", "contents_checked", "contents_recorded"] {
        assert_eq!(
            verified[field], from_cli[field],
            "verify disagrees about {field}: {verified}"
        );
    }
    assert_eq!(verified["contents_checked"], json!(2), "{verified}");
    assert_eq!(verified["against"], json!(tree), "{verified}");
    assert_eq!(verified["problems"], json!([]), "{verified}");

    let alone = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"verify","params":{"handle":1,"progress":false}}),
    ]);
    let alone = &answer(&alone, 2)["result"];
    assert_eq!(alone["contents_checked"], json!(0), "{alone}");
    assert_eq!(alone["against"], Value::Null, "{alone}");
}

#[test]
fn a_byte_changed_inside_a_stored_entry_is_a_finding_on_the_wire_too() {
    // The archive says nothing about a stored entry's bytes, so only a manifest sees this.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let tree = dir.path().join("tree").display().to_string();
    assert_eq!(
        cli_json(&["extract", &archive_str, &tree])["files"],
        json!(2)
    );

    // Eleven bytes of greeting deflate to more than eleven, so `build` stored
    // them: nothing declares an inflated length and no stream ends.
    let (at, _) = spans(&archive, "data/greeting.txt");
    let mut bytes = fs::read(&archive).expect("readable");
    let start = usize::try_from(at).expect("a test offset fits");
    bytes[start] ^= 0xFF;
    fs::write(&archive, &bytes).expect("writable");

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"verify","params":{"handle":1,"progress":false}}),
        json!({"jsonrpc":"2.0","id":3,"method":"verify","params":{
            "handle":1,"against": tree, "progress": false}}),
    ]);

    let alone = &answer(&responses, 2)["result"];
    assert_eq!(alone["problems"], json!([]), "the archive alone: {alone}");

    let against = &answer(&responses, 3)["result"];
    let problems = against["problems"].as_array().expect("an array");
    assert_eq!(problems.len(), 1, "{against}");
    assert_eq!(problems[0]["path"], json!("data/greeting.txt"), "{against}");
    assert_eq!(against["contents_checked"], json!(2), "{against}");
}

#[test]
fn a_tree_of_another_archive_is_refused_on_the_wire_as_it_is_on_the_command_line() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let other = dir.path().join("other.rpf");
    make_other_archive(&other);

    let tree = dir.path().join("other-tree").display().to_string();
    assert_eq!(
        cli_json(&["extract", &other.display().to_string(), &tree])["files"],
        json!(1),
    );

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": archive.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"verify","params":{
            "handle":1,"against": tree, "progress": false}}),
    ]);

    let refusal = &answer(&responses, 2)["error"];
    assert_eq!(refusal["code"], json!(6), "{refusal}");
    let message = refusal["message"].as_str().expect("a message");
    assert!(message.contains(&tree), "{message}");
    assert!(message.contains("nothing was checked"), "{message}");
}

#[test]
fn a_verify_against_a_tree_still_reports_one_step_per_entry() {
    // Digesting an entry's contents is bounded work per entry, so it happens
    // inside the step that entry already reports: `done` and `total` are the same.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();
    let tree = dir.path().join("tree").display().to_string();
    assert_eq!(
        cli_json(&["extract", &archive_str, &tree])["files"],
        json!(2)
    );

    let (_, notifications) = narrated(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"verify","params":{
            "handle":1,"against": tree}}),
    ]);

    let named: Vec<&str> = notifications
        .iter()
        .filter_map(|n| n["params"]["path"].as_str())
        .collect();
    assert_eq!(named, vec!["art.yft", "data/greeting.txt"], "{named:?}");
    assert!(
        notifications
            .iter()
            .all(|n| n["params"]["total"] == json!(2)),
        "{notifications:?}",
    );
}

/// A second archive, sharing no path with [`make_archive`]'s.
fn make_other_archive(at: &Path) {
    let files = vec![FileSpec {
        path: "elsewhere.bin".to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Stored,
            encryption: 0,
        },
    }];
    let mut out = fs::File::create(at).expect("creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(vec![3_u8; 64])),
        &mut Unwatched,
    )
    .expect("builds");
}

// --- adding, deleting and renaming an entry on the wire ---------------------

/// Every path an open archive holds, from a recursive `list`.
fn listed(archive: &str) -> Vec<String> {
    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive}}),
        json!({"jsonrpc":"2.0","id":2,"method":"list","params":{
            "handle":1,"path":"","recursive":true}}),
    ]);
    answer(&responses, 2)["result"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|row| row["path"].as_str().expect("path").to_owned())
        .collect()
}

#[test]
fn a_created_entry_is_buffered_and_committed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        // Without `create` it is still not found.
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/added.txt","bytes": BASE64.encode(b"new")}}),
        json!({"jsonrpc":"2.0","id":3,"method":"write","params":{
            "handle":1,"path":"data/added.txt","bytes": BASE64.encode(b"new"),
            "create":true}}),
        json!({"jsonrpc":"2.0","id":4,"method":"read","params":{
            "handle":1,"path":"data/added.txt"}}),
        json!({"jsonrpc":"2.0","id":5,"method":"commit","params":{"handle":1,"progress":false}}),
        json!({"jsonrpc":"2.0","id":6,"method":"read","params":{
            "handle":1,"path":"data/added.txt"}}),
        json!({"jsonrpc":"2.0","id":7,"method":"verify","params":{"handle":1,"progress":false}}),
    ]);

    // Not merely an error: the path the archive does not hold is code 3 on the
    // command line and `NotFound` here, which is what `create: false` promises.
    let missing = answer(&responses, 2);
    assert_eq!(missing["error"]["code"], json!(3), "{missing}");
    assert_eq!(
        missing["error"]["data"]["reason"],
        json!("NotFound"),
        "{missing}"
    );
    assert_eq!(answer(&responses, 3)["result"]["pending"], json!(1));
    assert_eq!(answer(&responses, 4)["result"]["pending"], json!(true));

    let committed = answer(&responses, 5);
    assert_eq!(
        committed["result"]["method"],
        json!("rebuild"),
        "{committed}"
    );
    assert_eq!(committed["result"]["committed"], json!(1), "{committed}");

    let read = answer(&responses, 6);
    assert_eq!(read["result"]["pending"], json!(false), "{read}");
    assert_eq!(
        BASE64
            .decode(read["result"]["bytes"].as_str().expect("bytes"))
            .expect("base64"),
        b"new".to_vec(),
    );
    assert_eq!(
        answer(&responses, 7)["result"]["problems"],
        json!([]),
        "{responses:?}"
    );
    assert!(listed(&archive_str).contains(&"data/added.txt".to_owned()));
}

#[test]
fn delete_buffers_a_removal_and_asks_before_taking_children() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"delete","params":{"handle":1,"path":"data"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"delete","params":{
            "handle":1,"path":"data","recursive":true}}),
        json!({"jsonrpc":"2.0","id":4,"method":"pending","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":5,"method":"commit","params":{"handle":1,"progress":false}}),
        json!({"jsonrpc":"2.0","id":6,"method":"list","params":{
            "handle":1,"path":"","recursive":true}}),
    ]);

    let refused = answer(&responses, 2);
    assert!(refused["error"].is_object(), "{refused}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .expect("a message")
            .contains("not empty"),
        "{refused}",
    );

    assert_eq!(answer(&responses, 3)["result"]["pending"], json!(1));
    assert_eq!(answer(&responses, 4)["result"]["paths"], json!(["data"]));
    assert_eq!(
        answer(&responses, 5)["result"]["method"],
        json!("rebuild"),
        "{responses:?}"
    );

    let rows: Vec<String> = answer(&responses, 6)["result"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|row| row["path"].as_str().expect("path").to_owned())
        .collect();
    assert_eq!(rows, vec!["art.yft".to_owned()], "{rows:?}");
}

#[test]
fn rename_moves_an_entry_and_refuses_an_occupied_name() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"rename","params":{
            "handle":1,"from":"art.yft","to":"data/greeting.txt"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"rename","params":{
            "handle":1,"from":"art.yft","to":"data/moved.yft"}}),
        json!({"jsonrpc":"2.0","id":4,"method":"commit","params":{"handle":1,"progress":false}}),
        json!({"jsonrpc":"2.0","id":5,"method":"verify","params":{"handle":1,"progress":false}}),
    ]);

    let refused = answer(&responses, 2);
    assert!(refused["error"].is_object(), "{refused}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .expect("a message")
            .contains("already in the archive"),
        "{refused}",
    );

    assert_eq!(answer(&responses, 3)["result"]["pending"], json!(1));
    assert_eq!(answer(&responses, 4)["result"]["committed"], json!(1));
    assert_eq!(answer(&responses, 5)["result"]["problems"], json!([]));

    let rows = listed(&archive_str);
    assert!(rows.contains(&"data/moved.yft".to_owned()), "{rows:?}");
    assert!(!rows.contains(&"art.yft".to_owned()), "{rows:?}");
}

/// `build` derives directories from file paths, so an empty one is otherwise lost.
#[test]
fn mkdir_adds_a_directory_and_refuses_one_that_is_there() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"mkdir","params":{"handle":1,"path":"data"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"mkdir","params":{"handle":1,"path":"empty"}}),
        json!({"jsonrpc":"2.0","id":4,"method":"commit","params":{"handle":1,"progress":false}}),
    ]);

    assert!(answer(&responses, 2)["error"].is_object(), "{responses:?}");
    assert_eq!(answer(&responses, 3)["result"]["pending"], json!(1));
    assert_eq!(answer(&responses, 4)["result"]["committed"], json!(1));
    assert!(listed(&archive_str).contains(&"empty".to_owned()));
}

#[test]
fn a_dry_run_names_the_structural_change_it_would_make() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();
    let before = fs::read(&archive).expect("readable");

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"delete","params":{"handle":1,"path":"art.yft"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1,"dry_run":true}}),
        json!({"jsonrpc":"2.0","id":4,"method":"pending","params":{"handle":1}}),
    ]);

    let planned = answer(&responses, 3);
    assert_eq!(planned["result"]["method"], json!("rebuild"), "{planned}");
    assert_eq!(planned["result"]["committed"], json!(0), "{planned}");
    assert_eq!(
        planned["result"]["structural"],
        json!([{"path": "art.yft", "structural": "removes an entry"}]),
        "{planned}",
    );
    assert_eq!(answer(&responses, 4)["result"]["paths"], json!(["art.yft"]));
    assert_eq!(fs::read(&archive).expect("readable"), before, "it wrote");
}

#[test]
fn a_structural_change_is_refused_when_it_is_offered() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"delete","params":{"handle":1,"path":"nowhere"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"rename","params":{
            "handle":1,"from":"nowhere","to":"somewhere"}}),
        json!({"jsonrpc":"2.0","id":4,"method":"pending","params":{"handle":1}}),
    ]);

    for id in [2, 3] {
        let refused = answer(&responses, id);
        assert!(refused["error"].is_object(), "{refused}");
        assert_eq!(refused["error"]["code"], json!(3), "{refused}");
    }
    assert_eq!(answer(&responses, 4)["result"]["paths"], json!([]));
}

// --- What `list` answers, and how a caller reads it -------------------------

/// `list` of a file answers that one entry, which makes it a `stat`.
#[test]
fn list_of_a_file_answers_that_entry_and_a_caller_can_tell() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"list","params":{
            "handle":1,"path":"data/greeting.txt"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"list","params":{"handle":1,"path":"data"}}),
    ]);

    let file = answer(&responses, 2)["result"]
        .as_array()
        .expect("an array")
        .clone();
    assert_eq!(file.len(), 1, "{file:?}");
    assert_eq!(file[0]["path"], json!("data/greeting.txt"), "{file:?}");
    assert_eq!(file[0]["kind"], json!("binary"), "{file:?}");

    // The directory holding it: one row too, and its path is *not* the one
    // asked for. Only that comparison separates the two cases.
    let directory = answer(&responses, 3)["result"]
        .as_array()
        .expect("an array")
        .clone();
    assert_eq!(directory.len(), 1, "{directory:?}");
    assert_eq!(
        directory[0]["path"],
        json!("data/greeting.txt"),
        "{directory:?}"
    );
}

/// A resource's payload is never read, so a `null` encoding is not "nothing was found".
#[test]
fn a_list_row_says_what_the_payload_announces_and_a_resource_says_nothing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": archive.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"list","params":{
            "handle":1,"recursive":true}}),
    ]);
    let rows = answer(&responses, 2)["result"]
        .as_array()
        .expect("an array")
        .clone();
    let row = |path: &str| {
        rows.iter()
            .find(|row| row["path"] == json!(path))
            .unwrap_or_else(|| panic!("{path} is not in {rows:?}"))
            .clone()
    };

    // Deflated on disk, so this is the contents being classified and not the
    // first bytes of a deflate stream.
    assert_eq!(row("data/greeting.txt")["encoding"], json!("text"));
    assert_eq!(row("data/greeting.txt")["kind"], json!("binary"));

    // And the resource, whose payload here really does begin `RSC7` — which
    // changes nothing, because it is not consulted.
    assert_eq!(row("art.yft")["kind"], json!("resource"));
    assert_eq!(row("art.yft")["encoding"], Value::Null);
    assert_eq!(row("data")["encoding"], Value::Null);
}

/// A row's `path` is the whole in-archive path, not a name.
#[test]
fn a_list_row_carries_the_whole_path_it_was_addressed_from() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (outer_path, _) = make_nested(dir.path());
    let outer = outer_path.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": outer}}),
        json!({"jsonrpc":"2.0","id":2,"method":"list","params":{
            "handle":1,"path":"x64/inner.rpf"}}),
        // The caller's own spelling is what comes back, folded case and all: the
        // rows are addressed from what was asked for.
        json!({"jsonrpc":"2.0","id":3,"method":"list","params":{
            "handle":1,"path":"X64/INNER.RPF"}}),
    ]);

    let rows: Vec<String> = answer(&responses, 2)["result"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|row| row["path"].as_str().expect("path").to_owned())
        .collect();
    assert!(
        rows.iter().all(|path| path.starts_with("x64/inner.rpf/")),
        "a row must carry the whole path: {rows:?}",
    );
    let first = rows.first().expect("at least one entry").clone();
    let read = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": outer}}),
        json!({"jsonrpc":"2.0","id":2,"method":"read","params":{"handle":1,"path": first}}),
    ]);
    assert!(answer(&read, 2)["result"]["bytes"].is_string(), "{read:?}");

    let spelled: Vec<String> = answer(&responses, 3)["result"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|row| row["path"].as_str().expect("path").to_owned())
        .collect();
    assert!(
        spelled
            .iter()
            .all(|path| path.starts_with("X64/INNER.RPF/")),
        "the caller's spelling is what comes back: {spelled:?}",
    );
}

#[test]
fn extract_over_a_target_that_holds_something_is_refused_on_the_wire_too() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();
    let tree = dir.path().join("tree").display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"extract","params":{
            "handle":1,"into": tree,"progress":false}}),
        json!({"jsonrpc":"2.0","id":3,"method":"extract","params":{
            "handle":1,"into": tree,"progress":false}}),
        json!({"jsonrpc":"2.0","id":4,"method":"extract","params":{
            "handle":1,"into": tree,"overwrite":true,"progress":false}}),
    ]);

    assert_eq!(answer(&responses, 2)["result"]["files"], json!(2));

    let refused = answer(&responses, 3);
    assert_eq!(refused["error"]["code"], json!(6), "{refused}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .expect("a message")
            .contains("--overwrite"),
        "{refused}",
    );

    assert_eq!(answer(&responses, 4)["result"]["files"], json!(2));
}

#[test]
fn a_listing_is_the_archive_on_disk_and_a_read_is_not() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"delete","params":{"handle":1,"path":"art.yft"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"write","params":{
            "handle":1,"path":"added.txt","bytes": BASE64.encode(b"new"),"create":true}}),
        json!({"jsonrpc":"2.0","id":4,"method":"list","params":{
            "handle":1,"path":"","recursive":true}}),
        json!({"jsonrpc":"2.0","id":5,"method":"read","params":{"handle":1,"path":"added.txt"}}),
        json!({"jsonrpc":"2.0","id":6,"method":"pending","params":{"handle":1}}),
    ]);

    let rows: Vec<String> = answer(&responses, 4)["result"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|row| row["path"].as_str().expect("path").to_owned())
        .collect();
    assert!(
        rows.contains(&"art.yft".to_owned()),
        "a buffered removal is not in the listing: {rows:?}",
    );
    assert!(
        !rows.contains(&"added.txt".to_owned()),
        "a buffered addition is not in the listing either: {rows:?}",
    );

    let read = answer(&responses, 5);
    assert_eq!(read["result"]["pending"], json!(true), "{read}");

    assert_eq!(
        answer(&responses, 6)["result"]["paths"],
        json!(["added.txt", "art.yft"]),
    );
}

/// The AES-encrypted archive in the corpus, by its relative path.
const AES_ARCHIVE: &str = "gtav_aes/des_canister.rpf";

/// The Rockstar Games Launcher's own archive: AES-tagged under the launcher key
/// and, alone in the corpus, holding **no resource entry at all**.
const LAUNCHER_ARCHIVE: &str = "rockstar_launcher/Launcher.rpf";

/// The NG-encrypted archive, whose **file name is load-bearing**: an NG key is
/// chosen by the archive's own name.
const NG_ARCHIVE: &str = "gtav_ng/dlc.rpf";

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

/// As [`talk`], with a configuration directory of the test's own, so the key
/// cache the daemon reads is one this test put there.
fn talk_homed(home: &Path, requests: &[Value]) -> Vec<Value> {
    talk_homed_within(home, requests, PATIENCE)
}

/// As [`talk_homed`], with `patience` on the answer rather than [`PATIENCE`].
fn talk_homed_within(home: &Path, requests: &[Value], patience: std::time::Duration) -> Vec<Value> {
    let mut daemon = daemon();
    daemon
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("APPDATA", home.join("appdata"));
    drive_within(daemon, requests, patience).0
}

#[test]
#[cfg_attr(
    any(no_corpus, no_game_image),
    ignore = "RPF_CORPUS and RPF_GAME_IMAGE must both be set"
)]
fn the_wire_writes_into_an_ng_archive_and_it_opens_again() {
    let test = "the_wire_writes_into_an_ng_archive_and_it_opens_again";
    let Some(archive) = corpus(test, NG_ARCHIVE) else {
        return;
    };
    // A memory image: no executable carries the NG material, so extracting from
    // one would leave this at `NeedsKey`.
    let Some(source) = game_image(test) else {
        return;
    };

    let dir = tempfile::tempdir().expect("temp dir");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    // Its own file name, which the NG key is derived from.
    let copy = dir.path().join("dlc.rpf");
    fs::copy(&archive, &copy).expect("copyable");
    let at = copy.display().to_string();

    // The one wait here whose honest length is the image's size rather than the
    // daemon's speed: a full scan of it, and the image is not this test's to bound.
    let extracted = talk_homed_within(
        &home,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"keys.extract","params":{
            "executable": source.display().to_string()}}),
        ],
        scanning(&source),
    );
    assert!(answer(&extracted, 1)["result"].is_object(), "{extracted:?}");

    // A length the entry did not have, so the payload goes back under a different
    // one of the keys than it came out from.
    let responses = talk_homed(
        &home,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": at}}),
            json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
                "handle":1,"path":"content.xml",
                "bytes":"AAECAwQFBgcICQoLDA0ODxAREhM="}}),
            json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1}}),
        ],
    );
    assert_eq!(answer(&responses, 1)["result"]["entries"], json!(7));
    assert!(answer(&responses, 2)["result"].is_object(), "{responses:?}");
    assert_eq!(answer(&responses, 3)["result"]["committed"], json!(1));

    // A fresh daemon over the file that is now on disk: a table of contents
    // written in the clear does not open, nor does a payload keyed by the old size.
    let reopened = talk_homed(
        &home,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": at}}),
            json!({"jsonrpc":"2.0","id":2,"method":"read","params":{
                "handle":1,"path":"content.xml"}}),
        ],
    );
    assert_eq!(answer(&reopened, 1)["result"]["entries"], json!(7));
    assert_eq!(
        answer(&reopened, 2)["result"]["bytes"],
        json!("AAECAwQFBgcICQoLDA0ODxAREhM="),
        "{reopened:?}"
    );
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn the_wire_writes_into_an_aes_archive_and_it_opens_again() {
    let test = "the_wire_writes_into_an_aes_archive_and_it_opens_again";
    let Some(archive) = corpus(test, AES_ARCHIVE) else {
        return;
    };
    let Some(source) = executable(test, "GTA5.exe") else {
        return;
    };

    let dir = tempfile::tempdir().expect("temp dir");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let copy = dir.path().join("des_canister.rpf");
    fs::copy(&archive, &copy).expect("copyable");
    let at = copy.display().to_string();

    let extracted = talk_homed(
        &home,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"keys.extract","params":{
            "executable": source.display().to_string()}}),
        ],
    );
    assert!(answer(&extracted, 1)["result"].is_object(), "{extracted:?}");

    // Deliberately not text: `_manifest.ymf` holds a tokenised encoding, so a
    // textual payload is refused before any of this is reached.
    let responses = talk_homed(
        &home,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": at}}),
            json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
                "handle":1,"path":"_manifest.ymf",
                "bytes":"AAECAwQFBgcICQoLDA0ODxAREhM="}}),
            json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1}}),
        ],
    );
    assert_eq!(answer(&responses, 1)["result"]["entries"], json!(11));
    assert!(answer(&responses, 2)["result"].is_object(), "{responses:?}");
    assert_eq!(answer(&responses, 3)["result"]["committed"], json!(1));

    // A fresh daemon over the file that is now on disk: a table of contents
    // written in the clear does not open, and a payload that did does not read.
    let reopened = talk_homed(
        &home,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": at}}),
            json!({"jsonrpc":"2.0","id":2,"method":"read","params":{
                "handle":1,"path":"_manifest.ymf"}}),
        ],
    );
    assert_eq!(answer(&reopened, 1)["result"]["entries"], json!(11));
    assert_eq!(
        answer(&reopened, 2)["result"]["bytes"],
        json!("AAECAwQFBgcICQoLDA0ODxAREhM="),
        "{reopened:?}"
    );
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn the_daemon_opens_an_encrypted_archive_from_the_cache_it_was_started_with() {
    // The flag is on the process rather than on every method that opens an archive.
    let test = "the_daemon_opens_an_encrypted_archive_from_the_cache_it_was_started_with";
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

    let mut started = daemon();
    started
        .args(["--cache-dir", &named])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("APPDATA", home.join("appdata"));
    let responses = drive(
        started,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"keys.extract","params":{
                "executable": source.display().to_string()}}),
            json!({"jsonrpc":"2.0","id":2,"method":"open","params":{"path": at}}),
        ],
    )
    .0;

    let extracted = answer(&responses, 1);
    assert_eq!(extracted["result"]["cache"], json!(named), "{extracted}");
    let opened = answer(&responses, 2);
    assert_eq!(opened["result"]["entries"], json!(11), "{opened}");

    // The same flag reaches `pack`: what says it arrived is that the tree packs
    // at all, the material being needed for the seal and the rows' flag words.
    let tree = dir.path().join("tree").display().to_string();
    let packed = dir.path().join("packed.rpf").display().to_string();
    let mut started = daemon();
    started
        .args(["--cache-dir", &named])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("APPDATA", home.join("appdata"));
    let responses = drive(
        started,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": at}}),
            json!({"jsonrpc":"2.0","id":2,"method":"extract","params":{
                "handle":1,"into": tree, "progress": false}}),
            json!({"jsonrpc":"2.0","id":3,"method":"pack","params":{
                "from": tree, "archive": packed, "progress": false}}),
        ],
    )
    .0;
    let repacked = answer(&responses, 3);
    assert_eq!(repacked["result"]["entries"], json!(11), "{repacked}");
    assert!(Path::new(&packed).exists(), "the pack wrote no archive");

    // With no cache to reach, the same request answers for the material rather
    // than writing a cleartext archive under an encrypted tag.
    let bare = dir.path().join("bare.rpf").display().to_string();
    let mut started = daemon();
    started
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("APPDATA", home.join("appdata"));
    let responses = drive(
        started,
        &[json!({"jsonrpc":"2.0","id":1,"method":"pack","params":{
                "from": tree, "archive": bare, "progress": false}})],
    )
    .0;
    let refused = answer(&responses, 1);
    assert_eq!(refused["error"]["code"], json!(5), "{refused}");
    assert_eq!(
        refused["error"]["data"]["reason"],
        json!("NeedsKey"),
        "{refused}"
    );
    assert!(
        !Path::new(&bare).exists(),
        "a refused pack wrote an archive"
    );
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn the_daemon_packs_a_tree_extracted_from_an_archive_holding_no_resource() {
    // `Launcher.rpf` is the one corpus archive with no resource entry, so every
    // entry of an extracted tree of it is one this packer can rebuild.
    let test = "the_daemon_packs_a_tree_extracted_from_an_archive_holding_no_resource";
    let Some(archive) = corpus(test, LAUNCHER_ARCHIVE) else {
        return;
    };
    let Some(source) = executable(test, "Launcher.exe") else {
        return;
    };

    let dir = tempfile::tempdir().expect("temp dir");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let named = dir.path().join("keys").display().to_string();
    let at = archive.display().to_string();
    let tree = dir.path().join("tree").display().to_string();
    let packed = dir.path().join("packed.rpf").display().to_string();

    let mut started = daemon();
    started
        .args(["--cache-dir", &named])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("APPDATA", home.join("appdata"));
    let responses = drive(
        started,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"keys.extract","params":{
                "executable": source.display().to_string()}}),
            json!({"jsonrpc":"2.0","id":2,"method":"open","params":{"path": at}}),
            json!({"jsonrpc":"2.0","id":3,"method":"extract","params":{
                "handle":1,"into": tree, "progress": false}}),
            json!({"jsonrpc":"2.0","id":4,"method":"pack","params":{
                "from": tree, "archive": packed, "progress": false}}),
            json!({"jsonrpc":"2.0","id":5,"method":"open","params":{"path": packed}}),
        ],
    )
    .0;
    let opened = answer(&responses, 2);
    assert_eq!(opened["result"]["entries"], json!(118), "{opened}");
    let repacked = answer(&responses, 4);
    assert!(repacked["result"].is_object(), "{repacked}");
    // Against what the source archive answered rather than a fixed count.
    let reopened = answer(&responses, 5);
    assert!(reopened["result"].is_object(), "{reopened}");
    assert_eq!(
        reopened["result"]["entries"], opened["result"]["entries"],
        "{reopened}"
    );

    // And it was written sealed: a daemon with no cache to reach opens nothing,
    // where a cleartext archive under an encrypted tag would open for anyone.
    let mut started = daemon();
    started
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("APPDATA", home.join("appdata"));
    let responses = drive(
        started,
        &[json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": packed}})],
    )
    .0;
    let refused = answer(&responses, 1);
    assert_eq!(refused["error"]["code"], json!(5), "{refused}");
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn a_daemon_started_without_a_cache_still_says_the_archive_needs_a_key() {
    // The other half: the flag is what carried the material, not something
    // else on this machine.
    let test = "a_daemon_started_without_a_cache_still_says_the_archive_needs_a_key";
    let Some(archive) = corpus(test, AES_ARCHIVE) else {
        return;
    };
    let dir = tempfile::tempdir().expect("temp dir");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let responses = talk_homed(
        &home,
        &[json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": archive.display().to_string()}})],
    );
    let refused = answer(&responses, 1);
    assert_eq!(refused["error"]["code"], json!(5), "{refused}");
    assert_eq!(
        refused["error"]["data"]["reason"],
        json!("NeedsKey"),
        "{refused}"
    );
}

/// An archive holding one stored entry at `data/thing.ymt`, whose payload is
/// `contents`.
fn make_metadata_archive(at: &Path, contents: &[u8]) {
    let payload = contents.to_vec();
    let mut out = fs::File::create(at).expect("creatable");
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
    .expect("builds");
}

/// An entry holding `RBF` or `PSO` takes neither XML nor text, and
/// `"allow_encoding_change": true` is the way through — refused at the commit.
#[test]
fn a_write_of_text_into_a_tokenised_metadata_entry_is_refused_at_the_commit() {
    let dir = tempfile::tempdir().expect("temp dir");
    for held in [
        &b"RBF0\x01\x02\x03\x04tokens"[..],
        &b"PSIN\x01\x02\x03\x04sect"[..],
    ] {
        for offered in [
            &b"<CVehicleModelInfo />"[..],
            &b"a plain line of text\n"[..],
        ] {
            let archive = dir.path().join("test.rpf");
            make_metadata_archive(&archive, held);
            let path = archive.display().to_string();
            let before = fs::read(&archive).expect("readable");

            let responses = talk(&[
                json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": path}}),
                json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
                    "handle":1,"path":"data/thing.ymt","bytes": BASE64.encode(offered)}}),
                json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1}}),
            ]);
            let refused = answer(&responses, 3);
            assert_eq!(refused["error"]["code"], json!(6), "{refused}");
            assert_eq!(
                refused["error"]["data"]["reason"],
                json!("WrongEncoding"),
                "{refused}"
            );
            assert_eq!(
                fs::read(&archive).expect("readable"),
                before,
                "a refused commit wrote something"
            );

            let responses = talk(&[
                json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": path}}),
                json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
                    "handle":1,"path":"data/thing.ymt",
                    "bytes": BASE64.encode(offered),
                    "allow_encoding_change": true}}),
                json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1}}),
                json!({"jsonrpc":"2.0","id":4,"method":"read","params":{
                    "handle":1,"path":"data/thing.ymt"}}),
            ]);
            let committed = answer(&responses, 3);
            assert_eq!(committed["result"]["committed"], json!(1), "{committed}");
            let read = answer(&responses, 4);
            assert_eq!(
                read["result"]["bytes"],
                json!(BASE64.encode(offered)),
                "{read}"
            );
        }
    }
}

#[test]
fn a_dry_run_told_to_rebuild_reports_the_refusal_the_commit_would_make() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_metadata_archive(&archive, b"RBF0\x01\x02\x03\x04tokens");
    let path = archive.display().to_string();
    let before = fs::read(&archive).expect("readable");

    for rebuild in [false, true] {
        let responses = talk(&[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": path}}),
            json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
                "handle":1,"path":"data/thing.ymt",
                "bytes": BASE64.encode(b"<CVehicleModelInfo />")}}),
            json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{
                "handle":1,"rebuild": rebuild,"dry_run":true}}),
            json!({"jsonrpc":"2.0","id":4,"method":"pending","params":{"handle":1}}),
        ]);
        let refused = answer(&responses, 3);
        assert_eq!(
            refused["error"]["code"],
            json!(6),
            "a dry run with rebuild {rebuild} reported success: {refused}"
        );
        assert_eq!(
            refused["error"]["data"]["reason"],
            json!("WrongEncoding"),
            "{refused}"
        );
        assert_eq!(
            answer(&responses, 4)["result"]["paths"],
            json!(["data/thing.ymt"]),
            "the dry run dropped the buffered edit"
        );
        assert_eq!(
            fs::read(&archive).expect("readable"),
            before,
            "a dry run wrote"
        );
    }
}

/// The daemon's own `"force"` is the game-install override and carries no
/// second meaning, **on either verb it could be sent to**.
#[test]
fn force_does_not_let_text_into_a_tokenised_metadata_entry() {
    let dir = tempfile::tempdir().expect("temp dir");
    for forced_on_write in [false, true] {
        let archive = dir.path().join("test.rpf");
        make_metadata_archive(&archive, b"RBF0\x01\x02\x03\x04tokens");
        let path = archive.display().to_string();

        let responses = talk(&[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": path}}),
            json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
                "handle":1,"path":"data/thing.ymt",
                "bytes": BASE64.encode(b"<CVehicleModelInfo />"),
                "force": forced_on_write}}),
            json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{
                "handle":1,"force": true}}),
        ]);
        let refused = answer(&responses, 3);
        assert_eq!(
            refused["error"]["code"],
            json!(6),
            "forced on write: {forced_on_write}, {refused}"
        );
        assert_eq!(
            refused["error"]["data"]["reason"],
            json!("WrongEncoding"),
            "{refused}"
        );
    }
}

#[test]
fn read_answers_the_view_it_was_asked_for_and_names_what_the_entry_holds() {
    let dir = tempfile::tempdir().expect("temp dir");
    for (payload, document, _, encoding) in common::tokenised() {
        let archive = dir.path().join(format!("{encoding}.rpf"));
        make_metadata_archive(&archive, &payload);
        let path = archive.display().to_string();

        let responses = talk(&[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": path}}),
            json!({"jsonrpc":"2.0","id":2,"method":"read","params":{
                "handle":1,"path":"data/thing.ymt","as":"xml"}}),
            json!({"jsonrpc":"2.0","id":3,"method":"read","params":{
                "handle":1,"path":"data/thing.ymt","as":"auto"}}),
            json!({"jsonrpc":"2.0","id":4,"method":"read","params":{
                "handle":1,"path":"data/thing.ymt"}}),
        ]);
        for id in [2, 3] {
            let read = answer(&responses, id);
            assert_eq!(read["result"]["as"], json!("xml"), "{read}");
            assert_eq!(read["result"]["encoding"], json!(encoding), "{read}");
            assert_eq!(
                read["result"]["bytes"],
                json!(BASE64.encode(document)),
                "{read}"
            );
            assert_eq!(read["result"]["len"], json!(document.len()), "{read}");
        }
        // The default is the entry's own bytes, with the encoding named beside them.
        let raw = answer(&responses, 4);
        assert_eq!(raw["result"]["as"], json!("raw"), "{raw}");
        assert_eq!(raw["result"]["encoding"], json!(encoding), "{raw}");
        assert_eq!(
            raw["result"]["bytes"],
            json!(BASE64.encode(&payload)),
            "{raw}"
        );
    }
}

#[test]
fn a_document_is_written_back_read_back_and_committed_as_the_entrys_encoding() {
    let dir = tempfile::tempdir().expect("temp dir");
    for (payload, _, edited, encoding) in common::tokenised() {
        let archive = dir.path().join(format!("{encoding}-write.rpf"));
        make_metadata_archive(&archive, &payload);
        let path = archive.display().to_string();

        let responses = talk(&[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": path}}),
            json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
                "handle":1,"path":"data/thing.ymt",
                "bytes": BASE64.encode(edited), "as":"xml"}}),
            json!({"jsonrpc":"2.0","id":3,"method":"read","params":{
                "handle":1,"path":"data/thing.ymt","as":"auto"}}),
            json!({"jsonrpc":"2.0","id":4,"method":"commit","params":{"handle":1}}),
            json!({"jsonrpc":"2.0","id":5,"method":"list","params":{
                "handle":1,"path":"data/thing.ymt"}}),
        ]);
        let wrote = answer(&responses, 2);
        assert_eq!(wrote["result"]["pending"], json!(1), "{wrote}");
        assert_ne!(
            wrote["result"]["len"],
            json!(edited.len()),
            "what was buffered is the document rather than the payload: {wrote}"
        );

        let read = answer(&responses, 3);
        assert_eq!(read["result"]["pending"], json!(true), "{read}");
        assert_eq!(read["result"]["as"], json!("xml"), "{read}");
        assert_eq!(
            read["result"]["bytes"],
            json!(BASE64.encode(edited)),
            "a buffered document did not read back as itself: {read}"
        );

        let committed = answer(&responses, 4);
        assert_eq!(committed["result"]["committed"], json!(1), "{committed}");
        let listed = answer(&responses, 5);
        assert_eq!(
            listed["result"][0]["encoding"],
            json!(encoding),
            "the entry changed encoding: {listed}"
        );
    }
}

#[test]
fn a_document_is_refused_as_bytes_and_taken_as_a_document_on_the_wire() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("guard.rpf");
    let payload = common::rbf_payload(common::RBF_DOCUMENT);
    make_metadata_archive(&archive, &payload);
    let path = archive.display().to_string();
    let before = fs::read(&archive).expect("readable");

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": path}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/thing.ymt",
            "bytes": BASE64.encode(common::RBF_EDITED)}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1}}),
    ]);
    let refused = answer(&responses, 3);
    assert_eq!(refused["error"]["code"], json!(6), "{refused}");
    assert_eq!(
        refused["error"]["data"]["reason"],
        json!("WrongEncoding"),
        "{refused}"
    );
    assert_eq!(
        fs::read(&archive).expect("readable"),
        before,
        "a refused commit wrote something"
    );

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": path}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/thing.ymt",
            "bytes": BASE64.encode(common::RBF_EDITED), "as":"xml"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":4,"method":"read","params":{
            "handle":1,"path":"data/thing.ymt"}}),
    ]);
    let committed = answer(&responses, 3);
    assert_eq!(committed["result"]["committed"], json!(1), "{committed}");
    let read = answer(&responses, 4);
    assert_eq!(
        read["result"]["bytes"],
        json!(BASE64.encode(common::rbf_payload(common::RBF_EDITED))),
        "the entry does not hold the payload the document describes: {read}"
    );
}

#[test]
fn auto_offers_a_payload_that_is_not_a_document_exactly_as_it_is() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("paste.rpf");
    make_metadata_archive(&archive, &common::rbf_payload(common::RBF_DOCUMENT));
    let path = archive.display().to_string();
    let other = common::rbf_payload(common::RBF_EDITED);

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": path}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/thing.ymt",
            "bytes": BASE64.encode(&other), "as":"auto"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":4,"method":"read","params":{
            "handle":1,"path":"data/thing.ymt"}}),
    ]);
    assert_eq!(answer(&responses, 3)["result"]["committed"], json!(1));
    let read = answer(&responses, 4);
    assert_eq!(
        read["result"]["bytes"],
        json!(BASE64.encode(&other)),
        "{read}"
    );
}

#[test]
fn an_entry_with_no_xml_view_refuses_one_on_the_wire() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("noview.rpf");
    let resource = make_archive(&archive);
    assert!(!resource.is_empty());
    let path = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": path}}),
        // A resource: its payload is not read at all, so it has no view and its
        // `"encoding"` is `null` for the reason a listing row's is.
        json!({"jsonrpc":"2.0","id":2,"method":"read","params":{
            "handle":1,"path":"art.yft","as":"xml"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"read","params":{
            "handle":1,"path":"art.yft","as":"auto"}}),
        // And plain text, which announces itself and still has no view.
        json!({"jsonrpc":"2.0","id":4,"method":"read","params":{
            "handle":1,"path":"data/greeting.txt","as":"xml"}}),
        json!({"jsonrpc":"2.0","id":5,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt",
            "bytes": BASE64.encode("<a/>"), "as":"xml"}}),
    ]);
    for id in [2, 4] {
        let refused = answer(&responses, id);
        assert_eq!(refused["error"]["code"], json!(6), "{refused}");
        assert_eq!(
            refused["error"]["data"]["reason"],
            json!("NoXmlView"),
            "{refused}"
        );
    }
    let automatic = answer(&responses, 3);
    assert_eq!(automatic["result"]["as"], json!("raw"), "{automatic}");
    assert_eq!(
        automatic["result"]["encoding"],
        Value::Null,
        "a resource's payload is not read: {automatic}"
    );
    let refused = answer(&responses, 5);
    assert_eq!(
        refused["error"]["data"]["reason"],
        json!("NoXmlView"),
        "a write of a document into an entry with no view: {refused}"
    );
}

#[test]
fn a_view_the_wire_does_not_name_is_refused_as_a_parameter() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("views.rpf");
    make_metadata_archive(&archive, &common::rbf_payload(common::RBF_DOCUMENT));
    let path = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": path}}),
        json!({"jsonrpc":"2.0","id":2,"method":"read","params":{
            "handle":1,"path":"data/thing.ymt","as":"XML"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"read","params":{
            "handle":1,"path":"data/thing.ymt","as":7}}),
    ]);
    for id in [2, 3] {
        let refused = answer(&responses, id);
        assert_eq!(refused["error"]["code"], json!(-32602), "{refused}");
    }
    let named = answer(&responses, 2)["error"]["message"]
        .as_str()
        .expect("a message")
        .to_owned();
    for view in ["raw", "xml", "auto"] {
        assert!(named.contains(view), "must name {view}: {named}");
    }
}

/// An archive holding one resource entry at `data/thing.ymt` whose contents are
/// a `Meta`, with `flags` as the row's two flag words.
fn make_meta_archive(at: &Path, flags: rpf_core::ResourceFlags) {
    let payload = common::meta_resource();
    let mut out = fs::File::create(at).expect("creatable");
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
    .expect("builds");
}

#[test]
fn a_resource_meta_is_read_and_written_as_xml_on_the_wire() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("meta.rpf");
    make_meta_archive(&archive, common::META_FLAGS);
    let path = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": path}}),
        json!({"jsonrpc":"2.0","id":2,"method":"read","params":{
            "handle":1,"path":"data/thing.ymt","as":"xml"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"read","params":{
            "handle":1,"path":"data/thing.ymt","as":"auto"}}),
        json!({"jsonrpc":"2.0","id":4,"method":"write","params":{
            "handle":1,"path":"data/thing.ymt",
            "bytes": BASE64.encode(common::META_EDITED), "as":"auto"}}),
        json!({"jsonrpc":"2.0","id":5,"method":"read","params":{
            "handle":1,"path":"data/thing.ymt","as":"auto"}}),
        json!({"jsonrpc":"2.0","id":6,"method":"commit","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":7,"method":"read","params":{
            "handle":1,"path":"data/thing.ymt","as":"xml"}}),
    ]);
    for id in [2, 3] {
        let read = answer(&responses, id);
        assert_eq!(read["result"]["as"], json!("xml"), "{read}");
        assert_eq!(read["result"]["encoding"], json!(null), "{read}");
        assert_eq!(
            read["result"]["bytes"],
            json!(BASE64.encode(common::META_DOCUMENT)),
            "{read}"
        );
    }
    let wrote = answer(&responses, 4);
    assert_eq!(wrote["result"]["pending"], json!(1), "{wrote}");
    assert_ne!(
        wrote["result"]["len"],
        json!(common::META_EDITED.len()),
        "what was buffered is the document rather than the payload: {wrote}"
    );

    let buffered = answer(&responses, 5);
    assert_eq!(buffered["result"]["pending"], json!(true), "{buffered}");
    assert_eq!(buffered["result"]["as"], json!("xml"), "{buffered}");
    assert_eq!(
        buffered["result"]["bytes"],
        json!(BASE64.encode(common::META_EDITED)),
        "a buffered document did not read back as itself: {buffered}"
    );

    let committed = answer(&responses, 6);
    assert_eq!(committed["result"]["committed"], json!(1), "{committed}");
    let after = answer(&responses, 7);
    assert_eq!(
        after["result"]["bytes"],
        json!(BASE64.encode(common::META_EDITED)),
        "the edit did not land: {after}"
    );
}

/// A buffered resource payload whose own `RSC7` header contradicts the entry's
/// row has no view, in either direction: the two pairs declare one length.
#[test]
fn a_buffered_resource_whose_header_contradicts_its_row_has_no_view() {
    use std::io::Write as _;

    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("meta.rpf");
    make_meta_archive(&archive, common::META_FLAGS);

    let mut payload = Vec::new();
    payload.extend_from_slice(b"RSC7");
    payload.extend_from_slice(
        &rpf_core::format::resource::resource_version(
            common::META_ELSEWHERE.system,
            common::META_ELSEWHERE.graphics,
        )
        .to_le_bytes(),
    );
    payload.extend_from_slice(&common::META_ELSEWHERE.system.to_le_bytes());
    payload.extend_from_slice(&common::META_ELSEWHERE.graphics.to_le_bytes());
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(&common::minimal_meta())
        .expect("the page deflates");
    payload.extend_from_slice(&encoder.finish().expect("the encoder finishes"));

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": archive.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/thing.ymt",
            "bytes": BASE64.encode(&payload), "as":"raw"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"read","params":{
            "handle":1,"path":"data/thing.ymt","as":"xml"}}),
        json!({"jsonrpc":"2.0","id":4,"method":"read","params":{
            "handle":1,"path":"data/thing.ymt","as":"auto"}}),
        json!({"jsonrpc":"2.0","id":5,"method":"write","params":{
            "handle":1,"path":"data/thing.ymt",
            "bytes": BASE64.encode(common::META_EDITED), "as":"xml"}}),
    ]);
    assert_eq!(answer(&responses, 2)["result"]["pending"], json!(1));
    let refused = answer(&responses, 3);
    assert_eq!(
        refused["error"]["data"]["reason"],
        json!("NoXmlView"),
        "a buffer read against a boundary its own header denies: {refused}"
    );
    let raw = answer(&responses, 4);
    assert_eq!(raw["result"]["as"], json!("raw"), "{raw}");
    assert_eq!(
        raw["result"]["bytes"],
        json!(BASE64.encode(&payload)),
        "{raw}"
    );
    let refused = answer(&responses, 5);
    assert_eq!(
        refused["error"]["data"]["reason"],
        json!("NoXmlView"),
        "a document was written into a buffer at a boundary it denies: {refused}"
    );
}

/// As [`talk`], with the daemon given a keys cache of its own. `--cache-dir`
/// is a global flag, so it comes before the subcommand.
fn talk_with_cache(cache: &Path, requests: &[Value]) -> Vec<Value> {
    let mut daemon = Command::new(RPF);
    daemon.args([
        "--cache-dir",
        &cache.display().to_string(),
        "serve",
        "--stdio",
    ]);
    drive(daemon, requests).0
}

/// What is buffered is the payload as it will sit on disk, keyed.
#[test]
fn a_keyed_resource_reads_its_own_buffered_edit_back_as_xml() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("meta.rpf");
    let cache = dir.path().join("keys");
    common::make_keyed_meta_archive(&archive, &cache, 16);

    let responses = talk_with_cache(
        &cache,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
                "path": archive.display().to_string()}}),
            json!({"jsonrpc":"2.0","id":2,"method":"read","params":{
                "handle":1,"path":"data/thing.ymt","as":"xml"}}),
            json!({"jsonrpc":"2.0","id":3,"method":"write","params":{
                "handle":1,"path":"data/thing.ymt",
                "bytes": BASE64.encode(common::META_EDITED), "as":"xml"}}),
            json!({"jsonrpc":"2.0","id":4,"method":"read","params":{
                "handle":1,"path":"data/thing.ymt","as":"xml"}}),
            json!({"jsonrpc":"2.0","id":5,"method":"write","params":{
                "handle":1,"path":"data/thing.ymt",
                "bytes": BASE64.encode(common::META_DOCUMENT), "as":"xml"}}),
        ],
    );
    let opened = answer(&responses, 1);
    assert_eq!(opened["result"]["entries"], json!(3), "{opened}");
    let read = answer(&responses, 2);
    assert_eq!(
        read["result"]["bytes"],
        json!(BASE64.encode(common::META_DOCUMENT)),
        "the keyed fixture does not read as a document at all: {read}"
    );
    let wrote = answer(&responses, 3);
    assert_eq!(wrote["result"]["pending"], json!(1), "{wrote}");
    let back = answer(&responses, 4);
    assert_eq!(back["result"]["pending"], json!(true), "{back}");
    assert_eq!(back["result"]["as"], json!("xml"), "{back}");
    assert_eq!(
        back["result"]["bytes"],
        json!(BASE64.encode(common::META_EDITED)),
        "a buffered edit of a keyed resource did not read back: {back}"
    );
    let again = answer(&responses, 5);
    assert_eq!(
        again["result"]["pending"],
        json!(1),
        "a second document into the same buffer was refused: {again}"
    );
}

#[test]
fn a_second_auto_write_over_a_keyed_resource_does_not_land_the_document_as_the_payload() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("meta.rpf");
    let cache = dir.path().join("keys");
    common::make_keyed_meta_archive(&archive, &cache, 16);

    let responses = talk_with_cache(
        &cache,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
                "path": archive.display().to_string()}}),
            json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
                "handle":1,"path":"data/thing.ymt",
                "bytes": BASE64.encode(common::META_EDITED), "as":"xml"}}),
            json!({"jsonrpc":"2.0","id":3,"method":"write","params":{
                "handle":1,"path":"data/thing.ymt",
                "bytes": BASE64.encode(common::META_DOCUMENT), "as":"auto"}}),
            json!({"jsonrpc":"2.0","id":4,"method":"commit","params":{"handle":1}}),
        ],
    );
    for id in [2, 3] {
        let wrote = answer(&responses, id);
        assert_eq!(wrote["result"]["pending"], json!(1), "{wrote}");
        assert_ne!(
            wrote["result"]["len"],
            json!(common::META_DOCUMENT.len()),
            "what was buffered is the document rather than the payload: {wrote}"
        );
    }
    let committed = answer(&responses, 4);
    assert_eq!(committed["result"]["committed"], json!(1), "{committed}");

    // On disk, and read as bytes rather than through the view: the payload of a
    // resource is never a document, whatever the reader would make of it.
    let cache = rpf_core::keys::Cache::at(&cache);
    let mut file = fs::File::open(&archive).expect("readable");
    let opened = rpf_core::Archive::open(&mut file, &rpf_core::Unlock::cached(cache, "meta.rpf"))
        .expect("the committed archive opens under the material it was packed with");
    let index = opened.find("data/thing.ymt").expect("the entry is there");
    let payload = opened.extract(&mut file, index).expect("extracts");
    assert!(
        !payload.starts_with(b"<?xml"),
        "the document was written into the resource entry as its payload",
    );
    assert_ne!(payload, common::META_DOCUMENT.as_bytes());
    let names = rpf_core::Dictionary::default();
    let viewed = rpf_core::view::read(
        &mut file,
        &opened,
        index,
        "data/thing.ymt",
        rpf_core::view::Wanted {
            view: rpf_core::View::Xml,
            names: &names,
        },
    )
    .expect("the committed resource still reads as a document");
    assert_eq!(
        String::from_utf8_lossy(&viewed.bytes),
        common::META_DOCUMENT
    );
}

#[test]
fn an_auto_write_of_a_document_into_an_unreadable_resource_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("meta.rpf");
    let payload = vec![0xFF_u8; 64];
    let mut out = fs::File::create(&archive).expect("creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &[FileSpec {
            path: "data/thing.ymt".to_owned(),
            kind: FileKind::Resource {
                declared: Some(common::META_FLAGS),
            },
        }],
        &[],
        |_: &str| Ok(Cursor::new(payload.clone())),
        &mut Unwatched,
    )
    .expect("builds");
    drop(out);
    let before = fs::read(&archive).expect("readable");

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": archive.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/thing.ymt",
            "bytes": BASE64.encode(common::META_DOCUMENT), "as":"auto"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1}}),
    ]);
    let refused = answer(&responses, 2);
    assert_eq!(
        refused["error"]["data"]["reason"],
        json!("NoXmlView"),
        "a document became the payload of a resource nothing could read: {refused}"
    );
    let committed = answer(&responses, 3);
    assert_eq!(
        committed["result"]["committed"],
        json!(0),
        "the refused write was buffered anyway: {committed}"
    );
    assert_eq!(
        fs::read(&archive).expect("readable"),
        before,
        "the archive moved under a write that was refused"
    );
}

#[test]
fn a_meta_refuses_a_wrong_boundary_and_a_document_it_cannot_take() {
    let dir = tempfile::tempdir().expect("temp dir");
    let elsewhere = dir.path().join("elsewhere.rpf");
    make_meta_archive(&elsewhere, common::META_ELSEWHERE);
    let good = dir.path().join("meta.rpf");
    make_meta_archive(&good, common::META_FLAGS);
    let before = fs::read(&good).expect("readable");

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": elsewhere.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"read","params":{
            "handle":1,"path":"data/thing.ymt","as":"xml"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"write","params":{
            "handle":1,"path":"data/thing.ymt",
            "bytes": BASE64.encode(common::META_EDITED), "as":"xml"}}),
        json!({"jsonrpc":"2.0","id":4,"method":"open","params":{
            "path": good.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":5,"method":"write","params":{
            "handle":2,"path":"data/thing.ymt",
            "bytes": BASE64.encode("<?xml version=\"1.0\"?><SomethingElse/>"), "as":"xml"}}),
        json!({"jsonrpc":"2.0","id":6,"method":"commit","params":{"handle":2}}),
    ]);
    for id in [2, 3] {
        let refused = answer(&responses, id);
        assert_eq!(
            refused["error"]["data"]["reason"],
            json!("BadMeta"),
            "{refused}"
        );
    }
    let refused = answer(&responses, 5);
    assert_eq!(
        refused["error"]["data"]["reason"],
        json!("NotMetaXml"),
        "{refused}"
    );
    let committed = answer(&responses, 6);
    assert_eq!(committed["result"]["committed"], json!(0), "{committed}");
    assert_eq!(
        fs::read(&good).expect("readable"),
        before,
        "a refused conversion wrote something"
    );
}

#[test]
fn a_resource_that_is_not_a_meta_still_has_no_xml_view() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("rockstar.rpf");
    let resource = make_rockstar_archive(&archive);

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": archive.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"read","params":{
            "handle":1,"path":"art.ydr","as":"xml"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"read","params":{
            "handle":1,"path":"art.ydr","as":"auto"}}),
    ]);
    let refused = answer(&responses, 2);
    assert_eq!(
        refused["error"]["data"]["reason"],
        json!("NoXmlView"),
        "{refused}"
    );
    let automatic = answer(&responses, 3);
    assert_eq!(automatic["result"]["as"], json!("raw"), "{automatic}");
    assert_eq!(automatic["result"]["encoding"], json!(null), "{automatic}");
    assert_eq!(
        automatic["result"]["bytes"],
        json!(BASE64.encode(&resource)),
        "{automatic}"
    );
}

/// Asserted over the bytes a raw read gives back: the length that landed was the document's own.
#[test]
fn an_auto_write_of_a_document_into_a_resource_is_refused_on_the_wire() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    let resource = make_archive(&archive);
    let path = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": path}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"art.yft",
            "bytes": BASE64.encode(common::META_DOCUMENT), "as":"auto"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1}}),
        json!({"jsonrpc":"2.0","id":4,"method":"read","params":{
            "handle":1,"path":"art.yft","as":"raw"}}),
    ]);
    let refused = answer(&responses, 2);
    assert_eq!(
        refused["error"]["data"]["reason"],
        json!("NoXmlView"),
        "{refused}"
    );
    assert!(
        refused["result"].is_null(),
        "the document was buffered: {refused}"
    );
    let committed = answer(&responses, 3);
    assert_eq!(committed["result"]["committed"], json!(0), "{committed}");
    let after = answer(&responses, 4);
    assert_eq!(
        after["result"]["bytes"],
        json!(BASE64.encode(&resource)),
        "the document landed as the resource's payload: {after}"
    );
}
