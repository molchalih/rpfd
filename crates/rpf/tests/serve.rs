//! The stdio daemon: warm state, buffered edits, one rebuild per commit.
//!
//! Corpus-free — these build their own archives, as the command-line tests do.
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
    io::{BufRead as _, Cursor, Write as _},
    path::Path,
    process::{Command, Stdio},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rpf_core::{FileKind, FileSpec, Storage, Unwatched};
use serde_json::{Value, json};

const RPF: &str = env!("CARGO_BIN_EXE_rpf");

/// An archive with one deflated file and one resource.
fn make_archive(at: &Path) -> Vec<u8> {
    // A minimal but real resource: an RSC7 header whose flags describe one
    // 512-byte system page and no graphics pages, followed by a deflate stream
    // of exactly that. The flags are what `verify` reads the payload back
    // against — `docs/rpf-format.md`, Resource page flags — so a resource whose
    // flags described 131,072 bytes of a 512-byte payload would fail it, and
    // this one did until `verify` was something the daemon could be asked for.
    // The top nibbles give the header's version field, 162, as the same table
    // says they must.
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
            kind: FileKind::Resource,
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

/// An archive holding two entries that fold to one name, returning its bytes.
///
/// `build` will not write one, so it is built under two names of the same
/// length and then the second is edited in the names blob: everything but that
/// one name is what the writer produced.
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

/// Where one entry's payload sits and how much room it has, read from the
/// archive so that a report about them can be checked against something other
/// than itself.
fn spans(at: &Path, inside: &str) -> (u64, u64) {
    let mut file = fs::File::open(at).expect("archive opens");
    let archive =
        rpf_core::Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("archive parses");
    let index = archive.find(inside).expect("entry resolves");
    let (payload_at, _) = archive.payload_at(index).expect("payload span");
    (payload_at, archive.allocation(index).expect("allocation"))
}

/// Feeds every request in, and returns the responses.
///
/// Responses only: progress arrives as JSON-RPC notifications, which carry no
/// `id`, and a client reads past them looking for the one it sent. DR-008.
fn talk(requests: &[Value]) -> Vec<Value> {
    narrated(requests).0
}

/// The response carrying an id.
///
/// By id rather than by position: `cancel` is answered by the reading thread
/// without waiting its turn, so it can overtake a response to a request sent
/// before it. DR-008.
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

/// As [`talk`], with the daemon started in `cwd`, so a request can name an
/// archive by a relative path.
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

/// Feeds every request in and sorts what came back: responses first.
fn drive(mut daemon: Command, requests: &[Value]) -> (Vec<Value>, Vec<Value>) {
    let mut child = daemon
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("daemon starts");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        for request in requests {
            writeln!(stdin, "{request}").expect("writable");
        }
    }
    let output = child.wait_with_output().expect("daemon exits");
    String::from_utf8_lossy(&output.stdout)
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
        // A read of a buffered path returns what was written, not what is on disk.
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

    // After the commit the warm state describes the archive that is now on
    // disk, so the same read no longer reports a pending buffer.
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
fn a_resource_entry_refuses_a_payload_that_is_not_one() {
    // R6.6. The primary consumer is automation, which will attempt exactly this.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    let resource = make_archive(&archive);
    let archive_str = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"art.yft","bytes": BASE64.encode(b"plain text, not a resource")}}),
        // The same entry accepts a payload that is one.
        json!({"jsonrpc":"2.0","id":3,"method":"write","params":{
            "handle":1,"path":"art.yft","bytes": BASE64.encode(&resource)}}),
    ]);

    assert_eq!(
        responses[1]["error"]["code"],
        json!(6),
        "should have been refused"
    );
    let message = responses[1]["error"]["message"]
        .as_str()
        .unwrap_or_default();
    assert!(message.contains("RSC7"), "message was: {message}");
    assert!(
        responses[2].get("result").is_some(),
        "a real resource should be accepted"
    );
}

#[test]
fn unknown_methods_and_handles_are_refused_not_ignored() {
    // Two numbering schemes, and which one a code comes from is the answer to
    // "whose fault is this". Negative is JSON-RPC's own: the request did not
    // follow the protocol. Positive is the process exit code the same failure
    // would produce on the command line: the request was well formed and the
    // work did not succeed.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"nonsense","params":{}}),
        // A handle that was never opened is not a malformed request: it is a
        // well-formed one this daemon declines.
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
    // Which is what `"id": null` is reserved for: there was no id to echo,
    // because there was no request.
    let responses = talk(&[
        json!("not an object at all"),
        json!({"jsonrpc":"2.0","id":2,"params":{}}),
    ]);

    assert_eq!(responses[0]["id"], json!(null));
    assert_eq!(responses[0]["error"]["code"], json!(-32600));
    assert_eq!(responses[1]["id"], json!(null));
    assert_eq!(responses[1]["error"]["code"], json!(-32600));
}

/// Bytes that do not compress, so no edit of them fits a spare block.
fn incompressible(len: u32) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i.wrapping_mul(2_654_435_761) >> 13) & 0xFF).unwrap_or_default())
        .collect()
}

#[test]
fn a_commit_that_fits_patches_in_place() {
    // R4.14. The whole point: an edit that fits costs the bytes of the edit,
    // not the bytes of the archive.
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
    // Both edits land, and they land the same way: a commit is all of it or
    // none of it, never two patched and one rebuilt on top.
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
    // A patch is not crash-atomic and a rebuild is. A caller that wants the
    // stronger guarantee has to be able to ask for it.
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
    // R6.7. An editor asking "what does saving cost" must not lose the buffer
    // by asking, and must not have to guess which of the two ways it will go.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();
    let before = fs::read(&archive).expect("readable");
    // Read from the archive rather than believed from the answer: "an offset,
    // a length and some room" is true of every archive ever written, and an
    // editor deciding whether to save acts on the numbers.
    let (at, allocation) = spans(&archive, "data/greeting.txt");

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(b"replaced")}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1,"dry_run":true}}),
        // The buffer survives, so the real commit can still follow.
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
    // That the real commit then goes the way this predicted is what
    // `a_commit_that_fits_patches_in_place` asserts, against the same archive
    // and the same edit.
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
    // R6.8, DR-008. The objects carry no id, so a client reading for its own
    // response reads past them.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let (responses, notifications) = narrated(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(b"replaced")}}),
        // Rebuild rather than patch, because a patch writes the bytes of one
        // edit and has nothing worth reporting.
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
        // Nothing was dropped: this client read everything the daemon sent.
        assert_eq!(params["skipped"], json!(0), "{notification}");
    }

    // Every entry of the archive is accounted for, in order, and each is named
    // by the entry it is reporting. A path that says only "a string" would let
    // every notification carry the same one.
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
    // The one dry-run branch that answers without calling `plan` at all: the
    // rebuild was asked for rather than forced by an edit that will not fit, so
    // nothing computes the answer — and an answer nothing computes is an answer
    // nothing checks.
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
    // The same edit, not told to rebuild, is reported as a patch. So this
    // answer is the flag being obeyed rather than the edit not fitting;
    // `a_dry_run_commit_reports_what_it_would_do_and_keeps_the_edits` is that
    // case in full, against the same archive and the same edit.
}

#[test]
fn a_cancel_with_nothing_running_is_answered_not_stored() {
    // Storing it would cancel the next commit, which nobody asked for.
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
    // during the only period when it is useful has to arrive then, not after.
    // DR-008.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("big.rpf");

    // Big enough, and incompressible enough, that the rebuild takes far longer
    // than the interval the cancels are sent at. Sixteen entries also means
    // sixteen chances to observe the flag.
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

    let mut child = Command::new(RPF)
        .args(["serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("daemon starts");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");

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

    // Keep asking until the commit answers. The interval is short enough that
    // the flag is set within one entry of the rebuild starting.
    let mut commit = None;
    let mut cancels = 0;
    while commit.is_none() {
        let cancel = json!({"jsonrpc":"2.0","id":900,"method":"cancel","params":{}});
        if writeln!(stdin, "{cancel}").is_err() {
            break;
        }
        cancels += 1;
        assert!(cancels < 2000, "the commit never answered");
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
    let _ = child.wait();
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

/// An archive of `entries` files, each of `payload` zero bytes.
///
/// Zeros so that building it costs little, and many entries so that a rebuild
/// of it reports more progress than a pipe will hold: 64 KB of notifications
/// is what it takes to make a daemon that writes them synchronously block.
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

/// A change that collides only with another buffered change is refused when it
/// is offered, rather than accepted and failed at the commit.
///
/// Both arms were measured against a live daemon on 2026-08-29 and are rows of
/// DR-030's table. `allows` resolved each change against the archive on disk
/// alone, so neither collision was visible until the commit had already
/// decided everything else. DR-032.
#[test]
fn a_change_that_collides_only_with_a_buffered_one_is_refused_when_it_is_offered() {
    let dir = tempfile::tempdir().expect("temp dir");

    // `rename a -> b` then `write b {create: true}`: accepted, `pending: 2`,
    // and the commit answered `AlreadyExists`.
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

    // Renaming a directory and then something inside it: accepted twice, and
    // the commit answered exit 3, because `tree_of` applies renames in path
    // order and the directory's runs first.
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

/// DR-026's replacing rename can be assembled over the wire: a removal in the
/// same session frees the path a rename moves onto.
///
/// The record says a caller that means to replace the target removes it in the
/// same change set, which is why removals are applied before renames. The
/// library accepted that set and no order of requests could build it — `delete
/// readme.txt` then `rename x -> readme.txt` was exit 6, `"readme.txt" is
/// already in the archive`, measured 2026-08-29. DR-032.
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

/// A second change of another kind at one path is refused rather than quietly
/// replacing the first.
///
/// Measured 2026-08-29: `rename art.yft -> moved.yft` then `write art.yft`
/// answered `pending: 1`, and the commit renamed nothing — the rename left the
/// buffer with an `Ok` and no client could tell. A set holds one change per
/// path and that is not changing; what changes is that the wire says so.
/// DR-032.
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

/// `forget` takes one buffered change back and says what is left.
///
/// Withdrawing a gesture — create a file and delete it, rename an entry back to
/// the name it started with — used to cost a `discard` and a replay of
/// everything else, so a client had to retain every buffered payload in order
/// to send it again. DR-030 asked for this; DR-032 decided it.
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

/// Withdrawing a rename lets the path be changed again, which is the gesture
/// the wire had no way to express: the buffer took a change at a path and had
/// no way to take one away.
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

/// A buffered structural change does not turn every later write into a walk of
/// the entry table.
///
/// The shape this guards is the one that was measured to time out: `allows`
/// walks the entry table, and asking it per change over a four-thousand-entry
/// archive with four thousand buffered writes is quadratic. Judging a change
/// against the buffered set could have reintroduced exactly that, so the
/// question "could anything buffered have moved this path" is answered from the
/// set alone, and only a `true` costs the walk. Measured with the question
/// forced to `true`: 1.5 seconds becomes 34. DR-032.
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
    // And the one write the removal really does reach is refused, which is the
    // whole reason the question is asked.
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

/// Every error object carries the failure's own name beside its number, so a
/// client tells `AlreadyExists` from every other refusal without reading the
/// sentence.
///
/// DR-026 made `AlreadyExists` its own variant *because* a client mapping it
/// onto an editor's filesystem has a distinct answer for it (`FileExists`), and
/// the wire carried only `code: 6`, shared with every refusal there is — so the
/// stated reason for the variant was not true over the wire. DR-030 found that;
/// DR-032 answers it. The number is unchanged and is still what DR-010 says it
/// is.
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
        // And one that is not a refusal at all.
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
fn a_second_session_on_one_archive_is_refused_rather_than_detected_later() {
    // Two sessions on one archive is the shape all three demonstrated
    // corruptions took: the first rebuilds, so the file is replaced by rename
    // and every offset in it moves, and the second is still holding the entry
    // table it parsed at open. Committing that patched at offsets that now land
    // inside another entry's payload — and the result still verified.
    //
    // It is not detected any more, it is unreachable: the second session is
    // refused where the client can still do something about it. DR-009.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();
    let big = incompressible(200_000);

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"open","params":{"path": archive_str}}),
        // The first session goes on working, and rebuilds.
        json!({"jsonrpc":"2.0","id":3,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(&big)}}),
        json!({"jsonrpc":"2.0","id":4,"method":"commit","params":{"handle":1}}),
        // Closing it releases the claim, and the next session sees what the
        // commit left.
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
    // A claim that could be walked around by writing the same path differently
    // would be no claim at all, and every one of these is a path a client
    // plausibly sends. DR-009.
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
    // `cfg!` rather than `#[cfg]`: an attribute removes the push outright,
    // which leaves the binding needlessly mutable on Windows and the whole list
    // a candidate for an array. A run-time-shaped branch on a compile-time
    // constant costs nothing and keeps one spelling of the list.
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
        assert!(message.contains("handle 1"), "{spelling}: {message}");
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
    // The flags were global while sessions are per-handle, so a cancel aimed at
    // one commit landed on whichever commit happened to be running. A cancel
    // names what it is cancelling: the request that started it, or the handle
    // it is running against.
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

    let mut child = Command::new(RPF)
        .args(["serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("daemon starts");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");

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
    let mut sent = 0;
    while commit.is_none() {
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
        sent += 1;
        assert!(sent < 2000, "the commit never answered");
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
    let _ = child.wait();
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
fn a_cancel_during_a_commit_that_patches_is_told_why_it_cannot() {
    // Two registrations that only exist in the running daemon, and that the
    // unit tests around `Cancellation` cannot reach: the commit registers
    // itself before it has decided anything, because deciding reads and
    // compresses every buffered edit and a cancel arriving then must not be
    // told nothing is running; and the patch it decides on registers itself as
    // one that cannot be stopped, because a half-applied patch is the corrupt
    // archive §8 exists to prevent. Neither is asserted anywhere else, and
    // dropping either leaves every other test green.
    //
    // Four thousand entries so that both phases last long enough for a cancel
    // to arrive inside them: deciding deflates every edit, and applying seeks,
    // writes and flushes twice per entry.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("many.rpf");
    make_bulk_archive(&archive, 4000, 512);

    let mut child = Command::new(RPF)
        .args(["serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("daemon starts");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");

    let (lines, received) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if lines.send(line).is_err() {
                break;
            }
        }
    });

    writeln!(
        stdin,
        "{}",
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": archive.display().to_string()}})
    )
    .expect("writable");
    // An edit per entry, each small enough to fit where its entry already sits,
    // so the commit decides to patch rather than to rebuild.
    for index in 0..4000_u64 {
        let request = json!({"jsonrpc":"2.0","id": 100 + index,"method":"write","params":{
            "handle":1,"path": format!("bulk/{index:04}.bin"),
            "bytes": BASE64.encode(vec![9_u8; 512])}});
        writeln!(stdin, "{request}").expect("writable");
    }
    writeln!(
        stdin,
        "{}",
        json!({"jsonrpc":"2.0","id":9,"method":"commit","params":{"handle":1}})
    )
    .expect("writable");

    let mut commit = None;
    let mut answers = Vec::new();
    let mut sent = 0;
    while commit.is_none() {
        let cancel = json!({"jsonrpc":"2.0","id":1_000_000,"method":"cancel","params":{}});
        if writeln!(stdin, "{cancel}").is_err() {
            break;
        }
        sent += 1;
        assert!(sent < 40_000, "the commit never answered");
        std::thread::sleep(std::time::Duration::from_micros(125));

        while let Ok(line) = received.try_recv() {
            let object: Value = serde_json::from_str(&line).expect("a JSON object per line");
            if object["id"] == json!(9) {
                commit = Some(object);
            } else if object["id"] == json!(1_000_000) {
                answers.push(object);
            }
        }
    }
    drop(stdin);
    let commit = commit.expect("the commit answered");
    let _ = child.wait();
    let _ = reader.join();

    assert_eq!(
        commit["result"]["method"],
        json!("patch"),
        "the edits did not fit where their entries sit: {commit}"
    );
    assert_eq!(commit["result"]["committed"], json!(4000), "{commit}");

    // Nothing in a commit that patches can be stopped, at either stage.
    for object in &answers {
        assert_eq!(
            object["result"]["cancelling"],
            json!(false),
            "a commit that patches said it was stopping: {object}"
        );
    }
    let reason_while = |running: &str| -> Option<String> {
        answers
            .iter()
            .find(|object| object["result"]["running"] == json!(running))
            .map(|object| object["result"]["reason"].to_string())
    };
    let deciding = reason_while("commit").expect("no cancel arrived while the commit was deciding");
    assert!(
        deciding.contains("whether every edit fits"),
        "a cancel during the decision was answered without saying why: {deciding}"
    );
    let patching = reason_while("patch").expect("no cancel arrived while the patch was running");
    assert!(
        patching.contains("no part-way to stop at"),
        "a cancel during the patch was answered without saying why: {patching}"
    );
}

#[test]
fn a_cancel_after_a_commit_has_answered_finds_nothing_running() {
    // The job is registered for exactly as long as there is something to name.
    // Left registered, a cancel arriving afterwards is answered as though the
    // finished commit were still going — and, the rebuild being stoppable, it
    // is also marked cancelled, so the next rebuild in that session stops at
    // its first entry having been cancelled by nobody.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);

    let mut child = Command::new(RPF)
        .args(["serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("daemon starts");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut lines = std::io::BufReader::new(child.stdout.take().expect("stdout")).lines();

    for request in [
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": archive.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(b"replaced")}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1,"rebuild":true}}),
    ] {
        writeln!(stdin, "{request}").expect("writable");
    }

    // The cancel goes out only once the commit has answered, so it cannot race
    // the rebuild it would otherwise be naming.
    let mut committed = None;
    while committed.is_none() {
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
    let _ = child.wait();
}

#[test]
fn a_client_that_stops_reading_cannot_wedge_the_daemon() {
    // Standard output was written under a lock held across the write, so a
    // client that stopped draining it blocked the worker with the lock held —
    // and the reading thread then blocked on the same lock answering the
    // cancel, which is what turned backpressure into a deadlock. Nothing was
    // read from standard input again, the cancel included.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("many.rpf");
    // Enough entries, and small enough ones, that a rebuild has written more
    // progress than a pipe holds within the first few hundred milliseconds:
    // the daemon has to be blocked in that write before the cancel arrives,
    // because that is the moment the deadlock is made of.
    make_bulk_archive(&archive, 3000, 1024);

    let mut child = Command::new(RPF)
        .args(["serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("daemon starts");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");

    for request in [
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
            "path": archive.display().to_string()}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"bulk/0000.bin","bytes": BASE64.encode(b"replaced")}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1,"rebuild":true}}),
    ] {
        writeln!(stdin, "{request}").expect("writable");
    }
    // Nothing has read a byte of standard output, and nothing will until the
    // 1 MB request below has been accepted.
    std::thread::sleep(std::time::Duration::from_millis(500));

    let (done, finished) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        let cancel = json!({"jsonrpc":"2.0","id":4,"method":"cancel","params":{"handle":1}});
        let outcome = writeln!(stdin, "{cancel}").and_then(|()| {
            let big = json!({"jsonrpc":"2.0","id":5,"method":"write","params":{
                "handle":1,"path":"bulk/0001.bin","bytes": BASE64.encode(vec![7_u8; 1 << 20])}});
            writeln!(stdin, "{big}")
        });
        let _ = done.send(outcome.is_ok());
        stdin
    });

    let wedged = finished
        .recv_timeout(std::time::Duration::from_secs(8))
        .is_err();

    // Drain before anything is joined, so that a daemon that *is* wedged comes
    // unstuck and this test fails rather than hangs.
    let drain = std::thread::spawn(move || {
        let mut lines = Vec::new();
        for line in std::io::BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            lines.push(line);
        }
        lines
    });
    assert!(
        !wedged,
        "a 1 MB request was not accepted in eight seconds: the daemon is wedged"
    );

    let sending = writer.join().expect("the writing thread finished");
    drop(sending);
    let status = child.wait().expect("the daemon exits");
    let lines = drain.join().expect("the draining thread finished");
    assert!(status.success(), "the daemon exited with {status}");

    let objects: Vec<Value> = lines
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("a JSON object per line"))
        .collect();
    assert!(
        objects.iter().any(|object| object["id"] == json!(4)),
        "the cancel was never answered"
    );
    assert!(
        objects.iter().any(|object| object["id"] == json!(3)),
        "the commit was never answered"
    );
    // Progress is dropped rather than queued without bound, so a client that
    // was not reading does not receive one notification per entry after the
    // fact either.
    let progress = objects
        .iter()
        .filter(|object| object["method"] == json!("progress"))
        .count();
    assert!(
        progress < 3000,
        "every notification was kept for a client that was not reading: {progress}"
    );
}

#[test]
fn a_client_that_is_behind_is_told_how_many_notifications_it_missed() {
    // Progress is dropped rather than queued without bound, so a client reading
    // slower than the rebuild writes sees gaps in `done`. `skipped` is what
    // makes a gap readable: it counts what was dropped since the last
    // notification that got through, so between two that arrive it is exactly
    // the distance between them. Nothing else here reads the counter, and a
    // counter nothing reads may as well be a constant.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("many.rpf");
    make_bulk_archive(&archive, 3000, 1024);

    let mut child = Command::new(RPF)
        .args(["serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("daemon starts");
    let stdout = child.stdout.take().expect("stdout");
    let reading =
        std::thread::spawn(move || read_slowly(stdout, 512, std::time::Duration::from_millis(4)));
    {
        let mut stdin = child.stdin.take().expect("stdin");
        for request in [
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
                "path": archive.display().to_string()}}),
            json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
                "handle":1,"path":"bulk/0000.bin","bytes": BASE64.encode(b"replaced")}}),
            json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1,"rebuild":true}}),
        ] {
            writeln!(stdin, "{request}").expect("writable");
        }
    }
    let status = child.wait().expect("the daemon exits");
    let read = reading.join().expect("the reading thread finished");
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
    let mut gaps = 0_u32;
    for (done, skipped) in &steps {
        assert_eq!(
            *skipped,
            done.saturating_sub(previous).saturating_sub(1),
            "step {done} followed step {previous} but claims {skipped} dropped: {steps:?}",
        );
        if *skipped > 0 {
            gaps = gaps.saturating_add(1);
        }
        previous = *done;
    }
    assert!(
        gaps > 0,
        "nothing was dropped, so this says nothing about the counter: {} of 3000 arrived",
        steps.len(),
    );
}

#[test]
fn a_broken_standard_output_is_reported_rather_than_swallowed() {
    // The reading thread broke out of its loop when it could not write the
    // answer to a cancel, and run() then returned Ok(()): the daemon stopped
    // accepting requests, said nothing about why, and exited 0 having failed.
    // Which of the two conditions it broke on was not reported either.
    //
    // Enough cancels that the answers cannot all have been written into a pipe
    // nobody is reading, so the reading end below closes on a write that is
    // either in flight or still queued.
    let mut child = Command::new(RPF)
        .args(["serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("daemon starts");
    let mut stdin = child.stdin.take().expect("stdin");
    let feeding = std::thread::spawn(move || {
        let cancel = json!({"jsonrpc":"2.0","id":1,"method":"cancel","params":{}});
        for _ in 0..4000 {
            if writeln!(stdin, "{cancel}").is_err() {
                break;
            }
        }
    });
    std::thread::sleep(std::time::Duration::from_millis(300));
    drop(child.stdout.take());

    let status = child.wait().expect("the daemon exits");
    let _ = feeding.join();
    let mut complaint = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = std::io::Read::read_to_string(&mut stderr, &mut complaint);
    }

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
    // `stopped_as` is unit-tested, and the unit test passes with nothing
    // calling it. This is the bug it was written for, end to end: a rebuild
    // reporting progress to a client that has gone away stops itself, the
    // library reports that as `Cancelled` because a watcher said stop, and
    // reporting it onward as a cancellation tells the caller it asked for
    // something it did not ask for — and hands automation exit 8, "you stopped
    // it", for a broken pipe.
    //
    // Enough entries that the rebuild is still running, and still writing
    // progress, when the reading end closes.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("many.rpf");
    make_bulk_archive(&archive, 4000, 1024);

    let mut child = Command::new(RPF)
        .args(["serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("daemon starts");
    let mut stdin = child.stdin.take().expect("stdin");
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
    drop(child.stdout.take());
    // And standard input ends, because nothing more is coming: a daemon
    // waiting for the next request would otherwise wait for ever, and what is
    // under test is what it exits with, not when.
    drop(stdin);

    let status = child.wait().expect("the daemon exits");
    let mut complaint = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = std::io::Read::read_to_string(&mut stderr, &mut complaint);
    }

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
    // JSON-RPC forbids answering one, and `"id": null` is what a parse error
    // means. Answering with it made the two indistinguishable.
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
    // A 3000-entry archive is 3000 lines a client may have no use for.
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
    // `cancel` with no parameters means "whatever is running", which is the
    // destructive default, and a parameter that was *given* but not *seen*
    // degraded to it: `{"handle": "2"}` and the rest all answered
    // `cancelling: true` and stopped a commit on handle 1 that they had named
    // handle 2 to spare. Every other method answers -32602 for a parameter of
    // the wrong type, and this one is answered ahead of them all.
    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"cancel","params":{"handle":"2"}}),
        json!({"jsonrpc":"2.0","id":2,"method":"cancel","params":{"handle":2.0}}),
        json!({"jsonrpc":"2.0","id":3,"method":"cancel","params":{"handle":-1}}),
        json!({"jsonrpc":"2.0","id":4,"method":"cancel","params":{"handle":null}}),
        json!({"jsonrpc":"2.0","id":5,"method":"cancel","params":{"handel":2}}),
        json!({"jsonrpc":"2.0","id":6,"method":"cancel","params":"not-an-object"}),
        json!({"jsonrpc":"2.0","id":7,"method":"cancel","params":{"handle":[2]}}),
        // Well typed, and still answered: naming nothing means "whatever is
        // running", and nothing is.
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
    // The fault as it actually presented: a rebuild running on handle 1, a
    // cancel aimed at handle 2, and the handle not of a type the daemon read.
    // Every one of these killed handle 1's commit, ten times out of ten.
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

    let mut child = Command::new(RPF)
        .args(["serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("daemon starts");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");

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
    let mut sent = 0;
    while commit.is_none() {
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
        sent += 1;
        assert!(sent < 2000, "the commit never answered");
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
    let _ = child.wait();
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

/// Reads everything on `stdout`, taking `piece` bytes and then pausing.
///
/// An ordinary client, reading at an ordinary rate. The daemon has to deliver
/// an answer larger than it can write in one grace to one of these.
fn read_slowly(
    mut stdout: std::process::ChildStdout,
    piece: usize,
    pause: std::time::Duration,
) -> Vec<u8> {
    use std::io::Read as _;
    let mut all = Vec::new();
    let mut buffer = vec![0_u8; piece];
    loop {
        match stdout.read(&mut buffer) {
            Ok(0) | Err(_) => return all,
            Ok(taken) => all.extend_from_slice(buffer.get(..taken).unwrap_or_default()),
        }
        std::thread::sleep(pause);
    }
}

#[test]
fn an_answer_bigger_than_the_grace_survives_standard_input_ending() {
    // `rpf serve --stdio < requests.jsonl` is the shape the module doc names as
    // the primary consumer, and standard input ends there the moment the last
    // request has been read — long before the answer to it has been written.
    // The daemon gave standard output a flat two seconds from that point and
    // then exited, which cut the response off mid-object with no terminating
    // newline: that breaks the framing contract, not merely the response.
    // Measured ten times out of ten against the sample's 62,611,968-byte
    // `x64/vehicles.rpf` — 83,482,931 bytes of response on one line — with a
    // client reading at about 13 MB/s: ~18.1 MB arrived, unterminated, and the
    // read was never answered. Exit 7.
    //
    // Half a megabyte and a reader taking 8 KB every 40 ms is the same shape,
    // small enough to build in a test: 700 KB of base64 at 200 KB/s is three
    // and a half seconds, and the old grace was two.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("one.rpf");
    make_bulk_archive(&archive, 1, 512 * 1024);

    let mut child = Command::new(RPF)
        .args(["serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
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
        // And standard input ends here, with the answer not yet written.
    }
    let stdout = child.stdout.take().expect("stdout");
    let taken = read_slowly(stdout, 8 * 1024, std::time::Duration::from_millis(40));
    let status = child.wait().expect("the daemon exits");

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
///
/// `ps` because the question is what the operating system is actually holding
/// for the daemon, which is the thing that was measured going up and never
/// coming down.
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
    // PROGRESS_BACKLOG bounded the one thing that may be dropped and nothing
    // else. `Wire::answer` queued a response and returned, so the worker went
    // on accepting requests and materialising answers however far behind the
    // client was: measured against the sample with nothing drained, queueing
    // reads of one 20 MB entry, 24 answers reached 369 MB of resident memory
    // and 96 reached 1,393 MB. Linear, with no ceiling. The same runs with the
    // bound in place measure 56 MB either way.
    //
    // Zero-byte payloads, so the archive is small and quick to build and each
    // answer is still megabytes of base64.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("bulk.rpf");
    let entry = 2 * 1024 * 1024;
    make_bulk_archive(&archive, 64, entry);

    let mut child = Command::new(RPF)
        .args(["serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("daemon starts");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");

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
        let resident = resident_kilobytes(child.id());
        assert!(
            resident < 96 * 1024,
            "the daemon is holding {resident} KB of answers for a client that is not reading"
        );
    }

    // Everything is still owed, and arrives once the client reads again: an
    // answer may wait, and may never be dropped.
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
    let status = child.wait().expect("the daemon exits");
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
    // A hard link is a second directory entry for one file, and both spellings
    // canonicalise to themselves, so a claim keyed on the canonical path
    // accepted both. That is two sessions on one archive — the state DR-009
    // exists to make unreachable — and after either one rebuilds, the other
    // holds an entry table describing bytes that have moved.
    //
    // `#[cfg(any(unix, windows))]` rather than no gate: `FileId` still has an
    // identity-less arm, and a refusal is something it can never produce, so
    // this asserts nothing a third platform could pass. On Windows
    // `fs::hard_link` is `CreateHardLinkW` and the identity is the volume
    // serial and file index, so this is the same test against the same
    // filesystem feature; it ran only on Unix until R10.5, and it failed on
    // Windows before that. DR-037.
    //
    // **It requires a volume that names its files**, which every NTFS volume
    // does and the temporary directory is on in both places this suite runs. A
    // volume that answers with a zero serial — a redirector, measured in
    // DR-037 — leaves DR-009's claim on the path alone, and there is nothing
    // here to catch. That is the same NTFS-shaped assumption DR-035 already
    // makes about `fs::rename`, stated rather than discovered.
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
        // Closing the first releases the claim, and the second name opens.
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
    assert!(
        message.contains("handle 1"),
        "the refusal must name the handle holding it: {message}"
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
    // canonical path under `/System/Volumes/Data`. Verified on 2026-08-27:
    // `/private/var/folders/.../probe.txt` and
    // `/System/Volumes/Data/private/var/folders/.../probe.txt` each resolve to
    // themselves — two different canonical paths — and both name device
    // 16777229, inode 55712401.
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
    // afterwards is not the file it opened — a different inode on Unix, a
    // different file index on Windows. A claim that kept the identity it first
    // saw would go on claiming a file nobody has and stop recognising the one
    // it does have — and a second session on that is the corruption again.
    //
    // Gated and preconditioned exactly as the hard-link test above is, and for
    // the same two reasons.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();
    let big = incompressible(200_000);

    let mut child = daemon()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("daemon starts");
    let mut stdin = child.stdin.take().expect("stdin");
    for request in [
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
            "handle":1,"path":"data/greeting.txt","bytes": BASE64.encode(&big)}}),
        json!({"jsonrpc":"2.0","id":3,"method":"commit","params":{"handle":1}}),
    ] {
        writeln!(stdin, "{request}").expect("writable");
    }
    // The commit is read before the second name is made, so the link is made
    // against the inode the rebuild left rather than the one it replaced.
    let mut lines = std::io::BufReader::new(child.stdout.take().expect("stdout"));
    let committed = loop {
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
    let _ = child.wait();

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
    // It answered `{"closed": true, "discarded": 0}`, which tells a client that
    // closed the wrong handle that a claim was released when it was not —
    // precisely the "locked out of your own archive" case DR-009 says is
    // diagnosable. Every other method answers code 6 for the same handle.
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
    // `Cancellation::ask` echoed the running job's `request` — the client's own
    // JSON-RPC id, an arbitrary value it wrote once — into every cancel answer,
    // and cancel answers are queued by the reading thread, whose queue is
    // uncounted and unbounded so that the thread never waits. Measured with a
    // client that never reads standard output, a `commit` carrying a 256 KiB id
    // and a stream of 65-byte cancels: 222 KB of standard input grew the daemon
    // 855 MB, 1.19 MB grew it 4.57 GB and 1.48 MB grew it 5.67 GB — around
    // 3,900 times what the client wrote, linear and with no ceiling. The same
    // run with an eight-byte id grew it 1.4 MB.
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

    let mut child = daemon()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("daemon starts");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");

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
    // file in that directory is the rebuild having started. Waiting for it
    // rather than for a fixed interval, because how long a rebuild takes is a
    // property of the build profile: three hundred milliseconds was under way
    // in a debug build and long finished in a release one, where every cancel
    // below was then answered against nothing at all.
    let waiting = std::time::Instant::now();
    while fs::read_dir(dir.path())
        .into_iter()
        .flatten()
        .flatten()
        .count()
        < 2
    {
        assert!(
            waiting.elapsed() < std::time::Duration::from_secs(30),
            "the rebuild never started"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    // Aimed at a handle that was never opened, so the rebuild goes on running
    // and every one of these is answered rather than acted on.
    let cancel = json!({"jsonrpc":"2.0","id":9,"method":"cancel","params":{"handle":99}});
    for _ in 0..2000 {
        writeln!(stdin, "{cancel}").expect("writable");
    }
    // Nothing has read a byte of standard output, so the answers to those two
    // thousand cancels are all still queued.
    std::thread::sleep(std::time::Duration::from_millis(500));
    let resident = resident_kilobytes(child.id());

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
    let status = child.wait().expect("the daemon exits");
    let objects = drain.join().expect("the draining thread finished");

    assert!(
        resident < 96 * 1024,
        "the daemon is holding {resident} KB of cancel answers echoing an id written once"
    );
    assert!(status.success(), "the daemon exited with {status}");
    // The cancels named a handle that is not running, so the commit ran to the
    // end — and its own answer still carries the id the client sent.
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
/// bytes.
///
/// A client that hiccups: reading, reading fast, and once stopping for longer
/// than the daemon looks at it in one go.
fn read_with_one_pause(
    mut stdout: std::process::ChildStdout,
    after: usize,
    pause: std::time::Duration,
) -> Vec<u8> {
    use std::io::Read as _;
    let mut all = Vec::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut paused = false;
    loop {
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
    // The grace is an idle grace, and it was sampled against a counter that
    // only moved once a whole eight-kilobyte piece had cleared — so one pause
    // longer than the grace was indistinguishable from a client that had gone.
    // Measured with three requests, standard input closed at once and a client
    // reading at full speed that paused once at 200 KB: 1.0 s and 1.8 s
    // delivered three whole objects and exit 0; 2.2 s, ten times out of ten,
    // delivered one whole object and then between 270,336 and 311,296 bytes of
    // a second with no terminating newline, never sent the third, and exited 7.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("one.rpf");
    let entry = 512 * 1024;
    make_bulk_archive(&archive, 1, entry);

    let mut child = daemon()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("daemon starts");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        for request in [
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{
                "path": archive.display().to_string()}}),
            json!({"jsonrpc":"2.0","id":2,"method":"read","params":{
                "handle":1,"path":"bulk/0000.bin"}}),
            json!({"jsonrpc":"2.0","id":3,"method":"read","params":{
                "handle":1,"path":"bulk/0000.bin"}}),
        ] {
            writeln!(stdin, "{request}").expect("writable");
        }
        // And standard input ends here, which is all
        // `rpf serve --stdio < requests.jsonl` does.
    }
    let stdout = child.stdout.take().expect("stdout");
    let taken = read_with_one_pause(stdout, 200 * 1024, std::time::Duration::from_secs(3));
    let status = child.wait().expect("the daemon exits");

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
    // The other side of the pause above, and the reason the wait is bounded at
    // all: a client that holds standard output open and never takes a byte of
    // it cannot be told from one that has gone, and waiting on it for ever
    // would let it stop the daemon exiting.
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
    // Standard output is held open, and never read from.
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
    // §1's own test: anything one frontend can do the other must be able to do,
    // and until this both lived in the binary — so `rpf-editor`, which reaches
    // the container only through the daemon, could ask neither question.
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
    // A failing verify is a finding, not a failure of the call: the daemon did
    // exactly what it was asked and what it found is the answer. The command
    // line exits 4 because a process has one bit to say it with.
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    // The resource, because it is the entry that is actually deflated: eleven
    // bytes of greeting deflate to more than eleven, so `build` stores them,
    // and a stored entry has nothing to check its contents against.
    let (at, _) = spans(&archive, "art.yft");

    // Past the RSC7 header, where the deflate stream begins. 0xFF opens a block
    // with the reserved type, so the stream is refused rather than inflating to
    // some other length.
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

    // Both entries reported themselves on the way past, the failing one
    // included: `done` counts it, so leaving it out would be a gap the client
    // cannot account for.
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
    // The daemon resolves a write through `locate` exactly as `put` does, and
    // it echoed the caller's own spelling back in the answer while buffering an
    // edit against the other entry. Reproduced: the commit then patched `A.txt`
    // and reported `{"committed": 1, "method": "patch"}`.
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

    // Nothing was buffered, so there is nothing for the commit to write.
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
    // §1's test applied to a diagnostic: what the binary tells a caller about
    // the separator, the daemon tells them too, or the two frontends have
    // diverged. DR-016.
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
    // R6.11, and §1's own test with it: `info` grew an in-archive path, and
    // the daemon has to be able to ask the same question. The daemon names the
    // archive by handle, so `path` here means the same thing it means to
    // `list` — a path inside the archive the handle holds.
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

    // A directory is not an archive, and saying so is a refusal rather than a
    // malformed archive. DR-010.
    let refusal = answer(&responses, 4);
    assert_eq!(refusal["error"]["code"], json!(6), "{refusal}");
}

#[test]
fn opening_a_path_that_continues_past_an_archive_is_refused() {
    // The same complaint the command line makes, with the same number: an
    // in-archive path spelled as a filesystem one is a request the daemon does
    // not accept, not the disk misbehaving. DR-010.
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
    // §1's own test, made mechanical for the one command whose rows were built
    // in the binary until now: both frontends read them out of `rpf-core`, so a
    // row that differs between them means the walk has been written twice.
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
    // §1's own test, and the last place it failed: `extract` and `pack` lived
    // in the binary, so an editor client — which reaches the container only
    // through the daemon — could do neither. A tree is a path on the daemon's
    // own filesystem, the same thing `open`'s path already is. DR-014.
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

    // The strongest form of the claim: the two frontends produced the same
    // archive out of their own trees, byte for byte.
    assert_eq!(
        fs::read(&daemon_packed).expect("readable"),
        fs::read(&cli_packed).expect("readable"),
        "the two frontends packed different archives"
    );
}

#[test]
fn packing_over_an_archive_a_session_holds_is_refused() {
    // DR-009 arriving through a new door. `pack` is the one method that names
    // its output by path rather than by handle, and writing over an archive a
    // session holds moves every offset that session is still working from —
    // which is exactly the corruption DR-009 exists to make unreachable.
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
        // Released, and then the same pack is allowed.
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
    // Writing every entry of a 2.7 GB archive out to a tree, and reading one
    // back in, is unbounded work in the same way a rebuild is — so both take
    // DR-008's seam rather than running silently. A `pack` has no handle to be
    // named by, so its notifications carry none.
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
    // `read` prefers a buffered edit, because an editor that wrote a buffer
    // and read it back should see what it wrote. `extract` did neither: it
    // read the archive off disk and reported success, so a `write`, `extract`,
    // `pack` sequence produced an archive without the edit and said nothing.
    //
    // The answer is a refusal rather than a merge, because a tree means one
    // thing in both frontends — the archive as it is on disk, which is what
    // `rpf extract` produces and what `pack` reads back. A merged tree would
    // be an archive-shaped thing no archive holds, and packing it would leave
    // the edit in two places at once.
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

    // Discarding them is one of the two ways out, and the same request is then
    // the ordinary one.
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
    // DR-009 arriving through a third door. A session's offsets are true only
    // of the bytes it parsed, and an extraction writing an entry over that
    // file moves all of them while the session goes on committing against the
    // old ones — which is what `pack`'s guard was added to make unreachable.
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
        // archives sit in, which DR-029 refuses on its own. That refusal is not
        // what this test is about, and it is the cheaper of the two, so it is
        // waived to reach the claim.
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

// Key material — R2.7, DR-020. Three methods with no handle, because there is
// no archive open: an executable and a cache are named by paths on the
// daemon's own filesystem, which is the one thing a path on this wire has ever
// meant. DR-014.

/// Reports a skip, naming the test and what it would have read.
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
    // §1's test, for the three commands R2.7 added: if `rpf` can do it and
    // `serve --stdio` cannot, the logic is in the wrong crate.
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

    // The same number the command line exits with: intact file, and the part
    // that is missing is here. DR-010's fifth category.
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
    // DR-006 over the wire. The key is read in this process and every line the
    // daemon wrote is searched for it, raw, as hexadecimal and as base64 —
    // base64 especially, because `read` already puts entry payloads on this
    // wire that way and a key must never travel the same road.
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
    // §1's own test, on the last thing `rpf-core` could do that neither
    // frontend could ask for: DR-023 gave the library a per-entry checksum and
    // `Verified::against` to check it, and nothing outside the library could
    // reach either. `against` is a path on the daemon's own filesystem, the
    // same thing `open`'s `path`, `extract`'s `into` and `pack`'s `from`
    // already are. DR-014, DR-025.
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

    // And without one, the number is zero and the field that says why is null,
    // so a client cannot read the zero as a result.
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
    // The archive says nothing about a stored entry's bytes, so this is the one
    // failure only a manifest can see. It is still an answer rather than an
    // error — the call did what it was asked and what it found is its result —
    // which is what the command line spends its exit code 4 on.
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
    // Refused rather than answered with nothing checked, and refused with the
    // exit code the command line uses for it, because the two must not answer
    // one mistake with two numbers. DR-025.
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
    // inside the step that entry already reports: `done` and `total` are the
    // same numbers with a manifest and without one, and a `cancel` lands in the
    // same places. DR-008.
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

// --- R4.10 on the wire: adding, deleting and renaming an entry --------------

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

/// `write` with `create` adds an entry the archive did not hold, and `commit`
/// rebuilds for it. The wire can do what `rpf put --create` can, which is the
/// whole of §1's test.
#[test]
fn a_created_entry_is_buffered_and_committed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive_str = archive.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": archive_str}}),
        // Without `create` it is still not found, which is what it has always
        // been.
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

    assert!(answer(&responses, 2)["error"].is_object(), "{responses:?}");
    assert_eq!(answer(&responses, 3)["result"]["pending"], json!(1));
    // A read of the buffered path answers what was written, before it exists.
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

/// `delete` buffers a removal, and a directory that holds something needs
/// saying so — the same rule the command line has, because it is the same rule
/// in `rpf-core`.
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

/// `rename` moves an entry, and refuses a destination the archive already
/// holds rather than destroying it.
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

/// `mkdir` adds a directory that holds nothing, which a rebuild would
/// otherwise lose: `build` derives parents from file paths and cannot see one.
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

/// A dry run reports the change as what it is rather than as a payload that
/// would not fit, and writes nothing.
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
    // The change is still buffered, and nothing was written.
    assert_eq!(answer(&responses, 4)["result"]["paths"], json!(["art.yft"]));
    assert_eq!(fs::read(&archive).expect("readable"), before, "it wrote");
}

/// Every structural method resolves the change when it is offered, so a client
/// is told at the moment it can still act on it rather than at the commit.
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

// --- What `list` answers, and how a caller reads it. DR-028 -----------------

/// `list` of a file answers that one entry, which is what makes it a `stat`.
///
/// Pinned because a client depends on it and nothing said so: the editor client
/// builds its whole tree out of `list`, and "is this a file" is the question it
/// asks most. The tie-break is the row's `path` against the one that was asked
/// for — equal means the path named that entry, different means it named the
/// directory the entry is in — and it is exact, because a child's path is its
/// parent's plus a separator and a name and can never equal its parent's.
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

    // The file: one row, whose path is the one asked for.
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

/// A row's `path` is the whole in-archive path, not a name.
///
/// So a client uses it directly with `read`, `write` or `list`, and a client
/// that joined it onto the path it asked for would build
/// `x64/inner.rpf/x64/inner.rpf/art.yft`. Addressed from the path that was
/// asked for, in the caller's own spelling of it.
#[test]
fn a_list_row_carries_the_whole_path_it_was_addressed_from() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (outer_path, _) = make_nested(dir.path());
    let outer = outer_path.display().to_string();

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": outer}}),
        json!({"jsonrpc":"2.0","id":2,"method":"list","params":{
            "handle":1,"path":"x64/inner.rpf"}}),
        // The caller's own spelling is what comes back, folded case and all:
        // the rows are addressed from what was asked for, not from what the
        // archive spells the components as.
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
    // And each of them addresses: a client uses a row's path as it stands.
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

/// The wire refuses a non-empty target the way the command line does, and takes
/// the same way through. Both, or neither. DR-029.
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

/// A listing is the archive **on disk**: a buffered change is not in it until
/// the commit, and `read` is the one method that prefers what was buffered.
///
/// Pinned because the asymmetry is easy to read as a bug and is deliberate:
/// nothing on disk changes until `commit`, so a listing that showed an entry no
/// archive holds would describe something that does not exist. A client showing
/// a buffered addition keeps that view itself, and `pending` is what it
/// confirms it against.
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

    // And `read` is the exception: what was written comes back before it is
    // anywhere on disk.
    let read = answer(&responses, 5);
    assert_eq!(read["result"]["pending"], json!(true), "{read}");

    // `pending` is what a client confirms its own view against.
    assert_eq!(
        answer(&responses, 6)["result"]["paths"],
        json!(["added.txt", "art.yft"]),
    );
}

/// The AES-encrypted archive in the corpus, by the relative path that addresses
/// it. `docs/corpus.md`.
const AES_ARCHIVE: &str = "gtav_aes/des_canister.rpf";

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
    let mut daemon = daemon();
    daemon
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("APPDATA", home.join("appdata"));
    drive(daemon, requests).0
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn no_wire_method_writes_into_an_encrypted_archive() {
    // §1: what `rpf put` refuses, `serve --stdio` refuses, with the same number
    // and the same name. Each buffering method answers where the caller asks
    // rather than at the commit that could never have landed, so an editor is
    // told at the edit.
    let test = "no_wire_method_writes_into_an_encrypted_archive";
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
    let before = fs::read(&copy).expect("readable");

    let extracted = talk_homed(
        &home,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"keys.extract","params":{
            "executable": source.display().to_string()}}),
        ],
    );
    assert!(answer(&extracted, 1)["result"].is_object(), "{extracted:?}");

    let responses = talk_homed(
        &home,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"open","params":{"path": at}}),
            json!({"jsonrpc":"2.0","id":2,"method":"write","params":{
                "handle":1,"path":"_manifest.ymf","bytes":"cGxhaW4="}}),
            json!({"jsonrpc":"2.0","id":3,"method":"delete","params":{
                "handle":1,"path":"_manifest.ymf"}}),
            json!({"jsonrpc":"2.0","id":4,"method":"rename","params":{
                "handle":1,"from":"_manifest.ymf","to":"renamed.ymf"}}),
            json!({"jsonrpc":"2.0","id":5,"method":"mkdir","params":{
                "handle":1,"path":"added"}}),
            json!({"jsonrpc":"2.0","id":6,"method":"commit","params":{"handle":1}}),
        ],
    );

    // It opened: this is the write guard answering, not `NeedsKey`.
    let opened = answer(&responses, 1);
    assert_eq!(opened["result"]["entries"], json!(11), "{opened}");

    for id in [2, 3, 4, 5] {
        let refused = answer(&responses, id);
        assert_eq!(refused["error"]["code"], json!(9), "{refused}");
        assert_eq!(
            refused["error"]["data"]["reason"],
            json!("CannotWriteEncrypted"),
            "{refused}"
        );
    }
    // Nothing was ever buffered, so the commit has nothing to refuse.
    let committed = answer(&responses, 6);
    assert_eq!(committed["result"]["committed"], json!(0), "{committed}");

    assert_eq!(fs::read(&copy).expect("readable"), before);
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn the_daemon_opens_an_encrypted_archive_from_the_cache_it_was_started_with() {
    // §1's test: `rpf ls --cache-dir D` opens it, so `serve --stdio` must. The
    // flag is on the process rather than on every method that opens an archive,
    // which is what DR-041 rejected widening the wire for — and `keys.extract`
    // takes the same default while still honouring a `cache` it is given.
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
