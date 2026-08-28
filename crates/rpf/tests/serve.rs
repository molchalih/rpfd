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
    io::{BufRead as _, Write as _},
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
        &files,
        &[],
        |wanted| {
            Ok(if wanted == "art.yft" {
                payload.clone()
            } else {
                b"hello there".to_vec()
            })
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
        &files,
        &[],
        |_| Ok(b"payload".to_vec()),
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
    let archive = rpf_core::Archive::open(&mut file).expect("archive parses");
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
    rpf_core::build(&mut out, &files, &[], |_| Ok(bulk.clone()), &mut Unwatched).expect("builds");
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
    rpf_core::build(&mut out, &files, &[], |_| Ok(bytes.clone()), &mut Unwatched).expect("builds");
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
    rpf_core::build(&mut out, &files, &[], |_| Ok(bulk.clone()), &mut Unwatched).expect("builds");
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
    rpf_core::build(&mut out, &files, &[], |_| Ok(bulk.clone()), &mut Unwatched).expect("builds");
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
#[cfg(unix)]
fn a_second_name_for_one_file_is_the_same_archive() {
    // A hard link is a second directory entry for one inode, and both spellings
    // canonicalise to themselves, so a claim keyed on the canonical path
    // accepted both. That is two sessions on one archive — the state DR-009
    // exists to make unreachable — and after either one rebuilds, the other
    // holds an entry table describing bytes that have moved.
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
#[cfg(unix)]
fn a_session_still_holds_its_archive_after_its_own_rebuild() {
    // A rebuild replaces the archive by rename, so the file the session holds
    // afterwards is a different inode from the one it opened. A claim that kept
    // the inode it first saw would go on claiming a file nobody has and stop
    // recognising the one it does have — and a second session on that is the
    // corruption again.
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
    rpf_core::build(&mut out, &files, &[], |_| Ok(bulk.clone()), &mut Unwatched).expect("builds");
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
    let header = usize::try_from(rpf_core::format::RESOURCE_HEADER_LEN).expect("16 fits");
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
