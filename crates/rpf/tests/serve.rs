//! The stdio daemon: warm state, buffered edits, one rebuild per commit.
//!
//! Corpus-free — these build their own archives, as the command-line tests do.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code; a panic is the reporting mechanism"
)]

use std::{
    fs,
    io::Write as _,
    path::Path,
    process::{Command, Stdio},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rpf_core::{FileKind, FileSpec, Storage};
use serde_json::{Value, json};

const RPF: &str = env!("CARGO_BIN_EXE_rpf");

/// An archive with one deflated file and one resource.
fn make_archive(at: &Path) -> Vec<u8> {
    // A minimal but real resource: an RSC7 header whose flags describe one
    // 512-byte system page, followed by a deflate stream of exactly that.
    let mut resource = Vec::new();
    resource.extend_from_slice(b"RSC7");
    resource.extend_from_slice(&162_u32.to_le_bytes());
    resource.extend_from_slice(&0x8000_0010_u32.to_le_bytes());
    resource.extend_from_slice(&0_u32.to_le_bytes());
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
    rpf_core::build(&mut out, &files, &[], |wanted| {
        Ok(if wanted == "art.yft" {
            payload.clone()
        } else {
            b"hello there".to_vec()
        })
    })
    .expect("builds");
    resource
}

/// Feeds every request in, and returns the responses by id.
fn talk(requests: &[Value]) -> Vec<Value> {
    let mut child = Command::new(RPF)
        .args(["serve", "--stdio"])
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
        .map(|l| serde_json::from_str(l).expect("a JSON response per line"))
        .collect()
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
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);

    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"nonsense","params":{}}),
        json!({"jsonrpc":"2.0","id":2,"method":"read","params":{"handle":99,"path":"x"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"open","params":{}}),
    ]);
    for response in &responses {
        assert_eq!(response["error"]["code"], json!(6), "{response}");
    }
}
