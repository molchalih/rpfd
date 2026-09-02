//! `serve --mcp`: six tools over either era of the protocol, one JSON object
//! per line, and nothing on standard output that is not one of them.
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
    io::{Cursor, Write as _},
    path::Path,
    process::{Command, Stdio},
};

use rpf_core::{FileKind, FileSpec, Storage, Unwatched};
use serde_json::{Value, json};

mod common;

const RPF: &str = env!("CARGO_BIN_EXE_rpf");

/// The modern revision this server speaks, written out rather than read from
/// the source under test.
const REVISION: &str = "2026-07-28";

/// The newest handshake revision it speaks, which is the one the editors that
/// drive it ask for.
const LEGACY: &str = "2025-11-25";

/// The six, in the order `tools/list` contracts to answer them in.
const TOOLS: [&str; 6] = [
    "rpf_info",
    "rpf_list",
    "rpf_read",
    "rpf_plan",
    "rpf_apply",
    "rpf_verify",
];

/// How long anything here waits on the server before the wait is a failure.
const PATIENCE: std::time::Duration = std::time::Duration::from_secs(60);

/// A bound on one wait, naming what the wait is for. The watchdog ends a
/// process blocked inside a read.
struct Deadline {
    met: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Deadline {
    fn on(what: &'static str) -> Self {
        let met = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watching = std::sync::Arc::clone(&met);
        std::thread::spawn(move || {
            let started = std::time::Instant::now();
            while started.elapsed() < PATIENCE {
                if watching.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            if watching.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            let said = format!("waited {PATIENCE:?} for {what}, and it never arrived\n");
            let mut stderr = std::io::stderr();
            let _ = stderr.write_all(said.as_bytes());
            let _ = stderr.flush();
            std::process::abort();
        });
        Self { met }
    }
}

impl Drop for Deadline {
    fn drop(&mut self) {
        self.met.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// An archive with one deflated file and one resource.
fn make_archive(at: &Path) -> Vec<u8> {
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

/// An archive holding `names`, each with the same short stored payload.
fn make_wide_archive(at: &Path, names: &[String]) {
    let files: Vec<FileSpec> = names
        .iter()
        .map(|path| FileSpec {
            path: path.clone(),
            kind: FileKind::Binary {
                storage: Storage::Stored,
                encryption: 0,
            },
        })
        .collect();
    let mut out = fs::File::create(at).expect("creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(b"payload".to_vec())),
        &mut Unwatched,
    )
    .expect("builds");
}

/// Where one entry's payload starts in the file.
fn payload_at(archive: &Path, inside: &str) -> usize {
    let mut file = fs::File::open(archive).expect("archive opens");
    let parsed =
        rpf_core::Archive::open(&mut file, &rpf_core::Unlock::unkeyed()).expect("archive parses");
    let index = parsed.find(inside).expect("entry resolves");
    let (at, _) = parsed.payload_at(index).expect("payload span");
    usize::try_from(at).expect("an offset within a test archive fits a usize")
}

/// An archive with one entry long enough that deflate is worth it, so there is
/// a stream to spoil.
fn make_deflated_archive(at: &Path) {
    make_deflated_entries(at, &["data/long.txt".to_owned()]);
}

/// The same, for as many entries as are named.
fn make_deflated_entries(at: &Path, names: &[String]) {
    let files: Vec<FileSpec> = names
        .iter()
        .map(|path| FileSpec {
            path: path.clone(),
            kind: FileKind::Binary {
                storage: Storage::Deflate,
                encryption: 0,
            },
        })
        .collect();
    let mut out = fs::File::create(at).expect("creatable");
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &files,
        &[],
        |_: &str| {
            Ok(Cursor::new(
                b"hello, and here is enough text that deflate is worth it. ".repeat(8),
            ))
        },
        &mut Unwatched,
    )
    .expect("builds");
}

/// The `_meta` block a well-formed request carries.
fn meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": REVISION,
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": { "name": "test", "version": "0" },
    })
}

/// One well-formed request.
fn ask(id: u64, method: &str, params: Value) -> Value {
    let mut params = params;
    if let Some(object) = params.as_object_mut() {
        object.insert("_meta".to_owned(), meta());
    }
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

/// One well-formed `tools/call`.
fn call(id: u64, tool: &str, arguments: &Value) -> Value {
    ask(
        id,
        "tools/call",
        json!({ "name": tool, "arguments": arguments }),
    )
}

/// Feeds every line in, and returns what came back, parsed.
fn talk(lines: &[Value]) -> Vec<Value> {
    let rendered: Vec<String> = lines.iter().map(ToString::to_string).collect();
    let (_, out) = drive(&rendered);
    out.iter()
        .map(|line| serde_json::from_str::<Value>(line).expect("a JSON object per line"))
        .collect()
}

/// The response carrying an id.
fn answer(responses: &[Value], id: u64) -> &Value {
    responses
        .iter()
        .find(|response| response["id"] == json!(id))
        .unwrap_or_else(|| panic!("no response for {id} in {responses:?}"))
}

/// Feeds every line in and returns the exit code and the raw lines of standard
/// output, so a test can assert on the bytes rather than on a parse of them.
fn drive(lines: &[String]) -> (i32, Vec<String>) {
    let _deadline = Deadline::on("the server to answer every request and exit");
    let mut child = Command::new(RPF)
        .args(["serve", "--mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("server starts");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        for line in lines {
            writeln!(stdin, "{line}").expect("writable");
        }
    }
    let output = child.wait_with_output().expect("server exits");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(str::to_owned)
            .collect(),
    )
}

/// Runs the command line, and returns its exit code and what it wrote where.
fn cli(arguments: &[&str]) -> (i32, String, String) {
    let output = Command::new(RPF)
        .arg("--json")
        .args(arguments)
        .output()
        .expect("rpf runs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// An archive with one deflated file and one resource, in a temporary
/// directory, and its path as a string.
fn scratch() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let named = archive.display().to_string();
    (dir, named)
}

#[test]
fn discovery_names_the_one_revision_and_the_hints_that_let_it_be_cached() {
    let responses = talk(&[ask(1, "server/discover", json!({}))]);
    let result = &answer(&responses, 1)["result"];

    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["supportedVersions"], json!([REVISION]));
    assert!(
        result["capabilities"]["tools"].is_object(),
        "tools must be advertised: {result}"
    );
    assert!(
        result["capabilities"]["tools"]["listChanged"].is_null(),
        "a compiled-in tool set must not promise a notification: {result}"
    );
    assert!(result["ttlMs"].as_u64().is_some(), "{result}");
    assert_eq!(result["cacheScope"], "public");
    assert!(
        !result["instructions"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "the one prose the server gets to write: {result}"
    );
    let info = &result["_meta"]["io.modelcontextprotocol/serverInfo"];
    assert_eq!(info["name"], "rpf");
    assert_eq!(info["version"], env!("CARGO_PKG_VERSION"));
}

/// The `initialize` a handshake client opens with, shaped as the editor that
/// drives this server shapes it.
fn handshake(id: u64, revision: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": revision,
            "capabilities": {
                "roots": { "listChanged": true },
                "sampling": {},
                "elicitation": { "form": {}, "url": {} },
                "extensions": {
                    "io.modelcontextprotocol/ui": { "mimeTypes": ["text/html;profile=mcp-app"] },
                },
            },
            "clientInfo": { "name": "Visual Studio Code", "version": "1.135.0" },
        },
    })
}

/// One request of a connection that handshook: no `_meta`, because the
/// revision was settled once and does not ride along.
fn plain(id: u64, method: &str, params: &Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

#[test]
fn a_handshake_settles_a_revision_and_the_readiness_that_follows_is_silent() {
    let responses = talk(&[
        handshake(1, LEGACY),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        plain(2, "tools/list", &json!({})),
    ]);

    let result = &answer(&responses, 1)["result"];
    assert_eq!(result["protocolVersion"], LEGACY);
    assert!(
        result["capabilities"]["tools"].is_object(),
        "tools must be advertised: {result}"
    );
    assert!(
        result["capabilities"]["tools"]["listChanged"].is_null(),
        "a compiled-in tool set must not promise a notification: {result}"
    );
    assert_eq!(result["serverInfo"]["name"], "rpf");
    assert_eq!(result["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));
    assert!(
        !result["instructions"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "a handshake client learns the instructions here or nowhere: {result}"
    );

    assert_eq!(
        responses.len(),
        2,
        "the readiness notification was answered: {responses:?}"
    );
    assert!(
        answer(&responses, 2)["result"]["tools"].is_array(),
        "a request after the notification must still be answered"
    );
}

#[test]
fn a_handshake_offering_a_revision_this_server_lacks_is_answered_with_one_it_has() {
    for offered in ["2026-07-28", "1900-01-01"] {
        let responses = talk(&[handshake(1, offered)]);
        let result = &answer(&responses, 1)["result"];
        assert_eq!(
            result["protocolVersion"], LEGACY,
            "the newest there is, for the client to accept or refuse: {result}"
        );
    }

    for offered in ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"] {
        let responses = talk(&[handshake(1, offered)]);
        assert_eq!(
            answer(&responses, 1)["result"]["protocolVersion"],
            offered,
            "a revision this server has must be echoed back"
        );
    }

    let responses = talk(&[json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}})]);
    assert_eq!(
        answer(&responses, 1)["error"]["code"],
        json!(-32602),
        "an initialize with no revision has nothing to negotiate from"
    );
}

#[test]
fn a_handshake_connection_is_served_the_envelope_that_revision_has() {
    let (dir, archive) = scratch();
    let responses = talk(&[
        handshake(1, LEGACY),
        plain(2, "tools/list", &json!({})),
        plain(
            3,
            "tools/call",
            &json!({ "name": "rpf_info", "arguments": { "archive": archive } }),
        ),
        plain(4, "server/discover", &json!({})),
    ]);
    drop(dir);

    let listed = &answer(&responses, 2)["result"];
    let named: Vec<&str> = listed["tools"]
        .as_array()
        .expect("an array of tools")
        .iter()
        .map(|tool| tool["name"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(named, TOOLS);
    for field in ["resultType", "ttlMs", "cacheScope", "_meta"] {
        assert!(
            listed[field].is_null(),
            "{field} is of the modern revision alone: {listed}"
        );
    }
    let first = &listed["tools"][0];
    assert!(first["title"].is_string(), "{first}");
    assert!(first["annotations"].is_object(), "{first}");
    assert!(first["inputSchema"]["properties"].is_object(), "{first}");

    let called = &answer(&responses, 3)["result"];
    assert_eq!(called["isError"], json!(false));
    assert!(called["content"][0]["text"].is_string(), "{called}");
    assert!(called["structuredContent"]["entries"].is_u64(), "{called}");
    for field in ["resultType", "ttlMs", "cacheScope", "_meta"] {
        assert!(
            called[field].is_null(),
            "{field} is of the modern revision alone: {called}"
        );
    }

    assert_eq!(
        answer(&responses, 4)["error"]["code"],
        json!(-32601),
        "server/discover is of the modern revision alone"
    );
}

#[test]
fn a_revision_older_than_structured_content_is_not_sent_any() {
    let (dir, archive) = scratch();
    let responses = talk(&[
        handshake(1, "2025-03-26"),
        plain(2, "tools/list", &json!({})),
        plain(
            3,
            "tools/call",
            &json!({ "name": "rpf_info", "arguments": { "archive": archive } }),
        ),
    ]);
    drop(dir);

    let first = &answer(&responses, 2)["result"]["tools"][0];
    assert!(
        first["title"].is_null(),
        "a tool title arrived in 2025-06-18: {first}"
    );
    assert!(
        first["annotations"].is_object(),
        "annotations arrived in 2025-03-26: {first}"
    );

    let called = &answer(&responses, 3)["result"];
    assert!(
        called["structuredContent"].is_null(),
        "structuredContent arrived in 2025-06-18: {called}"
    );
    assert!(
        called["content"][0]["text"].is_string(),
        "the same report is still there as text: {called}"
    );
    assert_eq!(called["isError"], json!(false));
}

#[test]
fn a_revision_older_than_resource_links_is_told_the_path_in_text_instead() {
    for revision in ["2025-03-26", "2024-11-05"] {
        let (dir, archive) = scratch();
        let out = dir.path().join("art.bin");
        let named = out.display().to_string();
        let responses = talk(&[
            handshake(1, revision),
            plain(
                2,
                "tools/call",
                &json!({
                    "name": "rpf_read",
                    "arguments": { "archive": archive, "path": "art.yft", "out": named },
                }),
            ),
        ]);
        drop(dir);

        let result = &answer(&responses, 2)["result"];
        assert_eq!(result["isError"], json!(false), "{result}");
        let blocks = result["content"].as_array().expect("content");
        for block in blocks {
            assert_eq!(
                block["type"], "text",
                "a resource_link arrived in 2025-06-18: {result}"
            );
        }
        assert!(
            result["structuredContent"].is_null(),
            "structuredContent arrived in 2025-06-18: {result}"
        );
        let said: Vec<&str> = blocks
            .iter()
            .map(|block| block["text"].as_str().unwrap_or_default())
            .collect();
        assert!(
            said.iter().any(|text| text.contains(&named)),
            "the file the contents went to is all the caller has: {result}"
        );
        assert!(
            said.iter().any(|text| text.contains("file://")),
            "the link must survive as text: {result}"
        );
    }
}

#[test]
fn a_ping_is_answered_with_an_empty_result_in_either_era() {
    let responses = talk(&[ask(1, "ping", json!({}))]);
    let modern = &answer(&responses, 1)["result"];
    assert!(
        modern.is_object() && modern.as_object().expect("an object").is_empty(),
        "a ping is answered with an empty result: {modern}"
    );

    let responses = talk(&[
        handshake(1, "2024-11-05"),
        plain(2, "ping", &json!({})),
        plain(3, "tools/list", &json!({})),
    ]);
    let legacy = &answer(&responses, 2)["result"];
    assert!(
        legacy.is_object() && legacy.as_object().expect("an object").is_empty(),
        "{legacy}"
    );
    assert!(
        answer(&responses, 3)["result"]["tools"].is_array(),
        "the connection must go on after a ping"
    );
}

#[test]
fn an_older_revision_is_not_sent_annotations_it_does_not_have() {
    let responses = talk(&[
        handshake(1, "2024-11-05"),
        plain(2, "tools/list", &json!({})),
    ]);
    let first = &answer(&responses, 2)["result"]["tools"][0];
    assert!(first["annotations"].is_null(), "{first}");
    assert!(first["title"].is_null(), "{first}");
    assert!(first["description"].is_string(), "{first}");
    assert!(first["inputSchema"].is_object(), "{first}");
}

#[test]
fn the_protocol_fields_a_request_must_carry_are_required_and_the_optional_one_is_not() {
    let without = |key: &str| {
        let mut fields = meta();
        if let Some(object) = fields.as_object_mut() {
            object.remove(key);
        }
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta": fields}})
    };

    for key in [
        "io.modelcontextprotocol/protocolVersion",
        "io.modelcontextprotocol/clientCapabilities",
    ] {
        let responses = talk(&[without(key)]);
        assert_eq!(
            answer(&responses, 1)["error"]["code"],
            json!(-32602),
            "{key} is required"
        );
    }

    let responses = talk(&[without("io.modelcontextprotocol/clientInfo")]);
    assert!(
        answer(&responses, 1)["result"]["tools"].is_array(),
        "clientInfo is optional: {responses:?}"
    );
}

#[test]
fn a_revision_no_request_may_declare_is_answered_with_the_one_that_may() {
    let responses = talk(&[
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{
            "io.modelcontextprotocol/protocolVersion": "2025-11-25",
            "io.modelcontextprotocol/clientCapabilities": {},
        }}}),
    ]);
    let error = &answer(&responses, 1)["error"];
    assert_eq!(error["code"], json!(-32022));
    assert_eq!(error["data"]["requested"], "2025-11-25");
    assert_eq!(error["data"]["supported"], json!([REVISION]));
}

#[test]
fn the_shapes_this_protocol_does_not_have_are_refused_under_their_own_codes() {
    let (_, out) = drive(&[
        "not json at all".to_owned(),
        json!([
            ask(1, "tools/list", json!({})),
            ask(2, "tools/list", json!({}))
        ])
        .to_string(),
        json!({"jsonrpc":"2.0","id":null,"method":"tools/list"}).to_string(),
        json!({"jsonrpc":"2.0","id":4}).to_string(),
        ask(5, "frobnicate", json!({})).to_string(),
        call(6, "rpf_extract", &json!({ "archive": "a.rpf" })).to_string(),
    ]);
    let responses: Vec<Value> = out
        .iter()
        .map(|line| serde_json::from_str::<Value>(line).expect("JSON"))
        .collect();

    assert_eq!(responses.len(), 6, "one response each: {responses:?}");
    assert_eq!(responses[0]["error"]["code"], json!(-32700));
    assert_eq!(responses[0]["error"]["data"]["reason"], "ParseError");
    assert_eq!(responses[1]["error"]["code"], json!(-32600), "a batch");
    assert_eq!(responses[1]["id"], Value::Null);
    assert_eq!(responses[2]["error"]["code"], json!(-32600), "a null id");
    assert_eq!(responses[3]["error"]["code"], json!(-32600), "no method");
    assert_eq!(responses[4]["error"]["code"], json!(-32601));
    assert_eq!(responses[5]["error"]["code"], json!(-32602), "no such tool");
    assert_eq!(responses[5]["error"]["data"]["reason"], "MethodNotFound");
}

#[test]
fn a_tool_call_carrying_no_id_is_refused_rather_than_run_with_nowhere_to_answer() {
    let (dir, archive) = scratch();
    let source = dir.path().join("new.txt");
    fs::write(&source, b"replaced!!!").expect("writable");
    let before = fs::read(&archive).expect("readable");

    let mut request = call(
        1,
        "rpf_apply",
        &json!({ "archive": archive, "changes": [
        { "op": "write", "path": "data/greeting.txt", "from": source.display().to_string() },
    ] }),
    );
    if let Some(object) = request.as_object_mut() {
        object.remove("id");
    }
    let responses = talk(&[request]);

    assert_eq!(responses.len(), 1, "{responses:?}");
    assert_eq!(
        responses[0]["error"]["code"],
        json!(-32600),
        "{responses:?}"
    );
    assert_eq!(responses[0]["id"], Value::Null);
    assert_eq!(
        fs::read(&archive).expect("readable"),
        before,
        "an id-less call wrote the archive"
    );
}

#[test]
fn an_error_does_not_send_back_more_than_the_client_could_ever_be_answered_with() {
    let huge = "9".repeat(4 * 1024 * 1024);
    let (_, lines) = drive(&[
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{
            "io.modelcontextprotocol/protocolVersion": huge,
            "io.modelcontextprotocol/clientCapabilities": {},
        }}})
        .to_string(),
    ]);

    assert_eq!(lines.len(), 1, "{lines:?}");
    let line = lines.first().expect("one line");
    assert!(
        line.len() <= 96 * 1024,
        "an error carried {} bytes back",
        line.len()
    );
    let response: Value = serde_json::from_str(line).expect("JSON");
    assert_eq!(response["error"]["code"], json!(-32022));
    assert_eq!(response["error"]["data"]["supported"], json!([REVISION]));
    assert!(
        response["error"]["data"]["requested"]
            .as_str()
            .is_some_and(|said| said.len() < huge.len()),
        "the whole of what the client sent came back: {response}"
    );
}

#[test]
fn the_tool_list_is_deterministic_cacheable_and_says_what_each_argument_is_for() {
    let first = talk(&[ask(1, "tools/list", json!({}))]);
    let again = talk(&[ask(1, "tools/list", json!({}))]);
    assert_eq!(
        first[0].to_string(),
        again[0].to_string(),
        "two processes must answer byte-identically",
    );

    let result = &answer(&first, 1)["result"];
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["cacheScope"], "public");
    assert!(result["ttlMs"].as_u64().is_some());
    assert!(result["nextCursor"].is_null(), "six fit one page");

    let tools = result["tools"].as_array().expect("an array of tools");
    let named: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(named, TOOLS);

    for tool in tools {
        let name = tool["name"].as_str().unwrap_or_default();
        let schema = &tool["inputSchema"];
        assert_eq!(schema["type"], "object", "{name}");
        assert_eq!(schema["additionalProperties"], json!(false), "{name}");
        assert!(tool["outputSchema"].is_null(), "{name} declares none");

        let properties = schema["properties"].as_object().expect("properties");
        for required in schema["required"].as_array().expect("required") {
            let required = required.as_str().unwrap_or_default();
            assert!(
                properties.contains_key(required),
                "{name} requires {required}, which it does not have"
            );
        }
        for (field, described) in properties {
            let description = described["description"].as_str().unwrap_or_default();
            assert!(
                description.len() >= 40,
                "{name}.{field} says too little: {description:?}"
            );
        }

        let annotations = &tool["annotations"];
        // `rpf_read` writes a file when it is given `out`.
        let destructive = matches!(name, "rpf_apply" | "rpf_read");
        assert_eq!(annotations["readOnlyHint"], json!(!destructive), "{name}");
        assert_eq!(annotations["destructiveHint"], json!(destructive), "{name}");
        assert_eq!(annotations["openWorldHint"], json!(false), "{name}");
    }
}

#[test]
fn every_tool_answers_a_complete_result_that_says_it_did_not_fail() {
    let (dir, archive) = scratch();
    let out = dir.path().join("art.bin").display().to_string();
    let source = dir.path().join("new.txt");
    fs::write(&source, b"replaced!!!").expect("writable");
    let source = source.display().to_string();
    let write = json!([{ "op": "write", "path": "data/greeting.txt", "from": source }]);

    let responses = talk(&[
        call(1, "rpf_info", &json!({ "archive": archive })),
        call(
            2,
            "rpf_list",
            &json!({ "archive": archive, "recursive": true }),
        ),
        call(
            3,
            "rpf_read",
            &json!({ "archive": archive, "path": "data/greeting.txt" }),
        ),
        call(
            4,
            "rpf_read",
            &json!({ "archive": archive, "path": "art.yft", "as": "raw", "out": out }),
        ),
        call(
            5,
            "rpf_plan",
            &json!({ "archive": archive, "changes": write }),
        ),
        call(
            6,
            "rpf_apply",
            &json!({ "archive": archive, "changes": write }),
        ),
        call(7, "rpf_verify", &json!({ "archive": archive })),
    ]);

    for id in 1..=7 {
        let result = &answer(&responses, id)["result"];
        assert_eq!(result["resultType"], "complete", "{id}: {result}");
        assert_eq!(result["isError"], json!(false), "{id}: {result}");
        assert!(result["content"].is_array(), "{id}: {result}");
        assert_eq!(
            result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"], "rpf",
            "{id}"
        );
    }

    assert_eq!(
        answer(&responses, 1)["result"]["structuredContent"]["entries"],
        json!(4)
    );
    assert_eq!(
        answer(&responses, 5)["result"]["structuredContent"]["dry_run"],
        json!(true)
    );
    assert_eq!(
        answer(&responses, 6)["result"]["structuredContent"]["committed"],
        json!(1)
    );
    assert_eq!(
        answer(&responses, 7)["result"]["structuredContent"]["problems"],
        json!([])
    );
}

#[test]
fn a_failure_a_model_can_act_on_is_the_same_object_the_command_line_writes() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_archive(&archive);
    let archive = archive.display().to_string();

    let rpf2 = dir.path().join("rpf2.rpf");
    let mut header = b"RPF2".to_vec();
    header.extend_from_slice(&1_u32.to_le_bytes());
    header.extend_from_slice(&0_u32.to_le_bytes());
    header.extend_from_slice(&rpf_core::Version::Rpf7.open().to_le_bytes());
    fs::write(&rpf2, &header).expect("writable");
    let rpf2 = rpf2.display().to_string();

    let missing = dir
        .path()
        .join("nowhere")
        .join("out.bin")
        .display()
        .to_string();

    // Each row: the tool call, the command line that fails the same way, and
    // the exit code both must land on.
    let cases: [(Value, Vec<&str>, i64, &str); 4] = [
        (
            call(
                1,
                "rpf_read",
                &json!({ "archive": archive, "path": "data/absent.txt" }),
            ),
            vec!["cat", &archive, "data/absent.txt"],
            3,
            "NotFound",
        ),
        (
            call(1, "rpf_info", &json!({ "archive": rpf2 })),
            vec!["info", &rpf2],
            9,
            "UnsupportedVersion",
        ),
        (
            call(
                1,
                "rpf_read",
                &json!({ "archive": archive, "path": "art.yft", "as": "xml" }),
            ),
            vec!["cat", &archive, "art.yft", "--as", "xml"],
            6,
            "NoXmlView",
        ),
        (
            call(
                1,
                "rpf_read",
                &json!({ "archive": archive, "path": "art.yft", "as": "raw", "out": missing }),
            ),
            vec!["cat", &archive, "art.yft", "--out", &missing],
            7,
            "Io",
        ),
    ];

    for (request, arguments, code, reason) in cases {
        let responses = talk(&[request]);
        let result = &answer(&responses, 1)["result"];
        assert_eq!(result["isError"], json!(true), "{arguments:?}: {result}");
        assert_eq!(result["resultType"], "complete", "{arguments:?}");

        let (exit, _, stderr) = cli(&arguments);
        assert_eq!(i64::from(exit), code, "{arguments:?}: {stderr}");
        let written: Value = serde_json::from_str(&stderr).expect("one object on standard error");
        assert_eq!(
            result["structuredContent"], written,
            "one function builds it for every frontend: {arguments:?}"
        );
        assert_eq!(result["structuredContent"]["code"], json!(code));
        assert_eq!(result["structuredContent"]["data"]["reason"], reason);
    }
}

#[test]
fn an_archive_that_does_not_decompress_as_it_promises_is_a_corrupt_result() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("test.rpf");
    make_deflated_archive(&archive);
    // 0xFF opens a deflate block with the reserved type, so the stream is
    // refused where the archive around it still parses.
    let at = payload_at(&archive, "data/long.txt");
    let mut bytes = fs::read(&archive).expect("readable");
    bytes
        .get_mut(at..at.saturating_add(8))
        .expect("the payload is in the file")
        .fill(0xFF);
    fs::write(&archive, &bytes).expect("writable");
    let archive = archive.display().to_string();

    let responses = talk(&[call(
        1,
        "rpf_read",
        &json!({ "archive": archive, "path": "data/long.txt" }),
    )]);
    let result = &answer(&responses, 1)["result"];
    assert_eq!(result["isError"], json!(true), "{result}");
    assert_eq!(result["structuredContent"]["code"], json!(4), "{result}");
    drop(dir);
}

#[test]
fn an_encrypted_archive_with_no_key_material_asks_for_it_rather_than_failing_at_random() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cache = dir.path().join("cache");
    let archive = dir.path().join("keyed.rpf");
    common::make_keyed_meta_archive(&archive, &cache, 0);
    fs::remove_dir_all(&cache).expect("the cache goes away");
    let archive = archive.display().to_string();
    let empty = dir.path().join("empty").display().to_string();

    let responses = talk(&[call(1, "rpf_info", &json!({ "archive": archive }))]);
    let result = &answer(&responses, 1)["result"];
    assert_eq!(result["isError"], json!(true), "{result}");
    assert_eq!(result["structuredContent"]["code"], json!(5), "{result}");

    let (exit, _, stderr) = cli(&["--cache-dir", &empty, "info", &archive]);
    assert_eq!(exit, 5, "{stderr}");
}

#[test]
fn a_refusal_the_guardrails_make_names_the_argument_that_lifts_it() {
    let (dir, archive) = scratch();
    let installed = dir.path().join("GTA5.exe");
    fs::write(&installed, b"not really").expect("writable");
    for beside in ["GTAVLauncher.exe", "PlayGTAV.exe", "index.bin", "GTA5.exe"] {
        let _ = fs::write(dir.path().join(beside), b"x");
    }

    let occupied = json!([{ "op": "rename", "path": "art.yft", "to": "data/greeting.txt" }]);
    let responses = talk(&[
        call(
            1,
            "rpf_apply",
            &json!({ "archive": archive, "changes": occupied }),
        ),
        call(
            2,
            "rpf_apply",
            &json!({ "archive": archive, "changes": [
                { "op": "remove", "path": "art.yft" },
                { "op": "remove", "path": "art.yft" },
            ] }),
        ),
    ]);

    let renamed = &answer(&responses, 1)["result"];
    assert_eq!(renamed["isError"], json!(true), "{renamed}");
    assert_eq!(renamed["structuredContent"]["code"], json!(6), "{renamed}");

    let twice = &answer(&responses, 2)["result"];
    assert_eq!(twice["structuredContent"]["code"], json!(6), "{twice}");
    assert_eq!(twice["structuredContent"]["data"]["reason"], "Claimed");
}

#[test]
fn an_argument_the_schema_does_not_admit_is_reported_as_one() {
    let (_dir, archive) = scratch();
    let calls = [
        call(1, "rpf_info", &json!({})),
        call(
            2,
            "rpf_list",
            &json!({ "archive": archive, "recursive": "yes" }),
        ),
        call(
            3,
            "rpf_list",
            &json!({ "archive": archive, "verbose": true }),
        ),
        call(
            4,
            "rpf_apply",
            &json!({ "archive": archive, "changes": [{ "op": "remove", "path": "a", "to": "b" }] }),
        ),
        call(
            5,
            "rpf_apply",
            &json!({ "archive": archive, "changes": [] }),
        ),
        call(6, "rpf_list", &json!({ "archive": archive, "limit": 5000 })),
    ];
    let responses = talk(&calls);

    for id in 1..=6 {
        let result = &answer(&responses, id)["result"];
        assert_eq!(result["isError"], json!(true), "{id}: {result}");
        assert_eq!(
            result["structuredContent"]["code"],
            json!(2),
            "{id}: {result}"
        );
        assert_eq!(
            result["structuredContent"]["data"]["reason"], "InvalidArguments",
            "{id}: {result}"
        );
    }
}

#[test]
fn nothing_that_is_not_a_message_of_this_protocol_reaches_standard_output() {
    let (dir, archive) = scratch();
    let out = dir.path().join("art.bin").display().to_string();
    let source = dir.path().join("new.txt");
    fs::write(&source, b"replaced!!!").expect("writable");
    let source = source.display().to_string();
    let write = json!([{ "op": "write", "path": "data/greeting.txt", "from": source }]);

    let requests = [
        ask(1, "server/discover", json!({})),
        ask(2, "tools/list", json!({})),
        call(3, "rpf_info", &json!({ "archive": archive })),
        call(
            4,
            "rpf_list",
            &json!({ "archive": archive, "recursive": true }),
        ),
        call(
            5,
            "rpf_read",
            &json!({ "archive": archive, "path": "data/greeting.txt" }),
        ),
        call(
            6,
            "rpf_read",
            &json!({ "archive": archive, "path": "art.yft", "out": out }),
        ),
        call(
            7,
            "rpf_plan",
            &json!({ "archive": archive, "changes": write }),
        ),
        call(
            8,
            "rpf_apply",
            &json!({ "archive": archive, "changes": write }),
        ),
        call(9, "rpf_verify", &json!({ "archive": archive })),
    ];
    let rendered: Vec<String> = requests.iter().map(ToString::to_string).collect();
    let (exit, lines) = drive(&rendered);

    assert_eq!(exit, 0, "a clean end of standard input exits 0");
    assert_eq!(
        lines.len(),
        requests.len(),
        "one line per request: {lines:?}"
    );
    for line in &lines {
        let parsed: Value = serde_json::from_str(line).expect("every line parses as JSON");
        assert_eq!(parsed["jsonrpc"], "2.0", "{line}");
        assert!(
            parsed.get("result").is_some() ^ parsed.get("error").is_some(),
            "exactly one of result and error: {line}"
        );
    }
}

#[test]
fn an_entry_name_holding_a_newline_and_a_quote_comes_back_as_one_line_and_unchanged() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("odd.rpf");
    let awkward = "data/one\ntwo\"three.txt".to_owned();
    make_wide_archive(&archive, std::slice::from_ref(&awkward));

    let (_, lines) = drive(&[call(
        1,
        "rpf_list",
        &json!({ "archive": archive.display().to_string(), "recursive": true }),
    )
    .to_string()]);
    assert_eq!(
        lines.len(),
        1,
        "a name with a newline in it broke the framing"
    );

    let parsed: Value = serde_json::from_str(&lines[0]).expect("JSON");
    let rows = parsed["result"]["structuredContent"]["rows"]
        .as_array()
        .expect("rows");
    let listed = rows
        .iter()
        .find(|row| row["kind"] != "directory")
        .expect("the entry itself");
    assert_eq!(listed["path"], awkward, "the name did not survive the wire");
}

#[test]
fn a_listing_too_big_to_send_says_so_and_pages() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("wide.rpf");
    let names: Vec<String> = (0..900)
        .map(|index| format!("data/entry{index:04}-with-a-name-long-enough-to-cost.meta"))
        .collect();
    make_wide_archive(&archive, &names);
    let archive = archive.display().to_string();

    let responses = talk(&[
        call(
            1,
            "rpf_list",
            &json!({ "archive": archive, "recursive": true, "limit": 1000 }),
        ),
        call(
            2,
            "rpf_list",
            &json!({ "archive": archive, "recursive": true, "pattern": "data/entry000*.meta" }),
        ),
    ]);

    let (_, lines) = drive(&[call(
        1,
        "rpf_list",
        &json!({ "archive": archive, "recursive": true, "limit": 1000 }),
    )
    .to_string()]);
    assert!(
        lines[0].len() <= 96 * 1024,
        "the whole line must fit the cap"
    );

    let wide = &answer(&responses, 1)["result"]["structuredContent"];
    let total = wide["total"].as_u64().expect("total");
    let returned = wide["returned"].as_u64().expect("returned");
    assert_eq!(wide["truncated"], json!(true), "{wide}");
    assert!(returned < total, "{returned} of {total}");
    assert!(returned <= 1000, "no more than was asked for");

    // Paging reaches the end, and the pages add up to everything that matched.
    let mut seen = 0_u64;
    let mut offset = 0_u64;
    loop {
        let page = talk(&[call(
            1,
            "rpf_list",
            &json!({ "archive": archive, "recursive": true, "offset": offset, "limit": 1000 }),
        )]);
        let page = &answer(&page, 1)["result"]["structuredContent"];
        let got = page["returned"].as_u64().expect("returned");
        assert!(got > 0, "a page must make progress: {page}");
        seen = seen.saturating_add(got);
        offset = offset.saturating_add(got);
        if page["truncated"] == json!(false) {
            break;
        }
    }
    assert_eq!(seen, total, "the pages must add up to what matched");

    let filtered = &answer(&responses, 2)["result"]["structuredContent"];
    assert_eq!(filtered["total"], json!(10), "{filtered}");
    for row in filtered["rows"].as_array().expect("rows") {
        let path = row["path"].as_str().unwrap_or_default();
        assert!(path.starts_with("data/entry000"), "{path}");
    }
}

#[test]
fn contents_are_answered_inline_only_where_they_are_small_text_and_never_truncated() {
    let (dir, archive) = scratch();
    let out = dir.path().join("art.bin");
    let named = out.display().to_string();

    let responses = talk(&[
        call(
            1,
            "rpf_read",
            &json!({ "archive": archive, "path": "art.yft" }),
        ),
        call(
            2,
            "rpf_read",
            &json!({ "archive": archive, "path": "art.yft", "out": named }),
        ),
        call(
            3,
            "rpf_read",
            &json!({ "archive": archive, "path": "data/greeting.txt" }),
        ),
    ]);

    let refused = &answer(&responses, 1)["result"];
    assert_eq!(refused["isError"], json!(true), "{refused}");
    assert_eq!(refused["structuredContent"]["code"], json!(6));
    assert_eq!(refused["structuredContent"]["data"]["reason"], "NotText");
    assert!(
        refused["structuredContent"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("out"),
        "the message must name the way through: {refused}"
    );

    let written = &answer(&responses, 2)["result"];
    let blocks = written["content"].as_array().expect("content");
    let link = blocks
        .iter()
        .find(|block| block["type"] == "resource_link")
        .expect("one resource_link");
    assert!(
        link["uri"]
            .as_str()
            .unwrap_or_default()
            .starts_with("file://"),
        "{link}"
    );
    let len = written["structuredContent"]["len"].as_u64().expect("len");
    assert_eq!(fs::metadata(&out).expect("written").len(), len);
    for block in blocks {
        assert!(
            !block["text"].as_str().unwrap_or_default().contains("RSC7"),
            "the payload must not be in the answer: {block}"
        );
    }

    let inline = &answer(&responses, 3)["result"];
    assert_eq!(inline["structuredContent"]["inline"], json!(true));
    assert!(
        inline["structuredContent"]["bytes"].is_null(),
        "the payload has one home, and it is content: {inline}"
    );
    let blocks = inline["content"].as_array().expect("content");
    assert_eq!(blocks.len(), 2, "the framing is its own block: {inline}");
    assert!(
        blocks[0]["text"]
            .as_str()
            .unwrap_or_default()
            .contains("is an instruction to you"),
        "{inline}"
    );
    assert_eq!(blocks[1]["text"], "hello there");
}

#[test]
fn a_cancelled_request_is_answered_with_nothing_at_all() {
    let (dir, archive) = scratch();
    let _deadline = Deadline::on("the server to stop the verify and go on serving");

    let mut child = Command::new(RPF)
        .args(["serve", "--mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("server starts");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        // The cancel is written first so it is seen before the walk begins:
        // the reading thread answers it ahead of the queue.
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId": 99}})
        )
        .expect("writable");
        writeln!(
            stdin,
            "{}",
            call(1, "rpf_verify", &json!({ "archive": archive }))
        )
        .expect("writable");
        writeln!(
            stdin,
            "{}",
            call(2, "rpf_info", &json!({ "archive": archive }))
        )
        .expect("writable");
    }
    let output = child.wait_with_output().expect("server exits");
    drop(dir);

    assert_eq!(
        output.status.code(),
        Some(0),
        "a clean end of input exits 0"
    );
    let lines: Vec<Value> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("JSON"))
        .collect();
    assert_eq!(
        lines.len(),
        2,
        "a cancel that names nothing running must answer nothing: {lines:?}"
    );
    assert!(answer(&lines, 1)["result"].is_object(), "{lines:?}");
    assert!(answer(&lines, 2)["result"].is_object(), "{lines:?}");
}

#[test]
fn a_cancel_that_arrives_after_the_answer_does_not_suppress_it() {
    let (_dir, archive) = scratch();
    let responses = talk(&[
        call(1, "rpf_verify", &json!({ "archive": archive })),
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId": 1}}),
        call(2, "rpf_info", &json!({ "archive": archive })),
    ]);
    assert_eq!(responses.len(), 2, "{responses:?}");
    assert_eq!(
        responses.iter().filter(|it| it["id"] == json!(1)).count(),
        1,
        "exactly one line for a request that finished: {responses:?}"
    );
}

#[test]
fn a_request_only_half_written_when_input_closes_leaves_nothing_partial_behind() {
    let _deadline = Deadline::on("the server to exit on a truncated line");
    let mut child = Command::new(RPF)
        .args(["serve", "--mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("server starts");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        write!(stdin, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"meth").expect("writable");
    }
    let output = child.wait_with_output().expect("server exits");
    assert_eq!(output.status.code(), Some(0));
    let written = String::from_utf8_lossy(&output.stdout);
    for line in written.lines().filter(|line| !line.trim().is_empty()) {
        let parsed: Value = serde_json::from_str(line).expect("JSON");
        assert_eq!(parsed["error"]["code"], json!(-32700), "{line}");
    }
}

#[test]
fn serve_takes_one_transport_and_says_so_when_it_is_given_none_or_both() {
    for arguments in [vec!["serve"], vec!["serve", "--stdio", "--mcp"]] {
        let output = Command::new(RPF)
            .args(&arguments)
            .stdin(Stdio::null())
            .output()
            .expect("rpf runs");
        assert_eq!(output.status.code(), Some(6), "{arguments:?}");
        let said = String::from_utf8_lossy(&output.stderr);
        assert!(said.contains("--stdio") && said.contains("--mcp"), "{said}");
    }
}

#[test]
fn the_filter_is_the_same_one_on_every_frontend() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("wide.rpf");
    make_wide_archive(
        &archive,
        &[
            "data/vehicles.meta".to_owned(),
            "data/handling.meta".to_owned(),
            "data/deep/vehicles.meta".to_owned(),
            "data/notes.txt".to_owned(),
            "vehicles.meta".to_owned(),
        ],
    );
    let archive = archive.display().to_string();

    let (exit, out, stderr) = cli(&["ls", &archive, "-R", "--pattern", "data/*.meta"]);
    assert_eq!(exit, 0, "{stderr}");
    let rows: Value = serde_json::from_str(&out).expect("an array");
    assert_eq!(rows.as_array().expect("rows").len(), 2, "{out}");

    let responses = talk(&[call(
        1,
        "rpf_list",
        &json!({ "archive": archive, "recursive": true, "pattern": "**/vehicles.meta" }),
    )]);
    let listed = &answer(&responses, 1)["result"]["structuredContent"];
    assert_eq!(
        listed["total"],
        json!(3),
        "** must cross separators and find the root: {listed}"
    );
}

#[test]
fn a_badly_damaged_archive_reports_what_fits_and_how_many_there_were() {
    let dir = tempfile::tempdir().expect("temp dir");
    let archive = dir.path().join("broken.rpf");
    let names: Vec<String> = (0..140)
        .map(|index| format!("data/e{index:03}.txt"))
        .collect();
    make_deflated_entries(&archive, &names);

    // Every payload sits after the table of contents, so spoiling the file from
    // the first one to its end leaves 140 entries that will not inflate.
    let at = payload_at(&archive, &names[0]);
    let mut bytes = fs::read(&archive).expect("readable");
    bytes.get_mut(at..).expect("a payload region").fill(0xFF);
    fs::write(&archive, &bytes).expect("writable");

    let responses = talk(&[call(
        1,
        "rpf_verify",
        &json!({ "archive": archive.display().to_string() }),
    )]);
    let report = &answer(&responses, 1)["result"]["structuredContent"];
    assert_eq!(
        report["problems"].as_array().expect("problems").len(),
        100,
        "the result carries at most a hundred: {report}"
    );
    assert_eq!(report["problems_total"], json!(140), "{report}");
}
