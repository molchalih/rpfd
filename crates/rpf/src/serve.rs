//! `serve --stdio`: a long-lived process with warm state.
//!
//! R6.5, and the backend DR-002 chose for the editor client. The point is what
//! stays warm between requests: the parsed table of contents, the open file
//! handle, and edits that have been made but not committed. One process per
//! archive session rather than one process per file open.
//!
//! **Framing is one JSON object per line**, not the `Content-Length` headers a
//! language server uses. `docs/approach.md` calls this "the same shape as a
//! language server", and it is — long-lived, JSON-RPC, stdio, warm state — but
//! the framing is ours to choose, and the primary consumer is automation that
//! can drive a line at a time from a shell.
//!
//! Writes are buffered until `commit`. Nothing on disk changes before then, and
//! `commit` rebuilds once for every pending edit rather than once per edit.

use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, Write},
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rpf_core::{Archive, EntryKind};
use serde_json::{Value, json};

use crate::{commands, exit::Failure, install};

/// One open archive, and whatever has been changed but not committed.
struct Session {
    path: PathBuf,
    file: fs::File,
    archive: Archive,
    pending: BTreeMap<String, Vec<u8>>,
}

/// Everything the daemon holds between requests.
#[derive(Default)]
struct State {
    sessions: BTreeMap<u64, Session>,
    next_handle: u64,
}

/// Reads requests until standard input ends.
pub fn run() -> crate::exit::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut state = State::default();

    for line in stdin.lock().lines() {
        let line = line.map_err(|source| Failure::Io {
            path: "<stdin>".to_owned(),
            source,
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let response = respond(&mut state, &line);
        let text = serde_json::to_string(&response).unwrap_or_else(|_| {
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":1,"message":"unrenderable"}}"#.to_owned()
        });
        writeln!(stdout, "{text}").map_err(|source| Failure::Io {
            path: "<stdout>".to_owned(),
            source,
        })?;
        stdout.flush().map_err(|source| Failure::Io {
            path: "<stdout>".to_owned(),
            source,
        })?;
    }
    Ok(())
}

/// Turns one request line into one response object.
fn respond(state: &mut State, line: &str) -> Value {
    let Ok(request) = serde_json::from_str::<Value>(line) else {
        return error_of(&Value::Null, -32700, "not JSON");
    };
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return error_of(&id, -32600, "no method");
    };
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));

    match dispatch(state, method, &params) {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(failure) => {
            let code = failure.code() as i64;
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": code, "message": failure.to_string() },
            })
        }
    }
}

/// A JSON-RPC error object.
fn error_of(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Routes one call.
fn dispatch(state: &mut State, method: &str, params: &Value) -> crate::exit::Result<Value> {
    match method {
        "open" => open(state, params),
        "close" => close(state, params),
        "list" => list(state, params),
        "read" => read(state, params),
        "write" => write(state, params),
        "pending" => pending(state, params),
        "discard" => discard(state, params),
        "commit" => commit(state, params),
        other => Err(Failure::Refused {
            reason: format!("no method {other:?}"),
        }),
    }
}

/// A required string parameter.
fn string(params: &Value, name: &str) -> crate::exit::Result<String> {
    params
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Failure::Refused {
            reason: format!("{name:?} is required"),
        })
}

/// The session a request names.
fn session<'a>(state: &'a mut State, params: &Value) -> crate::exit::Result<&'a mut Session> {
    let handle = params
        .get("handle")
        .and_then(Value::as_u64)
        .ok_or_else(|| Failure::Refused {
            reason: "\"handle\" is required".to_owned(),
        })?;
    state
        .sessions
        .get_mut(&handle)
        .ok_or_else(|| Failure::Refused {
            reason: format!("no open archive with handle {handle}"),
        })
}

/// `open` — parse an archive and keep it warm.
fn open(state: &mut State, params: &Value) -> crate::exit::Result<Value> {
    let path = PathBuf::from(string(params, "path")?);
    let (file, archive) = commands::open(&path)?;

    state.next_handle = state.next_handle.saturating_add(1);
    let handle = state.next_handle;
    let entries = archive.entries().len();
    let len = archive.len_bytes();
    state.sessions.insert(
        handle,
        Session {
            path: path.clone(),
            file,
            archive,
            pending: BTreeMap::new(),
        },
    );

    Ok(json!({
        "handle": handle,
        "path": path.display().to_string(),
        "entries": entries,
        "len": len,
    }))
}

/// `close` — forget a session. Uncommitted edits are discarded, and the
/// response says how many, so that losing them is never silent.
fn close(state: &mut State, params: &Value) -> crate::exit::Result<Value> {
    let handle = params
        .get("handle")
        .and_then(Value::as_u64)
        .ok_or_else(|| Failure::Refused {
            reason: "\"handle\" is required".to_owned(),
        })?;
    let discarded = state
        .sessions
        .remove(&handle)
        .map_or(0, |s| s.pending.len());
    Ok(json!({ "closed": true, "discarded": discarded }))
}

/// `list` — the entries at a path, optionally recursively.
fn list(state: &mut State, params: &Value) -> crate::exit::Result<Value> {
    let inside = params
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let recursive = params
        .get("recursive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let session = session(state, params)?;

    let (holder, at) = session.archive.locate(&mut session.file, &inside)?;
    let mut rows = Vec::new();
    commands::list_into(
        &mut session.file,
        &holder,
        at,
        &inside,
        recursive,
        &mut rows,
    )?;
    Ok(Value::Array(rows))
}

/// `read` — one entry's bytes, as base64.
///
/// A pending write is returned in preference to what is on disk: an editor that
/// wrote a buffer and read it back should see what it wrote.
fn read(state: &mut State, params: &Value) -> crate::exit::Result<Value> {
    let inside = string(params, "path")?;
    let session = session(state, params)?;

    if let Some(buffered) = session.pending.get(&inside) {
        return Ok(json!({
            "path": inside,
            "len": buffered.len(),
            "pending": true,
            "bytes": BASE64.encode(buffered),
        }));
    }

    let (holder, index) = session.archive.locate(&mut session.file, &inside)?;
    if holder.entry(index)?.is_directory() {
        return Err(Failure::Refused {
            reason: format!("{inside} is a directory"),
        });
    }
    let bytes = holder.extract(&mut session.file, index)?;
    Ok(json!({
        "path": inside,
        "len": bytes.len(),
        "pending": false,
        "bytes": BASE64.encode(&bytes),
    }))
}

/// `write` — buffer an edit. Nothing on disk changes until `commit`.
fn write(state: &mut State, params: &Value) -> crate::exit::Result<Value> {
    let inside = string(params, "path")?;
    let encoded = string(params, "bytes")?;
    let bytes = BASE64
        .decode(encoded.as_bytes())
        .map_err(|_| Failure::Refused {
            reason: "\"bytes\" is not base64".to_owned(),
        })?;
    let session = session(state, params)?;

    // Resolve now rather than at commit, so a path that cannot exist is
    // refused while the caller is still in a position to do something about it.
    let (holder, index) = session.archive.locate(&mut session.file, &inside)?;
    if holder.entry(index)?.is_directory() {
        return Err(Failure::Refused {
            reason: format!("{inside} is a directory"),
        });
    }
    // R6.6: a resource entry takes an RSC7 payload and nothing else.
    if matches!(holder.entry(index)?.kind, EntryKind::Resource { .. })
        && bytes.get(0..4) != Some(&rpf_core::format::MAGIC_RSC7)
    {
        return Err(Failure::Refused {
            reason: format!("{inside} is a resource entry; its payload must begin with RSC7"),
        });
    }

    let len = bytes.len();
    session.pending.insert(inside.clone(), bytes);
    Ok(json!({ "path": inside, "len": len, "pending": session.pending.len() }))
}

/// `pending` — what has been written but not committed.
fn pending(state: &mut State, params: &Value) -> crate::exit::Result<Value> {
    let session = session(state, params)?;
    let paths: Vec<&String> = session.pending.keys().collect();
    Ok(json!({ "paths": paths }))
}

/// `discard` — drop the buffered edits.
fn discard(state: &mut State, params: &Value) -> crate::exit::Result<Value> {
    let session = session(state, params)?;
    let dropped = session.pending.len();
    session.pending.clear();
    Ok(json!({ "discarded": dropped }))
}

/// `commit` — apply every buffered edit in one rebuild, atomically.
fn commit(state: &mut State, params: &Value) -> crate::exit::Result<Value> {
    let force = params
        .get("force")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let session = session(state, params)?;

    if session.pending.is_empty() {
        return Ok(json!({ "committed": 0, "unchanged": true }));
    }
    if !force && let Some(root) = install::detect(&session.path) {
        return Err(Failure::GameInstall { root });
    }

    let directory = session
        .path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let mut scratch =
        tempfile::NamedTempFile::new_in(&directory).map_err(|source| Failure::Io {
            path: directory.display().to_string(),
            source,
        })?;

    let report = rpf_core::replace_many(
        &mut session.file,
        &session.archive,
        &session.pending,
        scratch.as_file_mut(),
    )?;
    let committed = session.pending.len();
    let path = session.path.clone();
    commands::persist(scratch, &path)?;

    // Re-open, so the warm state describes what is now on disk rather than what
    // used to be. An editor that commits and keeps working must not be reading
    // offsets from the archive it just replaced.
    let (file, archive) = commands::open(&path)?;
    session.file = file;
    session.archive = archive;
    session.pending.clear();

    Ok(json!({
        "committed": committed,
        "entries": report.entry_count,
        "len": report.len,
    }))
}
