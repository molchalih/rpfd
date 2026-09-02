//! `serve --stdio`: a long-lived process with warm state, framed as one JSON
//! object per line. Writes are buffered until `commit`, and an archive is open
//! in one session at a time. The reading thread never waits.

use std::{
    collections::BTreeMap,
    fs,
    io::{self, BufRead, Seek, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rpf_core::{
    Archive, Change, Changes, Dictionary, Encoding, Flow, Step, Unwatched, View, Watch, view,
};
use serde_json::{Value, json};

use crate::{commands, exit::Failure};

/// JSON-RPC's own error codes, for a request that did not follow the protocol.
const INVALID_REQUEST: i64 = -32600;
/// No such method.
const METHOD_NOT_FOUND: i64 = -32601;
/// A parameter is missing, or is not of the type the method takes.
const INVALID_PARAMS: i64 = -32602;
/// The line was not JSON.
const PARSE_ERROR: i64 = -32700;

/// How many progress notifications may queue before further ones are dropped —
/// the only thing on this wire that may be.
const PROGRESS_BACKLOG: usize = 64;

/// How many bytes of answers may be queued before the worker waits for the
/// client to catch up. One answer always goes through however big it is.
const ANSWER_BACKLOG: usize = 8 * 1024 * 1024;

/// How much of one line is written before the count of what the far end has
/// taken is brought up to date, and so a floor under what that count measures.
const WRITE_PIECE: usize = 1024;

/// How long the far end's reading is measured over.
const DRAIN_WINDOW: Duration = Duration::from_secs(5);

/// How many bytes standard output must take in one [`DRAIN_WINDOW`] for the far
/// end to count as still there. Below it a client is cut off with exit 7.
const DRAIN_FLOOR: usize = 20 * 1024;

/// Which file an open handle is on, as the operating system names one.
///
/// A resolved path is not a file identity: a hard link, and a firmlinked macOS
/// volume, both give one file two true canonical paths. An unnamed file is
/// equal to nothing, itself included, so it can never manufacture a match.
#[derive(Clone, Copy)]
enum FileId {
    /// The device and inode the operating system named.
    #[cfg(unix)]
    Named {
        /// Which filesystem.
        device: u64,
        /// Which file on it.
        inode: u64,
    },
    /// The volume serial number and file index the operating system named.
    #[cfg(windows)]
    Named {
        /// Which volume.
        volume: u64,
        /// Which file on it.
        index: u64,
    },
    /// Named by nothing but its path: the platform or the volume names none.
    #[cfg(not(unix))]
    Unnamed,
}

impl FileId {
    /// What the operating system calls the file behind an open handle.
    fn of(file: &fs::File, path: &Path) -> crate::exit::Result<Self> {
        Self::named_by(file).map_err(|source| Failure::Io {
            path: path.display().to_string(),
            source,
        })
    }

    /// The identity behind an open handle: the device and inode `fstat` gives.
    #[cfg(unix)]
    fn named_by(file: &fs::File) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt as _;
        let named = file.metadata()?;
        Ok(Self::Named {
            device: named.dev(),
            inode: named.ino(),
        })
    }

    /// The volume serial number and file index `GetFileInformationByHandle`
    /// gives. A zero in either half is the volume saying it does not name its
    /// files, which is `Unnamed` rather than an error.
    #[cfg(windows)]
    #[allow(
        clippy::unnecessary_wraps,
        reason = "the fallible signature is the seam all three arms share, and \
                  on this one nothing fails: not answering is Unnamed rather \
                  than an error. Narrowing the return type here alone would put \
                  a #[cfg] inside FileId::of and give one operation two \
                  spellings. docs/conventions.md §4"
    )]
    fn named_by(file: &fs::File) -> io::Result<Self> {
        let Ok(named) = winapi_util::file::information(file) else {
            return Ok(Self::Unnamed);
        };
        let (volume, index) = (named.volume_serial_number(), named.file_index());
        Ok(if volume == 0 || index == 0 {
            Self::Unnamed
        } else {
            Self::Named { volume, index }
        })
    }

    /// No identity on this platform, but the handle is statted anyway: a file
    /// that cannot be statted is not held.
    #[cfg(not(any(unix, windows)))]
    fn named_by(file: &fs::File) -> io::Result<Self> {
        file.metadata().map(|_| Self::Unnamed)
    }

    /// Whether these are one file. Always false where files are unnamed.
    const fn is(self, other: Self) -> bool {
        match (self, other) {
            #[cfg(unix)]
            (
                Self::Named { device, inode },
                Self::Named {
                    device: volume,
                    inode: file,
                },
            ) => device == volume && inode == file,
            #[cfg(windows)]
            (
                Self::Named { volume, index },
                Self::Named {
                    volume: disk,
                    index: file,
                },
            ) => volume == disk && index == file,
            #[cfg(not(unix))]
            _ => false,
        }
    }
}

/// One open archive, and whatever has been changed but not committed.
struct Session {
    /// The resolved path: what the session claims, reports back, and rebuilds.
    path: PathBuf,
    /// The file that path led to. Refreshed by every commit, which may replace
    /// the archive by rename.
    id: FileId,
    file: fs::File,
    archive: Archive,
    /// What has been changed and not committed. `commit` decides between
    /// patching and rebuilding for the whole set.
    pending: Changes,
}

/// Everything the daemon holds between requests.
#[derive(Default)]
struct State {
    sessions: BTreeMap<u64, Session>,
    next_handle: u64,
    /// `--cache-dir`, as this process was started with, and `None` for the
    /// platform's own. A `keys.*` request naming a `cache` overrides it.
    cache: Option<PathBuf>,
}

impl State {
    /// The handle holding an archive, and the name it holds it under.
    ///
    /// Either the path or the file settles it. `id` is absent when the file is
    /// not there to be statted.
    fn holder_of(&self, path: &Path, id: Option<FileId>) -> Option<(u64, &Path)> {
        self.sessions
            .iter()
            .find(|(_, session)| session.path == path || id.is_some_and(|id| session.id.is(id)))
            .map(|(handle, session)| (*handle, session.path.as_path()))
    }
}

/// How much of a request's `id` is echoed onto a line the client did not ask
/// for: unbounded, a large `id` would multiply into gigabytes. A response still
/// echoes its own `id` whole.
const NAME_ECHO: usize = 128;

/// The whole `id` when it is small enough to quote back, its size when it is
/// not. [`NAME_ECHO`].
fn name_of(request: &Value) -> Value {
    let rendered = render(request);
    if rendered.len() <= NAME_ECHO {
        return request.clone();
    }
    json!(format!("<an id of {} bytes>", rendered.len()))
}

/// The one long operation that can be running, named by the `id` that started
/// it.
struct Job {
    /// What a cancel is matched against: the whole `id`, whatever its size.
    request: Value,
    /// What an answer echoes back. [`NAME_ECHO`].
    name: Value,
    /// The session it runs against, or `None` for `pack`, which has none.
    handle: Option<u64>,
    /// What the client is told is running: `"commit"` while it is still being
    /// decided, then `"patch"` or `"rebuild"`.
    method: &'static str,
    /// Whether it can be stopped part-way.
    stoppable: Stoppable,
    /// Whether a cancel naming it has arrived.
    cancelled: bool,
}

/// Whether a running operation can be stopped, and what to say when it cannot.
pub enum Stoppable {
    /// It can be, and the watcher sees the mark between entries.
    Yes,
    /// It cannot, and this is why.
    No(&'static str),
}

/// The commit is still choosing between patching in place and rebuilding.
pub const DECIDING: &str = "the commit is still working out whether every edit fits where it is, which reads and \
     compresses them and stops at nothing";

/// A patch in place is under way.
pub const PATCHING: &str =
    "a patch in place writes the bytes of one edit; there is no part-way to stop at";

/// What a `cancel` acts on: at most one operation, and only the one it names.
/// One lock, so reading what runs and marking it cancelled cannot be separated.
#[derive(Default)]
pub struct Cancellation {
    job: Mutex<Option<Job>>,
}

impl Cancellation {
    /// The running job. A poisoned lock is recovered: what it guards is still
    /// readable.
    fn job(&self) -> MutexGuard<'_, Option<Job>> {
        self.job.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Registers the operation a `cancel` may now name.
    pub fn begin(
        &self,
        request: &Value,
        handle: Option<u64>,
        method: &'static str,
        stoppable: Stoppable,
    ) {
        *self.job() = Some(Job {
            request: request.clone(),
            name: name_of(request),
            handle,
            method,
            stoppable,
            cancelled: false,
        });
    }

    /// Whether the running operation has been asked to stop.
    pub fn stopped(&self) -> bool {
        self.job().as_ref().is_some_and(|job| job.cancelled)
    }

    /// Forgets it, so a later cancel finds nothing rather than being stored
    /// against whatever runs next.
    pub fn finish(&self) {
        *self.job() = None;
    }

    /// Answers a `cancel`, and acts on it when it names what is running.
    pub fn ask(&self, request: Option<&Value>, handle: Option<u64>) -> Value {
        let mut running = self.job();
        let Some(job) = running.as_mut() else {
            return json!({ "cancelling": false, "running": Value::Null });
        };
        let named = request.is_none_or(|named| *named == job.request)
            && handle.is_none_or(|named| job.handle == Some(named));
        let reason = match (named, &job.stoppable) {
            (true, &Stoppable::Yes) => {
                job.cancelled = true;
                return json!({
                    "cancelling": true,
                    "running": job.method,
                    "request": job.name,
                    "handle": job.handle,
                });
            }
            (true, &Stoppable::No(reason)) => reason,
            (false, _) => "that is not the operation running",
        };
        json!({
            "cancelling": false,
            "running": job.method,
            "request": job.name,
            "handle": job.handle,
            "reason": reason,
        })
    }
}

/// How far behind the client is, as the three threads see it.
#[derive(Default)]
struct Backlog {
    /// Progress notifications queued and not yet written.
    queued: AtomicUsize,
    /// Set when a write to standard output failed.
    broken: AtomicBool,
    /// Set when standard input has ended.
    ending: AtomicBool,
    /// Bytes standard output has taken, which is how both waits tell a slow far
    /// end from an absent one.
    taken: AtomicUsize,
    /// Bytes of answers queued by the worker and not yet written.
    answers: Mutex<usize>,
    /// Signalled when an answer has been written and there is room for another.
    room: Condvar,
}

impl Backlog {
    /// Bytes of answers queued and not yet written.
    fn answers(&self) -> MutexGuard<'_, usize> {
        self.answers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records bytes standard output has taken.
    fn took(&self, bytes: usize) {
        self.taken.fetch_add(bytes, Ordering::SeqCst);
    }

    /// Gives back the room a written answer was holding.
    fn wrote(&self, bytes: usize) {
        let mut answers = self.answers();
        *answers = answers.saturating_sub(bytes);
        self.room.notify_all();
    }
}

/// One line waiting to be written.
enum Outgoing {
    /// A response, or the answer to a cancel. Never dropped. `counted` says
    /// whether it was weighed against [`ANSWER_BACKLOG`]; only the worker's are.
    Answer { text: String, counted: bool },
    /// Progress. Dropped when the client is behind.
    Progress(String),
}

/// What the reading thread and the worker share. Nothing here blocks on the far
/// end of standard output: emitting queues a line and returns.
pub struct Wire {
    lines: mpsc::Sender<Outgoing>,
    backlog: Arc<Backlog>,
    /// What a cancel is registered against, and what a watcher asks.
    pub cancel: Cancellation,
}

impl Wire {
    /// Queues one response, waiting first while the client is too far behind.
    /// Only the worker calls this, and it is the only thread that may wait here.
    pub fn answer(&self, value: &Value) {
        let text = render(value);
        let len = text.len();
        self.make_room(len);
        if self
            .lines
            .send(Outgoing::Answer {
                text,
                counted: true,
            })
            .is_err()
        {
            self.backlog.wrote(len);
        }
    }

    /// Queues one answer without waiting for room: the reading thread's, which
    /// must never block. [`NAME_ECHO`] is what bounds it.
    fn answer_now(&self, value: &Value) {
        let _ = self.lines.send(Outgoing::Answer {
            text: render(value),
            counted: false,
        });
    }

    /// Waits until there is room for one more answer of `len` bytes. One always
    /// fits when nothing is queued; the wait is unbounded while standard input
    /// is open, and bounded by [`DRAIN_FLOOR`] once it has ended.
    fn make_room(&self, len: usize) {
        let mut answers = self.backlog.answers();
        while !self.gone() && *answers > 0 && answers.saturating_add(len) > ANSWER_BACKLOG {
            let before = self.backlog.taken.load(Ordering::SeqCst);
            let (waited, outcome) = self
                .backlog
                .room
                .wait_timeout(answers, DRAIN_WINDOW)
                .unwrap_or_else(PoisonError::into_inner);
            answers = waited;
            if outcome.timed_out()
                && self.backlog.ending.load(Ordering::SeqCst)
                && self
                    .backlog
                    .taken
                    .load(Ordering::SeqCst)
                    .saturating_sub(before)
                    < DRAIN_FLOOR
            {
                self.backlog.broken.store(true, Ordering::SeqCst);
            }
        }
        *answers = answers.saturating_add(len);
    }

    /// Queues one progress notification, or drops it. Returns which.
    fn progress(&self, value: &Value) -> bool {
        if self.gone() || self.backlog.queued.load(Ordering::SeqCst) >= PROGRESS_BACKLOG {
            return false;
        }
        self.backlog.queued.fetch_add(1, Ordering::SeqCst);
        if self.lines.send(Outgoing::Progress(render(value))).is_err() {
            self.backlog.queued.fetch_sub(1, Ordering::SeqCst);
            return false;
        }
        true
    }

    /// Whether standard output has stopped accepting what is written to it.
    pub fn gone(&self) -> bool {
        self.backlog.broken.load(Ordering::SeqCst)
    }
}

/// Renders one object, or something that says it could not be rendered.
fn render(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| {
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":1,"message":"unrenderable","data":{"reason":"Internal"}}}"#
            .to_owned()
    })
}

/// Writes queued lines, flushing each. The only call in the daemon that can
/// block for as long as a client declines to read.
fn writing(lines: &mpsc::Receiver<Outgoing>, backlog: &Backlog) {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for line in lines {
        let (text, counted) = match line {
            Outgoing::Answer { text, counted } => (text, counted),
            Outgoing::Progress(text) => {
                backlog.queued.fetch_sub(1, Ordering::SeqCst);
                (text, false)
            }
        };
        if !backlog.broken.load(Ordering::SeqCst) && !write_line(&mut out, &text, backlog) {
            backlog.broken.store(true, Ordering::SeqCst);
        }
        // Whether or not it reached the far end: a worker waiting on room a
        // dropped line still held would wait for ever.
        if counted {
            backlog.wrote(text.len());
        }
    }
    let _ = out.flush();
}

/// Writes one line and its newline in flushed pieces, so that what the far end
/// has taken is known mid-line, and says whether it got there. [`WRITE_PIECE`].
fn write_line(out: &mut impl Write, text: &str, backlog: &Backlog) -> bool {
    let mut rest = text.as_bytes();
    while !rest.is_empty() {
        let Some((piece, tail)) = rest.split_at_checked(rest.len().min(WRITE_PIECE)) else {
            return false;
        };
        if out.write_all(piece).and_then(|()| out.flush()).is_err() {
            return false;
        }
        backlog.took(piece.len());
        rest = tail;
    }
    if out.write_all(b"\n").and_then(|()| out.flush()).is_err() {
        return false;
    }
    backlog.took(1);
    true
}

/// Reports progress as notifications, and stops on a cancel or on nobody being
/// left to report to.
pub struct Notifying<'a> {
    wire: &'a Wire,
    /// The session being reported on, or `None` for a `pack`, which has none.
    handle: Option<u64>,
    /// What the notification echoes of the request. [`NAME_ECHO`].
    name: &'a Value,
    /// Whether the caller asked for progress at all.
    wanted: bool,
    /// Notifications dropped since the last one that got through.
    skipped: u32,
    /// Why it stopped, if it did.
    stopped: Option<Stopped>,
}

/// Why a watched write stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopped {
    /// A cancel named it. The caller's doing.
    Cancelled,
    /// Standard output stopped accepting what was written to it. Ours.
    OutputGone,
}

impl Watch for Notifying<'_> {
    fn step(&mut self, step: Step<'_>) -> Flow {
        if self.wire.cancel.stopped() {
            self.stopped = Some(Stopped::Cancelled);
            return Flow::Stop;
        }
        if self.wire.gone() {
            self.stopped = Some(Stopped::OutputGone);
            return Flow::Stop;
        }
        if !self.wanted {
            return Flow::Continue;
        }

        let notification = json!({
            "jsonrpc": "2.0",
            "method": "progress",
            "params": {
                "handle": self.handle,
                "request": self.name,
                "path": step.path,
                "done": step.done,
                "total": step.total,
                "bytes": step.bytes,
                "skipped": self.skipped,
            },
        });
        if self.wire.progress(&notification) {
            self.skipped = 0;
        } else {
            self.skipped = self.skipped.saturating_add(1);
        }
        Flow::Continue
    }
}

impl<'a> Notifying<'a> {
    /// A watcher that reports nothing and only watches for a stop: the MCP
    /// front sends no progress and still has to tell a cancel from a broken
    /// standard output.
    pub fn silent(wire: &'a Wire, name: &'a Value) -> Self {
        Self {
            wire,
            handle: None,
            name,
            wanted: false,
            skipped: 0,
            stopped: None,
        }
    }

    /// Why the write stopped, in the terms the contract uses.
    pub fn explain(&self, failure: Failure) -> Failure {
        stopped_as(self.stopped, failure)
    }
}

/// Translates a stopped write into the failure that actually happened: the
/// library has one variant for "the watcher said stop" and this daemon stops
/// for two unrelated reasons.
pub fn stopped_as(stopped: Option<Stopped>, failure: Failure) -> Failure {
    if matches!(stopped, Some(Stopped::OutputGone))
        && matches!(
            failure,
            Failure::Container(rpf_core::Error::Cancelled { .. })
        )
    {
        return Failure::Io {
            path: "<stdout>".to_owned(),
            source: io::Error::new(
                io::ErrorKind::BrokenPipe,
                "standard output stopped accepting the progress it was being sent",
            ),
        };
    }
    failure
}

/// One line handed to the worker, or the reason there will be no more.
enum Incoming {
    /// A request, to be handled in order.
    Request(String),
    /// Reading stopped, and why. Never silently: a daemon that stops accepting
    /// requests and says nothing would exit 0 having failed.
    Ended(Failure),
}

/// What the reading thread made of a line.
pub enum Seen {
    /// A `cancel`, acted on or refused, with the object to write back.
    Cancel(Value),
    /// A notification, which must not be answered.
    Notification,
    /// Anything else. It goes to the worker, in order.
    Request,
}

/// Reads requests until standard input ends.
///
/// # Errors
///
/// [`Failure::Io`] if standard input or output failed part-way.
pub fn run(named_cache: Option<&Path>) -> crate::exit::Result<()> {
    let mut state = State {
        cache: named_cache.map(Path::to_path_buf),
        ..State::default()
    };
    pump(answer_cancel, |line, wire| respond(&mut state, line, wire))
}

/// The transport both `serve --stdio` and `serve --mcp` are: three threads, one
/// object per line, and a reader that never waits. `ahead` is what the reading
/// thread answers where it stands; `respond` is the worker's, in order.
///
/// # Errors
///
/// [`Failure::Io`] if standard input or output failed part-way.
pub fn pump(
    ahead: fn(&str, &Cancellation) -> Seen,
    mut respond: impl FnMut(&str, &Wire) -> Option<Value>,
) -> crate::exit::Result<()> {
    let backlog = Arc::new(Backlog::default());
    let (lines, queued) = mpsc::channel::<Outgoing>();
    let (finished, drained) = mpsc::channel::<()>();
    let writing_backlog = Arc::clone(&backlog);
    let writer = thread::spawn(move || {
        writing(&queued, &writing_backlog);
        let _ = finished.send(());
    });

    let wire = Arc::new(Wire {
        lines,
        backlog: Arc::clone(&backlog),
        cancel: Cancellation::default(),
    });
    let (queue, requests) = mpsc::channel::<Incoming>();

    let reading_wire = Arc::clone(&wire);
    let reader = thread::spawn(move || {
        reading(io::stdin().lock(), &reading_wire, &queue, ahead);
        reading_wire.backlog.ending.store(true, Ordering::SeqCst);
        reading_wire.backlog.room.notify_all();
    });

    let mut fault = None;
    for message in requests {
        match message {
            Incoming::Request(line) => {
                if let Some(response) = respond(&line, &wire) {
                    wire.answer(&response);
                }
            }
            Incoming::Ended(failure) => {
                fault = Some(failure);
                break;
            }
        }
    }

    let _ = reader.join();
    drop(wire);
    let emptied = drain(&drained, &backlog);
    if emptied {
        // So the process cannot outlive a line it is half way through writing.
        let _ = writer.join();
    }

    if let Some(failure) = fault {
        return Err(failure);
    }
    if backlog.broken.load(Ordering::SeqCst) {
        return Err(Failure::Io {
            path: "<stdout>".to_owned(),
            source: io::Error::new(
                io::ErrorKind::BrokenPipe,
                "standard output stopped accepting what was written to it",
            ),
        });
    }
    if !emptied {
        return Err(Failure::Io {
            path: "<stdout>".to_owned(),
            source: io::Error::new(
                io::ErrorKind::TimedOut,
                "standard output stopped being read before everything queued for it was written",
            ),
        });
    }
    Ok(())
}

/// Waits for the writing thread to empty its queue, for as long as the far end
/// keeps up with [`DRAIN_FLOOR`]. `true` when every line was written whole.
fn drain(drained: &mpsc::Receiver<()>, backlog: &Backlog) -> bool {
    let mut before = backlog.taken.load(Ordering::SeqCst);
    loop {
        match drained.recv_timeout(DRAIN_WINDOW) {
            Ok(()) => return true,
            Err(mpsc::RecvTimeoutError::Disconnected) => return false,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let now = backlog.taken.load(Ordering::SeqCst);
                if now.saturating_sub(before) < DRAIN_FLOOR {
                    return false;
                }
                before = now;
            }
        }
    }
}

/// The reading thread: one line at a time, cancels answered where they stand.
/// `input` is a parameter so a test can drive it. [`Opening`].
fn reading(
    input: impl BufRead,
    wire: &Wire,
    queue: &mpsc::Sender<Incoming>,
    ahead: fn(&str, &Cancellation) -> Seen,
) {
    for line in input.lines() {
        let line = match line {
            Ok(line) => line,
            Err(source) => {
                let _ = queue.send(Incoming::Ended(Failure::Io {
                    path: "<stdin>".to_owned(),
                    source,
                }));
                return;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        // Ahead of the queue: a cancel that waits its turn arrives after the
        // thing it would have cancelled finished.
        match ahead(&line, &wire.cancel) {
            Seen::Cancel(answer) => {
                wire.answer_now(&answer);
                continue;
            }
            Seen::Notification => continue,
            Seen::Request => {}
        }
        if wire.gone() {
            let _ = queue.send(Incoming::Ended(Failure::Io {
                path: "<stdout>".to_owned(),
                source: io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "standard output stopped accepting what was written to it",
                ),
            }));
            return;
        }
        if queue.send(Incoming::Request(line)).is_err() {
            return;
        }
    }
}

/// What a `cancel` names. `None` for either means "whichever one is running",
/// so a parameter that was given must never end up here as `None`.
struct Aim {
    request: Option<Value>,
    handle: Option<u64>,
}

/// Reads what a `cancel` names, or says why its parameters do not say. An
/// unknown key is refused, unlike elsewhere: every parameter here is optional
/// and the default is the widest aim, so a misspelling would silently widen it.
fn aim(params: Option<&Value>) -> std::result::Result<Aim, String> {
    let unaimed = Aim {
        request: None,
        handle: None,
    };
    let given = match params {
        None | Some(Value::Null) => return Ok(unaimed),
        Some(given) => given,
    };
    let Some(object) = given.as_object() else {
        return Err("\"params\" is an object, with optional \"request\" and \"handle\"".to_owned());
    };
    if let Some(unknown) = object
        .keys()
        .find(|key| !matches!(key.as_str(), "request" | "handle"))
    {
        return Err(format!(
            "{unknown:?} is not a parameter of \"cancel\", which takes \"request\" and \"handle\""
        ));
    }
    let handle = match object.get("handle") {
        None => None,
        Some(named) => Some(
            named
                .as_u64()
                .ok_or_else(|| "\"handle\" is a number".to_owned())?,
        ),
    };
    Ok(Aim {
        request: object.get("request").cloned(),
        handle,
    })
}

/// Answers `cancel` from the reading thread, or hands the line back.
/// Parameters that cannot be read are refused rather than acted on.
fn answer_cancel(line: &str, cancel: &Cancellation) -> Seen {
    let Ok(request) = serde_json::from_str::<Value>(line) else {
        return Seen::Request;
    };
    if request.get("method").and_then(Value::as_str) != Some("cancel") {
        return Seen::Request;
    }
    let outcome =
        aim(request.get("params")).map(|aimed| cancel.ask(aimed.request.as_ref(), aimed.handle));
    match (request.get("id"), outcome) {
        (None, _) => Seen::Notification,
        (Some(id), Ok(result)) => {
            Seen::Cancel(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
        }
        (Some(id), Err(message)) => Seen::Cancel(error_of(id, &invalid_params(message))),
    }
}

/// Turns one request line into one response object, or into none.
fn respond(state: &mut State, line: &str, wire: &Wire) -> Option<Value> {
    let Ok(request) = serde_json::from_str::<Value>(line) else {
        return Some(error_of(
            &Value::Null,
            &protocol(PARSE_ERROR, "not JSON".to_owned()),
        ));
    };
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return Some(error_of(
            &Value::Null,
            &protocol(INVALID_REQUEST, "no method".to_owned()),
        ));
    };
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
    let id = request.get("id").cloned();
    let named = id.clone().unwrap_or(Value::Null);
    let outcome = dispatch(state, method, &params, wire, &named);

    // A request with no id is a notification, which must not be answered.
    let id = id?;
    Some(match outcome {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(rejected) => error_of(&id, &rejected),
    })
}

/// A JSON-RPC error object: a number, a sentence, and the failure's own name.
/// `reason` in `data` is a stable symbol and is on every error object.
fn error_of(id: &Value, rejected: &Rejected) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": crate::advice::object(rejected.code(), &rejected.message(), rejected.reason()),
    })
}

/// A request that did not follow the protocol, under one of JSON-RPC's own
/// codes.
fn protocol(code: i64, message: String) -> Rejected {
    Rejected::Protocol { code, message }
}

/// Why a call produced no result.
enum Rejected {
    /// The request did not follow the protocol. JSON-RPC's own codes.
    Protocol { code: i64, message: String },
    /// The work was attempted and did not succeed, under the exit code.
    Failed(Failure),
}

impl Rejected {
    /// The number that goes on the wire.
    fn code(&self) -> i64 {
        match *self {
            Self::Protocol { code, .. } => code,
            Self::Failed(ref failure) => failure.code() as i64,
        }
    }

    /// The name that goes beside the number, so a client can tell two refusals
    /// apart without reading the sentence.
    fn reason(&self) -> &'static str {
        match *self {
            Self::Protocol { code, .. } => match code {
                PARSE_ERROR => "ParseError",
                INVALID_REQUEST => "InvalidRequest",
                METHOD_NOT_FOUND => "MethodNotFound",
                _ => "InvalidParams",
            },
            Self::Failed(ref failure) => failure.name(),
        }
    }

    /// What to say about it.
    fn message(&self) -> String {
        match *self {
            Self::Protocol { ref message, .. } => message.clone(),
            Self::Failed(ref failure) => crate::advice::render(failure),
        }
    }
}

impl From<Failure> for Rejected {
    fn from(failure: Failure) -> Self {
        Self::Failed(failure)
    }
}

/// So a container failure is classified once rather than at each call site.
impl From<rpf_core::Error> for Rejected {
    fn from(error: rpf_core::Error) -> Self {
        Self::Failed(Failure::Container(error))
    }
}

/// A call that either produced something or was rejected.
type Answer<T> = std::result::Result<T, Rejected>;

/// What every method returns.
type Answered = Answer<Value>;

/// A parameter that is missing, or is not of the type the method takes.
fn invalid_params(message: String) -> Rejected {
    protocol(INVALID_PARAMS, message)
}

/// Routes one call.
fn dispatch(
    state: &mut State,
    method: &str,
    params: &Value,
    wire: &Wire,
    request: &Value,
) -> Answered {
    match method {
        "open" => open(state, params),
        "close" => close(state, params),
        "list" => list(state, params),
        "read" => read(state, params),
        "write" => write(state, params),
        "delete" => delete(state, params),
        "rename" => rename(state, params),
        "mkdir" => mkdir(state, params),
        "pending" => pending(state, params),
        "discard" => discard(state, params),
        "forget" => forget(state, params),
        "info" => info(state, params),
        "verify" => verify(state, params, wire, request),
        "extract" => extract(state, params, wire, request),
        "pack" => pack(state, params, wire, request),
        "commit" => commit(state, params, wire, request),
        "keys.extract" => keys_extract(state, params, wire, request),
        "keys.cache" => keys_cache(state, params),
        "keys.invalidate" => keys_invalidate(state, params),
        other => Err(protocol(METHOD_NOT_FOUND, format!("no method {other:?}"))),
    }
}

/// A required string parameter.
fn string(params: &Value, name: &str) -> Answer<String> {
    params
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| invalid_params(format!("{name:?} is required, as a string")))
}

/// The handle a request names.
fn handle_of(params: &Value) -> Answer<u64> {
    params
        .get("handle")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_params("\"handle\" is required, as a number".to_owned()))
}

/// Whether the caller wants progress notifications, which it does unless it
/// says otherwise.
fn wants_progress(params: &Value) -> Answer<bool> {
    match params.get("progress") {
        None | Some(Value::Null) => Ok(true),
        Some(value) => value
            .as_bool()
            .ok_or_else(|| invalid_params("\"progress\" is a boolean".to_owned())),
    }
}

/// A boolean parameter, defaulting to `false`.
fn flag(params: &Value, name: &str) -> Answer<bool> {
    match params.get(name) {
        None | Some(Value::Null) => Ok(false),
        Some(value) => value
            .as_bool()
            .ok_or_else(|| invalid_params(format!("{name:?} is a boolean"))),
    }
}

/// The view a request asks for, defaulting to `"raw"` so that a wire addition
/// never changes what a request already meant.
fn view_of(params: &Value) -> Answer<View> {
    match params.get("as") {
        None | Some(Value::Null) => Ok(View::Raw),
        Some(Value::String(name)) => View::parse(name).ok_or_else(|| {
            let known = View::ALL.map(View::name).join(", ");
            invalid_params(format!("{name:?} is not a view; one of {known}"))
        }),
        Some(_) => Err(invalid_params("\"as\" is a string".to_owned())),
    }
}

/// A view, with the dictionary this frontend offers with it. The command line's
/// `commands::wanted` is the same one.
const fn wanted(view: View) -> view::Wanted<'static> {
    view::Wanted {
        view,
        names: Dictionary::EMPTY,
    }
}

/// What a view answered. [`View::Auto`] is a question and never an answer, so
/// this reports whichever of the two forms came back.
const fn answered(xml: bool) -> &'static str {
    if xml {
        View::Xml.name()
    } else {
        View::Raw.name()
    }
}

/// A handle that was never opened, or has been closed. A well-formed request
/// this daemon declines, so a refusal and not `-32602`.
fn no_such_handle(handle: u64) -> Rejected {
    Rejected::from(Failure::Refused {
        reason: format!("no open archive with handle {handle}"),
    })
}

/// The session a request names.
fn session<'a>(state: &'a mut State, params: &Value) -> Answer<&'a mut Session> {
    let handle = handle_of(params)?;
    state
        .sessions
        .get_mut(&handle)
        .ok_or_else(|| no_such_handle(handle))
}

/// The same, for a method that buffers a change. An archive this build can read
/// and not write back is refused here rather than at the commit.
fn writing_session<'a>(state: &'a mut State, params: &Value) -> Answer<&'a mut Session> {
    let session = session(state, params)?;
    session.archive.writable().map_err(Failure::Container)?;
    Ok(session)
}

/// The archive a request names, as the one path a session reports and rebuilds.
/// Two names for one *file* do not resolve alike, which is what [`FileId`] is
/// for.
fn resolve(path: &Path) -> crate::exit::Result<PathBuf> {
    fs::canonicalize(path).map_err(|source| commands::opening(path, source))
}

/// `open` — claim an archive, parse it, and keep it warm. The claim is on the
/// file as well as the path, and a second `open` of one archive is refused.
fn open(state: &mut State, params: &Value) -> Answered {
    let asked = PathBuf::from(string(params, "path")?);
    let path = resolve(&asked)?;
    let (file, archive) = commands::open(&path, state.cache.as_deref())?;
    let id = FileId::of(&file, &path)?;
    if let Some((holder, held)) = state.holder_of(&path, Some(id)) {
        return Err(already_open(&path, held, holder).into());
    }

    state.next_handle = state.next_handle.saturating_add(1);
    let handle = state.next_handle;
    let entries = archive.entries().len();
    let len = archive.len_bytes();
    let reported = path.display().to_string();
    state.sessions.insert(
        handle,
        Session {
            path,
            id,
            file,
            archive,
            pending: Changes::new(),
        },
    );

    Ok(json!({
        // The resolved path, not the one asked for: it is what the session
        // claimed and what a refusal names.
        "handle": handle,
        "path": reported,
        "entries": entries,
        "len": len,
    }))
}

/// That an archive is held, and by which handle. The path asked for and the one
/// the holder claimed can differ — two names for one file — so both are named.
fn names_held(path: &Path, held: &Path, holder: u64) -> String {
    if held == path {
        format!("{} is already open on handle {holder}", path.display())
    } else {
        format!(
            "{} is another name for {}, which is already open on handle {holder}",
            path.display(),
            held.display()
        )
    }
}

/// Why one archive cannot be opened twice, and which handle has it.
fn already_open(path: &Path, held: &Path, holder: u64) -> Failure {
    Failure::Refused {
        reason: format!(
            "{}. An archive is open in one session at a time: every offset a session holds \
             is true only of the bytes it parsed, and a second session committing moves them. \
             Close handle {holder} first, or work on a copy",
            names_held(path, held, holder),
        ),
    }
}

/// `close` — forget a session, and release its claim on the archive.
/// Uncommitted edits are discarded, and the response says how many.
fn close(state: &mut State, params: &Value) -> Answered {
    let handle = handle_of(params)?;
    let closed = state
        .sessions
        .remove(&handle)
        .ok_or_else(|| no_such_handle(handle))?;
    Ok(json!({ "closed": true, "discarded": closed.pending.len() }))
}

/// An optional path inside the archive a handle holds, empty for its root.
fn inside_of(params: &Value) -> String {
    params
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

/// `list` — the entries at a path, optionally recursively.
///
/// It doubles as a `stat`: an ordinary file answers exactly one row rather than
/// an error, and an empty directory answers `[]`. A row's `path` is the whole
/// in-archive path and must not be joined onto what was asked for. A listing is
/// the archive on disk: buffered changes are not in it.
fn list(state: &mut State, params: &Value) -> Answered {
    let inside = inside_of(params);
    let recursive = flag(params, "recursive")?;
    let pattern = optional_string(params, "pattern")?;
    let session = session(state, params)?;

    let rows = commands::matching(
        rpf_core::Listed::at(&mut session.file, &session.archive, &inside, recursive)?,
        pattern.as_deref(),
    );
    Ok(Value::Array(
        rows.iter().map(commands::listing_row).collect(),
    ))
}

/// `read` — one entry's bytes, as base64.
///
/// A pending write is answered in preference to what is on disk, conversion
/// included. `"as"` says which form is wanted — `"raw"`, `"xml"` or `"auto"` —
/// and the answer says which it got, beside the `"encoding"` the entry holds.
fn read(state: &mut State, params: &Value) -> Answered {
    let inside = string(params, "path")?;
    let view = view_of(params)?;
    let session = session(state, params)?;

    if view != View::Raw && session.pending.contents_at(&inside).is_some() {
        let payload = buffered_payload(session, &inside)?;
        let held = buffered_held(session, &inside, &payload)?;
        let viewed = view::of(payload, held, &inside, wanted(view))?;
        return Ok(json!({
            "path": inside,
            "len": viewed.bytes.len(),
            "pending": true,
            "as": answered(viewed.xml),
            "encoding": viewed.encoding.map(Encoding::name),
            "bytes": BASE64.encode(&viewed.bytes),
        }));
    }

    if let Some(buffered) = session.pending.contents_at(&inside) {
        // Encoded as it is read, so the answer costs the encoded form and not a
        // copy of the payload beside it.
        let len = buffered.len()?;
        let mut encoder = base64::write::EncoderStringWriter::new(&BASE64);
        io::copy(&mut buffered.open()?, &mut encoder).map_err(|source| Failure::Io {
            path: inside.clone(),
            source,
        })?;
        // A payload nothing asked a question of is not classified: `"raw"`,
        // and `"encoding"` is `null`.
        return Ok(json!({
            "path": inside,
            "len": len,
            "pending": true,
            "as": answered(false),
            "encoding": Value::Null,
            "bytes": encoder.into_inner(),
        }));
    }

    let (holder, index) = session.archive.locate(&mut session.file, &inside)?;
    if holder.entry(index)?.is_directory() {
        return Err(Failure::Refused {
            reason: format!("{inside} is a directory"),
        }
        .into());
    }
    let viewed = view::read(&mut session.file, &holder, index, &inside, wanted(view))?;
    Ok(json!({
        "path": inside,
        "len": viewed.bytes.len(),
        "pending": false,
        "as": answered(viewed.xml),
        "encoding": viewed.encoding.map(Encoding::name),
        "bytes": BASE64.encode(&viewed.bytes),
    }))
}

/// The whole of a buffered write's payload, held rather than streamed because a
/// conversion is a whole document against a whole payload.
fn buffered_payload(session: &Session, inside: &str) -> Answer<Vec<u8>> {
    let Some(buffered) = session.pending.contents_at(inside) else {
        return Ok(Vec::new());
    };
    let mut payload = Vec::new();
    io::copy(&mut buffered.open()?, &mut payload).map_err(|source| Failure::Io {
        path: inside.to_owned(),
        source,
    })?;
    Ok(payload)
}

/// What the entry a payload is buffered over holds, for a conversion that has
/// only the buffer to work from.
///
/// The entry decides whether there is a view; the bytes decide only what is in
/// it — the page boundary appears nowhere in the payload and a keyed resource's
/// buffer is ciphertext. A path the archive does not hold yet is a creation, and
/// only its bytes can answer for it.
fn buffered_held(session: &mut Session, inside: &str, payload: &[u8]) -> Answer<view::Held> {
    match session.archive.locate(&mut session.file, inside) {
        Ok((holder, index)) => Ok(view::held_in_hand(
            &mut session.file,
            &holder,
            index,
            payload,
        )?),
        Err(rpf_core::Error::NotFound { .. }) => Ok(view::Held::from(Encoding::of(
            payload.get(..Encoding::HEAD_LEN).unwrap_or(payload),
        ))),
        Err(failed) => Err(failed.into()),
    }
}

/// `write` — buffer an edit. Nothing on disk changes until `commit`.
///
/// `create: true` lets it be a path the archive does not hold yet, which forces
/// a rebuild; without it such a path is [`rpf_core::Error::NotFound`].
fn write(state: &mut State, params: &Value) -> Answered {
    let inside = string(params, "path")?;
    let encoded = string(params, "bytes")?;
    let create = flag(params, "create")?;
    let allow_encoding_change = flag(params, "allow_encoding_change")?;
    let view = view_of(params)?;
    let offered = BASE64
        .decode(encoded.as_bytes())
        .map_err(|_| invalid_params("\"bytes\" is not base64".to_owned()))?;
    let session = writing_session(state, params)?;

    // Resolved now rather than at commit, while the caller can still act on a
    // refusal.
    let located = session.archive.locate(&mut session.file, &inside);
    match located {
        Ok((holder, index)) => {
            if holder.entry(index)?.is_directory() {
                return Err(Failure::Refused {
                    reason: format!("{inside} is a directory"),
                }
                .into());
            }
            // Buffered as the payload it becomes, so the set holds the entry's
            // own encoding whatever route it came in by: a converted write
            // needs no `allow_encoding_change`.
            let bytes = if view == View::Raw {
                offered
            } else if session.pending.contents_at(&inside).is_some() {
                let payload = buffered_payload(session, &inside)?;
                let held = buffered_held(session, &inside, &payload)?;
                view::applied(&payload, held, &inside, wanted(view), offered)?
            } else {
                view::apply(
                    &mut session.file,
                    &holder,
                    index,
                    &inside,
                    wanted(view),
                    offered,
                )?
            };
            let change = Change::Write {
                contents: std::sync::Arc::new(rpf_core::Bytes::new(bytes)),
                create,
                allow_encoding_change,
            };
            // A removal or a rename above this path leaves the commit writing
            // to something that will not be there. `bears_on` answers that from
            // the set alone, so the entry-table walk is paid only where it
            // could collide.
            session.pending.admits(&inside, &change)?;
            if session.pending.bears_on(&inside) {
                rpf_core::allows(
                    &mut session.file,
                    &session.archive,
                    &session.pending,
                    &inside,
                    &change,
                )?;
            }
            record(session, &inside, change).map_err(Into::into)
        }
        // A path being created has no entry to check against, so the whole
        // change is resolved instead.
        Err(rpf_core::Error::NotFound { .. }) if create => {
            let bytes = view::applied(&[], view::Held::Nothing, &inside, wanted(view), offered)?;
            let change = Change::Write {
                contents: std::sync::Arc::new(rpf_core::Bytes::new(bytes)),
                create,
                allow_encoding_change,
            };
            rpf_core::allows(
                &mut session.file,
                &session.archive,
                &session.pending,
                &inside,
                &change,
            )?;
            record(session, &inside, change).map_err(Into::into)
        }
        Err(other) => Err(Failure::Container(other).into()),
    }
}

/// `delete` — buffer a removal. Nothing on disk changes until `commit`.
///
/// `recursive: true` takes a directory's children with it; without it a
/// directory that holds anything is refused.
fn delete(state: &mut State, params: &Value) -> Answered {
    let inside = string(params, "path")?;
    let recursive = flag(params, "recursive")?;
    buffer(state, params, &inside, Change::Remove { recursive })
}

/// `rename` — buffer a move to another path in the same archive.
///
/// `to` is a whole in-archive path, so a rename moves between directories as
/// well as changing a name. A destination already held is refused.
fn rename(state: &mut State, params: &Value) -> Answered {
    let from = string(params, "from")?;
    let to = string(params, "to")?;
    let session = writing_session(state, params)?;
    let change = Change::RenameTo(to.clone());
    rpf_core::allows(
        &mut session.file,
        &session.archive,
        &session.pending,
        &from,
        &change,
    )?;
    session.pending.set(from.clone(), change);
    Ok(json!({
        "from": from,
        "to": to,
        "pending": session.pending.len(),
    }))
}

/// `mkdir` — buffer a directory, and whatever above it is missing.
fn mkdir(state: &mut State, params: &Value) -> Answered {
    let inside = string(params, "path")?;
    buffer(state, params, &inside, Change::MakeDirectory)
}

/// Records one change against a session, once `rpf_core::allows` has agreed to
/// it against the session's own buffer, so the commit will not refuse it for the
/// same reason.
fn buffer(state: &mut State, params: &Value, inside: &str, change: Change) -> Answered {
    let session = writing_session(state, params)?;
    rpf_core::allows(
        &mut session.file,
        &session.archive,
        &session.pending,
        inside,
        &change,
    )?;
    record(session, inside, change).map_err(Into::into)
}

/// Records one change against a session, and reports what is buffered. One
/// shape for every method that buffers; `len` is `null` for a change that
/// carries no payload.
///
/// # Errors
///
/// Whatever measuring the payload failed with.
fn record(session: &mut Session, inside: &str, change: Change) -> crate::exit::Result<Value> {
    let len = match change {
        Change::Write { ref contents, .. } => Some(contents.len()?),
        _ => None,
    };
    session.pending.set(inside, change);
    Ok(json!({
        "path": inside,
        "len": len,
        "pending": session.pending.len(),
    }))
}

/// `info` — the header, and what the entries add up to. `path` is empty or
/// absent for the archive itself, and otherwise names a nested archive.
fn info(state: &mut State, params: &Value) -> Answered {
    let inside = inside_of(params);
    let session = session(state, params)?;
    let summary = rpf_core::Summary::of(&mut session.file, &session.archive, &inside)?;
    Ok(commands::info_report(&session.path, &inside, &summary))
}

/// `verify` — read every entry back and check it against what the archive says.
///
/// Reports progress and takes a `cancel`. An entry that does not read back is
/// reported in `problems` rather than as an error. `against` names an extracted
/// tree of this archive, whose manifest is the only thing that can see a stored
/// entry's bytes change; without it `contents_checked` is zero and `against` is
/// `null`.
fn verify(state: &mut State, params: &Value, wire: &Wire, request: &Value) -> Answered {
    let handle = handle_of(params)?;
    let against = optional_path(params, "against")?;
    let wanted = wants_progress(params)?;
    let name = name_of(request);
    let session = session(state, params)?;

    let mut watch = Notifying {
        wire,
        handle: Some(handle),
        name: &name,
        wanted,
        skipped: 0,
        stopped: None,
    };
    wire.cancel
        .begin(request, Some(handle), "verify", Stoppable::Yes);
    let outcome = commands::verified(
        &mut session.file,
        &session.archive,
        against.as_deref(),
        &mut watch,
    );
    wire.cancel.finish();
    let checked = outcome.map_err(|failure| watch.explain(failure))?;

    let problems: Vec<Value> = checked
        .verified
        .problems
        .iter()
        .map(commands::verify_problem)
        .collect();
    Ok(commands::verify_report(
        &session.path,
        &checked,
        &problems,
        usize::MAX,
    ))
}

/// `extract` — write every entry of an open archive to a tree.
///
/// `into` is a directory on the daemon's own filesystem. It reports progress and
/// takes a `cancel`; a cancelled extraction leaves what it had already written.
/// `overwrite: true` lets it write into a non-empty directory.
///
/// It refuses a session with buffered edits, and a path an open session holds —
/// both up front, because a refusal found part-way would leave half a tree.
fn extract(state: &mut State, params: &Value, wire: &Wire, request: &Value) -> Answered {
    let handle = handle_of(params)?;
    let into = PathBuf::from(string(params, "into")?);
    let existing = crate::existing(flag(params, "overwrite")?);
    let wanted = wants_progress(params)?;
    let name = name_of(request);

    // Immutably, and a handle of its own: the claim check below reads every
    // session while this one is being extracted, which a `&mut Session` would
    // forbid.
    let state: &State = state;
    let session = state
        .sessions
        .get(&handle)
        .ok_or_else(|| no_such_handle(handle))?;
    if !session.pending.is_empty() {
        return Err(extracting_with_edits(&session.pending).into());
    }
    let mut src = session.file.try_clone().map_err(|source| Failure::Io {
        path: session.path.display().to_string(),
        source,
    })?;

    let mut watch = Notifying {
        wire,
        handle: Some(handle),
        name: &name,
        wanted,
        skipped: 0,
        stopped: None,
    };
    wire.cancel
        .begin(request, Some(handle), "extract", Stoppable::Yes);
    let outcome = commands::extract_into(
        &mut src,
        &session.archive,
        &into,
        existing,
        &|target| {
            state
                .holder_of(target, identity_of(target))
                .map(|(holder, held)| extracting_over_held(target, held, holder))
        },
        &mut watch,
    );
    wire.cancel.finish();
    let extracted = outcome.map_err(|failure| watch.explain(failure))?;

    Ok(json!({
        "archive": session.path.display().to_string(),
        "into": into.display().to_string(),
        "files": extracted.files,
        "directories": extracted.directories,
        "manifest": extracted.manifest.display().to_string(),
    }))
}

/// Why a tree cannot be extracted while edits are still buffered. It names them,
/// because committing or discarding them is what the caller has to do.
fn extracting_with_edits(pending: &Changes) -> Failure {
    let paths: Vec<&str> = pending.paths().collect();
    Failure::Refused {
        reason: format!(
            "{} buffered {} not been committed ({}). An extracted tree is the archive as it \
             is on disk — the same tree `rpf extract` writes and `pack` reads back — so it \
             cannot also carry an edit no archive holds. Commit them first, or discard them",
            paths.len(),
            if paths.len() == 1 {
                "edit has"
            } else {
                "edits have"
            },
            paths.join(", "),
        ),
    }
}

/// Why an extraction cannot write here, and which handle has it.
fn extracting_over_held(path: &Path, held: &Path, holder: u64) -> Failure {
    Failure::Refused {
        reason: format!(
            "{}. Extracting an entry over it would move every offset that session holds. \
             Close handle {holder} first, or extract somewhere else",
            names_held(path, held, holder),
        ),
    }
}

/// `pack` — build an archive from a tree and its manifest.
///
/// It has no handle, and both of its paths are on the daemon's filesystem. An
/// archive an open session holds cannot be packed over: every offset that
/// session holds is true only of the bytes it parsed.
fn pack(state: &mut State, params: &Value, wire: &Wire, request: &Value) -> Answered {
    let from = PathBuf::from(string(params, "from")?);
    let archive = PathBuf::from(string(params, "archive")?);
    let force = flag(params, "force")?;
    let wanted = wants_progress(params)?;
    let name = name_of(request);

    let target = target_of(&archive)?;
    if let Some((holder, held)) = state.holder_of(&target, identity_of(&target)) {
        return Err(packing_over_held(&target, held, holder).into());
    }
    let cache = state.cache.clone();

    let mut watch = Notifying {
        wire,
        handle: None,
        name: &name,
        wanted,
        skipped: 0,
        stopped: None,
    };
    wire.cancel.begin(request, None, "pack", Stoppable::Yes);
    let outcome = commands::pack_from(&from, &archive, force, cache.as_deref(), &mut watch);
    wire.cancel.finish();
    let report = outcome.map_err(|failure| watch.explain(failure))?;

    Ok(json!({
        "archive": archive.display().to_string(),
        "entries": report.entry_count,
        "len": report.len,
    }))
}

/// The path a write will land on, resolved as far as it exists: [`resolve`]
/// needs the file to be there and `pack` usually writes one that is not, so the
/// directory is resolved and the name joined back on.
///
/// # Errors
///
/// The directory does not resolve, or the path names no file at all.
fn target_of(path: &Path) -> crate::exit::Result<PathBuf> {
    if let Ok(resolved) = fs::canonicalize(path) {
        return Ok(resolved);
    }
    let name = path.file_name().ok_or_else(|| Failure::Refused {
        reason: format!("{} does not name an archive to write", path.display()),
    })?;
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(resolve(directory)?.join(name))
}

/// What the operating system calls the file at a path, when there is one.
/// `None` covers both "nothing is there" and "it could not be statted".
fn identity_of(path: &Path) -> Option<FileId> {
    let file = fs::File::open(path).ok()?;
    FileId::of(&file, path).ok()
}

/// Why an archive cannot be packed over, and which handle has it.
fn packing_over_held(path: &Path, held: &Path, holder: u64) -> Failure {
    Failure::Refused {
        reason: format!(
            "{}. Packing over it would move every offset that session holds. Close handle \
             {holder} first, or pack somewhere else",
            names_held(path, held, holder),
        ),
    }
}

/// An optional string parameter.
fn optional_string(params: &Value, name: &str) -> Answer<Option<String>> {
    match params.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(|text| Some(text.to_owned()))
            .ok_or_else(|| invalid_params(format!("{name:?} is a string"))),
    }
}

/// An optional path parameter, on the daemon's own filesystem.
fn optional_path(params: &Value, name: &str) -> Answer<Option<PathBuf>> {
    match params.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(|path| Some(PathBuf::from(path)))
            .ok_or_else(|| invalid_params(format!("{name:?} is a path, as a string"))),
    }
}

/// `keys.extract` — find the key material a game executable carries.
///
/// No handle: `executable` and the optional `cache` are paths on the daemon's
/// filesystem. It reports offsets, lengths, the source digest and where the
/// material was cached, and never a key. It sends no `progress` and cannot be
/// stopped, but registers as [`Stoppable::No`] so a cancel is told what is
/// running rather than that nothing is.
fn keys_extract(state: &State, params: &Value, wire: &Wire, request: &Value) -> Answered {
    let executable = PathBuf::from(string(params, "executable")?);
    let cache = named_cache(state, params)?;

    wire.cancel
        .begin(request, None, "keys.extract", Stoppable::No(SCANNING));
    let found = commands::find_keys(&executable, cache.as_deref(), &mut Unwatched);
    wire.cancel.finish();

    Ok(commands::keys_report(&found?))
}

/// Which cache a `keys.*` request works on: the one it names, or the one this
/// process was started with.
fn named_cache(state: &State, params: &Value) -> Answer<Option<PathBuf>> {
    Ok(optional_path(params, "cache")?.or_else(|| state.cache.clone()))
}

/// A key scan is under way.
const SCANNING: &str = "a key scan hashes the whole source looking for every value at once; it reports nothing \
     part-way and has no step to stop at";

/// `keys.cache` — where extracted material is kept, and how much is there.
fn keys_cache(state: &State, params: &Value) -> Answered {
    let cache = named_cache(state, params)?;
    let state = commands::cache_state(cache.as_deref())?;
    Ok(commands::cache_report(&state))
}

/// `keys.invalidate` — remove every cached entry.
fn keys_invalidate(state: &State, params: &Value) -> Answered {
    let cache = named_cache(state, params)?;
    let state = commands::invalidate_keys(cache.as_deref())?;
    Ok(commands::invalidated_report(&state))
}

/// `pending` — what has been written but not committed.
fn pending(state: &mut State, params: &Value) -> Answered {
    let session = session(state, params)?;
    let paths: Vec<&str> = session.pending.paths().collect();
    Ok(json!({ "paths": paths }))
}

/// `discard` — drop the buffered edits.
fn discard(state: &mut State, params: &Value) -> Answered {
    let session = session(state, params)?;
    let dropped = session.pending.len();
    session.pending.clear();
    Ok(json!({ "discarded": dropped }))
}

/// `forget` — take one buffered change back, and say what is left. `forgotten`
/// is false for a path nothing is buffered at, which is not a failure.
fn forget(state: &mut State, params: &Value) -> Answered {
    let inside = string(params, "path")?;
    let session = session(state, params)?;
    let forgotten = session.pending.forget(&inside).is_some();
    let paths: Vec<&str> = session.pending.paths().collect();
    Ok(json!({
        "path": inside,
        "forgotten": forgotten,
        "pending": paths.len(),
        "paths": paths,
    }))
}

/// Which of the two ways a commit will go, decided without writing anything.
/// `F` is what the patch writes through. [`Opening`].
enum Decision<F> {
    /// Every edit fits where its entry sits, and the archive opens for writing.
    Patch { patches: rpf_core::Patches, file: F },
    /// One does not fit, a rebuild was asked for, or the archive will not open
    /// for writing.
    Rebuild,
}

impl<F> Decision<F> {
    /// What the response will report, and what a `cancel` will be told is
    /// running.
    const fn method(&self) -> &'static str {
        match *self {
            Self::Patch { .. } => "patch",
            Self::Rebuild => "rebuild",
        }
    }

    /// Whether it can be stopped part-way. A patch cannot: there is no point
    /// between entries to stop at.
    const fn stoppable(&self) -> Stoppable {
        match *self {
            Self::Patch { .. } => Stoppable::No(PATCHING),
            Self::Rebuild => Stoppable::Yes,
        }
    }
}

/// What one commit was asked for, past the flags that decide nothing.
struct Asked<'a> {
    /// The session it runs against. A commit always has one.
    handle: u64,
    /// The `id` of the request, which is the name a cancel uses.
    request: &'a Value,
    /// The same `id`, cut down to what may be echoed. [`NAME_ECHO`].
    name: &'a Value,
    /// Whether progress was wanted at all.
    progress: bool,
    /// Whether a rebuild was asked for regardless of what would fit.
    rebuild: bool,
}

/// How a commit opens the archive the patch writes through. A parameter of
/// [`decide`] so that a test can observe the two registrations a commit makes
/// from inside the operation they cover.
trait Opening<F> {
    /// Opens the archive at `path` for writing. A commit reads a failure here
    /// as "rebuild instead".
    fn open(self, path: &Path) -> io::Result<F>;
}

impl<F, O> Opening<F> for O
where
    O: FnOnce(&Path) -> io::Result<F>,
{
    fn open(self, path: &Path) -> io::Result<F> {
        self(path)
    }
}

/// The archive itself, which is what a commit patches. A second handle, because
/// a session that only lists an archive must not need write permission on it.
/// [`Opening`].
fn archive_for_writing(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new().write(true).open(path)
}

/// Decides between patching in place and rebuilding, and writes nothing.
fn decide<F>(
    session: &mut Session,
    asked_to_rebuild: bool,
    open: impl Opening<F>,
) -> crate::exit::Result<Decision<F>> {
    if asked_to_rebuild {
        return Ok(Decision::Rebuild);
    }
    let plan = rpf_core::plan(&mut session.file, &session.archive, &session.pending)?;
    let rpf_core::Plan::Fits(patches) = plan else {
        return Ok(Decision::Rebuild);
    };
    let Ok(file) = open.open(&session.path) else {
        return Ok(Decision::Rebuild);
    };
    Ok(Decision::Patch { patches, file })
}

/// `commit` — apply every buffered edit at once.
///
/// Patches in place when every edit fits where its entry sits and rebuilds
/// otherwise, for the set rather than per edit. `rebuild: true` asks for the
/// rebuild regardless — it is atomic where a patch is not — and the response
/// reports which one ran.
fn commit(state: &mut State, params: &Value, wire: &Wire, request: &Value) -> Answered {
    let force = flag(params, "force")?;
    let asked_to_rebuild = flag(params, "rebuild")?;
    let dry_run = flag(params, "dry_run")?;
    let wanted = wants_progress(params)?;
    let name = name_of(request);
    let asked = Asked {
        handle: handle_of(params)?,
        request,
        name: &name,
        progress: wanted,
        rebuild: asked_to_rebuild,
    };
    // Taken before the session is borrowed: re-opening after the write needs
    // the same cache.
    let cache = state.cache.clone();
    let session = session(state, params)?;

    if session.pending.is_empty() {
        return Ok(json!({ "committed": 0, "unchanged": true }));
    }
    // Asked here as well as where each change was buffered, so that a dry run
    // reports the refusal rather than a rebuild that could not happen.
    session.archive.writable().map_err(Failure::Container)?;
    // Before the dry run: what the real call would do here is refuse.
    commands::refuse_game_install(&session.path, force)?;
    if dry_run {
        return would_commit(session, asked_to_rebuild);
    }

    let committed = session.pending.len();

    let outcome = commit_now(session, wire, &asked, archive_for_writing);
    wire.cancel.finish();
    let method = outcome?;

    let (entries, len) = refreshed(state, asked.handle, cache.as_deref())?;

    Ok(json!({
        "committed": committed,
        "method": method,
        "entries": entries,
        "len": len,
    }))
}

/// Re-opens the archive a commit has just written, so the warm state describes
/// what is now on disk. The claim is re-taken with it: a rebuild renames, and a
/// claim kept on the old inode would claim a file nobody has.
///
/// The set is cleared first and whatever happens next, because the write has
/// already landed: a retry of a commit that succeeded would apply it twice. A
/// re-open that fails takes the session with it: the handle would otherwise go
/// on serving the old file, which the rebuild may have unlinked.
fn refreshed(
    state: &mut State,
    handle: u64,
    cache: Option<&Path>,
) -> crate::exit::Result<(usize, u64)> {
    let Some(session) = state.sessions.get_mut(&handle) else {
        return Err(Failure::Refused {
            reason: format!("no open archive with handle {handle}"),
        });
    };
    session.pending.clear();
    let path = session.path.clone();
    match reopened(session, &path, cache) {
        Ok(counts) => Ok(counts),
        Err(failure) => {
            state.sessions.remove(&handle);
            Err(Failure::Io {
                path: path.display().to_string(),
                source: io::Error::other(format!(
                    "the archive was written; the session could not be re-opened on it: \
                     {failure}. Mount it again to go on editing"
                )),
            })
        }
    }
}

/// The re-open itself, so that a failure of either half invalidates the session.
fn reopened(
    session: &mut Session,
    path: &Path,
    cache: Option<&Path>,
) -> crate::exit::Result<(usize, u64)> {
    let (file, archive) = commands::open(path, cache)?;
    let counts = (archive.entries().len(), archive.len_bytes());
    session.id = FileId::of(&file, path)?;
    session.file = file;
    session.archive = archive;
    Ok(counts)
}

/// Registers itself, decides, registers what it decided so a `cancel` can name
/// it, and does it. Separate from [`commit`] so the job is forgotten either way.
fn commit_now<F: Write + Seek>(
    session: &mut Session,
    wire: &Wire,
    asked: &Asked<'_>,
    open: impl Opening<F>,
) -> crate::exit::Result<&'static str> {
    // Registered before the decision as well, because deciding reads and
    // compresses every buffered edit.
    wire.cancel.begin(
        asked.request,
        Some(asked.handle),
        "commit",
        Stoppable::No(DECIDING),
    );
    let decision = decide(session, asked.rebuild, open)?;
    let method = decision.method();
    wire.cancel.begin(
        asked.request,
        Some(asked.handle),
        method,
        decision.stoppable(),
    );
    match decision {
        Decision::Patch { patches, mut file } => patches.apply(&mut file)?,
        Decision::Rebuild => rebuild(session, wire, asked)?,
    }
    Ok(method)
}

/// Reports what a commit would do, taking the decision the way the real commit
/// takes it. The buffered edits are left where they are.
fn would_commit(session: &mut Session, asked_to_rebuild: bool) -> Answered {
    if asked_to_rebuild {
        // Nothing is allocated, so there is no plan to report — only the
        // resolution.
        rpf_core::resolves(&mut session.file, &session.archive, &session.pending)?;
        return Ok(json!({ "committed": 0, "dry_run": true, "method": "rebuild" }));
    }

    match rpf_core::plan(&mut session.file, &session.archive, &session.pending)? {
        rpf_core::Plan::Fits(patches) => {
            let planned: Vec<Value> = patches.planned().map(commands::planned_row).collect();
            Ok(json!({
                "committed": 0,
                "dry_run": true,
                "method": "patch",
                "planned": planned,
            }))
        }
        rpf_core::Plan::DoesNotFit(rejected) => {
            let rejected: Vec<Value> = rejected.iter().map(commands::rejected_row).collect();
            Ok(json!({
                "committed": 0,
                "dry_run": true,
                "method": "rebuild",
                "rejected": rejected,
            }))
        }
        // Nothing in place can add, remove or rename an entry, so the commit
        // will rebuild whatever else is in the set.
        rpf_core::Plan::Structural(structural) => {
            let structural: Vec<Value> = structural.iter().map(commands::structural_row).collect();
            Ok(json!({
                "committed": 0,
                "dry_run": true,
                "method": "rebuild",
                "structural": structural,
            }))
        }
    }
}

/// Rebuilds the archive with every buffered edit, into a temporary file that
/// replaces it.
fn rebuild(session: &mut Session, wire: &Wire, asked: &Asked<'_>) -> crate::exit::Result<()> {
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

    let mut watch = Notifying {
        wire,
        handle: Some(asked.handle),
        name: asked.name,
        wanted: asked.progress,
        skipped: 0,
        stopped: None,
    };
    // Intermediates go where the rebuilt archive is going, because there is
    // nobody to ask for another location.
    let outcome = rpf_core::rewrite(
        &mut session.file,
        &session.archive,
        &session.pending,
        scratch.as_file_mut(),
        &mut commands::ScratchIn::beside(&session.path),
        &mut watch,
    );
    if let Err(error) = outcome {
        return Err(watch.explain(Failure::from(error)));
    }

    let path = session.path.clone();
    commands::persist(scratch, &path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::exit::Code;

    /// How long a thread that should never wait is given before it is called
    /// wedged, so that one which does fails an assertion instead of hanging.
    const WEDGED: Duration = Duration::from_secs(60);

    /// A cancelled write, as the library reports one.
    fn cancelled() -> Failure {
        Failure::Container(rpf_core::Error::Cancelled { done: 1, total: 24 })
    }

    #[test]
    fn a_broken_output_pipe_is_not_reported_as_a_cancellation() {
        // Both arrive from the library as Error::Cancelled, because both are
        // Flow::Stop.
        assert!(matches!(
            stopped_as(Some(Stopped::OutputGone), cancelled()).code(),
            Code::Io
        ));
        assert!(matches!(
            stopped_as(Some(Stopped::Cancelled), cancelled()).code(),
            Code::Cancelled
        ));
        assert!(matches!(
            stopped_as(None, cancelled()).code(),
            Code::Cancelled
        ));
    }

    /// A two-entry archive on disk, and a session on it holding one buffered
    /// write against `a.txt`.
    fn session_on(path: PathBuf) -> Session {
        let files: Vec<rpf_core::FileSpec> = ["a.txt", "b.txt"]
            .into_iter()
            .map(|name| rpf_core::FileSpec {
                path: name.to_owned(),
                kind: rpf_core::FileKind::Binary {
                    storage: rpf_core::Storage::Stored,
                    encryption: 0,
                },
            })
            .collect();
        let mut out = fs::File::create(&path).expect("creatable");
        rpf_core::build(
            &mut out,
            rpf_core::Version::Rpf7,
            &files,
            &[],
            |_: &str| Ok(std::io::Cursor::new(b"contents".to_vec())),
            &mut rpf_core::Unwatched,
        )
        .expect("builds");
        drop(out);

        let (file, archive) = commands::open(&path, None).expect("opens");
        let id = FileId::of(&file, &path).expect("named");
        Session {
            path,
            id,
            file,
            archive,
            pending: Changes::one(
                "a.txt",
                Change::Write {
                    contents: std::sync::Arc::new(rpf_core::Bytes::new(b"replaced".to_vec())),
                    create: false,
                    allow_encoding_change: false,
                },
            ),
        }
    }

    /// [`Notifying::explain`] where the daemon actually calls it: the test above
    /// passes with nothing calling it.
    #[test]
    fn a_rebuild_that_loses_its_output_says_so_rather_than_claiming_a_cancel() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut session = session_on(dir.path().join("test.rpf"));

        // Standard output already stopped accepting anything, which is the one
        // condition that stops a rebuild without a cancel.
        let (lines, _queued) = mpsc::channel();
        let backlog = Arc::new(Backlog::default());
        backlog.broken.store(true, Ordering::SeqCst);
        let wire = Wire {
            lines,
            backlog,
            cancel: Cancellation::default(),
        };

        let name = json!(1);
        let asked = Asked {
            handle: 1,
            request: &name,
            name: &name,
            progress: true,
            rebuild: true,
        };

        let failure = rebuild(&mut session, &wire, &asked).expect_err("the far end has gone");
        assert!(
            matches!(failure.code(), Code::Io),
            "a broken output was reported as {failure:?}"
        );
        assert!(
            failure.to_string().contains("<stdout>"),
            "the failure does not name the output that broke: {failure}"
        );
    }

    #[test]
    fn a_session_that_cannot_be_reopened_after_a_write_is_closed_rather_than_left_stale() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("test.rpf");
        let mut state = State::default();
        state.sessions.insert(1, session_on(path.clone()));
        // The commit wrote; what it wrote is then not there to be opened.
        fs::remove_file(&path).expect("removable");

        let failure = refreshed(&mut state, 1, None).expect_err("nothing to re-open");
        assert!(
            matches!(failure.code(), Code::Io),
            "the archive was written, and this was reported as {failure:?}"
        );
        assert!(
            failure.to_string().contains("the archive was written"),
            "the failure does not say the write landed: {failure}"
        );
        assert!(
            state.sessions.is_empty(),
            "the handle outlived the file it reads, and would serve stale bytes",
        );
    }

    #[test]
    fn a_failure_that_is_not_a_stop_is_left_alone() {
        let refused = Failure::Refused {
            reason: "no".to_owned(),
        };
        assert!(matches!(
            stopped_as(Some(Stopped::OutputGone), refused).code(),
            Code::Refused
        ));
    }

    #[test]
    fn a_pack_is_cancellable_and_is_named_by_nothing_but_its_request() {
        // `pack` has no session, so a cancel that names a handle names something
        // else by construction.
        let cancel = Cancellation::default();
        cancel.begin(&json!(7), None, "pack", Stoppable::Yes);

        let aimed = cancel.ask(None, Some(1));
        assert_eq!(aimed["cancelling"], json!(false), "{aimed}");
        assert_eq!(aimed["handle"], json!(null), "{aimed}");
        assert!(!cancel.stopped(), "a cancel aimed at a handle stopped it");

        let answer = cancel.ask(Some(&json!(7)), None);
        assert_eq!(answer["cancelling"], json!(true), "{answer}");
        assert_eq!(answer["running"], json!("pack"), "{answer}");
        assert_eq!(answer["handle"], json!(null), "{answer}");
        assert!(cancel.stopped());
    }

    #[test]
    fn a_patch_answers_a_cancel_with_what_it_actually_does() {
        let cancel = Cancellation::default();
        cancel.begin(&json!(7), Some(1), "patch", Stoppable::No(PATCHING));

        let answer = cancel.ask(None, None);
        assert_eq!(answer["cancelling"], json!(false), "{answer}");
        assert_eq!(answer["running"], json!("patch"), "{answer}");
        assert_eq!(answer["reason"], json!(PATCHING), "{answer}");
        assert!(!cancel.stopped(), "a patch was marked cancelled");
    }

    #[test]
    fn a_commit_that_has_not_decided_yet_says_that_rather_than_nothing() {
        let cancel = Cancellation::default();
        cancel.begin(&json!(7), Some(1), "commit", Stoppable::No(DECIDING));

        let answer = cancel.ask(None, None);
        assert_eq!(answer["cancelling"], json!(false), "{answer}");
        assert_eq!(answer["running"], json!("commit"), "{answer}");
        assert_eq!(answer["reason"], json!(DECIDING), "{answer}");
    }

    /// The archive a commit patches, which answers a `cancel` on its first write
    /// — the first byte of the patch. [`Opening`].
    struct Asking<'a> {
        file: fs::File,
        cancel: &'a Cancellation,
        answered: &'a RefCell<Option<Value>>,
    }

    impl Write for Asking<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let mut answered = self.answered.borrow_mut();
            if answered.is_none() {
                *answered = Some(self.cancel.ask(None, None));
            }
            self.file.write(bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.file.flush()
        }
    }

    impl Seek for Asking<'_> {
        fn seek(&mut self, to: io::SeekFrom) -> io::Result<u64> {
            self.file.seek(to)
        }
    }

    #[test]
    fn a_cancel_during_a_commit_that_patches_is_told_why_it_cannot() {
        // The two registrations the commit makes for itself, asked from inside
        // it at the two moments a cancel can arrive: dropping either `begin`
        // leaves every other test green.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("test.rpf");
        let files: Vec<rpf_core::FileSpec> = ["a.txt", "b.txt"]
            .into_iter()
            .map(|name| rpf_core::FileSpec {
                path: name.to_owned(),
                kind: rpf_core::FileKind::Binary {
                    storage: rpf_core::Storage::Stored,
                    encryption: 0,
                },
            })
            .collect();
        let mut out = fs::File::create(&path).expect("creatable");
        rpf_core::build(
            &mut out,
            rpf_core::Version::Rpf7,
            &files,
            &[],
            |_: &str| Ok(std::io::Cursor::new(b"contents".to_vec())),
            &mut rpf_core::Unwatched,
        )
        .expect("builds");
        drop(out);

        let (file, archive) = commands::open(&path, None).expect("opens");
        let id = FileId::of(&file, &path).expect("named");
        // The same length the entry already holds, so the commit patches.
        let mut session = Session {
            path,
            id,
            file,
            archive,
            pending: Changes::one(
                "a.txt",
                Change::Write {
                    contents: std::sync::Arc::new(rpf_core::Bytes::new(b"replaced".to_vec())),
                    create: false,
                    allow_encoding_change: false,
                },
            ),
        };

        let (lines, _queued) = mpsc::channel();
        let wire = Wire {
            lines,
            backlog: Arc::new(Backlog::default()),
            cancel: Cancellation::default(),
        };
        let request = json!(9);
        let asked = Asked {
            handle: 1,
            request: &request,
            name: &request,
            progress: false,
            rebuild: false,
        };

        let deciding = RefCell::new(None);
        let patching = RefCell::new(None);
        let method = commit_now(&mut session, &wire, &asked, |path: &Path| {
            *deciding.borrow_mut() = Some(wire.cancel.ask(None, None));
            archive_for_writing(path).map(|file| Asking {
                file,
                cancel: &wire.cancel,
                answered: &patching,
            })
        })
        .expect("the edit fits where its entry sits");
        assert_eq!(method, "patch");

        let deciding = deciding.into_inner().expect("the commit opened its target");
        assert_eq!(deciding["cancelling"], json!(false), "{deciding}");
        assert_eq!(deciding["running"], json!("commit"), "{deciding}");
        assert_eq!(deciding["reason"], json!(DECIDING), "{deciding}");

        let patching = patching.into_inner().expect("the patch wrote nothing");
        assert_eq!(patching["cancelling"], json!(false), "{patching}");
        assert_eq!(patching["running"], json!("patch"), "{patching}");
        assert_eq!(patching["reason"], json!(PATCHING), "{patching}");
        assert_eq!(patching["handle"], json!(1), "{patching}");

        assert!(!wire.cancel.stopped(), "a patch was marked cancelled");
    }

    #[test]
    fn a_key_scan_says_it_is_running_rather_than_that_nothing_is() {
        let cancel = Cancellation::default();
        cancel.begin(&json!(7), None, "keys.extract", Stoppable::No(SCANNING));

        let answer = cancel.ask(None, None);
        assert_eq!(answer["cancelling"], json!(false), "{answer}");
        assert_eq!(answer["running"], json!("keys.extract"), "{answer}");
        assert_eq!(answer["reason"], json!(SCANNING), "{answer}");
        assert!(!cancel.stopped(), "a key scan was marked cancelled");

        cancel.finish();
        assert_eq!(cancel.ask(None, None)["running"], json!(null));
    }

    #[test]
    fn a_cancel_only_stops_the_operation_it_names() {
        let cancel = Cancellation::default();
        cancel.begin(&json!(7), Some(3), "rebuild", Stoppable::Yes);

        for aimed_elsewhere in [
            cancel.ask(Some(&json!(6)), None),
            cancel.ask(None, Some(4)),
            cancel.ask(Some(&json!(7)), Some(4)),
        ] {
            assert_eq!(
                aimed_elsewhere["cancelling"],
                json!(false),
                "{aimed_elsewhere}"
            );
        }
        assert!(!cancel.stopped(), "a cancel aimed elsewhere landed here");

        let aimed = cancel.ask(Some(&json!(7)), Some(3));
        assert_eq!(aimed["cancelling"], json!(true), "{aimed}");
        assert_eq!(aimed["running"], json!("rebuild"), "{aimed}");
        assert!(cancel.stopped());
    }

    #[test]
    fn a_cancel_with_nothing_running_is_not_remembered() {
        let cancel = Cancellation::default();
        let answer = cancel.ask(None, None);
        assert_eq!(answer["cancelling"], json!(false), "{answer}");
        assert_eq!(answer["running"], json!(null), "{answer}");

        cancel.begin(&json!(1), Some(1), "rebuild", Stoppable::Yes);
        assert!(!cancel.stopped(), "a cancel was stored for the next commit");
        cancel.finish();
        assert!(!cancel.stopped());
    }

    #[test]
    fn a_cancel_parameter_that_is_ill_typed_names_nothing_and_says_so() {
        // `as_u64` answers None for every one of these, and a parameter that
        // is given but not seen must never become the widest possible aim.
        for ill_typed in [
            json!({"handle": "2"}),
            json!({"handle": 2.0}),
            json!({"handle": -1}),
            json!({"handle": null}),
            json!({"handle": [2]}),
            json!({"handel": 2}),
            json!("not-an-object"),
            json!(7),
        ] {
            assert!(
                aim(Some(&ill_typed)).is_err(),
                "{ill_typed} was read as naming nothing"
            );
        }

        let aimed = aim(Some(&json!({"handle": 2, "request": 7}))).expect("well typed");
        assert_eq!(aimed.handle, Some(2));
        assert_eq!(aimed.request, Some(json!(7)));

        // No parameters at all still means "whatever is running", unchanged.
        for unaimed in [aim(None), aim(Some(&Value::Null)), aim(Some(&json!({})))] {
            let unaimed = unaimed.expect("no parameters is not a parameter of the wrong type");
            assert_eq!(unaimed.handle, None);
            assert_eq!(unaimed.request, None);
        }
    }

    #[test]
    fn an_ill_typed_cancel_is_refused_rather_than_acted_on() {
        let cancel = Cancellation::default();
        cancel.begin(&json!(3), Some(1), "rebuild", Stoppable::Yes);

        let Seen::Cancel(answer) = answer_cancel(
            r#"{"jsonrpc":"2.0","id":9,"method":"cancel","params":{"handle":"2"}}"#,
            &cancel,
        ) else {
            panic!("a cancel was not recognised as one");
        };
        assert_eq!(answer["error"]["code"], json!(INVALID_PARAMS), "{answer}");
        assert!(answer.get("result").is_none(), "{answer}");
        assert!(
            !cancel.stopped(),
            "an ill-typed cancel stopped the rebuild it had not named"
        );

        // The same aim, well typed, does not match and does not stop it either.
        let Seen::Cancel(answer) = answer_cancel(
            r#"{"jsonrpc":"2.0","id":9,"method":"cancel","params":{"handle":2}}"#,
            &cancel,
        ) else {
            panic!("a cancel was not recognised as one");
        };
        assert_eq!(answer["result"]["cancelling"], json!(false), "{answer}");
        assert!(!cancel.stopped());
    }

    #[test]
    fn a_cancel_answer_is_small_however_big_the_id_that_started_the_job() {
        // Queued by the reading thread, which never waits for room, so it must
        // stay proportional to the line that asked for it.
        let cancel = Cancellation::default();
        let huge = json!("i".repeat(256 * 1024));
        cancel.begin(&huge, Some(1), "rebuild", Stoppable::Yes);

        for answer in [cancel.ask(None, Some(2)), cancel.ask(None, None)] {
            assert!(
                render(&answer).len() < 1024,
                "a cancel answer carried {} bytes",
                render(&answer).len()
            );
        }
        assert!(cancel.stopped(), "the cancel named the job and missed it");
    }

    /// A wire with nobody writing, so what is queued stays queued.
    fn unread() -> (Arc<Wire>, Arc<Backlog>, mpsc::Receiver<Outgoing>) {
        let (lines, queued) = mpsc::channel::<Outgoing>();
        let backlog = Arc::new(Backlog::default());
        let wire = Arc::new(Wire {
            lines,
            backlog: Arc::clone(&backlog),
            cancel: Cancellation::default(),
        });
        (wire, backlog, queued)
    }

    #[test]
    fn a_worker_ahead_of_the_client_waits_rather_than_queueing_without_bound() {
        let (wire, backlog, queued) = unread();

        // One answer always goes through, however big.
        wire.answer(&json!("x".repeat(ANSWER_BACKLOG)));
        assert!(*backlog.answers() > ANSWER_BACKLOG);

        let (done, finished) = mpsc::channel::<()>();
        let waiting = Arc::clone(&wire);
        let second = thread::spawn(move || {
            waiting.answer(&json!("the next one"));
            let _ = done.send(());
        });
        assert!(
            finished.recv_timeout(Duration::from_millis(250)).is_err(),
            "a second answer was queued behind one the client has not read a byte of"
        );

        let Ok(Outgoing::Answer { text, counted }) = queued.recv() else {
            panic!("the first answer was not queued");
        };
        assert!(counted, "the worker's answer was not counted");
        backlog.wrote(text.len());

        assert!(
            finished.recv_timeout(Duration::from_secs(5)).is_ok(),
            "the answer never went through once there was room for it"
        );
        assert!(matches!(queued.recv(), Ok(Outgoing::Answer { .. })));
        let _ = second.join();
    }

    #[test]
    fn the_reading_thread_never_waits_for_room() {
        let (wire, backlog, queued) = unread();
        wire.answer(&json!("x".repeat(ANSWER_BACKLOG)));
        let held = *backlog.answers();

        let (done, finished) = mpsc::channel::<()>();
        let reading = Arc::clone(&wire);
        let cancels = thread::spawn(move || {
            for _ in 0..64 {
                reading.answer_now(&json!({"cancelling": false}));
            }
            let _ = done.send(());
        });
        assert!(
            finished.recv_timeout(Duration::from_secs(5)).is_ok(),
            "the reading thread waited for room behind an unread answer"
        );
        let _ = cancels.join();

        assert_eq!(
            *backlog.answers(),
            held,
            "a cancel answer was counted against the backlog"
        );
        let queued: Vec<Outgoing> = std::iter::from_fn(|| queued.try_recv().ok()).collect();
        assert_eq!(queued.len(), 65, "the cancel answers were not all queued");
        let counted = queued
            .iter()
            .filter(|line| matches!(**line, Outgoing::Answer { counted: true, .. }))
            .count();
        assert_eq!(counted, 1, "only the worker's answer is counted");
    }

    #[test]
    fn a_client_that_stops_reading_cannot_wedge_the_daemon() {
        // Asked of the reading thread directly, with the wire as far behind as
        // it can be: `reading` reaches the end of its input while an answer
        // bigger than the whole allowance sits unread. Nobody reads a byte of
        // standard output for the rest of this test.
        let (wire, backlog, queued) = unread();
        wire.answer(&json!({"jsonrpc": "2.0", "id": 2, "result": {
            "bytes": "x".repeat(ANSWER_BACKLOG)}}));
        assert!(*backlog.answers() > ANSWER_BACKLOG);
        let held = *backlog.answers();

        wire.cancel
            .begin(&json!(3), Some(1), "rebuild", Stoppable::Yes);

        // Progress is the one thing on this wire that may be dropped.
        let reported = 3000;
        let kept = (0..reported)
            .filter(|done| {
                wire.progress(&json!({
                    "jsonrpc": "2.0",
                    "method": "progress",
                    "params": {"handle": 1, "done": done, "total": reported},
                }))
            })
            .count();
        assert_eq!(
            kept, PROGRESS_BACKLOG,
            "notifications were kept for a client that was not reading"
        );

        // The commit's own answer waits for room, because the worker is the one
        // thread that may.
        let (done, finished) = mpsc::channel::<()>();
        let committing = Arc::clone(&wire);
        let worker = thread::spawn(move || {
            committing.answer(&json!({"jsonrpc": "2.0", "id": 3, "result": {"method": "rebuild"}}));
            let _ = done.send(());
        });

        // The reading thread does not: it answers the cancel where it stands
        // and accepts the megabyte behind it.
        let requests = format!(
            "{}\n{}\n",
            json!({"jsonrpc": "2.0", "id": 4, "method": "cancel", "params": {"handle": 1}}),
            json!({"jsonrpc": "2.0", "id": 5, "method": "write", "params": {
                "handle": 1, "path": "bulk/0001.bin", "bytes": BASE64.encode(vec![7_u8; 1 << 20])}}),
        );
        let (queue, incoming) = mpsc::channel::<Incoming>();
        let reader = Arc::clone(&wire);
        let reading_thread = thread::spawn(move || {
            reading(io::Cursor::new(requests), &reader, &queue, answer_cancel);
        });

        let accepted = incoming
            .recv_timeout(WEDGED)
            .expect("the megabyte behind the cancel was accepted");
        let Incoming::Request(line) = accepted else {
            panic!("standard input ended instead of carrying the request");
        };
        assert!(
            line.contains("\"id\":5"),
            "the wrong line reached the worker"
        );
        reading_thread.join().expect("the reading thread finished");

        assert!(
            wire.cancel.stopped(),
            "the cancel never reached the rebuild"
        );
        assert_eq!(
            *backlog.answers(),
            held,
            "the reading thread's answer was counted against the backlog"
        );

        // The worker's answer, sixty-four notifications, then the cancel answer.
        let written: Vec<Outgoing> = std::iter::from_fn(|| queued.try_recv().ok()).collect();
        assert_eq!(written.len(), 1 + PROGRESS_BACKLOG + 1);
        let Some(Outgoing::Answer { text, counted }) = written.last() else {
            panic!("the cancel was never answered");
        };
        assert!(!counted, "a cancel answer was weighed against the backlog");
        let answer: Value = serde_json::from_str(text).expect("a JSON object");
        assert_eq!(answer["id"], json!(4), "{answer}");
        assert_eq!(answer["result"]["cancelling"], json!(true), "{answer}");

        // And the commit is answered as soon as the client reads what it was
        // holding: waiting for room is backpressure, not a deadlock.
        let Some(Outgoing::Answer { text, .. }) = written.first() else {
            panic!("the answer the client was not reading was not queued");
        };
        backlog.wrote(text.len());
        assert!(
            finished.recv_timeout(WEDGED).is_ok(),
            "the commit was never answered once there was room for it"
        );
        worker.join().expect("the worker finished");
    }
}
