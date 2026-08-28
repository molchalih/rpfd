//! `serve --stdio`: a long-lived process with warm state. R6.5, DR-002.
//!
//! Framing is one JSON object per line. Writes are buffered until `commit`,
//! which decides once for every pending edit rather than once per edit. An
//! archive is open in one session at a time, claimed by device and inode as
//! well as by path: DR-009.
//!
//! **Three threads, and each one blocks on exactly one thing.** Standard input
//! is read on its own thread so a `cancel` arrives while there is still
//! something to cancel; standard output is written on a third, because a pipe
//! blocks for as long as the far end declines to read it. The worker between
//! them handles one request at a time and waits when the client is more than
//! [`ANSWER_BACKLOG`] behind. The reading thread never waits — a reading thread
//! that waits is the deadlock the three threads exist to avoid. DR-008.

use std::{
    collections::BTreeMap,
    fs,
    io::{self, BufRead, Write},
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
use rpf_core::{Archive, EntryKind, Flow, Step, Watch};
use serde_json::{Value, json};

use crate::{commands, exit::Failure, install};

/// JSON-RPC's own error codes, for a request that did not follow the protocol.
///
/// Negative is the protocol's numbering and positive is the exit code the same
/// failure would produce on the command line. R6.3, DR-008.
const INVALID_REQUEST: i64 = -32600;
/// No such method.
const METHOD_NOT_FOUND: i64 = -32601;
/// A parameter is missing, or is not of the type the method takes.
const INVALID_PARAMS: i64 = -32602;
/// The line was not JSON.
const PARSE_ERROR: i64 = -32700;

/// How many progress notifications may be waiting to be written before further
/// ones are dropped. It is the only thing on this wire that may be dropped, and
/// DR-008 says why.
const PROGRESS_BACKLOG: usize = 64;

/// How many bytes of answers may be queued and unwritten before the worker
/// waits for the client to catch up.
///
/// Unbounded, with nothing drained and one 20 MB entry read repeatedly: 24
/// answers reached 369 MB of resident memory and 96 reached 1,393 MB. With this
/// bound, 56 MB at both. One answer always goes through however big it is.
const ANSWER_BACKLOG: usize = 8 * 1024 * 1024;

/// How much of one line is written before the count of what the far end has
/// taken is brought up to date.
///
/// The count moves only once a whole piece has cleared, so the piece size is a
/// floor under what the count can measure: at eight kilobytes a client taking
/// 3,000 bytes a second moved it once every 2.7 seconds.
const WRITE_PIECE: usize = 1024;

/// How long the far end's reading is measured over.
///
/// A window rather than idleness since the last look, so that one pause is
/// absorbed: measured against a client reading at full speed that paused once,
/// a 2.2-second pause truncated a response mid-line ten times out of ten before
/// this was a window. DR-008.
const DRAIN_WINDOW: Duration = Duration::from_secs(5);

/// How many bytes standard output must take in one [`DRAIN_WINDOW`] for the far
/// end to count as still there: four kilobytes a second across it.
///
/// Below it a client cannot be told from one that has gone, and is cut off with
/// exit 7 rather than waited on for ever. DR-008.
const DRAIN_FLOOR: usize = 20 * 1024;

/// Which file an open handle is on, as the operating system names one.
///
/// A resolved path is not a file identity: a hard link, and a firmlinked macOS
/// volume, both give one file two true canonical paths. DR-009.
/// **Each variant exists only on the platforms it is true of**, which is what
/// keeps the two halves honest: a claim taken where files are named cannot be
/// missing an identity, and a platform that cannot name one cannot silently
/// produce a `Named` that means nothing.
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
    /// This platform names files only by their paths.
    #[cfg(not(unix))]
    Unnamed,
}

impl FileId {
    /// What the operating system calls the file behind an open handle.
    ///
    /// The handle is statted on every platform, including one that has no name
    /// to read out of the result: DR-009 says the claim is taken whole or not
    /// taken, and a session that could not stat the file it is holding has not
    /// opened it. What differs by platform is only what the metadata says.
    ///
    /// # Errors
    ///
    /// [`Failure::Io`] if the open handle cannot be statted.
    fn of(file: &fs::File, path: &Path) -> crate::exit::Result<Self> {
        let named = file.metadata().map_err(|source| Failure::Io {
            path: path.display().to_string(),
            source,
        })?;
        Ok(Self::named_by(&named))
    }

    /// The identity in an open handle's metadata, where the platform puts one
    /// there.
    #[cfg(unix)]
    fn named_by(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self::Named {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    /// The identity in an open handle's metadata: on this platform, none.
    ///
    /// Windows has one — the volume serial and the file index — and reading it
    /// is R10.5, which needs a Windows machine to measure on. Until then
    /// DR-009's claim degrades to path equality here, which its own second
    /// amendment shows is not enough.
    #[cfg(not(unix))]
    const fn named_by(_metadata: &fs::Metadata) -> Self {
        Self::Unnamed
    }

    /// Whether these are one file. Always false where files are unnamed: an
    /// identity that does not exist is not evidence that two paths are one.
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
            #[cfg(not(unix))]
            _ => false,
        }
    }
}

/// One open archive, and whatever has been changed but not committed.
struct Session {
    /// The resolved path: what the session claims, reports back, and rebuilds.
    path: PathBuf,
    /// The file that path led to. Refreshed by every commit: a rebuild replaces
    /// the archive by rename, so the file afterwards is not the file before.
    id: FileId,
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

impl State {
    /// The handle holding an archive, and the name it holds it under.
    ///
    /// Either the path or the file settles it: the file catches a second name
    /// for one archive, the path catches a new file at a name a session holds.
    /// Derived from the open sessions rather than kept beside them, so a claim
    /// is released exactly one way — the session going away (§3).
    /// `id` is absent when the file is not there to be statted, which is the
    /// ordinary case for an archive `pack` is about to create. The path is
    /// still asked, and it is the half that catches a name a session holds.
    fn holder_of(&self, path: &Path, id: Option<FileId>) -> Option<(u64, &Path)> {
        self.sessions
            .iter()
            .find(|(_, session)| session.path == path || id.is_some_and(|id| session.id.is(id)))
            .map(|(handle, session)| (*handle, session.path.as_path()))
    }
}

/// How much of a request's `id` is echoed back to somebody who did not send it.
///
/// A cancel answer and a progress notification echo the `id` of a *different*
/// request, once per line the client writes. Unbounded, against a `commit`
/// whose `id` was 256 KiB: 1.48 MB of standard input grew the daemon 5.67 GB,
/// 3,900 times what was written. A response still echoes its own `id` whole,
/// which costs what the client wrote and no more. DR-008.
const NAME_ECHO: usize = 128;

/// What a cancel answer or a progress notification may echo of a job's `id`.
///
/// The whole `id` when it is small enough to be quoted back on every line, and
/// its size when it is not. [`NAME_ECHO`].
fn name_of(request: &Value) -> Value {
    let rendered = render(request);
    if rendered.len() <= NAME_ECHO {
        return request.clone();
    }
    json!(format!("<an id of {} bytes>", rendered.len()))
}

/// The one long operation that can be running, named by the `id` of the request
/// that started it — the one name a client has before the answer comes back.
struct Job {
    /// What a cancel is matched against: the whole `id`, whatever its size.
    request: Value,
    /// What an answer echoes back. [`NAME_ECHO`].
    name: Value,
    /// The session it runs against, or `None` for the one operation that has
    /// none: `pack` builds an archive from a tree and is named by its output
    /// path rather than by a handle. DR-014.
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
///
/// A reason rather than a bare `false`: the two cases that cannot be stopped
/// cannot be stopped for different reasons.
enum Stoppable {
    /// It can be. A cancel naming it marks it, and the watcher sees that
    /// between entries.
    Yes,
    /// It cannot, and this is why.
    No(&'static str),
}

/// The commit is still choosing between patching in place and rebuilding.
const DECIDING: &str = "the commit is still working out whether every edit fits where it is, which reads and \
     compresses them and stops at nothing";

/// A patch in place is under way.
const PATCHING: &str =
    "a patch in place writes the bytes of one edit; there is no part-way to stop at";

/// What a `cancel` acts on: at most one operation, and only the one it names.
///
/// One lock rather than a flag per question, so that reading what is running
/// and marking it cancelled cannot be separated. DR-008.
#[derive(Default)]
struct Cancellation {
    job: Mutex<Option<Job>>,
}

impl Cancellation {
    /// The running job. A poisoned lock is recovered rather than reported:
    /// what it guards is still readable.
    fn job(&self) -> MutexGuard<'_, Option<Job>> {
        self.job.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Registers the operation a `cancel` may now name.
    fn begin(
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
    fn stopped(&self) -> bool {
        self.job().as_ref().is_some_and(|job| job.cancelled)
    }

    /// Forgets it, so that a cancel arriving afterwards finds nothing running
    /// and is answered rather than stored against whatever runs next.
    fn finish(&self) {
        *self.job() = None;
    }

    /// Answers a `cancel`, and acts on it when it names what is running.
    ///
    /// Reading what is running and marking it cancelled happen under one lock,
    /// so the operation told to stop is the operation that was named.
    fn ask(&self, request: Option<&Value>, handle: Option<u64>) -> Value {
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
    /// Set when standard input has ended, so that a worker waiting for the
    /// client to catch up can tell a client that is still there from one the
    /// daemon is now only waiting on.
    ending: AtomicBool,
    /// Bytes standard output has taken. The measure both waits use for whether
    /// the far end is reading slowly or not at all.
    taken: AtomicUsize,
    /// Bytes of answers queued by the worker and not yet written.
    answers: Mutex<usize>,
    /// Signalled when an answer has been written and there is room for another.
    room: Condvar,
}

impl Backlog {
    /// Bytes of answers queued and not yet written. A poisoned lock is
    /// recovered rather than reported: what it guards is still readable.
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
    /// A response, or the answer to a cancel. Never dropped.
    ///
    /// `counted` says whether it was weighed against [`ANSWER_BACKLOG`], and so
    /// whether writing it gives room back. Only the worker's answers are: the
    /// reading thread must never wait for room.
    Answer { text: String, counted: bool },
    /// Progress. Dropped when the client is behind.
    Progress(String),
}

/// What the reading thread and the worker share.
///
/// Nothing here blocks on the far end of standard output: emitting queues a
/// line and returns, and one thread writes them.
struct Wire {
    lines: mpsc::Sender<Outgoing>,
    backlog: Arc<Backlog>,
    cancel: Cancellation,
}

impl Wire {
    /// Queues one response, waiting first while the client is too far behind.
    ///
    /// Only the worker calls this, and it is the only thread that may wait
    /// here. While it waits the reading thread goes on reading and cancels go
    /// on being answered. DR-008.
    fn answer(&self, value: &Value) {
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

    /// Queues one answer without waiting for room: the reading thread's.
    ///
    /// A reading thread that blocks cannot be told anything, the cancel
    /// included. Uncounted rather than unbounded — [`NAME_ECHO`] is what keeps
    /// what it queues proportional to the line that asked for it.
    fn answer_now(&self, value: &Value) {
        let _ = self.lines.send(Outgoing::Answer {
            text: render(value),
            counted: false,
        });
    }

    /// Waits until there is room for one more answer of `len` bytes.
    ///
    /// One answer always fits when nothing is queued, however big it is. The
    /// wait is unbounded while standard input is open — the pipe the client is
    /// not draining is its own — and bounded by [`DRAIN_FLOOR`] once it has
    /// ended.
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
    fn gone(&self) -> bool {
        self.backlog.broken.load(Ordering::SeqCst)
    }
}

/// Renders one object, or something that says it could not be rendered.
fn render(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| {
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":1,"message":"unrenderable"}}"#.to_owned()
    })
}

/// Writes queued lines, flushing each.
///
/// On its own thread and owning standard output outright: this is the only call
/// in the daemon that can block for as long as a client declines to read.
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
        // Whether or not it reached the far end: a worker waiting for room a
        // dropped line still held would wait for ever.
        if counted {
            backlog.wrote(text.len());
        }
    }
    let _ = out.flush();
}

/// Writes one line and its newline, a piece at a time, and says whether it got
/// there.
///
/// In pieces, each flushed, so that what the far end has taken is known while a
/// long line is still being written. [`WRITE_PIECE`].
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

/// Reports progress as notifications, and stops when a cancel has arrived or
/// when there is nobody left to report to.
struct Notifying<'a> {
    wire: &'a Wire,
    /// The session being reported on, or `None` for a `pack`, which has none.
    handle: Option<u64>,
    /// What the notification echoes of the request that started the write.
    /// [`NAME_ECHO`].
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
enum Stopped {
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
        // Recorded rather than folded into a cancel: the caller asked for one
        // of these and not the other.
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

impl Notifying<'_> {
    /// Why the write stopped, in the terms §10 makes the contract.
    fn explain(&self, failure: Failure) -> Failure {
        stopped_as(self.stopped, failure)
    }
}

/// Translates a stopped write into the failure that actually happened.
///
/// The library has one variant for "the watcher said stop" and this daemon
/// stops for two unrelated reasons, only one of which the caller asked for.
fn stopped_as(stopped: Option<Stopped>, failure: Failure) -> Failure {
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
    /// requests and says nothing exits 0 having failed.
    Ended(Failure),
}

/// What the reading thread made of a line.
enum Seen {
    /// A `cancel`, acted on or refused, with the object to write back.
    Cancel(Value),
    /// A `cancel` sent as a notification: acted on where its parameters allowed
    /// it, and the specification forbids answering it either way.
    CancelNotification,
    /// Anything else. It goes to the worker, in order.
    Request,
}

/// Reads requests until standard input ends.
///
/// # Errors
///
/// [`Failure::Io`] if standard input or standard output failed part-way, which
/// is what makes the exit code say so.
pub fn run() -> crate::exit::Result<()> {
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

    let reading = Arc::clone(&wire);
    let reader = thread::spawn(move || {
        reading_stdin(&reading, &queue);
        // Every way out of that loop means the same thing: no more requests
        // are coming.
        reading.backlog.ending.store(true, Ordering::SeqCst);
        reading.backlog.room.notify_all();
    });

    let mut state = State::default();
    let mut fault = None;
    for message in requests {
        match message {
            Incoming::Request(line) => {
                if let Some(response) = respond(&mut state, &line, &wire) {
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
        // So that the process cannot outlive a line it is half way through
        // writing.
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

/// Waits for the writing thread to reach the end of its queue, for as long as
/// the far end keeps up with [`DRAIN_FLOOR`].
///
/// Returns `true` when the queue is empty and every line in it was written
/// whole. A client that sent a request before closing standard input has not
/// thereby given up the answer to it. DR-008.
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
fn reading_stdin(wire: &Wire, queue: &mpsc::Sender<Incoming>) {
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
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
        // thing it would have cancelled has finished.
        match answer_cancel(&line, &wire.cancel) {
            Seen::Cancel(answer) => {
                wire.answer_now(&answer);
                continue;
            }
            Seen::CancelNotification => continue,
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

/// What a `cancel` names.
///
/// Both optional, and `None` for either means "whichever one is running". A
/// parameter that was *given* must never end up here as `None`: that is the
/// difference between stopping nothing and stopping somebody else's commit.
struct Aim {
    request: Option<Value>,
    handle: Option<u64>,
}

/// Reads what a `cancel` names, or says why its parameters do not say.
///
/// This method is answered ahead of `dispatch`, so it validates for itself to
/// the standard every other method is held to. An unknown key is refused too,
/// which no other method does: here every parameter is optional and the default
/// is the destructive one, so a misspelled key is silently the widest possible
/// aim. DR-008.
fn aim(params: Option<&Value>) -> std::result::Result<Aim, String> {
    let unaimed = Aim {
        request: None,
        handle: None,
    };
    let given = match params {
        // No parameters at all still means "whatever is running", unchanged.
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
///
/// `cancelling` is false when nothing was running, when the cancel names
/// something else, and when what is running cannot be stopped — each with the
/// reason. Parameters that cannot be read are refused rather than acted on.
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
        (None, _) => Seen::CancelNotification,
        (Some(id), Ok(result)) => {
            Seen::Cancel(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
        }
        (Some(id), Err(message)) => Seen::Cancel(error_of(id, INVALID_PARAMS, &message)),
    }
}

/// Turns one request line into one response object, or into none.
fn respond(state: &mut State, line: &str, wire: &Wire) -> Option<Value> {
    let Ok(request) = serde_json::from_str::<Value>(line) else {
        return Some(error_of(&Value::Null, PARSE_ERROR, "not JSON"));
    };
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return Some(error_of(&Value::Null, INVALID_REQUEST, "no method"));
    };
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
    let id = request.get("id").cloned();
    let named = id.clone().unwrap_or(Value::Null);
    let outcome = dispatch(state, method, &params, wire, &named);

    // A request with no id is a notification, which the specification forbids
    // answering.
    let id = id?;
    Some(match outcome {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(rejected) => error_of(&id, rejected.code(), &rejected.message()),
    })
}

/// A JSON-RPC error object.
fn error_of(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Why a call produced no result.
enum Rejected {
    /// The request did not follow the protocol. JSON-RPC's own codes.
    Protocol { code: i64, message: String },
    /// The work was attempted and did not succeed. The code is the one the
    /// process would exit with. R6.3, DR-010.
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

    /// What to say about it.
    fn message(&self) -> String {
        match *self {
            Self::Protocol { ref message, .. } => message.clone(),
            Self::Failed(ref failure) => crate::separator::render(failure),
        }
    }
}

impl From<Failure> for Rejected {
    fn from(failure: Failure) -> Self {
        Self::Failed(failure)
    }
}

/// So that a container failure is classified once rather than at each call
/// site.
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
    Rejected::Protocol {
        code: INVALID_PARAMS,
        message,
    }
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
        "pending" => pending(state, params),
        "discard" => discard(state, params),
        "info" => info(state, params),
        "verify" => verify(state, params, wire, request),
        "extract" => extract(state, params, wire, request),
        "pack" => pack(state, params, wire, request),
        "commit" => commit(state, params, wire, request),
        "keys.extract" => keys_extract(params),
        "keys.cache" => keys_cache(params),
        "keys.invalidate" => keys_invalidate(params),
        other => Err(Rejected::Protocol {
            code: METHOD_NOT_FOUND,
            message: format!("no method {other:?}"),
        }),
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

/// Whether the caller wants progress notifications at all, which it does
/// unless it says otherwise: a 3000-entry archive is 3000 lines, and a caller
/// with nowhere to put them has to be able to decline.
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

/// A handle that was never opened, or has been closed.
///
/// A well-formed request this daemon declines, so a refusal and not `-32602`.
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

/// The archive a request names, as the one path a session reports and rebuilds.
///
/// Two names for one *file* do not resolve alike, which is what [`FileId`] is
/// for. A path that cannot be resolved has not been opened either, so it is an
/// ordinary open failure. DR-009.
///
/// With one exception, which is the command line's too: a path that runs past a
/// file is an in-archive path spelled as a filesystem one, and that is a
/// request rather than a disk. `commands::opening` decides it for both
/// frontends, so the two cannot answer one mistake with two numbers. DR-010.
fn resolve(path: &Path) -> crate::exit::Result<PathBuf> {
    fs::canonicalize(path).map_err(|source| commands::opening(path, source))
}

/// `open` — claim an archive, parse it, and keep it warm.
///
/// The claim is on the file as well as on the path, and the second `open` of
/// one archive is refused. DR-009.
fn open(state: &mut State, params: &Value) -> Answered {
    let asked = PathBuf::from(string(params, "path")?);
    let path = resolve(&asked)?;
    let (file, archive) = commands::open(&path)?;
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
            pending: BTreeMap::new(),
        },
    );

    Ok(json!({
        // The resolved path, not the one asked for: it is what the session
        // claimed, and what a refusal will name.
        "handle": handle,
        "path": reported,
        "entries": entries,
        "len": len,
    }))
}

/// That an archive is held, and by which handle.
///
/// The path asked for and the path the holder claimed can differ — two names
/// for one file — so both are named. One sentence for both of the refusals that
/// need it, so a client is told the same thing however it ran into the claim.
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
///
/// Uncommitted edits are discarded, and the response says how many, so that
/// losing them is never silent. A client that leaks handles locks itself out of
/// its own archives for the life of the daemon. DR-009.
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
fn list(state: &mut State, params: &Value) -> Answered {
    let inside = inside_of(params);
    let recursive = flag(params, "recursive")?;
    let session = session(state, params)?;

    let rows = rpf_core::Listed::at(&mut session.file, &session.archive, &inside, recursive)?;
    Ok(Value::Array(
        rows.iter().map(commands::listing_row).collect(),
    ))
}

/// `read` — one entry's bytes, as base64.
///
/// A pending write is returned in preference to what is on disk: an editor that
/// wrote a buffer and read it back should see what it wrote.
fn read(state: &mut State, params: &Value) -> Answered {
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
        }
        .into());
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
fn write(state: &mut State, params: &Value) -> Answered {
    let inside = string(params, "path")?;
    let encoded = string(params, "bytes")?;
    let bytes = BASE64
        .decode(encoded.as_bytes())
        .map_err(|_| invalid_params("\"bytes\" is not base64".to_owned()))?;
    let session = session(state, params)?;

    // Resolved now rather than at commit, while the caller can still act on a
    // refusal.
    let (holder, index) = session.archive.locate(&mut session.file, &inside)?;
    if holder.entry(index)?.is_directory() {
        return Err(Failure::Refused {
            reason: format!("{inside} is a directory"),
        }
        .into());
    }
    // R6.6: a resource entry takes an RSC7 payload and nothing else.
    if matches!(holder.entry(index)?.kind, EntryKind::Resource { .. })
        && bytes.get(0..4) != Some(&rpf_core::format::resource::MAGIC_RSC7)
    {
        return Err(Failure::Refused {
            reason: format!("{inside} is a resource entry; its payload must begin with RSC7"),
        }
        .into());
    }

    let len = bytes.len();
    session.pending.insert(inside.clone(), bytes);
    Ok(json!({ "path": inside, "len": len, "pending": session.pending.len() }))
}

/// `info` — the header, and what the entries add up to.
///
/// `path` means what it means to `list`: a path inside the archive the handle
/// holds. Empty, or absent, is the archive itself; anything else names a nested
/// archive. R6.11.
fn info(state: &mut State, params: &Value) -> Answered {
    let inside = inside_of(params);
    let session = session(state, params)?;
    let summary = rpf_core::Summary::of(&mut session.file, &session.archive, &inside)?;
    Ok(json!({
        "path": session.path.display().to_string(),
        "inside": inside,
        "len": summary.len,
        "encryption": commands::encryption_name(summary.encryption),
        "entries": summary.entries,
        "directories": summary.directories,
        "binary_files": summary.binary_files,
        "resource_files": summary.resource_files,
        "nested_archives": summary.nested_archives,
        "unreferenced_bytes": summary.unreferenced_bytes,
    }))
}

/// `verify` — read every entry back and check it against what the archive says.
///
/// Reading every entry of a 2.7 GB archive is unbounded work in the same way a
/// rebuild is, so it reports progress and takes a `cancel` while it runs, on
/// the same seam and with the same names. DR-008.
///
/// An entry that does not read back is reported in `problems` rather than as an
/// error: the call did what it was asked, and what it found is its answer. The
/// command line still exits 4, because a process has one bit to say it with.
///
/// `against` names an extracted tree of this archive on the **daemon's own**
/// filesystem — `rpf verify --against`'s parameter, under the vocabulary every
/// other path on this wire already uses (DR-014). Its manifest records what
/// each entry's contents should be, which is the only thing that can see a
/// **stored** entry's bytes change. Without it `contents_checked` is zero and
/// `against` is `null`, so a client cannot read the zero as a result. DR-023,
/// DR-025.
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
        .map(|problem| json!({ "path": problem.path, "reason": problem.error.to_string() }))
        .collect();
    Ok(commands::verify_report(&session.path, &checked, &problems))
}

/// `extract` — write every entry of an open archive to a tree.
///
/// `into` is a directory on the **daemon's own** filesystem, which is the one
/// thing a path on this wire has ever meant: `open` takes one, and a client
/// that cannot name a file the daemon can reach could not open an archive
/// either. DR-014.
///
/// Unbounded work, so it reports progress and takes a `cancel` on the same seam
/// a rebuild does. A cancelled extraction leaves the files it had already
/// written where they are — a tree is not replaced by rename the way an archive
/// is, and DR-014 says so rather than leaving it to be discovered.
///
/// Two things it refuses, both before anything is written.
///
/// **A session with buffered edits.** `read` prefers a pending edit to what is
/// on disk; `extract` read past them and reported success, so `write`,
/// `extract`, `pack` produced an archive without the edit and said nothing. It
/// is a refusal rather than a merge because a tree means one thing in both
/// frontends — the archive as it is on disk — and `rpf extract` cannot produce
/// anything else. A merged tree would be an archive-shaped thing no archive
/// holds, and packing it would leave one edit in two places.
///
/// **A path an open session holds.** DR-009's corruption through a third door,
/// refused with DR-009's own test and `pack`'s own sentence. It is asked once
/// up front, over every path the extraction will write, because a refusal found
/// part-way would leave the part already written.
fn extract(state: &mut State, params: &Value, wire: &Wire, request: &Value) -> Answered {
    let handle = handle_of(params)?;
    let into = PathBuf::from(string(params, "into")?);
    let wanted = wants_progress(params)?;
    let name = name_of(request);

    // Immutably, and a handle of its own: the claim check below reads every
    // session while this one is being extracted, which a `&mut Session` would
    // forbid. `try_clone` also leaves the session's own handle where it was.
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

/// Why a tree cannot be extracted while edits are still buffered.
///
/// It names them, because committing or discarding them is what the caller has
/// to do, and a refusal that does not say which is one the client has to guess
/// at.
fn extracting_with_edits(pending: &BTreeMap<String, Vec<u8>>) -> Failure {
    let paths: Vec<&str> = pending.keys().map(String::as_str).collect();
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
///
/// `pack`'s sentence, with the operation's own name in it: it is the same
/// corruption reached another way, and a client should recognise it as one
/// thing.
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
/// The one method with no handle: it makes an archive rather than working on
/// one that is open, so both of its paths are on the daemon's filesystem and
/// its output is named by path. DR-014.
///
/// That is a second way into DR-009's corruption, so it is refused the same
/// way: an archive an open session holds cannot be packed over, because every
/// offset that session holds is true only of the bytes it parsed.
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

    let mut watch = Notifying {
        wire,
        handle: None,
        name: &name,
        wanted,
        skipped: 0,
        stopped: None,
    };
    wire.cancel.begin(request, None, "pack", Stoppable::Yes);
    let outcome = commands::pack_from(&from, &archive, force, &mut watch);
    wire.cancel.finish();
    let report = outcome.map_err(|failure| watch.explain(failure))?;

    Ok(json!({
        "archive": archive.display().to_string(),
        "entries": report.entry_count,
        "len": report.len,
    }))
}

/// The path a write will land on, resolved as far as it exists.
///
/// [`resolve`] needs the file to be there and `pack` usually writes one that is
/// not, so the directory is resolved and the name joined back on. That is the
/// path a session would have claimed had it opened the file, which is what
/// makes the two comparable.
///
/// # Errors
///
/// [`Failure::Io`] when the directory does not resolve, and
/// [`Failure::Refused`] for a path that names no file at all.
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
///
/// `None` covers both "nothing is there" and "it could not be statted": either
/// way there is no identity to match a session's against, and the path is asked
/// on its own. DR-009.
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

/// An optional path parameter, on the daemon's own filesystem. DR-014.
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
/// One of the methods with no handle: it works on an executable and a cache
/// rather than on an open archive, so there is nothing to name it by. Both
/// `executable` and the optional `cache` are paths on the **daemon's own**
/// filesystem, which is what every path on this wire that is not an in-archive
/// path already means. DR-014, DR-020.
///
/// It reports offsets, lengths, the source executable's digest and where the
/// material was cached. **Never a key**: DR-006, and `commands::keys_report`
/// is the one place the object is built, so the command line and this method
/// cannot come to say different things.
///
/// It takes no `progress` and no `cancel`. The work is one pass over one file
/// — about a second for a 47 MB executable at `--release`, DR-017 — which is
/// bounded the way `read` of one large entry is, and `rpf_core::keys` takes no
/// watcher to report on it with.
fn keys_extract(params: &Value) -> Answered {
    let executable = PathBuf::from(string(params, "executable")?);
    let cache = optional_path(params, "cache")?;
    let found = commands::find_keys(&executable, cache.as_deref())?;
    Ok(commands::keys_report(&found))
}

/// `keys.cache` — where extracted material is kept, and how much is there.
fn keys_cache(params: &Value) -> Answered {
    let cache = optional_path(params, "cache")?;
    let state = commands::cache_state(cache.as_deref())?;
    Ok(commands::cache_report(&state))
}

/// `keys.invalidate` — remove every cached entry.
fn keys_invalidate(params: &Value) -> Answered {
    let cache = optional_path(params, "cache")?;
    let state = commands::invalidate_keys(cache.as_deref())?;
    Ok(commands::invalidated_report(&state))
}

/// `pending` — what has been written but not committed.
fn pending(state: &mut State, params: &Value) -> Answered {
    let session = session(state, params)?;
    let paths: Vec<&String> = session.pending.keys().collect();
    Ok(json!({ "paths": paths }))
}

/// `discard` — drop the buffered edits.
fn discard(state: &mut State, params: &Value) -> Answered {
    let session = session(state, params)?;
    let dropped = session.pending.len();
    session.pending.clear();
    Ok(json!({ "discarded": dropped }))
}

/// Which of the two ways a commit will go, decided without writing anything.
enum Decision {
    /// Every edit fits where its entry already sits, and the archive can be
    /// opened for writing.
    Patch {
        patches: rpf_core::Patches,
        file: fs::File,
    },
    /// One of them does not fit, or the caller asked for a rebuild, or the
    /// archive cannot be opened for writing at all.
    Rebuild,
}

impl Decision {
    /// What the response will report, and what a `cancel` will be told is
    /// running.
    const fn method(&self) -> &'static str {
        match *self {
            Self::Patch { .. } => "patch",
            Self::Rebuild => "rebuild",
        }
    }

    /// Whether it can be stopped part-way. A patch cannot: it writes the bytes
    /// of one edit, and there is no point between entries to stop at.
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

/// Decides between patching in place and rebuilding, and writes nothing.
///
/// Taken before the operation is registered as the one a `cancel` can name,
/// because only one of the two can be stopped. DR-008.
fn decide(session: &mut Session, asked_to_rebuild: bool) -> crate::exit::Result<Decision> {
    if asked_to_rebuild {
        return Ok(Decision::Rebuild);
    }
    let plan = rpf_core::plan(&mut session.file, &session.archive, &session.pending)?;
    let rpf_core::Plan::Fits(patches) = plan else {
        return Ok(Decision::Rebuild);
    };
    // A second handle, because the warm one is open for reading: a session that
    // only lists an archive must not need write permission on it. An archive
    // that cannot be opened for writing can still be rebuilt beside itself.
    let Ok(file) = fs::OpenOptions::new().write(true).open(&session.path) else {
        return Ok(Decision::Rebuild);
    };
    Ok(Decision::Patch { patches, file })
}

/// `commit` — apply every buffered edit at once.
///
/// Patches in place when every edit fits where its entry already sits, and
/// rebuilds when any one of them does not. The choice is made for the set, not
/// per edit. R4.14.
///
/// `rebuild: true` asks for the rebuild regardless: the two are not equivalent
/// in durability, since a rebuild is atomic and a patch is not, and the response
/// reports which one ran. `progress: false` declines the notifications.
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
    let session = session(state, params)?;

    if session.pending.is_empty() {
        return Ok(json!({ "committed": 0, "unchanged": true }));
    }
    // Before the dry run, not after: what a commit would do here is refuse, and
    // a dry run reports what the real call would do.
    if !force {
        match install::detect(&session.path) {
            Some(install::Detected::Installation(root)) => {
                return Err(Failure::GameInstall { root }.into());
            }
            Some(install::Detected::Unexaminable(directory)) => {
                return Err(Failure::UncertainInstall { directory }.into());
            }
            None => {}
        }
    }
    if dry_run {
        return would_commit(session, asked_to_rebuild);
    }

    let committed = session.pending.len();

    // Registered before the decision as well, because deciding reads and
    // compresses every buffered edit, and forgotten whatever the outcome.
    wire.cancel.begin(
        asked.request,
        Some(asked.handle),
        "commit",
        Stoppable::No(DECIDING),
    );
    let outcome = commit_now(session, wire, &asked);
    wire.cancel.finish();
    let method = outcome?;

    // Re-opened, so the warm state describes what is now on disk. The claim is
    // re-taken with it: a rebuild replaces the archive by rename, and a claim
    // kept on the old inode would claim a file nobody has. DR-009.
    let path = session.path.clone();
    let (file, archive) = commands::open(&path)?;
    let entries = archive.entries().len();
    let len = archive.len_bytes();
    session.id = FileId::of(&file, &path)?;
    session.file = file;
    session.archive = archive;
    session.pending.clear();

    Ok(json!({
        "committed": committed,
        "method": method,
        "entries": entries,
        "len": len,
    }))
}

/// Decides, registers what it decided so a `cancel` can name it, and does it.
///
/// Separate from [`commit`] so that the job is forgotten on the way out whether
/// this succeeded or not.
fn commit_now(
    session: &mut Session,
    wire: &Wire,
    asked: &Asked<'_>,
) -> crate::exit::Result<&'static str> {
    let decision = decide(session, asked.rebuild)?;
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

/// Reports what a commit would do, without doing any of it. R6.7.
///
/// The decision is taken the same way the real commit takes it, so this is a
/// prediction rather than an estimate. The buffered edits are left where they
/// are.
fn would_commit(session: &mut Session, asked_to_rebuild: bool) -> Answered {
    if asked_to_rebuild {
        return Ok(json!({ "committed": 0, "dry_run": true, "method": "rebuild" }));
    }

    match rpf_core::plan(&mut session.file, &session.archive, &session.pending)? {
        rpf_core::Plan::Fits(patches) => {
            let planned: Vec<Value> = patches
                .planned()
                .map(|entry| {
                    json!({
                        "path": entry.path,
                        "at": entry.at,
                        "len": entry.len,
                        "allocation": entry.allocation,
                    })
                })
                .collect();
            Ok(json!({
                "committed": 0,
                "dry_run": true,
                "method": "patch",
                "planned": planned,
            }))
        }
        rpf_core::Plan::DoesNotFit(rejected) => {
            let rejected: Vec<Value> = rejected
                .iter()
                .map(|entry| {
                    json!({
                        "path": entry.path,
                        "needed": entry.needed,
                        "allocation": entry.allocation,
                    })
                })
                .collect();
            Ok(json!({
                "committed": 0,
                "dry_run": true,
                "method": "rebuild",
                "rejected": rejected,
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
    // Intermediates go where the rebuilt archive is going, which is the answer
    // for a daemon precisely because there is nobody to ask for another one.
    // DR-022.
    let outcome = rpf_core::replace_many(
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
    use super::*;
    use crate::exit::Code;

    /// A cancelled write, as the library reports one.
    fn cancelled() -> Failure {
        Failure::Container(rpf_core::Error::Cancelled { done: 1, total: 24 })
    }

    #[test]
    fn a_broken_output_pipe_is_not_reported_as_a_cancellation() {
        // Both arrive from the library as Error::Cancelled, because both are
        // Flow::Stop, and a caller acts on them differently. §10, DR-008.
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

    /// [`Notifying::explain`] where the daemon actually calls it.
    ///
    /// The test above is the same conversion as a pure function, and passes
    /// with nothing calling it. This drives the function the daemon does,
    /// against a wire whose far end is already gone.
    #[test]
    fn a_rebuild_that_loses_its_output_says_so_rather_than_claiming_a_cancel() {
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
            |_| Ok(std::io::Cursor::new(b"contents".to_vec())),
            &mut rpf_core::Unwatched,
        )
        .expect("builds");
        drop(out);

        let (file, archive) = commands::open(&path).expect("opens");
        let id = FileId::of(&file, &path).expect("named");
        let mut session = Session {
            path,
            id,
            file,
            archive,
            pending: BTreeMap::from([("a.txt".to_owned(), b"replaced".to_vec())]),
        };

        // A wire whose standard output has already stopped accepting anything,
        // which is the one condition that stops a rebuild without a cancel.
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
        // `pack` is the one operation with no session, so a cancel that names a
        // handle names something else by construction. Naming nothing still
        // means "whatever is running", which is what DR-008 says it means, and
        // the answer reports no handle rather than inventing one. DR-014.
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
        // DR-008: a cancelled patch is not possible, and the client is told so
        // rather than told a commit is stopping when it is not.
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
        // Deciding reads and compresses every buffered edit, so neither
        // "nothing is running" nor "cancelling" is the right answer during it.
        let cancel = Cancellation::default();
        cancel.begin(&json!(7), Some(1), "commit", Stoppable::No(DECIDING));

        let answer = cancel.ask(None, None);
        assert_eq!(answer["cancelling"], json!(false), "{answer}");
        assert_eq!(answer["running"], json!("commit"), "{answer}");
        assert_eq!(answer["reason"], json!(DECIDING), "{answer}");
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
        // A cancel with nothing running used to be stored, and killed whatever
        // committed next. DR-008.
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
            // A key spelled wrong is given too.
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
        // A cancel answer is queued by the reading thread, which never waits
        // for room, so it must stay proportional to the line that asked for
        // it: echoing the job's whole `request` made 1.48 MB of standard input
        // grow the daemon 5.67 GB.
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

        // Writing the first is what gives the room back.
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
        // A reading thread that waits stops reading standard input, and the
        // cancel it was answering is what cannot then arrive. DR-008.
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
}
