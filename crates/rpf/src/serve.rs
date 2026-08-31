//! `serve --stdio`: a long-lived process with warm state. R6.5, DR-002.
//!
//! Framing is one JSON object per line. Writes are buffered until `commit`,
//! which decides once for every pending edit rather than once per edit. An
//! archive is open in one session at a time, claimed by the name the operating
//! system gives the open file — where it gives one — as well as by path:
//! DR-009, DR-037.
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
use rpf_core::{
    Archive, Change, Changes, Dictionary, Encoding, Flow, Step, Unwatched, View, Watch,
};
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
///
/// **Whether a file can be named is not settled in the same place everywhere.**
/// On Unix the platform settles it and the answer is always yes. On Windows the
/// volume and the transport settle it, at runtime: NTFS answers with a volume
/// serial and a file index, and a redirector answers with a zero volume serial,
/// which names nothing. So `Unnamed` is reachable there, and what keeps
/// the two halves honest is not the `#[cfg]` but the thing the `#[cfg]` was
/// standing in for — **an unnamed file is equal to nothing, itself included**,
/// so an identity that could not be read makes the claim fall back to the path
/// and can never manufacture a match. DR-037.
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
    /// This file is named by nothing but its path — because the platform
    /// names none, or because the volume it is on does not.
    #[cfg(not(unix))]
    Unnamed,
}

impl FileId {
    /// What the operating system calls the file behind an open handle.
    ///
    /// The handle is asked on every platform, including one that has no name to
    /// answer with. What differs by platform is which call is made, what it
    /// answers, and whether not answering is a failure: on Unix an `fstat` that
    /// fails means the handle is broken, and DR-009 says a session that could
    /// not stat the file it is holding has not opened it; on Windows not
    /// answering is a property of the volume rather than of the handle, and it
    /// is `Unnamed` instead. DR-037.
    ///
    /// # Errors
    ///
    /// [`Failure::Io`] where the platform's identity call can fail — on Unix,
    /// if the open handle cannot be statted.
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

    /// The identity behind an open handle: the volume serial number and file
    /// index `GetFileInformationByHandle` gives, where the volume gives them.
    ///
    /// `std::os::windows::fs::MetadataExt` names both and both are behind
    /// `windows_by_handle`, which the stable channel `rust-toolchain.toml` pins
    /// does not have, so the call is made rather than read out of a
    /// [`fs::Metadata`]. `winapi-util` owns it: §11 expects no `unsafe` here and
    /// §14 has a row for the crate. DR-037.
    ///
    /// **Both halves have to be non-zero, and the call failing is not an error
    /// here.** A zero in either half is the volume saying it does not name its
    /// files, and taking it at face value would make every file on that volume
    /// equal to every other — a second `open` refused against a handle holding
    /// something else, and `pack` and `extract` refusing unrelated paths.
    /// Measured: the `\\wsl.localhost` redirector answers with volume serial
    /// zero. A failed call is the same fact arriving as an error instead of as
    /// a zero, so it reads the same way rather than refusing the archive.
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

    /// The identity behind an open handle: on this platform, none. The handle
    /// is statted anyway, because a file that cannot be statted is not held.
    #[cfg(not(any(unix, windows)))]
    fn named_by(file: &fs::File) -> io::Result<Self> {
        file.metadata().map(|_| Self::Unnamed)
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
    /// The file that path led to. Refreshed by every commit: a rebuild replaces
    /// the archive by rename, so the file afterwards is not the file before.
    id: FileId,
    file: fs::File,
    archive: Archive,
    /// What has been changed and not committed: new contents for an entry, and
    /// since DR-026 an entry added, removed or renamed as well. `commit`
    /// decides between patching and rebuilding for the whole set of them.
    pending: Changes,
}

/// Everything the daemon holds between requests.
#[derive(Default)]
struct State {
    sessions: BTreeMap<u64, Session>,
    next_handle: u64,
    /// `--cache-dir`, as this process was started with, and `None` for the
    /// platform's own.
    ///
    /// A process-wide choice rather than a parameter on every method that opens
    /// an archive: DR-041 rejected widening the wire to say what the cache
    /// already knows, and a daemon serves one install at a time. A `keys.*`
    /// request that names a `cache` still overrides it, which is the only place
    /// the wire ever mentioned one.
    cache: Option<PathBuf>,
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
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":1,"message":"unrenderable","data":{"reason":"Internal"}}}"#
            .to_owned()
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
pub fn run(named_cache: Option<&Path>) -> crate::exit::Result<()> {
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

    let mut state = State {
        cache: named_cache.map(Path::to_path_buf),
        ..State::default()
    };
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

    // A request with no id is a notification, which the specification forbids
    // answering.
    let id = id?;
    Some(match outcome {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(rejected) => error_of(&id, &rejected),
    })
}

/// A JSON-RPC error object: a number, a sentence, and the failure's own name.
///
/// `data` is where the protocol puts anything more than a code and a message,
/// and `reason` there is a stable symbol — an `rpf_core::Error` variant's name,
/// or one of the frontend's own. It is on **every** error object this daemon
/// writes, so a client never has to ask whether it is there.
/// [`Rejected::reason`] says why it is there at all.
fn error_of(id: &Value, rejected: &Rejected) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": rejected.code(),
            "message": rejected.message(),
            "data": { "reason": rejected.reason() },
        },
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

    /// The name that goes beside the number.
    ///
    /// A code classifies who has to act and is shared by every refusal there
    /// is, so a client mapping this onto an editor's filesystem — where
    /// `AlreadyExists` is `FileExists` and nothing else is — had only the
    /// rendered sentence to tell them apart, which §10 and R7.6 forbid reading.
    /// DR-030 asked for this; DR-032 decided it. Additive: the number is
    /// unchanged and is still the contract DR-010 states.
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

/// The view a request asks for, which is the entry's own bytes unless it says
/// otherwise.
///
/// `"raw"` is the default because it is what every client sent before this
/// existed, and a wire addition never changes what a request already meant.
/// DR-053, DR-032's rule for an addition.
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

/// A view, with the dictionary this frontend offers with it.
///
/// The command line's [`commands::wanted`] is the same one, because a hash
/// spelled one way here and another way there would be two products (§1).
const fn wanted(view: View) -> rpf_core::view::Wanted<'static> {
    rpf_core::view::Wanted {
        view,
        names: Dictionary::EMPTY,
    }
}

/// What a view answered, in the one spelling `--as` takes.
///
/// [`View::Auto`] is a question and never an answer, so what is reported is
/// whichever of the two forms came back. DR-053.
const fn answered(xml: bool) -> &'static str {
    if xml {
        View::Xml.name()
    } else {
        View::Raw.name()
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

/// The same, for a method that buffers a change.
///
/// An archive this build can read and cannot write back is refused where the
/// caller asks, rather than at the commit that could never have landed. The
/// answer is `rpf-core`'s — this frontend holds no rule about it (§1) — and it
/// is the one `rpf put` gets from the same call, so neither frontend can do
/// what the other cannot.
fn writing_session<'a>(state: &'a mut State, params: &Value) -> Answer<&'a mut Session> {
    let session = session(state, params)?;
    session.archive.writable().map_err(Failure::Container)?;
    Ok(session)
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
///
/// **It doubles as a `stat`, and there is no other method that does.** `path`
/// naming a directory answers its children; naming a nested archive answers
/// what is inside it, because a nested archive is a directory as far as a path
/// is concerned; and naming an ordinary **file** answers exactly one row, for
/// that file, rather than an error. An empty directory answers `[]`.
///
/// So a caller tells "this is a file" from "this directory holds one child" by
/// comparing the row's `path` with the one it asked for: equal means the path
/// named that entry, different means it named the directory the entry sits in.
/// The comparison is exact rather than a heuristic — a child's path is its
/// parent's plus a separator and a name, so it can never equal its parent's —
/// and `[]` is unambiguous, because a file always answers one row. DR-028.
///
/// **A row's `path` is the whole in-archive path, not a name.** `list` of
/// `x64/inner.rpf` answers rows whose `path` is `x64/inner.rpf/art.yft`, so a
/// row addresses `read`, `write` and `list` as it stands, and a client that
/// joined it onto the path it asked for would build
/// `x64/inner.rpf/x64/inner.rpf/art.yft`. The rows are addressed **from the
/// path that was asked for**, in the caller's own spelling of it: components
/// resolve case-insensitively, so a caller that asked for `X64/INNER.RPF` gets
/// rows spelled that way. DR-028.
///
/// **A listing is the archive on disk.** Buffered changes are not in it, and
/// that is the same rule every method but `read` follows — nothing on disk
/// changes until `commit`, and a listing that showed an entry no archive holds
/// would be describing something that does not exist yet. `read` is the one
/// exception, because an editor that wrote a buffer and read it back must see
/// what it wrote. A client that wants to show a buffered addition or removal
/// keeps that view itself, from what it asked for, and `pending` is what it
/// asks the daemon to confirm it against.
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
///
/// **`"as"` says which form of the entry is wanted** — `"raw"`, `"xml"` or
/// `"auto"` — and the answer says which form it got, beside the `"encoding"`
/// the entry holds. A client presenting metadata as XML asks for `"auto"` and
/// reads the answer; it never asks the path what it is, because the scope
/// boundary is self-describing formats and `.ymt` is not one. DR-053.
///
/// The rule that a buffered write is preferred reaches the conversion as well:
/// what a document is converted **from** is the payload this method would
/// answer, so a read and a write of one entry are about the same bytes.
fn read(state: &mut State, params: &Value) -> Answered {
    let inside = string(params, "path")?;
    let view = view_of(params)?;
    let session = session(state, params)?;

    if view != View::Raw && session.pending.contents_at(&inside).is_some() {
        let payload = buffered_payload(session, &inside)?;
        let encoding = Encoding::of(
            payload
                .get(..Encoding::HEAD_LEN)
                .unwrap_or(payload.as_slice()),
        );
        let viewed = rpf_core::view::of(payload, encoding, &inside, wanted(view))?;
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
        // Read out of the source rather than out of a buffer the session kept:
        // what a `write` handed over may be a file on this machine, and the
        // daemon's own writes are `Bytes`, which opens over what it already
        // holds. Encoded **as it is read**, so the answer costs the encoded
        // form and not a copy of the payload beside it — which is what a first
        // cut of this did, and is the wrong direction on a change whose whole
        // subject is peak memory. DR-036.
        let len = buffered.len()?;
        let mut encoder = base64::write::EncoderStringWriter::new(&BASE64);
        io::copy(&mut buffered.open()?, &mut encoder).map_err(|source| Failure::Io {
            path: inside.clone(),
            source,
        })?;
        // A payload nothing asked a question of is not classified: `"raw"` is
        // what this method has always answered and it costs the head read
        // nothing. `"encoding"` is `null` for the same reason a resource's is —
        // it was not read.
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
    let viewed = rpf_core::view::read(&mut session.file, &holder, index, &inside, wanted(view))?;
    Ok(json!({
        "path": inside,
        "len": viewed.bytes.len(),
        "pending": false,
        "as": answered(viewed.xml),
        "encoding": viewed.encoding.map(Encoding::name),
        "bytes": BASE64.encode(&viewed.bytes),
    }))
}

/// The whole of a buffered write's payload.
///
/// Held rather than streamed, because a conversion is a whole document against
/// a whole payload and there is nothing to stream it into. What the daemon
/// buffers is [`rpf_core::Bytes`] — a `write` arrives as base64 and is already
/// in memory — so this is a copy of something held rather than a second read of
/// something large.
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

/// `write` — buffer an edit. Nothing on disk changes until `commit`.
///
/// `create: true` lets it be a path the archive does not hold yet, which is an
/// entry added and therefore a rebuild. Without it a path that is not there is
/// [`rpf_core::Error::NotFound`], which is what a write has always answered:
/// creating an entry a caller merely misspelled is the failure that guards
/// against. DR-026.
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
            // Converted here, against the payload `read` would have answered
            // for this path, and buffered as the payload it becomes. So what
            // the set holds is of the entry's own encoding whatever route it
            // came in by, and `edit::check_encoding` judges it unchanged: a
            // converted write needs no `allow_encoding_change` because there is
            // no encoding change in it, and a document that does not describe
            // the entry is refused here rather than taken as text. DR-053.
            let bytes = if view == View::Raw {
                offered
            } else if session.pending.contents_at(&inside).is_some() {
                let held = buffered_payload(session, &inside)?;
                rpf_core::view::applied(&held, &inside, wanted(view), offered)?
            } else {
                rpf_core::view::apply(
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
            // The archive's own answer is the whole of it only while nothing
            // buffered has moved the entry: a removal or a rename above this
            // path leaves the commit writing to something that will not be
            // there. `bears_on` answers that from the set alone, so the walk of
            // the entry table below is paid for a write that could actually
            // collide and not for the four thousand an editor sends that
            // cannot. DR-032.
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
        // change is resolved instead. Only here: `allows` walks the entry
        // table, and a write to an entry that exists is what an editor sends
        // once per save.
        Err(rpf_core::Error::NotFound { .. }) if create => {
            // And nothing to convert against either: an entry that is not there
            // holds no encoding for a document to adopt. `"auto"` takes the
            // bytes as they are and `"xml"` says why it cannot.
            let bytes = rpf_core::view::applied(&[], &inside, wanted(view), offered)?;
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
/// directory that holds anything is refused. The shape every editor's `delete`
/// already has, and the shape `rpf rm` has for the same reason. DR-026.
///
/// `list` goes on reporting the entry until the commit: a listing is the
/// archive on disk. See [`list`].
fn delete(state: &mut State, params: &Value) -> Answered {
    let inside = string(params, "path")?;
    let recursive = flag(params, "recursive")?;
    buffer(state, params, &inside, Change::Remove { recursive })
}

/// `rename` — buffer a move to another path in the same archive.
///
/// `to` is a whole in-archive path, spelled the way `from` is, so a rename
/// moves between directories as well as changing a name. A destination the
/// archive already holds is refused rather than replaced: `delete` it in the
/// same session, which says the same thing out loud. DR-026.
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

/// Records one change against a session, once the archive has agreed to it.
///
/// The agreement is `rpf_core::allows`, which runs the resolution a commit runs
/// and throws the result away — so a change buffered here is one the commit
/// will not refuse for the same reason, and the rules are stated once rather
/// than once in the library and once on the wire (§1). It is given **the
/// session's own buffer**, so a change that collides only with another change
/// of the same session is refused here too, and a change the buffer makes
/// possible — a rename onto a path a buffered removal frees — is accepted here
/// too. DR-032.
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

/// Records one change against a session, and reports what is buffered.
///
/// One shape for every method that buffers, so a client reads one answer. `len`
/// is the payload's, and `null` for a change that carries none.
///
/// # Errors
///
/// Whatever the payload cannot be measured with — a `write` names a source
/// rather than carrying bytes, so asking its length can fail. DR-036.
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
        "locked_archives": summary.locked_archives,
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
        .map(commands::verify_problem)
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
/// `overwrite: true` lets it write into a directory that already holds
/// something, which is refused without it — the same rule and the same way
/// through the command line's `--overwrite` gives. DR-029.
///
/// Three things it refuses, all before anything is written.
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
    let existing = crate::existing(flag(params, "overwrite")?);
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

/// Why a tree cannot be extracted while edits are still buffered.
///
/// It names them, because committing or discarding them is what the caller has
/// to do, and a refusal that does not say which is one the client has to guess
/// at.
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
/// It sends no `progress` and cannot be stopped, and since 2026-08-30 that is a
/// stated cost rather than a free choice. One pass now looks for all 376 values
/// rather than two, which is seconds for a 47 MB executable and **up to about
/// nineteen minutes for a full-process dump** — the kind of source the NG
/// material is actually in. Wiring the watcher `find_keys` now takes through to
/// a `progress` notification widens the wire, and DR-040 records it as the
/// follow-up rather than doing it here.
///
/// It does **register the job** it is running, which is not the same question
/// and is why that deferral is affordable. A scan holds the single worker
/// thread for its whole duration, and without a registration a `cancel`
/// arriving in that window was answered `{"cancelling": false, "running":
/// null}` — the daemon saying nothing is running while it is a quarter of an
/// hour into a scan. It registers as [`Stoppable::No`], which is the truth:
/// `Unwatched` gives the scan nothing to notice a cancel with, so the answer
/// names the method and says why it cannot stop instead of denying it exists.
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
///
/// One function, so the wire's `cache` and `--cache-dir` cannot come to mean
/// two things about which directory is read (§3).
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

/// `forget` — take one buffered change back, and say what is left.
///
/// Three ordinary editor gestures **remove** a change rather than adding one:
/// create a file and then delete it, make a folder and then delete it, rename
/// an entry back to the name it started with. Without this the only way to
/// reach the set those leave was `discard` and a replay of everything else,
/// which is why a client had to retain every buffered payload to send it again.
/// DR-030 asked for it; DR-032 is where it was decided.
///
/// `forgotten` is false for a path nothing is buffered at, which is not a
/// failure: a client withdrawing a gesture it may never have sent should not
/// have to track that, and `paths` says what is actually there either way.
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
    // Taken before the session is borrowed: re-opening after the write needs
    // the same cache the session was opened with.
    let cache = state.cache.clone();
    let session = session(state, params)?;

    if session.pending.is_empty() {
        return Ok(json!({ "committed": 0, "unchanged": true }));
    }
    // Asked here as well as where each change was buffered, so that a dry run
    // reports the refusal rather than a rebuild that could not happen. Nothing
    // pending is nothing to refuse.
    session.archive.writable().map_err(Failure::Container)?;
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
    let (file, archive) = commands::open(&path, cache.as_deref())?;
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
        // Nothing is allocated and nothing is restructured, so there is no
        // plan to report — only the resolution. R6.7.
        rpf_core::resolves(&mut session.file, &session.archive, &session.pending)?;
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
        // Nothing in place can add, remove or rename an entry, so the commit
        // will rebuild whatever else is in the set. Reported as what it is
        // rather than as a payload that would not fit. DR-026.
        rpf_core::Plan::Structural(structural) => {
            let structural: Vec<Value> = structural
                .iter()
                .map(|change| json!({ "path": change.path, "structural": change.what }))
                .collect();
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
    // Intermediates go where the rebuilt archive is going, which is the answer
    // for a daemon precisely because there is nobody to ask for another one.
    // DR-022.
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
            |_: &str| Ok(std::io::Cursor::new(b"contents".to_vec())),
            &mut rpf_core::Unwatched,
        )
        .expect("builds");
        drop(out);

        let (file, archive) = commands::open(&path, None).expect("opens");
        let id = FileId::of(&file, &path).expect("named");
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
    fn a_key_scan_says_it_is_running_rather_than_that_nothing_is() {
        // The window this closes is minutes wide: a scan of a full-process dump
        // holds the worker thread for about nineteen of them, and before
        // 2026-08-30 `keys.extract` registered nothing, so a cancel arriving
        // inside that window was told nothing was running at all. It still
        // cannot be stopped — `Unwatched` leaves the scan nothing to notice a
        // cancel with — but "cannot stop, and here is why" and "there is no
        // such operation" are different answers and only one of them is true.
        // DR-040.
        let cancel = Cancellation::default();
        cancel.begin(&json!(7), None, "keys.extract", Stoppable::No(SCANNING));

        let answer = cancel.ask(None, None);
        assert_eq!(answer["cancelling"], json!(false), "{answer}");
        assert_eq!(answer["running"], json!("keys.extract"), "{answer}");
        assert_eq!(answer["reason"], json!(SCANNING), "{answer}");
        assert!(!cancel.stopped(), "a key scan was marked cancelled");

        // And it is forgotten afterwards, so a later cancel is not answered
        // against a scan that finished.
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
