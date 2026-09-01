//! The commands themselves.
//!
//! Every one of them is a thin call into `rpf-core`. Nothing here knows the
//! byte layout of an archive; if it did, the editor client could not do the
//! same thing. `docs/conventions.md` §1.

use std::{
    fs,
    io::{IsTerminal, Seek as _, Write},
    path::{Path, PathBuf},
};

use rpf_core::{
    Archive, Change, Changes, Dictionary, Flow, ListedKind, Step, View, Watch,
    keys::{
        AES_KEY_LEN, Cache, HASH_LUT_LEN, LauncherKey, Material, NG_DECRYPT_TABLE_COUNT,
        NG_DECRYPT_TABLE_LEN, NG_EXPANDED_KEY_COUNT, NG_EXPANDED_KEY_LEN, SourceDigest,
    },
};
use serde_json::{Value, json};

use crate::{
    exit::{Failure, Result},
    install,
};

/// Scratch space for a cascading rebuild: unnamed temporary files in a
/// directory this end names.
///
/// `rpf-core` opens no files and resolves no paths (§7), so it asks for scratch
/// space through a seam and this is the frontend's answer to it. The directory
/// is the one the rebuilt archive is going to — the same place [`persist`]
/// already writes its temporary file, so an intermediate is on the filesystem
/// the result has to fit on and no second location has to be configured,
/// discovered or asked about. That last part is what makes it the daemon's
/// answer as well as the command line's: `serve --stdio` has nobody to ask.
///
/// `tempfile_in` rather than `NamedTempFile`: nothing needs the name, and an
/// unnamed handle is unlinked as soon as it is made, so an interrupted rebuild
/// leaves nothing behind to clean up. DR-022.
#[derive(Debug)]
pub struct ScratchIn {
    directory: PathBuf,
}

impl ScratchIn {
    /// Scratch beside `path`, which is where the rebuilt archive is going.
    pub fn beside(path: &Path) -> Self {
        Self {
            directory: path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
        }
    }
}

impl rpf_core::Scratch for ScratchIn {
    type Sink = fs::File;

    fn create(&mut self) -> rpf_core::Result<fs::File> {
        // The offset is the sink's own, and a sink that does not exist has no
        // meaningful one. `Error::Io` carries no path, so the directory this
        // failed in is not in the message — see the report for R4.13.
        tempfile::tempfile_in(&self.directory)
            .map_err(|source| rpf_core::Error::Io { offset: 0, source })
    }
}

/// Progress on standard error, for a person watching a long rebuild.
///
/// Only when standard error is a terminal. Piped output belongs to whatever is
/// consuming it, and `--json` on standard output should not have to be read
/// past noise on standard error. R6.8.
struct OnStderr {
    silent: bool,
    /// How wide the line last written was, so the next one can cover it.
    written: usize,
}

impl OnStderr {
    /// Reports if there is someone there to read it.
    fn new() -> Self {
        Self {
            silent: !std::io::stderr().is_terminal(),
            written: 0,
        }
    }

    /// Whether a line has been written that nothing has closed yet.
    ///
    /// What [`Drop`] acts on, named so the condition can be asserted without
    /// capturing standard error.
    const fn line_is_open(&self) -> bool {
        !self.silent && self.written > 0
    }
}

impl Watch for OnStderr {
    fn step(&mut self, step: Step<'_>) -> Flow {
        if !self.silent {
            let line = format!("{}/{} {}", step.done, step.total, step.path);
            eprint!("\r{line}{}", padding(self.written, line.chars().count()));
            self.written = line.chars().count();
            if step.done == step.total {
                eprintln!();
                self.written = 0;
            }
        }
        Flow::Continue
    }
}

/// Ends the progress line, however the work it was reporting on ended.
///
/// The `done == total` arm above closes the line of a walk that ran to its
/// end, which every watched operation did until 2026-08-30. A key scan is the
/// first that **stops early on purpose**: `scan::find` gives up the moment
/// every anchor is found, which on a memory image is around block 31 of 63, so
/// the last line it wrote never reached that arm and the first line of the
/// report was printed on top of it. Dropping is the one thing that happens on
/// every path — finished, finished early, cancelled, failed — so it is where
/// the newline belongs rather than in a `finish()` a caller has to remember
/// (`docs/conventions.md` §4). `written` is zero after the arm above, so a walk
/// that did run to its end does not get a second newline. DR-040.
impl Drop for OnStderr {
    fn drop(&mut self) {
        if self.line_is_open() {
            eprintln!();
            self.written = 0;
        }
    }
}

/// Spaces enough to cover what a shorter line leaves behind.
///
/// One line is reused rather than one printed per entry, and the reuse used to
/// be a carriage return followed by the ANSI erase-to-end-of-line. That
/// sequence needs virtual-terminal processing, which neither the standard
/// library nor this module enables on Windows and which `is_terminal()` cannot
/// report — so on a plain console the escape was printed rather than obeyed,
/// once per entry. A carriage return is handled by every console there is, and
/// spaces cover the tail of the previous line without asking anything of the
/// terminal at all. R10.9.
fn padding(written: usize, now: usize) -> String {
    " ".repeat(written.saturating_sub(now))
}

/// What opens an archive at this path, if it turns out to be encrypted.
///
/// The archive's **own file name** is what an NG archive's key is derived from
/// (`docs/rpf-format.md`, Encryption), and turning a path into a name is the
/// frontend's job — §7 keeps paths out of `rpf-core`. Which cache is
/// [`cache_of`]'s answer, so `--cache-dir` reaches opening and extraction
/// through one function rather than two that have to agree (§3). Nothing is
/// read here: the key cache is consulted only if an archive refuses to open
/// without it, so an unencrypted archive still runs on a machine that has no
/// cache and does not make one (R2.6). DR-041.
fn unlock_for(path: &Path, named_cache: Option<&Path>) -> rpf_core::Unlock {
    let Some(cache) = cache_of(named_cache) else {
        return rpf_core::Unlock::unkeyed();
    };
    // Lossy, deliberately. The name is key-material input — an NG archive's key
    // is a function of its bytes — so a file name this host cannot spell as
    // UTF-8 hashes over `EF BF BD` and chooses a key the packer did not. That
    // is not silent: the root-directory check refuses it as `WrongKey`, which
    // is the truthful answer, because the name we can spell is not the name it
    // was packed under. Refusing here instead would answer the same question
    // less clearly and would refuse unencrypted archives with such a name for
    // no reason at all.
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    rpf_core::Unlock::cached(cache, name)
}

/// Opens an archive file and parses its table of contents.
///
/// The one place either frontend opens an archive, which is what keeps the two
/// from differing about what they can open (§1): `serve --stdio` reaches it
/// through the same call.
///
/// `named_cache` is `--cache-dir`, and `None` is the platform's own.
pub fn open(path: &Path, named_cache: Option<&Path>) -> Result<(fs::File, Archive)> {
    let mut file = fs::File::open(path).map_err(|source| opening(path, source))?;
    let archive = Archive::open(&mut file, &unlock_for(path, named_cache))?;
    Ok((file, archive))
}

/// Why an archive would not open, classified by who has to act on it.
///
/// A filesystem path that runs *past* a file is an in-archive path spelled as a
/// filesystem one — `rpf info outer.rpf/x64/inner.rpf`. The operating system
/// answers "Not a directory", which as [`Failure::Io`] tells an agent consumer
/// that the disk misbehaved and retrying is reasonable. Nothing on the disk
/// failed: the request named something the tool does not accept, which DR-010
/// puts under [`Failure::Refused`]. R6.11.
///
/// Asked of the path rather than of the error, because which `io::ErrorKind` a
/// platform produces for it varies and the shape of the path does not.
pub fn opening(path: &Path, source: std::io::Error) -> Failure {
    if let Some(archive) = path.ancestors().skip(1).find(|above| above.is_file()) {
        return Failure::Refused {
            reason: format!(
                "{} continues past {}, which is a file; a path inside an archive is given \
                 separately from the archive that holds it",
                path.display(),
                archive.display(),
            ),
        };
    }
    Failure::Io {
        path: path.display().to_string(),
        source,
    }
}

/// `info` — the header, and what the entries add up to.
///
/// `inside` is empty for the archive itself, and names a nested archive
/// otherwise: every other reporting command addresses through nesting, and
/// R6.11 is this one catching up.
pub fn info(path: &Path, inside: &str, named_cache: Option<&Path>, json_out: bool) -> Result<()> {
    let (mut file, archive) = open(path, named_cache)?;
    let summary = rpf_core::Summary::of(&mut file, &archive, inside)?;

    if json_out {
        emit(&json!({
            "path": path.display().to_string(),
            "inside": inside,
            "len": summary.len,
            "encryption": encryption_name(summary.encryption),
            "entries": summary.entries,
            "directories": summary.directories,
            "binary_files": summary.binary_files,
            "resource_files": summary.resource_files,
            "nested_archives": summary.nested_archives,
            "locked_archives": summary.locked_archives,
            "unreferenced_bytes": summary.unreferenced_bytes,
        }));
    } else {
        println!("path         {}", path.display());
        if !inside.is_empty() {
            println!("inside       {inside}");
        }
        println!("length       {}", summary.len);
        println!("encryption   {}", encryption_name(summary.encryption));
        println!("entries      {}", summary.entries);
        println!("  directories {}", summary.directories);
        println!("  binary      {}", summary.binary_files);
        println!("  resource    {}", summary.resource_files);
        println!("nested       {}", summary.nested_archives);
        println!("  locked      {}", summary.locked_archives);
        println!("unreferenced {}", summary.unreferenced_bytes);
    }
    Ok(())
}

/// `ls` — what is at a path.
pub fn ls(
    path: &Path,
    inside: &str,
    recursive: bool,
    named_cache: Option<&Path>,
    json_out: bool,
) -> Result<()> {
    let (mut file, archive) = open(path, named_cache)?;
    let rows = rpf_core::Listed::at(&mut file, &archive, inside, recursive)?;

    if json_out {
        emit(&Value::Array(rows.iter().map(listing_row).collect()));
    } else {
        for row in &rows {
            let (kind, len) = named(row);
            let encoding = encoding_named(row).unwrap_or("-");
            println!("{kind:<9} {encoding:<4} {len:>12}  {}", row.path);
        }
    }
    Ok(())
}

/// One `ls` row as JSON, for whichever frontend is reporting it.
///
/// Presentation, and one place for it: `--json ls` and the daemon's `list` are
/// the same rows under the same names, and a second spelling of them is how two
/// frontends drift apart (§1).
pub fn listing_row(listed: &rpf_core::Listed) -> Value {
    let (kind, len) = named(listed);
    json!({ "path": listed.path, "kind": kind, "len": len, "encoding": encoding_named(listed) })
}

/// What a listed entry is called, and the one number reported beside it.
///
/// A directory's number is how many children it holds and a file's is its
/// length; the two share a column because a listing is one table.
fn named(listed: &rpf_core::Listed) -> (&'static str, u64) {
    match listed.kind {
        ListedKind::Directory { children } => ("directory", u64::from(children)),
        ListedKind::Binary { len, .. } => ("binary", len),
        ListedKind::Resource { len } => ("resource", len),
    }
}

/// What a listed entry's payload announces itself to be, in the one spelling
/// both frontends report it in. R3.7.
///
/// `None` — `null` on the wire — for a directory, for a resource, and for a
/// binary entry nothing recognised. **A resource is `null` because its payload
/// is not read**, not because it holds nothing: `docs/backlog.md` Q7. Its
/// `"kind"` is where a caller reads that it is one, which is a field it has
/// always had and a source no payload can contradict.
///
/// Adding this field is a contract addition, and DR-032 makes field names part
/// of the contract: `"encoding"` is now one, and its values are `"xml"`,
/// `"text"`, `"rbf"`, `"pso"` and `null`. The four spellings are
/// [`rpf_core::Encoding::name`]'s, so an error naming an encoding says the same
/// word a listing row does (§3).
fn encoding_named(listed: &rpf_core::Listed) -> Option<&'static str> {
    let ListedKind::Binary { encoding, .. } = listed.kind else {
        return None;
    };
    Some(encoding?.name())
}

/// A view, with the dictionary the command line has to offer with it.
///
/// The empty one, which is a complete answer: a hash a dictionary does not name
/// is rendered `hash_XXXXXXXX` and read back as the same hash, so what a
/// dictionary changes is legibility and never the payload (R5.5). There is no
/// switch for one because no dictionary ships — DR-006 — and adding one is R5.5's
/// to add, in both frontends at once.
const fn wanted(view: View) -> rpf_core::view::Wanted<'static> {
    rpf_core::view::Wanted {
        view,
        names: Dictionary::EMPTY,
    }
}

/// The command line's spelling of [`View`], for `--as`.
///
/// A wrapper rather than a second enum: the three names are [`View::name`]'s
/// and are written down once, so `--as xml` and the daemon's `"as": "xml"` can
/// never come to mean different things (§3). DR-053.
#[derive(Debug, Clone, Copy)]
pub struct ViewArg(View);

impl From<ViewArg> for View {
    fn from(argument: ViewArg) -> Self {
        argument.0
    }
}

impl clap::ValueEnum for ViewArg {
    fn value_variants<'a>() -> &'a [Self] {
        const VIEWS: [ViewArg; View::ALL.len()] = [
            ViewArg(View::ALL[0]),
            ViewArg(View::ALL[1]),
            ViewArg(View::ALL[2]),
        ];
        &VIEWS
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(clap::builder::PossibleValue::new(self.0.name()))
    }
}

/// `cat` — one entry's contents on standard output.
pub fn cat(path: &Path, inside: &str, view: View, named_cache: Option<&Path>) -> Result<()> {
    let (mut file, archive) = open(path, named_cache)?;
    let (holder, index) = archive.locate(&mut file, inside)?;
    if holder.entry(index)?.is_directory() {
        return Err(Failure::Refused {
            reason: format!("{inside} is a directory"),
        });
    }
    // A view other than the entry's own bytes is a whole document either way —
    // the conversion reads the payload and writes another — so there is no
    // stream to keep, and the terminal rule below is applied to what came back.
    if view != View::Raw {
        let viewed = rpf_core::view::read(&mut file, &holder, index, inside, wanted(view))?;
        return to_stdout(inside, &viewed.bytes);
    }
    // `extract`, not `read`: this has to be the same form `put` accepts, or
    // `rpf cat … > f && rpf put … f` would fail on every resource. For a binary
    // entry the two are identical; for a resource `extract` keeps the RSC7
    // header, which is what the file is outside the archive.
    let out = std::io::stdout();

    // Into a pipe or a file the entry goes straight through and is never held:
    // `cat` of a multi-gigabyte entry is one of the things §7 is about. A
    // terminal is the one case that has to see the bytes before it writes any
    // of them, and it is also the case where they are small.
    if !out.is_terminal() {
        let mut contents = holder.extracted(&mut file, index)?;
        // Buffered for the reason [`stream_file`] gives, and measured the same
        // way: standard output is line-buffered, which is a 1 KiB buffer that
        // `io::copy` declines to use.
        let mut sink = std::io::BufWriter::with_capacity(64 * 1024, out.lock());
        let failing = |source: std::io::Error| {
            rpf_core::Error::carried(source).map_or_else(
                |source| Failure::Io {
                    path: "<stdout>".to_owned(),
                    source,
                },
                Failure::Container,
            )
        };
        std::io::copy(&mut contents, &mut sink).map_err(failing)?;
        return sink.flush().map_err(failing);
    }

    to_stdout(inside, &holder.extract(&mut file, index)?)
}

/// Bytes a caller asked for, onto standard output, under the rule that a
/// terminal takes text and nothing else.
///
/// Refused at this tool's own boundary rather than at the platform's. On
/// Windows the standard library's console writer declines bytes that are not
/// UTF-8 — so `cat` of a resource inside a terminal failed with a sentence
/// about UTF-8, exit 7, while the same command redirected worked, and the same
/// command on macOS filled the terminal with a resource. One rule instead, the
/// same on all three and the same for every form an entry is asked for: a
/// terminal takes text, and anything else goes to a file or a pipe. R10.7.
fn to_stdout(inside: &str, bytes: &[u8]) -> Result<()> {
    let out = std::io::stdout();
    if !goes_to(bytes, out.is_terminal()) {
        return Err(Failure::Refused {
            reason: format!(
                "{inside} is not text and standard output is a terminal; \
                 redirect it to a file or a pipe"
            ),
        });
    }
    let mut sink = std::io::BufWriter::with_capacity(64 * 1024, out.lock());
    sink.write_all(bytes)
        .and_then(|()| sink.flush())
        .map_err(|source| Failure::Io {
            path: "<stdout>".to_owned(),
            source,
        })
}

/// How a change to what an archive holds is allowed to happen.
///
/// Grouped rather than passed as more parameters: a call site reading
/// `remove(a, b, false, true)` says nothing about which `false` is which.
#[derive(Debug, Clone, Copy, clap::Args)]
pub struct ChangeOptions {
    /// Write even into a detected game installation.
    #[arg(long)]
    pub force: bool,
    /// Report what would be written, and write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

/// How a write is allowed to happen: [`ChangeOptions`], and the two questions
/// only replacing an entry can be asked.
///
/// Adding, removing and renaming always rebuild — each of them moves the entry
/// count or the names blob, DR-026 — so `--rebuild` would be a flag with one
/// value on `rm`, `mv` and `mkdir`, and it is not offered there.
#[derive(Debug, Clone, Copy, clap::Args)]
pub struct WriteOptions {
    /// What every change to an archive may be told.
    #[command(flatten)]
    pub change: ChangeOptions,
    /// Rebuild the whole archive rather than patching in place. Slower, and
    /// atomic: an interrupted rebuild leaves the original untouched.
    #[arg(long)]
    pub rebuild: bool,
    /// Create the entry if the archive holds nothing at that path, rather than
    /// reporting it as not found. Creating one rebuilds; this changes nothing
    /// about a path the archive already holds.
    #[arg(long)]
    pub create: bool,
    /// Write text or XML into an entry that holds RBF or PSO. Refused without
    /// it: those are binary encodings, and the runtime reads the entry as one.
    #[arg(long)]
    pub allow_encoding_change: bool,
    /// What the file being put is: the entry's own bytes, an XML document to
    /// convert into whatever the entry holds, or either.
    #[arg(long = "as", value_name = "VIEW", default_value = "raw")]
    pub view: ViewArg,
}

impl From<ChangeOptions> for WriteOptions {
    fn from(change: ChangeOptions) -> Self {
        Self {
            change,
            rebuild: false,
            create: false,
            allow_encoding_change: false,
            view: ViewArg(View::Raw),
        }
    }
}

/// `put` — replace one entry.
///
/// Reads the file and hands the whole of the decision to [`apply`], which is
/// where every command that changes an archive goes: they differ in what change
/// they ask for and in nothing else (§4).
pub fn put(
    path: &Path,
    inside: &str,
    from: &Path,
    options: WriteOptions,
    named_cache: Option<&Path>,
    json_out: bool,
) -> Result<()> {
    let view = View::from(options.view);
    let contents: std::sync::Arc<dyn rpf_core::Contents> = if view == View::Raw {
        // A regular file is opened when the library wants it, so a donor of any
        // size costs a buffer rather than its length. Anything else — a FIFO, a
        // process substitution, `/dev/stdin` — can be neither reopened nor
        // seeked, and the only thing to be done with it is to read it once and
        // hold it, which is what this did for every donor before. DR-036.
        match fs::metadata(from) {
            Ok(found) if found.is_file() => std::sync::Arc::new(Donor::at(from)),
            _ => {
                let read = fs::read(from).map_err(|source| Failure::Io {
                    path: from.display().to_string(),
                    source,
                })?;
                std::sync::Arc::new(rpf_core::Bytes::new(read))
            }
        }
    } else {
        // A document is converted against the entry it is going into, and the
        // entry is read here, in the call that converts it — DR-049 makes a
        // `PSO` write an edit of the file it came from, so the file has to be
        // to hand. What is buffered is the payload, of the entry's own
        // encoding, so nothing downstream can tell it from a write of the same
        // bytes by any other route. DR-053.
        std::sync::Arc::new(rpf_core::Bytes::new(convert(
            path,
            inside,
            from,
            view,
            options.create,
            named_cache,
        )?))
    };
    apply(
        path,
        inside,
        &Changes::one(
            inside,
            Change::Write {
                contents,
                create: options.create,
                allow_encoding_change: options.allow_encoding_change,
            },
        ),
        options,
        named_cache,
        json_out,
    )
}

/// A file on this machine, offered to the library as the contents of a write.
///
/// The command line's answer to [`rpf_core::Contents`], and the reason a path
/// does not have to travel inward (`docs/conventions.md` §7): the library opens
/// this when it wants the bytes and never holds them, so `rpf put` of a donor
/// costs a buffer rather than the donor. DR-036.
#[derive(Debug)]
pub struct Donor(PathBuf);

impl Donor {
    /// The file at `path`, which is not opened until it is asked for.
    #[must_use]
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }
}

impl rpf_core::Contents for Donor {
    // `offset: 0` for the reason `ScratchIn` gives: the source is not the
    // archive, so there is no offset in it to name. The path is named where
    // this surfaces, which is the frontend that owns it.
    fn open(&self) -> rpf_core::Result<Box<dyn rpf_core::Payload + '_>> {
        let file =
            fs::File::open(&self.0).map_err(|source| rpf_core::Error::Io { offset: 0, source })?;
        Ok(Box::new(file))
    }

    fn len(&self) -> rpf_core::Result<u64> {
        let found =
            fs::metadata(&self.0).map_err(|source| rpf_core::Error::Io { offset: 0, source })?;
        Ok(found.len())
    }
}

/// The payload a document at `from` becomes, against the entry it is going into.
///
/// The archive is opened for reading only: this decides what will be written
/// and writes none of it, so `--dry-run` reaches it on the same terms every
/// other refusal does.
fn convert(
    path: &Path,
    inside: &str,
    from: &Path,
    view: View,
    create: bool,
    named_cache: Option<&Path>,
) -> Result<Vec<u8>> {
    let document = fs::read(from).map_err(|source| Failure::Io {
        path: from.display().to_string(),
        source,
    })?;
    let (mut file, archive) = open(path, named_cache)?;
    let (holder, index) = match archive.locate(&mut file, inside) {
        Ok(found) => found,
        // A path being created has no entry to convert against: an entry that
        // is not there holds no encoding for a document to adopt. `auto` takes
        // the bytes as they are and `xml` says why it cannot, which is what
        // the daemon answers for the same request.
        Err(rpf_core::Error::NotFound { .. }) if create => {
            return Ok(rpf_core::view::applied(
                &[],
                None,
                inside,
                wanted(view),
                document,
            )?);
        }
        Err(failure) => return Err(failure.into()),
    };
    Ok(rpf_core::view::apply(
        &mut file,
        &holder,
        index,
        inside,
        wanted(view),
        document,
    )?)
}

/// `rm` — remove an entry, and its children when it is a directory and
/// `recursive`.
pub fn remove(
    path: &Path,
    inside: &str,
    recursive: bool,
    options: ChangeOptions,
    named_cache: Option<&Path>,
    json_out: bool,
) -> Result<()> {
    apply(
        path,
        inside,
        &Changes::one(inside, Change::Remove { recursive }),
        options.into(),
        named_cache,
        json_out,
    )
}

/// `mv` — move an entry to another path in the same archive.
///
/// A destination the archive already holds is refused rather than replaced:
/// `rm` it first, which is the same two steps said out loud. DR-026.
pub fn rename(
    path: &Path,
    from: &str,
    to: &str,
    options: ChangeOptions,
    named_cache: Option<&Path>,
    json_out: bool,
) -> Result<()> {
    apply(
        path,
        from,
        &Changes::one(from, Change::RenameTo(to.to_owned())),
        options.into(),
        named_cache,
        json_out,
    )
}

/// `mkdir` — add a directory, and whatever above it is missing.
pub fn make_directory(
    path: &Path,
    inside: &str,
    options: ChangeOptions,
    named_cache: Option<&Path>,
    json_out: bool,
) -> Result<()> {
    apply(
        path,
        inside,
        &Changes::one(inside, Change::MakeDirectory),
        options.into(),
        named_cache,
        json_out,
    )
}

/// What an attempt to write a change set in place came to.
enum Attempted {
    /// It was written, or a dry run reported what would have been. There is
    /// nothing left to do.
    Done,
    /// No patch can express this set, or its payloads will not fit. The
    /// archive has to be rebuilt, and nothing has been written.
    MustRebuild,
}

/// Applies a set of changes to an archive, patching in place when every one of
/// them fits where it already sits and rebuilding when any does not.
///
/// The one path every write takes. `put`, `rm`, `mv` and `mkdir` differ in the
/// [`Changes`] they build and in nothing else, which is what keeps four
/// commands from growing four answers to "patch or rebuild".
///
/// The two are not equivalent in durability, and the report says which ran. A
/// rebuild is atomic. A patch is not: it writes into the live archive, and an
/// interruption between the payload and its entry row leaves the archive
/// describing bytes that are no longer there.
///
/// `dry_run` reports that decision and stops before acting on it. R6.7. It is
/// the same decision, taken the same way, so what it reports is what would
/// happen — including a refusal, which is why the game-install guard runs
/// first here too.
///
/// `inside` is the in-archive path the command is about, and it is what a
/// report names. Every command here asks for exactly one change, so it is that
/// change's path; a plan reports each entry it decided under the entry's own
/// path, which for one change is the same string.
pub fn apply(
    path: &Path,
    inside: &str,
    changes: &Changes,
    options: WriteOptions,
    named_cache: Option<&Path>,
    json_out: bool,
) -> Result<()> {
    refuse_game_install(path, options.change.force)?;

    if !options.rebuild {
        match in_place(path, changes, options, named_cache, json_out)? {
            Attempted::Done => return Ok(()),
            Attempted::MustRebuild => {}
        }
    } else if options.change.dry_run {
        // Reached only with --rebuild --dry-run: the rebuild was asked for
        // rather than forced by anything about the changes, so there is no
        // allocation and no structural change to report against. R6.7.
        let (mut file, archive) = open(path, named_cache)?;
        rpf_core::resolves(&mut file, &archive, changes)?;
        if json_out {
            emit(&json!({ "method": "rebuild", "path": inside, "dry_run": true }));
        } else {
            println!("would rebuild the archive");
        }
        return Ok(());
    }

    if options.change.dry_run {
        return Ok(());
    }

    let (mut file, archive) = open(path, named_cache)?;
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let mut scratch = tempfile::NamedTempFile::new_in(directory).map_err(|source| Failure::Io {
        path: directory.display().to_string(),
        source,
    })?;

    let report = rpf_core::rewrite(
        &mut file,
        &archive,
        changes,
        scratch.as_file_mut(),
        &mut ScratchIn::beside(path),
        &mut OnStderr::new(),
    )?;
    persist(scratch, path)?;

    if json_out {
        emit(&json!({
            "method": "rebuild",
            "path": inside,
            "entries": report.entry_count,
            "len": report.len,
        }));
    } else {
        println!(
            "rebuilt: {} entries, {} bytes",
            report.entry_count, report.len
        );
    }
    Ok(())
}

/// Tries to write `changes` where the entries already sit, reporting whatever
/// it decided.
///
/// A dry run only reads: needing write permission to answer "what would this
/// write do" would make it useless on the archives worth asking about.
fn in_place(
    path: &Path,
    changes: &Changes,
    options: WriteOptions,
    named_cache: Option<&Path>,
    json_out: bool,
) -> Result<Attempted> {
    let mut file = if options.change.dry_run {
        fs::File::open(path)
    } else {
        fs::OpenOptions::new().read(true).write(true).open(path)
    }
    .map_err(|source| Failure::Io {
        path: path.display().to_string(),
        source,
    })?;
    let archive = rpf_core::Archive::open(&mut file, &unlock_for(path, named_cache))?;

    match rpf_core::plan(&mut file, &archive, changes)? {
        rpf_core::Plan::Fits(patches) => {
            if !options.change.dry_run {
                patches.apply(&mut file)?;
            }
            for entry in patches.planned() {
                report_patch(entry, options.change.dry_run, json_out);
            }
            Ok(Attempted::Done)
        }
        rpf_core::Plan::DoesNotFit(rejected) => {
            if options.change.dry_run {
                for entry in &rejected {
                    report_would_rebuild(entry, json_out);
                }
                return Ok(Attempted::Done);
            }
            if !json_out {
                for entry in &rejected {
                    eprintln!(
                        "rpf: {} bytes will not fit the {} available; rebuilding",
                        entry.needed, entry.allocation,
                    );
                }
            }
            Ok(Attempted::MustRebuild)
        }
        rpf_core::Plan::Structural(structural) => {
            // Resolved before it is reported, because a plan decides only *how*
            // a change would be written and a dry run has to answer a refusal
            // as well. `allows` runs the resolution the rebuild runs and throws
            // the result away, so what it accepts is what the rebuild accepts
            // — and it is asked only of the changes a patch could not express,
            // because a write to an entry that exists is fully resolved by the
            // plan itself. R6.7.
            for change in &structural {
                let asked = changes.at(&change.path).ok_or_else(|| Failure::Refused {
                    reason: format!("{} is not a change that was asked for", change.path),
                })?;
                rpf_core::allows(&mut file, &archive, changes, &change.path, asked)?;
            }
            if options.change.dry_run {
                for change in &structural {
                    report_would_restructure(change, json_out);
                }
                return Ok(Attempted::Done);
            }
            if !json_out {
                for change in &structural {
                    eprintln!("rpf: {} {}; rebuilding", change.path, change.what);
                }
            }
            Ok(Attempted::MustRebuild)
        }
    }
}

/// Whether these bytes may go to standard output as it stands.
///
/// A terminal takes text; anything else goes to a file or a pipe. Separated
/// from [`cat`] so that the rule can be tested: whether standard output is a
/// terminal is not something a test can arrange without a pseudo-terminal, and
/// which bytes are text is the half that decides.
fn goes_to(bytes: &[u8], terminal: bool) -> bool {
    !terminal || std::str::from_utf8(bytes).is_ok()
}

/// Reports one patch, made or merely planned.
fn report_patch(entry: &rpf_core::Planned, dry_run: bool, json_out: bool) {
    if json_out {
        emit(&json!({
            "method": "patch",
            "path": entry.path,
            "at": entry.at,
            "len": entry.len,
            "allocation": entry.allocation,
            "dry_run": dry_run,
        }));
    } else if dry_run {
        println!(
            "would patch {} bytes in place at {} (room for {})",
            entry.len, entry.at, entry.allocation,
        );
    } else {
        println!(
            "patched {} bytes in place at {} (room for {})",
            entry.len, entry.at, entry.allocation,
        );
    }
}

/// Reports that a change would force a rebuild because no patch can express
/// it, and which change.
fn report_would_restructure(change: &rpf_core::Structural, json_out: bool) {
    if json_out {
        emit(&json!({
            "method": "rebuild",
            "path": change.path,
            "structural": change.what,
            "dry_run": true,
        }));
    } else {
        println!("would rebuild: {} {}", change.path, change.what);
    }
}

/// Reports that an edit would force a rebuild, and why.
fn report_would_rebuild(entry: &rpf_core::TooLarge, json_out: bool) {
    if json_out {
        emit(&json!({
            "method": "rebuild",
            "path": entry.path,
            "needed": entry.needed,
            "allocation": entry.allocation,
            "dry_run": true,
        }));
    } else {
        println!(
            "would rebuild: {} bytes will not fit the {} available",
            entry.needed, entry.allocation,
        );
    }
}

/// Whether an extraction may write into a directory that already holds
/// something.
///
/// An enum rather than a boolean because a call site reading
/// `extract_into(a, b, c, d, false, e)` says nothing, and because the two cases
/// are named decisions rather than a switch: DR-029.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Existing {
    /// Refuse a target that holds anything. What both frontends do unless told
    /// otherwise.
    Refuse,
    /// Write into it, replacing what an entry names and leaving the rest.
    Overwrite,
}

/// Refuses a target that already holds something.
///
/// An extraction claims the tree **is** the archive — `pack` reads it back and
/// `verify --against` checks against its manifest — and a tree that also holds
/// files no entry names is not that. Writing into one silently is how an
/// extraction of a second archive leaves the first archive's entries beside it,
/// and how `rpf extract a.rpf .` scatters an archive over a working directory.
/// DR-029.
///
/// A target that does not exist is not "already holding something"; nor is an
/// empty directory. So the ordinary first extraction is unaffected.
///
/// # Errors
///
/// [`Failure::Refused`] naming what is there, and [`Failure::Io`] for a target
/// that cannot be read at all.
fn refuse_existing(into: &Path, existing: Existing) -> Result<()> {
    if existing == Existing::Overwrite {
        return Ok(());
    }
    let held = match fs::read_dir(into) {
        Ok(mut held) => held.next(),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(Failure::Io {
                path: into.display().to_string(),
                source,
            });
        }
    };
    let Some(first) = held else {
        return Ok(());
    };
    let named = first.map_or_else(
        |_| "something".to_owned(),
        |entry| entry.file_name().to_string_lossy().into_owned(),
    );
    Err(Failure::Refused {
        reason: format!(
            "{} already holds {named:?}; an extracted tree is the archive, and one that also \
             holds files no entry names is not. Extract somewhere else, empty it, or pass \
             --overwrite to write into it as it is",
            into.display(),
        ),
    })
}

/// What an extraction put on the filesystem.
#[derive(Debug, Clone)]
pub struct Extracted {
    /// How many entries came out as files.
    pub files: usize,
    /// How many directories were created to hold them.
    pub directories: usize,
    /// Where the sidecar manifest was written.
    pub manifest: std::path::PathBuf,
}

/// `extract` — write every entry to a tree, with the manifest beside it.
///
/// The one thing this frontend will not write over is the archive it is
/// reading: `rpf extract test.rpf .` on an archive holding an entry of its own
/// name truncated and rewrote the file every remaining entry was still being
/// read out of. The daemon's rule is wider — every archive an open session
/// holds — and both are asked the same way, before anything is created.
pub fn extract(
    path: &Path,
    into: &Path,
    existing: Existing,
    named_cache: Option<&Path>,
    json_out: bool,
) -> Result<()> {
    let (mut file, archive) = open(path, named_cache)?;
    let reading = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let extracted = extract_into(
        &mut file,
        &archive,
        into,
        existing,
        &|target| {
            (target == reading).then(|| Failure::Refused {
                reason: format!(
                    "{} would be written over by an entry of the archive being read from it; \
                     extract somewhere else",
                    reading.display(),
                ),
            })
        },
        &mut OnStderr::new(),
    )?;

    if json_out {
        emit(&json!({
            "archive": path.display().to_string(),
            "into": into.display().to_string(),
            "files": extracted.files,
            "directories": extracted.directories,
            "manifest": extracted.manifest.display().to_string(),
        }));
    } else {
        println!(
            "{} files and {} directories into {}",
            extracted.files,
            extracted.directories,
            into.display(),
        );
    }
    Ok(())
}

/// Writes every entry of an open archive to a tree, with the manifest beside
/// it.
///
/// Nested archives come out as the `.rpf` files they are, byte for byte, rather
/// than being unpacked in place. Packing puts them back untouched, which is
/// what passthrough means. Editing inside one is `put`'s job, and it cascades.
///
/// One [`Step`] per file written, and it stops when the watcher says to. A
/// stopped extraction leaves the files it had already written where they are —
/// unlike a rebuild, which goes to a temporary file and is renamed only on
/// success. DR-014.
///
/// `existing` decides what happens when the target already holds something:
/// refused unless the caller says otherwise, because an extracted tree claims
/// to *be* the archive. DR-029, and [`refuse_existing`] carries the argument.
///
/// `claimed` is asked of **every path this will write**, before anything is
/// created, and the first refusal it gives is the answer. It is a parameter
/// rather than a check each frontend remembers to make first, because a tree
/// cannot be renamed into place: a refusal found half way through would leave
/// the half it had already written. What is claimed differs by frontend — the
/// command line holds the archive it is reading, the daemon holds every open
/// session — and that difference is the caller's, not this function's.
///
/// # Errors
///
/// [`Failure::Refused`] for a target that already holds something,
/// whatever `claimed` returns for a path this would write,
/// [`Failure::Io`] for a file or directory that could not be written,
/// `Error::Cancelled` when the watcher stops it, and as
/// `rpf_core::Manifest::of` for an archive whose names no host can hold.
pub fn extract_into<R: std::io::Read + std::io::Seek>(
    src: &mut R,
    archive: &Archive,
    into: &Path,
    existing: Existing,
    claimed: &dyn Fn(&Path) -> Option<Failure>,
    watch: &mut impl Watch,
) -> Result<Extracted> {
    // Before the walk that reads and digests every entry, so a refusal costs
    // nothing, and before anything is created, for `claimed`'s reason: a tree
    // cannot be renamed into place, so a refusal found part-way would leave the
    // part already written.
    refuse_existing(into, existing)?;

    let manifest = rpf_core::Manifest::of_contents(src, archive, watch)?;
    let specs = rpf_core::specs_of(archive)?;

    let root = resolved_root(into)?;
    for path in specs
        .iter()
        .map(|(spec, _)| root.join(&spec.path))
        .chain(std::iter::once(root.join(rpf_core::MANIFEST_NAME)))
    {
        if let Some(refusal) = claimed(&path) {
            return Err(refusal);
        }
    }

    create_dir(into)?;
    for directory in &manifest.directories {
        create_dir(&into.join(directory))?;
    }

    let total = u32::try_from(specs.len()).unwrap_or(u32::MAX);
    let mut done = 0_u32;
    let mut bytes = 0_u64;
    for (spec, index) in &specs {
        let target = into.join(&spec.path);
        if let Some(parent) = target.parent() {
            create_dir(parent)?;
        }
        // Streamed from the archive into the file rather than read and then
        // written, so an extraction costs its buffer rather than its largest
        // entry (§7). What that changes if a read fails part-way is that the
        // entry's file is there and short, where before it was not there at
        // all — an extraction that failed already left the entries before it,
        // and this is the same kind of leftover one entry later.
        let mut contents = archive.extracted(&mut *src, *index)?;
        let moved = stream_file(&target, &mut contents)?;

        done = done.saturating_add(1);
        bytes = bytes.saturating_add(moved);
        if watch.step(Step {
            path: &spec.path,
            done,
            total,
            bytes,
        }) == Flow::Stop
        {
            return Err(Failure::Container(rpf_core::Error::Cancelled {
                done,
                total,
            }));
        }
    }

    let manifest_path = into.join(rpf_core::MANIFEST_NAME);
    write_file(&manifest_path, manifest.to_json()?.as_bytes())?;

    Ok(Extracted {
        files: specs.len(),
        directories: manifest.directories.len(),
        manifest: manifest_path,
    })
}

/// `pack` — build an archive from a tree and its manifest.
pub fn pack(
    from: &Path,
    archive_path: &Path,
    force: bool,
    named_cache: Option<&Path>,
    json_out: bool,
) -> Result<()> {
    let report = pack_from(from, archive_path, force, named_cache, &mut OnStderr::new())?;

    if json_out {
        emit(&json!({
            "archive": archive_path.display().to_string(),
            "entries": report.entry_count,
            "len": report.len,
        }));
    } else {
        println!("{} entries, {} bytes", report.entry_count, report.len);
    }
    Ok(())
}

/// Builds an archive from a tree and its manifest, replacing whatever is at
/// `archive_path`.
///
/// Written to a temporary file in the same directory and renamed into place, so
/// a `pack` that is stopped part-way leaves the destination as it was (§8).
///
/// The archive is written at the version the manifest names, so a tree
/// extracted from one version cannot be packed as another. DR-018.
///
/// A tree whose manifest names an encrypted tag packs back under that tag's own
/// transform, and reaches key material the way every other command does:
/// [`unlock_for`], over `--cache-dir` or the platform's own cache, read only
/// where the tag names a transform this build can write forwards. `pack` opens
/// no archive, so the name that unlock carries is the **output** archive's —
/// and since DR-062 that route accepts NG, whose every region *is* keyed by
/// that name. Which is why the output's name is the right one and not merely a
/// harmless one: an archive is read back under the name it is written at, so
/// the name the table of contents is keyed by here is the name the reader will
/// key it by. An AES key is a function of neither (DR-054 §2, DR-057).
///
/// # Errors
///
/// [`Failure::GameInstall`] unless `force`, [`Failure::Io`] for a file in the
/// manifest that is not in the tree, and as `rpf_core::Manifest::pack_into`.
pub fn pack_from(
    from: &Path,
    archive_path: &Path,
    force: bool,
    named_cache: Option<&Path>,
    watch: &mut impl Watch,
) -> Result<rpf_core::Report> {
    refuse_game_install(archive_path, force)?;

    let manifest = manifest_in(from)?;
    let unlock = unlock_for(archive_path, named_cache);

    let directory = archive_path.parent().unwrap_or_else(|| Path::new("."));
    let mut scratch = tempfile::NamedTempFile::new_in(directory).map_err(|source| Failure::Io {
        path: directory.display().to_string(),
        source,
    })?;

    // A missing file is reported as itself rather than as a build failure: the
    // tree is the caller's, and naming the path is the actionable part.
    let mut missing = None;
    // The version the tree came out of, which the manifest has recorded since
    // schema 2 and which a schema-1 manifest is read as. DR-018: a tree
    // extracted from one version must not be packed as another, and this is
    // where that is honoured rather than defaulted.
    let report = manifest.pack_into(
        scratch.as_file_mut(),
        &unlock,
        |wanted: &str| {
            let source_path = from.join(wanted);
            match fs::File::open(&source_path) {
                Ok(handle) => Ok(handle),
                Err(error) => {
                    missing = Some((source_path, error));
                    Err(rpf_core::Error::BadPath {
                        path: wanted.to_owned(),
                        reason: "is in the manifest but not in the tree",
                    })
                }
            }
        },
        watch,
    );
    if let Some((path, source)) = missing {
        return Err(Failure::Io {
            path: path.display().to_string(),
            source,
        });
    }
    let report = report?;

    persist(scratch, archive_path)?;
    Ok(report)
}

/// Where a tree will land, resolved as far as the filesystem already goes.
///
/// An extraction may be told to write into a directory that does not exist
/// yet, at any depth, so this walks up until something resolves and joins the
/// rest back on. That is what makes a path a caller spelled relatively
/// comparable with the canonical path a session claimed — DR-009, whose test
/// is a path *and* a file identity, and the path half is useless against two
/// spellings of one directory.
///
/// It is not [`crate::serve`]'s `target_of`, which resolves the *file* a pack
/// is about to create and requires the directory holding it to be there
/// already. Two questions, two answers.
///
/// # Errors
///
/// [`Failure::Refused`] for a path with no component that resolves at all,
/// which on any platform this runs on means one that names nothing.
fn resolved_root(into: &Path) -> Result<PathBuf> {
    let mut tail: Vec<&std::ffi::OsStr> = Vec::new();
    let mut here: &Path = into;
    for _ in 0..=into.components().count() {
        if let Ok(resolved) = fs::canonicalize(here) {
            let mut root = resolved;
            for name in tail.iter().rev() {
                root.push(name);
            }
            return Ok(root);
        }
        let Some(name) = here.file_name() else { break };
        tail.push(name);
        here = match here.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
    }
    Err(Failure::Refused {
        reason: format!(
            "{} does not name a directory to extract into",
            into.display()
        ),
    })
}

/// Creates a directory and everything above it.
fn create_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|source| Failure::Io {
        path: path.display().to_string(),
        source,
    })
}

/// Writes a file, reporting the path rather than the syscall.
fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).map_err(|source| Failure::Io {
        path: path.display().to_string(),
        source,
    })
}

/// Writes a file as its contents stream out of wherever they come from, and
/// answers how many bytes moved.
///
/// The two sides fail differently and are reported differently: what the
/// **read** fails with is the container's, recovered by `Error::carried`, so a
/// corrupt entry stays exit 4 naming the entry; what the **write** fails with
/// is this frontend's, and names the file it could not write.
fn stream_file<S: std::io::Read>(path: &Path, contents: &mut S) -> Result<u64> {
    let named = || path.display().to_string();
    let file = fs::File::create(path).map_err(|source| Failure::Io {
        path: named(),
        source,
    })?;
    // Buffered because `io::copy` moves in the sink's own buffer when the sink
    // has one, and in 8 KiB steps when it does not. Measured on the 145 MB
    // sample: `rpf extract` is 0.03 s buffered against 0.05 s unbuffered, three
    // warm rounds each, which is the whole of what streaming cost.
    let mut target = std::io::BufWriter::with_capacity(64 * 1024, file);
    let moved = std::io::copy(contents, &mut target).map_err(|source| {
        rpf_core::Error::carried(source).map_or_else(
            |source| Failure::Io {
                path: named(),
                source,
            },
            Failure::Container,
        )
    })?;
    // Flushed here rather than left to the drop, which has nowhere to report a
    // failure: the last write of the file is as able to fail as any other.
    target.flush().map_err(|source| Failure::Io {
        path: named(),
        source,
    })?;
    Ok(moved)
}

/// Refuses to write into a detected game installation, or below a directory
/// that would not say whether it is one.
fn refuse_game_install(path: &Path, force: bool) -> Result<()> {
    if force {
        return Ok(());
    }
    match install::detect(path) {
        Some(install::Detected::Installation(root)) => Err(Failure::GameInstall { root }),
        Some(install::Detected::Unexaminable(directory)) => {
            Err(Failure::UncertainInstall { directory })
        }
        None => Ok(()),
    }
}

/// Moves a freshly written archive into place, keeping any permissions the
/// file it replaces already had.
///
/// The replace is atomic in the sense that no reader sees a torn file at the
/// destination name; it is not a promise about power loss. On Windows and NTFS
/// it is refused for a read-only destination, and for one another program holds
/// open without allowing deletion — and on a volume that cannot do a
/// POSIX-semantics rename at all, a destination *this* process holds open is
/// refused too. DR-035.
///
/// # Errors
///
/// [`Failure::Io`] naming the archive if the scratch file cannot be flushed or
/// moved into place. Also if the replaced file's permissions cannot be put back
/// on afterwards, which is the one failure that leaves the **new archive in
/// place** — correct, complete, and carrying the scratch file's own mode.
pub fn persist(scratch: tempfile::NamedTempFile, path: &Path) -> Result<()> {
    let mut scratch = scratch;
    scratch
        .as_file_mut()
        .flush()
        .map_err(|source| Failure::Io {
            path: "<temporary file>".to_owned(),
            source,
        })?;

    // Read before the replace and applied after it. A temporary file is created
    // 0600, and silently tightening a file we replaced would be a surprise the
    // caller never asked for — but putting the mode on the *scratch* first
    // hands a read-only destination's own read-only bit to the file we may then
    // have to delete, and Windows refuses to delete one of those. Between the
    // two, the archive briefly carries 0600, which is the safe direction.
    let replaced = fs::metadata(path)
        .ok()
        .map(|existing| existing.permissions());

    // `fs::rename` rather than `NamedTempFile::persist`, which is
    // `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` on Windows and refuses to
    // replace a destination *anything* holds open — including this process,
    // which holds the archive it is rebuilding. Measured on Windows 11
    // 10.0.26200.9168, NTFS: `MoveFileExW` REFUSED (os error 5) with the
    // destination open through `File::open`, where `fs::rename` succeeded.
    // DR-035.
    let (file, scratch_path) = scratch.keep().map_err(|error| Failure::Io {
        path: path.display().to_string(),
        source: error.error,
    })?;
    drop(file);
    fs::rename(&scratch_path, path).map_err(|source| {
        // `keep` disarmed the delete-on-drop, so without this a failed replace
        // leaves the scratch beside the archive it did not become.
        drop(fs::remove_file(&scratch_path));
        Failure::Io {
            path: path.display().to_string(),
            source,
        }
    })?;

    if let Some(permissions) = replaced {
        fs::set_permissions(path, permissions).map_err(|source| Failure::Io {
            path: path.display().to_string(),
            source,
        })?;
    }
    Ok(())
}

/// The manifest inside an extracted tree.
///
/// One spelling of "where a tree's own record is" (§3): `pack` reads a tree
/// back through it, and `verify --against` checks an archive against it. A
/// manifest reached two ways is two facts to keep in step.
///
/// The tree is named, not the file: that is the vocabulary `extract`'s `into`
/// and `pack`'s `from` already use, and the file's name is `rpf-core`'s to
/// decide. DR-025.
///
/// # Errors
///
/// [`Failure::Io`] when there is no manifest in `tree`, or it cannot be read,
/// and as `rpf_core::Manifest::from_json` for one this build does not
/// understand.
pub fn manifest_in(tree: &Path) -> Result<rpf_core::Manifest> {
    let path = tree.join(rpf_core::MANIFEST_NAME);
    let text = fs::read_to_string(&path).map_err(|source| Failure::Io {
        path: path.display().to_string(),
        source,
    })?;
    Ok(rpf_core::Manifest::from_json(&text)?)
}

/// What a `verify` measured, and how far past the archive's own promises it
/// reached.
///
/// Three numbers rather than one, because "27 entries verified" is a weaker
/// claim than it reads: it means every entry was read back, and an archive says
/// nothing at all about a stored entry's bytes. DR-023, DR-025.
#[derive(Debug)]
pub struct Checked {
    /// The walk itself: what was read, and what did not come back.
    pub verified: rpf_core::Verified,
    /// How many checksums the manifest recorded. Zero when there was none.
    pub recorded: u32,
    /// The extracted tree whose manifest it was checked against.
    pub against: Option<PathBuf>,
}

impl Checked {
    /// Whether the manifest the caller named answered the question it was
    /// asked.
    ///
    /// Checksums are joined to entries by path, so a manifest describing a
    /// *different* archive names none of them: `Verified::against` reports no
    /// failure at all — deliberately, because a confident failure about a sound
    /// archive is worse than none — and `contents_checked` stays at zero.
    /// Printing that zero and succeeding is the other half of the same mistake,
    /// so the pairing is refused instead. It is the caller's to fix, which
    /// under DR-010 makes it a refusal and not the archive's fault.
    ///
    /// A walk that found problems reports those instead. They are the more
    /// important news, and on the wire an error would carry this sentence and
    /// drop the list. DR-025.
    ///
    /// # Errors
    ///
    /// [`Failure::Refused`] when a manifest was given and nothing at all was
    /// checked against it.
    fn answered(&self) -> Result<()> {
        let Some(ref tree) = self.against else {
            return Ok(());
        };
        if self.verified.contents_checked > 0 || !self.verified.problems.is_empty() {
            return Ok(());
        }
        let manifest = tree.join(rpf_core::MANIFEST_NAME).display().to_string();
        Err(Failure::Refused {
            reason: if self.recorded == 0 {
                format!(
                    "{manifest} records no checksum for any entry, so nothing was checked. \
                     Extract this archive again to write a tree whose manifest records them, \
                     or ask without a manifest to read every entry back on its own",
                )
            } else {
                format!(
                    "{manifest} records {} checksums and none of them names an entry of this \
                     archive, so nothing was checked. A manifest describes the archive it was \
                     extracted from — name the tree this archive was extracted to, or ask \
                     without a manifest to read every entry back on its own",
                    self.recorded,
                )
            },
        })
    }
}

/// Reads every entry back, against the manifest of an extracted tree when one
/// is named.
///
/// One walk either way (§4): "does this read back" is asked of every entry, and
/// a manifest adds "and are its contents what was recorded" to the ones it
/// names. A stored entry is the reason the second question exists — it declares
/// no inflated length and carries no deflate stream that ends, so nothing in
/// the archive says what its bytes should be. DR-023.
///
/// Digesting is bounded work per entry and happens inside the step that entry
/// already reports, so `done` and `total` are the same numbers with a manifest
/// and without one. DR-008.
///
/// # Errors
///
/// As [`manifest_in`] for a tree with no manifest in it, [`Failure::Refused`]
/// when the manifest names no entry this archive holds — [`Checked::answered`]
/// — and as `rpf_core::Verified::of` for a walk that could not finish.
pub fn verified<R: std::io::Read + std::io::Seek>(
    src: &mut R,
    archive: &Archive,
    against: Option<&Path>,
    watch: &mut impl Watch,
) -> Result<Checked> {
    let manifest = against.map(manifest_in).transpose()?;
    let walked = match manifest {
        Some(ref manifest) => rpf_core::Verified::against(src, archive, manifest, watch)?,
        None => rpf_core::Verified::of(src, archive, watch)?,
    };
    let checked = Checked {
        verified: walked,
        recorded: manifest.map_or(0, |manifest| {
            u32::try_from(manifest.checksums().len()).unwrap_or(u32::MAX)
        }),
        against: against.map(Path::to_path_buf),
    };
    checked.answered()?;
    Ok(checked)
}

/// One `verify` problem as JSON, for whichever frontend is reporting it.
///
/// An object with the path and the reason apart, on both frontends. The command
/// line answered `"path: reason"` until DR-027, which cannot be split back
/// apart: a reason carries colons of its own — `entry 0: payload did not
/// inflate` — so a consumer looking for the path got the whole sentence up to
/// the first one. A breaking change to `--json`, made in one place so the two
/// frontends cannot come to say different things again.
pub fn verify_problem(problem: &rpf_core::Problem) -> Value {
    json!({ "path": problem.path, "reason": problem.error.to_string() })
}

/// A `verify` report as JSON, for whichever frontend is reporting it.
///
/// One place, so `--json verify` and the daemon's answer carry the same numbers
/// under the same names (§1), and since DR-027 the same problems too.
pub fn verify_report(path: &Path, checked: &Checked, problems: &[Value]) -> Value {
    json!({
        "path": path.display().to_string(),
        "entries_checked": checked.verified.checked,
        "contents_checked": checked.verified.contents_checked,
        "contents_recorded": checked.recorded,
        "against": checked.against.as_ref().map(|tree| tree.display().to_string()),
        "problems": problems,
    })
}

/// What a `verify` measured, in the words a person reads.
///
/// Never the bare count: `contents_checked` is zero unless a manifest was
/// given, and a zero printed beside "27 entries verified" reads as a result
/// rather than as a question nobody asked. The gap between the two counts is
/// explained rather than left to be misread — measured on the sample, 7 of 27 —
/// and the explanation is the mechanism, because nothing here can tell an entry
/// inside a nested archive from one the manifest did not record. DR-025.
fn coverage(checked: &Checked) -> Vec<String> {
    let read = format!("{} entries read back", checked.verified.checked);
    let Some(ref tree) = checked.against else {
        return vec![format!("{read}; contents not checked (no manifest given)")];
    };

    let contents = checked.verified.contents_checked;
    let mut lines = vec![format!(
        "{read}; {contents} of {} recorded checksums checked against {}",
        checked.recorded,
        tree.display(),
    )];
    let uncovered = checked.verified.checked.saturating_sub(contents);
    if uncovered > 0 {
        lines.push(format!(
            "{uncovered} entries carry no recorded checksum: an entry inside a nested archive \
             is covered by the checksum of the entry that holds it",
        ));
    }
    let unmatched = checked.recorded.saturating_sub(contents);
    if unmatched > 0 {
        lines.push(format!(
            "{unmatched} recorded checksums name nothing this archive holds",
        ));
    }
    lines
}

/// `verify` — read every entry back and check it against what the archive says,
/// and against what a tree's manifest recorded when one is named.
pub fn verify(
    path: &Path,
    against: Option<&Path>,
    named_cache: Option<&Path>,
    json_out: bool,
) -> Result<()> {
    let (mut file, archive) = open(path, named_cache)?;
    let checked = verified(&mut file, &archive, against, &mut OnStderr::new())?;
    let problems = &checked.verified.problems;

    if json_out {
        let rendered: Vec<Value> = problems.iter().map(verify_problem).collect();
        emit(&verify_report(path, &checked, &rendered));
    } else {
        for problem in problems {
            println!("{}: {}", problem.path, problem.error);
        }
        for line in coverage(&checked) {
            println!("{line}");
        }
        if !problems.is_empty() {
            println!(
                "{} of {} entries failed",
                problems.len(),
                checked.verified.checked,
            );
        }
    }

    Ok(checked.verified.outcome()?)
}

/// Material found by scanning the executable.
const FROM_EXECUTABLE: &str = "executable";

/// Material read back from the cache instead of scanned for.
const FROM_CACHE: &str = "cache";

/// What a `keys` command found, and the whole of what it may say.
///
/// Offsets, lengths, a digest and paths. **No key crosses this boundary**: the
/// `Keys` a scan produces is dropped inside [`find_keys`], and nothing that
/// leaves it can render into key material because it holds none. DR-006, which
/// is also why `rpf_core::keys::Keys` writes its own `Debug`.
#[derive(Debug, Clone)]
pub struct KeysFound {
    /// The executable it came from, as the caller named it.
    pub executable: PathBuf,
    /// The SHA-256 of that file, which is what the cache is keyed by.
    pub source: String,
    /// [`FROM_EXECUTABLE`] or [`FROM_CACHE`].
    pub from: &'static str,
    /// Where the AES-256 key sits in the executable.
    pub aes_key_at: u64,
    /// Where the NG hash lookup table sits in the executable.
    pub hash_lut_at: u64,
    /// Where the launcher's own AES key sits, where the source carried it.
    ///
    /// `None` for every game executable and every memory image of one: it is in
    /// `Launcher.exe` and nothing else measured here. An offset, never a key —
    /// which is what makes it safe for this struct to hold. DR-020, DR-042.
    pub launcher_key_at: Option<u64>,
    /// The NG material, where the source carried it.
    ///
    /// `None` for every game executable measured, and `Some` for a memory image
    /// of one. Its absence is not a failure: an archive with the AES tag needs
    /// nothing here. DR-040.
    pub ng: Option<NgFound>,
    /// The cache it was written to or read from, if this machine has one.
    pub cache: Option<PathBuf>,
}

/// The NG material a source carried, said in what may be said about it.
///
/// Counts and positions. Like [`KeysFound`], it holds no key and so cannot
/// render into one. DR-006, DR-020.
#[derive(Debug, Clone, Copy)]
pub struct NgFound {
    /// How many expanded keys were found, which is all of them or this is not
    /// reported at all.
    pub expanded_keys: usize,
    /// Where the expanded keys start in the source.
    pub expanded_keys_at: u64,
    /// How many decrypt tables were found.
    pub decrypt_tables: usize,
    /// Where the decrypt tables start in the source.
    pub decrypt_tables_at: u64,
}

/// A key cache, and a count of its entries.
#[derive(Debug, Clone)]
pub struct CacheCount {
    /// Where it is, or `None` where the environment does not say.
    pub directory: Option<PathBuf>,
    /// How many entries: held, for `keys cache`; removed, for
    /// `keys invalidate`.
    pub entries: usize,
}

/// The cache a `keys` command works on: the one named, or the platform's.
///
/// `None` is a complete answer rather than a failure — no `HOME` on a Unix, no
/// `%APPDATA%` on Windows — and the material is still extracted. `rpf_core`'s
/// `Cache::platform` says the same.
fn cache_of(named: Option<&Path>) -> Option<Cache> {
    match named {
        Some(directory) => Some(Cache::at(directory)),
        None => Cache::platform(),
    }
}

/// Finds the key material in a game executable, caching what it found.
///
/// The cache is keyed by the executable's own SHA-256, so a hit is material
/// from *this* file and the offsets it reports are true of it. There is no
/// stale entry to refresh — only entries for executables that are no longer
/// installed, which is what `keys invalidate` is for. R2.4, DR-017.
///
/// # Errors
///
/// [`Failure::Io`] if the executable cannot be read or the cache cannot be
/// written, naming which of the two; `Error::UnrecognisedExecutable` — exit 9 —
/// if the file carries neither value.
pub fn find_keys(
    executable: &Path,
    named_cache: Option<&Path>,
    watch: &mut impl Watch,
) -> Result<KeysFound> {
    let mut file = fs::File::open(executable).map_err(|source| at(executable, source))?;
    let source = SourceDigest::of(&mut file)?;
    let cache = cache_of(named_cache);

    if let Some(cache) = cache.as_ref()
        && let Some(material) = cache
            .load(&source)
            .map_err(|error| cache_failed(cache.directory(), error))?
    {
        return Ok(found(
            executable,
            &source,
            FROM_CACHE,
            &material,
            Some(cache),
        ));
    }

    file.rewind().map_err(|source| at(executable, source))?;
    let material = Material::extract(&mut file, watch)?;
    if let Some(cache) = cache.as_ref() {
        cache
            .store(&source, &material)
            .map_err(|error| cache_failed(cache.directory(), error))?;
    }
    Ok(found(
        executable,
        &source,
        FROM_EXECUTABLE,
        &material,
        cache.as_ref(),
    ))
}

/// What may be said about extracted material, and nothing else.
fn found(
    executable: &Path,
    source: &SourceDigest,
    from: &'static str,
    material: &Material,
    cache: Option<&Cache>,
) -> KeysFound {
    let keys = material.keys();
    KeysFound {
        executable: executable.to_path_buf(),
        source: source.hex(),
        from,
        aes_key_at: keys.aes_key_offset(),
        hash_lut_at: keys.hash_lut_offset(),
        launcher_key_at: material.launcher().map(LauncherKey::offset),
        ng: material.ng().map(|ng| NgFound {
            expanded_keys: NG_EXPANDED_KEY_COUNT,
            expanded_keys_at: ng.expanded_keys_offset(),
            decrypt_tables: NG_DECRYPT_TABLE_COUNT,
            decrypt_tables_at: ng.decrypt_tables_offset(),
        }),
        cache: cache.map(|cache| cache.directory().to_path_buf()),
    }
}

/// A cache read or write that failed, reported against the directory.
///
/// The container's own `Io` renders as "i/o failure at offset 0", which names
/// nothing anyone can act on. §2 converts at the seam, and the actionable half
/// is where the cache is.
fn cache_failed(directory: &Path, error: rpf_core::Error) -> Failure {
    match error {
        rpf_core::Error::Io { source, .. } => at(directory, source),
        other => Failure::Container(other),
    }
}

/// A filesystem failure reported against the path it happened on.
fn at(path: &Path, source: std::io::Error) -> Failure {
    Failure::Io {
        path: path.display().to_string(),
        source,
    }
}

/// Where extracted material is kept, and how many entries are there.
///
/// # Errors
///
/// [`Failure::Io`] if the directory exists and cannot be read.
pub fn cache_state(named: Option<&Path>) -> Result<CacheCount> {
    counted(cache_of(named), |cache| Ok(cache.entries()?.len()))
}

/// Removes every entry the cache holds, and says how many there were.
///
/// Whole rather than one entry at a time, and DR-020 says why: re-extraction
/// already replaces the entry for a given executable, so the only thing a
/// per-entry removal could do that extraction does not is leave the *other*
/// entries' key material on the machine.
///
/// # Errors
///
/// [`Failure::Io`] if the directory cannot be read or an entry cannot be
/// removed.
pub fn invalidate_keys(named: Option<&Path>) -> Result<CacheCount> {
    counted(cache_of(named), |cache| Ok(cache.clear()?))
}

/// One cache, counted by whichever of the two operations asked.
fn counted(cache: Option<Cache>, how: impl Fn(&Cache) -> Result<usize>) -> Result<CacheCount> {
    let entries = match cache.as_ref() {
        // The cache owns what one of its entries is (DR-024), and this owns
        // saying *where*: `Error::Io` carries an offset and no path, which is
        // meaningless for a directory that could not be read. The frontend is
        // the one that knows the directory, so it is the one that names it.
        Some(cache) => how(cache).map_err(|failure| match failure {
            Failure::Container(rpf_core::Error::Io { source, .. }) => at(cache.directory(), source),
            other => other,
        })?,
        None => 0,
    };
    Ok(CacheCount {
        directory: cache.map(|cache| cache.directory().to_path_buf()),
        entries,
    })
}

/// `keys extract` — find the key material a source carries.
///
/// # Errors
///
/// As [`find_keys`].
pub fn keys_extract(executable: &Path, cache: Option<&Path>, json_out: bool) -> Result<()> {
    let found = find_keys(executable, cache, &mut OnStderr::new())?;

    if json_out {
        emit(&keys_report(&found));
    } else {
        println!("source      {}", found.executable.display());
        println!("sha256      {}", found.source);
        println!("found in    {}", how_found(found.from));
        println!("aes key     {AES_KEY_LEN} bytes at {:#x}", found.aes_key_at);
        println!(
            "hash lut    {HASH_LUT_LEN} bytes at {:#x}",
            found.hash_lut_at
        );
        // Only where the source carries it, and there is no line for its
        // absence: an executable that does not hold it is every executable but
        // one, so a line saying so would be printed almost always and read
        // never. The NG line is the other way round, which is why it has one.
        if let Some(at) = found.launcher_key_at {
            println!("launcher    {AES_KEY_LEN} bytes at {at:#x}");
        }
        match found.ng {
            Some(ng) => {
                println!(
                    "ng keys     {} x {NG_EXPANDED_KEY_LEN} bytes at {:#x}",
                    ng.expanded_keys, ng.expanded_keys_at
                );
                println!(
                    "ng tables   {} x {NG_DECRYPT_TABLE_LEN} bytes at {:#x}",
                    ng.decrypt_tables, ng.decrypt_tables_at
                );
            }
            None => println!("ng material not in this source ({NG_ABSENT})"),
        }
        println!("cache       {}", readable(found.cache.as_deref()));
    }
    Ok(())
}

/// Where the material came from, as a person reads it.
///
/// The wire keeps saying `executable` — that value is a contract two suites
/// assert on and the editor client reads, and DR-040 decided against renaming
/// it in passing — but a memory image is not an executable, and the line a
/// person reads should not tell them it is.
fn how_found(from: &str) -> &'static str {
    if from == FROM_CACHE {
        "the cache"
    } else {
        "this source"
    }
}

/// What to tell someone whose source carried no NG material.
///
/// Said once, because the human line and the JSON field are the same fact and
/// §1 is why they must not drift. It is not an error and does not read as one:
/// every archive outside the NG set opens without it. DR-040.
///
/// It says where the material *can* be found and does not claim anything about
/// the source in hand. "A memory image of one does" was true while an
/// executable was the only source anyone could pass, and this change made it
/// conditional: an image taken before the module finished loading, of the wrong
/// process, or carved short carries none of it either, and telling that user
/// their image does is the one case this line is most likely to be read in.
const NG_ABSENT: &str =
    "an executable never carries it; it is in the clear only in a memory image of a running game";

/// `keys cache` — where extracted material is kept, and how much is there.
///
/// # Errors
///
/// As [`cache_state`].
pub fn keys_cache(cache: Option<&Path>, json_out: bool) -> Result<()> {
    let state = cache_state(cache)?;

    if json_out {
        emit(&cache_report(&state));
    } else {
        println!("cache   {}", readable(state.directory.as_deref()));
        println!("entries {}", state.entries);
    }
    Ok(())
}

/// `keys invalidate` — remove every cached entry.
///
/// # Errors
///
/// As [`invalidate_keys`].
pub fn keys_invalidate(cache: Option<&Path>, json_out: bool) -> Result<()> {
    let state = invalidate_keys(cache)?;

    if json_out {
        emit(&invalidated_report(&state));
    } else {
        println!(
            "removed {} entries from {}",
            state.entries,
            readable(state.directory.as_deref()),
        );
    }
    Ok(())
}

/// One extraction as JSON, for whichever frontend is reporting it.
///
/// One place for the shape, as `listing_row` is for a listed entry: `--json
/// keys extract` and the daemon's `keys.extract` are the same object, and a
/// second spelling of it is how two frontends drift apart (§1). Every field is
/// something DR-006 permits leaving the machine — an offset in decimal, a
/// length, the source executable's digest, and paths.
#[must_use]
pub fn keys_report(found: &KeysFound) -> Value {
    json!({
        "executable": found.executable.display().to_string(),
        "sha256": found.source,
        "from": found.from,
        "values": values_found(found),
        "ng": found.ng.is_some(),
        "cache": where_it_is(found.cache.as_deref()),
    })
}

/// The values an extraction found, each as a name, a length and a position.
///
/// The NG rows and the launcher key are present only when the source carried
/// them, so a consumer reads the list rather than assuming a fixed length — and
/// `ng` beside it answers the same question about the 373 without one. The
/// launcher key gets no such flag: it is one row, and a consumer that reads the
/// list at all has already answered it. DR-042.
fn values_found(found: &KeysFound) -> Value {
    let mut values = vec![
        json!({ "name": "aes_key", "len": AES_KEY_LEN, "at": found.aes_key_at }),
        json!({ "name": "hash_lut", "len": HASH_LUT_LEN, "at": found.hash_lut_at }),
    ];
    if let Some(at) = found.launcher_key_at {
        values.push(json!({ "name": "launcher_aes_key", "len": AES_KEY_LEN, "at": at }));
    }
    if let Some(ng) = found.ng {
        values.push(json!({
            "name": "ng_expanded_keys",
            "count": ng.expanded_keys,
            "len": NG_EXPANDED_KEY_LEN,
            "at": ng.expanded_keys_at,
        }));
        values.push(json!({
            "name": "ng_decrypt_tables",
            "count": ng.decrypt_tables,
            "len": NG_DECRYPT_TABLE_LEN,
            "at": ng.decrypt_tables_at,
        }));
    }
    Value::Array(values)
}

/// A cache and what it holds, as JSON.
#[must_use]
pub fn cache_report(state: &CacheCount) -> Value {
    json!({
        "cache": where_it_is(state.directory.as_deref()),
        "entries": state.entries,
    })
}

/// A cache and what it gave up, as JSON.
#[must_use]
pub fn invalidated_report(state: &CacheCount) -> Value {
    json!({
        "cache": where_it_is(state.directory.as_deref()),
        "removed": state.entries,
    })
}

/// A cache directory as JSON: its path, or `null` where there is none.
fn where_it_is(directory: Option<&Path>) -> Value {
    directory.map_or(Value::Null, |directory| {
        json!(directory.display().to_string())
    })
}

/// A cache directory as a person reads it, when there may not be one.
fn readable(directory: Option<&Path>) -> String {
    directory.map_or_else(
        || "(none: the environment does not say where a configuration directory is)".to_owned(),
        |directory| directory.display().to_string(),
    )
}

/// A readable name for an encryption tag.
pub fn encryption_name(tag: u32) -> String {
    if rpf_core::Version::Rpf7.is_open(tag) {
        "OPEN".to_owned()
    } else {
        format!("{tag:#010x}")
    }
}

/// Writes a value as one line of JSON.
fn emit(value: &Value) {
    let text = serde_json::to_string_pretty(value).unwrap_or_default();
    println!("{text}");
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        FROM_CACHE, FROM_EXECUTABLE, KeysFound, NG_ABSENT, NG_DECRYPT_TABLE_COUNT,
        NG_EXPANDED_KEY_COUNT, NgFound, OnStderr, Step, Watch as _, goes_to, keys_report, padding,
    };

    #[test]
    fn a_shorter_progress_line_covers_the_one_before_it() {
        // The reuse is a carriage return and spaces rather than the ANSI
        // erase-to-end-of-line, which a plain Windows console prints instead of
        // obeying. What the escape did, this has to do by hand. R10.9.
        assert_eq!(padding(20, 8).len(), 12, "the tail of the longer line");
        assert_eq!(padding(8, 20), "", "a longer line covers itself");
        assert_eq!(padding(8, 8), "", "the same width needs nothing");
        assert_eq!(padding(0, 40), "", "the first line has nothing to cover");
    }

    #[test]
    fn a_terminal_takes_text_and_nothing_else() {
        // Windows' console writer refuses bytes that are not UTF-8 and macOS'
        // terminal accepts them and is ruined by them. One rule for all three,
        // decided here rather than by whichever platform is running. R10.7.
        assert!(goes_to("hello".as_bytes(), true));
        assert!(goes_to("ä".as_bytes(), true), "text is text past ASCII");
        assert!(!goes_to(b"RSC7\xff\xfe", true));
        assert!(!goes_to(&[0x80], true), "a lone continuation byte");
    }

    #[test]
    fn what_an_extraction_reports_is_offsets_lengths_a_digest_and_paths() {
        // DR-006 at the one seam that could break it. This is the object both
        // frontends print, so the set of fields in it is the set of things key
        // extraction can put where somebody else can read them — a log, a bug
        // report, an automation's input. A field added without being thought
        // about fails here rather than on a user's machine.
        let found = KeysFound {
            executable: std::path::PathBuf::from("/games/GTA5.exe"),
            source: "0".repeat(64),
            from: FROM_CACHE,
            aes_key_at: 0x01E3_4C98,
            hash_lut_at: 0x01E3_4CC0,
            launcher_key_at: None,
            ng: None,
            cache: Some(std::path::PathBuf::from("/config/rpf")),
        };

        let reported = keys_report(&found);
        let mut fields: Vec<&str> = reported
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();
        assert_eq!(
            fields,
            ["cache", "executable", "from", "ng", "sha256", "values"]
        );

        let values = reported["values"].as_array().unwrap();
        assert_eq!(values.len(), 2);
        for value in values {
            let mut inner: Vec<&str> = value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            inner.sort_unstable();
            assert_eq!(inner, ["at", "len", "name"], "{value}");
        }
        assert_eq!(values[0]["len"], json!(32), "the AES key's length");
        assert_eq!(values[1]["len"], json!(256), "the lookup table's length");
        assert_eq!(reported["ng"], json!(false), "NG material claimed");
        assert_eq!(reported["cache"], json!("/config/rpf"));
    }

    #[test]
    fn an_extraction_that_found_ng_material_reports_counts_and_positions() {
        // The other half of the field-set check above, on the shape only a
        // memory image produces. What is added is two counts and two offsets —
        // 373 values summarised by how many there are and where they start, and
        // nothing that could render into one of them. DR-006, DR-020, DR-040.
        let found = KeysFound {
            executable: std::path::PathBuf::from("/dumps/gta5.dmp"),
            source: "0".repeat(64),
            from: FROM_EXECUTABLE,
            aes_key_at: 0x01E3_7E98,
            hash_lut_at: 0x01B7_E4C0,
            launcher_key_at: None,
            ng: Some(NgFound {
                expanded_keys: NG_EXPANDED_KEY_COUNT,
                expanded_keys_at: 0x01E3_3120,
                decrypt_tables: NG_DECRYPT_TABLE_COUNT,
                decrypt_tables_at: 0x01E8_6CE0,
            }),
            cache: None,
        };

        let reported = keys_report(&found);
        assert_eq!(reported["ng"], json!(true));
        let values = reported["values"].as_array().unwrap();
        assert_eq!(values.len(), 4, "{reported}");
        assert_eq!(values[2]["name"], json!("ng_expanded_keys"));
        assert_eq!(values[2]["count"], json!(101));
        assert_eq!(values[2]["len"], json!(272));
        assert_eq!(values[3]["name"], json!("ng_decrypt_tables"));
        assert_eq!(values[3]["count"], json!(272));
        assert_eq!(values[3]["len"], json!(1024));
        for value in values {
            let inner: Vec<&str> = value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert!(
                inner
                    .iter()
                    .all(|name| { matches!(*name, "at" | "len" | "name" | "count") }),
                "a field that is not a position, a length or a count: {value}"
            );
        }
    }

    #[test]
    fn a_walk_that_stops_early_leaves_its_line_for_drop_to_close() {
        // The bug this pins had a visible symptom and one input that produced
        // it. `scan::find` stops the moment every anchor is found, which on a
        // 65 MB memory image is block 31 of 63, so the `done == total` arm that
        // closes the line was never reached and the report's first line landed
        // on top of the progress line:
        //
        //     31/63 key materialsource      /path/to/image
        //
        // Every other watched operation walks to its end, which is why this
        // survived until a scan could finish early. DR-040.
        let mut watching = OnStderr {
            silent: false,
            written: 0,
        };

        assert!(!watching.line_is_open(), "nothing written yet");
        watching.step(Step {
            path: "key material",
            done: 31,
            total: 63,
            bytes: 0,
        });
        assert!(
            watching.line_is_open(),
            "a walk that stopped early left no line to close, so the fix is \
             unreachable and the report will be printed on top of it"
        );

        // A walk that does reach its end closes its own line, and must not then
        // get a second newline from `Drop`.
        watching.step(Step {
            path: "key material",
            done: 63,
            total: 63,
            bytes: 0,
        });
        assert!(!watching.line_is_open(), "a finished walk left a line open");

        // A watcher nobody can see never has a line to close either way.
        let mut piped = OnStderr {
            silent: true,
            written: 0,
        };
        piped.step(Step {
            path: "key material",
            done: 1,
            total: 63,
            bytes: 0,
        });
        assert!(!piped.line_is_open(), "a silent watcher wrote something");
    }

    #[test]
    fn what_a_missing_ng_survey_says_is_not_a_claim_about_the_source_in_hand() {
        // The sentence was true while an executable was the only source anyone
        // could pass. Now that an image can be passed, "a memory image of one
        // does" is asserted at precisely the user it is wrong for: the one
        // whose image was taken too early, or of the wrong process, or carved
        // short. It says where the material lives and takes no position on the
        // file that just came up empty. DR-040.
        assert!(
            !NG_ABSENT.contains("this"),
            "the line refers to the source in hand: {NG_ABSENT}"
        );
        assert!(
            NG_ABSENT.contains("running game"),
            "the line does not say what kind of image carries it: {NG_ABSENT}"
        );
        assert!(NG_ABSENT.is_ascii(), "{NG_ABSENT}");
    }

    #[test]
    fn an_extraction_that_found_the_launcher_key_reports_one_more_offset() {
        // The third half of the field-set check above, on the shape only
        // `Launcher.exe` produces. What is added is one row of the same three
        // fields every other row has — a name, a length and a position — and no
        // top-level field at all, so a client that knows this payload already
        // knows this one. DR-020, DR-042.
        let found = KeysFound {
            executable: std::path::PathBuf::from("/launcher/Launcher.exe"),
            source: "0".repeat(64),
            from: FROM_EXECUTABLE,
            aes_key_at: 0x005E_DDA0,
            hash_lut_at: 0x0048_F3A0,
            launcher_key_at: Some(0x005E_E3F0),
            ng: None,
            cache: None,
        };

        let reported = keys_report(&found);
        let mut fields: Vec<&str> = reported
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();
        assert_eq!(
            fields,
            ["cache", "executable", "from", "ng", "sha256", "values"],
            "the launcher key added a top-level field"
        );
        assert_eq!(reported["ng"], json!(false), "NG material claimed");

        let values = reported["values"].as_array().unwrap();
        assert_eq!(values.len(), 3, "{reported}");
        assert_eq!(values[2]["name"], json!("launcher_aes_key"));
        assert_eq!(values[2]["len"], json!(32), "an AES-256 key is 32 bytes");
        assert_eq!(values[2]["at"], json!(0x005E_E3F0));
        let mut inner: Vec<&str> = values[2]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        inner.sort_unstable();
        assert_eq!(inner, ["at", "len", "name"], "{}", values[2]);

        // A source without it says nothing about it rather than saying it is
        // absent: that is every executable but one.
        let without = KeysFound {
            launcher_key_at: None,
            ..found
        };
        let reported = keys_report(&without);
        assert_eq!(
            reported["values"].as_array().unwrap().len(),
            2,
            "{reported}"
        );
    }

    #[test]
    fn a_machine_with_no_configuration_directory_reports_no_cache() {
        // `Cache::platform` answers `None` where the environment does not say
        // where a configuration directory is, and that is a complete answer
        // rather than a failure: the material was still found.
        let found = KeysFound {
            executable: std::path::PathBuf::from("/games/GTA5.exe"),
            source: "0".repeat(64),
            from: FROM_CACHE,
            aes_key_at: 1,
            hash_lut_at: 2,
            launcher_key_at: None,
            ng: None,
            cache: None,
        };
        assert_eq!(keys_report(&found)["cache"], json!(null));
    }

    #[test]
    fn a_pipe_or_a_file_takes_anything() {
        // `rpf cat … > f && rpf put … f` is the round trip the command exists
        // for, and every resource in it is bytes rather than text.
        assert!(goes_to(b"RSC7\xff\xfe", false));
        assert!(goes_to(&[0x80], false));
        assert!(goes_to(&[], false));
    }
}
