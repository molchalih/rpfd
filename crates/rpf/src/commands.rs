//! The commands themselves, each a thin call into `rpf-core`.

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

/// Scratch space for a cascading rebuild: unnamed temporary files beside the
/// rebuilt archive.
#[derive(Debug)]
pub struct ScratchIn {
    directory: PathBuf,
}

impl ScratchIn {
    /// Scratch beside `path`, where the rebuilt archive is going.
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
        tempfile::tempfile_in(&self.directory)
            .map_err(|source| rpf_core::Error::Io { offset: 0, source })
    }
}

/// Progress on standard error, when it is a terminal.
struct OnStderr {
    silent: bool,
    /// How wide the line last written was, so the next one can cover it.
    written: usize,
}

impl OnStderr {
    /// Reports only if there is someone there to read it.
    fn new() -> Self {
        Self {
            silent: !std::io::stderr().is_terminal(),
            written: 0,
        }
    }

    /// Whether a line has been written that nothing has closed yet.
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

/// Ends the progress line, including for a scan that stopped early. `written`
/// is zero once a completed walk has closed its own line, so that case does not
/// get a second newline.
impl Drop for OnStderr {
    fn drop(&mut self) {
        if self.line_is_open() {
            eprintln!();
            self.written = 0;
        }
    }
}

/// Spaces enough to cover what a shorter line leaves behind. Spaces rather than
/// the ANSI erase-to-end-of-line, which a plain Windows console prints instead
/// of obeying.
fn padding(written: usize, now: usize) -> String {
    " ".repeat(written.saturating_sub(now))
}

/// What opens an archive at this path, if it turns out to be encrypted. An NG
/// archive's key is derived from the archive's own file name.
fn unlock_for(path: &Path, named_cache: Option<&Path>) -> rpf_core::Unlock {
    let Some(cache) = cache_of(named_cache) else {
        return rpf_core::Unlock::unkeyed();
    };
    // Lossy deliberately: a name this host cannot spell as UTF-8 hashes over
    // `EF BF BD` and chooses a key the packer did not, which the root-directory
    // check then refuses as `WrongKey`.
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    rpf_core::Unlock::cached(cache, name)
}

/// Opens an archive file and parses its table of contents. `named_cache` is
/// `--cache-dir`; `None` is the platform's own.
pub fn open(path: &Path, named_cache: Option<&Path>) -> Result<(fs::File, Archive)> {
    let mut file = fs::File::open(path).map_err(|source| opening(path, source))?;
    let archive = Archive::open(&mut file, &unlock_for(path, named_cache))?;
    Ok((file, archive))
}

/// Why an archive would not open, classified by who has to act on it. A path
/// that runs *past* a file is an in-archive path spelled as a filesystem one,
/// which is a refusal rather than an I/O failure.
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

/// `info` — the header, and what the entries add up to. `inside` is empty for
/// the archive itself, and names a nested archive otherwise.
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

/// One `ls` row as JSON, shared by `--json ls` and the daemon's `list`.
pub fn listing_row(listed: &rpf_core::Listed) -> Value {
    let (kind, len) = named(listed);
    json!({ "path": listed.path, "kind": kind, "len": len, "encoding": encoding_named(listed) })
}

/// What a listed entry is called, and the number beside it: a directory's
/// children, or a file's length.
fn named(listed: &rpf_core::Listed) -> (&'static str, u64) {
    match listed.kind {
        ListedKind::Directory { children } => ("directory", u64::from(children)),
        ListedKind::Binary { len, .. } => ("binary", len),
        ListedKind::Resource { len } => ("resource", len),
    }
}

/// What a listed entry's payload announces itself to be, spelled as
/// [`rpf_core::Encoding::name`] does. `None` for a directory, a resource, or a
/// binary entry nothing recognised.
fn encoding_named(listed: &rpf_core::Listed) -> Option<&'static str> {
    let ListedKind::Binary { encoding, .. } = listed.kind else {
        return None;
    };
    Some(encoding?.name())
}

/// A view, with the empty dictionary: an unnamed hash renders as
/// `hash_XXXXXXXX` and reads back as the same hash.
const fn wanted(view: View) -> rpf_core::view::Wanted<'static> {
    rpf_core::view::Wanted {
        view,
        names: Dictionary::EMPTY,
    }
}

/// The command line's spelling of [`View`], for `--as`.
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

/// `cat` — one entry's contents on standard output, or into `out`.
pub fn cat(
    path: &Path,
    inside: &str,
    view: View,
    out: Option<&Path>,
    named_cache: Option<&Path>,
    json_out: bool,
) -> Result<()> {
    let (mut file, archive) = open(path, named_cache)?;
    let (holder, index) = archive.locate(&mut file, inside)?;
    if holder.entry(index)?.is_directory() {
        return Err(Failure::Refused {
            reason: format!("{inside} is a directory"),
        });
    }
    if view != View::Raw {
        let viewed = rpf_core::view::read(&mut file, &holder, index, inside, wanted(view))?;
        return match out {
            Some(destination) => {
                write_file(destination, &viewed.bytes)?;
                report_written(destination, viewed.bytes.len() as u64, json_out);
                Ok(())
            }
            None => to_stdout(inside, &viewed.bytes),
        };
    }
    // `extract`, not `read`: this has to be the same form `put` accepts, or
    // `rpf cat … > f && rpf put … f` would fail on every resource.
    if let Some(destination) = out {
        let mut contents = holder.extracted(&mut file, index)?;
        let len = stream_file(destination, &mut contents)?;
        report_written(destination, len, json_out);
        return Ok(());
    }

    // A destination that is not a file has to see the bytes before it writes
    // any of them, because it may not take them at all.
    if holds_payloads() {
        let mut contents = holder.extracted(&mut file, index)?;
        let out = std::io::stdout();
        // Standard output is line-buffered, a 1 KiB buffer `io::copy` declines
        // to use.
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

/// Reports a payload written to a file, in place of the payload itself.
fn report_written(destination: &Path, len: u64, json_out: bool) {
    if json_out {
        emit(&json!({ "path": destination.display().to_string(), "len": len }));
    } else {
        println!("{len} bytes to {}", destination.display());
    }
}

/// Whether standard output is a regular file: the one destination that can hold
/// a payload nobody is going to read.
fn holds_payloads() -> bool {
    duplicated_stdout().is_some_and(|out| out.metadata().is_ok_and(|it| it.is_file()))
}

/// Standard output as a file this process owns and closes, on a platform whose
/// descriptors can be duplicated.
#[cfg(unix)]
fn duplicated_stdout() -> Option<fs::File> {
    use std::os::fd::AsFd as _;
    std::io::stdout()
        .as_fd()
        .try_clone_to_owned()
        .ok()
        .map(fs::File::from)
}

/// Standard output as a file this process owns and closes, on a platform whose
/// handles can be duplicated.
#[cfg(windows)]
fn duplicated_stdout() -> Option<fs::File> {
    use std::os::windows::io::AsHandle as _;
    std::io::stdout()
        .as_handle()
        .try_clone_to_owned()
        .ok()
        .map(fs::File::from)
}

/// Standard output as a file, on a platform that will not say: never one.
#[cfg(not(any(unix, windows)))]
fn duplicated_stdout() -> Option<fs::File> {
    None
}

/// Bytes onto standard output, under the rule that a destination which is not a
/// file takes text and nothing else.
fn to_stdout(inside: &str, bytes: &[u8]) -> Result<()> {
    if !goes_to(bytes, holds_payloads()) {
        return Err(Failure::Refused {
            reason: format!(
                "{inside} is not text and standard output is a terminal or a \
                 pipe; pass --out FILE, or redirect standard output to a file"
            ),
        });
    }
    let mut sink = std::io::BufWriter::with_capacity(64 * 1024, std::io::stdout().lock());
    sink.write_all(bytes)
        .and_then(|()| sink.flush())
        .map_err(|source| Failure::Io {
            path: "<stdout>".to_owned(),
            source,
        })
}

/// How a change to what an archive holds is allowed to happen.
#[derive(Debug, Clone, Copy, clap::Args)]
pub struct ChangeOptions {
    /// Write even into a detected game installation.
    #[arg(long)]
    pub force: bool,
    /// Report what would be written, and write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

/// How a write is allowed to happen: [`ChangeOptions`], plus what only
/// replacing an entry can be asked.
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
        // A regular file is opened when the library wants it, so a donor costs
        // a buffer rather than its length. Anything that can be neither
        // reopened nor seeked is read once and held.
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
        // A document is converted against the entry it is going into, so the
        // entry is read here.
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
/// It is opened when the bytes are wanted and never held.
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
    // `offset: 0`: the source is not the archive, so there is no offset in it
    // to name.
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

/// The payload a document at `from` becomes, against the entry it is going
/// into. The archive is opened for reading only, so `--dry-run` reaches it.
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
        // A path being created has no entry to convert against: `auto` takes
        // the bytes as they are and `xml` says why it cannot.
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

/// `mv` — move an entry to another path in the same archive. A destination the
/// archive already holds is refused rather than replaced.
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
    /// Written, or reported by a dry run. Nothing left to do.
    Done,
    /// The archive has to be rebuilt, and nothing has been written.
    MustRebuild,
}

/// Applies a set of changes to an archive, patching in place when every one of
/// them fits where it already sits and rebuilding when any does not.
///
/// A rebuild is atomic and a patch is not, and the report says which ran.
/// `dry_run` takes the same decision and stops before acting on it.
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
        // rather than forced, so there is no structural change to report.
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

/// Tries to write `changes` where the entries already sit. A dry run only
/// reads, so it needs no write permission.
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
            // A dry run has to answer a refusal as well as a plan, so `allows`
            // runs the resolution the rebuild runs and throws the result away.
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

/// Whether these bytes may go to standard output: a file takes anything, a
/// terminal and a pipe take text.
fn goes_to(bytes: &[u8], file: bool) -> bool {
    file || std::str::from_utf8(bytes).is_ok()
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

/// Reports that a change would force a rebuild because no patch can express it.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Existing {
    /// Refuse a target that holds anything. The default.
    Refuse,
    /// Write into it, replacing what an entry names and leaving the rest.
    Overwrite,
}

/// Refuses a target that already holds something: an extraction claims the tree
/// **is** the archive, which a tree holding files no entry names is not.
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

/// `extract` — write every entry to a tree, with the manifest beside it. The
/// source archive is claimed first, so an extraction cannot write over it.
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
/// Nested archives come out as the `.rpf` files they are, byte for byte.
/// `claimed` is asked of **every path this will write** before anything is
/// created, because a tree cannot be renamed into place.
pub fn extract_into<R: std::io::Read + std::io::Seek>(
    src: &mut R,
    archive: &Archive,
    into: &Path,
    existing: Existing,
    claimed: &dyn Fn(&Path) -> Option<Failure>,
    watch: &mut impl Watch,
) -> Result<Extracted> {
    // Before anything is created: a tree cannot be renamed into place, so a
    // refusal found part-way would leave the part written.
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
        // Streamed, so an extraction costs its buffer rather than its largest
        // entry.
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
/// `archive_path`. Written to a temporary file and renamed into place, so a
/// stopped `pack` leaves the destination as it was.
///
/// An encrypted tag packs back under that tag's own transform, keyed by the
/// **output** archive's name: an archive is read back under the name it is
/// written at.
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
    // actionable part is the path.
    let mut missing = None;
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

/// Where a tree will land, resolved as far as the filesystem already goes: the
/// target may not exist yet, at any depth, so this walks up until something
/// resolves and joins the rest back on.
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

/// Streams contents into a file, answering how many bytes moved. A failed read
/// stays the container's and names the entry; a failed write names the file.
fn stream_file<S: std::io::Read>(path: &Path, contents: &mut S) -> Result<u64> {
    let named = || path.display().to_string();
    let file = fs::File::create(path).map_err(|source| Failure::Io {
        path: named(),
        source,
    })?;
    // Buffered because `io::copy` moves in 8 KiB steps into an unbuffered sink.
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
    // failure.
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

/// Moves a freshly written archive into place, keeping any permissions the file
/// it replaces already had. No reader sees a torn file at the destination name.
///
/// # Errors
///
/// A failure to restore permissions leaves the **new archive in place**, whole
/// and carrying the scratch file's own mode.
pub fn persist(scratch: tempfile::NamedTempFile, path: &Path) -> Result<()> {
    let mut scratch = scratch;
    scratch
        .as_file_mut()
        .flush()
        .map_err(|source| Failure::Io {
            path: "<temporary file>".to_owned(),
            source,
        })?;

    // Read before the replace and applied after it: putting the mode on the
    // scratch first hands a read-only destination's own read-only bit to a file
    // Windows may then refuse to delete.
    let replaced = fs::metadata(path)
        .ok()
        .map(|existing| existing.permissions());

    // `fs::rename` rather than `NamedTempFile::persist`, which on Windows is
    // `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` and refuses to replace a
    // destination *anything* holds open — including this process.
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

/// The manifest inside an extracted tree. The tree is named, not the file,
/// whose name is `rpf-core`'s to decide.
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
    /// asked: one describing a *different* archive names no entry, checks
    /// nothing, and is refused rather than reported as a success.
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
/// is named. One walk either way.
///
/// A stored entry is why the manifest question exists: it declares no inflated
/// length and carries no deflate stream that ends, so nothing in the archive
/// says what its bytes should be.
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

/// One `verify` problem as JSON. Path and reason apart rather than as one
/// string: a reason carries colons of its own.
pub fn verify_problem(problem: &rpf_core::Problem) -> Value {
    json!({ "path": problem.path, "reason": problem.error.to_string() })
}

/// A `verify` report as JSON, shared by both frontends.
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

/// What a `verify` measured, in the words a person reads. Never the bare count:
/// the gap between the two counts is explained, because nothing here can tell
/// an entry inside a nested archive from one the manifest did not record.
fn coverage(checked: &Checked) -> Vec<String> {
    let read = format!("{} entries read back", checked.verified.checked);
    let Some(ref tree) = checked.against else {
        return vec![format!("{read}; contents not checked (no manifest given)")];
    };

    let contents = checked.verified.contents_checked;
    let unread = checked.verified.unread;
    let mut lines = vec![format!(
        "{read}; {contents} of {} recorded checksums checked against {}",
        checked.recorded,
        tree.display(),
    )];
    if unread > 0 {
        lines.push(format!(
            "{unread} entries did not read back as this archive describes them, so their \
             contents were not checked",
        ));
    }
    let uncovered = checked
        .verified
        .checked
        .saturating_sub(contents)
        .saturating_sub(unread);
    if uncovered > 0 {
        lines.push(format!(
            "{uncovered} entries carry no recorded checksum: an entry inside a nested archive \
             is covered by the checksum of the entry that holds it",
        ));
    }
    let unmatched = checked.recorded.saturating_sub(contents);
    if unmatched > 0 {
        lines.push(if unread == 0 {
            format!("{unmatched} recorded checksums name nothing this archive holds")
        } else {
            format!(
                "{unmatched} recorded checksums went unchecked: one naming an entry that did \
                 not read back cannot be told from one naming nothing this archive holds",
            )
        });
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

/// What a `keys` command found: offsets, lengths, a digest and paths. **No key
/// crosses this boundary.**
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
    /// `None` for anything but `Launcher.exe`. An offset, never a key.
    pub launcher_key_at: Option<u64>,
    /// The NG material, carried by a memory image and not by an executable. Its
    /// absence is not a failure: an archive with the AES tag needs none of it.
    pub ng: Option<NgFound>,
    /// The cache it was written to or read from, if this machine has one.
    pub cache: Option<PathBuf>,
}

/// The NG material a source carried, as counts and positions. It holds no key.
#[derive(Debug, Clone, Copy)]
pub struct NgFound {
    /// How many expanded keys were found: all of them, or nothing is reported.
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
/// `None` is a complete answer rather than a failure, and material is still
/// extracted.
fn cache_of(named: Option<&Path>) -> Option<Cache> {
    match named {
        Some(directory) => Some(Cache::at(directory)),
        None => Cache::platform(),
    }
}

/// Finds the key material in a game executable, caching what it found. The
/// cache is keyed by the executable's own SHA-256, so a hit is material from
/// *this* file and the offsets it reports are true of it.
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

/// A cache read or write that failed, reported against the directory rather
/// than as the container's offset-0 `Io`, which names nothing actionable.
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
pub fn cache_state(named: Option<&Path>) -> Result<CacheCount> {
    counted(cache_of(named), |cache| Ok(cache.entries()?.len()))
}

/// Removes every entry the cache holds, and says how many there were. Whole
/// rather than per-entry, so no other entry's key material is left behind.
pub fn invalidate_keys(named: Option<&Path>) -> Result<CacheCount> {
    counted(cache_of(named), |cache| Ok(cache.clear()?))
}

/// One cache, counted by whichever of the two operations asked.
fn counted(cache: Option<Cache>, how: impl Fn(&Cache) -> Result<usize>) -> Result<CacheCount> {
    let entries = match cache.as_ref() {
        // `Error::Io` carries an offset and no path; the frontend is the one
        // that knows the directory.
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
        // No line for its absence: every executable but one lacks it.
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

/// Where the material came from, as a person reads it. The wire keeps saying
/// `executable`, a contract value, but a memory image is not one.
fn how_found(from: &str) -> &'static str {
    if from == FROM_CACHE {
        "the cache"
    } else {
        "this source"
    }
}

/// What to tell someone whose source carried no NG material. It says where the
/// material *can* be found and claims nothing about the source in hand.
const NG_ABSENT: &str =
    "an executable never carries it; it is in the clear only in a memory image of a running game";

/// `keys cache` — where extracted material is kept, and how much is there.
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

/// One extraction as JSON, shared by `--json keys extract` and the daemon's
/// `keys.extract`. Every field is one that may leave the machine.
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

/// The values an extraction found, each as a name, a length and a position. The
/// list is not a fixed length: some rows appear only when the source has them.
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
        assert_eq!(padding(20, 8).len(), 12, "the tail of the longer line");
        assert_eq!(padding(8, 20), "", "a longer line covers itself");
        assert_eq!(padding(8, 8), "", "the same width needs nothing");
        assert_eq!(padding(0, 40), "", "the first line has nothing to cover");
    }

    #[test]
    fn a_terminal_or_a_pipe_takes_text_and_nothing_else() {
        assert!(goes_to("hello".as_bytes(), false));
        assert!(goes_to("ä".as_bytes(), false), "text is text past ASCII");
        assert!(!goes_to(b"RSC7\xff\xfe", false));
        assert!(!goes_to(&[0x80], false), "a lone continuation byte");
    }

    #[test]
    fn what_an_extraction_reports_is_offsets_lengths_a_digest_and_paths() {
        // The set of fields here is the set of things key extraction can put
        // where somebody else can read them.
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
        // The shape only a memory image produces: two counts and two offsets.
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
        // `scan::find` stops the moment every anchor is found, so the arm that
        // closes the line on `done == total` is never reached.
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

        // A walk that reaches its end closes its own line, and must not then
        // get a second newline from `Drop`.
        watching.step(Step {
            path: "key material",
            done: 63,
            total: 63,
            bytes: 0,
        });
        assert!(!watching.line_is_open(), "a finished walk left a line open");

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
        // The shape only `Launcher.exe` produces: one more row, and no
        // top-level field at all.
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
    fn a_file_takes_anything() {
        assert!(goes_to(b"RSC7\xff\xfe", true));
        assert!(goes_to(&[0x80], true));
        assert!(goes_to(&[], true));
    }
}
