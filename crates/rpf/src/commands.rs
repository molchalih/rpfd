//! The commands themselves.
//!
//! Every one of them is a thin call into `rpf-core`. Nothing here knows the
//! byte layout of an archive; if it did, the editor client could not do the
//! same thing. `docs/conventions.md` §1.

use std::{
    collections::BTreeMap,
    fs,
    io::{IsTerminal, Seek as _, Write},
    path::{Path, PathBuf},
};

use rpf_core::{
    Archive, Flow, ListedKind, Step, Unwatched, Watch,
    keys::{AES_KEY_LEN, Cache, HASH_LUT_LEN, Keys, SourceDigest},
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

/// Opens an archive file and parses its table of contents.
pub fn open(path: &Path) -> Result<(fs::File, Archive)> {
    let mut file = fs::File::open(path).map_err(|source| opening(path, source))?;
    let archive = Archive::open(&mut file)?;
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
pub fn info(path: &Path, inside: &str, json_out: bool) -> Result<()> {
    let (mut file, archive) = open(path)?;
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
        println!("unreferenced {}", summary.unreferenced_bytes);
    }
    Ok(())
}

/// `ls` — what is at a path.
pub fn ls(path: &Path, inside: &str, recursive: bool, json_out: bool) -> Result<()> {
    let (mut file, archive) = open(path)?;
    let rows = rpf_core::Listed::at(&mut file, &archive, inside, recursive)?;

    if json_out {
        emit(&Value::Array(rows.iter().map(listing_row).collect()));
    } else {
        for row in &rows {
            let (kind, len) = named(row);
            println!("{kind:<9} {len:>12}  {}", row.path);
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
    json!({ "path": listed.path, "kind": kind, "len": len })
}

/// What a listed entry is called, and the one number reported beside it.
///
/// A directory's number is how many children it holds and a file's is its
/// length; the two share a column because a listing is one table.
fn named(listed: &rpf_core::Listed) -> (&'static str, u64) {
    match listed.kind {
        ListedKind::Directory { children } => ("directory", u64::from(children)),
        ListedKind::Binary { len } => ("binary", len),
        ListedKind::Resource { len } => ("resource", len),
    }
}

/// `cat` — one entry's contents on standard output.
pub fn cat(path: &Path, inside: &str) -> Result<()> {
    let (mut file, archive) = open(path)?;
    let (holder, index) = archive.locate(&mut file, inside)?;
    if holder.entry(index)?.is_directory() {
        return Err(Failure::Refused {
            reason: format!("{inside} is a directory"),
        });
    }
    // `extract`, not `read`: this has to be the same form `put` accepts, or
    // `rpf cat … > f && rpf put … f` would fail on every resource. For a binary
    // entry the two are identical; for a resource `extract` keeps the RSC7
    // header, which is what the file is outside the archive.
    let bytes = holder.extract(&mut file, index)?;
    let out = std::io::stdout();
    // Refused at this tool's own boundary rather than at the platform's. On
    // Windows the standard library's console writer declines bytes that are not
    // UTF-8 — so `cat` of a resource inside a terminal failed with a sentence
    // about UTF-8, exit 7, while the same command redirected worked, and the
    // same command on macOS filled the terminal with a resource. One rule
    // instead, the same on all three: a terminal takes text, and anything else
    // goes to a file or a pipe. R10.7.
    if !goes_to(&bytes, out.is_terminal()) {
        return Err(Failure::Refused {
            reason: format!(
                "{inside} is not text and standard output is a terminal; \
                 redirect it to a file or a pipe"
            ),
        });
    }
    out.lock().write_all(&bytes).map_err(|source| Failure::Io {
        path: "<stdout>".to_owned(),
        source,
    })
}

/// How a write is allowed to happen.
///
/// Grouped rather than passed as three more parameters: `put` was already at
/// the argument and boolean limits `clippy.toml` sets, and a call site reading
/// `put(a, b, c, false, false, true)` says nothing about which `false` is which.
#[derive(Debug, Clone, Copy, clap::Args)]
pub struct WriteOptions {
    /// Write even into a detected game installation.
    #[arg(long)]
    pub force: bool,
    /// Rebuild the whole archive rather than patching in place. Slower, and
    /// atomic: an interrupted rebuild leaves the original untouched.
    #[arg(long)]
    pub rebuild: bool,
    /// Report what would be written, and write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

/// `put` — replace one entry.
///
/// Prefers patching in place: if the new payload fits where the old one sits,
/// only that payload and its entry row are written, and an archive of any size
/// costs the same as the file being put. `docs/approach.md`. When it does not
/// fit, or `rebuild` is asked for, the archive is rebuilt to a temporary file
/// and renamed into place.
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
pub fn put(
    path: &Path,
    inside: &str,
    from: &Path,
    options: WriteOptions,
    json_out: bool,
) -> Result<()> {
    refuse_game_install(path, options.force)?;

    let contents = fs::read(from).map_err(|source| Failure::Io {
        path: from.display().to_string(),
        source,
    })?;

    if !options.rebuild {
        // A dry run only reads: needing write permission to answer "what would
        // this write do" would make it useless on the archives worth asking
        // about.
        let mut file = if options.dry_run {
            fs::File::open(path)
        } else {
            fs::OpenOptions::new().read(true).write(true).open(path)
        }
        .map_err(|source| Failure::Io {
            path: path.display().to_string(),
            source,
        })?;
        let archive = rpf_core::Archive::open(&mut file)?;

        let edits = BTreeMap::from([(inside.to_owned(), contents.clone())]);
        match rpf_core::plan(&mut file, &archive, &edits)? {
            rpf_core::Plan::Fits(patches) => {
                if !options.dry_run {
                    patches.apply(&mut file)?;
                }
                for entry in patches.planned() {
                    report_patch(inside, entry, options.dry_run, json_out);
                }
                return Ok(());
            }
            rpf_core::Plan::DoesNotFit(rejected) => {
                if options.dry_run {
                    for entry in &rejected {
                        report_would_rebuild(inside, entry, json_out);
                    }
                    return Ok(());
                }
                if !json_out {
                    for entry in &rejected {
                        eprintln!(
                            "rpf: {} bytes will not fit the {} available; rebuilding",
                            entry.needed, entry.allocation,
                        );
                    }
                }
            }
        }
    }

    if options.dry_run {
        // Reached only with --rebuild --dry-run: the rebuild was asked for
        // rather than forced by a payload that would not fit, so there is no
        // allocation to report against.
        if json_out {
            emit(&json!({ "method": "rebuild", "path": inside, "dry_run": true }));
        } else {
            println!("would rebuild the archive");
        }
        return Ok(());
    }

    let (mut file, archive) = open(path)?;
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let mut scratch = tempfile::NamedTempFile::new_in(directory).map_err(|source| Failure::Io {
        path: directory.display().to_string(),
        source,
    })?;

    let edits = BTreeMap::from([(inside.to_owned(), contents)]);
    let report = rpf_core::replace_many(
        &mut file,
        &archive,
        &edits,
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
fn report_patch(inside: &str, entry: &rpf_core::Planned, dry_run: bool, json_out: bool) {
    if json_out {
        emit(&json!({
            "method": "patch",
            "path": inside,
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

/// Reports that an edit would force a rebuild, and why.
fn report_would_rebuild(inside: &str, entry: &rpf_core::TooLarge, json_out: bool) {
    if json_out {
        emit(&json!({
            "method": "rebuild",
            "path": inside,
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
pub fn extract(path: &Path, into: &Path, json_out: bool) -> Result<()> {
    let (mut file, archive) = open(path)?;
    let reading = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let extracted = extract_into(
        &mut file,
        &archive,
        into,
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
/// Whatever `claimed` returns for a path this would write,
/// [`Failure::Io`] for a file or directory that could not be written,
/// `Error::Cancelled` when the watcher stops it, and as
/// `rpf_core::Manifest::of` for an archive whose names no host can hold.
pub fn extract_into<R: std::io::Read + std::io::Seek>(
    src: &mut R,
    archive: &Archive,
    into: &Path,
    claimed: &dyn Fn(&Path) -> Option<Failure>,
    watch: &mut impl Watch,
) -> Result<Extracted> {
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
        let contents = archive.extract(src, *index)?;
        write_file(&target, &contents)?;

        done = done.saturating_add(1);
        bytes = bytes.saturating_add(u64::try_from(contents.len()).unwrap_or(u64::MAX));
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
pub fn pack(from: &Path, archive_path: &Path, force: bool, json_out: bool) -> Result<()> {
    let report = pack_from(from, archive_path, force, &mut OnStderr::new())?;

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
/// # Errors
///
/// [`Failure::GameInstall`] unless `force`, [`Failure::Io`] for a file in the
/// manifest that is not in the tree, and as `rpf_core::build`.
pub fn pack_from(
    from: &Path,
    archive_path: &Path,
    force: bool,
    watch: &mut impl Watch,
) -> Result<rpf_core::Report> {
    refuse_game_install(archive_path, force)?;

    let manifest = manifest_in(from)?;
    let specs = manifest.specs();

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
    let report = rpf_core::build(
        scratch.as_file_mut(),
        manifest.version,
        &specs,
        &manifest.directories,
        |wanted| {
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
pub fn persist(scratch: tempfile::NamedTempFile, path: &Path) -> Result<()> {
    let mut scratch = scratch;
    scratch
        .as_file_mut()
        .flush()
        .map_err(|source| Failure::Io {
            path: "<temporary file>".to_owned(),
            source,
        })?;

    // A temporary file is created 0600. Silently tightening a file we replaced
    // would be a surprise the caller never asked for.
    if let Ok(existing) = fs::metadata(path) {
        fs::set_permissions(scratch.path(), existing.permissions()).map_err(|source| {
            Failure::Io {
                path: scratch.path().display().to_string(),
                source,
            }
        })?;
    }

    scratch.persist(path).map_err(|error| Failure::Io {
        path: path.display().to_string(),
        source: error.error,
    })?;
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

/// A `verify` report as JSON, for whichever frontend is reporting it.
///
/// One place, so `--json verify` and the daemon's answer carry the same numbers
/// under the same names (§1). `problems` is the caller's, because the command
/// line renders one as a sentence and the daemon as an object.
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
pub fn verify(path: &Path, against: Option<&Path>, json_out: bool) -> Result<()> {
    let (mut file, archive) = open(path)?;
    let checked = verified(&mut file, &archive, against, &mut OnStderr::new())?;
    let problems: Vec<String> = checked
        .verified
        .problems
        .iter()
        .map(|problem| format!("{}: {}", problem.path, problem.error))
        .collect();

    if json_out {
        let rendered: Vec<Value> = problems.iter().map(|problem| json!(problem)).collect();
        emit(&verify_report(path, &checked, &rendered));
    } else {
        for problem in &problems {
            println!("{problem}");
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
    /// The cache it was written to or read from, if this machine has one.
    pub cache: Option<PathBuf>,
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
pub fn find_keys(executable: &Path, named_cache: Option<&Path>) -> Result<KeysFound> {
    let mut file = fs::File::open(executable).map_err(|source| at(executable, source))?;
    let source = SourceDigest::of(&mut file)?;
    let cache = cache_of(named_cache);

    if let Some(cache) = cache.as_ref()
        && let Some(keys) = cache
            .load(&source)
            .map_err(|error| cache_failed(cache.directory(), error))?
    {
        return Ok(found(executable, &source, FROM_CACHE, &keys, Some(cache)));
    }

    file.rewind().map_err(|source| at(executable, source))?;
    let keys = Keys::extract(&mut file, &mut Unwatched)?;
    if let Some(cache) = cache.as_ref() {
        cache
            .store(&source, &keys)
            .map_err(|error| cache_failed(cache.directory(), error))?;
    }
    Ok(found(
        executable,
        &source,
        FROM_EXECUTABLE,
        &keys,
        cache.as_ref(),
    ))
}

/// What may be said about extracted material, and nothing else.
fn found(
    executable: &Path,
    source: &SourceDigest,
    from: &'static str,
    keys: &Keys,
    cache: Option<&Cache>,
) -> KeysFound {
    KeysFound {
        executable: executable.to_path_buf(),
        source: source.hex(),
        from,
        aes_key_at: keys.aes_key_offset(),
        hash_lut_at: keys.hash_lut_offset(),
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

/// `keys extract` — find the key material a game executable carries.
///
/// # Errors
///
/// As [`find_keys`].
pub fn keys_extract(executable: &Path, cache: Option<&Path>, json_out: bool) -> Result<()> {
    let found = find_keys(executable, cache)?;

    if json_out {
        emit(&keys_report(&found));
    } else {
        println!("executable  {}", found.executable.display());
        println!("sha256      {}", found.source);
        println!("found in    {}", found.from);
        println!("aes key     {AES_KEY_LEN} bytes at {:#x}", found.aes_key_at);
        println!(
            "hash lut    {HASH_LUT_LEN} bytes at {:#x}",
            found.hash_lut_at
        );
        println!("cache       {}", readable(found.cache.as_deref()));
    }
    Ok(())
}

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
        "values": [
            { "name": "aes_key", "len": AES_KEY_LEN, "at": found.aes_key_at },
            { "name": "hash_lut", "len": HASH_LUT_LEN, "at": found.hash_lut_at },
        ],
        "cache": where_it_is(found.cache.as_deref()),
    })
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

    use super::{FROM_CACHE, KeysFound, goes_to, keys_report, padding};

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
        assert_eq!(fields, ["cache", "executable", "from", "sha256", "values"]);

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
        assert_eq!(reported["cache"], json!("/config/rpf"));
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
