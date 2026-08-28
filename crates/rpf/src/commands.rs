//! The commands themselves.
//!
//! Every one of them is a thin call into `rpf-core`. Nothing here knows the
//! byte layout of an archive; if it did, the editor client could not do the
//! same thing. `docs/conventions.md` §1.

use std::{
    collections::BTreeMap,
    fs,
    io::{IsTerminal, Write},
    path::Path,
};

use rpf_core::{Archive, Flow, ListedKind, Step, Watch};
use serde_json::{Value, json};

use crate::{
    exit::{Failure, Result},
    install,
};

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

    let report = rpf_core::replace_at(
        &mut file,
        &archive,
        inside,
        contents,
        scratch.as_file_mut(),
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
pub fn extract(path: &Path, into: &Path, json_out: bool) -> Result<()> {
    let (mut file, archive) = open(path)?;
    let extracted = extract_into(&mut file, &archive, into, &mut OnStderr::new())?;

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
/// # Errors
///
/// [`Failure::Io`] for a file or directory that could not be written,
/// `Error::Cancelled` when the watcher stops it, and as
/// `rpf_core::Manifest::of` for an archive whose names no host can hold.
pub fn extract_into<R: std::io::Read + std::io::Seek>(
    src: &mut R,
    archive: &Archive,
    into: &Path,
    watch: &mut impl Watch,
) -> Result<Extracted> {
    let manifest = rpf_core::Manifest::of(archive)?;

    create_dir(into)?;
    for directory in &manifest.directories {
        create_dir(&into.join(directory))?;
    }

    let specs = rpf_core::specs_of(archive)?;
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

    let manifest_path = from.join(rpf_core::MANIFEST_NAME);
    let text = fs::read_to_string(&manifest_path).map_err(|source| Failure::Io {
        path: manifest_path.display().to_string(),
        source,
    })?;
    let manifest = rpf_core::Manifest::from_json(&text)?;
    let specs = manifest.specs();

    let directory = archive_path.parent().unwrap_or_else(|| Path::new("."));
    let mut scratch = tempfile::NamedTempFile::new_in(directory).map_err(|source| Failure::Io {
        path: directory.display().to_string(),
        source,
    })?;

    // A missing file is reported as itself rather than as a build failure: the
    // tree is the caller's, and naming the path is the actionable part.
    let mut missing = None;
    let report = rpf_core::build(
        scratch.as_file_mut(),
        &specs,
        &manifest.directories,
        |wanted| {
            let source_path = from.join(wanted);
            match fs::read(&source_path) {
                Ok(bytes) => Ok(bytes),
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

/// `verify` — read every entry back and check it against what the archive says.
pub fn verify(path: &Path, json_out: bool) -> Result<()> {
    let (mut file, archive) = open(path)?;
    let verified = rpf_core::Verified::of(&mut file, &archive, &mut OnStderr::new())?;
    let problems: Vec<String> = verified
        .problems
        .iter()
        .map(|problem| format!("{}: {}", problem.path, problem.error))
        .collect();

    if json_out {
        emit(&json!({
            "path": path.display().to_string(),
            "entries_checked": verified.checked,
            "problems": problems,
        }));
    } else if problems.is_empty() {
        println!("{} entries verified", verified.checked);
    } else {
        for problem in &problems {
            println!("{problem}");
        }
        println!("{} of {} entries failed", problems.len(), verified.checked);
    }

    Ok(verified.outcome()?)
}

/// A readable name for an encryption tag.
pub fn encryption_name(tag: u32) -> String {
    if tag == rpf_core::format::ENCRYPTION_OPEN {
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
    use super::{goes_to, padding};

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
    fn a_pipe_or_a_file_takes_anything() {
        // `rpf cat … > f && rpf put … f` is the round trip the command exists
        // for, and every resource in it is bytes rather than text.
        assert!(goes_to(b"RSC7\xff\xfe", false));
        assert!(goes_to(&[0x80], false));
        assert!(goes_to(&[], false));
    }
}
