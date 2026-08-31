//! Writes the metadata dump `RPF_METADATA` names: every `PSO`, `RBF` and
//! resource `Meta` payload in a corpus, out of its archive and onto disk.
//!
//! Run by hand, once per corpus, like `tools/oracle`. What it leaves behind is
//! the dump; what is committed is a fixture describing it. `README.md` says
//! how to run it and what the names mean.
//!
//! It holds no archive knowledge (`docs/conventions.md` §1): every offset,
//! every inflate, every decrypt and the resource page arithmetic are
//! `rpf-core`'s, and what is here is a walk, a recognition test and a file
//! name.

use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fmt,
    fs::{self, File},
    io::{self, Read, Seek, Write as _},
    path::{Path, PathBuf},
    process::ExitCode,
};

use metadata_dump::dumped_name;
use rpf_core::{
    Archive, Encoding, EntryKind, Unlock, archive::Nested, format::resource::size_from_flags,
    keys::Cache, metadata::meta,
};

/// Why a dump step stopped: the two layers below this one, kept apart.
///
/// §10 wants typed variants rather than a rendered sentence, and a frontend is
/// where the two are converted into one report. Nothing here is matched on —
/// the walk reports a failure and steps over it — but the source is not lost.
#[derive(Debug)]
enum Failure {
    /// The filesystem, which `rpf-core` never touches.
    Io(io::Error),
    /// The container.
    Archive(rpf_core::Error),
}

impl fmt::Display for Failure {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(source) => write!(out, "{source}"),
            Self::Archive(source) => write!(out, "{source}"),
        }
    }
}

impl From<io::Error> for Failure {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

impl From<rpf_core::Error> for Failure {
    fn from(source: rpf_core::Error) -> Self {
        Self::Archive(source)
    }
}

/// What a dumped payload turned out to be, and how the name says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    /// A binary entry whose contents open `PSIN`.
    Pso,
    /// A binary entry whose contents open `RBF0`.
    Rbf,
    /// A resource entry whose inflated payload carries [`meta::MAGIC`] at
    /// [`meta::MAGIC_AT`]. The only kind whose name carries a system length.
    Meta,
}

impl Kind {
    /// The word this kind is asked for by on the command line.
    const fn named(self) -> &'static str {
        match self {
            Self::Pso => "pso",
            Self::Rbf => "rbf",
            Self::Meta => "meta",
        }
    }

    /// Every kind, which is what a run with no `--kinds` writes.
    const ALL: [Self; 3] = [Self::Pso, Self::Rbf, Self::Meta];
}

/// What the run was asked to do.
#[derive(Debug)]
struct Request {
    /// The directory archives are found under, walked recursively.
    corpus: PathBuf,
    /// The directory payloads are written into. Created if absent.
    out: PathBuf,
    /// Which kinds to write.
    kinds: Vec<Kind>,
    /// Where the key cache lives, or `None` for the platform's own.
    cache: Option<PathBuf>,
}

impl Request {
    /// Reads the command line, or says what the usage is.
    fn parse(args: impl Iterator<Item = OsString>) -> Result<Self, String> {
        let mut positional = Vec::new();
        let mut kinds = Vec::new();
        let mut cache = None;
        let mut args = args.skip(1);
        while let Some(arg) = args.next() {
            match arg.to_str() {
                Some("--kinds") => {
                    let value = args.next().ok_or("--kinds wants a list")?;
                    let value = value.to_str().ok_or("--kinds wants UTF-8")?.to_owned();
                    for word in value.split(',').filter(|word| !word.is_empty()) {
                        let kind = Kind::ALL
                            .into_iter()
                            .find(|kind| kind.named() == word)
                            .ok_or_else(|| format!("no such kind: {word}"))?;
                        kinds.push(kind);
                    }
                }
                Some("--cache-dir") => {
                    cache = Some(PathBuf::from(
                        args.next().ok_or("--cache-dir wants a directory")?,
                    ));
                }
                Some(flag) if flag.starts_with("--") => {
                    return Err(format!("no such option: {flag}"));
                }
                _ => positional.push(PathBuf::from(arg)),
            }
        }
        let [corpus, out] = <[PathBuf; 2]>::try_from(positional).map_err(|_| {
            "usage: metadata-dump [--kinds pso,rbf,meta] [--cache-dir DIR] <corpus> <out>"
                .to_owned()
        })?;
        if kinds.is_empty() {
            kinds = Kind::ALL.to_vec();
        }
        Ok(Self {
            corpus,
            out,
            kinds,
            cache,
        })
    }

    /// Whether this run writes payloads of this kind.
    fn wants(&self, kind: Kind) -> bool {
        self.kinds.contains(&kind)
    }
}

/// What the walk has written and what it could not read.
#[derive(Debug, Default)]
struct Tally {
    /// Payloads written, by kind.
    written: BTreeMap<&'static str, usize>,
    /// Bytes written.
    bytes: u64,
    /// Entries that would not read back, and archives that would not open.
    refused: usize,
    /// Nested archives whose table of contents wanted a key that was not held.
    locked: usize,
}

impl Tally {
    /// How many payloads have been written, which is the next one's index.
    fn count(&self) -> usize {
        self.written
            .values()
            .copied()
            .fold(0, usize::saturating_add)
    }
}

/// One run: what it was asked for, and what it has written so far.
#[derive(Debug)]
struct Dump<'a> {
    /// What the run was asked to do.
    request: &'a Request,
    /// What it has written and what it could not read.
    tally: Tally,
}

impl<'a> Dump<'a> {
    /// Opens one archive file and walks it.
    ///
    /// The archive's own file name chooses its key, and turning a path into a
    /// name is the frontend's job — §7 keeps paths out of `rpf-core`.
    fn archive(&mut self, path: &Path, label: &str) -> Result<(), Failure> {
        let mut file = File::open(path)?;
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let cache = match &self.request.cache {
            Some(directory) => Some(Cache::at(directory)),
            None => Cache::platform(),
        };
        let unlock = cache.map_or_else(Unlock::unkeyed, |cache| Unlock::cached(cache, name));
        let archive = Archive::open(&mut file, &unlock)?;
        self.walk(&archive, &mut file, label);
        Ok(())
    }

    /// A run that has written nothing.
    const fn new(request: &'a Request) -> Self {
        Self {
            request,
            tally: Tally {
                written: BTreeMap::new(),
                bytes: 0,
                refused: 0,
                locked: 0,
            },
        }
    }

    /// Records one entry that would not read back.
    fn refuse(&mut self, what: &str, why: &dyn fmt::Display) {
        eprintln!("{what}: {why}");
        self.tally.refused = self.tally.refused.saturating_add(1);
    }

    /// Walks one archive's entry table, descending into every archive nested
    /// in it.
    ///
    /// One entry that will not read back is reported and stepped over rather
    /// than ending the walk: a corpus this size holds a few, and stopping at
    /// the first would dump a fraction of it and say it was done.
    fn walk<R: Read + Seek>(&mut self, archive: &Archive, src: &mut R, prefix: &str) {
        let count = u32::try_from(archive.entries().len()).unwrap_or(u32::MAX);
        for index in 0..count {
            let (Ok(entry), Ok(inside)) = (archive.entry(index), archive.path(index)) else {
                self.refuse(prefix, &format!("entry {index} does not read"));
                continue;
            };
            let kind = entry.kind;
            let path = format!("{prefix}/{inside}");
            let outcome = match kind {
                EntryKind::Directory { .. } => Ok(()),
                EntryKind::Binary { .. } => self.binary(archive, src, index, &path),
                EntryKind::Resource { system_flags, .. } => {
                    self.resource(archive, src, index, system_flags, &path)
                }
            };
            if let Err(failure) = outcome {
                self.refuse(&path, &failure);
            }
        }
    }

    /// A binary entry: a nested archive to descend into, or a payload to
    /// recognise.
    fn binary<R: Read + Seek>(
        &mut self,
        archive: &Archive,
        src: &mut R,
        index: u32,
        path: &str,
    ) -> Result<(), Failure> {
        match archive.nested_at(src, index)? {
            Nested::Open(nested) => {
                self.walk(&nested, src, path);
                return Ok(());
            }
            Nested::Locked(_) => {
                self.tally.locked = self.tally.locked.saturating_add(1);
                return Ok(());
            }
            Nested::None => {}
        }
        let kind = match archive.classify(src, index)?.encoding() {
            Some(Encoding::Pso) => Kind::Pso,
            Some(Encoding::Rbf) => Kind::Rbf,
            Some(Encoding::Xml | Encoding::Text) | None => return Ok(()),
        };
        if !self.request.wants(kind) {
            return Ok(());
        }
        let payload = archive.read(src, index)?;
        self.write(kind, path, &payload, None)
    }

    /// A resource entry: its inflated payload is a `Meta` or it is not.
    ///
    /// The system length is the entry's, from its system flags —
    /// `docs/rpf-format.md`, Resource page flags — and is the one thing about a
    /// dumped `Meta` that its own bytes do not state.
    fn resource<R: Read + Seek>(
        &mut self,
        archive: &Archive,
        src: &mut R,
        index: u32,
        system_flags: u32,
        path: &str,
    ) -> Result<(), Failure> {
        if !self.request.wants(Kind::Meta) {
            return Ok(());
        }
        let payload = archive.read(src, index)?;
        if !meta::identifies(&payload) {
            return Ok(());
        }
        self.write(
            Kind::Meta,
            path,
            &payload,
            Some(size_from_flags(system_flags)),
        )
    }

    /// Writes one payload out under the name the dump's layout gives it.
    ///
    /// Through a temporary name and a rename, and removed if either step fails:
    /// the index in a dumped name comes from a running count, so a run that
    /// stopped part-way through a `write_all` and was started again would put a
    /// *complete* payload under a name a truncated one already holds — and a
    /// truncated `Meta` is still recognised by `meta::identifies`, so the
    /// corpus tests would read it as a malformed shipped file. The same rule
    /// `docs/conventions.md` §8 states for an archive, for the same reason.
    fn write(
        &mut self,
        kind: Kind,
        path: &str,
        payload: &[u8],
        system_len: Option<u64>,
    ) -> Result<(), Failure> {
        let name = dumped_name(self.tally.count().saturating_add(1), path, system_len);
        let at = self.request.out.join(&name);
        let partial = self.request.out.join(format!("{name}.partial"));
        if let Err(failure) = Self::spill(&partial, payload).and_then(|()| {
            fs::rename(&partial, &at)?;
            Ok(())
        }) {
            drop(fs::remove_file(&partial));
            return Err(failure);
        }
        let written = self.tally.written.entry(kind.named()).or_default();
        *written = written.saturating_add(1);
        self.tally.bytes = self
            .tally
            .bytes
            .saturating_add(u64::try_from(payload.len()).unwrap_or(u64::MAX));
        Ok(())
    }

    /// One payload into one file, whole.
    fn spill(at: &Path, payload: &[u8]) -> Result<(), Failure> {
        let mut out = File::create(at)?;
        out.write_all(payload)?;
        Ok(())
    }
}

/// How deep [`collect`] descends before it stops rather than following a link
/// round again. A game install is a dozen directories deep at most.
const MAX_DEPTH: usize = 64;

fn main() -> ExitCode {
    let request = match Request::parse(env::args_os()) {
        Ok(request) => request,
        Err(complaint) => {
            eprintln!("{complaint}");
            return ExitCode::FAILURE;
        }
    };
    match run(&request) {
        Ok(tally) => {
            for (kind, count) in &tally.written {
                eprintln!("{count} {kind}");
            }
            eprintln!(
                "{} payloads, {} bytes, {} refused, {} locked",
                tally.count(),
                tally.bytes,
                tally.refused,
                tally.locked
            );
            ExitCode::SUCCESS
        }
        Err(failure) => {
            eprintln!("{failure}");
            ExitCode::FAILURE
        }
    }
}

/// Walks every archive under the corpus and writes what it recognises.
fn run(request: &Request) -> Result<Tally, Failure> {
    fs::create_dir_all(&request.out)?;
    let mut archives = Vec::new();
    collect(&request.corpus, &mut archives, 0)?;
    archives.sort();

    let mut dump = Dump::new(request);
    for path in &archives {
        let label = path
            .strip_prefix(&request.corpus)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if let Err(failure) = dump.archive(path, &label) {
            dump.refuse(&label, &failure);
        }
    }
    Ok(dump.tally)
}

/// Every `.rpf` under `root`, recursively, to [`MAX_DEPTH`].
///
/// `Path::is_dir` follows a symlink, so a directory linked to one of its own
/// ancestors is an unbounded descent — and this walks a game install, which is
/// somebody else's directory tree. The cap is what makes that a truncated walk
/// rather than a stack overflow.
fn collect(root: &Path, found: &mut Vec<PathBuf>, depth: usize) -> Result<(), io::Error> {
    if depth >= MAX_DEPTH {
        eprintln!("{}: deeper than {MAX_DEPTH}, not descended", root.display());
        return Ok(());
    }
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(&path, found, depth.saturating_add(1))?;
        } else if path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("rpf"))
        {
            found.push(path);
        }
    }
    Ok(())
}
