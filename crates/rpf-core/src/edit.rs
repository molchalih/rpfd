//! Changing what an archive holds, rather than what an entry holds.
//!
//! [`crate::patch`] answers "these are the new bytes of this entry" and
//! [`mod@crate::build`] answers "these are the files, make an archive of them".
//! Between them sits the question neither could be asked: add an entry, remove
//! one, rename one. R4.10, DR-026.
//!
//! **Every structural change rebuilds the archive.** An entry added or removed
//! changes the entry count, which changes the length of the entry table, which
//! moves the names blob, which moves the floor every payload has to sit above
//! — so nothing about the file after its header stays where it was. A rename
//! moves the names blob the same way. There is no in-place form of any of them,
//! and [`crate::plan`] says so with [`crate::Plan::Structural`] before anything
//! is written rather than discovering it entry by entry.
//!
//! **What is unverified.** That this crate's reader reads back what these
//! changes produce is tested here and against the sample. That the *runtime*
//! accepts an archive whose entry count is not the one its producer wrote is
//! Q8, it needs a machine running the game, and nothing in this repository can
//! answer it. DR-026 states that rather than leaving it to be assumed.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{self, Cursor, Read, Seek},
    sync::Arc,
};

use crate::{
    archive::Archive,
    build::{FileKind, FileSpec, Payload, Storage, directories_of, kind_of, specs_of},
    error::{Error, Result},
    format::{folded, resource::MAGIC_RSC7, same_name},
    name,
};

/// Where a [`Change::Write`]'s bytes come from, opened whenever they are
/// wanted.
///
/// A seam the library asks and the frontend answers, exactly as [`Scratch`]
/// is for scratch space — DR-022's shape, and the reason paths do not appear
/// inside this crate (`docs/conventions.md` §7). The command line answers with
/// the donor file it was given, so the bytes are never resident; the daemon
/// answers with [`Bytes`], because a payload that arrived over a pipe is
/// already in hand and reopening it would mean asking the client for it again.
///
/// **Opened more than once, and that is the point.** `tree_of` reads four
/// bytes to decide a new entry's kind, `plan` reads the whole payload to
/// compress it and measure the result, and a rebuild reads it again to write
/// it — so this answers a fresh stream each time rather than one the callers
/// have to rewind between them.
///
/// `Send + Sync` because [`Change`] carried an `Arc<Vec<u8>>` and was both, and
/// a trait object silently taking that away from a public type is a break with
/// no deprecation for any consumer that moves a set into a thread.
///
/// [`Scratch`]: crate::Scratch
pub trait Contents: fmt::Debug + Send + Sync {
    /// The bytes, from their start.
    ///
    /// # Errors
    ///
    /// Whatever the source cannot be opened as.
    fn open(&self) -> Result<Box<dyn Payload + '_>>;

    /// How many bytes there are, without reading them.
    ///
    /// # Errors
    ///
    /// Whatever the source cannot be measured with.
    fn len(&self) -> Result<u64>;

    /// Whether there are none.
    ///
    /// # Errors
    ///
    /// As [`Contents::len`], which is what it asks.
    fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}

/// Contents a caller already holds.
///
/// Shared rather than owned, because `split` divides a set into one set per
/// nested archive and a cascading rebuild splits again at every level: a
/// payload owned here would be one copy of it per level. Measured 2026-08-29,
/// before this was shared — an 11 MB donor through `rpf put` peaked at 33.5 MB
/// of live heap, and a rebuild of a payload 6 MB larger added 12 MB to its own
/// peak. DR-032.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bytes(Arc<Vec<u8>>);

impl Bytes {
    /// Holds `contents`.
    #[must_use]
    pub fn new(contents: Vec<u8>) -> Self {
        Self(Arc::new(contents))
    }
}

impl Contents for Bytes {
    fn open(&self) -> Result<Box<dyn Payload + '_>> {
        Ok(Box::new(Cursor::new(self.0.as_slice())))
    }

    fn len(&self) -> Result<u64> {
        Ok(u64::try_from(self.0.len()).unwrap_or(u64::MAX))
    }
}

/// One change to what an archive holds.
///
/// Keyed by the path it is about, which is why a rename carries only its
/// destination: the source is the key. At most one change per path, so a set
/// cannot ask for two things at one address (§5).
#[derive(Debug, Clone)]
pub enum Change {
    /// New contents for a path.
    Write {
        /// The file as it exists **outside** the archive: for a resource, its
        /// `RSC7` header and still-deflated body. The same form
        /// [`Archive::extract`] returns.
        contents: Arc<dyn Contents>,
        /// Whether a path the archive does not hold is created rather than
        /// refused. Without it a write to a path that is not there is
        /// [`Error::NotFound`], which is what it has always been: creating an
        /// entry a caller merely misspelled is the failure that guards against.
        create: bool,
    },
    /// Remove the entry at a path.
    Remove {
        /// Whether a directory takes its children with it. Without it a
        /// directory that holds anything is refused, which is the shape every
        /// editor's `delete` already has.
        recursive: bool,
    },
    /// Move the entry at a path to another path in the same archive.
    ///
    /// The destination is a whole path, addressed exactly as the source is —
    /// from the archive the caller opened, through nesting — so a rename can
    /// move an entry between directories as well as change its name. A
    /// destination inside a *different* archive is refused: moving bytes across
    /// that boundary is two rebuilds and a re-encoding, not a rename.
    ///
    /// A directory takes everything below it. A destination the archive already
    /// holds is [`Error::AlreadyExists`] — removing it in the same change set
    /// is how a caller says it meant to replace it, and removals are applied
    /// first for exactly that reason. DR-026.
    RenameTo(String),
    /// Create a directory, and whatever above it is missing.
    MakeDirectory,
}

/// What a change is called when it has to be reported as one it is.
const ADDS_ENTRY: &str = "adds an entry";
/// As [`ADDS_ENTRY`].
const REMOVES_ENTRY: &str = "removes an entry";
/// As [`ADDS_ENTRY`].
const RENAMES_ENTRY: &str = "renames an entry";
/// As [`ADDS_ENTRY`].
const ADDS_DIRECTORY: &str = "adds a directory";

/// A change no in-place patch can express, and why.
///
/// [`crate::Plan::Structural`] carries these, so a dry run reports every one of
/// them rather than the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Structural {
    /// The path, as it was given.
    pub path: String,
    /// What the change does that no patch can: one of the four sentences this
    /// module owns.
    pub what: &'static str,
}

impl Structural {
    /// The reason `change` cannot be patched in place, or `None` when it can.
    ///
    /// A [`Change::Write`] is the one that depends on the archive rather than
    /// on itself — replacing an entry that is there is a patch, creating one
    /// that is not is a rebuild — so `exists` is asked of the caller that
    /// resolved it.
    pub(crate) fn of(path: &str, change: &Change, exists: bool) -> Option<Self> {
        let what = match *change {
            Change::Write { .. } if exists => return None,
            Change::Write { .. } => ADDS_ENTRY,
            Change::Remove { .. } => REMOVES_ENTRY,
            Change::RenameTo(_) => RENAMES_ENTRY,
            Change::MakeDirectory => ADDS_DIRECTORY,
        };
        Some(Self {
            path: path.to_owned(),
            what,
        })
    }
}

/// A set of changes to one archive, at most one per path.
///
/// Ordered by path, so the same set always reaches the same archive: an entry
/// table is laid out from the tree, and a tree assembled in a different order
/// is a different archive.
#[derive(Debug, Clone, Default)]
pub struct Changes {
    at: BTreeMap<String, Change>,
    /// The keys of `at` whose changes are not plain writes, which is an index
    /// over `at` rather than a second fact: `restructuring` recomputes it and a
    /// test says the two agree.
    ///
    /// It exists because the question "could anything in this set have moved
    /// what is at this path" is asked once per change offered, and answering it
    /// by walking the whole set is the shape that was measured to time out —
    /// four thousand buffered writes against a four-thousand-entry archive.
    /// Every one of those writes is a plain write, so this index is empty for
    /// the whole of that case. DR-032.
    structural: BTreeSet<String>,
}

/// Whether a change is one the archive's own answer about a path cannot
/// account for.
///
/// A plain [`Change::Write`] is not: it replaces an entry that is already
/// there, so it changes nothing about what the archive holds and can collide
/// with another change only at its own path. Everything else is, and
/// `Write { create: true }` with it — whether that one adds an entry depends on
/// the archive rather than on the set, so it is counted.
fn restructuring(change: &Change) -> bool {
    !matches!(*change, Change::Write { create: false, .. })
}

/// What a change already in a set is, for a refusal that has to name it.
fn does(change: &Change) -> &'static str {
    match *change {
        Change::Write { .. } => "a write",
        Change::Remove { .. } => "a removal",
        Change::RenameTo(_) => "a rename",
        Change::MakeDirectory => "a new directory",
    }
}

/// Where a change puts what it is about, when that is somewhere else.
fn destination(change: &Change) -> Option<&str> {
    match *change {
        Change::RenameTo(ref to) => Some(to.as_str()),
        _ => None,
    }
}

/// Whether two changes, each a path and where it puts things, can reach one
/// another.
///
/// Every refusal [`tree_of`] makes turns on whether the tree holds a path — the
/// source of a rename, its destination, a created path, a directory's children
/// — and a change can only alter that for paths at, under or above one of its
/// own two. So two changes with no such relation between any of their paths
/// cannot decide anything about each other, and leaving one out of the
/// resolution changes no answer.
fn reach(one: (&str, Option<&str>), other: (&str, Option<&str>)) -> bool {
    let (here, moves_to) = one;
    let (there, moves_onto) = other;
    let related = |a: &str, b: &str| at_or_under(a, b) || at_or_under(b, a);
    related(here, there)
        || moves_to.is_some_and(|to| related(to, there))
        || moves_onto.is_some_and(|onto| related(here, onto))
        || moves_to
            .zip(moves_onto)
            .is_some_and(|(to, onto)| related(to, onto))
}

impl Changes {
    /// A set with nothing in it.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A set of exactly one change.
    #[must_use]
    pub fn one(path: impl Into<String>, change: Change) -> Self {
        let mut changes = Self::new();
        changes.set(path, change);
        changes
    }

    /// New contents for paths the archive already holds, which is the whole of
    /// what a change set was before there were others.
    #[must_use]
    pub fn writing(edits: BTreeMap<String, Vec<u8>>) -> Self {
        Self {
            at: edits
                .into_iter()
                .map(|(path, contents)| {
                    (
                        path,
                        Change::Write {
                            contents: Arc::new(Bytes::new(contents)),
                            create: false,
                        },
                    )
                })
                .collect(),
            // Every one of them is a plain write, which is what the index
            // leaves out.
            structural: BTreeSet::new(),
        }
    }

    /// Records `change` at `path`, answering whatever was there before.
    ///
    /// A second change at a path **replaces** the first, which is what a map
    /// does. [`Changes::admits`] is what a caller assembling a set from
    /// separate requests asks first, because there the replacement is a change
    /// the caller asked for and no longer gets.
    pub fn set(&mut self, path: impl Into<String>, change: Change) -> Option<Change> {
        let path = path.into();
        if restructuring(&change) {
            self.structural.insert(path.clone());
        } else {
            self.structural.remove(&path);
        }
        self.at.insert(path, change)
    }

    /// Takes the change at `path` back out, answering what was there.
    ///
    /// One gesture withdrawn rather than all of them: creating a file and
    /// deleting it, or renaming an entry back to the name it started with,
    /// leaves a set that should hold neither change, and the only way to reach
    /// it was to drop the set and offer the rest again. DR-030 asked for this;
    /// DR-032 is where it was decided.
    pub fn forget(&mut self, path: &str) -> Option<Change> {
        self.structural.remove(path);
        self.at.remove(path)
    }

    /// Whether `change` can be recorded at `path` beside what is already here.
    ///
    /// A set holds one change per path, so a second change at a path drops the
    /// first — and a caller that asked for both is owed the refusal rather than
    /// the silence. Two **writes** are not that: saving one file twice is what
    /// an editor does and the later contents are what it means. Neither is the
    /// same change offered again.
    ///
    /// Exactly as spelled: `x/y` and `x//y` are one entry and two keys here,
    /// and the second is [`Error::Overlapping`] at the commit, which is where
    /// an archive is available to resolve them against.
    ///
    /// # Errors
    ///
    /// [`Error::Claimed`], naming what is in the way.
    pub fn admits(&self, path: &str, change: &Change) -> Result<()> {
        let Some(held) = self.at.get(path) else {
            return Ok(());
        };
        // Spelled out rather than derived: a write's contents may be a file
        // this crate never reads until it is asked to, so two of them cannot be
        // compared — and never needed to be. Two writes at one path are the
        // case the record calls a replacement (DR-032); everything else is the
        // same change offered twice.
        let same = match (held, change) {
            (Change::Write { .. }, Change::Write { .. })
            | (Change::MakeDirectory, Change::MakeDirectory) => true,
            (Change::Remove { recursive: held }, Change::Remove { recursive: asked }) => {
                held == asked
            }
            (Change::RenameTo(held), Change::RenameTo(asked)) => held == asked,
            _ => false,
        };
        if same {
            return Ok(());
        }
        Err(Error::Claimed {
            path: path.to_owned(),
            held: does(held),
        })
    }

    /// Whether anything in this set could change what the archive holds at
    /// `path`.
    ///
    /// What a caller asks before spending a walk of the entry table on a change
    /// the archive has already fully answered — a write to an entry that is
    /// there. `false` means the set cannot reach it, and costs a look at the
    /// changes that restructure rather than at all of them.
    #[must_use]
    pub fn bears_on(&self, path: &str) -> bool {
        self.restructuring_changes()
            .any(|(at, change)| reach((at, destination(change)), (path, None)))
    }

    /// The changes that are not plain writes, by the path they are at.
    fn restructuring_changes(&self) -> impl Iterator<Item = (&str, &Change)> {
        self.structural
            .iter()
            .filter_map(|at| self.at.get_key_value(at))
            .map(|(at, change)| (at.as_str(), change))
    }

    /// The change at `path`, if there is one.
    #[must_use]
    pub fn at(&self, path: &str) -> Option<&Change> {
        self.at.get(path)
    }

    /// The contents a [`Change::Write`] at `path` carries, unopened.
    ///
    /// What a reader asks when it wants what was written rather than what is on
    /// disk. `None` for a path with no change, and for a change that is not a
    /// write. The bytes are not read here — [`Contents::open`] is what reads
    /// them, and a caller that only wants the length asks [`Contents::len`].
    #[must_use]
    pub fn contents_at(&self, path: &str) -> Option<&dyn Contents> {
        match self.at.get(path) {
            Some(Change::Write { contents, .. }) => Some(&**contents),
            _ => None,
        }
    }

    /// Every path a change is recorded at, in order.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.at.keys().map(String::as_str)
    }

    /// Every change, by the path it is at, in order.
    ///
    /// The same iteration `for (path, change) in &changes` gives, and both
    /// exist because the language convention wants them to: an `IntoIterator`
    /// on a reference without an `iter` beside it is what
    /// `clippy::into_iter_without_iter` refuses.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Change)> {
        self.into_iter()
    }

    /// How many changes are in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.at.len()
    }

    /// Whether there is nothing to do.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.at.is_empty()
    }

    /// Forgets all of them.
    pub fn clear(&mut self) {
        self.at.clear();
        self.structural.clear();
    }
}

/// A `Changes` is iterated by reference and never by value: a set is applied
/// and then still describes what was applied.
impl<'a> IntoIterator for &'a Changes {
    type Item = (&'a str, &'a Change);
    type IntoIter = std::iter::Map<
        std::collections::btree_map::Iter<'a, String, Change>,
        fn((&'a String, &'a Change)) -> (&'a str, &'a Change),
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.at.iter().map(|(path, change)| (path.as_str(), change))
    }
}

/// Where one file of a rebuilt archive gets its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Source {
    /// From the entry of that index in the archive being rebuilt.
    Entry(u32),
    /// From the [`Change::Write`] recorded at that path.
    Written(String),
}

/// One file of the archive being written: what it will be, and where its bytes
/// come from.
///
/// The two together because they only mean anything together — the spec is what
/// [`crate::build`] is given and the source is what its `fetch` answers, and
/// splitting them into parallel slices is what put `write_payloads` over the
/// argument limit once already.
#[derive(Debug)]
pub(crate) struct Node {
    pub(crate) spec: FileSpec,
    pub(crate) source: Source,
}

/// The tree an archive becomes once a set of changes is applied to it.
#[derive(Debug)]
pub(crate) struct Tree {
    pub(crate) nodes: Vec<Node>,
    pub(crate) directories: Vec<String>,
}

impl Tree {
    /// The files, as [`crate::build`] takes them.
    pub(crate) fn files(&self) -> Vec<FileSpec> {
        self.nodes.iter().map(|node| node.spec.clone()).collect()
    }

    /// Where each file gets its bytes, by the path it will be written at.
    pub(crate) fn sources(&self) -> BTreeMap<&str, &Source> {
        self.nodes
            .iter()
            .map(|node| (node.spec.path.as_str(), &node.source))
            .collect()
    }

    /// Whether anything in the tree answers to `path`.
    ///
    /// Folded, because two paths differing only in case are one name to every
    /// reader of the result ([`crate::format::same_name`]), so a rename onto
    /// `B.TXT` beside `b.txt` is a rename onto something that is there.
    fn holds(&self, path: &str) -> bool {
        let wanted = folded(path);
        self.nodes
            .iter()
            .any(|node| folded(&node.spec.path) == wanted)
            || self.directories.iter().any(|held| folded(held) == wanted)
    }
}

/// Whether `path` is `under`, or is `under` itself.
///
/// Component-wise and case-folded, so `datastore` is not under `data` and
/// `DATA/a.txt` is. [`same_name`] rather than [`folded`] because this is asked
/// once per node of the tree per change of a set, and folding allocates a
/// string for each of them.
fn at_or_under(path: &str, under: &str) -> bool {
    let Some(head) = path.get(..under.len()) else {
        return false;
    };
    same_name(head, under)
        && match path.as_bytes().get(under.len()) {
            None => true,
            Some(&byte) => byte == b'/',
        }
}

/// `path` with the `from` prefix replaced by `to`, for a path that is `from` or
/// is under it.
fn moved(path: &str, from: &str, to: &str) -> String {
    match path.get(from.len()..) {
        Some(rest) if !rest.is_empty() => format!("{to}{rest}"),
        _ => to.to_owned(),
    }
}

/// Reads up to `into.len()` bytes, tolerating a source that answers in pieces.
///
/// A payload shorter than the buffer is not a failure: it is a file that is not
/// a resource.
fn fill(from: &mut dyn Read, into: &mut [u8]) -> Result<usize> {
    let mut filled = 0_usize;
    while filled < into.len() {
        let Some(rest) = into.get_mut(filled..) else {
            break;
        };
        match from.read(rest) {
            Ok(0) => break,
            Ok(read) => filled = filled.saturating_add(read),
            Err(ref error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Error::recovered(0, error)),
        }
    }
    Ok(filled)
}

/// The kind of entry a payload has to be written as.
///
/// The payload decides, because for a new entry there is no entry to ask. A
/// resource carries its own `RSC7` header and its page flags with it, and
/// nothing else could recover them; anything else is offered to the compressor,
/// which is what `build` does with every file `pack` gives it. DR-026, and Q7
/// is why this is safe on the evidence there is: 27 entries of the sample, zero
/// disagreements between the resource bit and the payload's own magic.
///
/// # Errors
///
/// Whatever the payload's own source fails to open or read with.
fn kind_for(contents: &dyn Contents) -> Result<FileKind> {
    // Four bytes off the front, not the payload: a 2.9 GB donor decides its own
    // kind for the price of one read.
    let mut magic = [0_u8; MAGIC_RSC7.len()];
    let read = fill(&mut *contents.open()?, &mut magic)?;
    Ok(if magic.get(..read) == Some(MAGIC_RSC7.as_slice()) {
        FileKind::Resource
    } else {
        FileKind::Binary {
            storage: Storage::Deflate,
            encryption: 0,
        }
    })
}

/// The entry `path` names in `archive`, refusing the root.
///
/// The root is not an entry a change may be about: an archive without its root
/// directory is not an archive, and every path is addressed from it.
fn entry_at(archive: &Archive, path: &str) -> Result<u32> {
    let index = archive.find(path)?;
    if index == 0 {
        return Err(Error::BadPath {
            path: path.to_owned(),
            reason: "is the archive's root",
        });
    }
    Ok(index)
}

/// The tree `archive` becomes once `changes` are applied to it.
///
/// Resolved in one pass per kind of change, and the order between the kinds is
/// part of the contract: **removals, then renames, then writes, then
/// directories.** Removals first is what lets one change set rename over a path
/// it also removes, which is how a caller says it meant to replace what was
/// there — a rename that silently destroyed an entry would be the one operation
/// on an archive with nothing to undo it. DR-026.
///
/// Every path is resolved against `archive`, and every refusal is decided
/// against the tree as it stands at that point, so the two together are what
/// makes the order visible rather than incidental.
///
/// # Errors
///
/// [`Error::NotFound`] for a change about a path the archive does not hold,
/// [`Error::AlreadyExists`] for a rename or a directory onto one it does,
/// [`Error::BadPath`] for the root, for a non-empty directory removed without
/// saying so, and for a name [`name::check_tree`] refuses,
/// [`Error::WrongKind`] for a write to a directory, and as [`specs_of`].
pub(crate) fn tree_of(archive: &Archive, changes: &Changes) -> Result<Tree> {
    check_one_each(archive, changes)?;
    let mut tree = Tree {
        nodes: specs_of(archive)?
            .into_iter()
            .map(|(spec, index)| Node {
                spec,
                source: Source::Entry(index),
            })
            .collect(),
        directories: directories_of(archive)?,
    };

    for (path, change) in changes {
        let Change::Remove { recursive } = *change else {
            continue;
        };
        remove(archive, &mut tree, changes, path, recursive)?;
    }
    for (path, change) in changes {
        let Change::RenameTo(ref to) = *change else {
            continue;
        };
        rename(archive, &mut tree, path, to)?;
    }
    for (path, change) in changes {
        let Change::Write {
            ref contents,
            create,
        } = *change
        else {
            continue;
        };
        write(archive, &mut tree, path, &**contents, create)?;
    }
    for (path, change) in changes {
        if !matches!(*change, Change::MakeDirectory) {
            continue;
        }
        make_directory(&mut tree, path)?;
    }

    Ok(tree)
}

/// Refuses a set in which two changes are about one entry.
///
/// `x/y`, `x//y` and `X/Y` are three spellings of one path and one entry, and a
/// set holding two of them asks for two things at one address. Applying both
/// silently lets the last one win and the loser vanish with an `Ok`, which is
/// the failure this exists for. [`crate::patch::plan`] refuses the same pair,
/// and the two write paths have to agree — a caller falling back from one to
/// the other would otherwise get a different archive depending on which ran.
fn check_one_each(archive: &Archive, changes: &Changes) -> Result<()> {
    let mut claimed: BTreeMap<u32, &str> = BTreeMap::new();
    for (path, _) in changes {
        let Ok(index) = archive.find(path) else {
            continue;
        };
        if let Some(other) = claimed.insert(index, path) {
            return Err(Error::Overlapping {
                path: path.to_owned(),
                other: other.to_owned(),
            });
        }
    }
    Ok(())
}

/// Whether `changes` puts anything below `held` that is not there yet.
///
/// A directory the set is about to write into is not empty, whatever the
/// archive says. Asked because [`tree_of`] applies removals before writes, so a
/// removal on its own sees only what is on disk. DR-038.
fn arrives_under(changes: &Changes, held: &str) -> bool {
    // The restructuring index, not the whole set: every arm below is a
    // restructuring change, so this is the same answer over a strictly smaller
    // walk — and DR-032 added that index precisely so a removal does not scan
    // four thousand plain writes to match none of them.
    changes
        .restructuring_changes()
        .any(|(at, change)| match *change {
            // A write to a path that already exists needs no room made for it,
            // and the tree already counts it. Only a creation adds one. The
            // path *at* `held` is the replacing case DR-026 allows, so it is
            // not an arrival — compared by name rather than by bytes, because
            // in this module two spellings of one name are one path.
            Change::Write { create: true, .. } | Change::MakeDirectory => {
                !same_name(at, held) && at_or_under(at, held)
            }
            Change::RenameTo(ref to) => !same_name(to, held) && at_or_under(to, held),
            _ => false,
        })
}

/// Takes the entry at `path` out of the tree, with its children when it is a
/// directory and `recursive`.
fn remove(
    archive: &Archive,
    tree: &mut Tree,
    changes: &Changes,
    path: &str,
    recursive: bool,
) -> Result<()> {
    let index = entry_at(archive, path)?;
    let held = archive.path(index)?;
    if !archive.entry(index)?.is_directory() {
        tree.nodes
            .retain(|node| !at_or_under(&node.spec.path, &held));
        return Ok(());
    }

    let children = tree
        .nodes
        .iter()
        .map(|node| node.spec.path.as_str())
        .chain(tree.directories.iter().map(String::as_str))
        .filter(|inside| *inside != held.as_str())
        .filter(|inside| at_or_under(inside, &held))
        .count();
    if !recursive && (children > 0 || arrives_under(changes, &held)) {
        return Err(Error::BadPath {
            path: held,
            reason: "is a directory that is not empty",
        });
    }
    tree.nodes
        .retain(|node| !at_or_under(&node.spec.path, &held));
    tree.directories
        .retain(|inside| !at_or_under(inside, &held));
    Ok(())
}

/// Moves the entry at `path`, and everything under it, to `to`.
fn rename(archive: &Archive, tree: &mut Tree, path: &str, to: &str) -> Result<()> {
    let index = entry_at(archive, path)?;
    let held = archive.path(index)?;
    name::check_tree(to)?;

    if !tree.holds(&held) {
        return Err(Error::NotFound {
            path: path.to_owned(),
            segment: path.rsplit('/').next().unwrap_or(path).to_owned(),
        });
    }
    if at_or_under(to, &held) {
        return Err(Error::BadPath {
            path: to.to_owned(),
            reason: "is inside the entry being renamed",
        });
    }
    if tree.holds(to) {
        return Err(Error::AlreadyExists {
            path: to.to_owned(),
        });
    }

    for node in &mut tree.nodes {
        if at_or_under(&node.spec.path, &held) {
            node.spec.path = moved(&node.spec.path, &held, to);
        }
    }
    for directory in &mut tree.directories {
        if at_or_under(directory, &held) {
            *directory = moved(directory, &held, to);
        }
    }
    Ok(())
}

/// Puts new contents at `path`, creating the entry when the archive does not
/// hold one and the caller asked for that.
fn write(
    archive: &Archive,
    tree: &mut Tree,
    path: &str,
    contents: &dyn Contents,
    create: bool,
) -> Result<()> {
    match archive.find(path) {
        Ok(0) => Err(Error::WrongKind {
            path: path.to_owned(),
            found: "directory",
            wanted: "file",
        }),
        Ok(index) => {
            // The entry's own storage rule is kept, which is what a replacement
            // has always meant: one that was stored stays stored, and one that
            // was deflated is offered to the compressor again. `kind_of`
            // refuses a directory, which is the other thing this has to answer.
            let kind = kind_of(path, archive.entry(index)?)?;
            let node = tree
                .nodes
                .iter_mut()
                .find(|node| node.source == Source::Entry(index))
                .ok_or_else(|| Error::NotFound {
                    path: path.to_owned(),
                    segment: path.rsplit('/').next().unwrap_or(path).to_owned(),
                })?;
            node.spec.kind = kind;
            node.source = Source::Written(path.to_owned());
            Ok(())
        }
        Err(error @ Error::NotFound { .. }) => {
            if !create {
                return Err(error);
            }
            name::check_tree(path)?;
            if tree.holds(path) {
                return Err(Error::AlreadyExists {
                    path: path.to_owned(),
                });
            }
            tree.nodes.push(Node {
                spec: FileSpec {
                    path: path.to_owned(),
                    kind: kind_for(contents)?,
                },
                source: Source::Written(path.to_owned()),
            });
            Ok(())
        }
        Err(other) => Err(other),
    }
}

/// Adds a directory, and leaves whatever above it is missing to `build`, which
/// creates a path's parents whether or not they were named.
fn make_directory(tree: &mut Tree, path: &str) -> Result<()> {
    name::check_tree(path)?;
    if tree.holds(path) {
        return Err(Error::AlreadyExists {
            path: path.to_owned(),
        });
    }
    tree.directories.push(path.to_owned());
    Ok(())
}

/// The nested archive a path lands in, and the path within it.
///
/// `None` when the path names something in `archive` itself — **including a
/// path nothing resolves at all**, which is the ordinary case for an addition:
/// a path the archive does not hold yet is a path in this archive, and the
/// components above it are directories to create.
///
/// Only the first nesting level: a change two archives down is grouped into the
/// first, and the recursion that rebuilds it groups it again.
///
/// # Errors
///
/// As [`Archive::child_named`] for a name more than one child answers to.
pub(crate) fn landing_of(archive: &Archive, path: &str) -> Result<Option<(u32, String)>> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut current = 0_u32;
    for (position, segment) in segments.iter().enumerate() {
        let Some(index) = archive.child_named(current, segment)? else {
            return Ok(None);
        };
        if archive.entry(index)?.is_directory() {
            current = index;
            continue;
        }
        let rest = segments.get(position.saturating_add(1)..).unwrap_or(&[]);
        if rest.is_empty() {
            return Ok(None);
        }
        return Ok(Some((index, rest.join("/"))));
    }
    Ok(None)
}

/// Whether `change` can be made at `path`, against the archive **and** against
/// the changes already buffered over it.
///
/// The same resolution a commit performs, run early and thrown away — so a
/// change this accepts is one the rebuild will not refuse for the same reason,
/// and the rules are written once rather than once here and once there (§3).
/// `buffered` is the set the change would join; a set holding the offered
/// change itself is fine, and the change at `path` is the one being replaced.
///
/// **It resolves the set, not one change.** It used to resolve each change
/// against the archive on disk alone, which made two answers wrong in both
/// directions: a rename onto a path a buffered removal frees was refused
/// although the commit accepts it, and a rename onto a path another buffered
/// rename claims was accepted although the commit does not. Both were measured
/// over the wire on 2026-08-29 and both are DR-030's; DR-032 is where they were
/// answered.
///
/// What it costs is a walk of the entry table, as before, plus work
/// proportional to the buffered changes that could bear on this one — never to
/// the buffered set as a whole and never to the archive twice. `bearing_on`.
///
/// A client buffers changes and commits them later, and a refusal is worth far
/// more at the moment the caller can still act on it. R7.1.
///
/// # Errors
///
/// As `tree_of` and as `split`, [`Error::Claimed`] for a second change of
/// another kind at `path`, and as [`Archive::locate`] for a path addressing
/// through a nested archive that will not open.
pub fn allows<R: Read + Seek>(
    src: &mut R,
    archive: &Archive,
    buffered: &Changes,
    path: &str,
    change: &Change,
) -> Result<()> {
    buffered.admits(path, change)?;
    let mut staged = bearing_on(buffered, path, change);
    staged.set(path, change.clone());
    let (here, nested) = split(archive, &staged)?;
    match landing_of(archive, path)? {
        None => tree_of(archive, &here).map(|_| ()),
        Some((index, _)) => {
            let holder = archive.open_nested(src, index)?;
            let nothing = Changes::new();
            let inside = nested.get(&index).map_or(&nothing, |group| &group.changes);
            tree_of(&holder, inside).map(|_| ())
        }
    }
}

/// The buffered changes that bear on `change` at `path`, and no others.
///
/// Two changes with no path in common between them decide nothing about each
/// other ([`reach`]), so resolving the offered change against the whole set and
/// against this subset give the same answer — and this subset is what keeps the
/// cost off the archive. What is scanned is the set's **restructuring**
/// changes; a plain write is scanned for only when the offered change is a
/// removal, because that is the one kind that can take an entry out from under
/// a write already buffered against it. Four thousand buffered writes, which is
/// the case that made an earlier `allows` time out, are none of either.
/// DR-032.
fn bearing_on(buffered: &Changes, path: &str, change: &Change) -> Changes {
    let offered = (path, destination(change));
    let mut staged = Changes::new();
    for (at, buffered_change) in buffered.restructuring_changes() {
        if at == path {
            continue;
        }
        if reach((at, destination(buffered_change)), offered) {
            staged.set(at, buffered_change.clone());
        }
    }
    if matches!(*change, Change::Remove { .. }) {
        for (at, buffered_change) in buffered {
            if at != path
                && matches!(*buffered_change, Change::Write { create: false, .. })
                && at_or_under(at, path)
            {
                staged.set(at, buffered_change.clone());
            }
        }
    }
    staged
}

/// Refuses a rename whose destination is in a different archive from its
/// source.
///
/// Moving bytes from one archive into another is two rebuilds and a
/// re-encoding, not a rename, and a path that crossed the boundary silently
/// would land as a *directory* named `something.rpf` inside the archive it came
/// from.
pub(crate) fn check_one_archive(archive: &Archive, from: &str, to: &str) -> Result<()> {
    let here = landing_of(archive, from)?.map(|(index, _)| index);
    let there = landing_of(archive, to)?.map(|(index, _)| index);
    if here == there {
        return Ok(());
    }
    Err(Error::BadPath {
        path: to.to_owned(),
        reason: "is inside another archive",
    })
}

/// A rename's destination as the archive it lands in spells it.
fn within_target(archive: &Archive, to: &str) -> Result<String> {
    Ok(match landing_of(archive, to)? {
        Some((_, within)) => within,
        None => to.to_owned(),
    })
}

/// Every change of a set, split into the ones this archive answers and the ones
/// a nested archive does.
///
/// The nested groups are keyed by the entry index of the archive they land in,
/// so several changes inside one nested archive rebuild it **once** rather than
/// once each.
///
/// # Errors
///
/// As [`landing_of`], and [`Error::BadPath`] for a rename across archives.
pub(crate) fn split(archive: &Archive, changes: &Changes) -> Result<(Changes, Grouped)> {
    let mut here = Changes::new();
    let mut nested: Grouped = BTreeMap::new();
    // Which change staked each path within each nested archive, so a second one
    // reaching it is refused **naming both spellings** rather than the archive
    // they share. `sub//inner.rpf//f.txt` and `sub/inner.rpf/f.txt` are two
    // strings and one entry, and which two collided is what a caller acts on.
    let mut staked: BTreeMap<(u32, String), &str> = BTreeMap::new();

    for (path, change) in changes {
        if let Change::RenameTo(ref to) = *change {
            check_one_archive(archive, path, to)?;
        }
        match landing_of(archive, path)? {
            None => {
                here.set(path, change.clone());
            }
            Some((index, within)) => {
                let within_change = match *change {
                    Change::RenameTo(ref to) => Change::RenameTo(within_target(archive, to)?),
                    ref other => other.clone(),
                };
                if let Some(other) = staked.insert((index, within.clone()), path) {
                    return Err(Error::Overlapping {
                        path: path.to_owned(),
                        other: other.to_owned(),
                    });
                }
                let group = nested.entry(index).or_insert_with(|| Nested {
                    first: path.to_owned(),
                    changes: Changes::new(),
                });
                group.changes.set(within, within_change);
            }
        }
    }

    // A change to a nested archive's own bytes and a change to something inside
    // it are the same bytes twice, and the two cannot both be written. The one
    // addressing *through* the archive is what is refused, because a path sorts
    // before every path under it, so the one naming the archive is what was
    // staked first.
    for (path, _) in &here {
        let Ok(index) = archive.find(path) else {
            continue;
        };
        if let Some(group) = nested.get(&index) {
            return Err(Error::Overlapping {
                path: group.first.clone(),
                other: path.to_owned(),
            });
        }
    }
    Ok((here, nested))
}

/// The changes landing inside one nested archive.
#[derive(Debug)]
pub(crate) struct Nested {
    /// The first change that addressed through this archive. It is what a
    /// change replacing the archive wholesale is reported as colliding with.
    pub(crate) first: String,
    /// The changes, spelled as paths within it.
    pub(crate) changes: Changes,
}

/// Nested change groups, by the entry index of the archive they land in.
pub(crate) type Grouped = BTreeMap<u32, Nested>;
