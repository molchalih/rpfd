//! Changing what an archive holds, rather than what an entry holds: add an
//! entry, remove one, rename one. Every such change rebuilds the archive,
//! because it moves the entry table and so every payload after it.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{self, Cursor, Read, Seek},
    sync::Arc,
};

use crate::{
    archive::{Archive, NestedTransform},
    build::{FileKind, FileSpec, Payload, Storage, directories_of, kind_of, specs_of},
    error::{Error, Result},
    format::{folded, resource::MAGIC_RSC7, same_name},
    metadata::Encoding,
    name,
};

/// Where a [`Change::Write`]'s bytes come from, opened whenever they are
/// wanted — more than once, so every call answers a fresh stream.
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

/// Contents a caller already holds, shared rather than owned so that a
/// cascading rebuild does not copy them once per nesting level.
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

/// One change to what an archive holds, keyed by the path it is about — which
/// is why a rename carries only its destination.
#[derive(Debug, Clone)]
pub enum Change {
    /// New contents for a path.
    Write {
        /// The file as it exists **outside** the archive, which is the form
        /// [`Archive::extract`] returns.
        contents: Arc<dyn Contents>,
        /// Whether a path the archive does not hold is created rather than
        /// refused with [`Error::NotFound`].
        create: bool,
        /// Whether the entry may end up holding a different encoding from the
        /// one it holds now, rather than [`Error::WrongEncoding`].
        allow_encoding_change: bool,
    },
    /// Remove the entry at a path.
    Remove {
        /// Whether a directory takes its children with it, rather than a
        /// directory holding anything being refused.
        recursive: bool,
    },
    /// Move the entry at a path to another path in the same archive.
    ///
    /// A directory takes everything below it, a destination inside a different
    /// archive is refused, and one the archive already holds is
    /// [`Error::AlreadyExists`] unless the same set removes it first.
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Structural {
    /// The path, as it was given.
    pub path: String,
    /// What the change does that no patch can.
    pub what: &'static str,
}

impl Structural {
    /// The reason `change` cannot be patched in place, or `None` when it can;
    /// a write is a patch when the entry is there and a rebuild when it is not.
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

/// A set of changes to one archive, at most one per path, ordered by path so
/// that the same set always reaches the same archive.
#[derive(Debug, Clone, Default)]
pub struct Changes {
    at: BTreeMap<String, Change>,
    /// The keys of `at` whose changes are not plain writes: an index over `at`
    /// rather than a second fact, so that reaching a path costs no full walk.
    structural: BTreeSet<String>,
}

/// Whether a change is one the archive's own answer about a path cannot
/// account for: everything but a plain [`Change::Write`].
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
/// another, which they can only for paths at, under or above one of their own.
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

    /// New contents for paths the archive already holds, each a plain write:
    /// neither creating an entry nor allowing its encoding to change.
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
                            allow_encoding_change: false,
                        },
                    )
                })
                .collect(),
            // Every one is a plain write, which the index leaves out.
            structural: BTreeSet::new(),
        }
    }

    /// Records `change` at `path`, replacing and answering whatever was there.
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
    pub fn forget(&mut self, path: &str) -> Option<Change> {
        self.structural.remove(path);
        self.at.remove(path)
    }

    /// Whether `change` can be recorded at `path` beside what is already here.
    ///
    /// A second change at a path drops the first, and the caller is owed the
    /// refusal; two **writes** are not that, nor is the same change again.
    /// Judged exactly as spelled, `x/y` and `x//y` being two keys here.
    ///
    /// # Errors
    ///
    /// [`Error::Claimed`], naming what is in the way.
    pub fn admits(&self, path: &str, change: &Change) -> Result<()> {
        let Some(held) = self.at.get(path) else {
            return Ok(());
        };
        // Spelled out rather than derived: a write's contents may be a file
        // this crate never reads, so two of them cannot be compared.
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
    /// `path`, answered over the restructuring changes alone.
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

    /// The contents a [`Change::Write`] at `path` carries, unopened, or `None`
    /// for a path with no change or a change that is not a write.
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

/// A set is iterated by reference: it is applied and then still describes it.
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

/// One file of the archive being written: the spec [`crate::build`] is given,
/// and the source its `fetch` answers.
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

    /// Whether anything in the tree answers to `path`, folded because two
    /// paths differing only in case are one name to every reader.
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
/// `DATA/a.txt` is; [`same_name`] rather than [`folded`] allocates nothing.
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

/// Reads up to `into.len()` bytes, tolerating a source that answers in pieces;
/// a payload shorter than the buffer is not a failure.
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

/// Refuses a payload that the entry it is being written into cannot hold.
///
/// Both write paths reach it here, so a caller falling back from one to the
/// other gets the same answer; `allowed` is the caller saying it meant this.
///
/// # Errors
///
/// [`Error::WrongEncoding`] for a payload a tokenised entry will not take, and
/// as [`Archive::classify`] and [`Contents::open`].
pub(crate) fn check_encoding<R: Read + Seek>(
    src: &mut R,
    archive: &Archive,
    index: u32,
    path: &str,
    contents: &dyn Contents,
    allowed: bool,
) -> Result<()> {
    if allowed {
        return Ok(());
    }
    let Some(held) = archive.classify(src, index)?.encoding() else {
        return Ok(());
    };
    let mut window = [0_u8; Encoding::HEAD_LEN];
    let read = fill(&mut *contents.open()?, &mut window)?;
    let Some(offered) = held.refuses(Encoding::of(window.get(..read).unwrap_or_default())) else {
        return Ok(());
    };
    Err(Error::WrongEncoding {
        path: path.to_owned(),
        held,
        offered,
    })
}

/// The kind of entry a payload has to be written as, for a path the archive
/// does not hold yet.
///
/// The payload decides, there being no entry to ask: one carrying an `RSC7`
/// header states its own page flags, and one that does not becomes a binary
/// entry rather than a resource with no flags anyone knows.
///
/// # Errors
///
/// Whatever the payload's own source fails to open or read with.
fn kind_for(contents: &dyn Contents) -> Result<FileKind> {
    // Four bytes off the front, not the payload.
    let mut magic = [0_u8; MAGIC_RSC7.len()];
    let read = fill(&mut *contents.open()?, &mut magic)?;
    Ok(if magic.get(..read) == Some(MAGIC_RSC7.as_slice()) {
        FileKind::Resource { declared: None }
    } else {
        FileKind::Binary {
            storage: Storage::Deflate,
            encryption: 0,
        }
    })
}

/// The entry `path` names in `archive`, the root not being an entry a change
/// may be about.
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
/// directories.** Removals first is what lets one set rename over a path it
/// also removes. Every refusal is decided against the tree as it then stands.
///
/// # Errors
///
/// [`Error::NotFound`], [`Error::AlreadyExists`], [`Error::BadPath`],
/// [`Error::WrongKind`], [`Error::WrongEncoding`],
/// [`Error::CannotWriteEncrypted`], and as [`specs_of`].
pub(crate) fn tree_of<R: Read + Seek>(
    src: &mut R,
    archive: &Archive,
    changes: &Changes,
) -> Result<Tree> {
    // Where a rebuild's target is asked whether it can be written at all, for
    // every level of a cascade and for the resolution `allows` runs early.
    archive.writable()?;
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
        rename(&mut *src, archive, &mut tree, path, to)?;
    }
    for (path, change) in changes {
        let Change::Write {
            ref contents,
            create,
            allow_encoding_change,
        } = *change
        else {
            continue;
        };
        write(
            src,
            archive,
            &mut tree,
            path,
            &**contents,
            Told {
                create,
                allow_encoding_change,
            },
        )?;
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
/// `x/y`, `x//y` and `X/Y` are three spellings of one entry, and applying two
/// of them lets the last win and the loser vanish with an `Ok`.
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

/// Whether `changes` puts anything below `held` that is not there yet: a
/// directory the set writes into is not empty, whatever the archive says.
fn arrives_under(changes: &Changes, held: &str) -> bool {
    // The restructuring index, not the whole set: every arm below is a
    // restructuring change, so this is the same answer over a smaller walk.
    changes
        .restructuring_changes()
        .any(|(at, change)| match *change {
            // Only a creation adds a path; the path *at* `held` is the
            // replacing case, so it is not an arrival.
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
fn rename<R: Read + Seek>(
    src: &mut R,
    archive: &Archive,
    tree: &mut Tree,
    path: &str,
    to: &str,
) -> Result<()> {
    let index = entry_at(archive, path)?;
    let held = archive.path(index)?;
    name::check_tree(to)?;
    renamable(src, archive, index, &held, to)?;

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

/// Refuses a rename that would leave a **nested archive** keyed by a name it no
/// longer has.
///
/// A nested archive travels through a rebuild as opaque bytes, and an NG
/// archive's own table and names blob are keyed by the name its holder files it
/// under, so renaming the entry leaves an archive that parses, verifies, and
/// answers [`Error::WrongKey`] to whoever opens it. A move is the one
/// exemption: the key takes the entry's own name and not its path.
///
/// # Errors
///
/// [`Error::CannotRenameKeyed`], naming the nested archive's tag and transform.
fn renamable<R: Read + Seek>(
    src: &mut R,
    archive: &Archive,
    index: u32,
    held: &str,
    to: &str,
) -> Result<()> {
    let name = |path: &str| path.rsplit('/').next().unwrap_or(path).to_owned();
    if name(held) == name(to) {
        return Ok(());
    }
    let Some(nested) = archive.nested_transform(src, index) else {
        return Ok(());
    };
    let (tag, scheme) = match nested {
        // Nothing in it is keyed, so its name is not part of what it is.
        NestedTransform::Open => return Ok(()),
        NestedTransform::Known { tag, scheme } => {
            if !scheme.keyed_by_name() {
                return Ok(());
            }
            (tag, scheme.named())
        }
        // What keys it is unknown, so it is refused rather than guessed at.
        // Unreachable with any tag this build defines.
        NestedTransform::Unknown { tag } => (tag, "unrecognised"),
    };
    Err(Error::CannotRenameKeyed {
        path: held.to_owned(),
        to: to.to_owned(),
        tag,
        scheme,
    })
}

/// What a [`Change::Write`] was told, beside the bytes.
#[derive(Debug, Clone, Copy)]
struct Told {
    /// [`Change::Write::create`].
    create: bool,
    /// [`Change::Write::allow_encoding_change`].
    allow_encoding_change: bool,
}

/// Puts new contents at `path`, creating the entry when the archive does not
/// hold one and the caller asked for that.
fn write<R: Read + Seek>(
    src: &mut R,
    archive: &Archive,
    tree: &mut Tree,
    path: &str,
    contents: &dyn Contents,
    told: Told,
) -> Result<()> {
    match archive.find(path) {
        Ok(0) => Err(Error::WrongKind {
            path: path.to_owned(),
            found: "directory",
            wanted: "file",
        }),
        Ok(index) => {
            // The entry's own storage rule is kept: one that was stored stays
            // stored, and one that was deflated is compressed again.
            let kind = kind_of(path, archive.entry(index)?)?;
            check_encoding(
                src,
                archive,
                index,
                path,
                contents,
                told.allow_encoding_change,
            )?;
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
            if !told.create {
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
/// `None` when the path names something in `archive` itself, a path nothing
/// resolves included. Only the first nesting level: a change two archives down
/// is grouped into the first, and the recursion groups it again.
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
/// The same resolution a commit performs, run early and thrown away, so the
/// rules are written once rather than once here and once there. It resolves the
/// **set** and not one change: a rename onto a path a buffered removal frees is
/// accepted, and one onto a path another buffered rename claims is not.
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
        None => tree_of(src, archive, &here).map(|_| ()),
        Some((index, _)) => {
            let holder = archive.open_nested(src, index)?;
            let nothing = Changes::new();
            let group = nested.get(&index);
            let inside = group.map_or(&nothing, |group| &group.changes);
            tree_of(src, &holder, inside)
                .map(|_| ())
                .map_err(|failure| match group {
                    Some(group) => respelled(failure, &group.spellings),
                    None => failure,
                })
        }
    }
}

/// The buffered changes that bear on `change` at `path`, and no others.
///
/// Two changes with no path in common decide nothing about each other, so this
/// subset gives the same answer as the whole set. A plain write is scanned for
/// only when the offered change is a removal, which is the one kind that can
/// take an entry out from under a write already buffered against it.
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
/// A path that crossed the boundary silently would land as a *directory* named
/// `something.rpf` inside the archive it came from.
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
/// Keyed by the entry index of the archive they land in, so several changes
/// inside one nested archive rebuild it **once**.
///
/// # Errors
///
/// As [`landing_of`], and [`Error::BadPath`] for a rename across archives.
pub(crate) fn split(archive: &Archive, changes: &Changes) -> Result<(Changes, Grouped)> {
    let mut here = Changes::new();
    let mut nested: Grouped = BTreeMap::new();
    // Which change staked each path within each nested archive.
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
                    spellings: Spellings::new(),
                });
                group.spellings.insert(within.clone(), path.to_owned());
                group.changes.set(within, within_change);
            }
        }
    }

    // A change to a nested archive's own bytes and one to something inside it
    // are the same bytes twice, so the one addressing through it is refused.
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
    /// The first change that addressed through this archive.
    pub(crate) first: String,
    /// The changes, spelled as paths within it.
    pub(crate) changes: Changes,
    /// How the caller spelled each of those paths.
    pub(crate) spellings: Spellings,
}

/// A path within a nested archive, and the path the caller addressed it by.
pub(crate) type Spellings = BTreeMap<String, String>;

/// The same failure, with every path it names spelled as the caller spelled it.
///
/// [`split`] re-keys such a change to the path *within* that archive, which is
/// not one the caller can act on. Exact matches only.
pub(crate) fn respelled(mut failure: Error, spellings: &Spellings) -> Error {
    for named in named_paths_mut(&mut failure) {
        if let Some(spelt) = spellings.get(named.as_str()) {
            named.clone_from(spelt);
        }
    }
    failure
}

/// Every path a failure names that can be one of a change set's own.
fn named_paths_mut(failure: &mut Error) -> Vec<&mut String> {
    match *failure {
        Error::NotFound { ref mut path, .. }
        | Error::WrongKind { ref mut path, .. }
        | Error::WrongEncoding { ref mut path, .. }
        | Error::NotAResource { ref mut path, .. }
        | Error::AlreadyExists { ref mut path, .. }
        | Error::BadPath { ref mut path, .. }
        | Error::Claimed { ref mut path, .. }
        | Error::FieldOverflow { ref mut path, .. } => vec![path],
        Error::Overlapping {
            ref mut path,
            ref mut other,
        } => vec![path, other],
        _ => Vec::new(),
    }
}

/// Nested change groups, by the entry index of the archive they land in.
pub(crate) type Grouped = BTreeMap<u32, Nested>;

#[cfg(test)]
mod tests {
    use std::{cell::Cell, io};

    use super::{fill, named_paths_mut, respelled};
    use crate::error::Error;

    /// A source whose first read fails uninterrupted, then ends.
    struct FailsOnceThenEnds {
        asked: Cell<u32>,
    }

    impl io::Read for FailsOnceThenEnds {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            let asked = self.asked.get();
            self.asked.set(asked.saturating_add(1));
            if asked == 0 {
                Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "not interrupted",
                ))
            } else {
                Ok(0)
            }
        }
    }

    #[test]
    fn fill_does_not_retry_a_read_error_that_is_not_an_interruption() {
        let mut source = FailsOnceThenEnds {
            asked: Cell::new(0),
        };
        let mut into = [0_u8; 4];
        fill(&mut source, &mut into).expect_err("a real read error must not be swallowed");
    }

    /// A source that fills what it is handed, and refuses an empty ask.
    struct FillsOnceAndRefusesAnEmptyAsk;

    impl io::Read for FillsOnceAndRefusesAnEmptyAsk {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Err(io::Error::other("asked to read into an empty buffer"));
            }
            buf.fill(0x5A);
            Ok(buf.len())
        }
    }

    #[test]
    fn fill_stops_asking_once_the_buffer_is_full() {
        let mut into = [0_u8; 4];
        let filled = fill(&mut FillsOnceAndRefusesAnEmptyAsk, &mut into)
            .expect("a source that filled the buffer in one call must not be asked again");
        assert_eq!(filled, 4);
        assert_eq!(into, [0x5A; 4]);
    }

    #[test]
    fn an_overlapping_failure_has_both_its_paths_respelled() {
        let failure = Error::Overlapping {
            path: "inner/a.txt".to_owned(),
            other: "inner/b.txt".to_owned(),
        };
        let spellings = [
            ("inner/a.txt".to_owned(), "archive.rpf/a.txt".to_owned()),
            ("inner/b.txt".to_owned(), "archive.rpf/b.txt".to_owned()),
        ]
        .into_iter()
        .collect();

        let fixed = respelled(failure, &spellings);
        let Error::Overlapping { path, other } = fixed else {
            panic!("respelling an Overlapping failure must keep it Overlapping");
        };
        assert_eq!(path, "archive.rpf/a.txt");
        assert_eq!(other, "archive.rpf/b.txt");
    }

    #[test]
    fn named_paths_mut_reaches_both_names_of_an_overlapping_failure() {
        let mut failure = Error::Overlapping {
            path: "a".to_owned(),
            other: "b".to_owned(),
        };
        assert_eq!(named_paths_mut(&mut failure).len(), 2);
    }
}
