//! Changing what an archive holds: add, remove, or rename an entry, each a full rebuild.

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

/// Where a `Change::Write`'s bytes come from, opened fresh each time it may be wanted again.
pub trait Contents: fmt::Debug + Send + Sync {
    /// The bytes, from their start.
    /// # Errors
    /// Whatever the source cannot be opened as.
    fn open(&self) -> Result<Box<dyn Payload + '_>>;

    /// How many bytes there are, without reading them.
    /// # Errors
    /// Whatever the source cannot be measured with.
    fn len(&self) -> Result<u64>;

    /// Whether there are none.
    /// # Errors
    /// As `Contents::len`.
    fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}

/// Contents a caller already holds, shared so a cascading rebuild does not copy them per level.
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

/// One change to what an archive holds, keyed by the path; a rename carries only its destination.
#[derive(Debug, Clone)]
pub enum Change {
    /// New contents for a path.
    Write {
        /// The file as it exists outside the archive, the form `Archive::extract` returns.
        contents: Arc<dyn Contents>,
        /// Whether a missing path is created rather than refused with `NotFound`.
        create: bool,
        /// Whether the entry's encoding may change, rather than refusing with `WrongEncoding`.
        allow_encoding_change: bool,
    },
    /// Remove the entry at a path.
    Remove {
        /// Whether a non-empty directory takes its children with it, rather than being refused.
        recursive: bool,
    },
    /// Move the entry, and everything below it, to a path the archive does not already hold.
    RenameTo(String),
    /// Create a directory, and whatever above it is missing.
    MakeDirectory,
}

const ADDS_ENTRY: &str = "adds an entry";
const REMOVES_ENTRY: &str = "removes an entry";
const RENAMES_ENTRY: &str = "renames an entry";
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

/// A set of changes to one archive, at most one per path, ordered for determinism.
#[derive(Debug, Clone, Default)]
pub struct Changes {
    at: BTreeMap<String, Change>,
    /// Keys of `at` that are not plain writes; an index avoiding a full walk to find them.
    structural: BTreeSet<String>,
}

fn restructuring(change: &Change) -> bool {
    !matches!(*change, Change::Write { create: false, .. })
}

/// What a change does, in the words a refusal names it by.
#[must_use]
pub fn does(change: &Change) -> &'static str {
    match *change {
        Change::Write { .. } => "a write",
        Change::Remove { .. } => "a removal",
        Change::RenameTo(_) => "a rename",
        Change::MakeDirectory => "a new directory",
    }
}

fn destination(change: &Change) -> Option<&str> {
    match *change {
        Change::RenameTo(ref to) => Some(to.as_str()),
        _ => None,
    }
}

/// Whether two changes can reach one another: paths at, under, or above either one.
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

    /// New contents for paths the archive already holds, each a plain, non-creating write.
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

    /// Whether `change` can be recorded at `path` beside what is here (matched exactly, unfolded).
    /// # Errors
    /// `Claimed`, naming what is in the way.
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

    /// Whether anything in this set could change what the archive holds at `path`.
    #[must_use]
    pub fn bears_on(&self, path: &str) -> bool {
        self.restructuring_changes()
            .any(|(at, change)| reach((at, destination(change)), (path, None)))
    }

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

    /// Contents a `Change::Write` at `path` carries, unopened, or `None` otherwise.
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Source {
    Entry(u32),
    Written(String),
}

#[derive(Debug)]
pub(crate) struct Node {
    pub(crate) spec: FileSpec,
    pub(crate) source: Source,
}

#[derive(Debug)]
pub(crate) struct Tree {
    pub(crate) nodes: Vec<Node>,
    pub(crate) directories: Vec<String>,
}

impl Tree {
    pub(crate) fn files(&self) -> Vec<FileSpec> {
        self.nodes.iter().map(|node| node.spec.clone()).collect()
    }

    pub(crate) fn sources(&self) -> BTreeMap<&str, &Source> {
        self.nodes
            .iter()
            .map(|node| (node.spec.path.as_str(), &node.source))
            .collect()
    }

    /// Whether anything in the tree answers to `path`, case-folded.
    fn holds(&self, path: &str) -> bool {
        let wanted = folded(path);
        self.nodes
            .iter()
            .any(|node| folded(&node.spec.path) == wanted)
            || self.directories.iter().any(|held| folded(held) == wanted)
    }
}

/// Whether `path` is `under`, or is it; component-wise and case-folded (`datastore` isn't).
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

fn moved(path: &str, from: &str, to: &str) -> String {
    match path.get(from.len()..) {
        Some(rest) if !rest.is_empty() => format!("{to}{rest}"),
        _ => to.to_owned(),
    }
}

/// Reads up to `into.len()` bytes; a short or piecewise source is not a failure.
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

/// Tree `archive` becomes once `changes` apply; removals go first so a rename can claim its path.
pub(crate) fn tree_of<R: Read + Seek>(
    src: &mut R,
    archive: &Archive,
    changes: &Changes,
) -> Result<Tree> {
    // Checked early so every level of a rebuild cascade and `allows`'s resolution see it.
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

/// Refuses a set in which two changes are about one entry, by any of its spellings.
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

fn arrives_under(changes: &Changes, held: &str) -> bool {
    // The restructuring index, not the whole set: every arm below is one of those changes.
    changes
        .restructuring_changes()
        .any(|(at, change)| match *change {
            // A path *at* `held` replaces it rather than arriving under it.
            Change::Write { create: true, .. } | Change::MakeDirectory => {
                !same_name(at, held) && at_or_under(at, held)
            }
            Change::RenameTo(ref to) => !same_name(to, held) && at_or_under(to, held),
            _ => false,
        })
}

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

/// Refuses a rename that would break a nested NG archive keyed by its own (soon-stale) filename.
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
        // Refused rather than guessed at; unreachable with any tag this build defines.
        NestedTransform::Unknown { tag } => (tag, "unrecognised"),
    };
    Err(Error::CannotRenameKeyed {
        path: held.to_owned(),
        to: to.to_owned(),
        tag,
        scheme,
    })
}

#[derive(Debug, Clone, Copy)]
struct Told {
    create: bool,
    allow_encoding_change: bool,
}

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
            // The entry's own storage rule is kept: stored stays stored, deflated recompresses.
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

/// Adds a directory; parents left missing are created later by `build`.
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

/// Nested archive a path lands in and the path within it, one level deep; deeper changes recurse.
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

/// Whether `change` can be made at `path`, resolving the whole buffered set, not just `change`.
/// # Errors
/// As `tree_of` and `split`, and `Claimed` for a conflicting buffered change at `path`.
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

/// Buffered changes bearing on `change` at `path`; a plain write is included only for a removal.
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

fn within_target(archive: &Archive, to: &str) -> Result<String> {
    Ok(match landing_of(archive, to)? {
        Some((_, within)) => within,
        None => to.to_owned(),
    })
}

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

    // Its own bytes and something inside it are the same bytes twice; refuse the latter.
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

#[derive(Debug)]
pub(crate) struct Nested {
    pub(crate) first: String,
    /// The changes, spelled as paths within it.
    pub(crate) changes: Changes,
    /// How the caller spelled each of those paths.
    pub(crate) spellings: Spellings,
}

/// A path within a nested archive, and the path the caller addressed it by.
pub(crate) type Spellings = BTreeMap<String, String>;

/// The same failure, with every path it names respelled as the caller spelled it (exact matches).
pub(crate) fn respelled(mut failure: Error, spellings: &Spellings) -> Error {
    for named in named_paths_mut(&mut failure) {
        if let Some(spelt) = spellings.get(named.as_str()) {
            named.clone_from(spelt);
        }
    }
    failure
}

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
