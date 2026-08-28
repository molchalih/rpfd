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
    collections::BTreeMap,
    io::{Read, Seek},
};

use crate::{
    archive::Archive,
    build::{FileKind, FileSpec, Storage, directories_of, kind_of, specs_of},
    error::{Error, Result},
    format::{folded, resource::MAGIC_RSC7},
    name,
};

/// One change to what an archive holds.
///
/// Keyed by the path it is about, which is why a rename carries only its
/// destination: the source is the key. At most one change per path, so a set
/// cannot ask for two things at one address (§5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// New contents for a path.
    Write {
        /// The file as it exists **outside** the archive: for a resource, its
        /// `RSC7` header and still-deflated body. The same form
        /// [`Archive::extract`] returns.
        contents: Vec<u8>,
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changes {
    at: BTreeMap<String, Change>,
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
                            contents,
                            create: false,
                        },
                    )
                })
                .collect(),
        }
    }

    /// Records `change` at `path`, answering whatever was there before.
    pub fn set(&mut self, path: impl Into<String>, change: Change) -> Option<Change> {
        self.at.insert(path.into(), change)
    }

    /// The change at `path`, if there is one.
    #[must_use]
    pub fn at(&self, path: &str) -> Option<&Change> {
        self.at.get(path)
    }

    /// The contents a [`Change::Write`] at `path` carries.
    ///
    /// What a reader asks when it wants what was written rather than what is on
    /// disk. `None` for a path with no change, and for a change that is not a
    /// write.
    #[must_use]
    pub fn contents_at(&self, path: &str) -> Option<&[u8]> {
        match self.at.get(path) {
            Some(Change::Write { contents, .. }) => Some(contents),
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
/// `DATA/a.txt` is.
fn at_or_under(path: &str, under: &str) -> bool {
    let path = folded(path);
    let under = folded(under);
    path == under
        || path
            .strip_prefix(&under)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// `path` with the `from` prefix replaced by `to`, for a path that is `from` or
/// is under it.
fn moved(path: &str, from: &str, to: &str) -> String {
    match path.get(from.len()..) {
        Some(rest) if !rest.is_empty() => format!("{to}{rest}"),
        _ => to.to_owned(),
    }
}

/// The kind of entry a payload has to be written as.
///
/// The payload decides, because for a new entry there is no entry to ask. A
/// resource carries its own `RSC7` header and its page flags with it, and
/// nothing else could recover them; anything else is offered to the compressor,
/// which is what `build` does with every file `pack` gives it. DR-026, and Q7
/// is why this is safe on the evidence there is: 27 entries of the sample, zero
/// disagreements between the resource bit and the payload's own magic.
fn kind_for(contents: &[u8]) -> FileKind {
    if contents.get(0..4) == Some(&MAGIC_RSC7) {
        FileKind::Resource
    } else {
        FileKind::Binary {
            storage: Storage::Deflate,
            encryption: 0,
        }
    }
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
        remove(archive, &mut tree, path, recursive)?;
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
        write(archive, &mut tree, path, contents, create)?;
    }
    for (path, change) in changes {
        if *change != Change::MakeDirectory {
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

/// Takes the entry at `path` out of the tree, with its children when it is a
/// directory and `recursive`.
fn remove(archive: &Archive, tree: &mut Tree, path: &str, recursive: bool) -> Result<()> {
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
    if children > 0 && !recursive {
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
    contents: &[u8],
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
                    kind: kind_for(contents),
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

/// Whether `change` can be made at `path`, asked before it is buffered.
///
/// The same resolution a commit performs, run against the archive as it stands
/// and thrown away — so a change this accepts is one the rebuild will not
/// refuse for the same reason, and the rules are written once rather than once
/// here and once there (§3). What it cannot answer is a change that only
/// collides with another change in the same set; that is the commit's, because
/// only the commit has the set.
///
/// A client buffers changes and commits them later, and a refusal is worth far
/// more at the moment the caller can still act on it. R7.1.
///
/// # Errors
///
/// As `tree_of`, and as [`Archive::locate`] for a path addressing through a
/// nested archive that will not open.
pub fn allows<R: Read + Seek>(
    src: &mut R,
    archive: &Archive,
    path: &str,
    change: &Change,
) -> Result<()> {
    let (holder, within) = match landing_of(archive, path)? {
        Some((index, within)) => (archive.open_nested(src, index)?, within),
        None => (archive.clone(), path.to_owned()),
    };
    if let Change::RenameTo(ref to) = *change {
        check_one_archive(archive, path, to)?;
    }
    let within_change = match *change {
        Change::RenameTo(ref to) => Change::RenameTo(within_target(archive, to)?),
        ref other => other.clone(),
    };
    tree_of(&holder, &Changes::one(within, within_change)).map(|_| ())
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
