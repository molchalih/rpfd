//! Writing an archive.
//!
//! The correctness-critical direction. Everything here is a way to produce an
//! archive that parses and does not load, so the rules it follows are the
//! measured ones, each citing its row in `docs/rpf-format.md`.
//!
//! Layout is computed before any payload is touched. The entry count and the
//! names blob follow from the paths alone, so the first payload's position is
//! known up front; payloads are then written in one pass and the header and
//! entry table filled in afterwards. Each payload is **streamed** from where it
//! comes from to where it goes, so neither a file nor the archive is held.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    io::{Read, Seek, SeekFrom, Write},
};

use flate2::{Compression, write::DeflateEncoder};
use serde::{Deserialize, Serialize};

use crate::{
    archive::{Archive, MAX_DEPTH},
    edit::{self, Changes},
    entry::{Entry, EntryKind},
    error::{Error, NoWrite, Result},
    format::{
        Content, FileFields, Header, Row, Version,
        crypto::{CIPHER_BLOCK_LEN, Seal, Sealer},
        folded,
        resource::{MAGIC_RSC7, RESOURCE_HEADER_LEN},
        u32_at, widen,
    },
    name,
    scratch::Scratch,
    watch::{Flow, Step, Watch},
};

/// Whether a payload is deflated or written as it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    /// Written as-is, with the compressed-size field left at zero.
    Stored,
    /// Deflated, unless that makes it bigger.
    Deflate,
}

/// What kind of entry to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// Plain bytes.
    Binary {
        /// Whether to deflate.
        storage: Storage,
        /// The per-entry encryption field. Zero on every entry measured so far.
        encryption: u32,
    },
    /// An `RSC7` resource, written through untouched.
    ///
    /// Passthrough is a commitment: `docs/approach.md`. What has to be
    /// reconstructed is the row, and `declared` is where its two flag words
    /// come from when the payload does not carry an `RSC7` header of its own —
    /// which in a Rockstar archive is every resource there is (Q7). `None`
    /// says nothing but the payload knows them, which is a created entry, and a
    /// payload without a header is then [`Error::NotAResource`]. DR-046.
    Resource {
        /// The flag words to record when the payload does not carry its own.
        declared: Option<ResourceFlags>,
    },
}

/// A resource's two flag words, which are its length and its version.
///
/// `docs/rpf-format.md`, Resource page flags: [`crate::format::resource_len`]
/// reads a length out of them and the version is their two top nibbles, so
/// carrying the pair carries both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceFlags {
    /// System page flags — offset 8 of the entry row, and of the header.
    #[serde(with = "flag_word")]
    pub system: u32,
    /// Graphics page flags — offset 12 of the entry row, and of the header.
    #[serde(with = "flag_word")]
    pub graphics: u32,
}

/// A flag word as anything outside the archive spells it: `0x` and eight
/// lower-case hexadecimal digits, fixed width.
///
/// This is the one value the sidecar manifest holds whose *bits* mean things —
/// `page_count` decodes nine fields out of one word — so it is written the way
/// `docs/rpf-format.md`, DR-046 and this module's own tests write it, and a
/// reviewer comparing a manifest line against any of them reads the same
/// characters. A width that is not eight is refused rather than padded or
/// truncated, because a dropped digit in a fixed-width word is a resource of
/// another length and another version. DR-058 §1.
mod flag_word {
    use serde::{Deserialize as _, Deserializer, Serializer, de::Error as _};

    #[allow(
        clippy::trivially_copy_pass_by_ref,
        reason = "the signature is serde's, not this module's"
    )]
    pub(super) fn serialize<S: Serializer>(
        word: &u32,
        out: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        out.collect_str(&format_args!("{word:#010x}"))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        text: D,
    ) -> std::result::Result<u32, D::Error> {
        let text = String::deserialize(text)?;
        let spelled = "a page-flag word is 0x and eight lower-case hexadecimal digits";
        let digits = text
            .strip_prefix("0x")
            .ok_or_else(|| D::Error::custom(spelled))?;
        if digits.len() != 8
            || !digits
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(D::Error::custom(spelled));
        }
        u32::from_str_radix(digits, 16).map_err(|_| D::Error::custom(spelled))
    }
}

/// One file to put in the archive.
#[derive(Debug, Clone)]
pub struct FileSpec {
    /// Path within the archive, slash-separated, no leading slash.
    pub path: String,
    /// How to write it.
    pub kind: FileKind,
}

/// What was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// Entries in the table, the root directory included.
    pub entry_count: u32,
    /// Length of the names blob.
    pub names_len: u32,
    /// Total length of the archive.
    pub len: u64,
}

/// A directory in the tree being assembled.
#[derive(Default)]
struct Dir {
    /// Children by name. A `BTreeMap` because children are stored in ascending
    /// name order — measured on all 6 directories of the sample. Whether the
    /// runtime *requires* it is Q1, still open.
    children: BTreeMap<String, Child>,
    /// Each child's name folded the way readers compare it, mapping to the one
    /// spelling that took it. See [`crate::format::folded`], which is the same
    /// rule `Archive::child_named` resolves by: two children of one directory
    /// differing only in case are one name at runtime, and the second is
    /// unreachable by any spelling of its own path — including its own.
    folded: HashMap<String, String>,
}

#[derive(Clone, Copy)]
enum Child {
    Dir(usize),
    File(usize),
}

/// `name` appended to the path of the directory it sits in, root included.
fn joined(at: &str, name: &str) -> String {
    if at.is_empty() {
        name.to_owned()
    } else {
        format!("{at}/{name}")
    }
}

/// The child of `dir` that `name` would resolve to, or `None` if the name is
/// free. `at` is the path of `dir` itself, empty for the root.
///
/// Fails when a child is already there under a different spelling of the same
/// folded name: the two are indistinguishable to a reader, so writing both
/// loses one of them. The refusal names **the two that collide**, which for a
/// directory component is not the path being added — `X64/alpha.txt` against an
/// existing `x64` is a collision between `X64` and `x64`, and those are what a
/// caller has to rename one of.
fn taken(dir: &Dir, at: &str, name: &str) -> Result<Option<Child>> {
    let Some(exact) = dir.folded.get(&folded(name)) else {
        return Ok(None);
    };
    if exact != name {
        return Err(Error::NameCollision {
            path: joined(at, name),
            other: joined(at, exact),
        });
    }
    Ok(dir.children.get(exact).copied())
}

/// Records `name` as taken within the directory at `parent`.
fn claim(arena: &mut [Dir], parent: usize, path: &str, name: &str, child: Child) -> Result<()> {
    let dir = arena.get_mut(parent).ok_or(Error::BadPath {
        path: path.to_owned(),
        reason: "unreachable parent",
    })?;
    dir.children.insert(name.to_owned(), child);
    dir.folded.insert(folded(name), name.to_owned());
    Ok(())
}

/// Resolves one path component to the directory it names, creating it if the
/// name is free.
///
/// `path` is the whole path being added, which is what a refusal about *it*
/// names; `at` is the path of `parent`, which is what a refusal about the
/// component names.
fn descend(
    arena: &mut Vec<Dir>,
    parent: usize,
    path: &str,
    at: &str,
    segment: &str,
) -> Result<usize> {
    let dir = arena.get(parent).ok_or(Error::BadPath {
        path: path.to_owned(),
        reason: "unreachable parent",
    })?;
    match taken(dir, at, segment)? {
        Some(Child::Dir(id)) => Ok(id),
        // Silently replacing the file would drop it from the tree, and its
        // contents would never be fetched or written.
        Some(Child::File(_)) => Err(Error::BadPath {
            path: path.to_owned(),
            reason: "a file and a directory share one name",
        }),
        None => {
            arena.push(Dir::default());
            let created = arena.len().saturating_sub(1);
            claim(arena, parent, path, segment, Child::Dir(created))?;
            Ok(created)
        }
    }
}

/// An entry with its position decided but its payload not yet written.
enum Planned {
    Dir {
        name: String,
        first_child: u32,
        child_count: u32,
    },
    File {
        name: String,
        spec: usize,
    },
}

impl Planned {
    const fn name(&self) -> &String {
        match self {
            Self::Dir { name, .. } | Self::File { name, .. } => name,
        }
    }
}

/// Rounds `value` up to the next multiple of the version's block unit.
fn align_up(version: Version, value: u64) -> Option<u64> {
    let block = version.block_len();
    let over = value.checked_rem(block)?;
    if over == 0 {
        return Some(value);
    }
    value.checked_add(block.checked_sub(over)?)
}

/// Refuses a path that would put an entry deeper than a reader will walk.
///
/// §8: every write path has a read path that verifies it, and `Archive::parse`
/// refuses a tree deeper than [`MAX_DEPTH`]. Without this, `pack` would write
/// an archive that this crate's own reader declines to open — the stated top
/// risk with the failure moved one step later.
///
/// `segments` counts the path's own components, which is the depth of the entry
/// it becomes: a file in the root is depth 1, and so is a directory named
/// there.
fn check_path_depth(segments: usize) -> Result<()> {
    let depth = u32::try_from(segments).unwrap_or(u32::MAX);
    if depth > MAX_DEPTH {
        return Err(Error::TooDeep {
            what: "directory tree",
            depth,
            limit: MAX_DEPTH,
        });
    }
    Ok(())
}

/// Builds the directory tree, returning the arena and the root's id.
fn plan_tree(files: &[FileSpec], directories: &[String]) -> Result<Vec<Dir>> {
    let mut arena: Vec<Dir> = vec![Dir::default()];

    // Directories named outright, so that one holding no files still survives a
    // round trip. Files create their own parents below; this adds only what
    // nothing else would.
    for directory in directories {
        name::check_tree(directory)?;
        let segments: Vec<&str> = directory.split('/').collect();
        check_path_depth(segments.len())?;
        let mut current = 0_usize;
        let mut at = String::new();
        for segment in segments {
            current = descend(&mut arena, current, directory, &at, segment)?;
            at = joined(&at, segment);
        }
    }

    for (index, spec) in files.iter().enumerate() {
        name::check_tree(&spec.path)?;
        let segments: Vec<&str> = spec.path.split('/').collect();
        let Some((name, parents)) = segments.split_last() else {
            return Err(Error::BadPath {
                path: spec.path.clone(),
                reason: "is empty",
            });
        };
        check_path_depth(segments.len())?;

        let mut current = 0_usize;
        let mut at = String::new();
        for segment in parents {
            current = descend(&mut arena, current, &spec.path, &at, segment)?;
            at = joined(&at, segment);
        }

        let dir = arena.get(current).ok_or(Error::BadPath {
            path: spec.path.clone(),
            reason: "unreachable parent",
        })?;
        if taken(dir, &at, name)?.is_some() {
            return Err(Error::BadPath {
                path: spec.path.clone(),
                reason: "is named twice in one directory",
            });
        }
        claim(&mut arena, current, &spec.path, name, Child::File(index))?;
    }
    Ok(arena)
}

/// Assigns entry indices breadth-first, which is the layout the sample uses:
/// each directory's children occupy one contiguous run, and the runs appear in
/// the order the directories do. `docs/rpf-format.md`, Entry table.
fn plan_entries(arena: &[Dir]) -> Result<Vec<Planned>> {
    let mut planned = vec![Planned::Dir {
        name: String::new(),
        first_child: 0,
        child_count: 0,
    }];
    let mut queue: VecDeque<(usize, usize)> = VecDeque::from([(0_usize, 0_usize)]);

    while let Some((entry_index, dir_id)) = queue.pop_front() {
        let dir = arena.get(dir_id).ok_or(Error::BadPath {
            path: String::new(),
            reason: "unreachable directory",
        })?;

        let first_child = u32::try_from(planned.len()).map_err(|_| Error::FieldOverflow {
            path: String::new(),
            what: "entry count",
            len: u64::try_from(planned.len()).unwrap_or(u64::MAX),
            limit: u64::from(u32::MAX),
        })?;
        let child_count = u32::try_from(dir.children.len()).unwrap_or(u32::MAX);

        for (offset, (name, child)) in dir.children.iter().enumerate() {
            let child_entry = planned.len();
            match *child {
                Child::Dir(id) => {
                    planned.push(Planned::Dir {
                        name: name.clone(),
                        first_child: 0,
                        child_count: 0,
                    });
                    let _ = offset;
                    queue.push_back((child_entry, id));
                }
                Child::File(spec) => planned.push(Planned::File {
                    name: name.clone(),
                    spec,
                }),
            }
        }

        if let Some(Planned::Dir {
            first_child: f,
            child_count: c,
            ..
        }) = planned.get_mut(entry_index)
        {
            *f = first_child;
            *c = child_count;
        }
    }
    Ok(planned)
}

/// Bytes one payload can be read from, in full, from its start.
///
/// [`build`] takes its payloads as readers rather than as buffers, so that a
/// cascading rebuild can hand it an ancestor sitting in scratch space instead
/// of one sitting in memory. R4.13, DR-022. Anything that is both [`Read`] and
/// [`Seek`] is one; a caller holding bytes wraps them in a [`std::io::Cursor`].
///
/// Seekable because `store` reads a payload twice in one case — the deflated
/// form that did not pay for itself, which is then written as it came.
pub trait Payload: Read + Seek {}

impl<T: Read + Seek> Payload for T {}

/// Where [`build`] takes each payload from, at the moment it writes it.
///
/// Asked once per file, in entry-table order, and given the path from the
/// [`FileSpec`]. What it answers is a [`Payload`] — a reader, read from its
/// start — and the bytes go straight through to the sink, so neither a file nor
/// the archive is resident.
///
/// **The answer may borrow what it is read out of**, and that is the whole
/// reason this is a trait rather than a closure: a `FnMut` cannot return a
/// value borrowing what it captured, so a rebuild handed one had to extract
/// each entry into a buffer before it could hand it over. That buffer was
/// R3.9's remaining term.
///
/// A caller whose payloads own themselves never names this: every
/// `FnMut(&str) -> Result<impl Payload>` is a [`Fetch`], which is what `pack`
/// opening a file per path still writes.
pub trait Fetch {
    /// One payload, borrowing this source for as long as it is read.
    type Payload<'a>: Payload
    where
        Self: 'a;

    /// The payload for `path`.
    ///
    /// # Errors
    ///
    /// Whatever the source cannot answer for that path.
    fn payload(&mut self, path: &str) -> Result<Self::Payload<'_>>;
}

impl<F, P> Fetch for F
where
    F: FnMut(&str) -> Result<P>,
    P: Payload,
{
    type Payload<'a>
        = P
    where
        Self: 'a;

    fn payload(&mut self, path: &str) -> Result<P> {
        self(path)
    }
}

/// One payload as it went into the archive, and the fields describing it.
///
/// `compressed_len` is left wide on purpose. Narrowing it to whatever width the
/// version's row gives that field is [`file_row`]'s job and nobody else's, so a
/// value that will not fit arrives there to be refused rather than being
/// quietly cut down on the way.
pub(crate) struct Written {
    /// What the row's compressed-size field describes: the deflated length, or
    /// zero for a payload stored as it came. `docs/rpf-format.md`, Compression.
    pub(crate) compressed_len: u64,
    /// The fields the payload's own form decides.
    pub(crate) content: Content,
    /// The payload's length — what the entry addresses, and what the next
    /// payload's position is measured from.
    pub(crate) len: u64,
    /// How far past the payload's start anything was written.
    ///
    /// Equal to `len` except in one case, and that case is why it exists: a
    /// deflate stream that turned out no smaller than what it encoded is
    /// overwritten by the plain bytes, which are shorter, and the tail of it is
    /// zeroed rather than left behind (§8). Nothing is left stale, but the
    /// write did reach further than the payload now does, and the caller's
    /// high-water mark has to know that or the archive ends up longer than the
    /// length it reports.
    pub(crate) reached: u64,
}

/// Whether a payload written as `kind` goes under the archive's own transform.
///
/// **The mirror of what the reader takes it out from**, and the one place the
/// writer decides it: `archive::Archive::opened` asks the same two questions of
/// the entry it is reading, and a payload put back under a different rule than
/// it came out from is an archive that parses and does not load.
///
/// - A **binary** entry is under the transform exactly when its own per-entry
///   encryption field says so. The field takes two values and no others across
///   91,604 binary entries; in an AES archive it is exactly that and nothing
///   more, because the correlation with deflation that holds in an NG archive
///   does not hold there. `docs/rpf-format.md`, Entry table; `docs/backlog.md`
///   Q10.
/// - A **resource** goes back exactly as it came out, and `false` is what
///   achieves that rather than a claim that its payload is in the clear. What
///   this writer is handed is the payload **as it sits on disk** — a resource
///   crosses in `archive::Form::File`, which passes the bytes through untouched
///   — so writing them without a transform is what preserves whatever transform
///   they were already under. 3,022 of 696,578 resources are under the
///   archive's own transform (DR-051), and this answer is right for those and
///   for the clear ones alike *because it does not depend on which they are*.
///   A resource has no per-entry field to consult in any case: offsets 8 and 12
///   are its two flag words (§5).
///
///   So it does **not** track what the read side found, and "correcting" it to
///   would seal bytes that are already sealed and double-encrypt those 3,022 on
///   the next rebuild. What would break the invariant is the other change: a
///   caller handing this writer a resource in **contents** form — decrypted and
///   inflated — which is not a payload and which no write path produces.
///   `archive::RESOURCE_IS_IN_THE_CLEAR` is the read side of the same rule and
///   not of the same fact: as its own doc says, it is not a claim about the
///   contents either.
///
///   **The one write path that produces a resource payload rather than passing
///   one through seals it itself**, before it ever reaches here: `view::apply`
///   frames an edited `Meta` back up and hands it to
///   `archive::Archive::seal_payload_from`, which puts it under the transform
///   the entry was read under. That is what keeps the paragraph above true of a
///   converted write, and it is DR-060. A converted write that landed here
///   unsealed wrote plaintext into an encrypted archive, and `verify` read it
///   back happily, because the read side tries the clear boundary first.
pub(crate) const fn is_sealed(version: Version, kind: FileKind) -> bool {
    match kind {
        FileKind::Binary { encryption, .. } => !version.entry_is_open(encryption),
        FileKind::Resource { .. } => false,
    }
}

/// Where a payload's bytes go, and the transform they go under.
///
/// A payload of an encrypted archive is written **through** the archive's seal,
/// a block at a time from the payload's own start and with a tail shorter than
/// a block carried through as it stands — which is the extent
/// `format::crypto::Cipher::apply` reads it back by, stated once there and
/// obeyed here.
///
/// Streaming rather than buffered, because R3.9 is about a payload costing a
/// buffer rather than its length, and an encrypted one is a payload like any
/// other. It is sound only because neither transform chains between blocks: a
/// block is sealed from what is in it and its position, so a `store` that
/// abandons a speculative deflate stream and writes over it from the payload's
/// start resumes at block zero and loses nothing.
enum Sink<'a, W> {
    /// Straight through.
    Clear(&'a mut W),
    /// Through the archive's seal.
    Sealed(Sealing<'a, W>),
}

/// The sealing half of a [`Sink`].
struct Sealing<'a, W> {
    out: &'a mut W,
    seal: &'a Seal,
    /// Where this payload begins in `out`, which is where its blocks are
    /// counted from.
    start: u64,
    /// The block being filled.
    block: [u8; CIPHER_BLOCK_LEN],
    /// How much of it is filled.
    filled: usize,
    /// Whether the payload has ended, after which bytes are slack and go
    /// through as they are.
    past: bool,
}

impl<'a, W: Write + Seek> Sink<'a, W> {
    /// A sink at `start`, sealed when `seal` is `Some`.
    fn new(out: &'a mut W, seal: Option<&'a Seal>, start: u64) -> Self {
        match seal {
            None => Self::Clear(out),
            Some(seal) => Self::Sealed(Sealing {
                out,
                seal,
                start,
                block: [0; CIPHER_BLOCK_LEN],
                filled: 0,
                past: false,
            }),
        }
    }

    /// Ends the payload: a tail shorter than a block goes out as it stands, and
    /// anything written afterwards is slack rather than payload.
    ///
    /// Idempotent, because the deflate fallback ends its payload before it pads
    /// and `store` ends every payload once more (§4: a function that decides
    /// something decides it completely).
    ///
    /// # Errors
    ///
    /// [`Error::Io`] from the sink.
    fn ends(&mut self) -> Result<()> {
        let Self::Sealed(ref mut sealing) = *self else {
            return Ok(());
        };
        let tail = sealing.block.get(..sealing.filled).unwrap_or_default();
        let at = sealing.start;
        sealing
            .out
            .write_all(tail)
            .map_err(|source| Error::Io { offset: at, source })?;
        sealing.filled = 0;
        sealing.past = true;
        Ok(())
    }
}

impl<W: Write + Seek> Write for Sink<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let sealing = match *self {
            Self::Clear(ref mut out) => return out.write(buf),
            Self::Sealed(ref mut sealing) => sealing,
        };
        if sealing.past {
            return sealing.out.write(buf);
        }
        let room = CIPHER_BLOCK_LEN.saturating_sub(sealing.filled);
        let taking = room.min(buf.len());
        let Some(taken) = buf.get(..taking) else {
            return Ok(0);
        };
        let Some(into) = sealing
            .block
            .get_mut(sealing.filled..sealing.filled.saturating_add(taking))
        else {
            return Ok(0);
        };
        into.copy_from_slice(taken);
        sealing.filled = sealing.filled.saturating_add(taking);
        if sealing.filled == CIPHER_BLOCK_LEN {
            let mut block = sealing.block;
            sealing.seal.block(&mut block);
            sealing.out.write_all(&block)?;
            sealing.filled = 0;
        }
        Ok(taking)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match *self {
            Self::Clear(ref mut out) => out.flush(),
            Self::Sealed(ref mut sealing) => sealing.out.flush(),
        }
    }
}

impl<W: Write + Seek> Seek for Sink<'_, W> {
    /// Seeks the sink under it, abandoning any partly-filled block.
    ///
    /// The one seek a `store` makes is back to the payload's own start, to
    /// write over a deflate stream that did not pay for itself. Anything held
    /// is about to be overwritten, so it is dropped rather than flushed; a
    /// destination that is not a block boundary of this payload would leave the
    /// blocks after it counted from the wrong place, and is refused.
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        let sealing = match *self {
            Self::Clear(ref mut out) => return out.seek(to),
            Self::Sealed(ref mut sealing) => sealing,
        };
        let at = sealing.out.seek(to)?;
        let within = at.checked_sub(sealing.start);
        if !within.is_some_and(|by| by.is_multiple_of(widen(CIPHER_BLOCK_LEN))) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "a sealed payload seeks only to a block boundary of its own",
            ));
        }
        sealing.filled = 0;
        sealing.past = false;
        Ok(at)
    }
}

/// The name an entry carries in the names blob, out of the path it is written
/// at.
///
/// The last `/`-separated segment, which is exactly where [`plan_tree`] splits
/// a path into parents and a name — so the name a key is chosen by here and the
/// name the reader finds in the blob are one derivation and not two (§3). A
/// backslash is a name byte and not a separator, so it is not one of these
/// (DR-016).
fn entry_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The storage rule an existing entry carries, as the [`FileKind`] that spells
/// it for a write.
///
/// One spelling of one question (§4): a rebuild asks it through [`specs_of`],
/// and an in-place patch asks it to apply the same rule to a new payload.
/// Deriving it separately in each is how they came to disagree.
///
/// # Errors
///
/// [`Error::WrongKind`] for a directory, which has no payload to store.
pub(crate) fn kind_of(path: &str, entry: &Entry) -> Result<FileKind> {
    match entry.kind {
        EntryKind::Directory { .. } => Err(Error::WrongKind {
            path: path.to_owned(),
            found: "directory",
            wanted: "file",
        }),
        // The row's own flag words travel with the kind, because they are the
        // only place a Rockstar resource's flags exist: its payload does not
        // begin with `RSC7` and carries no readable header (Q7). DR-046.
        EntryKind::Resource {
            system_flags,
            graphics_flags,
            ..
        } => Ok(FileKind::Resource {
            declared: Some(ResourceFlags {
                system: system_flags,
                graphics: graphics_flags,
            }),
        }),
        EntryKind::Binary {
            compressed_len,
            encryption,
            ..
        } => Ok(FileKind::Binary {
            storage: if compressed_len == 0 {
                Storage::Stored
            } else {
                Storage::Deflate
            },
            encryption,
        }),
    }
}

/// Copies the rest of `src` into `out`, reporting how many bytes moved.
fn copy_all<S, W>(src: &mut S, out: &mut W, at: u64) -> Result<u64>
where
    S: Read,
    W: Write,
{
    std::io::copy(src, out).map_err(|source| Error::Io { offset: at, source })
}

/// The uncompressed length as the entry's field has to hold it.
fn uncompressed_len(path: &str, len: u64) -> Result<u32> {
    u32::try_from(len).map_err(|_| Error::FieldOverflow {
        path: path.to_owned(),
        what: "uncompressed size",
        len,
        limit: u64::from(u32::MAX),
    })
}

/// Applies a storage rule to one file, streaming it from `src` into `out` at
/// wherever `out` is now.
///
/// The one implementation of the rule. A rebuild reaches it with the rule the
/// caller asked for and a patch with the rule the entry already carries, but
/// the rule is applied here in both cases — the two used to apply it
/// separately, and a resource over the 24-bit size field was refused by one and
/// truncated by the other.
///
/// Nothing larger than a copy buffer is held: the payload passes from `src` to
/// `out`, and the deflated form goes out as it is produced rather than being
/// assembled first. R4.13 is what that is for — an ancestor a cascade has just
/// rebuilt is read out of scratch space here, not out of memory.
///
/// `src` is read from its start, whatever position it arrives at.
///
/// # Errors
///
/// [`Error::NotAResource`] for a resource whose payload is not one,
/// [`Error::FieldOverflow`] for contents too long for the entry's fields, and
/// [`Error::Io`] from either side.
///
/// `sealer` is the archive's own forward transform where it has one, and
/// whether this payload goes under it is [`is_sealed`]'s answer and nowhere
/// else's.
///
/// **The seal is keyed here, from this payload's own name and its contents'
/// length**, because an NG key index is `(hash(name) + length + 61) % 101`
/// (Q2): an entry rewritten at a size that lands on a different index must be
/// written under *that* key, or the archive parses and does not load. The
/// length is the source's, measured before a byte goes out — which is the
/// entry's uncompressed length in both storage forms, deflated or stored, and
/// is what the reader hands [`Cipher::new`](crate::format::crypto::Cipher::new)
/// off the row it will read back. The name is the entry's own, which is the
/// last `/`-separated segment of `path`: [`plan_tree`] splits it exactly there,
/// so the two cannot drift.
pub(crate) fn store<S, W>(
    version: Version,
    path: &str,
    kind: FileKind,
    sealed: Option<Sealed<'_>>,
    src: &mut S,
    out: &mut W,
) -> Result<Written>
where
    S: Payload,
    W: Write + Seek,
{
    let start = out
        .stream_position()
        .map_err(|source| Error::Io { offset: 0, source })?;
    let contents_len = src.seek(SeekFrom::End(0)).map_err(|source| Error::Io {
        offset: start,
        source,
    })?;
    src.rewind().map_err(|source| Error::Io {
        offset: start,
        source,
    })?;

    let under = match sealed.filter(|_| is_sealed(version, kind)) {
        None => None,
        Some(sealed) => Some(sealed.of(entry_name(path), contents_len)?),
    };
    let under = under.as_ref();
    let mut sink = Sink::new(out, under, start);
    let written = match kind {
        FileKind::Resource { declared } => store_resource(path, declared, src, &mut sink, start),
        FileKind::Binary {
            storage: Storage::Stored,
            encryption,
        } => {
            let len = copy_all(src, &mut sink, start)?;
            Ok(Written {
                // Stored: the compressed-size field carries the sentinel zero
                // and the real length goes with the contents.
                // docs/rpf-format.md, Compression.
                compressed_len: 0,
                content: Content::Binary {
                    uncompressed_len: uncompressed_len(path, len)?,
                    encryption,
                },
                len,
                reached: len,
            })
        }
        FileKind::Binary {
            storage: Storage::Deflate,
            encryption,
        } => store_deflated(version, path, encryption, src, &mut sink, start),
    }?;
    // The payload ends here whatever form it took, so its tail shorter than a
    // block goes out as it stands. The deflate fallback has already ended its
    // own before padding, and this is idempotent.
    sink.ends()?;
    Ok(written)
}

/// [`store`] for a resource: written through untouched, with the flag words its
/// row will declare taken from the payload's own `RSC7` header when it has one
/// and from `declared` when it has not.
///
/// **The payload wins when it carries a header, because the header describes
/// the payload** — a resource exported from any archive carries its flags with
/// it, and they are the new entry's rather than the old one's. Otherwise
/// `declared` is the only source there is: `docs/backlog.md` Q7 measured
/// 696,578 of 696,578 Rockstar resource payloads that do not begin with `RSC7`,
/// so requiring the magic here refused every resource a Rockstar archive ever
/// produced. DR-046.
fn store_resource<S, W>(
    path: &str,
    declared: Option<ResourceFlags>,
    src: &mut S,
    out: &mut Sink<'_, W>,
    start: u64,
) -> Result<Written>
where
    S: Payload,
    W: Write + Seek,
{
    // The head is read before anything goes out, so a payload too short to be a
    // resource is refused with nothing written for it. Read rather than seeked
    // over: a header carries the flags the entry duplicates.
    let mut head = Vec::new();
    (&mut *src)
        .take(RESOURCE_HEADER_LEN)
        .read_to_end(&mut head)
        .map_err(|source| Error::Io {
            offset: start,
            source,
        })?;
    if u64::try_from(head.len()).unwrap_or(u64::MAX) < RESOURCE_HEADER_LEN {
        return Err(Error::NotAResource {
            path: path.to_owned(),
            reason: "the payload is shorter than a resource header",
        });
    }
    let magic: [u8; 4] = head
        .get(0..4)
        .and_then(|s| s.try_into().ok())
        .unwrap_or_default();
    // Offsets 8 and 12 of an `RSC7` header are the flag words, and both are
    // inside the sixteen bytes read above, so the default is unreachable rather
    // than a guess at a truncated header.
    let flags = if magic == MAGIC_RSC7 {
        ResourceFlags {
            system: u32_at(&head, 8).unwrap_or_default(),
            graphics: u32_at(&head, 12).unwrap_or_default(),
        }
    } else {
        declared.ok_or_else(|| Error::NotAResource {
            path: path.to_owned(),
            reason: "the payload carries no RSC7 header and no entry declares \
                     its page flags",
        })?
    };

    out.write_all(&head).map_err(|source| Error::Io {
        offset: start,
        source,
    })?;
    let len = RESOURCE_HEADER_LEN.saturating_add(copy_all(src, out, start)?);
    Ok(Written {
        compressed_len: len,
        content: Content::Resource {
            system_flags: flags.system,
            graphics_flags: flags.graphics,
        },
        len,
        reached: len,
    })
}

/// [`store`] for a payload offered to the compressor, including the case where
/// the compressor does not earn its place.
fn store_deflated<S, W>(
    version: Version,
    path: &str,
    encryption: u32,
    src: &mut S,
    out: &mut Sink<'_, W>,
    start: u64,
) -> Result<Written>
where
    S: Payload,
    W: Write + Seek,
{
    let (plain, deflated) = {
        let mut encoder = DeflateEncoder::new(&mut *out, Compression::default());
        let plain = std::io::copy(src, &mut encoder).map_err(|source| Error::Io {
            offset: start,
            source,
        })?;
        encoder.try_finish().map_err(|source| Error::Io {
            offset: start,
            source,
        })?;
        (plain, encoder.total_out())
    };
    let content = Content::Binary {
        uncompressed_len: uncompressed_len(path, plain)?,
        encryption,
    };

    // Deflating has to pay for itself, and it has to fit the field — whose
    // width is the version's, so the seam is asked rather than a limit written
    // here. Falling back to stored is R4.4, not a workaround.
    if deflated < plain && version.holds_compressed_len(deflated) {
        return Ok(Written {
            compressed_len: deflated,
            content,
            len: deflated,
            reached: deflated,
        });
    }

    // It did not pay. The plain bytes go over the stream that was speculatively
    // written, and what is left of that stream past them is zeroed: real
    // archives carry stale bytes in their slack and this one must not write its
    // own (§8). The zeroing is bounded by deflate's worst-case expansion, which
    // is a fraction of a percent of the payload.
    out.seek(SeekFrom::Start(start))
        .map_err(|source| Error::Io {
            offset: start,
            source,
        })?;
    src.rewind().map_err(|source| Error::Io {
        offset: start,
        source,
    })?;
    let len = copy_all(src, out, start)?;
    let reached = deflated.max(len);
    let overhang = reached.saturating_sub(len);
    // The payload is `len` bytes, and the zeroing past it is slack rather than
    // payload — so the seal ends here. Sealing the padding as well would put
    // the last few bytes of the payload inside a block a reader that stops at
    // `len` never decrypts, which is the tail rule broken by a byte count the
    // entry does not declare.
    out.ends()?;
    if overhang > 0 {
        copy_all(&mut std::io::repeat(0).take(overhang), out, start)?;
    }
    Ok(Written {
        compressed_len: 0,
        content,
        len,
        reached,
    })
}

/// The tree as it will be written: the files as specified, the entries they
/// became, and the name offset of each.
///
/// Grouped because they are one thing — three parallel slices that only mean
/// anything together, and passing them singly put `write_payloads` over the
/// argument limit `clippy.toml` sets.
struct Layout<'a> {
    version: Version,
    files: &'a [FileSpec],
    planned: &'a [Planned],
    name_offsets: &'a [u32],
    /// The archive's own forward transform, where it has one. One seal per
    /// payload is minted from it, keyed by that entry's own name and length.
    sealed: Option<Sealed<'a>>,
}

/// Writes every payload at its aligned position, returning the entry rows and
/// the offset one past the **last byte actually written** — zero when nothing
/// was, which includes an archive whose every payload is empty.
///
/// `cursor` enters at the first payload's offset and leaves at the archive's
/// end. Payloads stream from `fetch` to `out`, so neither a file nor the
/// archive is resident.
///
/// That second value is where padding may begin, and it is deliberately neither
/// `cursor`, which is rounded up to the next block, nor the position the last
/// payload was written *at*. Both readings have been wrong here:
///
/// - `cursor` is one block too far when a payload ends on a boundary, and a
///   byte written at `cursor - 1` to stretch the file to that length lands on
///   the payload's own last byte;
/// - the last payload's start is too far when that payload is **empty**. A
///   `write_all` of no bytes extends no file, so the highest byte written is
///   still the previous payload's, and padding forward from the empty
///   payload's own start pads nothing. The archive is then short of the length
///   its entries describe, and its last entry addresses past the end of it.
///
/// So it is the high-water mark of the writes themselves, and only a write with
/// bytes in it moves it.
///
/// **Payloads go out in entry-table order, at a cursor that only advances, and
/// a saturated resource's row is only correct because of it.** A resource
/// longer than the 24-bit compressed-size field writes `MAX_SIZE_24` and states
/// its extent nowhere; the reader recovers it as the room from this payload's
/// start to the next payload's, so the entry that follows this one in the table
/// must be the payload that follows it on disk, with nothing between them but
/// alignment padding. Reordering payloads for locality, batching them by size,
/// or interleaving them would leave those rows describing another entry's data.
/// DR-056, DR-051 clause 1;
/// `a_resource_longer_than_its_size_field_writes_the_sentinel_and_reads_back`
/// in `crates/rpf-core/tests/boundaries.rs` is what fails if it stops holding.
///
/// `watch` is stepped once per file written, and can stop the write. DR-008.
fn write_payloads<W, F>(
    out: &mut W,
    layout: &Layout<'_>,
    cursor: &mut u64,
    fetch: &mut F,
    watch: &mut impl Watch,
) -> Result<(Vec<Row>, u64)>
where
    W: Write + Seek,
    F: Fetch,
{
    let Layout {
        version,
        files,
        planned,
        name_offsets,
        sealed,
    } = *layout;
    let mut rows = Vec::with_capacity(planned.len());
    let total = u32::try_from(files.len()).unwrap_or(u32::MAX);
    let mut done = 0_u32;
    let mut end = 0_u64;

    for (index, entry) in planned.iter().enumerate() {
        let name_offset = name_offsets.get(index).copied().unwrap_or_default();

        let spec_index = match *entry {
            Planned::Dir {
                first_child,
                child_count,
                ..
            } => {
                rows.push(version.directory_row(name_offset, first_child, child_count));
                continue;
            }
            Planned::File { spec, .. } => spec,
        };

        let spec = files.get(spec_index).ok_or(Error::BadPath {
            path: String::new(),
            reason: "unknown file",
        })?;
        let at = *cursor;
        out.seek(SeekFrom::Start(at))
            .map_err(|source| Error::Io { offset: at, source })?;
        let mut payload = fetch.payload(&spec.path)?;
        let written = store(version, &spec.path, spec.kind, sealed, &mut payload, out)?;

        // The row is built after the payload rather than before it, because a
        // streamed payload's length is not known until it has been streamed.
        // A value the entry cannot describe is therefore refused with bytes
        // already in the sink — which is a temporary file that a failed build
        // never renames into place (§8), not the archive.
        let block = at.checked_div(version.block_len()).unwrap_or(u64::MAX);
        let row = file_row(version, &spec.path, name_offset, block, &written)?;

        // Only a write that put bytes somewhere moves the high-water mark. An
        // empty payload leaves the sink exactly as long as it was, so claiming
        // its start as the end of what was written loses everything between
        // there and the previous payload's last byte.
        if written.reached > 0 {
            end = at.saturating_add(written.reached);
        }
        *cursor =
            align_up(version, at.saturating_add(written.reached)).ok_or(Error::FieldOverflow {
                path: spec.path.clone(),
                what: "archive length",
                len: at,
                limit: u64::MAX,
            })?;

        rows.push(row);

        // After the write, not before: a step reports what has happened.
        done = done.saturating_add(1);
        let flow = watch.step(Step {
            path: &spec.path,
            done,
            total,
            bytes: *cursor,
        });
        if flow == Flow::Stop {
            return Err(Error::Cancelled { done, total });
        }
    }
    Ok((rows, end))
}

/// Writes an archive containing `files`, taking each one's contents from
/// `fetch` at the moment it is written.
///
/// `fetch` is a [`Fetch`] — asked once per file, in entry-table order, for a
/// reader over that path's payload — and the bytes go straight through to
/// `out`, so neither a file nor the archive is resident. A caller holding bytes
/// hands back a [`std::io::Cursor`] over them from a closure, which is a
/// [`Fetch`] like
/// any other.
///
/// `version` is what the archive is written as, and it is the caller's: a
/// rebuild takes it from the archive it is rebuilding and `pack` takes it from
/// the manifest, which has recorded it since schema 2. [`Version`] is closed
/// over the versions this build has a codec for, so one it does not have
/// cannot be named here. DR-018.
///
/// # Errors
///
/// [`Error::BadPath`] for a path that cannot become entries,
/// [`Error::NotAResource`] for a resource whose payload is not one,
/// [`Error::FieldOverflow`] when a value will not fit the format's field, and
/// [`Error::Io`] from the sink or from `fetch`.
pub fn build<W, F>(
    out: &mut W,
    version: Version,
    files: &[FileSpec],
    directories: &[String],
    fetch: F,
    watch: &mut impl Watch,
) -> Result<Report>
where
    W: Write + Seek,
    F: Fetch,
{
    build_under(out, Under::open(version), files, directories, fetch, watch)
}

/// What an archive is written as: its version, its encryption tag, and the
/// transform that tag names where it names one.
///
/// One value rather than three arguments, because they are one fact and a
/// caller able to pass a tag without the transform it names would write a
/// header claiming an encryption the bytes are not under (§4).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Under<'a> {
    /// The version the archive is written at.
    version: Version,
    /// The tag the header carries.
    tag: u32,
    /// The forward transform, or `None` for an archive written in the clear.
    sealer: Option<&'a Sealer>,
    /// The name the archive will be **read back** under, which is half of what
    /// its table of contents and its names blob are keyed by.
    ///
    /// Empty for an archive written in the clear, which has no key and so no
    /// name to be right or wrong about. For a rebuild it is the original's
    /// name and not the scratch file's: a rebuild renames over the original
    /// (DR-035), and the reader keys by the name it finds the archive under.
    name: &'a str,
}

impl<'a> Under<'a> {
    /// Written in the clear, at this version's "not encrypted" tag.
    pub(crate) const fn open(version: Version) -> Self {
        Self {
            version,
            tag: version.open(),
            sealer: None,
            name: "",
        }
    }

    /// Written under `tag`'s transform, into a file that will be read back
    /// under `name`.
    pub(crate) const fn sealed(
        version: Version,
        tag: u32,
        sealer: &'a Sealer,
        name: &'a str,
    ) -> Self {
        Self {
            version,
            tag,
            sealer: Some(sealer),
            name,
        }
    }
}

/// A forward transform and the tag a refusal to run it names.
///
/// One value rather than two arguments, and it exists so that the one place a
/// region's key is chosen is also the one place a missing key is refused:
/// [`Sealed::of`] is where a name and a length become a [`Seal`], and it is the
/// only way to obtain one inside a write.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Sealed<'a> {
    /// The archive's forward transform.
    sealer: &'a Sealer,
    /// The tag the header carries, which a refusal names.
    tag: u32,
}

impl<'a> Sealed<'a> {
    /// The transform for an archive carrying `tag`.
    pub(crate) const fn new(sealer: &'a Sealer, tag: u32) -> Self {
        Self { sealer, tag }
    }

    /// The seal for one region, keyed by the name and length of what is being
    /// written into it.
    ///
    /// # Errors
    ///
    /// [`Error::CannotWriteEncrypted`] with [`NoWrite::NoInverse`] where the
    /// material holds no key at the index that name and length chose — which
    /// material of the shape `NgKeys` promises never is, and which is refused
    /// rather than written in the clear because writing plaintext into a region
    /// the format requires to be ciphertext is the failure this whole path
    /// exists to make impossible.
    pub(crate) fn of(self, name: &str, len: u64) -> Result<Seal> {
        self.sealer
            .seal(name, len)
            .ok_or(Error::CannotWriteEncrypted {
                tag: self.tag,
                reason: NoWrite::NoInverse,
            })
    }
}

/// [`build`], with what the archive's own bytes go under.
///
/// The one implementation; [`build`] is it in the clear, `rebuild` is it under
/// whatever the archive it is rebuilding was under, and
/// [`Manifest::pack_into`](crate::manifest::Manifest::pack_into) is it under
/// whatever the manifest's tag names.
///
/// The three regions the tag covers are sealed each from **its own start**, and
/// that is not the same as sealing the file: the header stays in the clear, the
/// entry table is one region, the names blob a second, and each payload a third
/// kind. `docs/rpf-format.md`, Encryption, `verified`.
///
/// The entry table is sealed **row by row**, which is sound only where a row is
/// one aligned cipher block of it. That is [`Archive::seal`]'s to ask and it
/// refuses a version where it does not hold, so a [`Under`] carrying a seal has
/// already been answered for (§3).
///
/// # Errors
///
/// As [`build`].
pub(crate) fn build_under<W, F>(
    out: &mut W,
    under: Under<'_>,
    files: &[FileSpec],
    directories: &[String],
    mut fetch: F,
    watch: &mut impl Watch,
) -> Result<Report>
where
    W: Write + Seek,
    F: Fetch,
{
    let Under {
        version,
        tag,
        sealer,
        name,
    } = under;
    let sealed = sealer.map(|sealer| Sealed::new(sealer, tag));
    let arena = plan_tree(files, directories)?;
    let planned = plan_entries(&arena)?;
    let names = version.plan_names(planned.iter().map(|entry| entry.name().as_str()))?;
    let (names_blob, name_offsets) = (names.blob, names.offsets);

    let entry_count = u32::try_from(planned.len()).map_err(|_| Error::FieldOverflow {
        path: String::new(),
        what: "entry count",
        len: u64::try_from(planned.len()).unwrap_or(u64::MAX),
        limit: u64::from(u32::MAX),
    })?;
    let names_len = u32::try_from(names_blob.len()).unwrap_or(u32::MAX);

    let table_len = u64::from(entry_count).saturating_mul(version.row_len());
    // The same sum `Archive` checks every payload offset against, so an archive
    // laid out here cannot have its first payload refused by the reader.
    let floor = version.payload_floor(u64::from(entry_count), u64::from(names_len));
    let mut cursor = align_up(version, floor).ok_or(Error::FieldOverflow {
        path: String::new(),
        what: "archive length",
        len: floor,
        limit: u64::MAX,
    })?;

    // Payloads first, at their aligned positions, one file resident at a time.
    let layout = Layout {
        version,
        files,
        planned: &planned,
        name_offsets: &name_offsets,
        sealed,
    };
    let (rows, payload_end) = write_payloads(out, &layout, &mut cursor, &mut fetch, watch)?;

    // **The table of contents and the names blob are keyed by the archive's own
    // name and its *finished* length**, which is why this is minted here and
    // not before a payload was written: `cursor` is where the last payload
    // ended, rounded up to the block the padding below fills, and that is the
    // length the file has on disk and the length the reader will hand
    // `Cipher::new`. Keying by the length the archive had *before* it was
    // rebuilt picks a different one of the 101 NG keys and writes an archive
    // that parses and does not load (Q2, DR-062). The AES arm ignores both and
    // is unaffected either way.
    let regions = match sealed {
        None => None,
        Some(sealed) => Some(sealed.of(name, cursor)?),
    };
    let regions = regions.as_ref();

    // Then the header, the table and the names, now that every offset is known.
    out.seek(SeekFrom::Start(0))
        .map_err(|source| Error::Io { offset: 0, source })?;
    let header = Header {
        version,
        entry_count,
        names_len,
        encryption: tag,
    };
    // The header is never under the transform: it is what says there is one.
    out.write_all(&header.write())
        .map_err(|source| Error::Io { offset: 0, source })?;
    // Row by row rather than table by table, which is what
    // `Version::row_is_a_cipher_block` buys and why it was asked above: a row
    // is one whole aligned block of the transform over the entry table, so
    // sealing each in turn is sealing the region. Nothing is materialised that
    // was not already.
    for row in &rows {
        let row = match regions {
            None => *row,
            Some(seal) => row.sealed(seal),
        };
        out.write_all(row.as_bytes()).map_err(|source| Error::Io {
            offset: version.header_len(),
            source,
        })?;
    }
    // The names blob is a region of its own, sealed from **its** start and not
    // from the table's — a build that sealed the two as one gets the table
    // right and the names wrong. `docs/rpf-format.md`, Encryption, `verified`.
    let mut names_blob = names_blob;
    if let Some(seal) = regions {
        seal.apply(&mut names_blob);
    }
    out.write_all(&names_blob).map_err(|source| Error::Io {
        offset: version.header_len().saturating_add(table_len),
        source,
    })?;

    // Pad to the last block so the archive's length matches what the entries
    // describe. It is written from the end of what was written, never backwards
    // from `cursor`: when the last payload ends exactly on a block boundary
    // there is nothing to pad, and a byte written at `cursor - 1` to stretch
    // the file is that payload's own last byte. Nothing catches it afterwards —
    // the archive parses, the row is right, and a stored entry has no checksum
    // and no deflate stream to disagree with.
    //
    // Slack is written zero rather than left as a hole: real archives carry
    // stale bytes there, which is a thing to tolerate on read and not to
    // reproduce (§8).
    //
    // Where padding begins: past the last byte any payload wrote, or past the
    // names blob when no payload wrote one — which covers both an archive with
    // no files and an archive whose payloads are all empty.
    let written_to = payload_end.max(floor);
    // Under one block by construction — `cursor` is `written_to` rounded up to
    // the next boundary — so the conversion cannot lose anything.
    let pad = usize::try_from(cursor.saturating_sub(written_to)).unwrap_or_default();
    if pad > 0 {
        out.seek(SeekFrom::Start(written_to))
            .map_err(|source| Error::Io {
                offset: written_to,
                source,
            })?;
        out.write_all(&vec![0_u8; pad])
            .map_err(|source| Error::Io {
                offset: written_to,
                source,
            })?;
    }
    out.flush().map_err(|source| Error::Io {
        offset: cursor,
        source,
    })?;

    Ok(Report {
        entry_count,
        names_len,
        len: cursor,
    })
}

/// One file's row, from a path, a name offset, a block and a written payload.
///
/// The one place the three of those become the version's fields (§4). A rebuild
/// reaches it through [`write_payloads`] and an in-place patch through
/// [`crate::patch::plan`], and both go through [`Version::file_row`] so that
/// neither can narrow a value the other would have refused.
///
/// # Errors
///
/// [`Error::FieldOverflow`] for a value the row cannot represent, and
/// [`Error::ArchiveTooLarge`] for a payload laid out past what the version
/// addresses. Only a rebuild reaches the second: an in-place patch's block
/// comes back out of the entry it is patching, so it is already inside the
/// field it is about to be written into.
pub(crate) fn file_row(
    version: Version,
    path: &str,
    name_offset: u32,
    block: u64,
    written: &Written,
) -> Result<Row> {
    version.file_row(
        path,
        &FileFields {
            name_offset,
            block,
            compressed_len: written.compressed_len,
            content: written.content,
        },
    )
}

/// The specification that would rebuild an archive as it stands, paired with
/// the entry index each file came from.
///
/// The storage choice is read off the original rather than guessed: an entry
/// that was stored stays stored, and one that was deflated is offered to the
/// compressor again. Deflate is not deterministic across implementations, so a
/// rebuild preserves contents, not bytes.
///
/// # Errors
///
/// As [`Archive::path`], for an entry whose ancestry does not resolve;
/// [`Error::BadPath`] for a name [`name::check_tree`] refuses, which is the
/// read half of that rule — a name that cannot be one node of a tree is refused
/// here rather than addressed as another node by whoever reads it; and
/// [`Error::NameCollision`] as [`Archive::check_names`].
pub fn specs_of(archive: &Archive) -> Result<Vec<(FileSpec, u32)>> {
    archive.check_names()?;
    let count = u32::try_from(archive.entries().len()).unwrap_or(u32::MAX);
    let mut out = Vec::new();
    for index in 0..count {
        let entry = archive.entry(index)?;
        if entry.is_directory() {
            continue;
        }
        let path = archive.path(index)?;
        let kind = kind_of(&path, entry)?;
        name::check_tree(&path)?;
        out.push((FileSpec { path, kind }, index));
    }
    Ok(out)
}

/// Every directory in an archive, by path, root excluded.
///
/// Carried through a rebuild so a directory holding no files is not lost on the
/// way: `build` derives parents from file paths, which cannot see one.
///
/// # Errors
///
/// As [`Archive::path`], [`Error::BadPath`] for a name [`name::check_tree`]
/// refuses, and [`Error::NameCollision`] as [`Archive::check_names`].
pub fn directories_of(archive: &Archive) -> Result<Vec<String>> {
    archive.check_names()?;
    let count = u32::try_from(archive.entries().len()).unwrap_or(u32::MAX);
    let mut out = Vec::new();
    for index in 1..count {
        if archive.entry(index)?.is_directory() {
            let path = archive.path(index)?;
            name::check_tree(&path)?;
            out.push(path);
        }
    }
    Ok(out)
}

/// Rebuilds `archive` into `out` with `changes` applied to what it holds,
/// taking each payload from the source except where `overrides` supplies one.
///
/// `changes` is what the rebuilt archive holds that the original did not, and
/// the other way round: an entry added, removed or renamed, and new contents
/// for one that stays. `edit::tree_of` is where each of those is
/// resolved and refused; nothing about them is decided here.
///
/// An override is the file **as it exists outside the archive** — the same form
/// [`Archive::extracted`] streams, so a resource keeps its `RSC7` header. That
/// is the form [`build`]'s [`Fetch`] is defined in, and using one form
/// throughout is what keeps a replaced resource from losing its flags.
/// Overrides are keyed by the entry index they replace, which is what makes
/// them survive a rename: the entry moves, and the bytes a cascade rebuilt for
/// it move with it.
///
/// **An entry the overrides do not cover is streamed out of `src` as it is
/// written**, never held: what a rebuild costs is its buffers, not its largest
/// entry. R3.9.
///
/// The map is taken by value and each override is **moved out of it** as its
/// entry is written, because an override may be a whole rebuilt ancestor and
/// copying one to hand it over is the cost R4.13 exists to remove. Each entry
/// is written once, so each override is taken once; one left over was for an
/// entry this archive does not have.
///
/// The rebuilt archive is written at the version the original was read at. A
/// rebuild is not a conversion, and this is where that is said.
///
/// # Errors
///
/// As `edit::tree_of` for a change that cannot be made, as [`build`],
/// plus the read errors for payloads taken from the source.
pub fn rebuild<'p, R, W>(
    src: &mut R,
    archive: &Archive,
    changes: &'p Changes,
    out: &mut W,
    overrides: BTreeMap<u32, Box<dyn Payload + 'p>>,
    watch: &mut impl Watch,
) -> Result<Report>
where
    R: Read + Seek,
    W: Write + Seek,
{
    let tree = edit::tree_of(&mut *src, archive, changes)?;
    let files = tree.files();
    // The archive's own transform, asked once for the whole rebuild: the entry
    // table, the names blob and every payload that carries the field go under
    // the same one. An AES key takes neither a name nor a length, so a rebuild
    // that is longer, shorter, or written under another file name is under the
    // key it was read under — which is what makes an AES archive writable and
    // an NG one not. `docs/rpf-format.md`, Encryption; DR-054.
    let sealer = archive.seal()?;
    let under = match sealer {
        None => Under::open(archive.version()),
        // The name is the one the archive was **opened** under, not the scratch
        // file this is written into: a rebuild renames over the original
        // (DR-035), so that is the name the reader will key the table of
        // contents by.
        Some(ref sealer) => Under::sealed(
            archive.version(),
            archive.encryption(),
            sealer,
            archive.keyed_name(),
        ),
    };
    let fetch = FromArchive {
        src,
        archive,
        changes,
        sources: tree.sources(),
        overrides,
    };

    build_under(out, under, &files, &tree.directories, fetch, watch)
}

/// Where a [`rebuild`] takes each payload from: an override the caller
/// supplied, contents a change carries, or the archive itself.
///
/// A struct rather than a closure because the third of those **borrows the
/// archive's source for as long as it is read**, which is what [`Fetch`] exists
/// to allow: a closure would have to extract the entry into a buffer to hand it
/// over, and that buffer is what R3.9 is about.
struct FromArchive<'a, R> {
    src: &'a mut R,
    archive: &'a Archive,
    changes: &'a Changes,
    /// Where each file of the rebuilt tree gets its bytes, by the path it will
    /// be written at.
    sources: BTreeMap<&'a str, &'a edit::Source>,
    /// Taken by value, and each one **moved out** as its entry is written: an
    /// override may be a whole rebuilt ancestor, and copying one to hand it
    /// over is the cost R4.13 exists to remove.
    overrides: BTreeMap<u32, Box<dyn Payload + 'a>>,
}

impl<R: Read + Seek> Fetch for FromArchive<'_, R> {
    type Payload<'a>
        = Box<dyn Payload + 'a>
    where
        Self: 'a;

    fn payload(&mut self, wanted: &str) -> Result<Box<dyn Payload + '_>> {
        let source = *self.sources.get(wanted).ok_or_else(|| Error::BadPath {
            path: wanted.to_owned(),
            reason: "not an entry of this archive",
        })?;
        match *source {
            edit::Source::Entry(index) => match self.overrides.remove(&index) {
                Some(payload) => Ok(payload),
                None => Ok(Box::new(self.archive.extracted(&mut *self.src, index)?)),
            },
            edit::Source::Written(ref at) => {
                let contents = self.changes.contents_at(at).ok_or_else(|| Error::BadPath {
                    path: wanted.to_owned(),
                    reason: "has no contents to write",
                })?;
                contents.open()
            }
        }
    }
}

/// Rebuilds `archive` into `out` with a set of changes, **cascading through
/// nesting**.
///
/// Paths may address through nested archives in one string, as
/// [`Archive::locate`] does. Changes are grouped by the archive they land in,
/// so several inside one nested archive rebuild it **once** rather than once
/// each — which is the difference between an editor saving three files and an
/// editor rebuilding a 62 MB payload three times.
///
/// **Each rebuilt ancestor goes to scratch space and is streamed from there
/// into its parent**, never assembled in memory, so what is held at once does
/// not scale with the ancestor. Where that space comes from is the caller's
/// answer, because this crate opens no files: [`Scratch`], DR-022, R4.13.
///
/// `done` and `total` in a [`Step`] count the archive being written now rather
/// than the whole nesting, unchanged by this: there is no honest total for a
/// cascade until it has been walked. DR-008's fourth amendment.
///
/// Two changes that resolve to one entry are refused, whether they spell it the
/// same way or not: `x/y`, `x//y` and `X/Y` are one file, and a whole nested
/// archive and a file inside it are the same bytes twice.
/// [`crate::patch::plan`] refuses exactly these, and the two write paths have
/// to agree — a caller that falls back from one to the other would otherwise
/// get a different archive depending on which ran.
///
/// # Errors
///
/// [`Error::NotFound`] for a path that does not resolve,
/// [`Error::NotAnArchive`] for a component that is not one,
/// [`Error::Overlapping`] for two changes that resolve to one entry, and as
/// [`rebuild`].
pub fn rewrite<R, W, S>(
    src: &mut R,
    archive: &Archive,
    changes: &Changes,
    out: &mut W,
    scratch: &mut S,
    watch: &mut impl Watch,
) -> Result<Report>
where
    R: Read + Seek,
    W: Write + Seek,
    S: Scratch,
{
    let (here, nested) = edit::split(archive, changes)?;

    let mut overrides: BTreeMap<u32, Box<dyn Payload>> = BTreeMap::new();
    for (index, group) in nested {
        let holder = archive.open_nested(src, index)?;
        // The ancestor is rebuilt into scratch space and handed on as a reader
        // over it. It is never a `Vec`, which is the whole of R4.13: this used
        // to be `Cursor::new(Vec::new())` and then `buffer.into_inner()`, and
        // the archive above it copied that again to write it.
        let mut sink = scratch.create()?;
        rewrite(src, &holder, &group.changes, &mut sink, scratch, watch)
            .map_err(|failure| edit::respelled(failure, &group.spellings))?;
        overrides.insert(index, Box::new(sink));
    }

    rebuild(src, archive, &here, out, overrides, watch)
}

/// Whether this set can be committed as it stands, writing none of it.
///
/// The resolution [`rewrite`] performs, run and thrown away, at every level of
/// the nesting. It does not build, so a refusal only a row builder raises is
/// not among its answers. [`crate::allows`] is the same question asked of one
/// change joining a buffered set; this is the whole set, which is what a dry
/// run is about. R6.7.
///
/// # Errors
///
/// As [`rewrite`], less what only a build raises.
pub fn resolves<R>(src: &mut R, archive: &Archive, changes: &Changes) -> Result<()>
where
    R: Read + Seek,
{
    let (here, nested) = edit::split(archive, changes)?;
    for (index, group) in nested {
        let holder = archive.open_nested(src, index)?;
        resolves(src, &holder, &group.changes)
            .map_err(|failure| edit::respelled(failure, &group.spellings))?;
    }
    edit::tree_of(src, archive, &here).map(|_| ())
}

#[cfg(test)]
mod tests {
    //! What an archive written **under a transform** is, with no key material
    //! anywhere.
    //!
    //! `keys::Material::over_zeros` and the AES tag are what make this run on a
    //! machine with no game installed: the transform is real, the key is
    //! thirty-two zero bytes, and DR-006 is untouched because nothing here is or
    //! came from a key. The gated half — a Rockstar archive under a Rockstar
    //! key — is `crates/rpf-core/tests/encrypted.rs`.
    //!
    //! What this constrains is the whole of the AES write path in one claim: an
    //! archive written sealed **opens again and reads back**. No single-region
    //! assertion covers that, because the header, the entry table, the names
    //! blob and each payload are four different rules and getting any one of
    //! them wrong reads back as nonsense.

    use std::{
        cell::Cell,
        io::{Cursor, Seek, SeekFrom, Write},
        sync::Arc,
    };

    use super::{FileKind, FileSpec, Sink, Storage, Under, build_under};
    use crate::{
        archive::Archive,
        entry::EntryKind,
        error::Error,
        format::{
            Version,
            crypto::{CIPHER_BLOCK_LEN, Scheme, Seal, Sealer, synthetic},
            resource::{MAGIC_RSC7, RESOURCE_HEADER_LEN},
            rpf7, widen,
        },
        keys::{Material, Unlock},
        watch::Unwatched,
    };

    /// The zero-key AES forward transform, and the [`Unlock`] that opens what
    /// it wrote.
    fn zeroed(named: &str) -> (Sealer, Unlock) {
        let material = Arc::new(Material::over_zeros());
        let scheme = Version::Rpf7.scheme(rpf7::ENCRYPTION_AES).expect("AES");
        let sealer = Sealer::new(scheme, &material).expect("AES seals");
        (sealer, Unlock::held(material, named))
    }

    /// Files whose lengths straddle the cipher block: shorter than one, exactly
    /// one, and one with a tail — plus one that deflates.
    fn contents() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("short.bin", vec![b'a'; 7]),
            ("block.bin", vec![b'b'; 16]),
            ("tail.bin", (0..100_u8).collect()),
            (
                "deep/deflated.txt",
                b"the same words over and over ".repeat(40),
            ),
        ]
    }

    /// The same, as what to write.
    fn specs() -> Vec<FileSpec> {
        contents()
            .iter()
            .map(|(path, _)| FileSpec {
                path: (*path).to_owned(),
                // Stored for the first three, so the payload on disk **is** the
                // contents and a byte decrypted wrong is a byte compared wrong.
                // The fourth is deflated, so both storage rules are covered and
                // the deflate fallback's seek back to the payload's start is
                // exercised under the seal.
                kind: FileKind::Binary {
                    storage: if path.contains(".txt") {
                        Storage::Deflate
                    } else {
                        Storage::Stored
                    },
                    // 1: under the archive's own transform. `docs/rpf-format.md`,
                    // Entry table.
                    encryption: 1,
                },
            })
            .collect()
    }

    /// Builds that archive, sealed or not, and answers its bytes.
    fn built(under: Under<'_>) -> Vec<u8> {
        let held = contents();
        let mut out = Cursor::new(Vec::new());
        build_under(
            &mut out,
            under,
            &specs(),
            &[],
            |wanted: &str| {
                let found = held
                    .iter()
                    .find(|(path, _)| *path == wanted)
                    .map(|(_, bytes)| bytes.clone())
                    .unwrap_or_default();
                Ok(Cursor::new(found))
            },
            &mut Unwatched,
        )
        .expect("the archive builds");
        out.into_inner()
    }

    #[test]
    fn a_sealed_archive_opens_again_and_every_entry_reads_back() {
        let (sealer, unlock) = zeroed("sealed.rpf");
        let bytes = built(Under::sealed(
            Version::Rpf7,
            rpf7::ENCRYPTION_AES,
            &sealer,
            "sealed.rpf",
        ));
        let mut source = Cursor::new(bytes);
        let archive = Archive::open(&mut source, &unlock).expect("the sealed archive opens");
        assert_eq!(archive.encryption(), rpf7::ENCRYPTION_AES);
        assert_eq!(archive.scheme(), Some("AES-256"));

        for (path, expected) in contents() {
            let index = archive
                .find(path)
                .unwrap_or_else(|error| panic!("{path} does not resolve: {error}"));
            let read = archive
                .read(&mut source, index)
                .unwrap_or_else(|error| panic!("{path} does not read back: {error}"));
            assert_eq!(read, expected, "{path} came back different");
        }
    }

    #[test]
    fn the_header_is_in_the_clear_and_the_entry_table_is_not() {
        // What a build that sealed nothing, or sealed the header too, would
        // pass anyway: the tag is in the clear because it is what says there is
        // a transform, and the row after it is not, because it is under one.
        let (forward, _) = zeroed("sealed.rpf");
        let sealed = built(Under::sealed(
            Version::Rpf7,
            rpf7::ENCRYPTION_AES,
            &forward,
            "sealed.rpf",
        ));
        let open = built(Under::open(Version::Rpf7));

        assert_eq!(
            sealed.get(..4),
            open.get(..4),
            "the magic is not under the transform"
        );
        assert_eq!(
            sealed.get(12..16),
            Some(&rpf7::ENCRYPTION_AES.to_le_bytes()[..]),
            "the header does not carry the tag it was sealed under"
        );
        assert_eq!(
            sealed.len(),
            open.len(),
            "sealing changed the length of the archive"
        );
        assert_ne!(
            sealed.get(16..32),
            open.get(16..32),
            "the root directory row went out in the clear"
        );
    }

    #[test]
    fn a_sealed_archive_does_not_open_without_a_key() {
        // The other half of the claim above: "it opens with the key" says
        // nothing unless it does not open without one.
        let (sealer, _) = zeroed("sealed.rpf");
        let bytes = built(Under::sealed(
            Version::Rpf7,
            rpf7::ENCRYPTION_AES,
            &sealer,
            "sealed.rpf",
        ));
        let error = Archive::open(&mut Cursor::new(bytes), &Unlock::unkeyed())
            .expect_err("a sealed archive needs a key");
        assert!(
            matches!(error, Error::NeedsKey { tag } if tag == rpf7::ENCRYPTION_AES),
            "{error:?}"
        );
    }

    #[test]
    fn an_ng_tag_seals_only_where_the_material_derives_the_transform() {
        // **The re-aimed refusal, ungated.** Until DR-062 `Scheme::Ng.seals()`
        // was `false` for the tag, whatever anyone held: the answer was "this
        // build has no forward direction". It now asks the material, because
        // the seventeen rounds derive from the decrypt tables in milliseconds
        // and derive from nothing else — so the refusal means "this build has
        // nothing to derive it from", and it still fires for material that
        // carries no NG half. `Material::over_zeros` is exactly that material:
        // an AES key and a hash table and no memory image behind it.
        let empty = Material::over_zeros();
        assert!(!Scheme::Ng.seals(Some(&empty)));
        assert!(!Scheme::Ng.seals(None));
        assert!(Sealer::new(Scheme::Ng, &empty).is_none());
        assert!(Seal::new(Scheme::Ng, &empty, "a.bin", 16).is_none());

        // And it seals where the tables are there, which is the half that was
        // impossible before.
        let held = synthetic::ng_material(0x51EA_1000);
        assert!(Scheme::Ng.seals(Some(&held)));
        assert!(Sealer::new(Scheme::Ng, &held).is_some());

        // The AES arm is unchanged and is not a question about material: the
        // key is the tag's, and a caller holding none is answered by
        // `Error::WrongKey`, which says something else entirely.
        for tag in [rpf7::ENCRYPTION_AES, rpf7::ENCRYPTION_AES_LAUNCHER] {
            let scheme = Version::Rpf7.scheme(tag).expect("an AES tag");
            assert!(scheme.seals(None), "{tag:#010x} does not seal");
            assert!(scheme.seals(Some(&empty)), "{tag:#010x} does not seal");
        }
    }

    /// The synthetic NG transform, and the [`Unlock`] that opens what it wrote.
    ///
    /// No key material anywhere and none possible: `synthetic::ng_material` is
    /// arithmetic over a seed (DR-006), and what it makes testable is the write
    /// path rather than any value.
    fn ng_zeroed(named: &str) -> (Sealer, Unlock) {
        let material = Arc::new(synthetic::ng_material(0x0DE1_2A55));
        let scheme = Version::Rpf7.scheme(rpf7::ENCRYPTION_NG).expect("NG");
        let sealer = Sealer::new(scheme, &material).expect("synthetic tables derive");
        (sealer, Unlock::held(material, named))
    }

    #[test]
    fn an_ng_archive_is_written_and_opens_again_with_every_entry_intact() {
        // **R4.7's own claim, ungated.** An NG-tagged archive written by this
        // build — header, entry table, names blob and four payloads, three
        // stored and one deflated — opened again from the bytes it wrote and
        // read back entry by entry. A build that sealed the table under the
        // wrong one of the 101 keys does not open at all; one that sealed a
        // payload under the wrong key opens and hands back rubbish, so both
        // halves are claimed.
        let (sealer, unlock) = ng_zeroed("written.rpf");
        let bytes = built(Under::sealed(
            Version::Rpf7,
            rpf7::ENCRYPTION_NG,
            &sealer,
            "written.rpf",
        ));
        let mut source = Cursor::new(bytes);
        let archive = Archive::open(&mut source, &unlock).expect("the NG archive opens");
        assert_eq!(archive.encryption(), rpf7::ENCRYPTION_NG);
        assert_eq!(archive.scheme(), Some("NG"));
        archive
            .writable()
            .expect("an NG archive with material writes");

        for (path, expected) in contents() {
            let index = archive
                .find(path)
                .unwrap_or_else(|error| panic!("{path} does not resolve: {error}"));
            let read = archive
                .read(&mut source, index)
                .unwrap_or_else(|error| panic!("{path} does not read back: {error}"));
            assert_eq!(read, expected, "{path} came back different");
        }
    }

    #[test]
    fn an_ng_archive_does_not_open_without_the_material_that_wrote_it() {
        // The other half: "it opens with the material" says nothing unless it
        // does not open without it — which is also the claim that the bytes
        // went out under the transform rather than in the clear under an NG
        // tag, which is the shape that parses and does not load.
        let (sealer, _) = ng_zeroed("written.rpf");
        let bytes = built(Under::sealed(
            Version::Rpf7,
            rpf7::ENCRYPTION_NG,
            &sealer,
            "written.rpf",
        ));
        let error = Archive::open(&mut Cursor::new(bytes), &Unlock::unkeyed())
            .expect_err("an NG archive needs its material");
        assert!(
            matches!(error, Error::NeedsKey { tag } if tag == rpf7::ENCRYPTION_NG),
            "{error:?}"
        );
    }

    #[test]
    fn an_ng_entry_written_at_a_new_size_picks_the_new_key_and_reads_back() {
        // **Q2, and the failure it names.** The NG key index is
        // `(hash(name) + length + 61) % 101`, so an entry rewritten at a
        // different uncompressed length picks a *different* one of the 101
        // keys. A writer that sealed it under the key the entry had before
        // produces an archive that parses — the table of contents is right,
        // the row is right, the length is right — and does not load, because
        // the payload decrypts to noise.
        //
        // The two sizes below are chosen so that the index actually moves:
        // asserted rather than assumed, because a test where both sizes chose
        // the same key would pass against a writer that never re-keyed at all.
        let (sealer, unlock) = ng_zeroed("resized.rpf");
        // 48 and 49 move the **payload's** key while leaving the archive's own
        // length alone; 700 also moves the archive past a block boundary, so
        // the table of contents and the names blob are re-keyed too — the
        // second of the two re-derivations, and the one a rebuild depends on.
        let sizes = [48_usize, 49, 700];
        assert_ne!(
            sealer.seal("grows.bin", 48).and_then(|s| s.key_index()),
            sealer.seal("grows.bin", 49).and_then(|s| s.key_index()),
            "the two sizes chose the same key, so this test proves nothing"
        );

        let spec = FileSpec {
            path: "grows.bin".to_owned(),
            kind: FileKind::Binary {
                storage: Storage::Stored,
                encryption: 1,
            },
        };
        let mut lengths = Vec::new();
        for size in sizes {
            let held = vec![b'z'; size];
            let mut out = Cursor::new(Vec::new());
            build_under(
                &mut out,
                Under::sealed(Version::Rpf7, rpf7::ENCRYPTION_NG, &sealer, "resized.rpf"),
                std::slice::from_ref(&spec),
                &[],
                |_: &str| Ok(Cursor::new(held.clone())),
                &mut Unwatched,
            )
            .expect("the archive builds");
            let written = out.into_inner();
            lengths.push(written.len());
            let mut source = Cursor::new(written);
            let archive = Archive::open(&mut source, &unlock).expect("it opens");
            let index = archive.find("grows.bin").expect("grows.bin resolves");
            assert_eq!(
                archive.read(&mut source, index).expect("it reads back"),
                held,
                "an entry of {size} bytes did not read back"
            );
        }
        lengths.sort_unstable();
        lengths.dedup();
        assert!(
            lengths.len() > 1,
            "every size wrote an archive of the same length, so the table of \
             contents was never re-keyed"
        );
    }

    #[test]
    fn one_entry_row_is_one_block_of_the_transform_over_the_entry_table() {
        // What lets an in-place patch reseal a single row. It is a coincidence
        // of three numbers rather than a rule the format states, so it is
        // asserted rather than assumed. `docs/rpf-format.md`, Entry table.
        assert!(Version::Rpf7.row_is_a_cipher_block());
        assert_eq!(
            Version::Rpf7.row_len(),
            crate::format::crypto::CIPHER_BLOCK_LEN as u64
        );
    }

    #[test]
    fn a_resource_payload_is_never_written_through_the_transform() {
        // `FileKind::Resource` crosses in passthrough form (its own doc
        // comment above), and `is_sealed` is where that holds even under an
        // archive written under a seal: a resource says `false` regardless of
        // the archive's own tag, because a resource has no per-entry field for
        // the read side to know a transform needs undoing. What lands on disk
        // must equal what went in, not the seal's transform of it.
        let (sealer, unlock) = zeroed("resource.rpf");
        let mut resource = vec![0_u8; usize::try_from(RESOURCE_HEADER_LEN).expect("fits")];
        resource[..4].copy_from_slice(&MAGIC_RSC7);
        resource[8..12].copy_from_slice(&7_u32.to_le_bytes());
        resource[12..16].copy_from_slice(&11_u32.to_le_bytes());
        resource.extend((0..64_u8).cycle().take(48));

        let spec = FileSpec {
            path: "resource.bin".to_owned(),
            kind: FileKind::Resource { declared: None },
        };
        let mut out = Cursor::new(Vec::new());
        build_under(
            &mut out,
            Under::sealed(Version::Rpf7, rpf7::ENCRYPTION_AES, &sealer, "resource.rpf"),
            std::slice::from_ref(&spec),
            &[],
            |wanted: &str| {
                assert_eq!(wanted, "resource.bin");
                Ok(Cursor::new(resource.clone()))
            },
            &mut Unwatched,
        )
        .expect("the archive builds");
        let bytes = out.into_inner();

        let mut source = Cursor::new(bytes.clone());
        let archive = Archive::open(&mut source, &unlock).expect("the sealed archive opens");
        let index = archive.find("resource.bin").expect("resource.bin resolves");
        let EntryKind::Resource { block, .. } = archive.entry(index).expect("entry").kind else {
            panic!("resource.bin did not decode as a resource entry");
        };
        let at = usize::try_from(u64::from(block).saturating_mul(Version::Rpf7.block_len()))
            .expect("offset fits");
        let end = at.saturating_add(resource.len());
        let on_disk = bytes.get(at..end).expect("payload is in bounds");
        assert_eq!(
            on_disk, resource,
            "a resource payload came out under the archive's transform"
        );
    }

    /// A writer that counts the flushes it receives, so a `Write` impl that
    /// forwards to it can be told apart from one that swallows the call.
    struct Counting {
        inner: Cursor<Vec<u8>>,
        flushes: Cell<u32>,
    }

    impl Write for Counting {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.inner.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes.set(self.flushes.get().saturating_add(1));
            self.inner.flush()
        }
    }

    impl Seek for Counting {
        fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(to)
        }
    }

    #[test]
    fn sink_flush_reaches_the_writer_underneath_it_clear_and_sealed_alike() {
        let mut clear = Counting {
            inner: Cursor::new(Vec::new()),
            flushes: Cell::new(0),
        };
        Sink::new(&mut clear, None, 0)
            .flush()
            .expect("flush succeeds");
        assert_eq!(clear.flushes.get(), 1, "a clear Sink swallowed the flush");

        let mut under_seal = Counting {
            inner: Cursor::new(Vec::new()),
            flushes: Cell::new(0),
        };
        Sink::new(&mut under_seal, Some(&Seal::over_zeros()), 0)
            .flush()
            .expect("flush succeeds");
        assert_eq!(
            under_seal.flushes.get(),
            1,
            "a sealed Sink swallowed the flush"
        );
    }

    #[test]
    fn a_sealed_sink_seeks_only_to_its_own_block_boundaries() {
        // `store_deflated`'s fallback seeks a sealed sink back to a payload's
        // own start when the compressor did not pay for itself, and that start
        // is always a block boundary of the payload — the one case this method
        // exists to let through. A target that is not one is refused, because
        // nothing past it would decrypt right if it were allowed.
        let seal = Seal::over_zeros();
        let start = 16_u64;
        let mut inner = Cursor::new(vec![0_u8; 64]);
        let mut sink = Sink::new(&mut inner, Some(&seal), start);

        let aligned = start.saturating_add(widen(CIPHER_BLOCK_LEN));
        let at = sink
            .seek(SeekFrom::Start(aligned))
            .expect("a block boundary of the payload is a legal seek target");
        assert_eq!(at, aligned);

        let misaligned = aligned.saturating_add(1);
        sink.seek(SeekFrom::Start(misaligned))
            .expect_err("a non-boundary offset must be refused");
    }
}
