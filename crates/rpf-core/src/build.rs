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
    io::{Cursor, Read, Seek, SeekFrom, Write},
};

use flate2::{Compression, write::DeflateEncoder};

use crate::{
    archive::{Archive, MAX_DEPTH},
    entry::{Entry, EntryKind},
    error::{Error, Result},
    format::{
        Content, FileFields, Header, Row, Version, folded,
        resource::{MAGIC_RSC7, RESOURCE_HEADER_LEN},
        u32_at,
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
    /// The payload already carries its own flags and version, so nothing about
    /// it is reconstructed. Passthrough is a commitment: `docs/approach.md`.
    Resource,
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
/// [`Seek`] is one; a caller holding bytes wraps them in a [`Cursor`].
///
/// Seekable because [`store`] reads a payload twice in one case — the deflated
/// form that did not pay for itself, which is then written as it came.
pub trait Payload: Read + Seek {}

impl<T: Read + Seek> Payload for T {}

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
pub(crate) fn kind_of(index: u32, entry: &Entry) -> Result<FileKind> {
    match entry.kind {
        EntryKind::Directory { .. } => Err(Error::WrongKind {
            entry: index,
            found: "directory",
            wanted: "file",
        }),
        EntryKind::Resource { .. } => Ok(FileKind::Resource),
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
pub(crate) fn store<S, W>(
    version: Version,
    path: &str,
    kind: FileKind,
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
    src.rewind().map_err(|source| Error::Io {
        offset: start,
        source,
    })?;

    match kind {
        FileKind::Resource => store_resource(path, src, out, start),
        FileKind::Binary {
            storage: Storage::Stored,
            encryption,
        } => {
            let len = copy_all(src, out, start)?;
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
        } => store_deflated(version, path, encryption, src, out, start),
    }
}

/// [`store`] for a resource: written through untouched, with its own flags read
/// out of its `RSC7` header on the way past.
fn store_resource<S, W>(path: &str, src: &mut S, out: &mut W, start: u64) -> Result<Written>
where
    S: Payload,
    W: Write,
{
    // The header is read before anything goes out, so a payload that is not a
    // resource is refused with nothing written for it. Read rather than seeked
    // over: the flags in it are what the entry duplicates.
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
        });
    }
    let magic: [u8; 4] = head
        .get(0..4)
        .and_then(|s| s.try_into().ok())
        .unwrap_or_default();
    if magic != MAGIC_RSC7 {
        return Err(Error::NotAResource {
            path: path.to_owned(),
        });
    }
    // The flags are the payload's own, at offsets 8 and 12 of its RSC7 header,
    // and they are what the entry duplicates. Both are inside the sixteen bytes
    // checked just above, so the default is unreachable rather than a guess at
    // a truncated header.
    let word_at_8 = u32_at(&head, 8).unwrap_or_default();
    let word_at_12 = u32_at(&head, 12).unwrap_or_default();

    out.write_all(&head).map_err(|source| Error::Io {
        offset: start,
        source,
    })?;
    let len = RESOURCE_HEADER_LEN.saturating_add(copy_all(src, out, start)?);
    Ok(Written {
        compressed_len: len,
        content: Content::Resource {
            system_flags: word_at_8,
            graphics_flags: word_at_12,
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
    out: &mut W,
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
/// `watch` is stepped once per file written, and can stop the write. DR-008.
fn write_payloads<W, P, F>(
    out: &mut W,
    layout: &Layout<'_>,
    cursor: &mut u64,
    fetch: &mut F,
    watch: &mut impl Watch,
) -> Result<(Vec<Row>, u64)>
where
    W: Write + Seek,
    P: Payload,
    F: FnMut(&str) -> Result<P>,
{
    let Layout {
        version,
        files,
        planned,
        name_offsets,
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
        let written = store(version, &spec.path, spec.kind, &mut fetch(&spec.path)?, out)?;

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
/// `fetch` is called once per file, in entry-table order, and is given the
/// path from the [`FileSpec`]. What it answers is a [`Payload`] — a reader,
/// read from its start — and the bytes go straight through to `out`, so
/// neither a file nor the archive is resident. A caller holding bytes hands
/// back a [`Cursor`] over them.
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
pub fn build<W, P, F>(
    out: &mut W,
    version: Version,
    files: &[FileSpec],
    directories: &[String],
    mut fetch: F,
    watch: &mut impl Watch,
) -> Result<Report>
where
    W: Write + Seek,
    P: Payload,
    F: FnMut(&str) -> Result<P>,
{
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
    };
    let (rows, payload_end) = write_payloads(out, &layout, &mut cursor, &mut fetch, watch)?;

    // Then the header, the table and the names, now that every offset is known.
    out.seek(SeekFrom::Start(0))
        .map_err(|source| Error::Io { offset: 0, source })?;
    let header = Header {
        version,
        entry_count,
        names_len,
        encryption: version.open(),
    };
    out.write_all(&header.write())
        .map_err(|source| Error::Io { offset: 0, source })?;
    for row in &rows {
        out.write_all(row.as_bytes()).map_err(|source| Error::Io {
            offset: version.header_len(),
            source,
        })?;
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
/// [`Error::FieldOverflow`] for a value the row cannot represent.
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
        let kind = kind_of(index, entry)?;
        let path = archive.path(index)?;
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

/// Rebuilds `archive` into `out`, taking each payload from the source except
/// where `overrides` supplies one.
///
/// An override is the file **as it exists outside the archive** — the same form
/// [`Archive::extract`] returns, so a resource keeps its `RSC7` header. That is
/// the form [`build`]'s `fetch` is defined in, and using one form throughout is
/// what keeps a replaced resource from losing its flags.
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
/// As [`build`], plus the read errors for payloads taken from the source.
pub fn rebuild<'p, R, W>(
    src: &mut R,
    archive: &Archive,
    out: &mut W,
    mut overrides: BTreeMap<u32, Box<dyn Payload + 'p>>,
    watch: &mut impl Watch,
) -> Result<Report>
where
    R: Read + Seek,
    W: Write + Seek,
{
    let specs = specs_of(archive)?;
    let by_path: BTreeMap<&str, u32> = specs
        .iter()
        .map(|(spec, index)| (spec.path.as_str(), *index))
        .collect();
    let files: Vec<FileSpec> = specs.iter().map(|(spec, _)| spec.clone()).collect();
    let directories = directories_of(archive)?;

    build(
        out,
        archive.version(),
        &files,
        &directories,
        |wanted| {
            let index = *by_path.get(wanted).ok_or(Error::BadPath {
                path: wanted.to_owned(),
                reason: "not an entry of this archive",
            })?;
            match overrides.remove(&index) {
                Some(payload) => Ok(payload),
                None => Ok(Box::new(Cursor::new(archive.extract(src, index)?))),
            }
        },
        watch,
    )
}

/// Resolves the first component of `segments` that names a file, returning its
/// index and whatever path is left over.
///
/// A non-empty remainder means the file is an archive to descend into.
fn split_at_file<'a>(archive: &Archive, segments: &'a [&'a str]) -> Result<(u32, &'a [&'a str])> {
    let mut current = 0_u32;
    for (position, segment) in segments.iter().enumerate() {
        let index = archive
            .child_named(current, segment)?
            .ok_or_else(|| Error::NotFound {
                path: segments.join("/"),
                segment: (*segment).to_owned(),
            })?;
        if archive.entry(index)?.is_directory() {
            current = index;
            continue;
        }
        let rest = segments.get(position.saturating_add(1)..).unwrap_or(&[]);
        return Ok((index, rest));
    }
    Err(Error::NotFound {
        path: segments.join("/"),
        segment: segments.last().copied().unwrap_or_default().to_owned(),
    })
}

/// Rebuilds `archive` into `out` with any number of entries replaced,
/// **cascading through nesting**.
///
/// Paths may address through nested archives in one string, as
/// [`Archive::locate`] does. Edits are grouped by the archive they land in, so
/// several changes inside one nested archive rebuild it **once** rather than
/// once each — which is the difference between an editor saving three files and
/// an editor rebuilding a 62 MB payload three times.
///
/// Each value is the file as it exists outside the archive: for a resource, its
/// `RSC7` header and still-deflated body.
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
/// Two edits that resolve to one entry are refused, whether they spell it the
/// same way or not: `x/y`, `x//y` and `X/Y` are one file, and a whole nested
/// archive and a file inside it are the same bytes twice. [`crate::patch::plan`]
/// refuses exactly these, and the two write paths have to agree — a caller that
/// falls back from one to the other would otherwise get a different archive
/// depending on which ran.
///
/// # Errors
///
/// [`Error::NotFound`] for a path that does not resolve,
/// [`Error::NotAnArchive`] for a component that is not one,
/// [`Error::Overlapping`] for two edits that resolve to one entry, and as
/// [`build`].
pub fn replace_many<R, W, S>(
    src: &mut R,
    archive: &Archive,
    edits: &BTreeMap<String, Vec<u8>>,
    out: &mut W,
    scratch: &mut S,
    watch: &mut impl Watch,
) -> Result<Report>
where
    R: Read + Seek,
    W: Write + Seek,
    S: Scratch,
{
    let mut direct: BTreeMap<u32, Box<dyn Payload>> = BTreeMap::new();
    // Which edit replaced each entry outright, so a second one naming the same
    // entry is refused rather than quietly winning. Keying the edits by path
    // string and then by index collapsed them: last write won, and the losers
    // vanished with an Ok.
    let mut claimed: BTreeMap<u32, String> = BTreeMap::new();
    let mut deeper: BTreeMap<u32, Nested> = BTreeMap::new();

    for (path, contents) in edits {
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let (index, rest) = split_at_file(archive, &segments)?;

        if let Some(other) = claimed.get(&index) {
            return Err(Error::Overlapping {
                path: path.clone(),
                other: other.clone(),
            });
        }

        if rest.is_empty() {
            if let Some(nested) = deeper.get(&index) {
                return Err(Error::Overlapping {
                    path: path.clone(),
                    other: nested.first.clone(),
                });
            }
            claimed.insert(index, path.clone());
            direct.insert(index, Box::new(Cursor::new(contents.clone())));
        } else {
            let nested = deeper.entry(index).or_insert_with(|| Nested {
                first: path.clone(),
                edits: BTreeMap::new(),
            });
            if let Some((other, _)) = nested
                .edits
                .insert(rest.join("/"), (path.clone(), contents.clone()))
            {
                return Err(Error::Overlapping {
                    path: path.clone(),
                    other,
                });
            }
        }
    }

    for (index, nested) in deeper {
        let inner: BTreeMap<String, Vec<u8>> = nested
            .edits
            .into_iter()
            .map(|(within, (_, bytes))| (within, bytes))
            .collect();
        let holder = archive.open_nested(src, index)?;
        // The ancestor is rebuilt into scratch space and handed on as a reader
        // over it. It is never a `Vec`, which is the whole of R4.13: this used
        // to be `Cursor::new(Vec::new())` and then `buffer.into_inner()`, and
        // the archive above it copied that again to write it.
        let mut sink = scratch.create()?;
        replace_many(src, &holder, &inner, &mut sink, scratch, watch)?;
        direct.insert(index, Box::new(sink));
    }

    rebuild(src, archive, out, direct, watch)
}

/// The edits landing inside one nested archive.
struct Nested {
    /// The first edit that addressed through this archive. It is what an edit
    /// replacing the archive wholesale is reported as colliding with.
    first: String,
    /// Path within the nested archive, to the edit that named it and its new
    /// contents. Two spellings reaching one path within are two entries in the
    /// map only until the recursive call resolves them, which is where the
    /// refusal comes from; two reaching the *same* string are caught here.
    edits: BTreeMap<String, (String, Vec<u8>)>,
}
