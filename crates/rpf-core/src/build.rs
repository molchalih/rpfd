//! Writing an archive.
//!
//! The correctness-critical direction. Everything here is a way to produce an
//! archive that parses and does not load, so the rules it follows are the
//! measured ones, each citing its row in `docs/rpf-format.md`.
//!
//! Layout is computed before any payload is touched. The entry count and the
//! names blob follow from the paths alone, so the first payload's position is
//! known up front; payloads are then written in one pass and the header and
//! entry table filled in afterwards. That keeps one file in memory at a time
//! rather than the archive.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    io::{Cursor, Seek, SeekFrom, Write},
};

use flate2::{Compression, write::DeflateEncoder};

use crate::{
    archive::{Archive, MAX_DEPTH},
    entry::{Entry, EntryKind},
    error::{Error, Result},
    format::{
        BLOCK_LEN, ENCRYPTION_OPEN, ENTRY_LEN, HEADER_LEN, MAGIC_RPF7, MAGIC_RSC7, RESOURCE_FLAG,
        RESOURCE_HEADER_LEN, folded, payload_floor, u32_at,
    },
    watch::{Flow, Step, Watch},
};

/// Largest value a 24-bit size field holds.
const MAX_SIZE_24: u64 = 0x00FF_FFFF;
/// Largest block index, the resource bit excluded.
const MAX_BLOCK: u64 = 0x007F_FFFF;
/// Largest name offset a **file** entry holds. Directories get a full word.
const MAX_FILE_NAME_OFFSET: u64 = 0x0000_FFFF;

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

/// The child of `dir` that `name` would resolve to, or `None` if the name is
/// free.
///
/// Fails when a child is already there under a different spelling of the same
/// folded name: the two are indistinguishable to a reader, so writing both
/// loses one of them.
fn taken(dir: &Dir, path: &str, name: &str) -> Result<Option<Child>> {
    let Some(exact) = dir.folded.get(&folded(name)) else {
        return Ok(None);
    };
    if exact != name {
        return Err(Error::BadPath {
            path: path.to_owned(),
            reason: "two children of one directory differ only in case",
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
fn descend(arena: &mut Vec<Dir>, parent: usize, path: &str, segment: &str) -> Result<usize> {
    let dir = arena.get(parent).ok_or(Error::BadPath {
        path: path.to_owned(),
        reason: "unreachable parent",
    })?;
    match taken(dir, path, segment)? {
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

/// Rounds `value` up to the next multiple of [`BLOCK_LEN`].
fn align_up(value: u64) -> Option<u64> {
    let over = value % BLOCK_LEN;
    if over == 0 {
        return Some(value);
    }
    value.checked_add(BLOCK_LEN.checked_sub(over)?)
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
        let segments: Vec<&str> = directory.split('/').filter(|s| !s.is_empty()).collect();
        check_path_depth(segments.len())?;
        let mut current = 0_usize;
        for segment in segments {
            current = descend(&mut arena, current, directory, segment)?;
        }
    }

    for (index, spec) in files.iter().enumerate() {
        let segments: Vec<&str> = spec.path.split('/').collect();
        let Some((name, parents)) = segments.split_last() else {
            return Err(Error::BadPath {
                path: spec.path.clone(),
                reason: "empty",
            });
        };
        if name.is_empty() || parents.iter().any(|s| s.is_empty()) {
            return Err(Error::BadPath {
                path: spec.path.clone(),
                reason: "empty component",
            });
        }
        check_path_depth(segments.len())?;

        let mut current = 0_usize;
        for segment in parents {
            current = descend(&mut arena, current, &spec.path, segment)?;
        }

        let dir = arena.get(current).ok_or(Error::BadPath {
            path: spec.path.clone(),
            reason: "unreachable parent",
        })?;
        if taken(dir, &spec.path, name)?.is_some() {
            return Err(Error::BadPath {
                path: spec.path.clone(),
                reason: "duplicate",
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

/// Lays out the names blob, one copy of each distinct name.
fn plan_names(planned: &[Planned]) -> Result<(Vec<u8>, Vec<u32>)> {
    let mut blob = Vec::new();
    let mut seen: HashMap<&str, u32> = HashMap::new();
    let mut offsets = Vec::with_capacity(planned.len());

    for entry in planned {
        let name = entry.name().as_str();
        if let Some(&at) = seen.get(name) {
            offsets.push(at);
            continue;
        }
        let at = u32::try_from(blob.len()).map_err(|_| Error::FieldOverflow {
            path: name.to_owned(),
            what: "names blob",
            len: u64::try_from(blob.len()).unwrap_or(u64::MAX),
            limit: u64::from(u32::MAX),
        })?;
        blob.extend_from_slice(name.as_bytes());
        blob.push(0);
        seen.insert(name, at);
        offsets.push(at);
    }
    Ok((blob, offsets))
}

/// The payload of one file, ready to write, and the fields describing it.
///
/// `compressed_len` is left wide on purpose. Narrowing it to the entry's 24-bit
/// field is [`file_row`]'s job and nobody else's, so a value that will not fit
/// arrives there to be refused rather than being quietly cut down on the way.
pub(crate) struct Prepared {
    pub(crate) bytes: Vec<u8>,
    pub(crate) compressed_len: u64,
    pub(crate) word_at_8: u32,
    pub(crate) word_at_12: u32,
    pub(crate) resource: bool,
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

/// Applies a storage rule to one file's contents.
///
/// The one implementation of it. A rebuild reaches it with the rule the caller
/// asked for and a patch with the rule the entry already carries, but the rule
/// is applied here in both cases — the two used to apply it separately, and a
/// resource over the 24-bit size field was refused by one and truncated by the
/// other.
///
/// # Errors
///
/// [`Error::NotAResource`] for a resource whose payload is not one, and
/// [`Error::FieldOverflow`] for contents too long for the entry's fields.
pub(crate) fn prepare(path: &str, kind: FileKind, contents: Vec<u8>) -> Result<Prepared> {
    let plain_len = u64::try_from(contents.len()).unwrap_or(u64::MAX);

    match kind {
        FileKind::Resource => {
            if plain_len < RESOURCE_HEADER_LEN {
                return Err(Error::NotAResource {
                    path: path.to_owned(),
                });
            }
            let magic: [u8; 4] = contents
                .get(0..4)
                .and_then(|s| s.try_into().ok())
                .unwrap_or_default();
            if magic != MAGIC_RSC7 {
                return Err(Error::NotAResource {
                    path: path.to_owned(),
                });
            }
            // The flags are the payload's own, at offsets 8 and 12 of its
            // RSC7 header, and they are what the entry duplicates. Both are
            // inside the sixteen bytes checked just above, so the default is
            // unreachable rather than a guess at a truncated header.
            let word_at_8 = u32_at(&contents, 8).unwrap_or_default();
            let word_at_12 = u32_at(&contents, 12).unwrap_or_default();
            Ok(Prepared {
                bytes: contents,
                compressed_len: plain_len,
                word_at_8,
                word_at_12,
                resource: true,
            })
        }

        FileKind::Binary {
            storage,
            encryption,
        } => {
            let uncompressed = u32::try_from(plain_len).map_err(|_| Error::FieldOverflow {
                path: path.to_owned(),
                what: "uncompressed size",
                len: plain_len,
                limit: u64::from(u32::MAX),
            })?;

            if storage == Storage::Deflate {
                let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
                encoder
                    .write_all(&contents)
                    .and_then(|()| encoder.try_finish())
                    .map_err(|source| Error::Io { offset: 0, source })?;
                let deflated = encoder
                    .finish()
                    .map_err(|source| Error::Io { offset: 0, source })?;
                let deflated_len = u64::try_from(deflated.len()).unwrap_or(u64::MAX);

                // Deflating has to pay for itself, and it has to fit the field.
                // Falling back to stored is R4.4, not a workaround.
                if deflated_len < plain_len && deflated_len <= MAX_SIZE_24 {
                    return Ok(Prepared {
                        bytes: deflated,
                        compressed_len: deflated_len,
                        word_at_8: uncompressed,
                        word_at_12: encryption,
                        resource: false,
                    });
                }
            }

            // Stored: the compressed-size field is the sentinel zero and the
            // real length lives at offset 8. docs/rpf-format.md, Compression.
            Ok(Prepared {
                bytes: contents,
                compressed_len: 0,
                word_at_8: uncompressed,
                word_at_12: encryption,
                resource: false,
            })
        }
    }
}

/// Fails when a value will not fit its field.
fn check(path: &str, what: &'static str, len: u64, limit: u64) -> Result<()> {
    if len > limit {
        return Err(Error::FieldOverflow {
            path: path.to_owned(),
            what,
            len,
            limit,
        });
    }
    Ok(())
}

/// The tree as it will be written: the files as specified, the entries they
/// became, and the name offset of each.
///
/// Grouped because they are one thing — three parallel slices that only mean
/// anything together, and passing them singly put `write_payloads` over the
/// argument limit `clippy.toml` sets.
struct Layout<'a> {
    files: &'a [FileSpec],
    planned: &'a [Planned],
    name_offsets: &'a [u32],
}

/// Writes every payload at its aligned position, returning the entry rows and
/// the offset one past the **last byte actually written** — zero when nothing
/// was, which includes an archive whose every payload is empty.
///
/// `cursor` enters at the first payload's offset and leaves at the archive's
/// end. One file is resident at a time; the archive never is.
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
fn write_payloads<W, F>(
    out: &mut W,
    layout: &Layout<'_>,
    cursor: &mut u64,
    fetch: &mut F,
    watch: &mut impl Watch,
) -> Result<(Vec<[u8; 16]>, u64)>
where
    W: Write + Seek,
    F: FnMut(&str) -> Result<Vec<u8>>,
{
    let Layout {
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
                rows.push(directory_row(name_offset, first_child, child_count));
                continue;
            }
            Planned::File { spec, .. } => spec,
        };

        let spec = files.get(spec_index).ok_or(Error::BadPath {
            path: String::new(),
            reason: "unknown file",
        })?;
        let prepared = prepare(&spec.path, spec.kind, fetch(&spec.path)?)?;

        let at = *cursor;
        let block = at / BLOCK_LEN;
        // The row is built before the payload goes out, so a value the entry
        // cannot describe is refused with nothing written for it.
        let row = file_row(&spec.path, name_offset, block, &prepared)?;

        out.seek(SeekFrom::Start(at))
            .map_err(|source| Error::Io { offset: at, source })?;
        out.write_all(&prepared.bytes)
            .map_err(|source| Error::Io { offset: at, source })?;

        let written = u64::try_from(prepared.bytes.len()).unwrap_or(u64::MAX);
        // Only a write that put bytes somewhere moves the high-water mark. An
        // empty payload leaves the sink exactly as long as it was, so claiming
        // its start as the end of what was written loses everything between
        // there and the previous payload's last byte.
        if written > 0 {
            end = at.saturating_add(written);
        }
        *cursor = align_up(at.saturating_add(written)).ok_or(Error::FieldOverflow {
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
/// path from the [`FileSpec`]. One file is resident at a time; the archive
/// never is.
///
/// # Errors
///
/// [`Error::BadPath`] for a path that cannot become entries,
/// [`Error::NotAResource`] for a resource whose payload is not one,
/// [`Error::FieldOverflow`] when a value will not fit the format's field, and
/// [`Error::Io`] from the sink or from `fetch`.
pub fn build<W, F>(
    out: &mut W,
    files: &[FileSpec],
    directories: &[String],
    mut fetch: F,
    watch: &mut impl Watch,
) -> Result<Report>
where
    W: Write + Seek,
    F: FnMut(&str) -> Result<Vec<u8>>,
{
    let arena = plan_tree(files, directories)?;
    let planned = plan_entries(&arena)?;
    let (names_blob, name_offsets) = plan_names(&planned)?;

    let entry_count = u32::try_from(planned.len()).map_err(|_| Error::FieldOverflow {
        path: String::new(),
        what: "entry count",
        len: u64::try_from(planned.len()).unwrap_or(u64::MAX),
        limit: u64::from(u32::MAX),
    })?;
    let names_len = u32::try_from(names_blob.len()).unwrap_or(u32::MAX);

    let table_len = u64::from(entry_count).saturating_mul(ENTRY_LEN);
    // The same sum `Archive` checks every payload offset against, so an archive
    // laid out here cannot have its first payload refused by the reader.
    let floor = payload_floor(u64::from(entry_count), u64::from(names_len));
    let mut cursor = align_up(floor).ok_or(Error::FieldOverflow {
        path: String::new(),
        what: "archive length",
        len: floor,
        limit: u64::MAX,
    })?;

    // Payloads first, at their aligned positions, one file resident at a time.
    let layout = Layout {
        files,
        planned: &planned,
        name_offsets: &name_offsets,
    };
    let (rows, payload_end) = write_payloads(out, &layout, &mut cursor, &mut fetch, watch)?;

    // Then the header, the table and the names, now that every offset is known.
    out.seek(SeekFrom::Start(0))
        .map_err(|source| Error::Io { offset: 0, source })?;
    let mut header = Vec::with_capacity(16);
    header.extend_from_slice(&MAGIC_RPF7);
    header.extend_from_slice(&entry_count.to_le_bytes());
    header.extend_from_slice(&names_len.to_le_bytes());
    header.extend_from_slice(&ENCRYPTION_OPEN.to_le_bytes());
    out.write_all(&header)
        .map_err(|source| Error::Io { offset: 0, source })?;
    for row in &rows {
        out.write_all(row).map_err(|source| Error::Io {
            offset: HEADER_LEN,
            source,
        })?;
    }
    out.write_all(&names_blob).map_err(|source| Error::Io {
        offset: HEADER_LEN.saturating_add(table_len),
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

/// One directory row.
fn directory_row(name_offset: u32, first_child: u32, child_count: u32) -> [u8; 16] {
    let mut row = [0_u8; 16];
    row[0..4].copy_from_slice(&name_offset.to_le_bytes());
    row[4..8].copy_from_slice(&crate::format::DIRECTORY_MARKER.to_le_bytes());
    row[8..12].copy_from_slice(&first_child.to_le_bytes());
    row[12..16].copy_from_slice(&child_count.to_le_bytes());
    row
}

/// One file row: a 16-bit name offset, a 24-bit size and a 24-bit block, then
/// two words whose meaning depends on the resource bit.
///
/// Every narrow field is checked **here**, where the narrowing happens, rather
/// than by whoever calls it. A row is sixteen bytes of truncation waiting to
/// happen — the compressed size is written as the low three bytes of a wider
/// value, and dropping the top byte produces an entry that describes a
/// fraction of its own payload and reads back without complaint. The two
/// callers used to check different subsets of these, so one of them wrote that
/// row. A value that will not fit the format cannot now become a row at all.
///
/// # Errors
///
/// [`Error::FieldOverflow`] for a value the row cannot represent.
pub(crate) fn file_row(
    path: &str,
    name_offset: u32,
    block: u64,
    prepared: &Prepared,
) -> Result<[u8; 16]> {
    check(
        path,
        "file name offset",
        u64::from(name_offset),
        MAX_FILE_NAME_OFFSET,
    )?;
    check(
        path,
        "compressed size",
        prepared.compressed_len,
        MAX_SIZE_24,
    )?;
    check(path, "block offset", block, MAX_BLOCK)?;

    let offset_field = if prepared.resource {
        block | u64::from(RESOURCE_FLAG)
    } else {
        block
    };

    let mut row = [0_u8; 16];
    row[0..2].copy_from_slice(&name_offset.to_le_bytes()[..2]);
    row[2..5].copy_from_slice(&prepared.compressed_len.to_le_bytes()[..3]);
    row[5..8].copy_from_slice(&offset_field.to_le_bytes()[..3]);
    row[8..12].copy_from_slice(&prepared.word_at_8.to_le_bytes());
    row[12..16].copy_from_slice(&prepared.word_at_12.to_le_bytes());
    Ok(row)
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
/// As [`Archive::path`], for an entry whose ancestry does not resolve.
pub fn specs_of(archive: &Archive) -> Result<Vec<(FileSpec, u32)>> {
    let count = u32::try_from(archive.entries().len()).unwrap_or(u32::MAX);
    let mut out = Vec::new();
    for index in 0..count {
        let entry = archive.entry(index)?;
        if entry.is_directory() {
            continue;
        }
        let kind = kind_of(index, entry)?;
        out.push((
            FileSpec {
                path: archive.path(index)?,
                kind,
            },
            index,
        ));
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
/// As [`Archive::path`].
pub fn directories_of(archive: &Archive) -> Result<Vec<String>> {
    let count = u32::try_from(archive.entries().len()).unwrap_or(u32::MAX);
    let mut out = Vec::new();
    for index in 1..count {
        if archive.entry(index)?.is_directory() {
            out.push(archive.path(index)?);
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
/// # Errors
///
/// As [`build`], plus the read errors for payloads taken from the source.
pub fn rebuild<R, W>(
    src: &mut R,
    archive: &Archive,
    out: &mut W,
    overrides: &BTreeMap<u32, Vec<u8>>,
    watch: &mut impl Watch,
) -> Result<Report>
where
    R: std::io::Read + Seek,
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
        &files,
        &directories,
        |wanted| {
            let index = *by_path.get(wanted).ok_or(Error::BadPath {
                path: wanted.to_owned(),
                reason: "not an entry of this archive",
            })?;
            match overrides.get(&index) {
                Some(bytes) => Ok(bytes.clone()),
                None => archive.extract(src, index),
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
            .child_named(current, segment)
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

/// Rebuilds `archive` into `out` with one entry replaced, **cascading through
/// nesting**.
///
/// A convenience for the single-edit case; see [`replace_many`], which is where
/// the work happens.
///
/// # Errors
///
/// As [`replace_many`].
pub fn replace_at<R, W>(
    src: &mut R,
    archive: &Archive,
    path: &str,
    contents: Vec<u8>,
    out: &mut W,
    watch: &mut impl Watch,
) -> Result<Report>
where
    R: std::io::Read + Seek,
    W: Write + Seek,
{
    let mut edits = BTreeMap::new();
    edits.insert(path.to_owned(), contents);
    replace_many(src, archive, &edits, out, watch)
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
/// Intermediates are rebuilt in memory one level at a time, so peak cost is the
/// largest single ancestor. `docs/backlog.md` R4.13.
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
pub fn replace_many<R, W>(
    src: &mut R,
    archive: &Archive,
    edits: &BTreeMap<String, Vec<u8>>,
    out: &mut W,
    watch: &mut impl Watch,
) -> Result<Report>
where
    R: std::io::Read + Seek,
    W: Write + Seek,
{
    let mut direct: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
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
            direct.insert(index, contents.clone());
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
        let mut buffer = Cursor::new(Vec::new());
        replace_many(src, &holder, &inner, &mut buffer, watch)?;
        direct.insert(index, buffer.into_inner());
    }

    rebuild(src, archive, out, &direct, watch)
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
