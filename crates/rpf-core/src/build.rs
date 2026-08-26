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
    archive::Archive,
    entry::EntryKind,
    error::{Error, Result},
    format::{
        BLOCK_LEN, ENCRYPTION_OPEN, ENTRY_LEN, HEADER_LEN, MAGIC_RPF7, MAGIC_RSC7, RESOURCE_FLAG,
        RESOURCE_HEADER_LEN,
    },
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
}

enum Child {
    Dir(usize),
    File(usize),
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

/// Builds the directory tree, returning the arena and the root's id.
fn plan_tree(files: &[FileSpec], directories: &[String]) -> Result<Vec<Dir>> {
    let mut arena: Vec<Dir> = vec![Dir::default()];
    let mut lookup: HashMap<(usize, String), usize> = HashMap::new();

    // Directories named outright, so that one holding no files still survives a
    // round trip. Files create their own parents below; this adds only what
    // nothing else would.
    for directory in directories {
        let mut current = 0_usize;
        for segment in directory.split('/').filter(|s| !s.is_empty()) {
            let key = (current, segment.to_owned());
            current = if let Some(&existing) = lookup.get(&key) {
                existing
            } else {
                arena.push(Dir::default());
                let created = arena.len().saturating_sub(1);
                lookup.insert(key, created);
                let slot = arena.get_mut(current).ok_or(Error::BadPath {
                    path: directory.clone(),
                    reason: "unreachable parent",
                })?;
                slot.children
                    .insert(segment.to_owned(), Child::Dir(created));
                created
            };
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

        let mut current = 0_usize;
        for segment in parents {
            let key = (current, (*segment).to_owned());
            current = if let Some(&existing) = lookup.get(&key) {
                existing
            } else {
                arena.push(Dir::default());
                let created = arena.len().saturating_sub(1);
                lookup.insert(key, created);
                let slot = arena.get_mut(current).ok_or(Error::BadPath {
                    path: spec.path.clone(),
                    reason: "unreachable parent",
                })?;
                slot.children
                    .insert((*segment).to_owned(), Child::Dir(created));
                created
            };
        }

        let slot = arena.get_mut(current).ok_or(Error::BadPath {
            path: spec.path.clone(),
            reason: "unreachable parent",
        })?;
        if slot
            .children
            .insert((*name).to_owned(), Child::File(index))
            .is_some()
        {
            return Err(Error::BadPath {
                path: spec.path.clone(),
                reason: "duplicate",
            });
        }
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
struct Prepared {
    bytes: Vec<u8>,
    compressed_len: u32,
    word_at_8: u32,
    word_at_12: u32,
    resource: bool,
}

/// Applies the storage rule to one file's contents.
fn prepare(path: &str, kind: FileKind, contents: Vec<u8>) -> Result<Prepared> {
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
            check(path, "resource size", plain_len, MAX_SIZE_24)?;
            // The flags are the payload's own, at offsets 8 and 12 of its
            // RSC7 header, and they are what the entry duplicates.
            let word_at_8 = word(&contents, 8);
            let word_at_12 = word(&contents, 12);
            let compressed_len = u32::try_from(plain_len).unwrap_or(u32::MAX);
            Ok(Prepared {
                bytes: contents,
                compressed_len,
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
                    let compressed_len = u32::try_from(deflated_len).unwrap_or(u32::MAX);
                    return Ok(Prepared {
                        bytes: deflated,
                        compressed_len,
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

/// Reads a little-endian word, zero if it does not fit.
fn word(bytes: &[u8], at: usize) -> u32 {
    let raw: [u8; 4] = bytes
        .get(at..at.saturating_add(4))
        .and_then(|s| s.try_into().ok())
        .unwrap_or_default();
    u32::from_le_bytes(raw)
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

/// Writes every payload at its aligned position, returning the entry rows.
///
/// `cursor` enters at the first payload's offset and leaves at the archive's
/// end. One file is resident at a time; the archive never is.
fn write_payloads<W, F>(
    out: &mut W,
    files: &[FileSpec],
    planned: &[Planned],
    name_offsets: &[u32],
    cursor: &mut u64,
    fetch: &mut F,
) -> Result<Vec<[u8; 16]>>
where
    W: Write + Seek,
    F: FnMut(&str) -> Result<Vec<u8>>,
{
    let mut rows = Vec::with_capacity(planned.len());

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
        check(&spec.path, "block offset", block, MAX_BLOCK)?;
        check(
            &spec.path,
            "file name offset",
            u64::from(name_offset),
            MAX_FILE_NAME_OFFSET,
        )?;

        out.seek(SeekFrom::Start(at))
            .map_err(|source| Error::Io { offset: at, source })?;
        out.write_all(&prepared.bytes)
            .map_err(|source| Error::Io { offset: at, source })?;

        let written = u64::try_from(prepared.bytes.len()).unwrap_or(u64::MAX);
        *cursor = align_up(at.saturating_add(written)).ok_or(Error::FieldOverflow {
            path: spec.path.clone(),
            what: "archive length",
            len: at,
            limit: u64::MAX,
        })?;

        rows.push(file_row(
            name_offset,
            prepared.compressed_len,
            u32::try_from(block).unwrap_or(u32::MAX),
            prepared.resource,
            prepared.word_at_8,
            prepared.word_at_12,
        ));
    }
    Ok(rows)
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
    let header_region = HEADER_LEN
        .saturating_add(table_len)
        .saturating_add(u64::from(names_len));
    let mut cursor = align_up(header_region).ok_or(Error::FieldOverflow {
        path: String::new(),
        what: "archive length",
        len: header_region,
        limit: u64::MAX,
    })?;

    // Payloads first, at their aligned positions, one file resident at a time.
    let rows = write_payloads(out, files, &planned, &name_offsets, &mut cursor, &mut fetch)?;

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
    // describe. Slack is zero here by construction; real archives carry stale
    // bytes in it, which is a thing to tolerate on read, not to reproduce.
    out.seek(SeekFrom::Start(cursor.saturating_sub(1)))
        .map_err(|source| Error::Io {
            offset: cursor,
            source,
        })?;
    out.write_all(&[0]).map_err(|source| Error::Io {
        offset: cursor,
        source,
    })?;
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
fn file_row(
    name_offset: u32,
    compressed_len: u32,
    block: u32,
    resource: bool,
    word_at_8: u32,
    word_at_12: u32,
) -> [u8; 16] {
    let mut row = [0_u8; 16];
    let name = u16::try_from(name_offset).unwrap_or(u16::MAX);
    row[0..2].copy_from_slice(&name.to_le_bytes());
    row[2..5].copy_from_slice(&compressed_len.to_le_bytes()[..3]);
    let offset_field = if resource {
        block | RESOURCE_FLAG
    } else {
        block
    };
    row[5..8].copy_from_slice(&offset_field.to_le_bytes()[..3]);
    row[8..12].copy_from_slice(&word_at_8.to_le_bytes());
    row[12..16].copy_from_slice(&word_at_12.to_le_bytes());
    row
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
        let kind = match entry.kind {
            EntryKind::Directory { .. } => continue,
            EntryKind::Resource { .. } => FileKind::Resource,
            EntryKind::Binary {
                compressed_len,
                encryption,
                ..
            } => FileKind::Binary {
                storage: if compressed_len == 0 {
                    Storage::Stored
                } else {
                    Storage::Deflate
                },
                encryption,
            },
        };
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

    build(out, &files, &directories, |wanted| {
        let index = *by_path.get(wanted).ok_or(Error::BadPath {
            path: wanted.to_owned(),
            reason: "not an entry of this archive",
        })?;
        match overrides.get(&index) {
            Some(bytes) => Ok(bytes.clone()),
            None => archive.extract(src, index),
        }
    })
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
) -> Result<Report>
where
    R: std::io::Read + Seek,
    W: Write + Seek,
{
    let mut edits = BTreeMap::new();
    edits.insert(path.to_owned(), contents);
    replace_many(src, archive, &edits, out)
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
/// # Errors
///
/// [`Error::NotFound`] for a path that does not resolve,
/// [`Error::NotAnArchive`] for a component that is not one, and as [`build`].
pub fn replace_many<R, W>(
    src: &mut R,
    archive: &Archive,
    edits: &BTreeMap<String, Vec<u8>>,
    out: &mut W,
) -> Result<Report>
where
    R: std::io::Read + Seek,
    W: Write + Seek,
{
    let mut direct: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut deeper: BTreeMap<u32, BTreeMap<String, Vec<u8>>> = BTreeMap::new();

    for (path, contents) in edits {
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let (index, rest) = split_at_file(archive, &segments)?;
        if rest.is_empty() {
            direct.insert(index, contents.clone());
        } else {
            deeper
                .entry(index)
                .or_default()
                .insert(rest.join("/"), contents.clone());
        }
    }

    for (index, inner) in deeper {
        let nested = archive.open_nested(src, index)?;
        let mut buffer = Cursor::new(Vec::new());
        replace_many(src, &nested, &inner, &mut buffer)?;
        direct.insert(index, buffer.into_inner());
    }

    rebuild(src, archive, out, &direct)
}
