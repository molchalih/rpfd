//! Writing an archive: layout first, payloads stream in one pass, then header and table fill in.

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
        /// The per-entry encryption field.
        encryption: u32,
    },
    /// An `RSC7` resource, written through untouched; `declared` supplies flags when it has none.
    Resource {
        /// The flag words to record when the payload does not carry its own.
        declared: Option<ResourceFlags>,
    },
}

/// A resource's two flag words, which are its length and its version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceFlags {
    /// System page flags — offset 8 of the entry row, and of the header.
    #[serde(with = "flag_word")]
    pub system: u32,
    /// Graphics page flags — offset 12 of the entry row, and of the header.
    #[serde(with = "flag_word")]
    pub graphics: u32,
}

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

#[derive(Default)]
struct Dir {
    /// Children by name, in the ascending name order the format stores them in.
    children: BTreeMap<String, Child>,
    /// Each folded name maps to the spelling that took it; a second collision is unreachable.
    folded: HashMap<String, String>,
}

#[derive(Clone, Copy)]
enum Child {
    Dir(usize),
    File(usize),
}

fn joined(at: &str, name: &str) -> String {
    if at.is_empty() {
        name.to_owned()
    } else {
        format!("{at}/{name}")
    }
}

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

fn claim(arena: &mut [Dir], parent: usize, path: &str, name: &str, child: Child) -> Result<()> {
    let dir = arena.get_mut(parent).ok_or(Error::BadPath {
        path: path.to_owned(),
        reason: "unreachable parent",
    })?;
    dir.children.insert(name.to_owned(), child);
    dir.folded.insert(folded(name), name.to_owned());
    Ok(())
}

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
        // Silently replacing the file would drop it from the tree.
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

fn align_up(version: Version, value: u64) -> Option<u64> {
    let block = version.block_len();
    let over = value.checked_rem(block)?;
    if over == 0 {
        return Some(value);
    }
    value.checked_add(block.checked_sub(over)?)
}

/// Refuses a path deeper than `MAX_DEPTH`, which is what `Archive::parse` will walk.
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

fn plan_tree(files: &[FileSpec], directories: &[String]) -> Result<Vec<Dir>> {
    let mut arena: Vec<Dir> = vec![Dir::default()];

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

/// Assigns entry indices breadth-first, each directory's children in one contiguous run.
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

/// Bytes one payload reads from, in full, from its start; seekable because `store` may reread it.
pub trait Payload: Read + Seek {}

impl<T: Read + Seek> Payload for T {}

/// Where `build` takes each payload from; a trait not a closure since the answer may borrow it.
pub trait Fetch {
    /// One payload, borrowing this source for as long as it is read.
    type Payload<'a>: Payload
    where
        Self: 'a;

    /// The payload for `path`.
    /// # Errors
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

/// One written payload, plus fields; `compressed_len` is wide so overflow errors, never truncates.
pub(crate) struct Written {
    /// What the compressed-size field describes: deflated length, or zero for a stored payload.
    pub(crate) compressed_len: u64,
    pub(crate) content: Content,
    /// The payload's length: what the entry addresses, and the next payload is measured from.
    pub(crate) len: u64,
    /// How far past the payload's start was written; past `len` is a zeroed abandoned stream.
    pub(crate) reached: u64,
}

/// Whether `kind` goes under the transform; a resource answers `false` regardless of the tag.
pub(crate) const fn is_sealed(version: Version, kind: FileKind) -> bool {
    match kind {
        FileKind::Binary { encryption, .. } => !version.entry_is_open(encryption),
        FileKind::Resource { .. } => false,
    }
}

/// Where a payload's bytes go: a block at a time from its own start, with a short tail as-is.
enum Sink<'a, W> {
    Clear(&'a mut W),
    Sealed(Sealing<'a, W>),
}

struct Sealing<'a, W> {
    out: &'a mut W,
    seal: &'a Seal,
    /// Where this payload begins in `out`, which is where its blocks are counted from.
    start: u64,
    block: [u8; CIPHER_BLOCK_LEN],
    filled: usize,
    /// Whether the payload has ended, after which bytes are slack and go through as they are.
    past: bool,
}

impl<'a, W: Write + Seek> Sink<'a, W> {
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

    /// Ends the payload, idempotently: a short tail goes out as-is, anything after is slack.
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
    /// Seeks the sink under it; a destination off this payload's block boundary is refused.
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

/// The name an entry carries: the last `/`-separated path segment; backslashes are name bytes.
pub(crate) fn entry_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The storage rule an entry carries, as the `FileKind` for a write; errors for a directory.
pub(crate) fn kind_of(path: &str, entry: &Entry) -> Result<FileKind> {
    match entry.kind {
        EntryKind::Directory { .. } => Err(Error::WrongKind {
            path: path.to_owned(),
            found: "directory",
            wanted: "file",
        }),
        // The row's own flag words travel with the kind: a Rockstar resource's
        // payload does not begin with `RSC7` and carries no readable header.
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

fn copy_all<S, W>(src: &mut S, out: &mut W, at: u64) -> Result<u64>
where
    S: Read,
    W: Write,
{
    std::io::copy(src, out).map_err(|source| Error::Io { offset: at, source })
}

fn uncompressed_len(path: &str, len: u64) -> Result<u32> {
    u32::try_from(len).map_err(|_| Error::FieldOverflow {
        path: path.to_owned(),
        what: "uncompressed size",
        len,
        limit: u64::from(u32::MAX),
    })
}

/// Applies a storage rule to a file streamed `src` to `out`; the seal keys on name and length.
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
    sink.ends()?;
    Ok(written)
}

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
    // Offsets 8 and 12 of an `RSC7` header are the flag words, both inside the
    // sixteen bytes read above, so the default is unreachable.
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

    if deflated < plain && version.holds_compressed_len(deflated) {
        return Ok(Written {
            compressed_len: deflated,
            content,
            len: deflated,
            reached: deflated,
        });
    }

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
    // The zeroing past `len` is slack, not payload; sealing it too would leave the payload's
    // last bytes in a block a reader that stops at `len` never decrypts.
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

struct Layout<'a> {
    version: Version,
    files: &'a [FileSpec],
    planned: &'a [Planned],
    name_offsets: &'a [u32],
    sealed: Option<Sealed<'a>>,
}

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

    // Payloads go out in table order at a cursor that only advances; a resource whose size
    // saturates the 24-bit field states its extent nowhere, so the reader recovers it as the
    // gap to the next payload, which holds only because of this ordering.
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

        let block = at.checked_div(version.block_len()).unwrap_or(u64::MAX);
        let row = file_row(version, &spec.path, name_offset, block, &written)?;

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

/// Writes an archive containing `files`, taking contents from `fetch` as each is written.
/// # Errors
/// `BadPath` for an unwritable path, `NotAResource`/`FieldOverflow`, `Io` from sink or fetch.
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

#[derive(Debug, Clone, Copy)]
pub(crate) struct Under<'a> {
    version: Version,
    tag: u32,
    sealer: Option<&'a Sealer>,
    /// Empty when unsealed; for a rebuild, the original's name, not the scratch file's.
    name: &'a str,
}

impl<'a> Under<'a> {
    pub(crate) const fn open(version: Version) -> Self {
        Self {
            version,
            tag: version.open(),
            sealer: None,
            name: "",
        }
    }

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

/// A forward transform and the tag a refusal names; `Sealed::of` is the only way to get a `Seal`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Sealed<'a> {
    sealer: &'a Sealer,
    tag: u32,
}

impl<'a> Sealed<'a> {
    pub(crate) const fn new(sealer: &'a Sealer, tag: u32) -> Self {
        Self { sealer, tag }
    }

    pub(crate) fn of(self, name: &str, len: u64) -> Result<Seal> {
        self.sealer
            .seal(name, len)
            .ok_or(Error::CannotWriteEncrypted {
                tag: self.tag,
                reason: NoWrite::NoInverse,
            })
    }
}

/// `build`, sealed under `under`: each region seals from its own start, the header stays clear.
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
    let floor = version.payload_floor(u64::from(entry_count), u64::from(names_len));
    let mut cursor = align_up(version, floor).ok_or(Error::FieldOverflow {
        path: String::new(),
        what: "archive length",
        len: floor,
        limit: u64::MAX,
    })?;

    let layout = Layout {
        version,
        files,
        planned: &planned,
        name_offsets: &name_offsets,
        sealed,
    };
    let (rows, payload_end) = write_payloads(out, &layout, &mut cursor, &mut fetch, watch)?;

    // Keyed by the archive's own name and finished length, so it is minted after the payloads.
    let regions = match sealed {
        None => None,
        Some(sealed) => Some(sealed.of(name, cursor)?),
    };
    let regions = regions.as_ref();

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
    // A row is one whole aligned block of the transform over the entry table,
    // so sealing each in turn seals the region.
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
    let mut names_blob = names_blob;
    if let Some(seal) = regions {
        seal.apply(&mut names_blob);
    }
    out.write_all(&names_blob).map_err(|source| Error::Io {
        offset: version.header_len().saturating_add(table_len),
        source,
    })?;

    let written_to = payload_end.max(floor);
    // Under one block by construction, so the conversion cannot lose anything.
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

/// The spec to rebuild an archive as it stands, paired with each file's entry index.
/// # Errors
/// `BadPath` for a name `check_tree` refuses, `NameCollision` for a case-folding clash.
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

/// Every directory in an archive, by path, root excluded, so an empty one survives a rebuild.
/// # Errors
/// `BadPath` for a name `check_tree` refuses, `NameCollision` for a case-folding clash.
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

/// Rebuilds `archive` into `out` with `changes`, at the version read; not a conversion.
/// # Errors
/// As `edit::tree_of` for an invalid change, as `build`, plus read errors from the source.
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
    let sealer = archive.seal()?;
    let under = match sealer {
        None => Under::open(archive.version()),
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

struct FromArchive<'a, R> {
    src: &'a mut R,
    archive: &'a Archive,
    changes: &'a Changes,
    /// Where each file of the rebuilt tree gets its bytes, by the path it will be written at.
    sources: BTreeMap<&'a str, &'a edit::Source>,
    /// Taken by value, moved out as its entry is written: an override may be a rebuilt ancestor.
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

/// Rebuilds `archive` into `out` with changes, cascading through nesting into `Scratch` space.
/// # Errors
/// `NotFound`, `NotAnArchive`, `Overlapping` for changes resolving to one entry, and as `rebuild`.
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
        let mut sink = scratch.create()?;
        rewrite(src, &holder, &group.changes, &mut sink, scratch, watch)
            .map_err(|failure| edit::respelled(failure, &group.spellings))?;
        overrides.insert(index, Box::new(sink));
    }

    rebuild(src, archive, &here, out, overrides, watch)
}

/// Whether this set can be committed as it stands, writing nothing: `rewrite`'s own resolution.
/// # Errors
/// As `rewrite`, less what only a build raises.
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

    use std::{
        cell::Cell,
        io::{Cursor, Seek, SeekFrom, Write},
        sync::Arc,
    };

    use super::{FileKind, FileSpec, Sink, Storage, Under, build_under};
    use crate::{
        archive::Archive,
        edit::{Change, Changes},
        entry::EntryKind,
        error::{Error, Result},
        format::{
            Version,
            crypto::{CIPHER_BLOCK_LEN, Scheme, Seal, Sealer, synthetic},
            resource::{MAGIC_RSC7, RESOURCE_HEADER_LEN},
            rpf7, widen,
        },
        keys::{Material, Unlock},
        scratch::InMemory,
        watch::Unwatched,
    };

    fn zeroed(named: &str) -> (Sealer, Unlock) {
        let material = Arc::new(Material::over_zeros());
        let scheme = Version::Rpf7.scheme(rpf7::ENCRYPTION_AES).expect("AES");
        let sealer = Sealer::new(scheme, &material).expect("AES seals");
        (sealer, Unlock::held(material, named))
    }

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

    fn specs() -> Vec<FileSpec> {
        contents()
            .iter()
            .map(|(path, _)| FileSpec {
                path: (*path).to_owned(),
                kind: FileKind::Binary {
                    storage: if path.contains(".txt") {
                        Storage::Deflate
                    } else {
                        Storage::Stored
                    },
                    encryption: 1,
                },
            })
            .collect()
    }

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
        let empty = Material::over_zeros();
        assert!(!Scheme::Ng.seals(Some(&empty)));
        assert!(!Scheme::Ng.seals(None));
        assert!(Sealer::new(Scheme::Ng, &empty).is_none());
        assert!(Seal::new(Scheme::Ng, &empty, "a.bin", 16).is_none());

        let held = synthetic::ng_material(0x51EA_1000);
        assert!(Scheme::Ng.seals(Some(&held)));
        assert!(Sealer::new(Scheme::Ng, &held).is_some());

        for tag in [rpf7::ENCRYPTION_AES, rpf7::ENCRYPTION_AES_LAUNCHER] {
            let scheme = Version::Rpf7.scheme(tag).expect("an AES tag");
            assert!(scheme.seals(None), "{tag:#010x} does not seal");
            assert!(scheme.seals(Some(&empty)), "{tag:#010x} does not seal");
        }
    }

    fn ng_zeroed(named: &str) -> (Sealer, Unlock) {
        let material = Arc::new(synthetic::ng_material(0x0DE1_2A55));
        let scheme = Version::Rpf7.scheme(rpf7::ENCRYPTION_NG).expect("NG");
        let sealer = Sealer::new(scheme, &material).expect("synthetic tables derive");
        (sealer, Unlock::held(material, named))
    }

    #[test]
    fn an_ng_archive_is_written_and_opens_again_with_every_entry_intact() {
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

    fn ng_inner(named: &str, holding: &str, contents: &[u8]) -> Vec<u8> {
        let (sealer, _) = ng_zeroed(named);
        let held = contents.to_vec();
        let mut out = Cursor::new(Vec::new());
        build_under(
            &mut out,
            Under::sealed(Version::Rpf7, rpf7::ENCRYPTION_NG, &sealer, named),
            &[FileSpec {
                path: holding.to_owned(),
                kind: FileKind::Binary {
                    storage: Storage::Stored,
                    encryption: 1,
                },
            }],
            &[],
            |_: &str| Ok(Cursor::new(held.clone())),
            &mut Unwatched,
        )
        .expect("the nested archive builds");
        out.into_inner()
    }

    fn ng_outer(named: &str, at: &str, inner: &[u8]) -> (Vec<u8>, Unlock) {
        let (sealer, unlock) = ng_zeroed(named);
        let mut out = Cursor::new(Vec::new());
        build_under(
            &mut out,
            Under::sealed(Version::Rpf7, rpf7::ENCRYPTION_NG, &sealer, named),
            &[FileSpec {
                path: at.to_owned(),
                kind: FileKind::Binary {
                    storage: Storage::Stored,
                    encryption: rpf7::ENTRY_OPEN,
                },
            }],
            &[],
            |_: &str| Ok(Cursor::new(inner.to_vec())),
            &mut Unwatched,
        )
        .expect("the holding archive builds");
        (out.into_inner(), unlock)
    }

    fn through_nested(bytes: Vec<u8>, unlock: &Unlock, at: &str, holding: &str) -> Result<Vec<u8>> {
        let mut src = Cursor::new(bytes);
        let archive = Archive::open(&mut src, unlock)?;
        let index = archive.find(at)?;
        let nested = archive.open_nested(&mut src, index)?;
        let inside = nested.find(holding)?;
        nested.read(&mut src, inside)
    }

    #[test]
    fn a_nested_ng_archive_is_not_renamed_out_from_under_its_own_key() {
        let inner = ng_inner("inner.rpf", "note.txt", b"held inside");
        let (bytes, unlock) = ng_outer("outer.rpf", "inner.rpf", &inner);
        assert_eq!(
            through_nested(bytes.clone(), &unlock, "inner.rpf", "note.txt")
                .expect("the nested archive opens as it stands"),
            b"held inside"
        );

        let mut src = Cursor::new(bytes.clone());
        let archive = Archive::open(&mut src, &unlock).expect("the holder opens");
        let changes = Changes::one("inner.rpf", Change::RenameTo("other.rpf".to_owned()));
        let mut out = Cursor::new(Vec::new());
        let refused = crate::rewrite(
            &mut src,
            &archive,
            &changes,
            &mut out,
            &mut InMemory,
            &mut Unwatched,
        )
        .expect_err("renaming a nested NG archive is refused");
        assert_eq!(refused.name(), "CannotRenameKeyed", "{refused:?}");
        assert!(
            matches!(
                refused,
                Error::CannotRenameKeyed { tag, scheme, .. }
                    if tag == rpf7::ENCRYPTION_NG && scheme == "NG"
            ),
            "{refused:?}"
        );
    }

    #[test]
    fn a_nested_ng_archive_moves_between_directories_and_still_opens() {
        let inner = ng_inner("inner.rpf", "note.txt", b"held inside");
        let (bytes, unlock) = ng_outer("outer.rpf", "inner.rpf", &inner);
        let mut src = Cursor::new(bytes);
        let archive = Archive::open(&mut src, &unlock).expect("the holder opens");
        let changes = Changes::one("inner.rpf", Change::RenameTo("deep/inner.rpf".to_owned()));
        let mut out = Cursor::new(Vec::new());
        crate::rewrite(
            &mut src,
            &archive,
            &changes,
            &mut out,
            &mut InMemory,
            &mut Unwatched,
        )
        .expect("a move that keeps the name is allowed");
        assert_eq!(
            through_nested(out.into_inner(), &unlock, "deep/inner.rpf", "note.txt")
                .expect("the nested archive still opens"),
            b"held inside"
        );
    }

    const UNKNOWN_TAG: u32 = 0x0BAD_5EA1;

    #[test]
    fn a_nested_archive_under_an_unrecognised_tag_is_not_renamed_either() {
        let mut inner = ng_inner("inner.rpf", "note.txt", b"held inside");
        inner[12..16].copy_from_slice(&UNKNOWN_TAG.to_le_bytes());
        let (bytes, unlock) = ng_outer("outer.rpf", "inner.rpf", &inner);

        let mut src = Cursor::new(bytes);
        let archive = Archive::open(&mut src, &unlock).expect("the holder opens");
        let changes = Changes::one("inner.rpf", Change::RenameTo("other.rpf".to_owned()));
        let mut out = Cursor::new(Vec::new());
        let refused = crate::rewrite(
            &mut src,
            &archive,
            &changes,
            &mut out,
            &mut InMemory,
            &mut Unwatched,
        )
        .expect_err("a nested archive under an unknown tag is not renamed");
        assert!(
            matches!(
                refused,
                Error::CannotRenameKeyed { tag, .. } if tag == UNKNOWN_TAG
            ),
            "{refused:?}"
        );
    }

    #[test]
    fn a_nested_unencrypted_archive_is_renamed_freely() {
        let mut out = Cursor::new(Vec::new());
        crate::build(
            &mut out,
            Version::Rpf7,
            &[FileSpec {
                path: "note.txt".to_owned(),
                kind: FileKind::Binary {
                    storage: Storage::Stored,
                    encryption: rpf7::ENTRY_OPEN,
                },
            }],
            &[],
            |_: &str| Ok(Cursor::new(b"held inside".to_vec())),
            &mut Unwatched,
        )
        .expect("the plain nested archive builds");
        let inner = out.into_inner();

        let mut out = Cursor::new(Vec::new());
        crate::build(
            &mut out,
            Version::Rpf7,
            &[FileSpec {
                path: "inner.rpf".to_owned(),
                kind: FileKind::Binary {
                    storage: Storage::Stored,
                    encryption: rpf7::ENTRY_OPEN,
                },
            }],
            &[],
            |_: &str| Ok(Cursor::new(inner.clone())),
            &mut Unwatched,
        )
        .expect("the holding archive builds");

        let mut src = Cursor::new(out.into_inner());
        let unlock = Unlock::unkeyed();
        let archive = Archive::open(&mut src, &unlock).expect("the holder opens");
        let changes = Changes::one("inner.rpf", Change::RenameTo("other.rpf".to_owned()));
        let mut out = Cursor::new(Vec::new());
        crate::rewrite(
            &mut src,
            &archive,
            &changes,
            &mut out,
            &mut InMemory,
            &mut Unwatched,
        )
        .expect("an unencrypted nested archive is renamed");

        assert_eq!(
            through_nested(out.into_inner(), &unlock, "other.rpf", "note.txt")
                .expect("the nested archive still opens"),
            b"held inside"
        );
    }

    #[test]
    fn a_nested_ng_archive_is_not_respelled_out_from_under_its_own_key_either() {
        let inner = ng_inner("inner.rpf", "note.txt", b"held inside");
        let (bytes, unlock) = ng_outer("outer.rpf", "inner.rpf", &inner);
        let mut src = Cursor::new(bytes);
        let archive = Archive::open(&mut src, &unlock).expect("the holder opens");
        let changes = Changes::one("inner.rpf", Change::RenameTo("INNER.RPF".to_owned()));
        let mut out = Cursor::new(Vec::new());
        let refused = crate::rewrite(
            &mut src,
            &archive,
            &changes,
            &mut out,
            &mut InMemory,
            &mut Unwatched,
        )
        .expect_err("a respelling of a keyed nested archive is not let through");
        assert_eq!(refused.name(), "CannotRenameKeyed", "{refused:?}");
    }

    #[test]
    fn an_ng_entry_written_at_a_new_size_picks_the_new_key_and_reads_back() {
        // The NG key index is `(hash(name) + length + 61) % 101`, so a rewrite
        // at a different length picks a different key; the sizes below are
        // asserted to move the index rather than assumed to.
        let (sealer, unlock) = ng_zeroed("resized.rpf");
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
        // What lets an in-place patch reseal a single row: a coincidence of
        // three numbers rather than a rule the format states.
        assert!(Version::Rpf7.row_is_a_cipher_block());
        assert_eq!(
            Version::Rpf7.row_len(),
            crate::format::crypto::CIPHER_BLOCK_LEN as u64
        );
    }

    #[test]
    fn a_resource_payload_is_never_written_through_the_transform() {
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
