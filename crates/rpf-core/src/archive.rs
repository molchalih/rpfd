//! The parsed table of contents of one archive, and reads against it.
//!
//! [`Archive`] holds only the table of contents — entries, names, and the shape
//! of the tree. It does **not** hold the source. Reads take `&mut R` where
//! `R: Read + Seek`, which is what §7 requires and what makes a nested archive
//! ordinary: it is another [`Archive`] parsed at a different base over the same
//! source.
//!
//! Nothing here loads an archive. A 2.7 GB file costs its table of contents to
//! open, and one entry to read. R3.9.

use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom},
};

use crate::{
    entry::{Entry, EntryKind},
    error::{Error, Result},
    format::{
        Header, MAX_HEADER_LEN, Names, Version, folded,
        resource::{MAGIC_RSC7, RESOURCE_HEADER_LEN, resource_len},
        same_name,
    },
};

/// How deep anything in this container is walked before it is refused.
///
/// **Policy, not a measured fact.** The format sets no limit and nothing about
/// a deep archive is self-contradictory; this is the depth we choose to follow
/// to, and DR-011 holds the reasoning and the measurements behind the number.
/// It is deliberately absent from `docs/rpf-format.md`, which holds facts an
/// archive told us.
///
/// It bounds two structures, because it is one fact about one thing: every
/// recursive walk over an archive — `child_named` down a path, `ls -R`,
/// `verify`, the daemon's recursive list — descends a directory tree, an
/// archive nested inside an archive, or both, and both depths are chosen by
/// the bytes rather than by us. The bound belongs here and not at each walker
/// (§5): a walker that carried its own counter would be one walker away from a
/// walker that forgot, and the symptom of forgetting is a stack overflow rather
/// than a wrong answer.
pub const MAX_DEPTH: u32 = 32;

/// Seeks and fills `buf`, reporting where it was when it failed.
fn read_exact_at<R: Read + Seek>(src: &mut R, offset: u64, buf: &mut [u8]) -> Result<()> {
    src.seek(SeekFrom::Start(offset))
        .map_err(|source| Error::Io { offset, source })?;
    src.read_exact(buf)
        .map_err(|source| Error::Io { offset, source })
}

/// Reads `len` bytes at `offset` into a fresh buffer.
///
/// The caller must have bounds-checked `len` against the archive first; this is
/// where an unchecked length would become an allocation.
fn read_vec_at<R: Read + Seek>(src: &mut R, offset: u64, len: u64) -> Result<Vec<u8>> {
    let len = usize::try_from(len).map_err(|_| Error::OutOfBounds {
        region: "payload",
        offset,
        len,
        archive_len: u64::MAX,
    })?;
    let mut buf = vec![0u8; len];
    read_exact_at(src, offset, &mut buf)?;
    Ok(buf)
}

/// One entry's contents, and how much of the payload they came out of.
///
/// The two lengths are the **payload's**, not the contents': `declared` is how
/// many bytes on disk the entry table gives the stream, and `used` is how many
/// of them the stream turned out to occupy. They can differ without anything
/// failing to inflate, because a deflate stream carries its own end and
/// whatever follows it is never looked at — which is the whole of R6.10 and
/// what [`Payload::checked`] is for.
pub(crate) struct Payload {
    entry: u32,
    contents: Vec<u8>,
    declared: u64,
    used: u64,
}

impl Payload {
    /// A payload written as it is, which has no stream to end early.
    fn stored(entry: u32, contents: Vec<u8>) -> Self {
        let len = u64::try_from(contents.len()).unwrap_or(u64::MAX);
        Self {
            entry,
            contents,
            declared: len,
            used: len,
        }
    }

    /// How many bytes the entry holds, for a caller counting progress rather
    /// than reading. The contents themselves come out of [`Payload::checked`]
    /// and nowhere else (§4).
    pub(crate) fn len(&self) -> u64 {
        u64::try_from(self.contents.len()).unwrap_or(u64::MAX)
    }

    /// The contents, unless the payload declares bytes the stream never
    /// reached.
    ///
    /// The one place that fact is decided. `docs/rpf-format.md`, Resource page
    /// flags, `verified`: every resource in the sample ends its stream exactly
    /// at its payload, 0 bytes over, 20 of 20.
    ///
    /// # Errors
    ///
    /// [`Error::TrailingBytes`], with both lengths.
    pub(crate) fn checked(self) -> Result<Vec<u8>> {
        if self.used < self.declared {
            return Err(Error::TrailingBytes {
                entry: self.entry,
                declared: self.declared,
                used: self.used,
            });
        }
        Ok(self.contents)
    }
}

/// Raw deflate, with the output length the archive promised.
///
/// Bounded by `expected` on purpose: a declared length is attacker-controlled,
/// so it caps the read rather than sizing an allocation up front.
fn inflate(entry: u32, raw: &[u8], expected: u64) -> Result<Payload> {
    let limit = expected.checked_add(1).ok_or(Error::LengthMismatch {
        entry,
        expected,
        actual: u64::MAX,
    })?;

    let mut out = Vec::new();
    let mut stream = flate2::read::DeflateDecoder::new(raw);
    (&mut stream)
        .take(limit)
        .read_to_end(&mut out)
        .map_err(|source| Error::Inflate { entry, source })?;

    let actual = u64::try_from(out.len()).unwrap_or(u64::MAX);
    if actual != expected {
        return Err(Error::LengthMismatch {
            entry,
            expected,
            actual,
        });
    }
    Ok(Payload {
        entry,
        contents: out,
        declared: u64::try_from(raw.len()).unwrap_or(u64::MAX),
        // What the decompressor took, rather than what it was handed: that is
        // where the stream ends, and the bytes after it belong to nothing.
        used: stream.total_in(),
    })
}

/// The table of contents of one archive.
#[derive(Debug, Clone)]
pub struct Archive {
    base: u64,
    len: u64,
    version: Version,
    encryption: u32,
    /// How many archives this one sits inside. Zero for a file opened on its
    /// own, and one more than its holder's for every nested archive, which is
    /// what [`MAX_DEPTH`] is counted against.
    depth: u32,
    entries: Vec<Entry>,
    names: Names,
    parents: Vec<Option<u32>>,
}

impl Archive {
    /// Parses the archive that begins at `base` and runs for `len` bytes.
    ///
    /// `len` is the archive's own extent, which for a nested archive is the
    /// size of the entry that holds it, not the size of the file. Every offset
    /// inside is checked against it.
    ///
    /// # Errors
    ///
    /// [`Error::NotAnArchive`] if the magic is nothing this format uses,
    /// [`Error::UnsupportedVersion`] if it names a version this build does not
    /// read, [`Error::NeedsKey`] if it is encrypted, and the bounds variants if
    /// the header describes regions that do not fit.
    pub fn parse<R: Read + Seek>(src: &mut R, base: u64, len: u64) -> Result<Self> {
        // An archive parsed by name rather than through a holder is the
        // outermost one there is, so it is nested inside nothing.
        Self::parse_nested(src, base, len, 0)
    }

    /// [`Archive::parse`], told how many archives it already sits inside.
    ///
    /// The depth is the caller's to supply because it is not in the bytes: an
    /// archive cannot tell where it is being read from. [`Archive::open_nested`]
    /// is the only caller that supplies anything but zero, which is what keeps
    /// the count honest.
    fn parse_nested<R: Read + Seek>(src: &mut R, base: u64, len: u64, depth: u32) -> Result<Self> {
        if depth > MAX_DEPTH {
            return Err(Error::TooDeep {
                what: "archive nesting",
                depth,
                limit: MAX_DEPTH,
            });
        }

        let Header {
            version,
            entry_count,
            names_len,
            encryption,
        } = read_header(src, base)?;
        let table_at = version.header_len();

        let table_len = u64::from(entry_count)
            .checked_mul(version.row_len())
            .ok_or(Error::OutOfBounds {
                region: "entry table",
                offset: table_at,
                len: u64::MAX,
                archive_len: len,
            })?;
        let names_at = table_at.checked_add(table_len).ok_or(Error::OutOfBounds {
            region: "entry table",
            offset: table_at,
            len: table_len,
            archive_len: len,
        })?;
        // Checked before the names blob, so that a header claiming more
        // entries than the file can hold names the entry table rather than the
        // blob that never got a chance to start (§10).
        if names_at > len {
            return Err(Error::OutOfBounds {
                region: "entry table",
                offset: table_at,
                len: table_len,
                archive_len: len,
            });
        }
        let names_end = names_at
            .checked_add(u64::from(names_len))
            .ok_or(Error::OutOfBounds {
                region: "names blob",
                offset: names_at,
                len: u64::from(names_len),
                archive_len: len,
            })?;
        if names_end > len {
            return Err(Error::OutOfBounds {
                region: "names blob",
                offset: names_at,
                len: u64::from(names_len),
                archive_len: len,
            });
        }

        let table = read_vec_at(src, base.checked_add(table_at).unwrap_or(base), table_len)?;
        let entries = parse_entries(version, &table, entry_count)?;

        let names_blob = read_vec_at(
            src,
            base.checked_add(names_at).unwrap_or(base),
            u64::from(names_len),
        )?;

        // Names are located once, here, so that `name` has nothing left to
        // find (§5). How they are encoded is the version's, which is why the
        // seam is asked rather than the blob read here.
        let names = Names::parse(version, names_blob, &entries)?;

        let parents = parse_parents(&entries)?;

        Ok(Self {
            base,
            len,
            version,
            encryption,
            depth,
            entries,
            names,
            parents,
        })
    }

    /// Parses the archive occupying the whole of `src`.
    ///
    /// # Errors
    ///
    /// As [`Archive::parse`], plus [`Error::Io`] if the length cannot be found.
    pub fn open<R: Read + Seek>(src: &mut R) -> Result<Self> {
        let len = src
            .seek(SeekFrom::End(0))
            .map_err(|source| Error::Io { offset: 0, source })?;
        Self::parse(src, 0, len)
    }

    /// Where this archive begins in the source.
    #[must_use]
    pub const fn base(&self) -> u64 {
        self.base
    }

    /// How long this archive is.
    #[must_use]
    pub const fn len_bytes(&self) -> u64 {
        self.len
    }

    /// The container version this archive is.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    /// The archive's encryption tag. Always [`Version::open`] for now, since
    /// anything else is refused at parse.
    #[must_use]
    pub const fn encryption(&self) -> u32 {
        self.encryption
    }

    /// Every entry, in table order. Entry 0 is the root directory.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The names blob exactly as it appears on disk.
    #[must_use]
    pub fn names_blob(&self) -> &[u8] {
        self.names.blob()
    }

    /// One entry by index.
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchEntry`] if the index is past the end.
    pub fn entry(&self, index: u32) -> Result<&Entry> {
        let at = usize::try_from(index)
            .ok()
            .and_then(|i| self.entries.get(i));
        at.ok_or(Error::NoSuchEntry {
            index,
            entry_count: count_of(&self.entries),
        })
    }

    /// One entry's own name, without its parents.
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchEntry`] if the index is past the end, and
    /// [`Error::BadName`] if the bytes at the entry's name offset are not
    /// UTF-8. Every name in the sample is ASCII; refusing the rest is §6's
    /// answer for third-party bytes, and it is a name the caller can be shown
    /// rather than a repair it cannot check.
    pub fn name(&self, index: u32) -> Result<&str> {
        self.names.at(index)
    }

    /// The full path of an entry, addressed from the archive root.
    ///
    /// The root itself is the empty string; everything else is
    /// slash-separated with no leading slash.
    ///
    /// The walk up the parent map is unguarded because it does not need a
    /// guard: `parse_parents` refuses any archive in which a child's index is
    /// not greater than its parent's, so every step of this loop moves to a
    /// smaller index and it ends (§5).
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchEntry`] if the index, or any ancestor, is past the end.
    pub fn path(&self, index: u32) -> Result<String> {
        let mut parts = Vec::new();
        let mut at = index;
        loop {
            let parent = usize::try_from(at)
                .ok()
                .and_then(|i| self.parents.get(i))
                .copied()
                .ok_or(Error::NoSuchEntry {
                    index: at,
                    entry_count: count_of(&self.entries),
                })?;
            let Some(parent) = parent else { break };
            parts.push(self.name(at)?);
            at = parent;
        }
        parts.reverse();
        Ok(parts.join("/"))
    }

    /// Refuses an archive in which two children of one directory are one name
    /// here.
    ///
    /// [`same_name`] folds case, so `A.txt` and `a.txt` under one parent are
    /// one name and the second is unreachable by any spelling of its own path.
    /// `build` has always refused to write such an archive; this is the reading
    /// of the same rule, so an archive that cannot be packed cannot be
    /// extracted either. R10.4.
    ///
    /// **Not done at parse**, deliberately, and this is the reason rather than
    /// an omission: an archive like this is legal in the format, no corpus here
    /// is wide enough to say the game never ships one, and refusing it at
    /// `Archive::parse` would leave `ls` unable to show what is wrong with it.
    /// What is refused is turning it into a tree — which is `specs_of` and
    /// `directories_of`, and therefore `extract`, `pack` and every rebuild.
    ///
    /// # Errors
    ///
    /// As `Archive::one_name_twice`, and as [`Archive::path`] for an entry
    /// whose ancestry does not resolve.
    pub fn check_names(&self) -> Result<()> {
        let mut seen: HashMap<(u32, String), u32> = HashMap::new();
        for index in 0..count_of(&self.entries) {
            let parent = usize::try_from(index)
                .ok()
                .and_then(|i| self.parents.get(i))
                .copied()
                .ok_or(Error::NoSuchEntry {
                    index,
                    entry_count: count_of(&self.entries),
                })?;
            // The root is nobody's child, so it has no sibling to collide with.
            let Some(parent) = parent else { continue };
            if let Some(first) = seen.insert((parent, folded(self.name(index)?)), index) {
                return Err(self.one_name_twice(first, index)?);
            }
        }
        Ok(())
    }

    /// The refusal for two children of one directory that are one name here.
    ///
    /// **Three conditions, and the reader answers each of them as the writer
    /// does.** `build` refuses a tree for two spellings of one folded name
    /// ([`Error::NameCollision`]), for one path given twice, and for a file and
    /// a directory of one name; reading an archive can meet all three, and
    /// answering them all as a case collision told a caller `"aa.txt" and
    /// "aa.txt" are one name here`, which names one string twice and says
    /// nothing. All three are `Category::Refused` and exit 6 either way, so the
    /// symmetry is in what is reported rather than in what a machine branches
    /// on.
    ///
    /// # Errors
    ///
    /// [`Error::NameCollision`] for two spellings of one name, [`Error::BadPath`]
    /// for one name carried by two entries, and as [`Archive::path`] for an
    /// entry whose ancestry does not resolve. It returns the refusal rather
    /// than raising it, so the two callers spell the refusal one way.
    fn one_name_twice(&self, first: u32, second: u32) -> Result<Error> {
        let path = self.path(second)?;
        if self.name(first)? != self.name(second)? {
            return Ok(Error::NameCollision {
                path,
                other: self.path(first)?,
            });
        }
        let reason = if self.entry(first)?.is_directory() == self.entry(second)?.is_directory() {
            "is named twice in one directory"
        } else {
            "a file and a directory share one name"
        };
        Ok(Error::BadPath { path, reason })
    }

    /// How an entry is named in a failure: its path from this archive's root,
    /// or `entry N` when the tree does not resolve far enough to give it one.
    ///
    /// The fallback is not a guess — it names the entry exactly, by the only
    /// thing that is still true of it — and it is reached only from an archive
    /// whose parent map is already broken, which is a failure of its own.
    fn named(&self, index: u32) -> String {
        self.path(index)
            .unwrap_or_else(|_| format!("entry {index}"))
    }

    /// The indices of a directory's children.
    ///
    /// # Errors
    ///
    /// [`Error::WrongKind`] if the entry is not a directory.
    pub fn children(&self, index: u32) -> Result<std::ops::Range<u32>> {
        let entry = self.entry(index)?;
        match entry.kind {
            EntryKind::Directory {
                first_child,
                child_count,
            } => {
                let end = first_child
                    .checked_add(child_count)
                    .ok_or(Error::BadChildRange {
                        entry: index,
                        first: first_child,
                        count: child_count,
                        entry_count: count_of(&self.entries),
                    })?;
                Ok(first_child..end)
            }
            other => Err(Error::WrongKind {
                path: self.named(index),
                found: other.noun(),
                wanted: "directory",
            }),
        }
    }

    /// Where an entry's payload begins in the source, bounds-checked against
    /// this archive's own extent.
    fn payload_span(&self, index: u32) -> Result<(u64, u64)> {
        let entry = self.entry(index)?;
        let (block, on_disk) = match entry.kind {
            EntryKind::Directory { .. } => {
                return Err(Error::WrongKind {
                    path: self.named(index),
                    found: "directory",
                    wanted: "file",
                });
            }
            EntryKind::Binary {
                block,
                compressed_len,
                uncompressed_len,
                ..
            } => {
                // Compressed size zero means stored, and then the other field
                // carries the real length. docs/rpf-format.md, Compression.
                let len = if compressed_len == 0 {
                    uncompressed_len
                } else {
                    compressed_len
                };
                (block, u64::from(len))
            }
            // No stored sentinel here, and the asymmetry with the arm above is
            // the format's rather than an oversight: a binary entry that
            // declares zero has its real length at offset 8, and a resource
            // does not — both of its trailing words are page flags.
            // `docs/rpf-format.md` records no measurement of a stored
            // resource, so nothing here invents a rule for recovering one; a
            // resource declaring zero is refused by `read` and `extract` for
            // being smaller than its own `RSC7` header.
            EntryKind::Resource {
                block,
                compressed_len,
                ..
            } => (block, u64::from(compressed_len)),
        };

        let relative = u64::from(block)
            .checked_mul(self.version.block_len())
            .ok_or(Error::OutOfBounds {
                region: "payload",
                offset: 0,
                len: on_disk,
                archive_len: self.len,
            })?;
        // A payload lies after the names blob — `docs/rpf-format.md`, Layout.
        // The upper bound alone leaves the archive's own header, entry table
        // and names blob addressable as file contents: an entry at block 0
        // reads back the table of contents, which is a plausible-but-wrong
        // value rather than a failure, and `allocation` then offers those same
        // bytes to a patch as room to write into.
        let floor = self.version.payload_floor(
            u64::try_from(self.entries.len()).unwrap_or(u64::MAX),
            u64::try_from(self.names.blob().len()).unwrap_or(u64::MAX),
        );
        if relative < floor {
            return Err(Error::PayloadUnderflow {
                entry: index,
                offset: relative,
                floor,
            });
        }

        let end = relative.checked_add(on_disk).ok_or(Error::OutOfBounds {
            region: "payload",
            offset: relative,
            len: on_disk,
            archive_len: self.len,
        })?;
        if end > self.len {
            return Err(Error::OutOfBounds {
                region: "payload",
                offset: relative,
                len: on_disk,
                archive_len: self.len,
            });
        }

        let absolute = self.base.checked_add(relative).ok_or(Error::OutOfBounds {
            region: "payload",
            offset: relative,
            len: on_disk,
            archive_len: self.len,
        })?;
        Ok((absolute, on_disk))
    }

    /// The payload extent of every file entry, relative to this archive's base.
    ///
    /// # Errors
    ///
    /// As [`Archive::entry`], and the bounds variants for a payload that does
    /// not fit.
    pub fn payload_extents(&self) -> Result<Vec<(u32, u64, u64)>> {
        let count = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        let mut out = Vec::new();
        for index in 0..count {
            if self.entry(index)?.is_directory() {
                continue;
            }
            let (absolute, len) = self.payload_span(index)?;
            out.push((index, absolute.saturating_sub(self.base), len));
        }
        Ok(out)
    }

    /// How many bytes an entry's payload may occupy without moving.
    ///
    /// This is room a caller may **write into**, so it stops at the first byte
    /// any other payload claims from this one's start onwards — not at the
    /// next payload to begin strictly later. Two entries sharing a block, and
    /// an entry whose payload runs through this one's start, are both invisible
    /// to the second reading, and both mean these bytes are already spoken
    /// for: the answer is then zero, not the distance to whatever comes next.
    ///
    /// [`crate::patch::plan`] rests on that. It treats an allocation as the
    /// bytes an edit claims and refuses two edits that overlap, which only
    /// tells it what it needs if an allocation really does end where the next
    /// payload begins.
    ///
    /// Real archives leave a great deal of room here — 82.7% of the sample is
    /// unreferenced — which is what makes patching in place worth doing at all.
    ///
    /// # Errors
    ///
    /// As [`Archive::payload_extents`], and [`Error::NoSuchEntry`] or
    /// [`Error::WrongKind`] for an index that is not a file in this archive.
    pub fn allocation(&self, index: u32) -> Result<u64> {
        // Resolved before the extents are searched: an index that is not an
        // entry at all must say so, rather than being reported as the wrong
        // kind of entry because the search for it came up empty (§10).
        let (absolute, _) = self.payload_span(index)?;
        let start = absolute.saturating_sub(self.base);

        let end = self
            .payload_extents()?
            .iter()
            .filter(|(at, _, _)| *at != index)
            .filter_map(|(_, other, len)| {
                let other_end = other.saturating_add(*len);
                (other_end > start).then_some((*other).max(start))
            })
            .min()
            .unwrap_or(self.len);
        Ok(end.saturating_sub(start))
    }

    /// Where an entry's payload begins, absolutely, and how long it is now.
    ///
    /// # Errors
    ///
    /// As [`Archive::payload_extents`].
    pub fn payload_at(&self, index: u32) -> Result<(u64, u64)> {
        self.payload_span(index)
    }

    /// Where this entry's row begins in the source.
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchEntry`] if the index is past the end.
    pub fn row_at(&self, index: u32) -> Result<u64> {
        let _ = self.entry(index)?;
        let offset = self
            .version
            .row_at(index)
            .and_then(|at| self.base.checked_add(at))
            .ok_or(Error::OutOfBounds {
                region: "entry table",
                offset: self.version.header_len(),
                len: self.version.row_len(),
                archive_len: self.len,
            })?;
        Ok(offset)
    }

    /// Reads an entry's **contents**: what the file means, with no container
    /// framing left on it.
    ///
    /// A binary entry inflates to its declared length. A resource entry has its
    /// 16-byte `RSC7` header removed and the remainder inflated. Compare
    /// [`Archive::extract`], which keeps the header.
    ///
    /// A payload whose deflate stream ends before the payload does still reads
    /// back, because it reads back correctly: the contents are what the archive
    /// promises, and only the bytes after the stream are unaccounted for.
    /// [`crate::Verified`] reports those as [`Error::TrailingBytes`]; refusing
    /// them here would reject an archive on one producer's evidence. R6.10.
    ///
    /// # Errors
    ///
    /// [`Error::WrongKind`] for a directory, the bounds variants for a payload
    /// that does not fit, and [`Error::Inflate`] or [`Error::LengthMismatch`]
    /// when the payload does not decompress as promised.
    pub fn read<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Vec<u8>> {
        Ok(self.read_payload(src, index)?.contents)
    }

    /// [`Archive::read`], keeping what the read learned about the payload it
    /// came out of.
    ///
    /// # Errors
    ///
    /// As [`Archive::read`].
    pub(crate) fn read_payload<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Payload> {
        let (offset, on_disk) = self.payload_span(index)?;
        let entry = self.entry(index)?;

        match entry.kind {
            EntryKind::Directory { .. } => Err(Error::WrongKind {
                path: self.named(index),
                found: "directory",
                wanted: "file",
            }),

            EntryKind::Binary {
                compressed_len,
                uncompressed_len,
                ..
            } => {
                let raw = read_vec_at(src, offset, on_disk)?;
                if compressed_len == 0 {
                    return Ok(Payload::stored(index, raw));
                }
                inflate(index, &raw, u64::from(uncompressed_len))
            }

            EntryKind::Resource {
                compressed_len,
                system_flags,
                graphics_flags,
                ..
            } => {
                let stream_len = u64::from(compressed_len)
                    .checked_sub(RESOURCE_HEADER_LEN)
                    .ok_or(Error::ResourceTooSmall {
                        entry: index,
                        compressed_len,
                    })?;
                let at =
                    offset
                        .checked_add(RESOURCE_HEADER_LEN)
                        .ok_or(Error::ResourceTooSmall {
                            entry: index,
                            compressed_len,
                        })?;
                let raw = read_vec_at(src, at, stream_len)?;
                inflate(index, &raw, resource_len(system_flags, graphics_flags))
            }
        }
    }

    /// Reads an entry as the **file it is outside the archive**.
    ///
    /// The difference from [`Archive::read`] is resources: this keeps the
    /// 16-byte `RSC7` header and leaves the body deflated, because that is what
    /// a `.yft` on disk is. Passthrough is a commitment — an entry we cannot
    /// interpret still round-trips byte for byte. `docs/approach.md`.
    ///
    /// # Errors
    ///
    /// As [`Archive::read`].
    pub fn extract<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Vec<u8>> {
        let entry = self.entry(index)?;
        if let EntryKind::Resource { compressed_len, .. } = entry.kind {
            let (offset, _) = self.payload_span(index)?;
            if u64::from(compressed_len) < RESOURCE_HEADER_LEN {
                return Err(Error::ResourceTooSmall {
                    entry: index,
                    compressed_len,
                });
            }
            return read_vec_at(src, offset, u64::from(compressed_len));
        }
        self.read(src, index)
    }

    /// Whether an entry's payload begins with the `RSC7` magic.
    ///
    /// The resource bit and the payload's magic are supposed to agree; whether
    /// they always do is Q7. This reads the payload rather than trusting the
    /// bit, so the two can be compared.
    ///
    /// # Errors
    ///
    /// As [`Archive::read`] for the bounds cases.
    pub fn payload_is_resource<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<bool> {
        let (offset, on_disk) = self.payload_span(index)?;
        if on_disk < 4 {
            return Ok(false);
        }
        let mut magic = [0u8; 4];
        read_exact_at(src, offset, &mut magic)?;
        Ok(magic == MAGIC_RSC7)
    }

    /// Finds an entry by path **within this archive**, not descending into any
    /// archive nested in it.
    ///
    /// Matching is [`same_name`], which is how the runtime addresses these
    /// paths. Every name in the sample is lower-case, so this repository cannot
    /// yet tell case-folded order from byte order — `docs/backlog.md` Q1.
    ///
    /// The empty path is the root directory.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] naming the component that failed, including when a
    /// component in the middle of the path turns out not to be a directory.
    pub fn find(&self, path: &str) -> Result<u32> {
        let mut current = 0_u32;
        for segment in path.split('/').filter(|s| !s.is_empty()) {
            current = self
                .child_named(current, segment)?
                .ok_or_else(|| Error::NotFound {
                    path: path.to_owned(),
                    segment: segment.to_owned(),
                })?;
        }
        Ok(current)
    }

    /// The child of `parent` with this name, or `None` if `parent` is not a
    /// directory or has no such child.
    ///
    /// Ambiguity is refused rather than resolved. [`same_name`] folds case, so
    /// two children of one directory can both answer to one spelling, and
    /// taking the first of them addresses one entry by another's name: measured,
    /// `rpf put … ax.txt` against an archive holding `AX.txt` beside `ax.txt`
    /// reported `patched 8 bytes in place`, exit 0, and `AX.txt` is what
    /// changed. This is the only resolution the patch-in-place path goes
    /// through, so it is where the refusal has to be — [`Archive::check_names`]
    /// is reached only by whoever turns the archive into a tree.
    ///
    /// # Errors
    ///
    /// As [`Archive::one_name_twice`] when more than one child answers to
    /// `name`.
    pub(crate) fn child_named(&self, parent: u32, name: &str) -> Result<Option<u32>> {
        let Ok(children) = self.children(parent) else {
            return Ok(None);
        };
        let mut found: Option<u32> = None;
        for index in children {
            if !self.name(index).is_ok_and(|held| same_name(held, name)) {
                continue;
            }
            if let Some(first) = found {
                return Err(self.one_name_twice(first, index)?);
            }
            found = Some(index);
        }
        Ok(found)
    }

    /// Finds an entry by a path that may address **through** nested archives,
    /// in one string.
    ///
    /// `x64/vehicles.rpf/meringls63amg24.yft` resolves in a single call. The
    /// descent is driven by position, not by extension: when a component
    /// resolves to a file and components remain, that file is opened as an
    /// archive. A file that is not one fails with [`Error::NotAnArchive`],
    /// which says more than "not found" would.
    ///
    /// Returns the archive that holds the entry — which is `self` when the path
    /// never left it — and the index within it.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] for a component that does not resolve, and as
    /// [`Archive::parse`] for a nested archive that does not open.
    pub fn locate<R: Read + Seek>(&self, src: &mut R, path: &str) -> Result<(Self, u32)> {
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut archive = self.clone();
        let mut current = 0_u32;

        for (position, segment) in segments.iter().enumerate() {
            let index = archive
                .child_named(current, segment)?
                .ok_or_else(|| Error::NotFound {
                    path: path.to_owned(),
                    segment: (*segment).to_owned(),
                })?;

            let is_last = position.saturating_add(1) == segments.len();
            let entry = archive.entry(index)?;

            if is_last || entry.is_directory() {
                current = index;
                continue;
            }

            // A file with components still to come is an archive to descend.
            archive = archive.open_nested(src, index)?;
            current = 0;
        }

        Ok((archive, current))
    }

    /// Parses an archive nested inside this one.
    ///
    /// Nesting is not a special case: the payload is another archive, and its
    /// offsets are relative to its own base. `docs/rpf-format.md`.
    ///
    /// This is the only way an archive's nesting depth grows, and it is
    /// bounded: a payload whose own payload is another archive, repeated, is
    /// recursion an archive chooses for its readers. [`MAX_DEPTH`].
    ///
    /// # Errors
    ///
    /// As [`Archive::parse`], plus [`Error::WrongKind`] for a directory and
    /// [`Error::TooDeep`] past [`MAX_DEPTH`] levels of nesting.
    pub fn open_nested<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Self> {
        let (offset, on_disk) = self.payload_span(index)?;
        let depth = self.depth.checked_add(1).ok_or(Error::TooDeep {
            what: "archive nesting",
            depth: u32::MAX,
            limit: MAX_DEPTH,
        })?;
        Self::parse_nested(src, offset, on_disk, depth)
    }

    /// The archive nested in an entry's payload, or `None` when the payload is
    /// not one.
    ///
    /// Every walk over an archive sniffs each payload for a nested one, so
    /// "this is not an archive" is the ordinary answer and cannot be a failure
    /// — a listing that stopped at the first `.txt` would be useless. A refusal
    /// on depth is not ordinary: it says the walk stopped short of what the
    /// archive describes, and swallowing it would report a truncated listing as
    /// a complete one, which is the plausible-but-wrong value §6 rules out
    /// alongside the panic it replaced.
    ///
    /// **An archive of a version this build does not read is `None` here**, and
    /// that is the limit of DR-010's amendment rather than a case it covers.
    /// `Error::UnsupportedVersion` carries the offset so that a nested archive
    /// of another version names where it is, which it does through
    /// [`Archive::locate`]; the sniff cannot fail on it without failing on
    /// every `.txt`, so `info` reports `nested 0` and `verify` passes clean on
    /// an archive holding a nested `RPF2`. Recorded rather than changed, and
    /// pinned by a test.
    ///
    /// # Errors
    ///
    /// [`Error::TooDeep`] past [`MAX_DEPTH`] levels of nesting, and nothing
    /// else: every other reason a payload is not an archive is `None`.
    pub fn nested_at<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Option<Self>> {
        match self.open_nested(src, index) {
            Ok(nested) => Ok(Some(nested)),
            Err(error @ Error::TooDeep { .. }) => Err(error),
            Err(_) => Ok(None),
        }
    }
}

/// Reads the header at `base`, or says why those bytes are not one.
///
/// The bytes are fetched here and decoded behind the seam: which fields a
/// header has, and how many bytes it occupies, are the version's.
/// [`Header::read`].
///
/// Leaves the source positioned wherever the read ended; every read after this
/// one seeks for itself.
fn read_header<R: Read + Seek>(src: &mut R, base: u64) -> Result<Header> {
    // Read as much of the longest header any version has as there is. A file
    // too short to hold one is not an archive, which is a better answer than
    // "i/o failure" — nothing failed, the bytes simply are not there.
    src.seek(SeekFrom::Start(base))
        .map_err(|source| Error::Io {
            offset: base,
            source,
        })?;
    let mut bytes = [0u8; MAX_HEADER_LEN];
    let mut filled = 0_usize;
    while filled < bytes.len() {
        let rest = bytes.get_mut(filled..).unwrap_or_default();
        let read = src.read(rest).map_err(|source| Error::Io {
            offset: base,
            source,
        })?;
        if read == 0 {
            break;
        }
        filled = filled.saturating_add(read);
    }

    let header = Header::read(bytes.get(0..filled).unwrap_or_default(), base)?;
    // Every encrypted path is R2. Refusing here, with a distinct variant, keeps
    // "cannot open this" separate from "this is broken". R6.3.
    if !header.version.is_open(header.encryption) {
        return Err(Error::NeedsKey {
            tag: header.encryption,
        });
    }
    Ok(header)
}

/// How many entries, saturating rather than truncating.
fn count_of(entries: &[Entry]) -> u32 {
    u32::try_from(entries.len()).unwrap_or(u32::MAX)
}

/// Splits the entry table into rows, at the stride its version gives them.
fn parse_entries(version: Version, table: &[u8], entry_count: u32) -> Result<Vec<Entry>> {
    let row_len = version.row_len();
    let stride = usize::try_from(row_len).unwrap_or(usize::MAX);
    let overrun = || Error::OutOfBounds {
        region: "entry table",
        offset: version.header_len(),
        len: u64::from(entry_count).saturating_mul(row_len),
        archive_len: 0,
    };
    let mut entries = Vec::new();
    for index in 0..entry_count {
        let start = usize::try_from(index)
            .ok()
            .and_then(|i| i.checked_mul(stride))
            .ok_or_else(overrun)?;
        let end = start.checked_add(stride).ok_or_else(overrun)?;
        let row = table.get(start..end).ok_or_else(overrun)?;
        let entry = version.decode_row(row).ok_or_else(overrun)?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Builds the child-to-parent map, and with it establishes that the entries are
/// a forest at all.
///
/// A child range inside the entry table is not enough. Three things are checked
/// here, and each of them is a crash somewhere downstream if it is not:
///
/// - the range fits the entry table, or an index in it names no entry;
/// - **every child comes after the directory that claims it.** The entry table
///   is laid out breadth-first, each directory's children in one run after it
///   (`docs/rpf-format.md`, Table order), so this holds of any archive a packer
///   wrote — and it is what makes the parent map well founded, since a walk up
///   it then strictly decreases and must end. `Archive::path` walks it in an
///   unguarded loop;
/// - **no entry is claimed twice.** Otherwise the children relation is a
///   lattice rather than a forest while the parent map, which holds one parent
///   per entry, looks perfectly ordinary — and it is the children relation that
///   `ls -R` recurses over.
///
/// The last two are what a single-valued, last-writer-wins parent map cannot
/// see. A directory whose range includes itself stays in the children relation
/// while being erased from the parent map the moment a later entry re-claims
/// the same child, and a check over the parent map alone then passes: measured,
/// three directory rows in 512 bytes left `info`, `cat` and `verify` all
/// reporting success and `ls -R` aborting with a stack overflow.
///
/// Refused here rather than guarded against at each walk (§5): a caller cannot
/// act on a value it never gets back.
fn parse_parents(entries: &[Entry]) -> Result<Vec<Option<u32>>> {
    let total = count_of(entries);
    let mut parents = vec![None; entries.len()];

    for (index, entry) in entries.iter().enumerate() {
        let EntryKind::Directory {
            first_child,
            child_count,
        } = entry.kind
        else {
            continue;
        };
        let index = u32::try_from(index).unwrap_or(u32::MAX);
        let bad_range = || Error::BadChildRange {
            entry: index,
            first: first_child,
            count: child_count,
            entry_count: total,
        };
        let end = first_child.checked_add(child_count).ok_or_else(bad_range)?;
        if end > total {
            return Err(bad_range());
        }

        for child in first_child..end {
            if child <= index {
                return Err(Error::CyclicTree {
                    entry: index,
                    child,
                });
            }
            let Some(slot) = usize::try_from(child).ok().and_then(|c| parents.get_mut(c)) else {
                return Err(bad_range());
            };
            if let Some(first) = *slot {
                return Err(Error::ClaimedTwice {
                    child,
                    first,
                    second: index,
                });
            }
            *slot = Some(index);
        }
    }

    check_depth(&parents)?;
    Ok(parents)
}

/// Refuses a tree deeper than [`MAX_DEPTH`].
///
/// One forward pass, and it is only that cheap because of the rule above: every
/// entry's parent has a smaller index, so by the time an entry is reached its
/// parent's depth is already known. An entry no directory claims is a root of
/// its own and counts as depth zero, which is what entry 0 is.
fn check_depth(parents: &[Option<u32>]) -> Result<()> {
    let mut depth: Vec<u32> = Vec::with_capacity(parents.len());
    for parent in parents {
        let here = match *parent {
            None => 0,
            Some(parent) => usize::try_from(parent)
                .ok()
                .and_then(|p| depth.get(p))
                .copied()
                .unwrap_or(MAX_DEPTH)
                .saturating_add(1),
        };
        if here > MAX_DEPTH {
            return Err(Error::TooDeep {
                what: "directory tree",
                depth: here,
                limit: MAX_DEPTH,
            });
        }
        depth.push(here);
    }
    Ok(())
}
