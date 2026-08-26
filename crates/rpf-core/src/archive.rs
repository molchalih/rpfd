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

use std::io::{Read, Seek, SeekFrom};

use crate::{
    entry::{Entry, EntryKind},
    error::{Error, Result},
    format::{
        BLOCK_LEN, ENCRYPTION_OPEN, ENTRY_LEN, HEADER_LEN, MAGIC_RPF7, MAGIC_RSC7,
        RESOURCE_HEADER_LEN, resource_len,
    },
};

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

/// Raw deflate, with the output length the archive promised.
///
/// Bounded by `expected` on purpose: a declared length is attacker-controlled,
/// so it caps the read rather than sizing an allocation up front.
fn inflate(entry: u32, raw: &[u8], expected: u64) -> Result<Vec<u8>> {
    let limit = expected.checked_add(1).ok_or(Error::LengthMismatch {
        entry,
        expected,
        actual: u64::MAX,
    })?;

    let mut out = Vec::new();
    flate2::read::DeflateDecoder::new(raw)
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
    Ok(out)
}

/// The table of contents of one archive.
#[derive(Debug, Clone)]
pub struct Archive {
    base: u64,
    len: u64,
    encryption: u32,
    entries: Vec<Entry>,
    names: Vec<String>,
    parents: Vec<Option<u32>>,
    names_blob: Vec<u8>,
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
    /// [`Error::NotAnArchive`] if the magic is wrong, [`Error::NeedsKey`] if it
    /// is encrypted, and the bounds variants if the header describes regions
    /// that do not fit.
    pub fn parse<R: Read + Seek>(src: &mut R, base: u64, len: u64) -> Result<Self> {
        // Read as much of the header as there is. A file too short to hold one
        // is not an archive, which is a better answer than "i/o failure" —
        // nothing failed, the bytes simply are not there.
        src.seek(SeekFrom::Start(base))
            .map_err(|source| Error::Io {
                offset: base,
                source,
            })?;
        let mut header = [0u8; 16];
        let mut filled = 0_usize;
        while filled < header.len() {
            let rest = header.get_mut(filled..).unwrap_or_default();
            let read = src.read(rest).map_err(|source| Error::Io {
                offset: base,
                source,
            })?;
            if read == 0 {
                break;
            }
            filled = filled.saturating_add(read);
        }
        if filled < header.len() {
            let found: [u8; 4] = header
                .get(0..4)
                .and_then(|s| s.try_into().ok())
                .unwrap_or_default();
            return Err(Error::NotAnArchive { base, found });
        }

        let magic: [u8; 4] = header
            .get(0..4)
            .and_then(|s| s.try_into().ok())
            .unwrap_or_default();
        if magic != MAGIC_RPF7 {
            return Err(Error::NotAnArchive { base, found: magic });
        }

        let entry_count = word(&header, 4);
        let names_len = word(&header, 8);
        let encryption = word(&header, 12);

        // Every encrypted path is R2. Refusing here, with a distinct variant,
        // keeps "cannot open this" separate from "this is broken". R6.3.
        if encryption != ENCRYPTION_OPEN {
            return Err(Error::NeedsKey { tag: encryption });
        }

        let table_len =
            u64::from(entry_count)
                .checked_mul(ENTRY_LEN)
                .ok_or(Error::OutOfBounds {
                    region: "entry table",
                    offset: HEADER_LEN,
                    len: u64::MAX,
                    archive_len: len,
                })?;
        let names_at = HEADER_LEN
            .checked_add(table_len)
            .ok_or(Error::OutOfBounds {
                region: "entry table",
                offset: HEADER_LEN,
                len: table_len,
                archive_len: len,
            })?;
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

        let table = read_vec_at(src, base.checked_add(HEADER_LEN).unwrap_or(base), table_len)?;
        let entries = parse_entries(&table, entry_count)?;

        let names_blob = read_vec_at(
            src,
            base.checked_add(names_at).unwrap_or(base),
            u64::from(names_len),
        )?;

        // Names are resolved once, here, so that `name` cannot fail later (§5).
        // The bound is `names_len`, never the blob's backing buffer: the bytes
        // after the blob can be stale names from a previous pack.
        let names = entries
            .iter()
            .enumerate()
            .map(|(index, entry)| resolve_name(&names_blob, entry.name_offset, index, names_len))
            .collect::<Result<Vec<_>>>()?;

        let parents = parse_parents(&entries)?;

        Ok(Self {
            base,
            len,
            encryption,
            entries,
            names,
            parents,
            names_blob,
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

    /// The archive's encryption tag. Always [`ENCRYPTION_OPEN`] for now, since
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
        &self.names_blob
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
    /// [`Error::NoSuchEntry`] if the index is past the end.
    pub fn name(&self, index: u32) -> Result<&str> {
        let at = usize::try_from(index).ok().and_then(|i| self.names.get(i));
        at.map(String::as_str).ok_or(Error::NoSuchEntry {
            index,
            entry_count: count_of(&self.entries),
        })
    }

    /// The full path of an entry, addressed from the archive root.
    ///
    /// The root itself is the empty string; everything else is
    /// slash-separated with no leading slash.
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
                entry: index,
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
                    entry: index,
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
            EntryKind::Resource {
                block,
                compressed_len,
                ..
            } => (block, u64::from(compressed_len)),
        };

        let relative = u64::from(block)
            .checked_mul(BLOCK_LEN)
            .ok_or(Error::OutOfBounds {
                region: "payload",
                offset: 0,
                len: on_disk,
                archive_len: self.len,
            })?;
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

    /// Reads an entry's **contents**: what the file means, with no container
    /// framing left on it.
    ///
    /// A binary entry inflates to its declared length. A resource entry has its
    /// 16-byte `RSC7` header removed and the remainder inflated. Compare
    /// [`Archive::extract`], which keeps the header.
    ///
    /// # Errors
    ///
    /// [`Error::WrongKind`] for a directory, the bounds variants for a payload
    /// that does not fit, and [`Error::Inflate`] or [`Error::LengthMismatch`]
    /// when the payload does not decompress as promised.
    pub fn read<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Vec<u8>> {
        let (offset, on_disk) = self.payload_span(index)?;
        let entry = self.entry(index)?;

        match entry.kind {
            EntryKind::Directory { .. } => Err(Error::WrongKind {
                entry: index,
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
                    return Ok(raw);
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
    /// Matching is ASCII case-insensitive, which is how the runtime addresses
    /// these paths. Every name in the sample is lower-case, so this repository
    /// cannot yet tell case-folded order from byte order — `docs/backlog.md` Q1.
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
                .child_named(current, segment)
                .ok_or_else(|| Error::NotFound {
                    path: path.to_owned(),
                    segment: segment.to_owned(),
                })?;
        }
        Ok(current)
    }

    /// The child of `parent` with this name, or `None` if `parent` is not a
    /// directory or has no such child.
    pub(crate) fn child_named(&self, parent: u32, name: &str) -> Option<u32> {
        self.children(parent)
            .ok()?
            .find(|&index| self.name(index).is_ok_and(|n| n.eq_ignore_ascii_case(name)))
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
                .child_named(current, segment)
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
    /// # Errors
    ///
    /// As [`Archive::parse`], plus [`Error::WrongKind`] for a directory.
    pub fn open_nested<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Self> {
        let (offset, on_disk) = self.payload_span(index)?;
        Self::parse(src, offset, on_disk)
    }
}

/// Reads a little-endian word from the header.
fn word(header: &[u8; 16], off: usize) -> u32 {
    let raw: [u8; 4] = header
        .get(off..off.saturating_add(4))
        .and_then(|s| s.try_into().ok())
        .unwrap_or_default();
    u32::from_le_bytes(raw)
}

/// How many entries, saturating rather than truncating.
fn count_of(entries: &[Entry]) -> u32 {
    u32::try_from(entries.len()).unwrap_or(u32::MAX)
}

/// Splits the entry table into rows.
fn parse_entries(table: &[u8], entry_count: u32) -> Result<Vec<Entry>> {
    let stride = usize::try_from(ENTRY_LEN).unwrap_or(16);
    let mut entries = Vec::new();
    for index in 0..entry_count {
        let start = usize::try_from(index)
            .ok()
            .and_then(|i| i.checked_mul(stride))
            .ok_or(Error::OutOfBounds {
                region: "entry table",
                offset: HEADER_LEN,
                len: u64::from(entry_count).saturating_mul(ENTRY_LEN),
                archive_len: 0,
            })?;
        let end = start.checked_add(stride).ok_or(Error::OutOfBounds {
            region: "entry table",
            offset: HEADER_LEN,
            len: u64::from(entry_count).saturating_mul(ENTRY_LEN),
            archive_len: 0,
        })?;
        let row = table.get(start..end).ok_or(Error::OutOfBounds {
            region: "entry table",
            offset: HEADER_LEN,
            len: u64::from(entry_count).saturating_mul(ENTRY_LEN),
            archive_len: 0,
        })?;
        let entry = Entry::parse(row).ok_or(Error::OutOfBounds {
            region: "entry table",
            offset: HEADER_LEN,
            len: u64::from(entry_count).saturating_mul(ENTRY_LEN),
            archive_len: 0,
        })?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Resolves one name, refusing anything that runs past `names_len`.
fn resolve_name(blob: &[u8], name_offset: u32, index: usize, names_len: u32) -> Result<String> {
    let entry = u32::try_from(index).unwrap_or(u32::MAX);
    let bad = Error::BadName {
        entry,
        name_offset,
        names_len,
    };

    let start = usize::try_from(name_offset).map_err(|_| Error::BadName {
        entry,
        name_offset,
        names_len,
    })?;
    let tail = blob.get(start..).ok_or(Error::BadName {
        entry,
        name_offset,
        names_len,
    })?;
    let end = tail.iter().position(|&b| b == 0).ok_or(bad)?;
    let raw = tail.get(..end).ok_or(Error::BadName {
        entry,
        name_offset,
        names_len,
    })?;
    Ok(String::from_utf8_lossy(raw).into_owned())
}

/// Builds the child-to-parent map, validating every child range on the way.
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
        let end = first_child
            .checked_add(child_count)
            .ok_or(Error::BadChildRange {
                entry: index,
                first: first_child,
                count: child_count,
                entry_count: total,
            })?;
        if end > total {
            return Err(Error::BadChildRange {
                entry: index,
                first: first_child,
                count: child_count,
                entry_count: total,
            });
        }
        for child in first_child..end {
            if let Some(slot) = usize::try_from(child).ok().and_then(|c| parents.get_mut(c)) {
                *slot = Some(index);
            }
        }
    }
    Ok(parents)
}
