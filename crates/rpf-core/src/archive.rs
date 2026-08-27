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
        RESOURCE_HEADER_LEN, payload_floor, resource_len, same_name, u32_at,
    },
};

/// How deep anything in this container is walked before it is refused.
///
/// It bounds two structures, because it is one fact about one thing: every
/// recursive walk over an archive — `child_named` down a path, `ls -R`,
/// `verify`, the daemon's recursive list — descends a directory tree, an
/// archive nested inside an archive, or both, and both depths are chosen by
/// the bytes rather than by us.
///
/// The bound belongs here and not at each walker (§5). A walker that carried
/// its own counter would be one walker away from a walker that forgot, and the
/// symptom of forgetting is a stack overflow rather than a wrong answer:
/// measured before this existed, 5,000 stacked directory rows — 80,384 bytes —
/// and 16,000 stacked archive headers — 8,192,000 bytes — each aborted
/// `rpf ls -R` with exit 134, and took the daemon's session with them.
///
/// 32 rather than a rounder number because it is two orders of magnitude above
/// anything real and still far below what a stack holds: the deepest tree in
/// the sample is `x64/vehiclemods/<file>`, 3, and the deepest nesting is 1.
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
    /// How many archives this one sits inside. Zero for a file opened on its
    /// own, and one more than its holder's for every nested archive, which is
    /// what [`MAX_DEPTH`] is counted against.
    depth: u32,
    entries: Vec<Entry>,
    names: Vec<NameSpan>,
    parents: Vec<Option<u32>>,
    names_blob: Vec<u8>,
}

/// Where one entry's name lies in the names blob.
///
/// A span rather than an owned `String`, because nothing stops an archive
/// pointing every entry at one long name: materialising each copy makes the
/// cost of *opening* the archive `entry_count × names_len`. Measured before
/// this was a span — 40,000 entries over a 40,000-byte blob, a 680,016-byte
/// file — 1,980,317,696 bytes of resident memory in 4.2 seconds, and ~7 MB of
/// input would have asked for ~200 GB. `Archive::open` is on the path of every
/// command and every daemon session, so that is a small file away from every
/// caller.
#[derive(Debug, Clone, Copy)]
struct NameSpan {
    /// Offset into the names blob.
    at: u32,
    /// Length in bytes, up to but not including the terminator.
    len: u32,
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
            entry_count,
            names_len,
            encryption,
        } = read_header(src, base)?;

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
        // Checked before the names blob, so that a header claiming more
        // entries than the file can hold names the entry table rather than the
        // blob that never got a chance to start (§10).
        if names_at > len {
            return Err(Error::OutOfBounds {
                region: "entry table",
                offset: HEADER_LEN,
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

        let table = read_vec_at(src, base.checked_add(HEADER_LEN).unwrap_or(base), table_len)?;
        let entries = parse_entries(&table, entry_count)?;

        let names_blob = read_vec_at(
            src,
            base.checked_add(names_at).unwrap_or(base),
            u64::from(names_len),
        )?;

        // Names are located once, here, so that `name` has nothing left to
        // find (§5). What it costs is one pass over the blob, not one scan and
        // one allocation per entry — see [`NameSpan`].
        let names = resolve_names(&names_blob, &entries)?;

        let parents = parse_parents(&entries)?;

        Ok(Self {
            base,
            len,
            encryption,
            depth,
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
    /// [`Error::NoSuchEntry`] if the index is past the end, and
    /// [`Error::BadName`] if the bytes at the entry's name offset are not
    /// UTF-8. Every name in the sample is ASCII; refusing the rest is §6's
    /// answer for third-party bytes, and it is a name the caller can be shown
    /// rather than a repair it cannot check.
    pub fn name(&self, index: u32) -> Result<&str> {
        let span = usize::try_from(index)
            .ok()
            .and_then(|i| self.names.get(i))
            .copied()
            .ok_or(Error::NoSuchEntry {
                index,
                entry_count: count_of(&self.entries),
            })?;

        let bad = || Error::BadName {
            entry: index,
            name_offset: span.at,
            names_len: u32::try_from(self.names_blob.len()).unwrap_or(u32::MAX),
        };
        let start = usize::try_from(span.at).unwrap_or(usize::MAX);
        let end = start.saturating_add(usize::try_from(span.len).unwrap_or(usize::MAX));
        let raw = self.names_blob.get(start..end).ok_or_else(bad)?;
        std::str::from_utf8(raw).map_err(|_| bad())
    }

    /// The full path of an entry, addressed from the archive root.
    ///
    /// The root itself is the empty string; everything else is
    /// slash-separated with no leading slash.
    ///
    /// The walk up the parent map is unguarded because it does not need a
    /// guard: [`parse_parents`] refuses any archive in which a child's index is
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
            .checked_mul(BLOCK_LEN)
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
        let floor = payload_floor(
            u64::try_from(self.entries.len()).unwrap_or(u64::MAX),
            u64::try_from(self.names_blob.len()).unwrap_or(u64::MAX),
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
        let offset = u64::from(index)
            .checked_mul(ENTRY_LEN)
            .and_then(|by| HEADER_LEN.checked_add(by))
            .and_then(|by| self.base.checked_add(by))
            .ok_or(Error::OutOfBounds {
                region: "entry table",
                offset: HEADER_LEN,
                len: ENTRY_LEN,
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
            .find(|&index| self.name(index).is_ok_and(|n| same_name(n, name)))
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

/// The three fields of an RPF7 header that say anything about the archive.
///
/// `docs/rpf-format.md`, RPF7 header, `verified`. The magic is not carried
/// because a [`Header`] cannot exist without it having matched, and the length
/// is not in the header at all.
struct Header {
    entry_count: u32,
    names_len: u32,
    encryption: u32,
}

/// Reads the header at `base`, or says why those bytes are not one.
///
/// Leaves the source positioned wherever the read ended; every read after this
/// one seeks for itself.
fn read_header<R: Read + Seek>(src: &mut R, base: u64) -> Result<Header> {
    // Read as much of the header as there is. A file too short to hold one is
    // not an archive, which is a better answer than "i/o failure" — nothing
    // failed, the bytes simply are not there.
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

    let magic: [u8; 4] = header
        .get(0..4)
        .and_then(|s| s.try_into().ok())
        .unwrap_or_default();
    if filled < header.len() || magic != MAGIC_RPF7 {
        return Err(Error::NotAnArchive { base, found: magic });
    }

    // Every field below is inside the sixteen bytes just filled, so the default
    // is unreachable rather than a decision about a short header.
    let encryption = u32_at(&header, 12).unwrap_or_default();
    // Every encrypted path is R2. Refusing here, with a distinct variant, keeps
    // "cannot open this" separate from "this is broken". R6.3.
    if encryption != ENCRYPTION_OPEN {
        return Err(Error::NeedsKey { tag: encryption });
    }

    Ok(Header {
        entry_count: u32_at(&header, 4).unwrap_or_default(),
        names_len: u32_at(&header, 8).unwrap_or_default(),
        encryption,
    })
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

/// Locates every entry's name in the names blob, refusing anything that is not
/// a terminated string inside it.
///
/// The blob is `namesLength` bytes and no more, never the backing buffer: the
/// bytes after it can be stale names from a previous pack. `docs/rpf-format.md`,
/// Slack.
///
/// Distinct name offsets are visited in ascending order and share one cursor,
/// so finding every terminator costs one pass over the blob rather than one
/// scan per entry. That is the same reason the result is a span and not a
/// `String`: both readings are `entry_count × names_len` when an archive points
/// every entry at one long name, and an archive may.
fn resolve_names(blob: &[u8], entries: &[Entry]) -> Result<Vec<NameSpan>> {
    let names_len = u32::try_from(blob.len()).unwrap_or(u32::MAX);
    // The entry index is what a caller needs to act on, and the offset is
    // shared, so the first entry carrying it is the one reported.
    let bad = |name_offset: u32| Error::BadName {
        entry: entries
            .iter()
            .position(|entry| entry.name_offset == name_offset)
            .and_then(|index| u32::try_from(index).ok())
            .unwrap_or(u32::MAX),
        name_offset,
        names_len,
    };

    let mut offsets: Vec<u32> = entries.iter().map(|entry| entry.name_offset).collect();
    offsets.sort_unstable();
    offsets.dedup();

    let mut located: Vec<NameSpan> = Vec::with_capacity(offsets.len());
    let mut cursor = 0_usize;
    for &at in &offsets {
        let start = usize::try_from(at).map_err(|_| bad(at))?;
        if start >= blob.len() {
            return Err(bad(at));
        }
        if cursor < start {
            cursor = start;
        }
        while blob.get(cursor).is_some_and(|&byte| byte != 0) {
            cursor = cursor.saturating_add(1);
        }
        if cursor >= blob.len() {
            return Err(bad(at));
        }
        let len = u32::try_from(cursor.saturating_sub(start)).map_err(|_| bad(at))?;
        located.push(NameSpan { at, len });
    }

    entries
        .iter()
        .map(|entry| {
            offsets
                .binary_search(&entry.name_offset)
                .ok()
                .and_then(|index| located.get(index))
                .copied()
                .ok_or_else(|| bad(entry.name_offset))
        })
        .collect()
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
