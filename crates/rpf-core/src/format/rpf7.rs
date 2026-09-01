//! The `RPF7` codec — GTA V Legacy and Enhanced, and `FiveM`.
//!
//! The only implementation behind [`Version`], and the only file in this crate
//! that holds a magic, a header length, a row width or a field offset. DR-012:
//! no version's codec is written before an archive of that version is in the
//! corpus, and none but this one is.
//!
//! Every constant here names the row of `docs/rpf-format.md` that established
//! it, and every one of those rows is `verified` — measured against the sample
//! rather than read from an implementation.

use crate::{
    entry::{Entry, EntryKind},
    error::{Error, Result},
    format::{
        Content, FileFields, Header, NamesPlan, Span, Version,
        crypto::{AesKey, Scheme},
        u16_at, u24_at, u32_at,
    },
};

/// Archive magic, as it appears on disk.
///
/// Reads `7FPR`, not `RPF7` — the four bytes are the little-endian spelling of
/// the version number. Comparing against `RPF7` finds no archive at all, which
/// is how the two nested archives in the sample were missed on the first walk.
///
/// `docs/rpf-format.md`, RPF7 header, `verified`.
pub const MAGIC: [u8; 4] = *b"7FPR";

/// The version number this codec reads, as it is spoken about.
///
/// `docs/rpf-format.md`, the magic table.
pub const NUMBER: u8 = 7;

/// Length of the archive header, in bytes. The entry table begins immediately
/// after it — not at 2048.
///
/// `docs/rpf-format.md`, Layout, `verified`.
pub const HEADER_LEN: usize = 16;

/// Length of one entry-table row, in bytes, for every entry kind.
///
/// A `usize` because it is an array bound: a row is a fixed-size array whose
/// length is the version's, which is the whole reason [`crate::format::Row`] is
/// an enum rather than a boxed trait object. DR-012.
///
/// `docs/rpf-format.md`, Entry table, `verified`.
pub const ROW_LEN: usize = 16;

/// The unit that an entry's offset field counts in.
///
/// Offsets are relative to the base of the archive holding the entry, which for
/// a nested archive is not the base of the file.
///
/// `docs/rpf-format.md`, Entry table, `verified` — all 27 payload offsets in the
/// sample are multiples of this.
pub const BLOCK_LEN: u64 = 512;

/// The value at offset 4 of an entry that marks it a directory rather than a
/// file. No file entry can produce it, because it would imply a compressed size
/// and offset that cannot both occur.
///
/// `docs/rpf-format.md`, Entry table, `verified`.
pub const DIRECTORY_MARKER: u32 = 0x7FFF_FF00;

/// The encryption tag meaning "not encrypted", ASCII `OPEN`.
///
/// `docs/rpf-format.md`, RPF7 header, `verified`.
pub const ENCRYPTION_OPEN: u32 = 0x4E45_504F;

/// The encryption tag meaning the RAGE AES-256 default.
///
/// `docs/rpf-format.md`, RPF7 header, `verified` — 43 archives across both GTA
/// V installs carry it, every one of them nested inside another archive.
pub const ENCRYPTION_AES: u32 = 0x0FFF_FFF9;

/// The encryption tag meaning the NG white-box transform.
///
/// `docs/rpf-format.md`, RPF7 header, `verified` — 10,743 archives across both
/// GTA V installs carry it, including every one of the 358 that sit on disk in
/// their own right.
pub const ENCRYPTION_NG: u32 = 0x0FEF_FFFF;

/// The encryption tag meaning the same AES-256 transform under the Rockstar
/// Games Launcher's own key.
///
/// The tag names a **key**, not an algorithm: the transform is
/// [`ENCRYPTION_AES`]'s, byte for byte, and only the 32 bytes running it
/// differ.
///
/// `docs/rpf-format.md`, RPF7 header, `verified`, 2026-08-30 — both builds of
/// the launcher's `Launcher.rpf` open under the key in `Launcher.exe`, 118 and
/// 120 entries, every payload reading back. A `secondary` reading of the same
/// row says the header's third dword carries a platform bit that selects a
/// second key for this tag on Xbox 360; that bit is **0** on every archive
/// measured here, so nothing reads it and this build routes the tag by itself.
/// DR-042.
pub const ENCRYPTION_AES_LAUNCHER: u32 = 0x0FFF_FFF7;

/// The value a **binary** entry's own encryption field carries when its payload
/// is stored in the clear.
///
/// `docs/rpf-format.md`, Entry table, `verified` — the field takes exactly two
/// values across both GTA V installs, 0 on 27,276 entries and 1 on 64,300, and
/// only the second needs the archive's transform to read back. A resource entry
/// has no such field: offsets 8 and 12 are its two flag words.
pub const ENTRY_OPEN: u32 = 0;

/// Which transform a tag names, and under which key, or `None` for a tag this
/// build cannot open.
///
/// Two of the three arms are the same cipher: an archive's tag chooses the key
/// as much as the transform, which is why [`Scheme::Aes`] carries an
/// [`AesKey`] rather than there being two AES schemes (DR-042). A tag that is
/// neither [`ENCRYPTION_OPEN`] nor one of these is encrypted under something
/// nobody here has identified, and no key anyone holds opens it, which is why
/// it is `None` rather than a further variant.
pub(super) const fn scheme(tag: u32) -> Option<Scheme> {
    match tag {
        ENCRYPTION_AES => Some(Scheme::Aes(AesKey::Rage)),
        ENCRYPTION_AES_LAUNCHER => Some(Scheme::Aes(AesKey::Launcher)),
        ENCRYPTION_NG => Some(Scheme::Ng),
        _ => None,
    }
}

/// Bit set within an entry's offset field marking the entry a resource.
///
/// `docs/rpf-format.md`, Entry table, `verified`.
pub const RESOURCE_FLAG: u32 = 0x0080_0000;

/// Largest value the 24-bit compressed-size field holds, and — on a
/// **resource** — the sentinel it writes when the payload is longer than that.
///
/// `docs/rpf-format.md`, Compression, `verified`: 166 of the corpus's 696,578
/// resources carry exactly this value, none carries more, and every one of the
/// 166 inflates to the length its flag words declare only when its payload is
/// taken to run to the next payload rather than to 16,777,215 bytes.
/// `Archive::size_field_saturated` is what reads it that way, and it reads it
/// on a resource only: a binary entry that cannot say its length has the zero
/// sentinel instead.
pub const MAX_SIZE_24: u64 = 0x00FF_FFFF;

/// Largest block index an entry's offset field holds, the resource bit excluded
/// — so the largest offset this version addresses is this times [`BLOCK_LEN`],
/// 4,294,966,784 bytes.
///
/// `docs/rpf-format.md`, Entry table, `verified`: it follows from the field's
/// 23 usable bits, and 358 Rockstar archives across both GTA V installs sit
/// under it, the largest at 3,981,039,616.
const MAX_BLOCK: u64 = 0x007F_FFFF;

/// Largest name offset a **file** entry holds. Directories get a full word.
const MAX_FILE_NAME_OFFSET: u64 = 0x0000_FFFF;

/// Whether a payload of this length fits the row's compressed-size field.
///
/// The writer asks before it chooses to deflate: a deflated form the row cannot
/// describe is not a smaller archive, it is a truncated size field.
pub(super) const fn holds_compressed_len(len: u64) -> bool {
    len <= MAX_SIZE_24
}

/// Whether a **resource** payload of this length leaves its row's
/// compressed-size field saying nothing about its extent.
///
/// **The one place the boundary is decided**, asked by the writer of a payload
/// in hand ([`file_row`]) and by the reader of a field ([`crate::Archive`])
/// alike, so that the two cannot come to read the same row differently.
///
/// `>=` rather than `>`, and that is the whole of it: a payload of exactly
/// [`MAX_SIZE_24`] bytes writes its real length, a longer one writes the
/// sentinel, and the twenty-four bits are the same either way. No reader can
/// tell the two apart, so a writer that treated the equal case as a length
/// keyed its payload by one number while the reader keyed it by another.
pub(super) const fn size_field_saturates(len: u64) -> bool {
    len >= MAX_SIZE_24
}

/// The length a resource payload's transform is keyed by.
///
/// **The one place that length is derived**, on both sides of the seam: the
/// writer minting a seal for a payload it holds and the reader choosing a
/// cipher for a payload on disk call this and nothing else, so a future change
/// cannot leave them keying the same bytes differently. DR-063.
///
/// An NG key index is `(hash(name) + length + 61) % 101`, so the length is
/// part of the key and the two sides have to name the same one. While the row
/// can state the payload's length it is the payload's own — that is the
/// measured rule, `script_rel.rpf/abigail1.ysc` at 90,775 bytes on disk. Once
/// the field saturates the row states nothing, and the reader recovers the
/// extent as the room to the next payload: block-aligned, because every
/// payload is written at an aligned offset. The real length is then knowledge
/// the reader does not have and cannot get, so the keying length is the room
/// — the one number both sides can compute — and the writer rounds up to it.
pub(super) const fn resource_key_len(len: u64) -> u64 {
    if !size_field_saturates(len) {
        return len;
    }
    match len.checked_rem(BLOCK_LEN) {
        None | Some(0) => len,
        Some(over) => len.saturating_add(BLOCK_LEN.saturating_sub(over)),
    }
}

/// The header these bytes hold, or `None` if there are not [`HEADER_LEN`] of
/// them.
///
/// The magic is not read here: a caller reaches this only by having matched it,
/// which is what [`Version::of`] is for.
pub(super) fn read_header(bytes: &[u8]) -> Option<Header> {
    Some(Header {
        version: Version::Rpf7,
        entry_count: u32_at(bytes, 4)?,
        names_len: u32_at(bytes, 8)?,
        encryption: u32_at(bytes, 12)?,
    })
}

/// The sixteen bytes an archive begins with.
pub(super) fn write_header(header: &Header) -> [u8; HEADER_LEN] {
    let mut out = [0_u8; HEADER_LEN];
    let words = [
        header.entry_count.to_le_bytes(),
        header.names_len.to_le_bytes(),
        header.encryption.to_le_bytes(),
    ];
    if let Some(magic) = out.get_mut(0..4) {
        magic.copy_from_slice(&MAGIC);
    }
    for (index, word) in words.iter().enumerate() {
        let at = index.saturating_mul(4).saturating_add(4);
        if let Some(slot) = at.checked_add(4).and_then(|end| out.get_mut(at..end)) {
            slot.copy_from_slice(word);
        }
    }
    out
}

/// One entry from exactly [`ROW_LEN`] bytes, or `None` when the slice is too
/// short.
///
/// Every field is a fixed-width integer, so there is nothing else here that can
/// fail — a row that decodes may still describe something impossible, which the
/// archive checks.
pub(super) fn decode_row(bytes: &[u8]) -> Option<Entry> {
    if bytes.len() < ROW_LEN {
        return None;
    }

    // A directory is identified by the second word alone. No file entry can
    // produce this value. docs/rpf-format.md, Entry table.
    if u32_at(bytes, 4)? == DIRECTORY_MARKER {
        return Some(Entry {
            name_offset: u32_at(bytes, 0)?,
            kind: EntryKind::Directory {
                first_child: u32_at(bytes, 8)?,
                child_count: u32_at(bytes, 12)?,
            },
        });
    }

    // A file entry packs a 16-bit name offset, a 24-bit compressed size and
    // a 24-bit block offset into the first eight bytes.
    let name_offset = u32::from(u16_at(bytes, 0)?);
    let compressed_len = u24_at(bytes, 2)?;
    let raw_offset = u24_at(bytes, 5)?;
    let block = raw_offset & !RESOURCE_FLAG;

    let kind = if raw_offset & RESOURCE_FLAG == 0 {
        EntryKind::Binary {
            block,
            compressed_len,
            uncompressed_len: u32_at(bytes, 8)?,
            encryption: u32_at(bytes, 12)?,
        }
    } else {
        EntryKind::Resource {
            block,
            compressed_len,
            system_flags: u32_at(bytes, 8)?,
            graphics_flags: u32_at(bytes, 12)?,
        }
    };

    Some(Entry { name_offset, kind })
}

/// One directory row: a full-word name offset, the marker, and the child run.
pub(super) fn directory_row(name_offset: u32, first_child: u32, child_count: u32) -> [u8; ROW_LEN] {
    let mut row = [0_u8; ROW_LEN];
    for (index, word) in [
        name_offset.to_le_bytes(),
        DIRECTORY_MARKER.to_le_bytes(),
        first_child.to_le_bytes(),
        child_count.to_le_bytes(),
    ]
    .iter()
    .enumerate()
    {
        let at = index.saturating_mul(4);
        if let Some(slot) = at.checked_add(4).and_then(|end| row.get_mut(at..end)) {
            slot.copy_from_slice(word);
        }
    }
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
/// One field is the exception, and it is the format's rather than this
/// function's: a **resource** whose compressed length reaches [`MAX_SIZE_24`]
/// writes that value as a saturation sentinel ([`size_field_saturates`], which
/// is where the boundary lives), because the extent of such a payload was
/// never in the field to begin with — it is the room to the next
/// payload, which is how the reader recovers it. A **binary** entry at the same
/// value is refused: its compressed length is the one statement of where its
/// payload ends, and the format has no other spelling for it. DR-056, DR-051.
///
/// # Errors
///
/// [`Error::FieldOverflow`] for a value the row cannot represent, and
/// [`Error::ArchiveTooLarge`] for a block offset past the end of what this
/// version addresses — which is the archive's size rather than this entry's.
pub(super) fn file_row(path: &str, fields: &FileFields) -> Result<[u8; ROW_LEN]> {
    check(
        path,
        "file name offset",
        u64::from(fields.name_offset),
        MAX_FILE_NAME_OFFSET,
    )?;
    let (word_at_8, word_at_12, resource) = match fields.content {
        Content::Binary {
            uncompressed_len,
            encryption,
        } => (uncompressed_len, encryption, false),
        Content::Resource {
            system_flags,
            graphics_flags,
        } => (system_flags, graphics_flags, true),
    };
    // A resource longer than the field holds writes [`MAX_SIZE_24`] and lets
    // the reader recover its extent from the room to the next payload; a binary
    // entry has no such spelling and is refused. DR-056, DR-051 clause 1.
    let compressed_field = if resource && size_field_saturates(fields.compressed_len) {
        MAX_SIZE_24
    } else {
        check(path, "compressed size", fields.compressed_len, MAX_SIZE_24)?;
        fields.compressed_len
    };
    // Not `check`: a block offset past the end is the archive's size and not
    // this entry's, and reporting it as this entry's names whichever payload
    // the layout happened to place first past the ceiling.
    if fields.block > MAX_BLOCK {
        return Err(Error::ArchiveTooLarge {
            path: path.to_owned(),
            reached: fields.block.saturating_mul(BLOCK_LEN),
            limit: MAX_BLOCK.saturating_mul(BLOCK_LEN),
        });
    }

    let offset_field = if resource {
        fields.block | u64::from(RESOURCE_FLAG)
    } else {
        fields.block
    };

    let mut row = [0_u8; ROW_LEN];
    write_at(&mut row, 0, &fields.name_offset.to_le_bytes(), 2);
    write_at(&mut row, 2, &compressed_field.to_le_bytes(), 3);
    write_at(&mut row, 5, &offset_field.to_le_bytes(), 3);
    write_at(&mut row, 8, &word_at_8.to_le_bytes(), 4);
    write_at(&mut row, 12, &word_at_12.to_le_bytes(), 4);
    Ok(row)
}

/// Copies the low `width` bytes of a little-endian field into the row.
///
/// A no-op if the row is too short, which it cannot be: every call below is
/// inside [`ROW_LEN`]. §6 forbids the slice index that would say so by
/// panicking.
fn write_at(row: &mut [u8; ROW_LEN], at: usize, field: &[u8], width: usize) {
    let Some(end) = at.checked_add(width) else {
        return;
    };
    let (Some(slot), Some(source)) = (row.get_mut(at..end), field.get(0..width)) else {
        return;
    };
    slot.copy_from_slice(source);
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

/// Locates every entry's name in the names blob, refusing anything that is not
/// a terminated string inside it.
///
/// Names are **strings** at this version — `docs/rpf-format.md` records hashes
/// at 3, 6 and 8 and strings at 0, 2, 4 and 7, all `secondary` but for this
/// row — so a version-independent reader cannot assume this shape, which is
/// why it lives behind the seam rather than in `Archive`.
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
///
/// # Errors
///
/// [`Error::BadName`] for a name offset that is not a terminated string inside
/// the blob.
pub(super) fn resolve_names(blob: &[u8], entries: &[Entry]) -> Result<Vec<Span>> {
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

    let mut located: Vec<Span> = Vec::with_capacity(offsets.len());
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
        located.push(Span { at, len });
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

/// Lays out the names blob, one copy of each distinct name.
///
/// # Errors
///
/// [`Error::FieldOverflow`] when the blob outgrows the header's length field.
pub(super) fn plan_names<'a, I: IntoIterator<Item = &'a str>>(names: I) -> Result<NamesPlan> {
    let mut blob: Vec<u8> = Vec::new();
    let mut seen: std::collections::HashMap<&'a str, u32> = std::collections::HashMap::new();
    let mut offsets = Vec::new();

    for name in names {
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
    Ok(NamesPlan { blob, offsets })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_sample_root_directory() {
        // Entry 0 of dlc.rpf: name offset 0, four children starting at 1.
        let row = directory_row(0, 1, 4);
        let entry = decode_row(&row).expect("a whole row");
        assert!(entry.is_directory());
        assert_eq!(
            entry.kind,
            EntryKind::Directory {
                first_child: 1,
                child_count: 4
            }
        );
    }

    #[test]
    fn decodes_a_binary_entry_as_measured() {
        // dlc.rpf /data/vehicles.meta: 1,631 compressed at block 4, 5,100 out.
        let row = file_row(
            "data/vehicles.meta",
            &FileFields {
                name_offset: 37,
                block: 4,
                compressed_len: 1631,
                content: Content::Binary {
                    uncompressed_len: 5100,
                    encryption: 0,
                },
            },
        )
        .expect("every field fits");

        let entry = decode_row(&row).expect("a whole row");
        assert_eq!(entry.name_offset, 37);
        assert_eq!(
            entry.kind,
            EntryKind::Binary {
                block: 4,
                compressed_len: 1631,
                uncompressed_len: 5100,
                encryption: 0,
            }
        );
    }

    #[test]
    fn the_resource_bit_selects_the_variant_and_leaves_the_block_clean() {
        // vehicles.rpf/meringls63amg24.ytd: block 98,908 with the resource bit.
        let row = file_row(
            "meringls63amg24.ytd",
            &FileFields {
                name_offset: 0,
                block: 98_908,
                compressed_len: 802_444,
                content: Content::Resource {
                    system_flags: 0x0002_0000,
                    graphics_flags: 0xD102_0008,
                },
            },
        )
        .expect("every field fits");

        // The bit is in the offset field on disk and out of the block in the
        // decode, which is the round trip that matters.
        assert_eq!(u24_at(&row, 5), Some(0x0001_825C | RESOURCE_FLAG));
        assert_eq!(
            decode_row(&row).expect("a whole row").kind,
            EntryKind::Resource {
                block: 98_908,
                compressed_len: 802_444,
                system_flags: 0x0002_0000,
                graphics_flags: 0xD102_0008,
            }
        );
    }

    #[test]
    fn a_short_row_is_refused_rather_than_panicking() {
        assert!(decode_row(&[0_u8; ROW_LEN.saturating_sub(1)]).is_none());
        assert!(decode_row(&[]).is_none());
    }

    #[test]
    fn a_table_longer_than_one_row_still_decodes_its_first() {
        // `Archive`'s own key check hands this the whole entry table rather
        // than one row sliced out of it (`archive::is_root_directory`), so a
        // slice past `ROW_LEN` must not be refused as too short.
        let row = directory_row(0, 1, 4);
        let mut table = row.to_vec();
        table.extend_from_slice(&row);
        let entry = decode_row(&table).expect("bytes past the first row do not make it too short");
        assert!(entry.is_directory());
    }

    #[test]
    fn every_narrow_field_refuses_a_value_it_cannot_hold() {
        // Each of these is a truncation that reads back without complaint.
        let fields = |name_offset: u32, block: u64, compressed_len: u64| FileFields {
            name_offset,
            block,
            compressed_len,
            content: Content::Binary {
                uncompressed_len: 0,
                encryption: 0,
            },
        };
        for (what, spec) in [
            ("file name offset", fields(0x0001_0000, 0, 0)),
            ("compressed size", fields(0, 0, 0x0100_0000)),
        ] {
            let error = file_row("a.txt", &spec).expect_err("does not fit");
            assert!(
                matches!(error, Error::FieldOverflow { what: named, .. } if named == what),
                "{what}: {error:?}"
            );
        }
        // And the largest value each field *does* hold is still written.
        assert!(file_row("a.txt", &fields(0xFFFF, MAX_BLOCK, MAX_SIZE_24)).is_ok());
    }

    #[test]
    fn a_resource_past_the_size_field_writes_the_sentinel_where_a_binary_entry_is_refused() {
        // The same length in both variants, so the only thing that differs is
        // the kind. DR-056: the resource's extent was never in this field —
        // the reader takes it from the room to the next payload — and the
        // binary entry's is the only statement of it there is.
        let over = MAX_SIZE_24.saturating_add(1);
        let row = file_row(
            "big.ydr",
            &FileFields {
                name_offset: 0,
                block: 1,
                compressed_len: over,
                content: Content::Resource {
                    system_flags: 0x0002_0000,
                    graphics_flags: 0xD102_0008,
                },
            },
        )
        .expect("a resource past the field writes the sentinel");
        // Written whole rather than truncated to the field's low three bytes,
        // which for this value would have read back as zero — a stored entry.
        assert_eq!(u24_at(&row, 2).map(u64::from), Some(MAX_SIZE_24));
        assert!(matches!(
            decode_row(&row).expect("a whole row").kind,
            EntryKind::Resource { compressed_len, .. } if u64::from(compressed_len) == MAX_SIZE_24
        ));

        let refused = file_row(
            "big.bin",
            &FileFields {
                name_offset: 0,
                block: 1,
                compressed_len: over,
                content: Content::Binary {
                    uncompressed_len: 0,
                    encryption: 0,
                },
            },
        )
        .expect_err("a binary entry past the field has no other spelling");
        assert!(
            matches!(refused, Error::FieldOverflow { what, len, .. }
                if what == "compressed size" && len == over),
            "{refused:?}"
        );
    }

    #[test]
    fn a_block_offset_past_the_end_is_the_archive_being_too_large() {
        // Measured 2026-08-29 on a 2,965,617,664-byte archive built for the
        // purpose: adding a further 1.5 GB entry reported `"data/vehicles.meta":
        // block offset is 8594217, over the format's limit of 8388607` — an
        // entry the caller never named, which is the first one the layout put
        // past the ceiling. The fact is the archive's size, so the failure is.
        let past = FileFields {
            name_offset: 0,
            block: MAX_BLOCK.saturating_add(1),
            compressed_len: 0,
            content: Content::Binary {
                uncompressed_len: 0,
                encryption: 0,
            },
        };
        let error = file_row("data/vehicles.meta", &past).expect_err("does not fit");
        let Error::ArchiveTooLarge { reached, limit, .. } = error else {
            panic!("{error:?}");
        };
        // 8,388,607 blocks of 512 bytes: just under 4 GiB, and the reason no
        // archive in either GTA V install exceeds it. docs/corpus.md.
        assert_eq!(limit, 4_294_966_784);
        assert_eq!(reached, 4_294_967_296);
    }

    #[test]
    fn the_header_round_trips_through_its_own_bytes() {
        // The sample: 11 entries, a 144-byte names blob, tag `OPEN`.
        let header = Header {
            version: Version::Rpf7,
            entry_count: 11,
            names_len: 144,
            encryption: ENCRYPTION_OPEN,
        };
        let bytes = write_header(&header);
        assert_eq!(bytes.get(0..4), Some(MAGIC.as_slice()));
        assert_eq!(read_header(&bytes), Some(header));
    }

    #[test]
    fn a_header_shorter_than_the_version_needs_is_not_read() {
        let bytes = write_header(&Header {
            version: Version::Rpf7,
            entry_count: 11,
            names_len: 144,
            encryption: ENCRYPTION_OPEN,
        });
        assert!(read_header(bytes.get(0..15).expect("15 of 16")).is_none());
    }

    #[test]
    fn magic_is_the_little_endian_spelling() {
        // The trap that hid both nested archives on the first walk.
        assert_eq!(MAGIC, [0x37, 0x46, 0x50, 0x52]);
        assert_ne!(MAGIC, *b"RPF7");
    }

    #[test]
    fn one_copy_of_each_distinct_name_goes_in_the_blob() {
        let plan = plan_names(["", "data", "x64", "data"]).expect("fits");
        assert_eq!(plan.blob, b"\0data\0x64\0");
        assert_eq!(plan.offsets, vec![0, 1, 6, 1]);
    }

    #[test]
    fn a_name_offset_past_the_blob_is_refused_rather_than_read_on() {
        // Never read past `namesLength`: the bytes after the blob can be stale
        // names from a previous pack. `docs/rpf-format.md`, Slack, `verified`.
        let entries = [Entry {
            name_offset: 4,
            kind: EntryKind::Directory {
                first_child: 0,
                child_count: 0,
            },
        }];
        assert!(matches!(
            resolve_names(b"ab\0", &entries),
            Err(Error::BadName { entry: 0, .. })
        ));
        // And a name the blob never terminates is the same refusal.
        assert!(matches!(
            resolve_names(b"abcde", &entries),
            Err(Error::BadName { .. })
        ));
    }
}
