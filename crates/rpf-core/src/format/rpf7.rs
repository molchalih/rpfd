//! The `RPF7` codec — GTA V Legacy and Enhanced, and `FiveM`.
//!
//! The only implementation behind [`Version`], and the only file in this crate
//! that holds a magic, a header length, a row width or a field offset.

use crate::{
    entry::{Entry, EntryKind},
    error::{Error, Result},
    format::{
        Content, FileFields, Header, NamesPlan, Span, Version,
        crypto::{AesKey, Scheme},
        u16_at, u24_at, u32_at,
    },
};

/// Archive magic, as it appears on disk: `7FPR`, the little-endian spelling of
/// the version number. Comparing against `RPF7` finds no archive at all.
pub const MAGIC: [u8; 4] = *b"7FPR";

/// The version number this codec reads, as it is spoken about.
pub const NUMBER: u8 = 7;

/// Length of the archive header, in bytes. The entry table begins immediately
/// after it — not at 2048.
pub const HEADER_LEN: usize = 16;

/// Length of one entry-table row, in bytes, for every entry kind. A `usize`
/// because it is the bound of the array [`crate::format::Row`] holds.
pub const ROW_LEN: usize = 16;

/// The unit that an entry's offset field counts in. Offsets are relative to the
/// base of the archive holding the entry, which for a nested archive is not the
/// base of the file.
pub const BLOCK_LEN: u64 = 512;

/// The value at offset 4 of an entry that marks it a directory rather than a
/// file. No file entry can produce it, because it would imply a compressed size
/// and offset that cannot both occur.
pub const DIRECTORY_MARKER: u32 = 0x7FFF_FF00;

/// The encryption tag meaning "not encrypted", ASCII `OPEN`.
pub const ENCRYPTION_OPEN: u32 = 0x4E45_504F;

/// The encryption tag meaning the RAGE AES-256 default.
pub const ENCRYPTION_AES: u32 = 0x0FFF_FFF9;

/// The encryption tag meaning the NG white-box transform.
pub const ENCRYPTION_NG: u32 = 0x0FEF_FFFF;

/// The encryption tag meaning the same AES-256 transform under the Rockstar
/// Games Launcher's own key: the tag names a key, not an algorithm, and the
/// transform is [`ENCRYPTION_AES`]'s byte for byte.
pub const ENCRYPTION_AES_LAUNCHER: u32 = 0x0FFF_FFF7;

/// The value a binary entry's own encryption field carries when its payload is
/// stored in the clear; 1 means it is under the archive's transform. A resource
/// entry has no such field, offsets 8 and 12 being its two flag words.
pub const ENTRY_OPEN: u32 = 0;

/// Which transform a tag names, and under which key, or `None` for a tag this
/// build cannot open. Two of the three arms are the same cipher under different
/// keys, which is why [`Scheme::Aes`] carries an [`AesKey`].
pub(super) const fn scheme(tag: u32) -> Option<Scheme> {
    match tag {
        ENCRYPTION_AES => Some(Scheme::Aes(AesKey::Rage)),
        ENCRYPTION_AES_LAUNCHER => Some(Scheme::Aes(AesKey::Launcher)),
        ENCRYPTION_NG => Some(Scheme::Ng),
        _ => None,
    }
}

/// Bit set within an entry's offset field marking the entry a resource.
pub const RESOURCE_FLAG: u32 = 0x0080_0000;

/// Largest value the 24-bit compressed-size field holds, and — on a resource —
/// the sentinel it writes when the payload is longer, whose extent the reader
/// then takes as the room to the next payload.
pub const MAX_SIZE_24: u64 = 0x00FF_FFFF;

/// Largest block index an entry's offset field holds, the resource bit excluded
/// — so the largest offset this version addresses is this times [`BLOCK_LEN`],
/// 4,294,966,784 bytes. It follows from the field's 23 usable bits.
const MAX_BLOCK: u64 = 0x007F_FFFF;

/// Largest name offset a **file** entry holds. Directories get a full word.
const MAX_FILE_NAME_OFFSET: u64 = 0x0000_FFFF;

/// Whether a payload of this length fits the row's compressed-size field. The
/// writer asks before it chooses to deflate.
pub(super) const fn holds_compressed_len(len: u64) -> bool {
    len <= MAX_SIZE_24
}

/// Whether a resource payload of this length leaves its row's compressed-size
/// field saying nothing about its extent: the one place that boundary is
/// decided, for the writer and the reader alike.
///
/// `>=` rather than `>`: a payload of exactly [`MAX_SIZE_24`] bytes writes the
/// same twenty-four bits as a longer one, so no reader can tell them apart.
pub(super) const fn size_field_saturates(len: u64) -> bool {
    len >= MAX_SIZE_24
}

/// The length a resource payload's transform is keyed by: the one place that
/// length is derived, for the writer and the reader alike.
///
/// While the row can state the payload's length it is the payload's own; once
/// the field saturates the reader can only recover the extent as the
/// block-aligned room to the next payload, so that is the keying length.
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
/// them. The magic is not read here: a caller reaches this only by having
/// matched it.
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
/// short. A row that decodes may still describe something impossible, which
/// the archive checks.
pub(super) fn decode_row(bytes: &[u8]) -> Option<Entry> {
    if bytes.len() < ROW_LEN {
        return None;
    }

    // A directory is identified by the second word alone; no file entry can
    // produce this value.
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
/// Every narrow field is checked here, where the narrowing happens. The one
/// exception is the format's: a resource whose compressed length reaches
/// [`MAX_SIZE_24`] writes that value as a saturation sentinel, while a binary
/// entry at the same value is refused.
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
    // A resource longer than the field holds writes `MAX_SIZE_24` and lets the
    // reader recover its extent from the room to the next payload; a binary
    // entry has no such spelling and is refused.
    let compressed_field = if resource && size_field_saturates(fields.compressed_len) {
        MAX_SIZE_24
    } else {
        check(path, "compressed size", fields.compressed_len, MAX_SIZE_24)?;
        fields.compressed_len
    };
    // Not `check`: a block offset past the end is the archive's size and not
    // this entry's.
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

/// Copies the low `width` bytes of a little-endian field into the row. A no-op
/// if the row is too short, which it cannot be: every call is inside
/// [`ROW_LEN`].
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
/// The blob is `namesLength` bytes and no more, never the backing buffer: the
/// bytes after it can be stale names from a previous pack. Distinct offsets are
/// visited in ascending order and share one cursor, so every terminator is
/// found in one pass rather than one scan per entry.
///
/// # Errors
///
/// [`Error::BadName`] for a name offset that is not a terminated string inside
/// the blob.
pub(super) fn resolve_names(blob: &[u8], entries: &[Entry]) -> Result<Vec<Span>> {
    let names_len = u32::try_from(blob.len()).unwrap_or(u32::MAX);
    // The offset is shared, so the first entry carrying it is reported.
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
        // decode.
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
        // Callers hand this the whole entry table rather than one row sliced
        // out of it, so a longer slice must not be refused as too short.
        let row = directory_row(0, 1, 4);
        let mut table = row.to_vec();
        table.extend_from_slice(&row);
        let entry = decode_row(&table).expect("bytes past the first row do not make it too short");
        assert!(entry.is_directory());
    }

    #[test]
    fn every_narrow_field_refuses_a_value_it_cannot_hold() {
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
        assert!(file_row("a.txt", &fields(0xFFFF, MAX_BLOCK, MAX_SIZE_24)).is_ok());
    }

    #[test]
    fn a_resource_past_the_size_field_writes_the_sentinel_where_a_binary_entry_is_refused() {
        // The same length in both variants, so the only thing that differs is
        // the kind.
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
        // which for this value would read back as zero — a stored entry.
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
        // The entry reported is whichever one the layout put first past the
        // ceiling, and the fact is the archive's size, so the failure is.
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
        // 8,388,607 blocks of 512 bytes: just under 4 GiB.
        assert_eq!(limit, 4_294_966_784);
        assert_eq!(reached, 4_294_967_296);
    }

    #[test]
    fn the_header_round_trips_through_its_own_bytes() {
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
        // names from a previous pack.
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
        assert!(matches!(
            resolve_names(b"abcde", &entries),
            Err(Error::BadName { .. })
        ));
    }
}
