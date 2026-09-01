//! The RPF7 header and entry-row layout, hand-encoded once for the tests that
//! assemble an archive byte by byte. No width is restated here; every one is
//! asked of the version seam.
#![allow(
    dead_code,
    reason = "each including test crate gets its own copy of this module and \
              uses the part of the layout it needs"
)]
#![allow(
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "test scaffolding writing fixed-width rows into buffers it just \
              created. docs/conventions.md §15"
)]

use rpf_core::format::{
    Version,
    rpf7::{DIRECTORY_MARKER, ENCRYPTION_OPEN, MAGIC, ROW_LEN},
};

/// The version every archive assembled here is written at.
pub const V: Version = Version::Rpf7;
/// Its header length, entry-row width and block unit.
pub const HEADER_LEN: u64 = V.header_len();
pub const ENTRY_LEN: u64 = V.row_len();
pub const BLOCK_LEN: u64 = V.block_len();

/// One directory row: name offset, the marker, first child, child count.
pub fn directory_row(name_offset: u32, first_child: u32, child_count: u32) -> [u8; ROW_LEN] {
    let mut row = [0u8; ROW_LEN];
    row[0..4].copy_from_slice(&name_offset.to_le_bytes());
    row[4..8].copy_from_slice(&DIRECTORY_MARKER.to_le_bytes());
    row[8..12].copy_from_slice(&first_child.to_le_bytes());
    row[12..16].copy_from_slice(&child_count.to_le_bytes());
    row
}

/// One file row: a 16-bit name offset, a 24-bit compressed size, a 24-bit
/// block offset carrying the resource bit, and the two words whose meaning
/// depends on that bit.
pub fn file_row(
    name_offset: u16,
    compressed_len: u32,
    block: u32,
    word8: u32,
    word12: u32,
) -> [u8; ROW_LEN] {
    let mut row = [0u8; ROW_LEN];
    row[0..2].copy_from_slice(&name_offset.to_le_bytes());
    row[2..5].copy_from_slice(&compressed_len.to_le_bytes()[..3]);
    row[5..8].copy_from_slice(&block.to_le_bytes()[..3]);
    row[8..12].copy_from_slice(&word8.to_le_bytes());
    row[12..16].copy_from_slice(&word12.to_le_bytes());
    row
}

/// [`file_row`] for a stored binary file: compressed size 0 is the stored
/// sentinel, and the real length is the word at offset 8.
pub fn stored_row(name_offset: u16, block: u32, len: u32) -> [u8; ROW_LEN] {
    file_row(name_offset, 0, block, len, 0)
}

/// Header, entry table, names blob, then zeroes out to `len`.
pub fn archive_bytes(rows: &[[u8; ROW_LEN]], names: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&(rows.len() as u32).to_le_bytes());
    out.extend_from_slice(&(names.len() as u32).to_le_bytes());
    out.extend_from_slice(&ENCRYPTION_OPEN.to_le_bytes());
    for row in rows {
        out.extend_from_slice(row);
    }
    out.extend_from_slice(names);
    if out.len() < len {
        out.resize(len, 0);
    }
    out
}
