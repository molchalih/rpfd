//! One row of the entry table.
//!
//! A directory, a binary file and a resource file are separate variants because
//! the last two words of the row mean different things in each (§5). A single
//! struct with an `uncompressed_len` that is secretly two flag words is a bug
//! waiting for its first resource.

use crate::format::{DIRECTORY_MARKER, ENTRY_LEN, RESOURCE_FLAG};

/// Reads a little-endian `u16` at `off`, or `None` if it does not fit.
fn u16_at(bytes: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let raw: [u8; 2] = bytes.get(off..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(raw))
}

/// Reads a little-endian `u32` at `off`, or `None` if it does not fit.
fn u32_at(bytes: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let raw: [u8; 4] = bytes.get(off..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

/// Reads a little-endian 24-bit field at `off`, widened, or `None` if it does
/// not fit.
fn u24_at(bytes: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(3)?;
    let raw = bytes.get(off..end)?;
    let (low, mid, high) = (*raw.first()?, *raw.get(1)?, *raw.get(2)?);
    Some(u32::from(low) | (u32::from(mid) << 8) | (u32::from(high) << 16))
}

/// What an entry is, and the fields that only that kind has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A directory. Its children are a contiguous run of the entry table.
    Directory {
        /// Index of the first child entry.
        first_child: u32,
        /// How many children follow it.
        child_count: u32,
    },
    /// A file whose payload is plain bytes, deflated unless stored.
    Binary {
        /// Payload offset, in blocks, from the archive's own base.
        block: u32,
        /// On-disk size. Zero means stored rather than deflated, and then
        /// `uncompressed_len` is the real length.
        compressed_len: u32,
        /// Length the payload inflates to.
        uncompressed_len: u32,
        /// Per-entry encryption field. Zero on every entry measured so far;
        /// its range is Q10 in `docs/backlog.md`.
        encryption: u32,
    },
    /// A file whose payload is an `RSC7` resource.
    ///
    /// Carries no uncompressed length: both trailing words are flags, and the
    /// length comes from [`crate::format::resource_len`].
    Resource {
        /// Payload offset, in blocks, from the archive's own base.
        block: u32,
        /// On-disk size, **including** the 16-byte `RSC7` header.
        compressed_len: u32,
        /// System page flags.
        system_flags: u32,
        /// Graphics page flags.
        graphics_flags: u32,
    },
}

impl EntryKind {
    /// A word for this kind, for error messages.
    #[must_use]
    pub const fn noun(self) -> &'static str {
        match self {
            Self::Directory { .. } => "directory",
            Self::Binary { .. } => "binary file",
            Self::Resource { .. } => "resource file",
        }
    }
}

/// One row of the entry table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// Offset of this entry's name within the names blob.
    pub name_offset: u32,
    /// What the entry is.
    pub kind: EntryKind,
}

impl Entry {
    /// Parses one entry from exactly [`ENTRY_LEN`] bytes.
    ///
    /// Returns `None` when the slice is too short. Every field is a fixed-width
    /// integer, so there is nothing else here that can fail — a row that parses
    /// may still describe something impossible, which the archive checks.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if u64::try_from(bytes.len()).ok()? < ENTRY_LEN {
            return None;
        }

        // A directory is identified by the second word alone. No file entry can
        // produce this value. docs/rpf-format.md, Entry table.
        if u32_at(bytes, 4)? == DIRECTORY_MARKER {
            return Some(Self {
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

        Some(Self { name_offset, kind })
    }

    /// Whether this entry is a directory.
    #[must_use]
    pub const fn is_directory(&self) -> bool {
        matches!(self.kind, EntryKind::Directory { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_sample_root_directory() {
        // Entry 0 of dlc.rpf: name offset 0, four children starting at 1.
        let mut row = [0u8; 16];
        row[4..8].copy_from_slice(&DIRECTORY_MARKER.to_le_bytes());
        row[8..12].copy_from_slice(&1u32.to_le_bytes());
        row[12..16].copy_from_slice(&4u32.to_le_bytes());

        let entry = Entry::parse(&row).expect("16 bytes is enough");
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
    fn parses_a_binary_entry_as_measured() {
        // dlc.rpf /data/vehicles.meta: 1,631 compressed at block 4, 5,100 out.
        let mut row = [0u8; 16];
        row[0..2].copy_from_slice(&37u16.to_le_bytes());
        row[2..5].copy_from_slice(&1631u32.to_le_bytes()[..3]);
        row[5..8].copy_from_slice(&4u32.to_le_bytes()[..3]);
        row[8..12].copy_from_slice(&5100u32.to_le_bytes());

        let entry = Entry::parse(&row).expect("16 bytes is enough");
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
        const BLOCK: u32 = 0x0001_825C; // 98,908
        let mut row = [0u8; 16];
        row[2..5].copy_from_slice(&802_444u32.to_le_bytes()[..3]);
        row[5..8].copy_from_slice(&(BLOCK | RESOURCE_FLAG).to_le_bytes()[..3]);
        row[8..12].copy_from_slice(&0x0002_0000u32.to_le_bytes());
        row[12..16].copy_from_slice(&0xD102_0008u32.to_le_bytes());

        let entry = Entry::parse(&row).expect("16 bytes is enough");
        assert_eq!(
            entry.kind,
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
        assert!(Entry::parse(&[0u8; 15]).is_none());
        assert!(Entry::parse(&[]).is_none());
    }
}
