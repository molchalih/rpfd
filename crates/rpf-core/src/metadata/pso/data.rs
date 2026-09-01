//! Reading a value out of the `PSIN` section, bounds-checked against it.

use super::{
    bad,
    model::Malformed,
    schema::{Block, Blocks},
    section,
};
use crate::error::Result;

/// The low bits of a pointer's first dword: its 1-based block id, twelve bits.
const POINTER_BLOCK: u32 = 0xFFF;

/// How far the item offset sits above the block id.
const POINTER_OFFSET_SHIFT: u32 = 12;

/// The item offset's own width once shifted down: 20 bits.
const POINTER_OFFSET: u32 = 0x000F_FFFF;

/// The block a pointer names, and where in the data section it lands.
pub(super) type Landing<'a> = Option<(&'a Block, u32)>;

#[derive(Debug, Clone, Copy)]
pub(super) struct Data<'a> {
    pub(super) section: &'a [u8],
    pub(super) blocks: &'a Blocks,
}

impl<'a> Data<'a> {
    pub(super) fn bytes(&self, address: u32, len: u32) -> Result<&'a [u8]> {
        let gone = || bad(u64::from(address), Malformed::DataRange);
        let at = usize::try_from(address).map_err(|_| gone())?;
        let len = usize::try_from(len).map_err(|_| gone())?;
        let end = at.checked_add(len).ok_or_else(gone)?;
        self.section.get(at..end).ok_or_else(gone)
    }

    /// The NUL-terminated bytes at `address`, terminator excluded.
    pub(super) fn terminated(&self, address: u32) -> Result<&'a [u8]> {
        let gone = || bad(u64::from(address), Malformed::DataRange);
        let at = usize::try_from(address).map_err(|_| gone())?;
        Ok(until_nul(self.section.get(at..).ok_or_else(gone)?))
    }

    /// The big-endian `u32` at `address`.
    pub(super) fn word(&self, address: u32) -> Result<u32> {
        section::u32(self.bytes(address, 4)?, 0)
            .ok_or_else(|| bad(u64::from(address), Malformed::DataRange))
    }

    /// The big-endian `u16` at `address`.
    pub(super) fn half(&self, address: u32) -> Result<u16> {
        section::u16(self.bytes(address, 2)?, 0)
            .ok_or_else(|| bad(u64::from(address), Malformed::DataRange))
    }

    /// A pointer, as the block it names and the address it lands at; block id 0 is null.
    pub(super) fn block_pointer(&self, address: u32) -> Result<Landing<'a>> {
        let word = self.word(address)?;
        let id = word & POINTER_BLOCK;
        if id == 0 {
            return Ok(None);
        }
        let bad_pointer = || bad(u64::from(address), Malformed::Pointer);
        let offset = (word >> POINTER_OFFSET_SHIFT) & POINTER_OFFSET;
        let block = self.blocks.get(id).ok_or_else(bad_pointer)?;
        if offset >= block.length {
            return Err(bad_pointer());
        }
        let landed = block.offset.checked_add(offset).ok_or_else(bad_pointer)?;
        Ok(Some((block, landed)))
    }

    pub(super) fn pointer(&self, address: u32) -> Result<Option<u32>> {
        Ok(self.block_pointer(address)?.map(|(_, landed)| landed))
    }
}

pub(super) fn until_nul(bytes: &[u8]) -> &[u8] {
    bytes
        .iter()
        .position(|byte| *byte == 0)
        .and_then(|end| bytes.get(..end))
        .unwrap_or(bytes)
}

/// `base + index * stride`, or `None` when it does not fit a `u32`.
pub(super) fn step(base: u32, index: u32, stride: u32) -> Option<u32> {
    base.checked_add(index.checked_mul(stride)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_block(section_len: u32) -> Blocks {
        let mut table = Vec::from(*b"PMAP");
        table.extend_from_slice(&0u32.to_be_bytes()); // section length, unread here
        table.extend_from_slice(&1i32.to_be_bytes()); // rootId
        table.extend_from_slice(&1i16.to_be_bytes()); // entriesCount
        table.extend_from_slice(&[0u8; 2]); // pad to the entries' offset
        table.extend_from_slice(&0u32.to_be_bytes()); // nameHash
        table.extend_from_slice(&0i32.to_be_bytes()); // offset
        table.extend_from_slice(&0i32.to_be_bytes()); // unknown_8h
        let length = i32::try_from(section_len).expect("a test length fits");
        table.extend_from_slice(&length.to_be_bytes());
        Blocks::read(&table, section_len).expect("a well-formed one-block table")
    }

    #[test]
    fn terminated_stops_at_the_nul_and_leaves_it_out() {
        let section = *b"hello\0world";
        let blocks = one_block(u32::try_from(section.len()).expect("a test length fits"));
        let data = Data {
            section: &section,
            blocks: &blocks,
        };
        assert_eq!(data.terminated(0).expect("in range"), b"hello");
    }

    #[test]
    fn terminated_refuses_an_address_past_the_section() {
        let section = *b"hello\0";
        let len = u32::try_from(section.len()).expect("a test length fits");
        let blocks = one_block(len);
        let data = Data {
            section: &section,
            blocks: &blocks,
        };
        assert!(data.terminated(len + 1).is_err());
    }
}
