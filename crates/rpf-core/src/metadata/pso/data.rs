//! Reading a value out of the `PSIN` section, bounds-checked against it.
//!
//! One owner for the reads both directions of the conversion make
//! (`docs/conventions.md` §3): [`super::render`] reads a value to write it as
//! XML, [`super::apply`] reads one to compare a document against it, and the
//! pointer decode below is a `verified` row of `docs/metadata-encodings.md`
//! that must be encoded exactly once.

use super::{
    bad,
    model::Malformed,
    schema::{Block, Blocks},
    section,
};
use crate::error::Result;

/// The low bits of a pointer's first dword: its 1-based block id.
///
/// `docs/metadata-encodings.md`, Pointers. Twelve bits is at most 4,095 blocks,
/// a limit the corpus never approaches.
const POINTER_BLOCK: u32 = 0xFFF;

/// How far the item offset sits above the block id.
const POINTER_OFFSET_SHIFT: u32 = 12;

/// The item offset's own width once shifted down: 20 bits, so at most 1 MiB per
/// block.
const POINTER_OFFSET: u32 = 0x000F_FFFF;

/// The block a pointer names, and where in the data section it lands.
pub(super) type Landing<'a> = Option<(&'a Block, u32)>;

/// The `PSIN` section and the block table that addresses it.
#[derive(Debug, Clone, Copy)]
pub(super) struct Data<'a> {
    /// The `PSIN` section, header included: block offsets are relative to it.
    pub(super) section: &'a [u8],
    /// The block table every pointer resolves through.
    pub(super) blocks: &'a Blocks,
}

impl<'a> Data<'a> {
    /// `len` bytes at `address`, checked against the data section.
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

    /// A pointer, as the block it names and the address it lands at.
    ///
    /// `docs/metadata-encodings.md`, Pointers: a pointer is **32 bits, in the
    /// first dword** — block id in the low 12, item offset in the next 20 — and
    /// the second word carries nothing. Read as one big-endian `u64` with the
    /// block id in the low bits, every pointer in the corpus reads null.
    ///
    /// A block id of 0 is null; anything else must resolve, and an offset at or
    /// past the block's length is refused rather than guessed at. 0 of
    /// 1,362,769 pointers in the corpus do either, which is what says
    /// `CodeWalker`'s `offset = offset >> 8` recovery is never needed.
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

    /// Where a pointer lands, without its block.
    pub(super) fn pointer(&self, address: u32) -> Result<Option<u32>> {
        Ok(self.block_pointer(address)?.map(|(_, landed)| landed))
    }
}

/// `bytes` up to its first NUL.
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
