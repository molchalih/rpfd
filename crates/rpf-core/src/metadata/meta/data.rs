//! The reads both directions of the conversion share.
//!
//! One owner for the pointer decode, the bounds-checked reads and the counted
//! form's arithmetic (`docs/conventions.md` §3), so the `verified` rows those
//! encode are encoded exactly once. Reading a value and writing one are
//! opposite operations sharing an itinerary — the relation `rbf`'s
//! `token::read` and `token::write` stand in — and this is what they genuinely
//! share.

use crate::{
    error::Result,
    metadata::hash::{Dictionary, placeholder},
};

use super::{
    Block, Malformed, Meta, RESERVED_PREFIX, bad,
    kind::{CAPACITY_AT, COUNT_AT},
    u16_at, u64_at,
};

/// A place inside a data block: the block, and how far into it.
///
/// Where a value is. A [`super::MetaPointer`] resolves to one and nothing else
/// does, which is what keeps the two pointer kinds apart at the type level.
#[derive(Debug, Clone, Copy)]
pub(super) struct Spot<'a> {
    /// The block the value is in.
    pub(super) block: Block<'a>,
    /// How far into it the value starts.
    pub(super) offset: u32,
}

impl<'a> Spot<'a> {
    /// Where this spot is in the payload, which is what a refusal reports and
    /// what an edit writes at.
    pub(super) fn address(self) -> u64 {
        self.block.address(self.offset)
    }

    /// This spot moved `by` bytes further into the same block.
    ///
    /// # Errors
    ///
    /// [`Malformed::DataRange`] when the sum does not fit an offset, which is
    /// checked here rather than at the read so that the failure names the
    /// arithmetic that produced it.
    pub(super) fn step(self, by: u32) -> Result<Self> {
        let offset = self
            .offset
            .checked_add(by)
            .ok_or_else(|| bad(self.address(), Malformed::DataRange))?;
        Ok(Self {
            block: self.block,
            offset,
        })
    }

    /// `len` bytes from here.
    ///
    /// # Errors
    ///
    /// [`Malformed::DataRange`] when they do not lie inside the block, which is
    /// §6's rule that every read is bounds-checked against the containing
    /// declaration — here the length the block's own row states.
    pub(super) fn bytes(self, len: u32) -> Result<&'a [u8]> {
        let gone = || bad(self.address(), Malformed::DataRange);
        let from = usize::try_from(self.offset).map_err(|_| gone())?;
        let end = from
            .checked_add(usize::try_from(len).map_err(|_| gone())?)
            .ok_or_else(gone)?;
        self.block.bytes().get(from..end).ok_or_else(gone)
    }

    /// The little-endian `u16` at `by` bytes from here.
    ///
    /// # Errors
    ///
    /// [`Malformed::DataRange`] when it does not fit the block.
    pub(super) fn half(self, by: u32) -> Result<u16> {
        let at = self.step(by)?;
        let bytes = at.bytes(2)?;
        u16_at(bytes, 0).ok_or_else(|| bad(at.address(), Malformed::DataRange))
    }
}

/// The document a walk reads from, and the two things every value needs of it.
#[derive(Debug, Clone, Copy)]
pub(super) struct Values<'a, 'b> {
    /// The parsed file.
    pub(super) meta: &'b Meta<'a>,
}

impl<'a> Values<'a, '_> {
    /// Where the pointer at `spot` lands, or `None` when it is null.
    ///
    /// The `Meta` pointer, and never the resource pointer the header's own
    /// fields carry: `docs/metadata-encodings.md`, Two pointer kinds.
    ///
    /// # Errors
    ///
    /// [`Malformed::DataRange`] when the pointer does not fit its block, and
    /// [`Malformed::Pointer`] when it names a block the table does not hold or
    /// an offset at or past that block's length.
    pub(super) fn pointer(self, spot: Spot<'a>) -> Result<Option<Spot<'a>>> {
        let gone = || bad(spot.address(), Malformed::DataRange);
        let word = u64_at(spot.bytes(8)?, 0).ok_or_else(gone)?;
        let pointer = super::MetaPointer::wide(word);
        let Some(landing) = self.meta.landing(pointer, spot.address())? else {
            return Ok(None);
        };
        let block = *self
            .meta
            .block(landing.block)
            .ok_or_else(|| bad(spot.address(), Malformed::Pointer))?;
        Ok(Some(Spot {
            block,
            offset: landing.offset,
        }))
    }

    /// A counted field: where its bytes are, and how many of them it owns.
    ///
    /// The store is `min(count1, count2)`, which is the bound `PSO` arrived at
    /// over 39,469 counted strings — the two counts swap roles, and the smaller
    /// is the one that never claims room the file has not spent. `secondary`
    /// for this encoding, and every read through it is bounds-checked against
    /// the block the pointer lands in.
    ///
    /// # Errors
    ///
    /// [`Malformed::Pointer`] for a null pointer that still declares a
    /// non-zero count, which is a file contradicting itself.
    pub(super) fn counted(self, spot: Spot<'a>) -> Result<(Option<Spot<'a>>, u32)> {
        let store = u32::from(spot.half(COUNT_AT)?.min(spot.half(CAPACITY_AT)?));
        match self.pointer(spot)? {
            Some(landing) => Ok((Some(landing), store)),
            None if store == 0 => Ok((None, 0)),
            None => Err(bad(spot.address(), Malformed::Pointer)),
        }
    }

    /// An array's items: where the first one is, and how many there are.
    ///
    /// `count1` alone, unlike [`Values::counted`]: for an array the second
    /// count is the capacity of the allocation and the first is how much of it
    /// is in use, which is the reading `PSO`'s `ATARRAY` uses over 59,811
    /// members. An array is never read past `count1` and never written past it
    /// either — its length is an allocation, and DR-052 refuses a document
    /// that changes one.
    ///
    /// # Errors
    ///
    /// [`Malformed::Pointer`] for a null pointer that still declares items.
    pub(super) fn items(self, spot: Spot<'a>) -> Result<(Option<Spot<'a>>, u32)> {
        let count = u32::from(spot.half(COUNT_AT)?);
        match self.pointer(spot)? {
            Some(landing) => Ok((Some(landing), count)),
            None if count == 0 => Ok((None, 0)),
            None => Err(bad(spot.address(), Malformed::Pointer)),
        }
    }
}

/// Everything up to the first NUL, or all of it.
pub(super) fn until_nul(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|byte| *byte == 0) {
        Some(at) => bytes.get(..at).unwrap_or(bytes),
        None => bytes,
    }
}

/// How a name hash is spelled in the document.
///
/// The dictionary, and one guard on top of it: a name beginning
/// [`RESERVED_PREFIX`] is rendered as its placeholder instead. `Dictionary::load`
/// refuses a name beginning `pso:` because that mapping's vocabulary would
/// otherwise be ambiguous, and this encoding's prefix is a different string, so
/// the guard is asked here rather than left to a check that does not cover it.
pub(super) fn spell(names: &Dictionary, hash: u32) -> String {
    let name = names.render(hash);
    if name.starts_with(RESERVED_PREFIX) {
        return placeholder(hash);
    }
    name
}
