//! Resource-embedded `Meta` — the header, the three info tables, and the two
//! pointer kinds a file addresses itself with.
//!
//! `docs/metadata-encodings.md`, Resource-embedded `Meta`, `verified` against
//! all **49,614** files both GTA V builds ship. Little-endian, unlike `PSO`;
//! no checksum, no encrypted section, no `PSIG`. One measurement shapes the
//! module exactly as it shapes [`super::pso`]: every file was walked from its
//! root using **only its own tables** and reached **0** references it did not
//! define, over 88,171,116 nodes. So nothing here consults a builtin table and
//! there is none to consult.
//!
//! # Two pointer kinds, and the type system keeps them apart
//!
//! [`ResourcePointer`] addresses the file: the header's own fields and the
//! three info tables. [`MetaPointer`] addresses data: everything inside a data
//! block. They decode differently — `space = p >> 28` and
//! `offset = p & 0x0FFFFFFF` against `blockId = p & 0xFFF` and
//! `itemOffset = p >> 12` — and a value that is one is never the other. They
//! are therefore two types with no conversion between them and no shared
//! trait: `Pages` resolves the first and nothing else, [`Meta::landing`]
//! resolves the second and nothing else, and neither will accept the other's
//! value. Conflating them is what
//! `a_data_pointer_is_not_read_the_way_a_table_pointer_is` exists to catch.
//!
//! # What the payload is, and what `system_len` is
//!
//! A `Meta` payload is a *paged* resource, inflated: its system pages, then
//! its graphics pages. A resource pointer's space nibble says which of the two
//! it addresses and its offset is flat within that space, so resolving one
//! needs the boundary between them — which is a fact about the entry
//! (`crate::format::resource::size_from_flags` of its system flags) and not
//! about the payload. It reaches [`parse`] as a byte count and nothing else:
//! this layer still takes bytes, never seeks, never opens a file and never
//! learns that archives exist (`docs/conventions.md` §2).
//!
//! # The seam
//!
//! [`to_xml`] and [`from_xml`], bytes in and bytes out, exactly as `rbf`'s pair
//! and `pso`'s are. Two arguments neither of those two needs, and each is a
//! fact about this encoding rather than a widening of the seam:
//!
//! - **`system_len`**, because a `Meta` payload is a *paged* resource and a
//!   resource pointer's offset is flat within the space its nibble names. The
//!   boundary is a fact about the entry (`crate::format::resource::size_from_flags`
//!   of its system flags) and appears nowhere in the payload, so a caller that
//!   has the bytes has it too and nothing here can derive it.
//! - **the payload, in the write direction**, because a document cannot carry
//!   the file: page slack, inter-table padding, the 7.26% of a payload after
//!   the last data block, and **2.48% that no walk reaches and that is not
//!   zero**. DR-049, whose argument for `PSO`'s 2.86% is this one exactly. So
//!   [`from_xml`] **edits** the payload the document came from, writing each
//!   value at the address [`to_xml`] read it from and moving nothing
//!   structural.
//!
//! A [`Dictionary`] decides how the hashes render, and is cosmetic by
//! construction: 412 distinct member names and 73 structure hashes across the
//! whole corpus, and an empty dictionary spells every one `hash_XXXXXXXX`.
//!
//! # What is measured here and what is not
//!
//! [`parse`] — the header, the three tables and both pointer kinds — is
//! `verified` against all 49,614 files. **The value walk is not.** The type
//! table `kind` carries is `secondary`: `docs/metadata-encodings.md` counted
//! 23 distinct type codes and does not enumerate them, so the codes are the
//! reference implementation's, read as specification under `AGENTS.md`'s
//! authority order. `kind` says what bounds a wrong row, and
//! `every_shipped_meta_file_round_trips_byte_for_byte` in
//! `crates/rpf-core/tests/metadata.rs` is the measurement that would settle it
//! — **it has never been run against the corpus**, because no dump of the
//! 49,614 payloads has been within reach of this code.
//!
//! # What bounds it
//!
//! What [`parse`] allocates is the three tables, and each of them is bounded by
//! the payload itself: a table of `n` records is refused unless its whole
//! extent lies inside the space its pointer names, so `n` can never exceed the
//! payload's own length divided by the record's. Members and enum entries are
//! not collected at all — they are read from the payload on demand, through a
//! slice whose extent [`parse`] has already checked — so a file declaring
//! 65,535 structures of 65,535 members costs one refusal rather than 4 × 10⁹
//! records. The walk carries its own three ceilings, which `kind` owns: a
//! depth, a node budget and an output budget proportional to the payload.

mod apply;
mod data;
mod kind;
mod render;

use std::collections::BTreeMap;

pub use kind::{NotMetaXml, Unsupported};

use crate::{
    error::{Error, Result},
    metadata::hash::Dictionary,
};

/// The reserved XML name prefix this mapping's vocabulary lives under.
///
/// A prefix and deliberately **not** an XML namespace, for the reason DR-043
/// gives for `RBF` and DR-047 carries into `PSO`: an element's name comes from
/// a dictionary the user supplied, so namespace well-formedness is not this
/// layer's to promise. Each encoding owns its own, because the prefixes differ;
/// `data::spell` is the guard that keeps a dictionary name out of it.
pub const RESERVED_PREFIX: &str = "meta:";

/// Reads a resource `Meta` payload and writes the XML that describes it.
///
/// `payload` is the **inflated** payload of a resource entry and `system_len`
/// how many of its bytes are system pages — see [`parse`], which this is the
/// walk over.
///
/// # Errors
///
/// [`Error::BadMeta`] if the file contradicts itself — a pointer outside its
/// block, a member outside its structure, a walk deeper or larger than the
/// ceilings allow — and [`Error::UnsupportedMeta`] if it is well formed and
/// carries a member type code outside the 23 this build names.
pub fn to_xml(payload: &[u8], system_len: usize, names: &Dictionary) -> Result<Vec<u8>> {
    render::write(payload, system_len, names)
}

/// Reads the XML [`to_xml`] wrote and applies it to the payload it came from.
///
/// **Four arguments, and none of them will go away.** `payload` is the file
/// being edited, because 2.48% of it is unreached and nonzero and no document
/// can carry it (DR-049); `system_len` is the page boundary, which is a fact
/// about the entry and not about these bytes; `document` is the edit; `names`
/// spells the hashes, exactly as it does in the read direction.
///
/// The walk is [`to_xml`]'s, run backwards: every value the document carries is
/// written at the address [`to_xml`] read it from, under the same bound — the
/// block that holds it — and nothing structural moves. An edit that changes the
/// **shape** — an array's length, a structure's member list, a value past the
/// store its form gave it — is refused rather than guessed at. DR-052: editing
/// is value-level and stays that way. So is an edit that two elements of the
/// document disagree over, which a file pointing at one value twice makes
/// possible: DR-059.
///
/// # Errors
///
/// [`Error::BadMeta`] and [`Error::UnsupportedMeta`] for the payload, exactly
/// as [`to_xml`] answers them, and [`Error::NotMetaXml`] when the document is
/// not XML or does not describe this payload.
pub fn from_xml(
    payload: &[u8],
    system_len: usize,
    document: &[u8],
    names: &Dictionary,
) -> Result<Vec<u8>> {
    apply::write(payload, system_len, document, names)
}

/// The word at [`MAGIC_AT`] of an inflated resource `Meta` payload.
///
/// `docs/rpf-format.md`, Metadata encodings, and
/// `docs/metadata-encodings.md`, Recognition: `0x50524430` little-endian in
/// **49,614 of 49,614**, and no `.ynv` or `.ytd` of the same resource version
/// carries it — 0 of 21,135.
///
/// It is a metadata-layer test and never a container sniff: the word sits at
/// offset `0x10` of a *paged, inflated* payload, which the container has by
/// then already handed over. What names a resource is the entry's own row (Q7,
/// DR-044), which is why [`super::Encoding`] has no variant for this and
/// [`identifies`] is here instead.
pub const MAGIC: u32 = 0x5052_4430;

/// Where [`MAGIC`] sits in the payload.
pub const MAGIC_AT: usize = 0x10;

/// How long the header is, and the shortest payload that can be one.
pub const HEADER_LEN: usize = 0x50;

/// How long one `StructureInfo` record is.
///
/// `docs/metadata-encodings.md`, The three tables: `nameHash`, `nameHash2`, a
/// `u32` that is `0x300` or `0x400`, a `u32` that is 0, `membersPtr`,
/// `structLength`, a `u16` that is 0 in all 318,286, and `memberCount`.
const STRUCTURE_LEN: usize = 32;

/// How long one structure member is.
///
/// `docs/metadata-encodings.md`: `nameHash:u32, dataOffset:u32, type:u8,
/// subtype:u8, arrayInfoIndex:u16, referenceKey:u32`. **`dataOffset` is a
/// `u32` at offset 4**, not a `u16` late in the record — `PSO`'s twelve-byte
/// member is not this one, and reading it as such shifts every field.
const MEMBER_LEN: usize = 16;

/// How long one `EnumInfo` record is: `nameHash`, `unk`, `entriesPtr`,
/// `count`, `pad`.
const ENUM_LEN: usize = 24;

/// How long one enum entry is: `nameHash` and `value`.
const ENUM_ENTRY_LEN: usize = 8;

/// How long one data-block row is: `tag`, `length`, `ptr`.
const BLOCK_LEN: usize = 16;

/// The version word of a version-2 file, at `0x14`.
///
/// `docs/metadata-encodings.md`: 49,608 of 49,614.
pub const VERSION_TWO: u32 = 0x0001_0079;

/// The version word of a version-3 file.
///
/// The six `.ymt` whose word at `0x14` is `0x79` rather than `0x00010079`.
pub const VERSION_THREE: u32 = 0x0000_0079;

/// How far a resource pointer's space nibble sits above its offset.
const SPACE_SHIFT: u32 = 28;

/// A resource pointer's offset, once its space is taken off.
const RESOURCE_OFFSET: u32 = 0x0FFF_FFFF;

/// The space nibble of a pointer into the system pages.
const SYSTEM_SPACE: u32 = 5;

/// The space nibble of a pointer into the graphics pages.
const GRAPHICS_SPACE: u32 = 6;

/// The low bits of a `Meta` pointer: its 1-based block id.
///
/// `docs/metadata-encodings.md`: `PSO`'s pointer widened to 64 bits. The
/// decisive case for the twelve-bit boundary is `hei_ch3_06.ymap`, whose
/// entity pointer array reads `0x3, 0x80003, 0x100003, …` — block 3 at offsets
/// 0, 128 and 256, filling all 16,384 bytes of each block, which a sixteen-bit
/// split decodes to offsets of 8 addressing only the first 1,016 bytes.
const BLOCK_MASK: u64 = 0xFFF;

/// How far a `Meta` pointer's item offset sits above its block id.
const ITEM_SHIFT: u32 = 12;

/// Whether these bytes are a resource `Meta` payload.
///
/// The whole test, and the only one: the word at [`MAGIC_AT`] is [`MAGIC`].
/// `payload` is the *inflated* payload of a resource entry, so a caller that
/// has not inflated one has not yet asked a question this can answer.
#[must_use]
pub fn identifies(payload: &[u8]) -> bool {
    u32_at(payload, MAGIC_AT) == Some(MAGIC)
}

/// Which of a resource's two page spaces a [`ResourcePointer`] addresses.
///
/// `docs/metadata-encodings.md`, Two pointer kinds: 837,780 system and 176,598
/// graphics over 49,614 files, and **0 in any other space**.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Space {
    /// The system pages, which come first in the inflated payload.
    System,
    /// The graphics pages, which follow them.
    Graphics,
}

/// A pointer into the resource's pages: the header's fields and the three info
/// tables.
///
/// **Not interchangeable with [`MetaPointer`]**, which is the whole reason
/// both are types rather than integers. This one is resolved by this module's
/// `Pages` and by nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResourcePointer(u32);

impl ResourcePointer {
    /// The pointer this 64-bit field holds, or `None` when its high half is
    /// set.
    ///
    /// A resource pointer occupies eight bytes and carries thirty-two: the
    /// space nibble is at bit 28, and every one of the 1,014,378 pointers in
    /// the corpus resolves under that reading. A value with anything above bit
    /// 31 is not one, and is refused rather than truncated (§6).
    #[must_use]
    pub fn wide(word: u64) -> Option<Self> {
        match u32::try_from(word) {
            Ok(narrow) => Some(Self(narrow)),
            Err(_) => None,
        }
    }

    /// Whether this pointer is null.
    #[must_use]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    /// The space it addresses, or `None` when its nibble names neither.
    #[must_use]
    pub const fn space(self) -> Option<Space> {
        match self.0 >> SPACE_SHIFT {
            SYSTEM_SPACE => Some(Space::System),
            GRAPHICS_SPACE => Some(Space::Graphics),
            _ => None,
        }
    }

    /// Its offset within that space, flat over the pages the space holds.
    #[must_use]
    pub const fn offset(self) -> u32 {
        self.0 & RESOURCE_OFFSET
    }

    /// The word it was read from.
    #[must_use]
    pub const fn word(self) -> u32 {
        self.0
    }
}

/// A pointer inside a data block: `PSO`'s pointer widened to 64 bits.
///
/// **Not interchangeable with [`ResourcePointer`]**. This one is resolved by
/// [`Meta::landing`] and by nothing else. Corpus maxima: block id 401, item
/// offset 16,380.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MetaPointer(u64);

impl MetaPointer {
    /// The pointer this 64-bit field holds.
    #[must_use]
    pub const fn wide(word: u64) -> Self {
        Self(word)
    }

    /// Whether this pointer is null, which is a block id of 0.
    #[must_use]
    pub fn is_null(self) -> bool {
        self.block().is_none()
    }

    /// The 1-based block it names, or `None` when it is null.
    #[must_use]
    pub fn block(self) -> Option<BlockId> {
        BlockId::new(self.0 & BLOCK_MASK)
    }

    /// Its offset within that block.
    #[must_use]
    pub const fn item_offset(self) -> u64 {
        self.0 >> ITEM_SHIFT
    }

    /// The word it was read from.
    #[must_use]
    pub const fn word(self) -> u64 {
        self.0
    }
}

/// A 1-based data-block id, which is what a [`MetaPointer`] names and what the
/// header's root field holds.
///
/// It cannot be zero, because its constructor says so (§5): zero is the null
/// pointer and never a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockId(u16);

impl BlockId {
    /// This id, or `None` when it is 0 or wider than a block id can be.
    #[must_use]
    pub fn new(id: u64) -> Option<Self> {
        if id == 0 || id > BLOCK_MASK {
            return None;
        }
        match u16::try_from(id) {
            Ok(narrow) => Some(Self(narrow)),
            Err(_) => None,
        }
    }

    /// Its 1-based value.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Its 0-based index into the block table.
    #[must_use]
    const fn index(self) -> usize {
        (self.0 as usize).saturating_sub(1)
    }
}

/// The inflated payload, read as its system pages and then its graphics pages.
///
/// The two spaces are separate: a system pointer never reaches a graphics byte
/// and neither reaches past the payload. `docs/metadata-encodings.md`: the page
/// split *within* a space is an allocation detail — 24,572 files span more than
/// one system page, up to 124, and every one parses under the flat model.
#[derive(Debug, Clone, Copy)]
struct Pages<'a> {
    /// The system pages, flat.
    system: &'a [u8],
    /// The graphics pages, flat.
    graphics: &'a [u8],
}

impl<'a> Pages<'a> {
    /// The payload split at `system_len`.
    ///
    /// # Errors
    ///
    /// [`Malformed::Pages`] when `system_len` is longer than the payload, which
    /// is a caller that has read the entry's flag words wrong rather than a
    /// payload that is malformed.
    fn split(payload: &'a [u8], system_len: usize) -> Result<Self> {
        let (system, graphics) = payload
            .split_at_checked(system_len)
            .ok_or_else(|| bad(0, Malformed::Pages))?;
        Ok(Self { system, graphics })
    }

    /// The space this pointer addresses, and where that space begins in the
    /// payload.
    fn space(self, pointer: ResourcePointer, at: u64) -> Result<(&'a [u8], usize)> {
        match pointer.space() {
            Some(Space::System) => Ok((self.system, 0)),
            Some(Space::Graphics) => Ok((self.graphics, self.system.len())),
            None => Err(bad(at, Malformed::Space)),
        }
    }

    /// `len` bytes at `pointer`, and where they begin in the payload.
    ///
    /// `at` is where the pointer was read from, and is what a refusal reports.
    ///
    /// # Errors
    ///
    /// [`Malformed::Space`] for a pointer that names neither space, and
    /// [`Malformed::OutOfRange`] when the extent does not lie inside the one it
    /// names.
    fn bytes(self, pointer: ResourcePointer, len: usize, at: u64) -> Result<(&'a [u8], usize)> {
        let gone = || bad(at, Malformed::OutOfRange);
        let (space, base) = self.space(pointer, at)?;
        let from = usize::try_from(pointer.offset()).map_err(|_| gone())?;
        let end = from.checked_add(len).ok_or_else(gone)?;
        let bytes = space.get(from..end).ok_or_else(gone)?;
        Ok((bytes, base.checked_add(from).ok_or_else(gone)?))
    }

    /// Checks that this pointer lands inside the space it names, without an
    /// extent.
    ///
    /// What the header's two unnamed pointers get: `docs/metadata-encodings.md`
    /// measured 0 of 1,014,378 pointers out of range, and nothing says how many
    /// bytes either of them owns.
    fn lands(self, pointer: ResourcePointer, at: u64) -> Result<()> {
        self.bytes(pointer, 0, at).map(|_| ())
    }
}

/// The fixed [`HEADER_LEN`] bytes a `Meta` payload opens with.
///
/// `docs/metadata-encodings.md`, The header. Every field is read; the ones the
/// document names only by their offsets are carried rather than checked,
/// because nothing says what they mean.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    /// The virtual function table pointer at `0x00`, which a shipped file
    /// carries and nothing here interprets.
    pub vft: u32,
    /// The word at `0x04`, 1 in the files the document lists.
    pub kind: u32,
    /// The pages-info pointer at `0x08`.
    pub pages_info: ResourcePointer,
    /// The version word at `0x14`: [`VERSION_TWO`] or [`VERSION_THREE`].
    pub version: u32,
    /// The 1-based root data block, at `0x1C`.
    pub root: BlockId,
    /// The structure table, at `0x20`.
    pub structures: ResourcePointer,
    /// The enum table, at `0x28`.
    pub enums: ResourcePointer,
    /// The data-block table, at `0x30`.
    pub blocks: ResourcePointer,
    /// The `u64` at `0x38` — 0 on 48,714 files and a resource pointer on the
    /// rest, whose target nothing has measured.
    pub unknown_38: u64,
    /// The pointer at `0x40`, whose target nothing has measured.
    pub unknown_40: ResourcePointer,
    /// How many structures the structure table holds.
    pub structure_count: u16,
    /// How many enums the enum table holds.
    pub enum_count: u16,
    /// How many blocks the block table holds.
    pub block_count: u16,
}

impl Header {
    /// Reads the header, and nothing that a pointer in it names.
    ///
    /// This is the part of a `Meta` file that needs no page split, which is
    /// what makes it the part a payload dumped without its entry's flag words
    /// can still be checked against.
    ///
    /// # Errors
    ///
    /// [`Malformed::Header`] when the payload is shorter than
    /// [`HEADER_LEN`], [`Malformed::NotMeta`] when the word at [`MAGIC_AT`] is
    /// not [`MAGIC`], [`Malformed::Version`] for a version word that is
    /// neither of the two that occur, [`Malformed::PointerWidth`] for a
    /// pointer field whose high half is set, and [`Malformed::RootBlock`] when
    /// the root field is not a block id.
    pub fn read(payload: &[u8]) -> Result<Self> {
        let head = payload
            .get(..HEADER_LEN)
            .ok_or_else(|| bad(0, Malformed::Header))?;
        let word = |at: usize| -> Result<u32> {
            u32_at(head, at).ok_or_else(|| bad(address(at), Malformed::Header))
        };
        let wide = |at: usize| -> Result<u64> {
            u64_at(head, at).ok_or_else(|| bad(address(at), Malformed::Header))
        };
        let pointer = |at: usize| -> Result<ResourcePointer> {
            ResourcePointer::wide(wide(at)?)
                .ok_or_else(|| bad(address(at), Malformed::PointerWidth))
        };
        let half = |at: usize| -> Result<u16> {
            u16_at(head, at).ok_or_else(|| bad(address(at), Malformed::Header))
        };

        if word(MAGIC_AT)? != MAGIC {
            return Err(bad(address(MAGIC_AT), Malformed::NotMeta));
        }
        let version = word(0x14)?;
        if version != VERSION_TWO && version != VERSION_THREE {
            return Err(bad(0x14, Malformed::Version));
        }
        let root =
            BlockId::new(u64::from(word(0x1C)?)).ok_or_else(|| bad(0x1C, Malformed::RootBlock))?;
        Ok(Self {
            vft: word(0x00)?,
            kind: word(0x04)?,
            pages_info: pointer(0x08)?,
            version,
            root,
            structures: pointer(0x20)?,
            enums: pointer(0x28)?,
            blocks: pointer(0x30)?,
            unknown_38: wide(0x38)?,
            unknown_40: pointer(0x40)?,
            structure_count: half(0x48)?,
            enum_count: half(0x4A)?,
            block_count: half(0x4C)?,
        })
    }
}

/// A member's type code, as the file carries it.
///
/// **No meaning is attached to it here.** `docs/metadata-encodings.md` records
/// that 23 distinct codes occur over 3,891,369 members and does not say which,
/// so a decoder that named them would be guessing; a caller gets the byte and
/// this build refuses no value of it. What is settled is where the byte is —
/// offset 8 of a sixteen-byte member — and that is what this type carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeCode(u8);

impl TypeCode {
    /// This code, as the file carries it.
    ///
    /// The one way to make one, so that a code always comes from a byte
    /// somewhere rather than from a number a caller invented.
    #[must_use]
    pub const fn new(code: u8) -> Self {
        Self(code)
    }

    /// The byte the file carries.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// One member of a structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member {
    /// Its name, a `joaat` hash. 412 distinct names across the whole corpus.
    pub name: u32,
    /// Its byte offset within the structure. A `u32` at offset 4 of the
    /// record.
    pub data_offset: u32,
    /// Its type code.
    pub type_code: TypeCode,
    /// Its subtype: 0 on 3,811,021 members, `0x04` on 79,318, `0x24` on 1,030.
    pub subtype: u8,
    /// The index of the member describing this one's elements, for the array
    /// forms.
    pub array_info_index: u16,
    /// The structure or enum this member refers to, or 0 — which is the "no
    /// enum info" sentinel, the analogue of `PSO`'s `0xFFF`.
    pub reference_key: u32,
}

impl Member {
    /// Reads one member from exactly its own bytes.
    fn read(record: &[u8]) -> Option<Self> {
        Some(Self {
            name: u32_at(record, 0)?,
            data_offset: u32_at(record, 4)?,
            type_code: TypeCode(*record.get(8)?),
            subtype: *record.get(9)?,
            array_info_index: u16_at(record, 10)?,
            reference_key: u32_at(record, 12)?,
        })
    }
}

/// The members of one structure, read from the payload as they are asked for.
#[derive(Debug, Clone)]
pub struct Members<'a> {
    /// What is left of the member array.
    rest: &'a [u8],
}

impl Iterator for Members<'_> {
    type Item = Member;

    fn next(&mut self) -> Option<Member> {
        let (record, rest) = self.rest.split_at_checked(MEMBER_LEN)?;
        self.rest = rest;
        Member::read(record)
    }
}

/// One `StructureInfo`, with its member array already checked.
#[derive(Debug, Clone, Copy)]
pub struct Structure<'a> {
    /// Its name, a `joaat` hash. 73 distinct across the whole corpus.
    pub name: u32,
    /// The second name hash the record carries.
    pub name2: u32,
    /// The word at +8, `0x300` or `0x400`.
    pub kind: u32,
    /// How long an instance of it is.
    pub length: u32,
    /// How many members it declares.
    pub member_count: u16,
    /// Its member array, exactly `member_count` records long.
    members: &'a [u8],
}

impl<'a> Structure<'a> {
    /// Its members, in declaration order.
    #[must_use]
    pub const fn members(&self) -> Members<'a> {
        Members { rest: self.members }
    }

    /// The member at `index`, or `None`.
    #[must_use]
    pub fn member(&self, index: u16) -> Option<Member> {
        let at = usize::from(index).checked_mul(MEMBER_LEN)?;
        let end = at.checked_add(MEMBER_LEN)?;
        Member::read(self.members.get(at..end)?)
    }
}

/// One entry of an enum: a name hash and the value it stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnumEntry {
    /// The entry's name, a `joaat` hash.
    pub name: u32,
    /// The value it names.
    pub value: u32,
}

/// The entries of one enum, read from the payload as they are asked for.
#[derive(Debug, Clone)]
pub struct EnumEntries<'a> {
    /// What is left of the entry array.
    rest: &'a [u8],
}

impl Iterator for EnumEntries<'_> {
    type Item = EnumEntry;

    fn next(&mut self) -> Option<EnumEntry> {
        let (record, rest) = self.rest.split_at_checked(ENUM_ENTRY_LEN)?;
        self.rest = rest;
        Some(EnumEntry {
            name: u32_at(record, 0)?,
            value: u32_at(record, 4)?,
        })
    }
}

/// One `EnumInfo`, with its entry array already checked.
#[derive(Debug, Clone, Copy)]
pub struct Enumeration<'a> {
    /// Its name, a `joaat` hash.
    pub name: u32,
    /// The word at +4, which nothing has explained.
    pub unknown: u32,
    /// How many entries it declares.
    pub entry_count: u32,
    /// Its entry array, exactly `entry_count` records long.
    entries: &'a [u8],
}

impl<'a> Enumeration<'a> {
    /// Its entries, in declaration order.
    #[must_use]
    pub const fn entries(&self) -> EnumEntries<'a> {
        EnumEntries { rest: self.entries }
    }
}

/// What a data block's tag names.
///
/// `docs/metadata-encodings.md`: a structure the file defines (369,488 blocks)
/// or a bare type code (93,454), and **0 resolve to neither**. Which of the two
/// a tag is, is decided here by asking the file's own structure table — the
/// only question that can be asked, because the 23 type codes are not
/// enumerated anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockTag {
    /// A structure this file defines.
    Structure(u32),
    /// A bare type code, carried as the word the file holds.
    Type(u32),
}

/// One data block: a run of the payload with a tag.
#[derive(Debug, Clone, Copy)]
pub struct Block<'a> {
    /// What its tag names.
    pub tag: BlockTag,
    /// Where its bytes begin in the payload, which is what a refusal about one
    /// of its pointers reports.
    at: usize,
    /// Its bytes, exactly the length its row declares.
    bytes: &'a [u8],
}

impl<'a> Block<'a> {
    /// Its bytes.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// How long it is.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether it holds no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Where `offset` inside it sits in the payload.
    #[must_use]
    pub fn address(&self, offset: u32) -> u64 {
        address(self.at).saturating_add(u64::from(offset))
    }

    /// The [`MetaPointer`] at `offset` inside it, or `None` when eight bytes do
    /// not fit.
    ///
    /// A block's contents are little-endian, like the rest of the file.
    #[must_use]
    pub fn pointer(&self, offset: u32) -> Option<MetaPointer> {
        let at = usize::try_from(offset).ok()?;
        Some(MetaPointer::wide(u64_at(self.bytes, at)?))
    }
}

/// Where a [`MetaPointer`] lands.
#[derive(Debug, Clone, Copy)]
pub struct Landing<'a> {
    /// The block it names.
    pub block: BlockId,
    /// How far into that block it lands.
    pub offset: u32,
    /// That block's bytes from there to its end.
    pub bytes: &'a [u8],
}

/// A parsed `Meta` document: its header, its three tables, and its data blocks.
///
/// Everything it holds was checked when it was built (§5): every table lies
/// inside the space its pointer names, every structure's members and every
/// enum's entries lie inside theirs, every block's bytes are the length its row
/// declares, and the root names a block.
#[derive(Debug, Clone)]
pub struct Meta<'a> {
    /// The header.
    header: Header,
    /// The structure table.
    structures: Vec<Structure<'a>>,
    /// Where each structure hash sits in that table, first occurrence winning.
    structures_by_hash: BTreeMap<u32, usize>,
    /// The enum table.
    enums: Vec<Enumeration<'a>>,
    /// Where each enum hash sits in that table.
    enums_by_hash: BTreeMap<u32, usize>,
    /// The data-block table.
    blocks: Vec<Block<'a>>,
    /// The root block, resolved when this was built.
    root: Block<'a>,
}

impl<'a> Meta<'a> {
    /// Its header.
    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// Its structures, in table order.
    #[must_use]
    pub fn structures(&self) -> &[Structure<'a>] {
        &self.structures
    }

    /// The structure this hash names, or `None`.
    #[must_use]
    pub fn structure(&self, name: u32) -> Option<&Structure<'a>> {
        self.structures.get(*self.structures_by_hash.get(&name)?)
    }

    /// Its enums, in table order.
    #[must_use]
    pub fn enums(&self) -> &[Enumeration<'a>] {
        &self.enums
    }

    /// The enum this hash names, or `None`.
    #[must_use]
    pub fn enumeration(&self, name: u32) -> Option<&Enumeration<'a>> {
        self.enums.get(*self.enums_by_hash.get(&name)?)
    }

    /// Its data blocks, in table order.
    #[must_use]
    pub fn blocks(&self) -> &[Block<'a>] {
        &self.blocks
    }

    /// The block this id names, or `None`.
    #[must_use]
    pub fn block(&self, id: BlockId) -> Option<&Block<'a>> {
        self.blocks.get(id.index())
    }

    /// The root block, which exists because [`parse`] resolved it.
    ///
    /// `docs/metadata-encodings.md`: in range in **49,614 of 49,614**, values
    /// 1..8, and its tag is always a structure the file defines.
    #[must_use]
    pub const fn root(&self) -> &Block<'a> {
        &self.root
    }

    /// Where a [`MetaPointer`] lands, or `None` when it is null.
    ///
    /// `at` is where the pointer was read from — [`Block::address`] answers it
    /// — and is what a refusal reports.
    ///
    /// # Errors
    ///
    /// [`Malformed::Pointer`] when the pointer names a block the table does not
    /// hold, or an offset at or past that block's length. 0 of the corpus's
    /// 1,362,769 pointers do either, so a reader refuses rather than guessing,
    /// which is what `CodeWalker`'s `offset = offset >> 8` recovery does.
    pub fn landing(&self, pointer: MetaPointer, at: u64) -> Result<Option<Landing<'a>>> {
        let Some(id) = pointer.block() else {
            return Ok(None);
        };
        let gone = || bad(at, Malformed::Pointer);
        let block = self.block(id).ok_or_else(gone)?;
        let offset = u32::try_from(pointer.item_offset()).map_err(|_| gone())?;
        let from = usize::try_from(offset).map_err(|_| gone())?;
        let bytes = block.bytes.get(from..).ok_or_else(gone)?;
        if bytes.is_empty() {
            return Err(gone());
        }
        Ok(Some(Landing {
            block: id,
            offset,
            bytes,
        }))
    }
}

/// Reads a resource `Meta` payload into the document it describes.
///
/// `payload` is the **inflated** payload of a resource entry and `system_len`
/// is how many of its bytes are system pages —
/// `crate::format::resource::size_from_flags` of the entry's system flags. The
/// two spaces are addressed separately, so a `system_len` that is not the
/// entry's is a caller error rather than a malformed file; nothing in the
/// payload states it.
///
/// # Errors
///
/// [`Error::BadMeta`] for every way the file can contradict itself: the
/// variants of [`Malformed`], each at the payload offset that reached it.
pub fn parse(payload: &[u8], system_len: usize) -> Result<Meta<'_>> {
    let header = Header::read(payload)?;
    let pages = Pages::split(payload, system_len)?;
    for (pointer, at) in [(header.pages_info, 0x08), (header.unknown_40, 0x40)] {
        if !pointer.is_null() {
            pages.lands(pointer, at)?;
        }
    }

    let structures = read_structures(&header, pages)?;
    let structures_by_hash = index(structures.iter().map(|structure| structure.name));
    let enums = read_enums(&header, pages)?;
    let enums_by_hash = index(enums.iter().map(|enumeration| enumeration.name));
    let blocks = read_blocks(&header, pages, &structures_by_hash)?;
    let root = *blocks
        .get(header.root.index())
        .ok_or_else(|| bad(0x1C, Malformed::RootBlock))?;

    Ok(Meta {
        header,
        structures,
        structures_by_hash,
        enums,
        enums_by_hash,
        blocks,
        root,
    })
}

/// The structure table, with every member array checked.
fn read_structures<'a>(header: &Header, pages: Pages<'a>) -> Result<Vec<Structure<'a>>> {
    let count = usize::from(header.structure_count);
    let (records, base) = table(pages, header.structures, count, STRUCTURE_LEN, 0x20)?;
    let mut structures = Vec::with_capacity(count);
    for (index, record) in records.as_chunks::<STRUCTURE_LEN>().0.iter().enumerate() {
        let at = record_address(base, index, STRUCTURE_LEN);
        let gone = || bad(at, Malformed::OutOfRange);
        let field = |offset: usize| -> Result<u32> { u32_at(record, offset).ok_or_else(gone) };
        let members_pointer = u64_at(record, 16)
            .and_then(ResourcePointer::wide)
            .ok_or_else(|| bad(at, Malformed::PointerWidth))?;
        let member_count = u16_at(record, 30).ok_or_else(gone)?;
        let (members, _) = table(
            pages,
            members_pointer,
            usize::from(member_count),
            MEMBER_LEN,
            at,
        )?;
        structures.push(Structure {
            name: field(0)?,
            name2: field(4)?,
            kind: field(8)?,
            length: field(24)?,
            member_count,
            members,
        });
    }
    Ok(structures)
}

/// The enum table, with every entry array checked.
fn read_enums<'a>(header: &Header, pages: Pages<'a>) -> Result<Vec<Enumeration<'a>>> {
    let count = usize::from(header.enum_count);
    let (records, base) = table(pages, header.enums, count, ENUM_LEN, 0x28)?;
    let mut enums = Vec::with_capacity(count);
    for (index, record) in records.as_chunks::<ENUM_LEN>().0.iter().enumerate() {
        let at = record_address(base, index, ENUM_LEN);
        let gone = || bad(at, Malformed::OutOfRange);
        let field = |offset: usize| -> Result<u32> { u32_at(record, offset).ok_or_else(gone) };
        let entries_pointer = u64_at(record, 8)
            .and_then(ResourcePointer::wide)
            .ok_or_else(|| bad(at, Malformed::PointerWidth))?;
        let entry_count = field(16)?;
        let (entries, _) = table(
            pages,
            entries_pointer,
            usize::try_from(entry_count).map_err(|_| gone())?,
            ENUM_ENTRY_LEN,
            at,
        )?;
        enums.push(Enumeration {
            name: field(0)?,
            unknown: field(4)?,
            entry_count,
            entries,
        });
    }
    Ok(enums)
}

/// The data-block table, with every block's bytes checked.
fn read_blocks<'a>(
    header: &Header,
    pages: Pages<'a>,
    structures: &BTreeMap<u32, usize>,
) -> Result<Vec<Block<'a>>> {
    let count = usize::from(header.block_count);
    let (records, base) = table(pages, header.blocks, count, BLOCK_LEN, 0x30)?;
    let mut blocks = Vec::with_capacity(count);
    for (index, record) in records.as_chunks::<BLOCK_LEN>().0.iter().enumerate() {
        let at = record_address(base, index, BLOCK_LEN);
        let gone = || bad(at, Malformed::OutOfRange);
        let tag = u32_at(record, 0).ok_or_else(gone)?;
        let length = usize::try_from(u32_at(record, 4).ok_or_else(gone)?).map_err(|_| gone())?;
        let pointer = u64_at(record, 8)
            .and_then(ResourcePointer::wide)
            .ok_or_else(|| bad(at, Malformed::PointerWidth))?;
        let (bytes, from) = pages.bytes(pointer, length, at)?;
        blocks.push(Block {
            tag: if structures.contains_key(&tag) {
                BlockTag::Structure(tag)
            } else {
                BlockTag::Type(tag)
            },
            at: from,
            bytes,
        });
    }
    Ok(blocks)
}

/// `count` records of `stride` bytes at `pointer`, with where they begin in the
/// payload, or the empty slice when the count is 0.
///
/// **This is the only allocation bound the tables need.** A table is refused
/// unless its whole extent lies inside the space its pointer names, so a count
/// larger than the payload can hold is a refusal rather than a `Vec` of that
/// many records.
fn table(
    pages: Pages<'_>,
    pointer: ResourcePointer,
    count: usize,
    stride: usize,
    at: u64,
) -> Result<(&[u8], usize)> {
    if count == 0 {
        return Ok((&[], 0));
    }
    let len = count
        .checked_mul(stride)
        .ok_or_else(|| bad(at, Malformed::OutOfRange))?;
    pages.bytes(pointer, len, at)
}

/// Where the `index`th record of a table beginning at `base` sits in the
/// payload.
fn record_address(base: usize, index: usize, stride: usize) -> u64 {
    address(base.saturating_add(index.saturating_mul(stride)))
}

/// A name-to-index map over a table, first occurrence winning.
fn index(names: impl Iterator<Item = u32>) -> BTreeMap<u32, usize> {
    let mut map = BTreeMap::new();
    for (at, name) in names.enumerate() {
        map.entry(name).or_insert(at);
    }
    map
}

/// A refusal about the bytes, at the payload offset that reached it.
fn bad(offset: u64, cause: Malformed) -> Error {
    Error::BadMeta { offset, cause }
}

/// A refusal about this build rather than about the bytes.
fn unsupported(cause: Unsupported) -> Error {
    Error::UnsupportedMeta { cause }
}

/// `at` as an address a refusal can report.
fn address(at: usize) -> u64 {
    u64::try_from(at).unwrap_or(u64::MAX)
}

/// The little-endian `u16` at `at`.
fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let half = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes(<[u8; 2]>::try_from(half).ok()?))
}

/// The little-endian `u32` at `at`.
fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let word = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(<[u8; 4]>::try_from(word).ok()?))
}

/// The little-endian `u64` at `at`.
fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    let word = bytes.get(at..at.checked_add(8)?)?;
    Some(u64::from_le_bytes(<[u8; 8]>::try_from(word).ok()?))
}

/// Why a byte stream is not a well-formed resource `Meta` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Malformed {
    /// The payload is shorter than the [`HEADER_LEN`] bytes of header.
    Header,
    /// The word at [`MAGIC_AT`] is not [`MAGIC`].
    NotMeta,
    /// The version word at `0x14` is neither of the two that occur.
    ///
    /// `docs/metadata-encodings.md`: `0x00010079` on 49,608 files and `0x79` on
    /// the six version-3 `.ymt`.
    Version,
    /// The system page length the caller gave is longer than the payload.
    ///
    /// A fact about the entry's flag words rather than about these bytes, which
    /// is why it says so rather than blaming the file.
    Pages,
    /// A resource pointer's high 32 bits are set, so it is not one.
    PointerWidth,
    /// A resource pointer's space nibble is neither system nor graphics.
    ///
    /// `docs/metadata-encodings.md`: **0** of 1,014,378 pointers are in any
    /// other space.
    Space,
    /// A resource pointer, or the table or block it introduces, does not lie
    /// inside the space it names.
    ///
    /// `docs/metadata-encodings.md`: **0** of 1,014,378 pointers are out of
    /// range.
    OutOfRange,
    /// The root field names no block.
    RootBlock,
    /// A `Meta` pointer names a block the table does not hold, or an offset at
    /// or past that block's length.
    Pointer,
    /// A read fell outside the data block it was made in.
    DataRange,
    /// A member's value does not lie inside the structure that declares it.
    ///
    /// The one check that measures this build's `secondary` type widths against
    /// something the file itself states — `kind` says why it is load-bearing.
    MemberExtent,
    /// A structure a pointer or a member reaches is not one the file defines.
    ///
    /// `docs/metadata-encodings.md`: 0 of 462,942 block tags resolve to neither
    /// a structure the file defines nor a bare type code, and 0 of 167,988
    /// structure references on real members are unresolvable — so a file where
    /// one is, is not one Rockstar's packer wrote.
    UndefinedStructure,
    /// An array member's `arrayInfoIndex` names no member of its structure.
    ///
    /// `docs/metadata-encodings.md`: 925,473 indices resolved and **0**
    /// unresolvable.
    ArrayInfo,
    /// Structures nested deeper than this walk goes.
    TooDeep,
    /// The walk wrote more elements than its budget allows.
    TooManyNodes,
    /// The document grew past what a payload of this size is allowed to write.
    TooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A payload under construction, so that a test states the bytes it means
    /// and nothing else.
    struct Payload(Vec<u8>);

    impl Payload {
        /// A payload of `len` zero bytes.
        fn of(len: usize) -> Self {
            Self(vec![0; len])
        }

        /// Writes `bytes` at `at`, growing nothing: a test that writes past the
        /// end has written the wrong test.
        fn put(&mut self, at: usize, bytes: &[u8]) -> &mut Self {
            self.0[at..at.saturating_add(bytes.len())].copy_from_slice(bytes);
            self
        }

        fn u16(&mut self, at: usize, value: u16) -> &mut Self {
            self.put(at, &value.to_le_bytes())
        }

        fn u32(&mut self, at: usize, value: u32) -> &mut Self {
            self.put(at, &value.to_le_bytes())
        }

        fn u64(&mut self, at: usize, value: u64) -> &mut Self {
            self.put(at, &value.to_le_bytes())
        }

        fn bytes(&self) -> &[u8] {
            &self.0
        }
    }

    /// A system-space pointer at `offset`.
    fn system(offset: u32) -> u64 {
        u64::from(SYSTEM_SPACE << SPACE_SHIFT) | u64::from(offset)
    }

    /// A graphics-space pointer at `offset`.
    fn graphics(offset: u32) -> u64 {
        u64::from(GRAPHICS_SPACE << SPACE_SHIFT) | u64::from(offset)
    }

    /// A `Meta` pointer to `offset` of block `id`.
    fn data_pointer(id: u64, offset: u64) -> u64 {
        (offset << ITEM_SHIFT) | id
    }

    /// The header of a well-formed file with no table in it.
    fn bare(len: usize) -> Payload {
        let mut payload = Payload::of(len);
        payload
            .u32(0x00, 0xDEAD_BEEF)
            .u32(0x04, 1)
            .u64(0x08, system(0))
            .u32(MAGIC_AT, MAGIC)
            .u32(0x14, VERSION_TWO)
            .u32(0x1C, 1);
        payload
    }

    /// A file with one structure of one member, one enum of one entry, and one
    /// data block, laid out at fixed offsets a test can name.
    ///
    /// ```text
    /// 0x50 structure table    0x70 member array   0x80 enum table
    /// 0x98 enum entries       0xA0 block table    0xB0 block data
    /// ```
    fn whole() -> Payload {
        let mut payload = bare(0x100);
        payload
            .u64(0x20, system(0x50))
            .u64(0x28, system(0x80))
            .u64(0x30, system(0xA0))
            .u16(0x48, 1)
            .u16(0x4A, 1)
            .u16(0x4C, 1)
            // The structure: name, name2, kind, membersPtr, length, count.
            .u32(0x50, 0x1111_1111)
            .u32(0x54, 0x2222_2222)
            .u32(0x58, 0x300)
            .u64(0x60, system(0x70))
            .u32(0x68, 0x40)
            .u16(0x6E, 1)
            // Its member.
            .u32(0x70, 0x3333_3333)
            .u32(0x74, 0x0000_0010)
            .put(0x78, &[0x07, 0x04])
            .u16(0x7A, 2)
            .u32(0x7C, 0x4444_4444)
            // The enum, and its one entry.
            .u32(0x80, 0x5555_5555)
            .u32(0x84, 0x6666_6666)
            .u64(0x88, system(0x98))
            .u32(0x90, 1)
            .u32(0x98, 0x7777_7777)
            .u32(0x9C, 42)
            // The block: tag, length, pointer.
            .u32(0xA0, 0x1111_1111)
            .u32(0xA4, 0x10)
            .u64(0xA8, system(0xB0))
            .u32(0xB0, 0xABAD_1DEA);
        payload
    }

    /// What a refusal is, for a test that asserts one.
    #[track_caller]
    fn refusal(error: &Error) -> Malformed {
        match *error {
            Error::BadMeta { cause, .. } => cause,
            ref other => panic!("not a Meta refusal: {other}"),
        }
    }

    #[test]
    fn the_magic_is_the_word_the_format_document_records_at_0x10() {
        assert_eq!(MAGIC, 0x5052_4430);
        assert_eq!(MAGIC_AT, 0x10);
        let payload = bare(HEADER_LEN);
        assert!(identifies(payload.bytes()));
        // And it is a word at 0x10 rather than a magic at the front: the same
        // bytes at offset 0 name nothing.
        let mut moved = Payload::of(HEADER_LEN);
        moved.u32(0, MAGIC);
        assert!(!identifies(moved.bytes()));
        // A payload too short to hold it is not one, and does not panic.
        for len in 0..=MAGIC_AT + 4 {
            let _ = identifies(&vec![0xFF; len]);
        }
        assert!(!identifies(&[]));
    }

    #[test]
    fn a_resource_pointer_is_a_space_and_a_flat_offset() {
        let pointer = ResourcePointer::wide(system(0x1234)).expect("a 32-bit pointer");
        assert_eq!(pointer.space(), Some(Space::System));
        assert_eq!(pointer.offset(), 0x1234);
        let pointer = ResourcePointer::wide(graphics(0x0FFF_FFFF)).expect("a 32-bit pointer");
        assert_eq!(pointer.space(), Some(Space::Graphics));
        assert_eq!(pointer.offset(), 0x0FFF_FFFF);
        // Null, and every space but the two that occur.
        assert!(
            ResourcePointer::wide(0)
                .expect("null is a pointer")
                .is_null()
        );
        for space in [0_u32, 1, 2, 3, 4, 7, 8, 0xF] {
            let word = u64::from(space) << SPACE_SHIFT;
            assert_eq!(
                ResourcePointer::wide(word)
                    .expect("a 32-bit pointer")
                    .space(),
                None,
                "space {space:#x}"
            );
        }
        // And a value that does not fit 32 bits is not a resource pointer at
        // all, rather than one with its high bits dropped.
        assert_eq!(ResourcePointer::wide(1_u64 << 32), None);
        assert_eq!(ResourcePointer::wide(u64::MAX), None);
    }

    #[test]
    fn a_meta_pointer_is_a_block_id_and_an_item_offset() {
        let pointer = MetaPointer::wide(data_pointer(3, 128));
        assert_eq!(pointer.block().map(BlockId::get), Some(3));
        assert_eq!(pointer.item_offset(), 128);
        // `hei_ch3_06.ymap`'s entity array, which is what settles the 12-bit
        // boundary: block 3 at offsets 0, 128 and 256.
        for (word, offset) in [(0x3, 0), (0x8_0003, 128), (0x10_0003, 256)] {
            let pointer = MetaPointer::wide(word);
            assert_eq!(pointer.block().map(BlockId::get), Some(3));
            assert_eq!(pointer.item_offset(), offset);
        }
        // A 16-bit split would read the same three as block 3 at offset 8 and
        // reach only the first 1,016 bytes of a 16,384-byte block.
        assert_ne!(MetaPointer::wide(0x10_0003).item_offset(), 16);
        // A block id of 0 is null, and the id is bounded by its 12 bits.
        assert!(MetaPointer::wide(data_pointer(0, 4096)).is_null());
        assert_eq!(BlockId::new(0), None);
        assert_eq!(BlockId::new(BLOCK_MASK).map(BlockId::get), Some(4095));
        assert_eq!(BlockId::new(BLOCK_MASK + 1), None);
    }

    #[test]
    fn a_table_pointer_is_not_read_the_way_a_data_pointer_is() {
        // The conflation, in the direction the header takes it. The structure
        // table sits at `0x50` and its pointer is `0x50000050`: a resource
        // pointer of space 5, offset 0x50. Read as a `Meta` pointer the same
        // word is block 0x050 at item offset 0x50000, which resolves to
        // nothing here and would resolve to the wrong bytes in a file with
        // eighty blocks.
        let payload = whole();
        let conflated = MetaPointer::wide(system(0x50));
        assert_eq!(conflated.block().map(BlockId::get), Some(0x50));
        assert_eq!(conflated.item_offset(), 0x5_0000);

        let meta = parse(payload.bytes(), payload.bytes().len()).expect("a whole file");
        assert_eq!(meta.structures().len(), 1);
        assert_eq!(meta.structures()[0].name, 0x1111_1111);
    }

    #[test]
    fn a_data_pointer_is_not_read_the_way_a_table_pointer_is() {
        // The conflation in the other direction, and the case that would pass
        // if the two kinds were one integer. The word inside the block is
        // `0x5003`: as a `Meta` pointer it is block 3 at offset 5, and as a
        // resource pointer it is space 0, offset 0x5003 — which lands on a
        // marker this payload deliberately puts there.
        let mut payload = bare(0x6000);
        payload
            .u64(0x30, system(0xA0))
            .u16(0x4C, 3)
            // Three block rows, of which only the third is pointed at.
            .u32(0xA0, 1)
            .u32(0xA4, 8)
            .u64(0xA8, system(0x200))
            .u32(0xB0, 2)
            .u32(0xB4, 8)
            .u64(0xB8, system(0x200))
            .u32(0xC0, 3)
            .u32(0xC4, 0x10)
            .u64(0xC8, system(0x300))
            // Block 1 holds the pointer, block 3 the value it names.
            .u64(0x200, data_pointer(3, 5))
            .put(0x305, b"BLOCK")
            .put(0x5003, b"PAGES");
        let payload = payload;

        let meta = parse(payload.bytes(), payload.bytes().len()).expect("a whole file");
        let block = meta.blocks().first().expect("a first block");
        let pointer = block.pointer(0).expect("a pointer at the start");
        assert_eq!(pointer.word(), 0x5003);
        let landing = meta
            .landing(pointer, block.address(0))
            .expect("it resolves")
            .expect("it is not null");
        assert_eq!(landing.block.get(), 3);
        assert_eq!(landing.offset, 5);
        assert!(
            landing.bytes.starts_with(b"BLOCK"),
            "a conflated read lands on the resource-pointer marker instead"
        );
        // The two decodes really do differ here: as a resource pointer the same
        // word is space 0 at offset 0x5003, which is where `PAGES` is.
        let conflated = ResourcePointer::wide(pointer.word()).expect("a 32-bit word");
        assert_eq!(conflated.space(), None);
        assert_eq!(conflated.offset(), 0x5003);
        assert!(payload.bytes()[0x5003..].starts_with(b"PAGES"));
    }

    #[test]
    fn the_header_is_read_at_the_offsets_the_document_records() {
        let payload = whole();
        let header = Header::read(payload.bytes()).expect("a header");
        assert_eq!(header.vft, 0xDEAD_BEEF);
        assert_eq!(header.kind, 1);
        assert_eq!(header.version, VERSION_TWO);
        assert_eq!(header.root.get(), 1);
        assert_eq!(header.structures.offset(), 0x50);
        assert_eq!(header.enums.offset(), 0x80);
        assert_eq!(header.blocks.offset(), 0xA0);
        assert_eq!(header.unknown_38, 0);
        assert_eq!(
            (
                header.structure_count,
                header.enum_count,
                header.block_count
            ),
            (1, 1, 1)
        );
    }

    #[test]
    fn the_six_version_three_files_are_read_and_no_other_version_is() {
        let mut payload = bare(HEADER_LEN);
        payload.u32(0x14, VERSION_THREE);
        assert_eq!(
            Header::read(payload.bytes()).expect("version 3").version,
            VERSION_THREE
        );
        payload.u32(0x14, 0x0002_0079);
        assert_eq!(
            refusal(&Header::read(payload.bytes()).expect_err("no other version occurs")),
            Malformed::Version
        );
    }

    #[test]
    fn the_three_tables_are_read_at_their_own_strides() {
        let payload = whole();
        let meta = parse(payload.bytes(), payload.bytes().len()).expect("a whole file");

        let structure = meta.structure(0x1111_1111).expect("the structure");
        assert_eq!(structure.name2, 0x2222_2222);
        assert_eq!(structure.kind, 0x300);
        assert_eq!(structure.length, 0x40);
        assert_eq!(structure.member_count, 1);
        let members: Vec<Member> = structure.members().collect();
        assert_eq!(members.len(), 1);
        let member = members[0];
        // The correction that matters: `dataOffset` is a `u32` at offset 4, so
        // reading `PSO`'s twelve-byte member here shifts every field after it.
        assert_eq!(member.name, 0x3333_3333);
        assert_eq!(member.data_offset, 0x10);
        assert_eq!(member.type_code.get(), 0x07);
        assert_eq!(member.subtype, 0x04);
        assert_eq!(member.array_info_index, 2);
        assert_eq!(member.reference_key, 0x4444_4444);
        assert_eq!(structure.member(0), Some(member));
        assert_eq!(structure.member(1), None);

        let enumeration = meta.enumeration(0x5555_5555).expect("the enum");
        assert_eq!(enumeration.unknown, 0x6666_6666);
        assert_eq!(enumeration.entry_count, 1);
        assert_eq!(
            enumeration.entries().collect::<Vec<_>>(),
            vec![EnumEntry {
                name: 0x7777_7777,
                value: 42
            }]
        );

        let block = meta.root();
        assert_eq!(block.tag, BlockTag::Structure(0x1111_1111));
        assert_eq!(block.len(), 0x10);
        assert!(!block.is_empty());
        assert_eq!(u32_at(block.bytes(), 0), Some(0xABAD_1DEA));
        assert_eq!(meta.blocks().len(), 1);
        assert!(meta.structure(0).is_none());
        assert!(meta.enumeration(0).is_none());
        assert!(meta.block(BlockId::new(2).expect("a second id")).is_none());
    }

    #[test]
    fn a_block_tag_is_a_structure_the_file_defines_or_a_bare_type_code() {
        // The 23 type codes are not enumerated anywhere, so the only question
        // that can be asked is whether the file's own structure table has the
        // hash — which is the question `docs/metadata-encodings.md` measured:
        // 369,488 structures, 93,454 bare codes, 0 neither.
        let mut payload = whole();
        payload.u32(0xA0, 0x1111_1111);
        let meta = parse(payload.bytes(), payload.bytes().len()).expect("a whole file");
        assert_eq!(meta.root().tag, BlockTag::Structure(0x1111_1111));

        payload.u32(0xA0, 0x0000_0007);
        let meta = parse(payload.bytes(), payload.bytes().len()).expect("a whole file");
        assert_eq!(meta.root().tag, BlockTag::Type(7));
    }

    #[test]
    fn the_two_page_spaces_are_separate_and_the_split_decides_which() {
        // A graphics pointer's offset is flat within the graphics pages, so the
        // same file read with a different split reads different bytes — which
        // is why the split is a parameter and not a guess.
        let mut payload = bare(0x200);
        payload
            .u64(0x30, graphics(0x10))
            .u16(0x4C, 1)
            .u32(0x110, 0x99)
            .u32(0x114, 4)
            .u64(0x118, graphics(0x40))
            .u32(0x140, 0x0BAD_F00D);
        let payload = payload;

        let meta = parse(payload.bytes(), 0x100).expect("a file with a graphics block");
        assert_eq!(u32_at(meta.root().bytes(), 0), Some(0x0BAD_F00D));

        // With the whole payload declared system, the graphics space is empty
        // and every graphics pointer is out of range rather than silently
        // reading the system pages.
        assert_eq!(
            refusal(&parse(payload.bytes(), payload.bytes().len()).expect_err("no graphics pages")),
            Malformed::OutOfRange
        );
        // And a system table does not spill into the graphics pages: a block
        // whose extent crosses the split is refused.
        let mut crossing = bare(0x200);
        crossing
            .u64(0x30, system(0x110))
            .u16(0x4C, 1)
            .u32(0x114, 0x20)
            .u64(0x118, system(0xF0));
        assert_eq!(
            refusal(&parse(crossing.bytes(), 0x100).expect_err("it crosses the split")),
            Malformed::OutOfRange
        );
    }

    #[test]
    fn every_refusal_is_reachable() {
        // §6, and `docs/conventions.md` §12's rule that the malformed cases
        // are tested deliberately: one payload per variant of `Malformed` that
        // [`parse`] itself raises. The walk's own — `DataRange`,
        // `MemberExtent`, `UndefinedStructure`, `ArrayInfo`, `TooDeep`,
        // `TooManyNodes` and `TooLarge` — belong to `render` and `apply`, and
        // are pinned in `crates/rpf-core/tests/metadata.rs` and, for the three
        // that are ceilings, at their boundary in
        // `crates/rpf-core/tests/boundaries.rs`.
        let short = vec![0_u8; HEADER_LEN - 1];
        assert_eq!(
            refusal(&parse(&short, 0).expect_err("shorter than a header")),
            Malformed::Header
        );

        let mut wrong = bare(HEADER_LEN);
        wrong.u32(MAGIC_AT, 0x5052_4431);
        assert_eq!(
            refusal(&parse(wrong.bytes(), HEADER_LEN).expect_err("not the magic")),
            Malformed::NotMeta
        );

        let mut version = bare(HEADER_LEN);
        version.u32(0x14, 0);
        assert_eq!(
            refusal(&parse(version.bytes(), HEADER_LEN).expect_err("no such version")),
            Malformed::Version
        );

        let split = bare(HEADER_LEN);
        assert_eq!(
            refusal(&parse(split.bytes(), HEADER_LEN + 1).expect_err("past the payload")),
            Malformed::Pages
        );

        let mut wide = bare(HEADER_LEN);
        wide.u64(0x20, 1_u64 << 32);
        assert_eq!(
            refusal(&parse(wide.bytes(), HEADER_LEN).expect_err("not a resource pointer")),
            Malformed::PointerWidth
        );

        let mut space = bare(HEADER_LEN);
        space.u64(0x20, 0x7000_0000).u16(0x48, 1);
        assert_eq!(
            refusal(&parse(space.bytes(), HEADER_LEN).expect_err("no such space")),
            Malformed::Space
        );

        let mut past = bare(HEADER_LEN);
        past.u64(0x20, system(0x40)).u16(0x48, 1);
        assert_eq!(
            refusal(&parse(past.bytes(), HEADER_LEN).expect_err("past the system pages")),
            Malformed::OutOfRange
        );

        let mut root = bare(HEADER_LEN);
        root.u32(0x1C, 0);
        assert_eq!(
            refusal(&parse(root.bytes(), HEADER_LEN).expect_err("no root")),
            Malformed::RootBlock
        );
        // And a root the block table does not reach, which is the other half.
        let mut missing = bare(HEADER_LEN);
        missing.u32(0x1C, 2);
        assert_eq!(
            refusal(&parse(missing.bytes(), HEADER_LEN).expect_err("no such block")),
            Malformed::RootBlock
        );

        let payload = whole_with_pointer(data_pointer(2, 0));
        let meta_file = parse(payload.bytes(), payload.bytes().len()).expect("a whole file");
        let block = meta_file.root();
        let pointer = block.pointer(0).expect("a pointer");
        assert_eq!(
            refusal(
                &meta_file
                    .landing(pointer, block.address(0))
                    .expect_err("no such block")
            ),
            Malformed::Pointer
        );
    }

    /// [`whole`], with `word` written over the start of its data block.
    fn whole_with_pointer(word: u64) -> Payload {
        let mut payload = whole();
        payload.u64(0xB0, word);
        payload
    }

    #[test]
    fn a_pointer_at_or_past_its_blocks_length_is_refused_rather_than_guessed_at() {
        // 0 of the corpus's pointers do either, which is what says
        // `CodeWalker`'s `offset = offset >> 8` recovery is never needed.
        let payload = whole_with_pointer(data_pointer(1, 0x10));
        let meta_file = parse(payload.bytes(), payload.bytes().len()).expect("a whole file");
        let block = meta_file.root();
        let pointer = block.pointer(0).expect("a pointer");
        assert_eq!(
            refusal(
                &meta_file
                    .landing(pointer, block.address(0))
                    .expect_err("at the block's length")
            ),
            Malformed::Pointer
        );
        // One byte earlier resolves, so the boundary is at the length and not
        // one past it.
        let payload = whole_with_pointer(data_pointer(1, 0xF));
        let meta_file = parse(payload.bytes(), payload.bytes().len()).expect("a whole file");
        let block = meta_file.root();
        let landing = meta_file
            .landing(block.pointer(0).expect("a pointer"), block.address(0))
            .expect("it resolves")
            .expect("it is not null");
        assert_eq!(landing.bytes.len(), 1);
        // A null pointer is null and not a refusal.
        let payload = whole_with_pointer(0);
        let meta_file = parse(payload.bytes(), payload.bytes().len()).expect("a whole file");
        let block = meta_file.root();
        assert!(
            meta_file
                .landing(block.pointer(0).expect("a pointer"), block.address(0))
                .expect("null resolves")
                .is_none()
        );
    }

    #[test]
    fn a_table_larger_than_the_payload_is_a_refusal_and_never_an_allocation() {
        // The bound on every allocation `parse` makes: a table of `n` records
        // has to lie inside the space its pointer names, so 65,535 structures
        // in an 0x100-byte payload is one refusal rather than 65,535 records.
        let mut payload = whole();
        payload.u16(0x48, u16::MAX);
        assert_eq!(
            refusal(&parse(payload.bytes(), payload.bytes().len()).expect_err("no room")),
            Malformed::OutOfRange
        );
        // The same for a structure's members, which is where a hostile count
        // costs most: nothing collects them, and the extent is still checked.
        let mut payload = whole();
        payload.u16(0x6E, u16::MAX);
        assert_eq!(
            refusal(&parse(payload.bytes(), payload.bytes().len()).expect_err("no room")),
            Malformed::OutOfRange
        );
        // And for an enum's entries, whose count is a `u32`.
        let mut payload = whole();
        payload.u32(0x90, u32::MAX);
        assert_eq!(
            refusal(&parse(payload.bytes(), payload.bytes().len()).expect_err("no room")),
            Malformed::OutOfRange
        );
    }

    #[test]
    fn a_table_of_no_records_needs_no_pointer() {
        // A count of 0 with a null pointer is an empty table and not a refusal:
        // the pointer names nothing because there is nothing to name.
        let payload = bare(HEADER_LEN);
        let meta = parse(payload.bytes(), HEADER_LEN).expect_err("the root names no block");
        assert_eq!(refusal(&meta), Malformed::RootBlock);
        // With one block, the same file parses and its two other tables are
        // empty.
        let mut payload = bare(0x100);
        payload
            .u64(0x30, system(0xA0))
            .u16(0x4C, 1)
            .u32(0xA4, 4)
            .u64(0xA8, system(0xB0));
        let meta = parse(payload.bytes(), payload.bytes().len()).expect("a file with one block");
        assert!(meta.structures().is_empty());
        assert!(meta.enums().is_empty());
        assert_eq!(meta.blocks().len(), 1);
        assert_eq!(meta.root().len(), 4);
    }

    #[test]
    fn no_payload_of_any_shape_panics() {
        // §6: the bytes are third-party and some of them are malformed
        // deliberately. Every prefix of a whole file, and every prefix with its
        // last byte set, at every split.
        let payload = whole();
        let bytes = payload.bytes();
        for len in 0..bytes.len() {
            let mut truncated = bytes[..len].to_vec();
            let _ = parse(&truncated, len);
            let _ = parse(&truncated, len / 2);
            let _ = parse(&truncated, len.saturating_add(1));
            if let Some(last) = truncated.last_mut() {
                *last = 0xFF;
            }
            let _ = parse(&truncated, len);
        }
        // And a header whose every field is set.
        let ones = vec![0xFF_u8; 0x200];
        let _ = parse(&ones, 0x100);
    }
}
