//! Resource-embedded `Meta`: header, three info tables, two pointer kinds.

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
pub const RESERVED_PREFIX: &str = "meta:";

/// Reads a resource `Meta` payload and writes the XML that describes it.
/// # Errors
/// Returns an error if the payload is malformed or uses an unsupported type code.
pub fn to_xml(payload: &[u8], system_len: usize, names: &Dictionary) -> Result<Vec<u8>> {
    render::write(payload, system_len, names)
}

/// Reads the XML `to_xml` wrote and applies it back to the payload it came from.
/// # Errors
/// Returns an error if the payload is malformed, or the document is not XML describing it.
pub fn from_xml(
    payload: &[u8],
    system_len: usize,
    document: &[u8],
    names: &Dictionary,
) -> Result<Vec<u8>> {
    apply::write(payload, system_len, document, names)
}

/// The word at `MAGIC_AT` of an inflated resource `Meta` payload.
pub const MAGIC: u32 = 0x5052_4430;

/// Where `MAGIC` sits in the payload.
pub const MAGIC_AT: usize = 0x10;

/// How long the header is, and the shortest payload that can be one.
pub const HEADER_LEN: usize = 0x50;

const STRUCTURE_LEN: usize = 32;

const MEMBER_LEN: usize = 16;

const ENUM_LEN: usize = 24;

const ENUM_ENTRY_LEN: usize = 8;

const BLOCK_LEN: usize = 16;

/// The version word of a version-2 file, at `0x14`.
pub const VERSION_TWO: u32 = 0x0001_0079;

/// The version word of a version-3 file, `0x79` rather than `0x00010079`.
pub const VERSION_THREE: u32 = 0x0000_0079;

const SPACE_SHIFT: u32 = 28;

const RESOURCE_OFFSET: u32 = 0x0FFF_FFFF;

const SYSTEM_SPACE: u32 = 5;

const GRAPHICS_SPACE: u32 = 6;

const BLOCK_MASK: u64 = 0xFFF;

const ITEM_SHIFT: u32 = 12;

/// Whether these bytes are a resource `Meta` payload; `payload` must be inflated.
#[must_use]
pub fn identifies(payload: &[u8]) -> bool {
    u32_at(payload, MAGIC_AT) == Some(MAGIC)
}

/// Which of a resource's two page spaces a `ResourcePointer` addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Space {
    /// The system pages, which come first in the inflated payload.
    System,
    /// The graphics pages, which follow them.
    Graphics,
}

/// A pointer into the resource's pages: the header's fields and the three tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResourcePointer(u32);

impl ResourcePointer {
    /// The pointer this 64-bit field holds, or `None` when its high half is set.
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

/// A 1-based data-block id; zero is reserved for the null pointer.
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

    #[must_use]
    const fn index(self) -> usize {
        (self.0 as usize).saturating_sub(1)
    }
}

#[derive(Debug, Clone, Copy)]
struct Pages<'a> {
    system: &'a [u8],
    graphics: &'a [u8],
}

impl<'a> Pages<'a> {
    fn split(payload: &'a [u8], system_len: usize) -> Result<Self> {
        let (system, graphics) = payload
            .split_at_checked(system_len)
            .ok_or_else(|| bad(0, Malformed::Pages))?;
        Ok(Self { system, graphics })
    }

    fn space(self, pointer: ResourcePointer, at: u64) -> Result<(&'a [u8], usize)> {
        match pointer.space() {
            Some(Space::System) => Ok((self.system, 0)),
            Some(Space::Graphics) => Ok((self.graphics, self.system.len())),
            None => Err(bad(at, Malformed::Space)),
        }
    }

    fn bytes(self, pointer: ResourcePointer, len: usize, at: u64) -> Result<(&'a [u8], usize)> {
        let gone = || bad(at, Malformed::OutOfRange);
        let (space, base) = self.space(pointer, at)?;
        let from = usize::try_from(pointer.offset()).map_err(|_| gone())?;
        let end = from.checked_add(len).ok_or_else(gone)?;
        let bytes = space.get(from..end).ok_or_else(gone)?;
        Ok((bytes, base.checked_add(from).ok_or_else(gone)?))
    }

    fn lands(self, pointer: ResourcePointer, at: u64) -> Result<()> {
        self.bytes(pointer, 0, at).map(|_| ())
    }
}

/// The fixed header bytes a `Meta` payload opens with.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    /// The virtual function table pointer at `0x00`, carried but not interpreted.
    pub vft: u32,
    /// The word at `0x04`, 1 in the files the document lists.
    pub kind: u32,
    /// The pages-info pointer at `0x08`.
    pub pages_info: ResourcePointer,
    /// The version word at `0x14`: `VERSION_TWO` or `VERSION_THREE`.
    pub version: u32,
    /// The 1-based root data block, at `0x1C`.
    pub root: BlockId,
    /// The structure table, at `0x20`.
    pub structures: ResourcePointer,
    /// The enum table, at `0x28`.
    pub enums: ResourcePointer,
    /// The data-block table, at `0x30`.
    pub blocks: ResourcePointer,
    /// The `u64` at `0x38`, usually 0; its meaning otherwise is unmeasured.
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
    /// Reads the header; the one part of a `Meta` file needing no page split.
    /// # Errors
    /// Returns an error if the header is malformed, wrong version, or names no root.
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

/// A member's type code, as the file carries it; `kind` gives it meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeCode(u8);

impl TypeCode {
    /// This code, as the file carries it.
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
    /// Its name, a `joaat` hash.
    pub name: u32,
    /// Its byte offset within the structure.
    pub data_offset: u32,
    /// Its type code.
    pub type_code: TypeCode,
    /// Its subtype, one of 0, `0x04` and `0x24`.
    pub subtype: u8,
    /// The index of the member describing this one's elements, for arrays.
    pub array_info_index: u16,
    /// The structure or enum this member refers to, or 0 for none.
    pub reference_key: u32,
}

impl Member {
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
    /// Its name, a `joaat` hash.
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

/// What a data block's tag names, decided from the file's own structure table.
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

    /// The `MetaPointer` at `offset` inside it, or `None` when it does not fit.
    #[must_use]
    pub fn pointer(&self, offset: u32) -> Option<MetaPointer> {
        let at = usize::try_from(offset).ok()?;
        Some(MetaPointer::wide(u64_at(self.bytes, at)?))
    }
}

/// Where a `MetaPointer` lands.
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
#[derive(Debug, Clone)]
pub struct Meta<'a> {
    header: Header,
    structures: Vec<Structure<'a>>,
    structures_by_hash: BTreeMap<u32, usize>,
    enums: Vec<Enumeration<'a>>,
    enums_by_hash: BTreeMap<u32, usize>,
    blocks: Vec<Block<'a>>,
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

    /// The root block, which exists because `parse` resolved it.
    #[must_use]
    pub const fn root(&self) -> &Block<'a> {
        &self.root
    }

    /// Where a `MetaPointer` lands, or `None` when it is null.
    /// # Errors
    /// Returns an error if the pointer names a block or offset the table lacks.
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
/// # Errors
/// Returns an error, at the offending offset, if the file contradicts itself.
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

fn bad(offset: u64, cause: Malformed) -> Error {
    Error::BadMeta { offset, cause }
}

fn unsupported(cause: Unsupported) -> Error {
    Error::UnsupportedMeta { cause }
}

fn address(at: usize) -> u64 {
    u64::try_from(at).unwrap_or(u64::MAX)
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let half = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes(<[u8; 2]>::try_from(half).ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let word = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(<[u8; 4]>::try_from(word).ok()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    let word = bytes.get(at..at.checked_add(8)?)?;
    Some(u64::from_le_bytes(<[u8; 8]>::try_from(word).ok()?))
}

/// Why a byte stream is not a well-formed resource `Meta` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Malformed {
    /// The payload is shorter than the header.
    Header,
    /// The word at `MAGIC_AT` is not `MAGIC`.
    NotMeta,
    /// The version word at `0x14` is neither of the two that occur.
    Version,
    /// The caller's system page length is longer than the payload.
    Pages,
    /// A resource pointer's high 32 bits are set, so it is not one.
    PointerWidth,
    /// A resource pointer's space nibble is neither system nor graphics.
    Space,
    /// A resource pointer, table, or block lies outside the space it names.
    OutOfRange,
    /// The root field names no block.
    RootBlock,
    /// A `Meta` pointer names a block or offset the table does not hold.
    Pointer,
    /// A read fell outside the data block it was made in.
    DataRange,
    /// A member's value does not lie inside the structure that declares it.
    MemberExtent,
    /// A structure a pointer or a member reaches is not one the file defines.
    UndefinedStructure,
    /// An array's elements are declared no bytes wide.
    ZeroStride,
    /// An array member's `arrayInfoIndex` names no member of its structure.
    ArrayInfo,
    /// Structures nested deeper than this walk goes.
    TooDeep,
    /// The walk wrote more elements than a payload of this size may write.
    TooManyNodes,
    /// The document grew past what a payload of this size is allowed to write.
    TooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::metadata::hash::placeholder;

    struct Payload(Vec<u8>);

    impl Payload {
        fn of(len: usize) -> Self {
            Self(vec![0; len])
        }

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

    fn system(offset: u32) -> u64 {
        u64::from(SYSTEM_SPACE << SPACE_SHIFT) | u64::from(offset)
    }

    fn graphics(offset: u32) -> u64 {
        u64::from(GRAPHICS_SPACE << SPACE_SHIFT) | u64::from(offset)
    }

    fn data_pointer(id: u64, offset: u64) -> u64 {
        (offset << ITEM_SHIFT) | id
    }

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

    fn whole() -> Payload {
        let mut payload = bare(0x100);
        payload
            .u64(0x20, system(0x50))
            .u64(0x28, system(0x80))
            .u64(0x30, system(0xA0))
            .u16(0x48, 1)
            .u16(0x4A, 1)
            .u16(0x4C, 1)
            .u32(0x50, 0x1111_1111)
            .u32(0x54, 0x2222_2222)
            .u32(0x58, 0x300)
            .u64(0x60, system(0x70))
            .u32(0x68, 0x40)
            .u16(0x6E, 1)
            .u32(0x70, 0x3333_3333)
            .u32(0x74, 0x0000_0010)
            .put(0x78, &[0x07, 0x04])
            .u16(0x7A, 2)
            .u32(0x7C, 0x4444_4444)
            .u32(0x80, 0x5555_5555)
            .u32(0x84, 0x6666_6666)
            .u64(0x88, system(0x98))
            .u32(0x90, 1)
            .u32(0x98, 0x7777_7777)
            .u32(0x9C, 42)
            .u32(0xA0, 0x1111_1111)
            .u32(0xA4, 0x10)
            .u64(0xA8, system(0xB0))
            .u32(0xB0, 0xABAD_1DEA);
        payload
    }

    #[track_caller]
    fn refusal(error: &Error) -> Malformed {
        match *error {
            Error::BadMeta { cause, .. } => cause,
            ref other => panic!("not a Meta refusal: {other}"),
        }
    }

    #[track_caller]
    fn refused_at(error: &Error) -> u64 {
        match *error {
            Error::BadMeta { offset, .. } => offset,
            ref other => panic!("not a Meta refusal: {other}"),
        }
    }

    #[test]
    fn the_magic_is_the_word_the_format_document_records_at_0x10() {
        assert_eq!(MAGIC, 0x5052_4430);
        assert_eq!(MAGIC_AT, 0x10);
        let payload = bare(HEADER_LEN);
        assert!(identifies(payload.bytes()));
        let mut moved = Payload::of(HEADER_LEN);
        moved.u32(0, MAGIC);
        assert!(!identifies(moved.bytes()));
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
        assert_eq!(pointer.word(), 0x5000_1234);
        let pointer = ResourcePointer::wide(graphics(0x0FFF_FFFF)).expect("a 32-bit pointer");
        assert_eq!(pointer.space(), Some(Space::Graphics));
        assert_eq!(pointer.offset(), 0x0FFF_FFFF);
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
        assert_eq!(ResourcePointer::wide(1_u64 << 32), None);
        assert_eq!(ResourcePointer::wide(u64::MAX), None);
    }

    #[test]
    fn a_meta_pointer_is_a_block_id_and_an_item_offset() {
        let pointer = MetaPointer::wide(data_pointer(3, 128));
        assert_eq!(pointer.block().map(BlockId::get), Some(3));
        assert_eq!(pointer.item_offset(), 128);
        for (word, offset) in [(0x3, 0), (0x8_0003, 128), (0x10_0003, 256)] {
            let pointer = MetaPointer::wide(word);
            assert_eq!(pointer.block().map(BlockId::get), Some(3));
            assert_eq!(pointer.item_offset(), offset);
        }
        assert_ne!(MetaPointer::wide(0x10_0003).item_offset(), 16);
        assert!(MetaPointer::wide(data_pointer(0, 4096)).is_null());
        assert!(!MetaPointer::wide(data_pointer(3, 128)).is_null());
        assert_eq!(BlockId::new(0), None);
        assert_eq!(BlockId::new(BLOCK_MASK).map(BlockId::get), Some(4095));
        assert_eq!(BlockId::new(BLOCK_MASK + 1), None);
    }

    #[test]
    fn a_table_pointer_is_not_read_the_way_a_data_pointer_is() {
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
        let mut payload = bare(0x6000);
        payload
            .u64(0x30, system(0xA0))
            .u16(0x4C, 3)
            .u32(0xA0, 1)
            .u32(0xA4, 8)
            .u64(0xA8, system(0x200))
            .u32(0xB0, 2)
            .u32(0xB4, 8)
            .u64(0xB8, system(0x200))
            .u32(0xC0, 3)
            .u32(0xC4, 0x10)
            .u64(0xC8, system(0x300))
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
        assert_eq!(member.name, 0x3333_3333);
        assert_eq!(member.data_offset, 0x10);
        assert_eq!(member.type_code.get(), 0x07);
        assert_eq!(member.subtype, 0x04);
        assert_eq!(member.array_info_index, 2);
        assert_eq!(member.reference_key, 0x4444_4444);
        assert_eq!(structure.member(0), Some(member));
        assert_eq!(structure.member(1), None);

        assert_eq!(meta.enums().len(), 1);
        assert_eq!(meta.enums()[0].name, 0x5555_5555);
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

        let mut hollow = whole();
        hollow.u32(0xA4, 0);
        let meta = parse(hollow.bytes(), hollow.bytes().len()).expect("a whole file");
        assert_eq!(meta.root().len(), 0);
        assert!(meta.root().is_empty());
    }

    #[test]
    fn a_block_tag_is_a_structure_the_file_defines_or_a_bare_type_code() {
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

        assert_eq!(
            refusal(&parse(payload.bytes(), payload.bytes().len()).expect_err("no graphics pages")),
            Malformed::OutOfRange
        );
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

    fn whole_with_pointer(word: u64) -> Payload {
        let mut payload = whole();
        payload.u64(0xB0, word);
        payload
    }

    #[test]
    fn a_pointer_at_or_past_its_blocks_length_is_refused_rather_than_guessed_at() {
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
        let payload = whole_with_pointer(data_pointer(1, 0xF));
        let meta_file = parse(payload.bytes(), payload.bytes().len()).expect("a whole file");
        let block = meta_file.root();
        let landing = meta_file
            .landing(block.pointer(0).expect("a pointer"), block.address(0))
            .expect("it resolves")
            .expect("it is not null");
        assert_eq!(landing.bytes.len(), 1);
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
        let mut payload = whole();
        payload.u16(0x48, u16::MAX);
        assert_eq!(
            refusal(&parse(payload.bytes(), payload.bytes().len()).expect_err("no room")),
            Malformed::OutOfRange
        );
        let mut payload = whole();
        payload.u16(0x6E, u16::MAX);
        assert_eq!(
            refusal(&parse(payload.bytes(), payload.bytes().len()).expect_err("no room")),
            Malformed::OutOfRange
        );
        let mut payload = whole();
        payload.u32(0x90, u32::MAX);
        assert_eq!(
            refusal(&parse(payload.bytes(), payload.bytes().len()).expect_err("no room")),
            Malformed::OutOfRange
        );
    }

    #[test]
    fn a_table_of_no_records_needs_no_pointer() {
        let payload = bare(HEADER_LEN);
        let meta = parse(payload.bytes(), HEADER_LEN).expect_err("the root names no block");
        assert_eq!(refusal(&meta), Malformed::RootBlock);
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
        let ones = vec![0xFF_u8; 0x200];
        let _ = parse(&ones, 0x100);
    }

    #[test]
    fn the_headers_two_unnamed_pointers_have_to_land_in_the_space_they_name() {
        for at in [0x08_usize, 0x40] {
            let mut payload = bare(HEADER_LEN);
            payload.u64(at, system(0x100));
            let error = parse(payload.bytes(), HEADER_LEN).expect_err("past the system pages");
            assert_eq!(refusal(&error), Malformed::OutOfRange, "at {at:#x}");
            assert_eq!(refused_at(&error), address(at), "at {at:#x}");
        }
        let mut payload = whole();
        payload.u64(0x08, 0).u64(0x40, 0);
        parse(payload.bytes(), payload.bytes().len()).expect("null pointers name nothing");
        payload.u64(0x08, system(0x50)).u64(0x40, system(0xFF));
        parse(payload.bytes(), payload.bytes().len()).expect("both pointers land");
    }

    #[test]
    fn a_malformed_table_record_is_refused_at_its_own_address() {
        let mut structures = bare(0x200);
        structures
            .u64(0x20, system(0x100))
            .u16(0x48, 2)
            .u64(0x130, 1_u64 << 32);
        let error = parse(structures.bytes(), structures.bytes().len())
            .expect_err("the second structure's pointer is not one");
        assert_eq!(refusal(&error), Malformed::PointerWidth);
        assert_eq!(refused_at(&error), 0x120);

        let mut blocks = bare(0x200);
        blocks
            .u64(0x30, system(0x100))
            .u16(0x4C, 2)
            .u64(0x108, system(0x180))
            .u64(0x118, 1_u64 << 32);
        let error = parse(blocks.bytes(), blocks.bytes().len())
            .expect_err("the second block's pointer is not one");
        assert_eq!(refusal(&error), Malformed::PointerWidth);
        assert_eq!(refused_at(&error), 0x110);
    }

    fn pointer_cycle() -> Payload {
        let mut payload = bare(0x100);
        payload
            .u64(0x20, system(0x50))
            .u64(0x30, system(0xA0))
            .u16(0x48, 1)
            .u16(0x4C, 2)
            .u32(0x50, 0x1111_1111)
            .u32(0x54, 0x2222_2222)
            .u32(0x58, 0x300)
            .u64(0x60, system(0x70))
            .u32(0x68, 8)
            .u16(0x6E, 1)
            .u32(0x70, 0x3333_3333)
            .u32(0x74, 0)
            .put(0x78, &[0x07, 0x00])
            .u32(0xA0, 0x1111_1111)
            .u32(0xA4, 8)
            .u64(0xA8, system(0xC0))
            .u32(0xB0, 0x07)
            .u32(0xB4, 8)
            .u64(0xB8, system(0xC8))
            .u64(0xC0, data_pointer(2, 0))
            .u64(0xC8, data_pointer(2, 0));
        payload
    }

    fn pointer_cycle_document() -> Vec<u8> {
        let root = placeholder(0x1111_1111);
        let field = placeholder(0x3333_3333);
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <{root} meta:struct=\"{root}\">\n  <{field} meta:struct=\"{root}\"/>\n</{root}>\n"
        )
        .into_bytes()
    }

    #[test]
    fn a_pointer_hop_is_a_level_of_depth_so_a_block_naming_itself_is_refused() {
        let payload = pointer_cycle();
        let error = to_xml(
            payload.bytes(),
            payload.bytes().len(),
            &Dictionary::default(),
        )
        .expect_err("a block of pointers that names itself has no depth");
        assert_eq!(refusal(&error), Malformed::TooDeep);
    }

    #[test]
    fn applying_a_document_through_a_block_that_names_itself_is_refused_as_well() {
        let payload = pointer_cycle();
        let error = from_xml(
            payload.bytes(),
            payload.bytes().len(),
            &pointer_cycle_document(),
            &Dictionary::default(),
        )
        .expect_err("the write direction follows the same cycle the read direction does");
        assert_eq!(refusal(&error), Malformed::TooDeep);
    }
}
