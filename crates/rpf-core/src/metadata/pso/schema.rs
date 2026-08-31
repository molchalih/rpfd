//! The block table and the embedded schema, as types that carry their own
//! guarantees.
//!
//! `docs/metadata-encodings.md`, `PSO` — `PMAP` and `PSCH`. The whole of R5.3
//! rests on one measurement: a walk of all 9,753 files from `PMAP.rootId`,
//! using only each file's own `PSCH`, reached **0** references the file did not
//! define. So nothing here consults a builtin table, and there is none to
//! consult.
//!
//! What is checked at construction (`docs/conventions.md` §5) is everything a
//! later read would otherwise have to re-check: a block lies inside the data
//! section, the root names a block, a structure's length is not negative, an
//! array's element index names an `ARRAYINFO` member of its own structure, and
//! a wrapped `dataOffset` has been recovered. What is *not* checked here is
//! whether a referenced structure exists, because a `PSCH` legitimately
//! describes structures the data never instantiates — 36 such hashes across the
//! corpus, none ever reached.

use std::collections::BTreeMap;

use super::{
    bad,
    model::{ARRAYINFO, MAX_WRAPS, Malformed, NO_ENUM, Unsupported},
    section, unsupported,
};
use crate::error::Result;

/// How long an `ATBINARYMAP` member is.
///
/// Measured 2026-08-30 over the corpus: the map members of one structure are 24
/// bytes apart, and the layout is two `u32`s — `0x01000000` and `0`, in 17,560
/// of 17,560 instances — followed by the same 16-byte counted pointer an
/// `ATARRAY` uses.
pub(super) const MAP_LEN: u32 = 24;

/// Where an `ATBINARYMAP`'s counted pointer sits inside it.
pub(super) const MAP_POINTER_AT: u32 = 8;

/// How long the 16-byte counted forms are: `Array_Structure` and `CharPointer`.
///
/// `docs/metadata-encodings.md`, Pointers: the pointer, then `count1:u16be`,
/// `count2:u16be`, `unk:u32be`.
pub(super) const COUNTED_LEN: u32 = 16;

/// Where the first of a counted form's two counts sits inside it.
///
/// `count1` is the length and `count2` the capacity. They are equal for every
/// one of the 591,472 `ATARRAY`s in the corpus and differ for 35% of the
/// 112,515 `ATSTRING`s, so this reads the one that is the length.
pub(super) const COUNT_AT: u32 = 8;

/// Where the second of a counted form's two counts sits inside it.
///
/// `count2` is the capacity, and it is what bounds a write rather than what a
/// read answers: over all 39,469 counted strings the corpus reaches, the
/// characters number `min(count1, count2)` and the terminator is the byte
/// after. DR-052.
pub(super) const CAPACITY_AT: u32 = 10;

/// How long one `PMAP` entry is: `nameHash`, `offset`, `unknown_8h`, `length`.
const BLOCK_LEN: usize = 16;

/// How long one `PSCH` structure member is.
const MEMBER_LEN: usize = 12;

/// How long one `PSCH` index entry is: `nameHash` and `offset`.
const INDEX_LEN: usize = 8;

/// How long one enum entry is: `entryNameHash` and `entryKey`.
const ENUM_ENTRY_LEN: usize = 8;

/// Where a structure entry's members begin: after the packed word, the
/// structure length and `unk_Ch`.
const MEMBERS_AT: usize = 12;

/// Where an enum entry's own entries begin: after its packed word.
const ENUM_ENTRIES_AT: usize = 4;

/// Where a `PSCH` section's index begins: after the tag, the length and the
/// count.
const INDEX_AT: usize = 12;

/// Where a `PMAP` section's entries begin: after the tag, the length, the root
/// id, the count and `unknown_Eh`.
const BLOCKS_AT: usize = 16;

/// How long a pointer is: 32 bits of block and offset, and a second word that
/// carries nothing.
///
/// `docs/metadata-encodings.md`, Pointers: read as one big-endian `u64` with
/// the block id in the low bits — the shape the reference implementation's
/// field layout suggests — **every** pointer in the corpus reads as null.
pub(super) const POINTER_LEN: u32 = 8;

/// How long a hashed string is: the `u32` hash and nothing else.
pub(super) const HASH_LEN: u32 = 4;

/// How deep [`Schema::extent`] follows an inline array of an inline array.
///
/// An element descriptor is an index into the same member list, so a hostile
/// schema can point one at itself. The corpus reaches 2.
const MAX_ELEMENT_NESTING: usize = 8;

/// How far one wrap moves a `dataOffset`: the width of the `u16` field it is.
///
/// `docs/metadata-encodings.md`, `ARRAY` subtype `0x81`.
const WRAP: u32 = 0x1_0000;

/// One `PMAP` entry: a run of the data section with a type tag.
#[derive(Debug, Clone, Copy)]
pub(super) struct Block {
    /// Its `nameHash`: a structure name, or one of the eight plain-data type
    /// tags `docs/metadata-encodings.md` lists.
    pub(super) name: u32,
    /// Where it starts, from the start of the `PSIN` section, header included.
    pub(super) offset: u32,
    /// How long it is.
    pub(super) length: u32,
}

/// The `PMAP` block table, with its root already resolved.
#[derive(Debug, Clone)]
pub(super) struct Blocks {
    entries: Vec<Block>,
    root: Block,
}

impl Blocks {
    /// Reads the block table, checking every block against the data section.
    ///
    /// `docs/metadata-encodings.md`, `PMAP`: the 16-byte header variant is the
    /// only one that occurs — 9,753 of 9,753 — so `CodeWalker`'s second layout,
    /// detected by `entriesCount <= 0` under `//any other way to know which
    /// version?`, is not implemented and an empty table is an empty table.
    ///
    /// # Errors
    ///
    /// [`Malformed::BlockRange`] for an entry that is not inside `data_len`,
    /// and [`Malformed::RootId`] when the root names no block.
    pub(super) fn read(section: &[u8], data_len: u32) -> Result<Self> {
        let root_id =
            section::i32(section, 8).ok_or_else(|| bad(8, Malformed::SectionTruncated))?;
        let count = section::i16(section, 12)
            .ok_or_else(|| bad(12, Malformed::SectionTruncated))?
            .max(0);
        let count = usize::try_from(count).unwrap_or(0);
        let mut entries = Vec::new();
        for index in 0..count {
            let base = index
                .checked_mul(BLOCK_LEN)
                .and_then(|step| step.checked_add(BLOCKS_AT))
                .ok_or_else(|| bad(0, Malformed::Section))?;
            entries.push(read_block(section, base, data_len)?);
        }
        let root = usize::try_from(root_id)
            .ok()
            .and_then(|id| id.checked_sub(1))
            .and_then(|index| entries.get(index).copied())
            .ok_or_else(|| bad(8, Malformed::RootId))?;
        Ok(Self { entries, root })
    }

    /// The block a 1-based id names, or `None`.
    pub(super) fn get(&self, id: u32) -> Option<&Block> {
        let index = usize::try_from(id).ok()?.checked_sub(1)?;
        self.entries.get(index)
    }

    /// The root block, which exists because the constructor checked it.
    pub(super) const fn root(&self) -> &Block {
        &self.root
    }
}

/// Reads one 16-byte `PMAP` entry and checks it against the data section.
fn read_block(section: &[u8], base: usize, data_len: u32) -> Result<Block> {
    let at = u64::try_from(base).unwrap_or(u64::MAX);
    let truncated = || bad(at, Malformed::SectionTruncated);
    let name = section::u32(section, base).ok_or_else(truncated)?;
    let offset = section::i32(section, base.saturating_add(4)).ok_or_else(truncated)?;
    let length = section::i32(section, base.saturating_add(12)).ok_or_else(truncated)?;
    let range = || bad(at, Malformed::BlockRange);
    let offset = u32::try_from(offset).map_err(|_| range())?;
    let length = u32::try_from(length).map_err(|_| range())?;
    if offset.checked_add(length).is_none_or(|end| end > data_len) {
        return Err(range());
    }
    Ok(Block {
        name,
        offset,
        length,
    })
}

/// How wide an enum or a bitset is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Width {
    /// Subtype 2, one byte.
    Eight,
    /// Subtype 1, two bytes.
    Sixteen,
    /// Subtype 0, four bytes.
    ThirtyTwo,
}

impl Width {
    /// How many bytes it occupies.
    pub(super) const fn bytes(self) -> u32 {
        match self {
            Self::Eight => 1,
            Self::Sixteen => 2,
            Self::ThirtyTwo => 4,
        }
    }

    /// The width a subtype names, or `None` for one that is not a width.
    const fn of(subtype: u8) -> Option<Self> {
        match subtype {
            0 => Some(Self::ThirtyTwo),
            1 => Some(Self::Sixteen),
            2 => Some(Self::Eight),
            _ => None,
        }
    }
}

/// Which of the six `STRING` subtypes a member is.
///
/// `docs/metadata-encodings.md`: exactly these six occur, over 77,431 string
/// members, and 0 fall through. Subtype 9 `ATHASHVALUE` — the one predicted to
/// be the commonest string kind — does not occur at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Text {
    /// Subtype 0, a fixed inline character array of this many bytes.
    Member(u16),
    /// Subtype 1, a pointer to NUL-terminated bytes.
    Pointer,
    /// Subtype 2, the same shape under a different name.
    ConstString,
    /// Subtype 3, a 16-byte counted form: pointer, length, capacity.
    AtString,
    /// Subtype 7, a `u32` hash.
    AtNonFinalHashString,
    /// Subtype 8, a `u32` hash.
    AtFinalHashString,
}

impl Text {
    /// The word the XML writes for it.
    pub(super) const fn word(self) -> &'static str {
        match self {
            Self::Member(_) => "string",
            Self::Pointer => "string.pointer",
            Self::ConstString => "string.const",
            Self::AtString => "string.counted",
            Self::AtNonFinalHashString => "hashstring",
            Self::AtFinalHashString => "hashstring.final",
        }
    }
}

/// Which of the three `STRUCT` subtypes a member is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Nested {
    /// Subtype 0, the structure inline at the member's own offset.
    Structure(u32),
    /// Subtype 3, a pointer. Its type is the target block's `nameHash`.
    Pointer,
    /// Subtype 4, a pointer that behaves identically here.
    SimplePointer,
}

/// Which of the six `ARRAY` subtypes a member is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Layout {
    /// Subtype 0, a 16-byte counted pointer. 59,811 of 64,906.
    AtArray,
    /// Subtype 1, elements inline at the member's own offset.
    AtFixedArray,
    /// Subtype 2, the same, under a different name.
    AtRangeArray,
    /// Subtype 4, the same again.
    Member,
    /// Subtype 6, an 8-byte pointer with the count in the schema.
    ///
    /// **`secondary`, and the only thing here that is.** The two members that
    /// carry it sit at byte 40 of a 64-byte structure whose next member is at
    /// 48, so the member is eight bytes and cannot hold the 16-byte counted
    /// form; the count is `referenceKey >> 16`. But the data walk never reaches
    /// either of them — 0 occurrences across all 9,753 rendered documents,
    /// measured 2026-08-30 — so this is read from the layout rather than
    /// confirmed against a value.
    PointerWithCount,
    /// Subtype `0x81`: inline, at a `dataOffset` that has wrapped past 16 bits.
    Wrapped,
}

impl Layout {
    /// Whether the elements lie at the member's own offset.
    pub(super) const fn is_inline(self) -> bool {
        matches!(
            self,
            Self::AtFixedArray | Self::AtRangeArray | Self::Member | Self::Wrapped
        )
    }

    /// The word the XML writes for it.
    pub(super) const fn word(self) -> &'static str {
        match self {
            Self::AtArray => "atarray",
            Self::AtFixedArray => "atfixedarray",
            Self::AtRangeArray => "atrangearray",
            Self::Member => "member",
            Self::PointerWithCount => "pointerwithcount",
            Self::Wrapped => "wrapped",
        }
    }
}

/// A fixed-width value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Scalar {
    Bool,
    Char,
    UChar,
    Short,
    UShort,
    Int,
    Uint,
    Color,
    Float,
    Vector2,
    Vector3,
    Vector4,
    Vec3V,
    Vec4V,
    Float16,
    Uint64,
}

impl Scalar {
    /// How many bytes it occupies.
    ///
    /// `docs/metadata-encodings.md`'s census, and the sizes the corpus walk
    /// used: a `VECTOR3` is **sixteen** bytes carrying three floats, not
    /// twelve.
    pub(super) const fn bytes(self) -> u32 {
        match self {
            Self::Bool | Self::Char | Self::UChar => 1,
            Self::Short | Self::UShort | Self::Float16 => 2,
            Self::Int | Self::Uint | Self::Color | Self::Float => 4,
            Self::Vector2 | Self::Uint64 => 8,
            Self::Vector3 | Self::Vector4 | Self::Vec3V | Self::Vec4V => 16,
        }
    }

    /// The word the XML writes for it.
    pub(super) const fn word(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::Char => "char",
            Self::UChar => "uchar",
            Self::Short => "short",
            Self::UShort => "ushort",
            Self::Int => "int",
            Self::Uint => "uint",
            Self::Color => "color",
            Self::Float => "float",
            Self::Vector2 => "float2",
            Self::Vector3 => "float3",
            Self::Vector4 => "float4",
            Self::Vec3V => "vec3v",
            Self::Vec4V => "vec4v",
            Self::Float16 => "float16",
            Self::Uint64 => "uint64",
        }
    }
}

/// What a member holds, with everything the schema can settle already settled.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum Kind {
    /// A fixed-width value that is its own description.
    Scalar(Scalar),
    /// One of the six string forms.
    Text(Text),
    /// A nested structure, inline or through a pointer.
    Nested(Nested),
    /// An array. `element` indexes the `ARRAYINFO` member that describes one
    /// element, and `count` is the schema's count for the inline forms.
    Array {
        /// How the elements are reached.
        layout: Layout,
        /// Which member of this structure describes one element.
        element: u16,
        /// How many, for the forms whose count is in the schema.
        count: u16,
    },
    /// An enum, resolved through the file's own enum table.
    Enumerated {
        /// How wide the stored value is.
        width: Width,
        /// Which enum table names it.
        table: u32,
    },
    /// A bitset, whose bits an enum names.
    ///
    /// `docs/metadata-encodings.md`: a `BITSET`'s `referenceKey` is **never** an
    /// enum hash — 0 of 1,526 — it is `(bitCount << 16) | memberIndex` through
    /// the `ARRAYINFO` indirection, and index `0xFFF` is a "no enum" sentinel
    /// rather than an index.
    /// The high half of the reference is a bit count, and it is not needed to
    /// render one: every set bit is written, named or numbered, so the value
    /// survives whatever the count says.
    Bits {
        /// How wide the stored value is.
        width: Width,
        /// Which enum table names its bits, when one does.
        table: Option<u32>,
    },
    /// An `ATBINARYMAP`: a 24-byte header whose counted pointer lands on an
    /// array of key/value structures.
    Map,
}

/// One member of a structure.
#[derive(Debug, Clone, Copy)]
pub(super) struct Member {
    /// Its name hash, or [`ARRAYINFO`] when it describes another member's
    /// element type rather than a field.
    pub(super) name: u32,
    /// Its byte offset within the structure, wrapping already recovered.
    pub(super) offset: u32,
    /// What it holds.
    pub(super) kind: Kind,
}

impl Member {
    /// Whether it describes another member's element type rather than a field.
    pub(super) const fn is_arrayinfo(&self) -> bool {
        self.name == ARRAYINFO
    }
}

/// One structure of the embedded schema.
#[derive(Debug, Clone)]
pub(super) struct Structure {
    /// How long one instance is.
    pub(super) length: u32,
    /// Its members, in schema order, `ARRAYINFO` members included.
    pub(super) members: Vec<Member>,
}

/// A file's whole embedded schema: its structures and its enums.
///
/// A name hash indexes what the entry at a `PSCH` offset holds rather than
/// owning a copy of it, because several index entries may carry different name
/// hashes and name the **same** entry offset. Measured 2026-08-30: a file that
/// does that buys a whole member list per 8 bytes of index, which is how 64,520
/// bytes of schema came to hold 160 MB and return `Ok`.
#[derive(Debug, Clone, Default)]
pub(super) struct Schema {
    defined: Vec<Structure>,
    tables: Vec<BTreeMap<i32, u32>>,
    structures: BTreeMap<u32, usize>,
    enums: BTreeMap<u32, usize>,
}

/// The entries already read, by the offset they were read from.
///
/// What makes an index entry naming an offset already read cost one map entry
/// rather than another copy of everything at that offset.
#[derive(Debug, Default)]
struct Shared {
    structures: BTreeMap<usize, usize>,
    enums: BTreeMap<usize, usize>,
    /// Where each structure in [`Schema::defined`] was read from, in the same
    /// order, so that a refusal recovery makes can say which entry it is about.
    origins: Vec<u64>,
}

impl Schema {
    /// The structure this name hash describes, or `None`.
    pub(super) fn structure(&self, name: u32) -> Option<&Structure> {
        self.defined.get(*self.structures.get(&name)?)
    }

    /// Every value an enum table names, in key order.
    ///
    /// The inverse [`super::apply`] needs: rendering goes value to name and a
    /// document carries the name, so the write direction has to search. Handed
    /// out whole rather than searched here, because deciding which of two keys
    /// a rendered name belongs to needs the dictionary, and the schema does not
    /// have one.
    pub(super) fn enum_table(&self, table: u32) -> Option<&BTreeMap<i32, u32>> {
        self.tables.get(*self.enums.get(&table)?)
    }

    /// The name an enum table gives a stored value, or `None`.
    pub(super) fn enumerated(&self, table: u32, value: i32) -> Option<u32> {
        self.tables
            .get(*self.enums.get(&table)?)?
            .get(&value)
            .copied()
    }

    /// Reads a `PSCH` section, then resolves what needs the whole schema.
    ///
    /// # Errors
    ///
    /// [`Malformed::SchemaEntry`] for an entry that does not resolve,
    /// [`Malformed::Wrapped`] for a wrapped `dataOffset` the structure does not
    /// settle, and [`Unsupported::DataType`] for a member outside the 37 pairs
    /// the corpus carries.
    pub(super) fn read(section: &[u8]) -> Result<Self> {
        let count = section::u32(section, 8).ok_or_else(|| bad(8, Malformed::SectionTruncated))?;
        let count = usize::try_from(count).unwrap_or(0);
        let mut schema = Self::default();
        let mut shared = Shared::default();
        for index in 0..count {
            let slot = index
                .checked_mul(INDEX_LEN)
                .and_then(|step| step.checked_add(INDEX_AT))
                .ok_or_else(|| bad(0, Malformed::SchemaEntry))?;
            let at = u64::try_from(slot).unwrap_or(u64::MAX);
            let name =
                section::u32(section, slot).ok_or_else(|| bad(at, Malformed::SectionTruncated))?;
            let offset = section::i32(section, slot.saturating_add(4))
                .ok_or_else(|| bad(at, Malformed::SectionTruncated))?;
            let offset = usize::try_from(offset).map_err(|_| bad(at, Malformed::SchemaEntry))?;
            schema.read_entry(section, name, offset, &mut shared)?;
        }
        schema.recover_wrapped_offsets(&shared.origins)?;
        Ok(schema)
    }

    /// Reads one `PSCH` entry: a structure, or an enum.
    fn read_entry(
        &mut self,
        section: &[u8],
        name: u32,
        offset: usize,
        shared: &mut Shared,
    ) -> Result<()> {
        let at = u64::try_from(offset).unwrap_or(u64::MAX);
        let packed =
            section::u32(section, offset).ok_or_else(|| bad(at, Malformed::SchemaEntry))?;
        match packed >> 24 {
            0 => {
                let slot = if let Some(slot) = shared.structures.get(&offset) {
                    *slot
                } else {
                    let structure = read_structure(section, offset, packed)?;
                    self.defined.push(structure);
                    shared.origins.push(at);
                    let slot = self.defined.len().saturating_sub(1);
                    shared.structures.insert(offset, slot);
                    slot
                };
                self.structures.insert(name, slot);
                Ok(())
            }
            1 => {
                let slot = if let Some(slot) = shared.enums.get(&offset) {
                    *slot
                } else {
                    let table = read_enum(section, offset, packed)?;
                    self.tables.push(table);
                    let slot = self.tables.len().saturating_sub(1);
                    shared.enums.insert(offset, slot);
                    slot
                };
                self.enums.insert(name, slot);
                Ok(())
            }
            _ => Err(bad(at, Malformed::SchemaEntry)),
        }
    }

    /// Puts every wrapped `dataOffset` back where it belongs.
    ///
    /// `docs/metadata-encodings.md`, `ARRAY` subtype `0x81`: bit 7 of the
    /// subtype marks a `dataOffset` that has wrapped past the 16 bits the field
    /// has, and one flag bit cannot say how many times. Measured 2026-08-30:
    /// the multiple is recovered **uniquely** by the two constraints the
    /// structure itself imposes — the member begins at or after the end of the
    /// member before it, and its own extent fits inside the structure. On the
    /// one real case, a member of `junctions.pso` whose field holds `0x99B0` in
    /// a structure 170,688 bytes long, exactly one multiple satisfies both, and
    /// it is the 2 that puts the elements at 170,416, which is where they are.
    ///
    /// Needs the whole schema, because the preceding member's extent may be an
    /// inline array of a structure defined later in the index. A member the two
    /// constraints do not settle is [`Malformed::Wrapped`] rather than left as
    /// it lies: the raw `u16` is a real offset inside the structure, so leaving
    /// it renders whatever happens to be there — the `0x99B0` that reads
    /// `0.0, 0.0, 0.0` where coordinates are — and nothing about that is
    /// visible in the output.
    fn recover_wrapped_offsets(&mut self, origins: &[u64]) -> Result<()> {
        for slot in 0..self.defined.len() {
            let Some(structure) = self.defined.get(slot) else {
                continue;
            };
            let at = origins.get(slot).copied().unwrap_or(0);
            let mut recovered = Vec::new();
            for (index, member) in structure.members.iter().enumerate() {
                if matches!(
                    member.kind,
                    Kind::Array {
                        layout: Layout::Wrapped,
                        ..
                    }
                ) {
                    recovered.push((index, self.unwrapped(structure, index, at)?));
                }
            }
            let Some(structure) = self.defined.get_mut(slot) else {
                continue;
            };
            for (index, offset) in recovered {
                if let Some(member) = structure.members.get_mut(index) {
                    member.offset = offset;
                }
            }
        }
        Ok(())
    }

    /// The offset a wrapped member really has.
    ///
    /// Both constraints are monotone in the multiple, so the first and the last
    /// that fit are arithmetic rather than a search over all [`MAX_WRAPS`] of
    /// them: a member no multiple fits used to cost 65,536 iterations, which is
    /// how 8 KB of schema came to cost 6.8 seconds.
    ///
    /// # Errors
    ///
    /// [`Malformed::Wrapped`] when no multiple fits, and when more than one
    /// does. `docs/metadata-encodings.md`'s argument that this recovery is
    /// correct is that the two constraints settle the multiple **uniquely**, so
    /// a structure in which they do not is one that argument does not cover.
    fn unwrapped(&self, structure: &Structure, index: usize, at: u64) -> Result<u32> {
        let refuse = || bad(at, Malformed::Wrapped);
        let step = u64::from(WRAP);
        let member = structure.members.get(index).ok_or_else(refuse)?;
        let base = u64::from(member.offset);
        let extent = u64::from(self.extent(structure, member, 0).ok_or_else(refuse)?);
        let after = u64::from(self.member_ends_at(structure, index));
        let ceiling = u64::from(structure.length)
            .checked_sub(extent)
            .and_then(|top| top.checked_sub(base))
            .ok_or_else(refuse)?;
        let first = after.saturating_sub(base).div_ceil(step);
        let last = ceiling.checked_div(step).ok_or_else(refuse)?;
        if first != last || last > u64::from(MAX_WRAPS) {
            return Err(refuse());
        }
        let recovered = first
            .checked_mul(step)
            .and_then(|moved| base.checked_add(moved))
            .ok_or_else(refuse)?;
        u32::try_from(recovered).map_err(|_| refuse())
    }

    /// Where the member before `index` ends, which is the lowest offset the
    /// member at `index` may have.
    ///
    /// A preceding member whose extent the schema does not settle contributes
    /// its own offset rather than nothing: it is where that member starts, so
    /// the member after it cannot begin earlier, and it is the strongest bound
    /// available. Falling back to 0 instead would make multiple 0 satisfy the
    /// constraint always, which is the constraint not being applied.
    fn member_ends_at(&self, structure: &Structure, index: usize) -> u32 {
        structure
            .members
            .get(..index)
            .unwrap_or_default()
            .iter()
            .rev()
            .find(|earlier| !earlier.is_arrayinfo())
            .map_or(0, |earlier| {
                earlier
                    .offset
                    .saturating_add(self.extent(structure, earlier, 0).unwrap_or(0))
            })
    }

    /// How many bytes one instance of `member` occupies inside `owner`.
    ///
    /// `None` when the schema does not settle it: a structure it does not
    /// define, or element descriptors nested past
    /// [`MAX_ELEMENT_NESTING`].
    pub(super) fn extent(&self, owner: &Structure, member: &Member, depth: usize) -> Option<u32> {
        if depth > MAX_ELEMENT_NESTING {
            return None;
        }
        match member.kind {
            Kind::Scalar(scalar) => Some(scalar.bytes()),
            Kind::Text(Text::Member(len)) => Some(u32::from(len)),
            Kind::Text(Text::AtString) => Some(COUNTED_LEN),
            Kind::Text(Text::AtNonFinalHashString | Text::AtFinalHashString) => Some(HASH_LEN),
            Kind::Nested(Nested::Structure(name)) => {
                self.structure(name).map(|structure| structure.length)
            }
            Kind::Text(Text::Pointer | Text::ConstString) | Kind::Nested(_) => Some(POINTER_LEN),
            Kind::Enumerated { width, .. } | Kind::Bits { width, .. } => Some(width.bytes()),
            Kind::Map => Some(MAP_LEN),
            Kind::Array {
                layout,
                element,
                count,
            } => self.array_extent(owner, layout, element, count, depth),
        }
    }

    /// [`Schema::extent`] for the array forms.
    fn array_extent(
        &self,
        owner: &Structure,
        layout: Layout,
        element: u16,
        count: u16,
        depth: usize,
    ) -> Option<u32> {
        if !layout.is_inline() {
            return Some(match layout {
                Layout::PointerWithCount => POINTER_LEN,
                _ => COUNTED_LEN,
            });
        }
        let described = owner.members.get(usize::from(element))?;
        let stride = self.extent(owner, described, depth.saturating_add(1))?;
        u32::from(count).checked_mul(stride)
    }
}

/// Reads one structure entry and its members.
fn read_structure(section: &[u8], offset: usize, packed: u32) -> Result<Structure> {
    let at = u64::try_from(offset).unwrap_or(u64::MAX);
    let count = usize::try_from(packed & 0xFFFF).unwrap_or(0);
    let length = section::i32(section, offset.saturating_add(4))
        .ok_or_else(|| bad(at, Malformed::SectionTruncated))?;
    let length = u32::try_from(length).map_err(|_| bad(at, Malformed::StructureLength))?;
    let mut raw = Vec::with_capacity(count.min(1 << 16));
    for index in 0..count {
        let base = index
            .checked_mul(MEMBER_LEN)
            .and_then(|step| step.checked_add(MEMBERS_AT))
            .and_then(|step| step.checked_add(offset))
            .ok_or_else(|| bad(at, Malformed::SchemaEntry))?;
        raw.push(read_member(section, base)?);
    }
    let members = resolve(&raw, at)?;
    Ok(Structure { length, members })
}

/// A member as the twelve bytes give it, before its kind is worked out.
#[derive(Debug, Clone, Copy)]
struct Raw {
    name: u32,
    code: u8,
    subtype: u8,
    offset: u16,
    reference: u32,
}

/// Reads the twelve bytes of one member.
///
/// `referenceKey` is at offset **8**, not 10. `docs/metadata-encodings.md`:
/// getting this wrong shifts every reference by two bytes and leaves member
/// types and offsets looking plausible while every hash is garbage, which is
/// how it was found.
fn read_member(section: &[u8], base: usize) -> Result<Raw> {
    let at = u64::try_from(base).unwrap_or(u64::MAX);
    let truncated = || bad(at, Malformed::SectionTruncated);
    Ok(Raw {
        name: section::u32(section, base).ok_or_else(truncated)?,
        code: section::u8(section, base.saturating_add(4)).ok_or_else(truncated)?,
        subtype: section::u8(section, base.saturating_add(5)).ok_or_else(truncated)?,
        offset: section::u16(section, base.saturating_add(6)).ok_or_else(truncated)?,
        reference: section::u32(section, base.saturating_add(8)).ok_or_else(truncated)?,
    })
}

/// Turns the raw members of one structure into checked ones.
///
/// Two passes, because an element index points at another member of the same
/// list: the kinds are worked out first and the indices checked against the
/// finished list second.
fn resolve(raw: &[Raw], at: u64) -> Result<Vec<Member>> {
    let mut members = Vec::with_capacity(raw.len());
    for entry in raw {
        members.push(Member {
            name: entry.name,
            offset: u32::from(entry.offset),
            kind: kind_of(entry, raw)?,
        });
    }
    for member in &members {
        if let Kind::Array { element, .. } = member.kind
            && !members
                .get(usize::from(element))
                .is_some_and(Member::is_arrayinfo)
        {
            return Err(bad(at, Malformed::ArrayInfo));
        }
    }
    Ok(members)
}

/// What a member's twelve bytes describe.
///
/// `docs/metadata-encodings.md`'s census is the whole list: 37 `(type,
/// subtype)` pairs over 580,044 members, and a decoder that handles those
/// handles every metadata file both games ship.
fn kind_of(entry: &Raw, raw: &[Raw]) -> Result<Kind> {
    let refuse = || {
        unsupported(Unsupported::DataType {
            code: entry.code,
            subtype: entry.subtype,
        })
    };
    let scalar = |scalar: Scalar| Ok(Kind::Scalar(scalar));
    match (entry.code, entry.subtype) {
        (0x00, 0) => scalar(Scalar::Bool),
        (0x01, 0) => scalar(Scalar::Char),
        (0x02, 0) => scalar(Scalar::UChar),
        (0x03, 0) => scalar(Scalar::Short),
        (0x04, 0) => scalar(Scalar::UShort),
        (0x05, 0) => scalar(Scalar::Int),
        (0x06, 0) => scalar(Scalar::Uint),
        (0x06, 1) => scalar(Scalar::Color),
        (0x07, 0) => scalar(Scalar::Float),
        (0x08, 0) => scalar(Scalar::Vector2),
        (0x09, 0) => scalar(Scalar::Vector3),
        (0x0A, 0) => scalar(Scalar::Vector4),
        (0x14, 0) => scalar(Scalar::Vec3V),
        (0x15, 0) => scalar(Scalar::Vec4V),
        (0x1E, 0) => scalar(Scalar::Float16),
        (0x20, 0) => scalar(Scalar::Uint64),
        (0x0B, _) => text_of(entry.subtype, entry.reference).ok_or_else(refuse),
        (0x0C, 0) => Ok(Kind::Nested(Nested::Structure(entry.reference))),
        (0x0C, 3) => Ok(Kind::Nested(Nested::Pointer)),
        (0x0C, 4) => Ok(Kind::Nested(Nested::SimplePointer)),
        (0x0D, _) => array_of(entry.subtype, entry.reference).ok_or_else(refuse),
        (0x0E, _) => Width::of(entry.subtype)
            .map(|width| Kind::Enumerated {
                width,
                table: entry.reference,
            })
            .ok_or_else(refuse),
        (0x0F, _) => bits_of(entry.subtype, entry.reference, raw).ok_or_else(refuse),
        (0x10, 1) => Ok(Kind::Map),
        _ => Err(refuse()),
    }
}

/// The string form a subtype names.
fn text_of(subtype: u8, reference: u32) -> Option<Kind> {
    let text = match subtype {
        0 => Text::Member(u16::try_from(reference >> 16).ok()?),
        1 => Text::Pointer,
        2 => Text::ConstString,
        3 => Text::AtString,
        7 => Text::AtNonFinalHashString,
        8 => Text::AtFinalHashString,
        _ => return None,
    };
    Some(Kind::Text(text))
}

/// The array form a subtype names, with its element index and its count.
///
/// `docs/metadata-encodings.md`: the `0xFFFF` mask alone gives a valid
/// `ARRAYINFO` index in 64,906 of 64,906, so `CodeWalker`'s `0xFFF` re-mask
/// fallback is not here.
fn array_of(subtype: u8, reference: u32) -> Option<Kind> {
    let layout = match subtype {
        0 => Layout::AtArray,
        1 => Layout::AtFixedArray,
        2 => Layout::AtRangeArray,
        4 => Layout::Member,
        6 => Layout::PointerWithCount,
        0x81 => Layout::Wrapped,
        _ => return None,
    };
    Some(Kind::Array {
        layout,
        element: u16::try_from(reference & 0xFFFF).ok()?,
        count: u16::try_from(reference >> 16).ok()?,
    })
}

/// The bitset a subtype and a reference name.
fn bits_of(subtype: u8, reference: u32, raw: &[Raw]) -> Option<Kind> {
    let width = Width::of(subtype)?;
    let index = u16::try_from(reference & 0xFFFF).ok()?;
    let table = if index == NO_ENUM {
        None
    } else {
        raw.get(usize::from(index))
            .filter(|described| described.name == ARRAYINFO && described.code == 0x0E)
            .map(|described| described.reference)
    };
    Some(Kind::Bits { width, table })
}

/// Reads one enum entry into a value-to-name table.
fn read_enum(section: &[u8], offset: usize, packed: u32) -> Result<BTreeMap<i32, u32>> {
    let at = u64::try_from(offset).unwrap_or(u64::MAX);
    let count = usize::try_from(packed & 0x00FF_FFFF).unwrap_or(0);
    let mut table = BTreeMap::new();
    for index in 0..count {
        let base = index
            .checked_mul(ENUM_ENTRY_LEN)
            .and_then(|step| step.checked_add(ENUM_ENTRIES_AT))
            .and_then(|step| step.checked_add(offset))
            .ok_or_else(|| bad(at, Malformed::SchemaEntry))?;
        let here = u64::try_from(base).unwrap_or(u64::MAX);
        let truncated = || bad(here, Malformed::SectionTruncated);
        let name = section::u32(section, base).ok_or_else(truncated)?;
        let key = section::i32(section, base.saturating_add(4)).ok_or_else(truncated)?;
        table.entry(key).or_insert(name);
    }
    Ok(table)
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test code; clippy.toml's allow-*-in-tests settings have no \
              equivalent for this lint. docs/conventions.md §15"
)]
mod tests {
    use super::*;
    use crate::error::Error;

    /// The twelve bytes of one `PSCH` member.
    fn member(name: u32, code: u8, subtype: u8, offset: u16, reference: u32) -> [u8; 12] {
        let mut bytes = [0u8; 12];
        bytes[0..4].copy_from_slice(&name.to_be_bytes());
        bytes[4] = code;
        bytes[5] = subtype;
        bytes[6..8].copy_from_slice(&offset.to_be_bytes());
        bytes[8..12].copy_from_slice(&reference.to_be_bytes());
        bytes
    }

    /// A `PSCH` section whose `names` index entries **all** name the one
    /// structure that follows the index.
    fn psch(names: u32, members: &[[u8; 12]], length: i32) -> Vec<u8> {
        let count = usize::try_from(names).expect("a test count fits");
        let entry_at = INDEX_AT + count * INDEX_LEN;
        let mut out = Vec::from(*b"PSCH");
        let total = entry_at + MEMBERS_AT + members.len() * MEMBER_LEN;
        out.extend_from_slice(
            &u32::try_from(total)
                .expect("a test length fits")
                .to_be_bytes(),
        );
        out.extend_from_slice(&names.to_be_bytes());
        for name in 0..names {
            out.extend_from_slice(&(name + 1).to_be_bytes());
            out.extend_from_slice(&i32::try_from(entry_at).expect("fits").to_be_bytes());
        }
        out.extend_from_slice(
            &u32::try_from(members.len())
                .expect("a test member count fits")
                .to_be_bytes(),
        );
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        for entry in members {
            out.extend_from_slice(entry);
        }
        out
    }

    /// The three members a wrapped `dataOffset` needs around it: a long inline
    /// array, the wrapped member itself, and the `ARRAYINFO` both resolve
    /// through.
    fn wrapped_members() -> [[u8; 12]; 3] {
        [
            // 16,384 `UINT`s inline at 0, so the member after it starts at
            // 65,536 and multiple 0 cannot be the answer.
            member(1, 0x0D, 0x01, 0, (16_384 << 16) | 2),
            member(2, 0x0D, 0x81, 0, (1 << 16) | 2),
            member(ARRAYINFO, 0x06, 0x00, 0, 0),
        ]
    }

    /// The `cause` of a refusal, or a panic naming what was got instead.
    fn cause(section: &[u8]) -> Malformed {
        match Schema::read(section) {
            Err(Error::BadPso { cause, .. }) => cause,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn many_index_entries_naming_one_offset_store_one_structure() {
        // The measured defect: `Schema::read` inserted a whole `Structure` per
        // index entry, and several entries may carry different name hashes and
        // point at the same offset. 8 bytes of index bought a whole member
        // list, which is how 64,520 bytes of schema came to hold 160 MB and
        // return `Ok`.
        let members: Vec<[u8; 12]> = (0..500)
            .map(|index| member(index, 0x06, 0x00, 0, 0))
            .collect();
        let section = psch(7_000, &members, 4);
        let schema = Schema::read(&section).expect("a well-formed schema");
        assert_eq!(schema.structures.len(), 7_000, "every name resolves");
        assert_eq!(
            schema.defined.len(),
            1,
            "and they resolve to one shared structure, not 7,000 copies of it"
        );
        assert_eq!(schema.structure(1).map(|one| one.members.len()), Some(500));
        assert_eq!(
            schema.structure(7_000).map(|one| one.members.len()),
            Some(500)
        );
    }

    #[test]
    fn many_index_entries_naming_one_enum_store_one_table() {
        // The same shape one entry kind over: an enum entry is 8 bytes and a
        // duplicate index entry re-read the whole table.
        let mut section = Vec::from(*b"PSCH");
        let entries: u32 = 4_000;
        let count = usize::try_from(entries).expect("fits");
        let entry_at = INDEX_AT + count * INDEX_LEN;
        section.extend_from_slice(
            &u32::try_from(entry_at + 4 + ENUM_ENTRY_LEN * 8)
                .expect("fits")
                .to_be_bytes(),
        );
        section.extend_from_slice(&entries.to_be_bytes());
        for name in 0..entries {
            section.extend_from_slice(&(name + 1).to_be_bytes());
            section.extend_from_slice(&i32::try_from(entry_at).expect("fits").to_be_bytes());
        }
        section.extend_from_slice(&0x0100_0008u32.to_be_bytes()); // kind 1, eight entries
        for value in 0..8i32 {
            section.extend_from_slice(
                &(0x1000u32 + u32::try_from(value).expect("fits")).to_be_bytes(),
            );
            section.extend_from_slice(&value.to_be_bytes());
        }
        let schema = Schema::read(&section).expect("a well-formed schema");
        assert_eq!(schema.enums.len(), 4_000);
        assert_eq!(schema.tables.len(), 1);
        assert_eq!(schema.enumerated(1, 3), Some(0x1003));
        assert_eq!(schema.enumerated(4_000, 3), Some(0x1003));
    }

    #[test]
    fn a_wrapped_offset_exactly_one_multiple_fits_is_recovered() {
        // `docs/metadata-encodings.md`, `ARRAY` subtype `0x81`. The member
        // before it ends at 65,536 and its own four bytes must fit inside a
        // structure 70,000 bytes long, so multiple 1 is the only one and the
        // raw 0 is really 65,536.
        let section = psch(1, &wrapped_members(), 70_000);
        let schema = Schema::read(&section).expect("the multiple is unique");
        let structure = schema.structure(1).expect("the structure is defined");
        assert_eq!(structure.members[1].offset, 65_536);
    }

    #[test]
    fn a_wrapped_offset_no_multiple_fits_is_refused_rather_than_left_as_it_lies() {
        // Leaving the raw `u16` is what the reference implementation does, and
        // it is silent: the field holds a real offset inside the structure, so
        // the read succeeds and renders whatever is there. 65,000 bytes is too
        // short for any multiple to clear the member before it.
        assert_eq!(
            cause(&psch(1, &wrapped_members(), 65_000)),
            Malformed::Wrapped
        );
    }

    #[test]
    fn a_wrapped_offset_more_than_one_multiple_fits_is_refused_rather_than_guessed() {
        // The whole of `docs/metadata-encodings.md`'s argument that this
        // recovery is correct is that the two constraints settle the multiple
        // **uniquely**. At 140,000 bytes both 1 and 2 fit, so this structure is
        // not one that argument covers and taking the first would be a guess.
        assert_eq!(
            cause(&psch(1, &wrapped_members(), 140_000)),
            Malformed::Wrapped
        );
    }

    #[test]
    fn a_schema_of_nothing_but_duplicates_costs_its_own_size_and_not_more() {
        // The measured defect at the size it was measured at: 4,000 index
        // entries and one 2,750-member structure is 64,024 bytes, and copying
        // the structure per entry made that 11,000,000 members — +160 MB of
        // resident memory, and `Ok`. `fuzz/src/lib.rs` holds a 64 KiB input to
        // 64 MiB, so this shape was 2.5 times past this project's own standard.
        //
        // The bound is wall-clock and generous on purpose: it is a regression
        // detector rather than a benchmark, and what it detects is a copy that
        // is quadratic in the input rather than linear.
        let members: Vec<[u8; 12]> = (0..2_750)
            .map(|index| member(index, 0x06, 0x00, 0, 0))
            .collect();
        let section = psch(4_000, &members, 4);
        assert_eq!(section.len(), 65_024);
        let started = std::time::Instant::now();
        let schema = Schema::read(&section).expect("a well-formed schema");
        assert_eq!(schema.defined.len(), 1);
        assert_eq!(schema.structures.len(), 4_000);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "{:?} to read 64 KB of schema is a copy per index entry",
            started.elapsed()
        );
    }
}
