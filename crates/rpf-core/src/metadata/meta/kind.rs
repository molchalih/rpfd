//! What a member's type code means, what a document calls it, and the ceilings
//! a walk of one obeys.
//!
//! # The type table is measured, and this is the only place it is written
//!
//! `docs/metadata-encodings.md` counted **23 distinct type codes over
//! 3,891,369 members** and, until the corpus was walked, did not say which.
//! The census below now does: every member of all 49,614 files was read out of
//! its structure table and the 23 codes are exactly
//!
//! ```text
//! 0x01 0x05 0x07 0x10 0x11 0x12 0x13 0x14 0x15 0x21 0x33 0x34
//! 0x40 0x44 0x4A 0x50 0x52 0x59 0x60 0x62 0x63 0x64 0x65
//! ```
//!
//! Three of them are aggregates whose width is not a constant, and each was
//! derived from the corpus rather than named from outside it. A member's width
//! is bounded above by the offset of the next member of its structure, so the
//! measurement is what that bound admits:
//!
//! - **`0x50`, a fixed-length array stored inline.** Its `referenceKey` is the
//!   element count and its `arrayInfoIndex` names the `ARRAYINFO` member that
//!   describes the elements, so its width is `referenceKey × element width`.
//!   That product equals the gap to the next member in **51,168 of 51,168**
//!   members — three floats in twelve bytes, twelve bytes in twelve, five
//!   floats in twenty — and the index resolves to a real `ARRAYINFO` member
//!   every time.
//! - **`0x40`, a NUL-terminated string in a fixed inline buffer.** Its
//!   `referenceKey` is the buffer's length, 64 in all 566 members, and the gap
//!   is 64 or 67. Its `arrayInfoIndex` is not an element description and is
//!   not read.
//! - **`0x52`, the counted array**, and **`0x44`, the counted string**: the
//!   sixteen-byte form of a pointer, `count1`, `count2` and a dead word, whose
//!   gap is 16 in 946,644 of the 953,492 members that carry one. `0x52` is the
//!   only code that carries a subtype — 0 on 793,391 members, `0x04` on 78,648
//!   and `0x24` on 1,030, which with `0x59`'s 670 is the whole subtype census
//!   the document records.
//!
//! Two codes the reference implementation names — `0x03` and `0x06` — occur
//! **0** times, and are therefore not named here: a code outside the table is
//! [`Unsupported::DataType`] rather than a width that happened to fit.
//!
//! One rule keeps a wrong row from becoming a wrong file rather than a
//! refusal: **a member's value has to lie inside its own structure.** The
//! structure's length is a number the *file* states, so a width that is wrong
//! for a real member is answered [`super::Malformed::MemberExtent`] instead of
//! reading its neighbour.
//!
//! # Which of these widths are proved, and which are only consistent
//!
//! The corpus round trip — 49,614 of 49,614 rendered and applied back byte for
//! byte — is quoted more strongly than it deserves, and this table is the
//! honest version. An unedited trip writes **nothing**: `apply` compares each
//! value with what is already there and finds it equal, so the payload comes
//! back because it went in untouched. What the trip establishes is that the
//! walk reached every value without refusing and the re-parse agreed with the
//! render; a wrong stride that lands on a null, a zero or a pointer that still
//! resolves passes it while rendering nonsense.
//!
//! | Width | Standing |
//! |---|---|
//! | `0x50` = `referenceKey` × element | **proved** — the product equals the gap to the next member in 51,168 of 51,168, so nothing else fits |
//! | `0x44` and `0x52` = 16 | **consistent, not tight.** The gap is 16 on 946,644 members and larger on the rest, so 16 is an upper bound that fits everywhere and 12 would fit the padded ones too. It is `PSO`'s counted form with its pointer widened, which is where the 16 comes from |
//! | `0x40` = `referenceKey` = 64 | **consistent, not tight** — one value across all 566 members, against a gap of 64 or 67 |
//! | `0x07` = 8 | **not disambiguated by the corpus at all.** All 95,705 occurrences are `ARRAYINFO` element descriptors, which have no next member and so no gap to bound them. The 8 is the pointer width the two counted forms already rest on, and nothing in the corpus would notice another value |
//!
//! What does bound a wrong width in the file rather than in this table is the
//! extent rule above, and — for an array — [`Field::stride`], which refuses an
//! element of no width at all.
//!
//! The layouts of the two counted forms rest on one measured fact: a `Meta`
//! pointer is **`PSO`'s pointer widened to 64 bits**
//! (`docs/metadata-encodings.md`, Two pointer kinds), so the counted form here
//! is `PSO`'s counted form with its pointer widened. Every read through it is
//! bounds-checked against the block the pointer lands in.

use crate::error::Result;

use super::{Malformed, Member, Meta, Structure, bad, unsupported};

/// The `ARRAYINFO` sentinel: the name hash a member carries when it describes
/// another member's elements rather than a field of its own.
///
/// `docs/metadata-encodings.md` records the indirection for `Meta` — 925,473
/// indices resolved, 0 unresolvable — and the sentinel *value* is `PSO`'s,
/// which the same document measures. `secondary` for this encoding: a file
/// whose sentinel is another value renders one extra member and refuses
/// nothing.
pub(super) const ARRAYINFO: u32 = 0x0000_0100;

/// How deeply structures may nest before the walk refuses.
///
/// The format states no limit and a pointer graph is attacker-chosen, so it can
/// name a cycle. DR-011: a stated depth limit rather than a stack overflow. The
/// same value [`crate::metadata::pso`] uses, and for the same reason.
pub(super) const MAX_DEPTH: usize = 128;

/// How many elements one byte of payload may write.
///
/// A depth limit alone does not bound the work: a block graph shaped as a
/// diamond repeated `MAX_DEPTH` times is acyclic, within the depth, and
/// exponential. Charged by every element written rather than by the structures
/// among them, which is the repair `PSO`'s own budget needed.
///
/// A ratio and not a flat count, for the reason [`MAX_OUTPUT_RATIO`] is one:
/// the work a payload may make is proportional to the payload. Calibrated
/// against the corpus rather than guessed at — the 49,614 files write
/// 1,487,349,189 elements between them, and the worst *ratio* any single one
/// reaches is **1.0472** elements per payload byte, on `hei_ch1_08_grass_1.ymap`.
/// This is a little under eight times that. The flat `1 << 20` it replaced was
/// under the largest shipped file by a factor of four and refused 530 of them.
pub(super) const MAX_NODES_RATIO: usize = 8;

/// How many elements any payload may write, whatever its size.
///
/// **The ceiling over the ratio**, and the half a ratio cannot do: a ratio
/// bounds the work *relative to* the input, so a 100 MB payload is entitled to
/// 800 million elements and the several gigabytes of `String` they write. The
/// flat `1 << 20` this pair replaced bounded the memory absolutely and was the
/// wrong size — under the largest shipped file by a factor of four — which is
/// an argument about the value and not about having one.
///
/// Sized off the corpus in the unit the corpus was measured in: the largest
/// single `Meta` file writes **3,833,493** elements (`ch3_06_grass_0.ymap`),
/// and this is a little over seventeen times that. It binds only above 8 MB of
/// payload, and the largest `Meta` payload of either shipped build is 3.8 MB,
/// so no shipped file comes near either half.
pub(super) const MAX_NODES: usize = 64 << 20;

/// How many elements a payload of `payload` bytes may write.
///
/// One owner for the ceiling (`docs/conventions.md` §3), as
/// [`document_budget`] is for the other.
pub(super) fn node_budget(payload: usize) -> usize {
    payload.saturating_mul(MAX_NODES_RATIO).min(MAX_NODES)
}

/// How many bytes of document one byte of payload may write.
///
/// The bound the memory actually needs, in the unit the memory is in. `PSO`'s
/// own value, and the `Meta` corpus clears it: the worst real ratio over the
/// 49,614 files is **54.51**, on `hei_ch1_08_grass_1.ymap`, so this is a
/// little under five times the largest document any shipped file writes.
pub(super) const MAX_OUTPUT_RATIO: usize = 256;

/// The smallest document any payload may write, whatever its size.
///
/// The floor under [`MAX_OUTPUT_RATIO`], and the half that does the work for a
/// short payload: a `Meta` addresses its data by block, so a small file can
/// legitimately name a great deal of it.
pub(super) const MIN_OUTPUT: usize = 16 * 1024 * 1024;

/// The largest document any payload may write, whatever its size.
///
/// The ceiling over [`MAX_OUTPUT_RATIO`], for the reason [`MAX_NODES`] is one
/// over the element ratio: this is the bound the memory actually obeys, and a
/// ratio alone leaves it proportional to an attacker-chosen input rather than
/// absolute. The largest document any shipped file writes is **199 MB**, on
/// the same `ch3_06_grass_0.ymap`, and this is a little over five times that.
/// It binds only above 4 MB of payload, which no shipped `Meta` payload
/// reaches.
pub(super) const MAX_OUTPUT: usize = 1 << 30;

/// How many bytes of document a payload of `payload` bytes may have.
///
/// One owner for the ceiling both directions obey (`docs/conventions.md` §3):
/// [`super::render`] refuses to write past it, and [`super::apply`] refuses a
/// longer document **before parsing one**.
///
/// A floor and a ceiling around the ratio: [`MIN_OUTPUT`] because a small file
/// can legitimately name a great deal of a payload, [`MAX_OUTPUT`] because a
/// large one must not be entitled to gigabytes.
#[expect(
    clippy::manual_clamp,
    reason = "two bounds that cannot panic, where clamp would"
)]
pub(super) fn document_budget(payload: usize) -> usize {
    // `clamp` would be the same two comparisons and panics when its bounds
    // cross; these two are constants and do not, but the ceiling is the one
    // value here most likely to be tuned, so it is written as two bounds that
    // cannot panic however either is set.
    payload
        .saturating_mul(MAX_OUTPUT_RATIO)
        .max(MIN_OUTPUT)
        .min(MAX_OUTPUT)
}

/// How long a pointer field is: a `Meta` pointer is a 64-bit word.
pub(super) const POINTER_LEN: u32 = 8;

/// How long a counted field is: the pointer, two counts and a dead word.
pub(super) const COUNTED_LEN: u32 = 16;

/// Where `count1` sits inside a counted field.
pub(super) const COUNT_AT: u32 = 8;

/// Where `count2` sits inside a counted field.
pub(super) const CAPACITY_AT: u32 = 10;

/// A fixed-width value, and the width it occupies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Scalar {
    /// `Boolean`, `0x01`.
    Bool,
    /// `SignedByte`, `0x10`.
    Byte,
    /// `UnsignedByte`, `0x11`.
    UByte,
    /// `SignedShort`, `0x12`.
    Short,
    /// `UnsignedShort`, `0x13`.
    UShort,
    /// `SignedInt`, `0x14`.
    Int,
    /// `UnsignedInt`, `0x15`.
    UInt,
    /// `Float`, `0x21`.
    Float,
    /// `Float_XYZ`, `0x33`.
    Float3,
    /// `Float_XYZW`, `0x34`.
    Float4,
    /// `Hash`, `0x4A`, a `joaat` name.
    Hash,
    /// `ByteEnum`, `0x60`.
    ByteEnum,
    /// `IntEnum`, `0x62`.
    IntEnum,
    /// `ShortFlags`, `0x63`.
    ShortFlags,
    /// `IntFlags1`, `0x64`.
    IntFlags1,
    /// `IntFlags2`, `0x65`.
    IntFlags2,
}

impl Scalar {
    /// The word its reserved attribute carries.
    pub(super) const fn word(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::Byte => "byte",
            Self::UByte => "ubyte",
            Self::Short => "short",
            Self::UShort => "ushort",
            Self::Int => "int",
            Self::UInt => "uint",
            Self::Float => "float",
            Self::Float3 => "float3",
            Self::Float4 => "float4",
            Self::Hash => "hash",
            Self::ByteEnum => "enum.byte",
            Self::IntEnum => "enum.int",
            Self::ShortFlags => "flags.short",
            Self::IntFlags1 => "flags.int1",
            Self::IntFlags2 => "flags.int2",
        }
    }

    /// How many bytes it occupies.
    pub(super) const fn bytes(self) -> u32 {
        match self {
            Self::Bool | Self::Byte | Self::UByte | Self::ByteEnum => 1,
            Self::Short | Self::UShort | Self::ShortFlags => 2,
            Self::Int
            | Self::UInt
            | Self::Float
            | Self::Hash
            | Self::IntEnum
            | Self::IntFlags1
            | Self::IntFlags2 => 4,
            Self::Float3 => 12,
            Self::Float4 => 16,
        }
    }
}

/// What a member is, once its type code has been named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// A fixed-width value, inline.
    Scalar(Scalar),
    /// A structure, inline, whose type is the member's `referenceKey`.
    Structure(u32),
    /// A pointer to a data block, whose type is that block's tag.
    ///
    /// `0x07` and `0x59` both. Neither carries its target's type in the member
    /// — the block table does, which is `docs/metadata-encodings.md`'s
    /// measurement that 0 of 462,942 block tags resolve to neither a structure
    /// nor a type code.
    Pointer,
    /// A counted array, `0x52`: a pointer, a length and a capacity, whose
    /// element type is the `ARRAYINFO` member the `arrayInfoIndex` names.
    Array,
    /// A fixed-length array of that many elements, stored inline, `0x50`.
    ///
    /// The count is the member's `referenceKey` and the element type is the
    /// `ARRAYINFO` member its `arrayInfoIndex` names, exactly as [`Kind::Array`]
    /// resolves one. The difference is where the elements are: here, in the
    /// member's own bytes rather than through a pointer.
    InlineArray(u32),
    /// A counted string, `0x44`.
    Text,
    /// A NUL-terminated string in an inline buffer of that many bytes, `0x40`.
    ///
    /// The buffer's length is the member's `referenceKey`. Its
    /// `arrayInfoIndex` describes no elements and is not read.
    InlineText(u32),
}

impl Kind {
    /// What this type code means.
    ///
    /// The whole member, because three of the aggregate forms take a number out
    /// of it: `0x05` its `referenceKey` as the structure's name, `0x50` its
    /// `referenceKey` as an element count and `0x40` its `referenceKey` as a
    /// buffer length.
    ///
    /// # Errors
    ///
    /// [`crate::Error::UnsupportedMeta`] for a code outside the 23. The bytes
    /// are not wrong; this build has no name for them, which is a different
    /// thing to tell a caller (`docs/conventions.md` §10).
    pub(super) fn of(member: Member) -> Result<Self> {
        Ok(match member.type_code.get() {
            0x01 => Self::Scalar(Scalar::Bool),
            0x10 => Self::Scalar(Scalar::Byte),
            0x11 => Self::Scalar(Scalar::UByte),
            0x12 => Self::Scalar(Scalar::Short),
            0x13 => Self::Scalar(Scalar::UShort),
            0x14 => Self::Scalar(Scalar::Int),
            0x15 => Self::Scalar(Scalar::UInt),
            0x21 => Self::Scalar(Scalar::Float),
            0x33 => Self::Scalar(Scalar::Float3),
            0x34 => Self::Scalar(Scalar::Float4),
            0x4A => Self::Scalar(Scalar::Hash),
            0x60 => Self::Scalar(Scalar::ByteEnum),
            0x62 => Self::Scalar(Scalar::IntEnum),
            0x63 => Self::Scalar(Scalar::ShortFlags),
            0x64 => Self::Scalar(Scalar::IntFlags1),
            0x65 => Self::Scalar(Scalar::IntFlags2),
            0x05 => Self::Structure(member.reference_key),
            0x07 | 0x59 => Self::Pointer,
            0x52 => Self::Array,
            0x50 => Self::InlineArray(member.reference_key),
            0x44 => Self::Text,
            0x40 => Self::InlineText(member.reference_key),
            other => return Err(unsupported(Unsupported::DataType { code: other })),
        })
    }
}

/// One value the walk is at: the member that describes it, and the structure
/// that member belongs to.
///
/// The pair travels together everywhere, because an array's element type is a
/// member of the *owning* structure rather than of the member's own — the
/// `ARRAYINFO` indirection, `docs/metadata-encodings.md`. The owner is an
/// option because a typed data block carries values and no member record, so
/// there is no structure an index could resolve against.
#[derive(Debug, Clone, Copy)]
pub(super) struct Field<'a> {
    /// What the file says this value is.
    pub(super) member: Member,
    /// The structure the member belongs to, when there is one.
    pub(super) owner: Option<Structure<'a>>,
}

impl Field<'_> {
    /// What kind of value it is.
    ///
    /// # Errors
    ///
    /// [`crate::Error::UnsupportedMeta`] for a type code outside the 23.
    pub(super) fn kind(self) -> Result<Kind> {
        Kind::of(self.member)
    }

    /// The field describing this one's elements, for the two array forms.
    ///
    /// The `ARRAYINFO` indirection: `arrayInfoIndex` is an index into the
    /// *owning* structure's member array, and the member it names describes
    /// the elements rather than a field of its own.
    ///
    /// # Errors
    ///
    /// [`Malformed::ArrayInfo`] when there is no owner to resolve the index
    /// against, or the owner has no such member. `docs/metadata-encodings.md`:
    /// 925,473 indices resolved and 0 unresolvable.
    pub(super) fn element(self, at: u64) -> Result<Self> {
        let owner = self.owner.ok_or_else(|| bad(at, Malformed::ArrayInfo))?;
        let member = owner
            .member(self.member.array_info_index)
            .ok_or_else(|| bad(at, Malformed::ArrayInfo))?;
        Ok(Self {
            member,
            owner: Some(owner),
        })
    }

    /// How many bytes of its container one of these occupies.
    ///
    /// The stride of an array of them, and what a member's own extent is
    /// checked against.
    ///
    /// # Errors
    ///
    /// [`crate::Error::UnsupportedMeta`] for a type code outside the 23,
    /// [`Malformed::UndefinedStructure`] when an inline structure's type is one
    /// the file does not define, [`Malformed::ArrayInfo`] when an inline
    /// array's element description does not resolve, and
    /// [`Malformed::TooDeep`] when the element descriptions nest deeper than
    /// [`MAX_DEPTH`] — an `arrayInfoIndex` that names its own member is a
    /// cycle, and the corpus contains no nesting at all.
    pub(super) fn width(self, meta: &Meta<'_>, at: u64) -> Result<u32> {
        self.width_within(meta, at, MAX_DEPTH)
    }

    /// The width of one element of an array of these — the array's **stride**
    /// — which is [`Field::width`] with a width of zero refused.
    ///
    /// The one place a zero stride is answered, so that both directions and
    /// both array layouts refuse the same file (`docs/conventions.md` §3).
    /// [`Malformed::ZeroStride`] says why it is an answer rather than a
    /// ceiling's problem: an element of no width makes an array of any count
    /// occupy no bytes, so the extent check passes for every count and the walk
    /// writes one element per count out of a payload that never grows.
    ///
    /// # Errors
    ///
    /// As [`Field::width`], plus [`Malformed::ZeroStride`].
    pub(super) fn stride(self, meta: &Meta<'_>, at: u64) -> Result<u32> {
        match self.width(meta, at)? {
            0 => Err(bad(at, Malformed::ZeroStride)),
            width => Ok(width),
        }
    }

    /// [`Field::width`], with the fuel that bounds the `ARRAYINFO` chain.
    fn width_within(self, meta: &Meta<'_>, at: u64, fuel: usize) -> Result<u32> {
        let left = fuel
            .checked_sub(1)
            .ok_or_else(|| bad(at, Malformed::TooDeep))?;
        Ok(match self.kind()? {
            Kind::Scalar(scalar) => scalar.bytes(),
            Kind::Structure(name) => {
                meta.structure(name)
                    .ok_or_else(|| bad(at, Malformed::UndefinedStructure))?
                    .length
            }
            Kind::Pointer => POINTER_LEN,
            Kind::Array | Kind::Text => COUNTED_LEN,
            Kind::InlineText(len) => len,
            Kind::InlineArray(count) => {
                let stride = self.element(at)?.width_within(meta, at, left)?;
                // The same refusal [`Field::stride`] makes, made here because
                // this is where an inline array's own element width is
                // derived: an array that instantiates elements of no width is
                // refused, and one that instantiates none asks nothing of them.
                if stride == 0 && count != 0 {
                    return Err(bad(at, Malformed::ZeroStride));
                }
                count
                    .checked_mul(stride)
                    .ok_or_else(|| bad(at, Malformed::MemberExtent))?
            }
        })
    }
}

/// Whether a member is one of a structure's fields, or the description of
/// another member's elements.
pub(super) fn is_field(name: u32) -> bool {
    name != ARRAYINFO
}

/// Checks that a member's value lies inside the structure that declares it.
///
/// The one place a width this module derives is measured against something the
/// file itself states. `docs/conventions.md` §6: every read is bounds-checked
/// against the containing declaration, not against what happens to be there.
///
/// # Errors
///
/// [`Malformed::MemberExtent`] when it does not.
pub(super) fn fits(structure: &Structure<'_>, offset: u32, width: u32, at: u64) -> Result<()> {
    let end = offset
        .checked_add(width)
        .ok_or_else(|| bad(at, Malformed::MemberExtent))?;
    if end > structure.length {
        return Err(bad(at, Malformed::MemberExtent));
    }
    Ok(())
}

/// A resource `Meta` file that is well formed and says something this build
/// does not decode.
///
/// Separate from [`Malformed`] because the caller's position is different: the
/// bytes are right and the missing part is here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unsupported {
    /// A member type code outside the 23 this build names.
    ///
    /// The 23 are the census of all 49,614 files, so a code that reaches this
    /// is one neither shipped build contains — `Kind::of` says what the table
    /// is and how it was measured.
    DataType {
        /// The code the file carries.
        code: u8,
    },
}

/// Why XML handed to [`super::from_xml`] does not describe the payload it was
/// given beside.
///
/// The write direction is an **edit** of the file the document was written from
/// — DR-049 — so a refusal here says which way the two disagree rather than
/// that the bytes are wrong. The bytes being wrong is [`Malformed`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotMetaXml {
    /// The XML is not well formed.
    Syntax {
        /// What the parser said.
        detail: String,
    },
    /// The document holds no element.
    Empty,
    /// A second element closed at the top level.
    SecondRoot,
    /// Elements nested deeper than the walk goes.
    TooDeep,
    /// The document is longer than any document describing a payload this size
    /// can be.
    ///
    /// The ceiling [`super::to_xml`] writes under, read as a refusal before the
    /// document is parsed: the whole of it is materialised into a tree before
    /// the first comparison against the payload.
    TooLarge {
        /// How many bytes a document editing this payload may have.
        budget: usize,
        /// How many it has.
        len: usize,
    },
    /// An element carries no reserved `meta:` attribute, or more than one.
    Reserved {
        /// The attribute, or the element that has none.
        name: String,
    },
    /// An element is not the one the file says goes here.
    Tag {
        /// What the file's own tables name this member.
        wanted: String,
        /// What the document called it.
        found: String,
    },
    /// An element's type word, or the value the mapping fixes, is not the one
    /// the file declares.
    Word {
        /// What the file says.
        wanted: String,
        /// What the document says.
        found: String,
    },
    /// An element has a different number of children than the file says.
    ///
    /// An array's length and a structure's member list are facts about the
    /// payload, not about the document: an edit in place moves no allocation,
    /// so neither can change. DR-052.
    Children {
        /// Which element, as the document spells it.
        name: String,
        /// How many the file has.
        wanted: usize,
        /// How many the document has.
        found: usize,
    },
    /// A value does not read back as the type its own word says it is.
    Value {
        /// Which element.
        name: String,
    },
    /// A value carries a backslash escape this layer never writes.
    BadEscape,
    /// A string or a run of bytes is longer than the store it has to live in.
    ///
    /// Nothing here moves a block or rewrites a pointer, so a value may be
    /// shortened and never lengthened past its own store. For a string the
    /// store is one byte short of the room, because the terminator is one of
    /// the bytes the room holds; and it is never less than the value already
    /// there, so a payload that arrives full is still written back unchanged.
    /// DR-052.
    TooLong {
        /// Which element, as the document spells it.
        name: String,
        /// How many bytes there are.
        room: u32,
        /// How many the value needs.
        len: u32,
    },
    /// Text where this mapping writes none.
    UnexpectedText,
    /// Two elements of the document write different bytes at one address.
    ///
    /// A file may point at one value twice, and then the document renders that
    /// value twice; an edit of one of the two would otherwise be decided by
    /// whichever element the walk applied last, and the other silently
    /// discarded. DR-059: the write direction refuses instead, and a repeated
    /// write of the *same* bytes — which is every unedited trip over such a
    /// file, and an edit made on both — is not one.
    Aliased {
        /// The element that disagreed, as the document spells it.
        name: String,
        /// The payload address the two write at.
        address: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The largest resource `Meta` payload either shipped build carries, in
    /// bytes. `docs/metadata-encodings.md`, and the dump `RPF_METADATA` names.
    const LARGEST_SHIPPED_PAYLOAD: usize = 3_833_856;

    /// The most elements any single shipped file writes, and the largest
    /// document one writes: `ch3_06_grass_0.ymap`, a field of instanced grass.
    const MOST_SHIPPED_NODES: usize = 3_833_493;
    const LARGEST_SHIPPED_DOCUMENT: usize = 199 * 1_000_000;

    #[test]
    fn the_ceilings_bound_the_memory_absolutely_and_still_clear_the_corpus() {
        // Both halves of the pair, and the pair is the point. A ratio alone
        // bounds the work relative to an attacker-chosen input — a 100 MB
        // payload was entitled to 800 million elements and the gigabytes of
        // `String` they write — and a flat count alone was the wrong size for
        // the corpus, which is what retired the old `1 << 20`.
        assert_eq!(node_budget(usize::MAX), MAX_NODES);
        assert_eq!(document_budget(usize::MAX), MAX_OUTPUT);
        assert_eq!(document_budget(0), MIN_OUTPUT);

        // And neither ceiling reaches down to anything shipped: at the largest
        // payload in the corpus both budgets are still the ratio's, so what the
        // corpus run measures is the ratio and nothing else.
        assert_eq!(
            node_budget(LARGEST_SHIPPED_PAYLOAD),
            LARGEST_SHIPPED_PAYLOAD * MAX_NODES_RATIO
        );
        assert_eq!(
            document_budget(LARGEST_SHIPPED_PAYLOAD),
            LARGEST_SHIPPED_PAYLOAD * MAX_OUTPUT_RATIO
        );
        // Which is room for the worst file there is, several times over.
        assert!(node_budget(LARGEST_SHIPPED_PAYLOAD) > MOST_SHIPPED_NODES);
        assert!(document_budget(LARGEST_SHIPPED_PAYLOAD) > LARGEST_SHIPPED_DOCUMENT);
        const { assert!(MAX_NODES > MOST_SHIPPED_NODES) };
        const { assert!(MAX_OUTPUT > LARGEST_SHIPPED_DOCUMENT) };
    }
}
