//! What a member's type code means, what a document calls it, and the ceilings
//! a walk of one obeys.
//!
//! # The type table is `secondary`, and this is the only place it is written
//!
//! `docs/metadata-encodings.md` counted **23 distinct type codes over
//! 3,891,369 members** and **does not say which**. So the codes below are not
//! measured here: they are the reference implementation's
//! `MetaStructureEntryDataType`, read as specification under `AGENTS.md`'s
//! authority order, row 3. What corroborates them is arithmetic rather than a
//! probe — the enumeration has exactly 23 members, which is the number the
//! corpus census reached — and that is weaker than a measurement and is
//! recorded as weaker.
//!
//! Two rules keep a wrong row from becoming a wrong file rather than a
//! refusal:
//!
//! - **A code outside the table is [`Unsupported::DataType`]**, never a width
//!   that happened to fit. The 23 are what this build claims and nothing else.
//! - **A member's value has to lie inside its own structure.** The structure's
//!   length is a number the *file* states, so a width that is wrong for a real
//!   member is answered [`super::Malformed::MemberExtent`] instead of reading
//!   its neighbour. That check is the whole reason the table can be carried at
//!   `secondary` at all.
//!
//! The layouts of the two aggregate forms are `secondary` for the same reason
//! and rest on one measured fact: a `Meta` pointer is **`PSO`'s pointer widened
//! to 64 bits** (`docs/metadata-encodings.md`, Two pointer kinds). The counted
//! form here is therefore `PSO`'s counted form with its pointer widened — the
//! pointer, `count1:u16`, `count2:u16` and a dead word — and every read through
//! it is bounds-checked against the block the pointer lands in, so a file this
//! reading is wrong about is refused rather than mis-edited.

use crate::error::Result;

use super::{Malformed, Member, Meta, Structure, TypeCode, bad, unsupported};

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

/// How many elements one payload's walk may write.
///
/// A depth limit alone does not bound the work: a block graph shaped as a
/// diamond repeated `MAX_DEPTH` times is acyclic, within the depth, and
/// exponential. Charged by every element written rather than by the structures
/// among them, which is the repair `PSO`'s own budget needed.
pub(super) const MAX_NODES: usize = 1 << 20;

/// How many bytes of document one byte of payload may write.
///
/// The bound the memory actually needs, in the unit the memory is in. Unlike
/// `PSO`'s, this ratio has **not** been calibrated against a corpus — no
/// `RPF_METADATA` dump of the 49,614 `Meta` payloads has been within reach of
/// this code — so it is `PSO`'s own value, which that encoding measured at ten
/// times the worst real ratio.
pub(super) const MAX_OUTPUT_RATIO: usize = 256;

/// The smallest document any payload may write, whatever its size.
///
/// The floor under [`MAX_OUTPUT_RATIO`], and the half that does the work for a
/// short payload: a `Meta` addresses its data by block, so a small file can
/// legitimately name a great deal of it.
pub(super) const MIN_OUTPUT: usize = 16 * 1024 * 1024;

/// How many bytes of document a payload of `payload` bytes may have.
///
/// One owner for the ceiling both directions obey (`docs/conventions.md` §3):
/// [`super::render`] refuses to write past it, and [`super::apply`] refuses a
/// longer document **before parsing one**.
pub(super) fn document_budget(payload: usize) -> usize {
    payload.saturating_mul(MAX_OUTPUT_RATIO).max(MIN_OUTPUT)
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
    /// `StructurePointer` and `DataBlockPointer` both. Neither carries its
    /// target's type in the member — the block table does, which is
    /// `docs/metadata-encodings.md`'s measurement that 0 of 462,942 block tags
    /// resolve to neither a structure nor a type code.
    Pointer,
    /// A counted array, whose element type is the `ARRAYINFO` member the
    /// `arrayInfoIndex` names.
    Array,
    /// A counted string.
    Text,
    /// A counted run of bytes.
    Bytes,
}

impl Kind {
    /// What this type code means.
    ///
    /// `reference` is the member's `referenceKey`, which is the structure's
    /// name for the one inline form that needs it.
    ///
    /// # Errors
    ///
    /// [`crate::Error::UnsupportedMeta`] for a code outside the 23. The bytes
    /// are not wrong; this build has no name for them, which is a different
    /// thing to tell a caller (`docs/conventions.md` §10).
    pub(super) fn of(code: TypeCode, reference: u32) -> Result<Self> {
        Ok(match code.get() {
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
            0x05 => Self::Structure(reference),
            0x06 | 0x59 => Self::Pointer,
            0x07 => Self::Array,
            0x03 | 0x40 => Self::Text,
            0x50 => Self::Bytes,
            other => return Err(unsupported(Unsupported::DataType { code: other })),
        })
    }

    /// How many bytes of its container one of these occupies.
    ///
    /// The stride of an array of them, and what a member's own extent is
    /// checked against.
    ///
    /// # Errors
    ///
    /// [`Malformed::UndefinedStructure`] when an inline structure's type is
    /// one the file does not define, which is the one width that is not a
    /// constant.
    pub(super) fn width(self, meta: &Meta<'_>, at: u64) -> Result<u32> {
        Ok(match self {
            Self::Scalar(scalar) => scalar.bytes(),
            Self::Structure(name) => {
                meta.structure(name)
                    .ok_or_else(|| bad(at, Malformed::UndefinedStructure))?
                    .length
            }
            Self::Pointer => POINTER_LEN,
            Self::Array | Self::Text | Self::Bytes => COUNTED_LEN,
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
        Kind::of(self.member.type_code, self.member.reference_key)
    }
}

/// Whether a member is one of a structure's fields, or the description of
/// another member's elements.
pub(super) fn is_field(name: u32) -> bool {
    name != ARRAYINFO
}

/// Checks that a member's value lies inside the structure that declares it.
///
/// The one place a `secondary` width is measured against something the file
/// itself states. `docs/conventions.md` §6: every read is bounds-checked
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
    /// `docs/metadata-encodings.md` counted 23 distinct codes and does not
    /// enumerate them, so the table this refusal is the complement of is
    /// `secondary` — `Kind::of` says what that costs and what bounds it.
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
