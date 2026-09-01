//! What a member's type code means, what a document calls it, and the ceilings
//! a walk of one obeys.
//!
//! The 23 type codes are written down only here; a code outside them is
//! [`Unsupported::DataType`] rather than a width that happened to fit. Three
//! are aggregates whose width is not a constant: `0x50` is
//! `referenceKey × element width` inline, `0x40` is a NUL-terminated string in
//! a `referenceKey`-byte buffer, and `0x44`/`0x52` are the sixteen-byte counted
//! form — a 64-bit pointer, `count1`, `count2` and a dead word.
//!
//! A member's value must lie inside its own structure, whose length the file
//! states, so a wrong width is [`super::Malformed::MemberExtent`] rather than a
//! read of the neighbour.

use crate::error::Result;

use super::{Malformed, Member, Meta, Structure, bad, unsupported};

/// The `ARRAYINFO` sentinel: the name hash a member carries when it describes
/// another member's elements rather than a field of its own.
pub(super) const ARRAYINFO: u32 = 0x0000_0100;

/// How deeply structures may nest before the walk refuses; the format states no
/// limit and an attacker-chosen pointer graph can name a cycle.
pub(super) const MAX_DEPTH: usize = 128;

/// How many elements one byte of payload may write; a depth limit alone leaves
/// a diamond-shaped block graph acyclic, within the depth, and exponential.
pub(super) const MAX_NODES_RATIO: usize = 8;

/// How many elements any payload may write, whatever its size; the ceiling over
/// the ratio, binding only above 8 MB of payload.
pub(super) const MAX_NODES: usize = 64 << 20;

/// How many elements a payload of `payload` bytes may write.
pub(super) fn node_budget(payload: usize) -> usize {
    payload.saturating_mul(MAX_NODES_RATIO).min(MAX_NODES)
}

/// How many bytes of document one byte of payload may write, which is the bound
/// the memory actually needs.
pub(super) const MAX_OUTPUT_RATIO: usize = 256;

/// The floor under [`MAX_OUTPUT_RATIO`]: a `Meta` addresses its data by block,
/// so a small file can legitimately name a great deal of it.
pub(super) const MIN_OUTPUT: usize = 16 * 1024 * 1024;

/// The ceiling over [`MAX_OUTPUT_RATIO`], so the memory is bounded absolutely
/// rather than by an attacker-chosen input.
pub(super) const MAX_OUTPUT: usize = 1 << 30;

/// How many bytes of document a payload of `payload` bytes may have: the
/// ceiling `render` writes under and `apply` refuses a longer document against.
#[expect(
    clippy::manual_clamp,
    reason = "two bounds that cannot panic, where clamp would"
)]
pub(super) fn document_budget(payload: usize) -> usize {
    // Two bounds that cannot panic however either constant is tuned; `clamp`
    // panics when its bounds cross.
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
    /// A pointer to a data block, `0x07` and `0x59`, whose type is that
    /// block's tag rather than anything the member carries.
    Pointer,
    /// A counted array, `0x52`: a pointer, a length and a capacity, whose
    /// element type is the `ARRAYINFO` member the `arrayInfoIndex` names.
    Array,
    /// A fixed-length array of `referenceKey` elements, `0x50`, stored in the
    /// member's own bytes; its element type resolves as [`Kind::Array`]'s.
    InlineArray(u32),
    /// A counted string, `0x44`.
    Text,
    /// A NUL-terminated string in an inline buffer of `referenceKey` bytes,
    /// `0x40`; its `arrayInfoIndex` describes no elements and is not read.
    InlineText(u32),
}

impl Kind {
    /// What this type code means; the whole member, because three aggregate
    /// forms read its `referenceKey`.
    ///
    /// # Errors
    ///
    /// [`crate::Error::UnsupportedMeta`] for a code outside the 23.
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
/// The owner is optional: a typed data block carries values and no member
/// record for an `ARRAYINFO` index to resolve against.
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

    /// The field describing this one's elements: `arrayInfoIndex` indexes the
    /// owning structure's member array.
    ///
    /// # Errors
    ///
    /// [`Malformed::ArrayInfo`] when there is no owner to resolve the index
    /// against, or the owner has no such member.
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

    /// How many bytes of its container one of these occupies, which is the
    /// stride of an array of them.
    ///
    /// # Errors
    ///
    /// [`crate::Error::UnsupportedMeta`], [`Malformed::UndefinedStructure`],
    /// [`Malformed::ArrayInfo`], and [`Malformed::TooDeep`] when the element
    /// descriptions nest deeper than [`MAX_DEPTH`].
    pub(super) fn width(self, meta: &Meta<'_>, at: u64) -> Result<u32> {
        self.width_within(meta, at, MAX_DEPTH)
    }

    /// [`Field::width`] with a width of zero refused: an element of no width
    /// makes an array of any count occupy no bytes, so the extent check would
    /// pass for every count.
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
                // `Field::stride`'s refusal, made where an inline array's
                // element width is derived; a count of zero asks nothing.
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

/// Checks that a member's value lies inside the structure that declares it,
/// which is the one place a derived width meets a length the file states.
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
/// does not decode; the bytes are right and the missing part is here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unsupported {
    /// A member type code outside the 23 this build names.
    DataType {
        /// The code the file carries.
        code: u8,
    },
}

/// Why XML handed to [`super::from_xml`] does not describe the payload it was
/// given beside; wrong bytes are [`Malformed`] instead.
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
    /// The document is longer than any document describing a payload this
    /// size can be, which is refused before it is parsed.
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
    /// An element has a different number of children than the file says; an
    /// edit in place moves no allocation, so neither count can change.
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
    /// store is one byte short of the room, the terminator taking the last.
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
    /// Two elements of the document write different bytes at one address,
    /// which a file pointing at one value twice makes possible. A repeated
    /// write of the same bytes is not one.
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

    /// The largest resource `Meta` payload either shipped build carries.
    const LARGEST_SHIPPED_PAYLOAD: usize = 3_833_856;

    /// The most elements any single shipped file writes, and the largest
    /// document one writes.
    const MOST_SHIPPED_NODES: usize = 3_833_493;
    const LARGEST_SHIPPED_DOCUMENT: usize = 199 * 1_000_000;

    #[test]
    fn the_ceilings_bound_the_memory_absolutely_and_still_clear_the_corpus() {
        // A ratio alone bounds the work only relative to an attacker-chosen
        // input; a flat count alone is the wrong size for the corpus.
        assert_eq!(node_budget(usize::MAX), MAX_NODES);
        assert_eq!(document_budget(usize::MAX), MAX_OUTPUT);
        assert_eq!(document_budget(0), MIN_OUTPUT);

        // At the largest shipped payload both budgets are still the ratio's.
        assert_eq!(
            node_budget(LARGEST_SHIPPED_PAYLOAD),
            LARGEST_SHIPPED_PAYLOAD * MAX_NODES_RATIO
        );
        assert_eq!(
            document_budget(LARGEST_SHIPPED_PAYLOAD),
            LARGEST_SHIPPED_PAYLOAD * MAX_OUTPUT_RATIO
        );
        assert!(node_budget(LARGEST_SHIPPED_PAYLOAD) > MOST_SHIPPED_NODES);
        assert!(document_budget(LARGEST_SHIPPED_PAYLOAD) > LARGEST_SHIPPED_DOCUMENT);
        const { assert!(MAX_NODES > MOST_SHIPPED_NODES) };
        const { assert!(MAX_OUTPUT > LARGEST_SHIPPED_DOCUMENT) };
    }
}
