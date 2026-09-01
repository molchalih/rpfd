//! What a member's type code means; the 23 codes this build names live only here.

use crate::error::Result;

use super::{Malformed, Member, Meta, Structure, bad, unsupported};

pub(super) const ARRAYINFO: u32 = 0x0000_0100;

pub(super) const MAX_DEPTH: usize = 128;

pub(super) const MAX_NODES_RATIO: usize = 8;

pub(super) const MAX_NODES: usize = 64 << 20;

pub(super) fn node_budget(payload: usize) -> usize {
    payload.saturating_mul(MAX_NODES_RATIO).min(MAX_NODES)
}

pub(super) const MAX_OUTPUT_RATIO: usize = 256;

pub(super) const MIN_OUTPUT: usize = 16 * 1024 * 1024;

pub(super) const MAX_OUTPUT: usize = 1 << 30;

#[expect(
    clippy::manual_clamp,
    reason = "two bounds that cannot panic, where clamp would"
)]
pub(super) fn document_budget(payload: usize) -> usize {
    payload
        .saturating_mul(MAX_OUTPUT_RATIO)
        .max(MIN_OUTPUT)
        .min(MAX_OUTPUT)
}

pub(super) const POINTER_LEN: u32 = 8;

pub(super) const COUNTED_LEN: u32 = 16;

pub(super) const COUNT_AT: u32 = 8;

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
    /// A pointer to a data block, `0x07` and `0x59`, typed by that block's tag.
    Pointer,
    /// A counted array, `0x52`, whose element type is its `ARRAYINFO` member.
    Array,
    /// A fixed-length array of `referenceKey` elements, `0x50`.
    InlineArray(u32),
    /// A counted string, `0x44`.
    Text,
    /// A NUL-terminated string in an inline buffer of `referenceKey` bytes, `0x40`.
    InlineText(u32),
}

impl Kind {
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

#[derive(Debug, Clone, Copy)]
pub(super) struct Field<'a> {
    pub(super) member: Member,
    pub(super) owner: Option<Structure<'a>>,
}

impl Field<'_> {
    pub(super) fn kind(self) -> Result<Kind> {
        Kind::of(self.member)
    }

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

    pub(super) fn width(self, meta: &Meta<'_>, at: u64) -> Result<u32> {
        self.width_within(meta, at, MAX_DEPTH)
    }

    pub(super) fn stride(self, meta: &Meta<'_>, at: u64) -> Result<u32> {
        match self.width(meta, at)? {
            0 => Err(bad(at, Malformed::ZeroStride)),
            width => Ok(width),
        }
    }

    /// `width`, with the fuel that bounds the `ARRAYINFO` chain.
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

pub(super) fn is_field(name: u32) -> bool {
    name != ARRAYINFO
}

pub(super) fn fits(structure: &Structure<'_>, offset: u32, width: u32, at: u64) -> Result<()> {
    let end = offset
        .checked_add(width)
        .ok_or_else(|| bad(at, Malformed::MemberExtent))?;
    if end > structure.length {
        return Err(bad(at, Malformed::MemberExtent));
    }
    Ok(())
}

/// A resource `Meta` file that is well formed but says something this build
/// does not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unsupported {
    /// A member type code outside the 23 this build names.
    DataType {
        /// The code the file carries.
        code: u8,
    },
}

/// Why XML handed to `from_xml` does not describe the payload beside it.
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
    /// The document is longer than one describing this payload can be.
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
    /// An element's type word, or a fixed attribute value, is not the file's.
    Word {
        /// What the file says.
        wanted: String,
        /// What the document says.
        found: String,
    },
    /// An element has a different number of children than the file says.
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

    const LARGEST_SHIPPED_PAYLOAD: usize = 3_833_856;

    const MOST_SHIPPED_NODES: usize = 3_833_493;
    const LARGEST_SHIPPED_DOCUMENT: usize = 199 * 1_000_000;

    #[test]
    fn the_ceilings_bound_the_memory_absolutely_and_still_clear_the_corpus() {
        assert_eq!(node_budget(usize::MAX), MAX_NODES);
        assert_eq!(document_budget(usize::MAX), MAX_OUTPUT);
        assert_eq!(document_budget(0), MIN_OUTPUT);

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
