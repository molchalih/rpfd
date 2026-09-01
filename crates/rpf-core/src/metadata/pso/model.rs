//! What a `PSO` file can be wrong about, and the ceilings a walk of one obeys.

/// The name hash a member carries when it describes another member's element
/// type rather than a field of its own.
pub(super) const ARRAYINFO: u32 = 0x0000_0100;

/// The `BITSET` "no enum info" sentinel, in place of a member index.
pub(super) const NO_ENUM: u16 = 0x0FFF;

/// How deeply structures may nest before the walk refuses: the format states
/// no limit, and a pointer graph can name a cycle.
pub(super) const MAX_DEPTH: usize = 128;

/// How many elements one payload's walk may write.
///
/// Depth alone does not bound the work — a diamond-shaped block graph is
/// acyclic and exponential — so the budget is charged per element written. It
/// bounds the walk, not the memory; [`MAX_OUTPUT_RATIO`] is the byte bound.
pub(super) const MAX_NODES: usize = 1 << 20;

/// How many bytes of document one byte of payload may write; proportional
/// because a cap large enough for a real document would free a tiny payload.
pub(super) const MAX_OUTPUT_RATIO: usize = 256;

/// The smallest document any payload may write: a floor under
/// [`MAX_OUTPUT_RATIO`], since a tiny file can legitimately name a lot of data.
pub(super) const MIN_OUTPUT: usize = 16 * 1024 * 1024;

/// How many bytes of document a payload of `payload` bytes may have;
/// [`super::apply`] refuses a longer document before parsing it.
pub(super) fn document_budget(payload: usize) -> usize {
    payload.saturating_mul(MAX_OUTPUT_RATIO).max(MIN_OUTPUT)
}

/// How far a `dataOffset` with bit 7 of its subtype set may have wrapped: the
/// field is a `u16`, so the ceiling is what the `i32` structure length allows.
pub(super) const MAX_WRAPS: u32 = 0xFFFF;

/// Why a byte stream is not a well-formed `PSO` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Malformed {
    /// The payload does not begin with the `PSIN` section tag.
    NotPso,
    /// A section header does not fit, or its length is less than the eight
    /// bytes of header it includes, or it overruns the payload.
    Section,
    /// The section chain does not land exactly on the end of the payload.
    Trailing,
    /// A section this build needs — `PSIN`, `PMAP` or `PSCH` — is not there.
    MissingSection,
    /// A section's own header does not fit inside the length it declared.
    SectionTruncated,
    /// A `PMAP` entry names a range that is not inside the `PSIN` section.
    BlockRange,
    /// `PMAP.rootId` is not a block.
    RootId,
    /// A `PSCH` index entry points outside the section, or its packed word
    /// claims a kind that is neither a structure nor an enum.
    SchemaEntry,
    /// A structure's declared length is negative.
    StructureLength,
    /// An array or map member's element index does not name an `ARRAYINFO`
    /// member of the same structure.
    ArrayInfo,
    /// A member whose subtype marks a wrapped `dataOffset` has no multiple of
    /// 65,536 that puts it after the member before it and inside its structure
    /// — or has more than one, so the recovery would be a guess.
    Wrapped,
    /// The `CHKS` section is not the twenty bytes it always is, so the two
    /// `u32`s the write direction stamps into it would land over what follows.
    Checksum,
    /// A read fell outside the `PSIN` section.
    DataRange,
    /// A pointer names a block that is not in the table, or an offset at or
    /// past that block's length.
    Pointer,
    /// A structure the data reaches is not one the file's own `PSCH` defines.
    UndefinedStructure,
    /// Structures nested deeper than this walk goes.
    TooDeep,
    /// The walk visited more structures than its budget allows.
    TooManyNodes,
    /// The document grew past what a payload of this size is allowed to write.
    TooLarge,
}

/// A `PSO` file that is well formed and says something this build does not
/// decode — separate from [`Malformed`] because the bytes are right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unsupported {
    /// A `(type, subtype)` pair this build does not decode.
    DataType {
        /// The `PsoDataType` code.
        code: u8,
        /// Its subtype.
        subtype: u8,
    },
}

/// Why XML handed to [`super::from_xml`] does not describe the payload it was
/// given beside: which way the two disagree, rather than the bytes being wrong,
/// which is [`Malformed`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotPsoXml {
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
    /// can be, refused before it is parsed into a tree.
    TooLarge {
        /// How many bytes a document editing this payload may have.
        budget: usize,
        /// How many it has.
        len: usize,
    },
    /// An element carries no reserved `pso:` attribute, or more than one;
    /// every element this mapping writes carries exactly one.
    Reserved {
        /// The attribute, or the element that has none.
        name: String,
    },
    /// An element is not the one the schema says goes here.
    Tag {
        /// What the file's own schema names this member.
        wanted: String,
        /// What the document called it.
        found: String,
    },
    /// An element's type word, or the value the mapping fixes, is not the one
    /// the schema says.
    Word {
        /// What the schema says.
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
    /// A string is longer than the bytes it has to live in: the store its form
    /// gives it, less the one byte its terminator needs.
    TooLong {
        /// Which element, as the document spells it.
        name: String,
        /// How many bytes there are.
        room: u32,
        /// How many the value needs.
        len: u32,
    },
    /// Two of an enum's keys render the same name, so the document cannot say
    /// which one it means.
    Ambiguous {
        /// The name both carry.
        name: String,
    },
    /// Text where this mapping writes none.
    UnexpectedText,
}
