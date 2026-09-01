//! What a `PSO` file can be wrong about, and the ceilings a walk of one obeys.

/// The name hash a member carries when it names another member's element type.
pub(super) const ARRAYINFO: u32 = 0x0000_0100;

pub(super) const NO_ENUM: u16 = 0x0FFF;

pub(super) const MAX_DEPTH: usize = 128;

pub(super) const MAX_NODES: usize = 1 << 20;

pub(super) const MAX_OUTPUT_RATIO: usize = 256;

pub(super) const MIN_OUTPUT: usize = 16 * 1024 * 1024;

pub(super) fn document_budget(payload: usize) -> usize {
    payload.saturating_mul(MAX_OUTPUT_RATIO).max(MIN_OUTPUT)
}

pub(super) const MAX_WRAPS: u32 = 0xFFFF;

/// Why a byte stream is not a well-formed `PSO` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Malformed {
    /// The payload does not begin with the `PSIN` section tag.
    NotPso,
    /// A section header does not fit or overruns the payload.
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
    /// A `PSCH` index entry points outside the section, or names an invalid kind.
    SchemaEntry,
    /// A structure's declared length is negative.
    StructureLength,
    /// An array or map member's element index does not name an `ARRAYINFO` member.
    ArrayInfo,
    /// A wrapped `dataOffset` has no valid 65,536-multiple recovery, or more than one.
    Wrapped,
    /// The `CHKS` section is not the twenty bytes it always is.
    Checksum,
    /// A read fell outside the `PSIN` section.
    DataRange,
    /// A pointer names a block not in the table, or an offset past its length.
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

/// A well-formed `PSO` file that says something this build does not decode.
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

/// Why XML handed to `from_xml` does not describe the payload beside it.
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
    /// The document is longer than allowed for a payload this size.
    TooLarge {
        /// How many bytes a document editing this payload may have.
        budget: usize,
        /// How many it has.
        len: usize,
    },
    /// An element carries no reserved `pso:` attribute, or more than one.
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
    /// An element's type word, or a fixed value, is not what the schema says.
    Word {
        /// What the schema says.
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
    /// A string is longer than the bytes it has to live in.
    TooLong {
        /// Which element, as the document spells it.
        name: String,
        /// How many bytes there are.
        room: u32,
        /// How many the value needs.
        len: u32,
    },
    /// Two of an enum's keys render the same name.
    Ambiguous {
        /// The name both carry.
        name: String,
    },
    /// Text where this mapping writes none.
    UnexpectedText,
}
