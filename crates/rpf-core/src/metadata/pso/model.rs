//! What a `PSO` file can be wrong about, and the ceilings a walk of one obeys.

/// The `ARRAYINFO` sentinel: the name hash a member carries when it describes
/// another member's element type rather than a field of its own.
///
/// `docs/metadata-encodings.md`, The `ARRAYINFO` indirection.
pub(super) const ARRAYINFO: u32 = 0x0000_0100;

/// The `BITSET` "no enum info" sentinel, in place of a member index.
///
/// `docs/metadata-encodings.md`: 36 of 1,526 `BITSET` members carry it, and it
/// is very likely what `CodeWalker`'s otherwise unexplained `0xFFF` re-mask is
/// a garbled memory of.
pub(super) const NO_ENUM: u16 = 0x0FFF;

/// How deeply structures may nest before the walk refuses.
///
/// The format states no limit. A pointer graph is attacker-chosen and can name
/// a cycle — a block whose structure holds a pointer back into itself — so the
/// walk needs a ceiling that is not the stack's. DR-011: a stated depth limit
/// rather than a stack overflow.
pub(super) const MAX_DEPTH: usize = 128;

/// How many elements one payload's walk may write.
///
/// A depth limit alone does not bound the work, and neither does a limit on
/// structures: a block graph shaped as a diamond repeated `MAX_DEPTH` times is
/// acyclic, within the depth, and exponential, and an inline array of an inline
/// array of an inline array is cubic in three numbers the schema declares
/// without nesting at all. So the budget is spent by every element the walk
/// writes rather than by the structures among them, and it is charged where the
/// element is written.
///
/// Measured 2026-08-30: the largest single file in the corpus writes **137,120**
/// elements and the whole 9,753-file corpus writes 17,893,616, so this is
/// roughly eight times the largest real document and costs nothing real.
///
/// **It does not bound the memory, and it was written down as though it did.**
/// The claim was that the walk's peak is its output, so a node ceiling is a
/// byte ceiling — checked against one payload, the 132-byte cubic one, which
/// peaked at 40 MB. An element's cost is not a constant: it carries two spaces
/// of indent per level of [`MAX_DEPTH`], so the same million nodes cost several
/// times as much when they are deep. `fuzz/fuzz_targets/pso.rs` found a
/// 5,068-byte payload peaking at **81,794,124 bytes** — 16,139 times its input,
/// and past the 64 MiB `fuzz/` holds a 64 KiB input to — on its way to
/// answering `DataRange`. [`MAX_OUTPUT_RATIO`] is the bound that is actually
/// about bytes; this one stays because it is what stops an exponential *walk*
/// whose output happens to be small.
pub(super) const MAX_NODES: usize = 1 << 20;

/// How many bytes of document one byte of payload may write.
///
/// The bound the memory needs, in the unit the memory is in. A node budget
/// bounds elements and an element is not a fixed number of bytes; this bounds
/// the document itself, which is what the walk's peak actually is.
///
/// Measured 2026-08-31 over all 9,753 shipped files: the largest document is
/// 6,226,862 bytes from an 828,312-byte payload, and the **worst ratio any real
/// file reaches is 26.4** — 3,803,181 bytes of document from 143,888 bytes of
/// `carvariations.ymt`. This is roughly ten times that, so it costs nothing
/// real, and it is checked: with this budget in place all 9,753 still convert.
///
/// Proportional rather than fixed because a fixed cap cannot do both jobs. One
/// that admits the 6.2 MB real document would let a 64 KiB payload write 6.2 MB
/// as well, which is the shape of the defect; one that bounds a 64 KiB payload
/// tightly would refuse the real file.
pub(super) const MAX_OUTPUT_RATIO: usize = 256;

/// The smallest document any payload may write, whatever its size.
///
/// A floor under [`MAX_OUTPUT_RATIO`], and the half of the bound that does the
/// work for a short payload — where a ratio does almost none, because a `PSO`
/// addresses its data by block and a very small file can legitimately name a
/// great deal of it. `an_array_charges_its_items_against_the_same_budget_a_
/// structure_charges` is the case that fixes the number: **132 bytes writing
/// 266,304 items**, which is a real property of the format the corpus does not
/// happen to contain, and 64 KiB of floor would have refused it.
///
/// 16 MiB is 2.6 times the largest document any shipped file writes
/// (6,226,862 bytes) and leaves the walk's peak near 32 MB, half of what
/// `fuzz/` holds a 64 KiB input to. The two together are the bound: the floor
/// answers for small payloads and the ratio for large ones, and no payload of
/// any size is unbounded.
pub(super) const MIN_OUTPUT: usize = 16 * 1024 * 1024;

/// How many bytes of document a payload of `payload` bytes may have.
///
/// One owner for the ceiling both directions obey (`docs/conventions.md` §3).
/// [`super::render`] refuses to write past it, and [`super::apply`] refuses a
/// document longer than it **before parsing one**, so a document that describes
/// no payload of this size costs nothing to decline. The two agree by
/// construction: every document [`super::render`] answers is at most this long.
pub(super) fn document_budget(payload: usize) -> usize {
    payload.saturating_mul(MAX_OUTPUT_RATIO).max(MIN_OUTPUT)
}

/// How far a `dataOffset` with bit 7 of its subtype set may have wrapped.
///
/// `docs/metadata-encodings.md`, `ARRAY` subtype `0x81`: the field is a `u16`
/// and the one real case has wrapped twice, at a structure 170,688 bytes long.
/// The ceiling is what the `i32` structure length allows.
pub(super) const MAX_WRAPS: u32 = 0xFFFF;

/// Why a byte stream is not a well-formed `PSO` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Malformed {
    /// The payload does not begin with the `PSIN` section tag.
    NotPso,
    /// A section header does not fit, or its length is less than the eight
    /// bytes of header it includes, or it overruns the payload.
    ///
    /// `docs/metadata-encodings.md`, Sections: the length includes the header,
    /// and Σ(section lengths) is the file length in 9,753 of 9,753.
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
    ///
    /// `docs/metadata-encodings.md` measured the `0xFFFF` mask to give a valid
    /// index in 64,906 of 64,906, so a file where it does not is not one
    /// Rockstar's packer wrote.
    ArrayInfo,
    /// A member whose subtype marks a wrapped `dataOffset` has no multiple of
    /// 65,536 that puts it after the member before it and inside its structure
    /// — or has more than one.
    ///
    /// `docs/metadata-encodings.md`, `ARRAY` subtype `0x81`: the argument that
    /// the recovery is correct is that the two constraints settle the multiple
    /// **uniquely**, so a structure in which they do not is one that argument
    /// does not cover, and taking the first would be a guess. Leaving the raw
    /// `u16` — what the reference implementation does — is worse than either,
    /// because it is a real offset inside the structure and renders whatever is
    /// there.
    Wrapped,
    /// The `CHKS` section is not the twenty bytes it always is.
    ///
    /// `docs/metadata-encodings.md`, `CHKS`: twenty bytes in 8,978 of 8,978
    /// files that carry one. The write direction stamps two `u32`s into it, so
    /// a shorter one would put them over whatever follows.
    Checksum,
    /// A read fell outside the `PSIN` section.
    DataRange,
    /// A pointer names a block that is not in the table, or an offset at or
    /// past that block's length.
    ///
    /// `docs/metadata-encodings.md`: 0 of 1,362,769 pointers in the corpus do
    /// either, so `CodeWalker`'s `offset = offset >> 8` guess is never needed
    /// and a reader should refuse rather than guess.
    Pointer,
    /// A structure the data reaches is not one the file's own `PSCH` defines.
    ///
    /// R1.7's measurement is that this happens 0 times in 9,753 files, which is
    /// what says no builtin fallback table is needed.
    UndefinedStructure,
    /// Structures nested deeper than this walk goes.
    TooDeep,
    /// The walk visited more structures than its budget allows.
    TooManyNodes,
    /// The document grew past what a payload of this size is allowed to write.
    TooLarge,
}

/// A `PSO` file that is well formed and says something this build does not
/// decode.
///
/// Separate from [`Malformed`] because the caller's position is different: the
/// bytes are right and the missing part is here. `docs/metadata-encodings.md`
/// measured 37 distinct `(type, subtype)` pairs over 580,044 members, and a
/// decoder that handles those handles every metadata file both games ship — so
/// every variant here is a pair that does not occur in either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unsupported {
    /// A `(type, subtype)` pair outside the 37 the corpus carries.
    DataType {
        /// The `PsoDataType` code.
        code: u8,
        /// Its subtype.
        subtype: u8,
    },
}

/// Why XML handed to [`super::from_xml`] does not describe the payload it was
/// given beside.
///
/// The write direction is an **edit** of the file the document was written
/// from — DR-049 — so a refusal here says which way the two disagree rather
/// than that the bytes are wrong. The bytes being wrong is [`Malformed`].
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
    /// can be.
    ///
    /// The ceiling [`super::render`] writes under, read as a refusal before the
    /// document is parsed: the whole document is materialised into a tree
    /// before the first comparison against the payload, so a document far
    /// larger than the file it edits has to be refusable on sight.
    TooLarge {
        /// How many bytes a document editing this payload may have.
        budget: usize,
        /// How many it has.
        len: usize,
    },
    /// An element carries no reserved `pso:` attribute, or more than one.
    ///
    /// Every element this mapping writes carries exactly one, which is DR-047's
    /// central decision: a record's type is written down and never inferred.
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
    /// A string is longer than the bytes it has to live in.
    ///
    /// Nothing here moves a block or rewrites a pointer, so a string may be
    /// shortened and never lengthened past its own room. The room is the store
    /// the value's form gives it, **less the one byte its terminator needs** —
    /// `docs/metadata-encodings.md`, Pointers — so an edit cannot leave a
    /// string with nothing to end it. It is never less than the value already
    /// there, so a payload that arrives that way is still written back
    /// unchanged. DR-052.
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
