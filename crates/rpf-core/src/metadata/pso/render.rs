//! The walk from the root block, and the XML it writes.
//!
//! Driven by the file's own `PSCH` and by nothing else — R5.3, and DR-047 is
//! the mapping. Every read is bounds-checked against the `PSIN` section and
//! every pointer against its own block's length, and the walk carries both a
//! depth ceiling and a budget, because the block graph is attacker-chosen and
//! can name a cycle or a diamond.
//!
//! Both are charged in [`Writer::empty`] and [`Writer::open`], which are the
//! only two places an element is written. Charging at the structure instead
//! left the array path free of both, and an array's size is a number the schema
//! declares rather than something it has to nest to reach.

use quick_xml::escape::escape;

use super::{
    bad,
    data::{Data, step, until_nul},
    model::{MAX_DEPTH, MAX_NODES, Malformed, document_budget},
    schema::{
        Blocks, COUNT_AT, Kind, Layout, MAP_POINTER_AT, Member, Nested, Scalar, Schema, Structure,
        Text, Width,
    },
    section,
};
use crate::{
    error::Result,
    metadata::{
        hash::{Dictionary, RESERVED_PREFIX},
        text,
    },
};

/// The word an array item or a map entry is written under.
///
/// Reserved, like every name this mapping invents, by the `pso:` prefix
/// [`Dictionary::load`] refuses a dictionary name to begin with. A prefix and
/// deliberately **not** a namespace, for the reason DR-043 gives for `RBF`.
pub(super) const ITEM: &str = "item";

/// The word a null pointer is written under. Its value is the type word the
/// value would have had.
pub(super) const NULL: &str = "null";

/// The word a structure is written under, in both of the places one is named:
/// as the attribute on the element of a structure, whose value is that
/// structure's own name — the only place a pointer's concrete type is written
/// down — and as the value of `pso:null` for a structure pointer that is null.
pub(super) const STRUCT: &str = "struct";

/// The word an array is written under; its value is which of the six `ARRAY`
/// subtypes it is.
pub(super) const ARRAY: &str = "array";

/// The word an `ATBINARYMAP` is written under.
pub(super) const MAP: &str = "map";

/// The one `MAP` subtype that occurs: 98 members, all of them subtype 1.
pub(super) const ATBINARYMAP: &str = "atbinarymap";

/// The word an enum is written under.
pub(super) const ENUM: &str = "enum";

/// The word a bitset is written under.
pub(super) const BITSET: &str = "bitset";

/// How far each level of nesting is indented.
const INDENT: &str = "  ";

/// Reads a `PSO` payload and writes the XML that describes it.
///
/// # Errors
///
/// [`crate::Error::BadPso`] when the file contradicts itself, and
/// [`crate::Error::UnsupportedPso`] when it is well formed and carries a member
/// type outside the 37 pairs the corpus has.
pub(super) fn write(payload: &[u8], names: &Dictionary) -> Result<Vec<u8>> {
    let sections = section::chain(payload).map_err(|(at, cause)| bad(at, cause))?;
    let find = |tag: [u8; 4]| {
        sections
            .iter()
            .find(|section| section.tag == tag)
            .map(|section| section.bytes)
    };
    let data = find(section::PSIN).ok_or_else(|| bad(0, Malformed::MissingSection))?;
    let table = find(section::PMAP).ok_or_else(|| bad(0, Malformed::MissingSection))?;
    let described = find(section::PSCH).ok_or_else(|| bad(0, Malformed::MissingSection))?;

    let data_len = u32::try_from(data.len()).map_err(|_| bad(0, Malformed::Section))?;
    let blocks = Blocks::read(table, data_len)?;
    let schema = Schema::read(described)?;

    let root = *blocks.root();
    let mut writer = Writer {
        data: Data {
            section: data,
            blocks: &blocks,
        },
        schema: &schema,
        names,
        out: String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"),
        nodes: 0,
        budget: document_budget(payload.len()),
    };
    let tag = names.render(root.name);
    writer.structure(root.name, root.offset, &tag, Place::root())?;
    // The per-element check is asked before the element is written, so the
    // document may overshoot by the last one. Asking again at the end is what
    // makes `document_budget` a bound the answer obeys rather than one the walk
    // merely aims at — and what lets `apply` refuse a longer document on sight
    // without refusing anything this ever wrote.
    if writer.out.len() > writer.budget {
        return Err(bad(0, Malformed::TooLarge));
    }
    Ok(writer.out.into_bytes())
}

/// The walk in progress.
#[derive(Debug)]
struct Writer<'a> {
    /// The data section and the block table that addresses it.
    data: Data<'a>,
    schema: &'a Schema,
    names: &'a Dictionary,
    out: String,
    nodes: usize,
    /// The most bytes of document this payload is allowed to write.
    ///
    /// `MAX_OUTPUT_RATIO` of the payload, and never less than `MIN_OUTPUT`.
    /// Held rather than recomputed because it is a fact about the payload and
    /// the payload does not change.
    budget: usize,
}

/// How deep the walk is, and how far the line is indented.
///
/// The two move together everywhere except inside an array, where an item is
/// one level of both.
#[derive(Debug, Clone, Copy)]
struct Place {
    depth: usize,
    indent: usize,
}

impl Place {
    /// The root's place.
    const fn root() -> Self {
        Self {
            depth: 0,
            indent: 0,
        }
    }

    /// One level in.
    const fn inside(self) -> Self {
        Self {
            depth: self.depth.saturating_add(1),
            indent: self.indent.saturating_add(1),
        }
    }
}

/// Where a value is, and what describes it.
#[derive(Debug, Clone, Copy)]
struct At<'a> {
    /// The structure whose member list an element index resolves against.
    owner: &'a Structure,
    /// Where the value starts, from the start of the `PSIN` section.
    address: u32,
    /// Where in the document it goes.
    place: Place,
}

/// Everything the item loop needs, so that it is one argument rather than five.
#[derive(Debug, Clone, Copy)]
struct Items {
    /// The word the container's reserved attribute carries.
    reserved: &'static str,
    /// Its value: which subtype the container is.
    word: &'static str,
    /// The member that describes one item.
    described: Member,
    /// Where the first item is.
    base: u32,
    /// How far apart they are.
    stride: u32,
    /// How many there are.
    count: u16,
}

impl<'a> Writer<'a> {
    /// Writes one structure instance as an element named `tag`.
    fn structure(&mut self, name: u32, address: u32, tag: &str, place: Place) -> Result<()> {
        let schema = self.schema;
        let names = self.names;
        let structure = schema
            .structure(name)
            .ok_or_else(|| bad(u64::from(address), Malformed::UndefinedStructure))?;
        let fields: Vec<&Member> = structure
            .members
            .iter()
            .filter(|member| !member.is_arrayinfo())
            .collect();
        let own_type = attribute(&reserved(STRUCT), &names.render(name));
        if fields.is_empty() {
            return self.empty(tag, &own_type, place);
        }
        self.open(tag, &own_type, place)?;
        for member in fields {
            let address = address
                .checked_add(member.offset)
                .ok_or_else(|| bad(u64::from(address), Malformed::DataRange))?;
            let field = names.render(member.name);
            self.value(
                member.kind,
                &field,
                At {
                    owner: structure,
                    address,
                    place: place.inside(),
                },
            )?;
        }
        self.close(tag, place);
        Ok(())
    }

    /// Writes one value — a member of a structure, or one element of an array.
    fn value(&mut self, kind: Kind, tag: &str, at: At<'a>) -> Result<()> {
        match kind {
            Kind::Scalar(scalar) => {
                let value = self.read_scalar(scalar, at.address)?;
                self.leaf(tag, &reserved(scalar.word()), &value, at.place)
            }
            Kind::Text(form) => self.text(form, tag, at),
            Kind::Nested(form) => self.nested(form, tag, at),
            Kind::Enumerated { width, table } => self.enumerated(width, table, tag, at),
            Kind::Bits { width, table } => self.bits(width, table, tag, at),
            Kind::Array {
                layout,
                element,
                count,
            } => self.array(layout, element, count, tag, at),
            Kind::Map => self.map(tag, at),
        }
    }

    /// Writes one of the six string forms.
    fn text(&mut self, form: Text, tag: &str, at: At<'a>) -> Result<()> {
        let names = self.names;
        let word = form.word();
        let value = match form {
            Text::AtNonFinalHashString | Text::AtFinalHashString => {
                names.render(self.data.word(at.address)?)
            }
            Text::Member(len) => {
                text::encode(until_nul(self.data.bytes(at.address, u32::from(len))?))
            }
            Text::Pointer | Text::ConstString => match self.data.pointer(at.address)? {
                None => return self.leaf(tag, &reserved(NULL), word, at.place),
                Some(address) => text::encode(self.data.terminated(address)?),
            },
            Text::AtString => {
                let count = self.data.half(at.address.saturating_add(COUNT_AT))?;
                match self.data.pointer(at.address)? {
                    None => return self.leaf(tag, &reserved(NULL), word, at.place),
                    Some(address) => {
                        text::encode(until_nul(self.data.bytes(address, u32::from(count))?))
                    }
                }
            }
        };
        self.leaf(tag, &reserved(word), &value, at.place)
    }

    /// Writes a nested structure, inline or through a pointer.
    ///
    /// `docs/metadata-encodings.md`: a `STRUCT` member with subtype 3 or 4
    /// carries `referenceKey == 0` in 43,225 of 43,225, so its type is not in
    /// the member at all — it is the `nameHash` of the block the pointer lands
    /// in, which is `PMAP` doing the work rather than an external schema.
    fn nested(&mut self, form: Nested, tag: &str, at: At<'a>) -> Result<()> {
        let (name, address) = match form {
            Nested::Structure(name) => (name, at.address),
            Nested::Pointer | Nested::SimplePointer => {
                let Some((block, address)) = self.data.block_pointer(at.address)? else {
                    return self.leaf(tag, &reserved(NULL), STRUCT, at.place);
                };
                (block.name, address)
            }
        };
        self.structure(name, address, tag, at.place)
    }

    /// Writes an enum, by the name its own table gives the stored value.
    fn enumerated(&mut self, width: Width, table: u32, tag: &str, at: At<'a>) -> Result<()> {
        let value = self.signed(width, at.address)?;
        let rendered = self
            .schema
            .enumerated(table, value)
            .map_or_else(|| value.to_string(), |name| self.names.render(name));
        self.leaf(tag, &reserved(ENUM), &rendered, at.place)
    }

    /// Writes a bitset as the set of bits it holds.
    ///
    /// A bit the enum names is written as that name; one it does not is written
    /// as its index. A dictionary name can never be a decimal number — it must
    /// begin with a letter, `_` or `:` — so the two cannot be confused.
    fn bits(&mut self, width: Width, table: Option<u32>, tag: &str, at: At<'a>) -> Result<()> {
        let value = self.unsigned(width, at.address)?;
        let mut set = Vec::new();
        for bit in 0..width.bytes().saturating_mul(8) {
            if value & (1u64 << bit) == 0 {
                continue;
            }
            let index = i32::try_from(bit).unwrap_or(i32::MAX);
            set.push(
                table
                    .and_then(|table| self.schema.enumerated(table, index))
                    .map_or_else(|| index.to_string(), |name| self.names.render(name)),
            );
        }
        self.leaf(tag, &reserved(BITSET), &set.join(" "), at.place)
    }

    /// Writes an array and its items.
    fn array(
        &mut self,
        layout: Layout,
        element: u16,
        count: u16,
        tag: &str,
        at: At<'a>,
    ) -> Result<()> {
        let (base, count) = match layout {
            Layout::AtArray => self.counted(
                at.address,
                self.data.half(at.address.saturating_add(COUNT_AT))?,
            )?,
            Layout::PointerWithCount => self.counted(at.address, count)?,
            _ => (at.address, count),
        };
        if count == 0 {
            // An empty array's element type is never asked for. A `PSCH`
            // legitimately describes structures the data never instantiates —
            // 36 such hashes across the corpus — and an array of none of them
            // is one of the ways they go unreached.
            return self.empty(tag, &attribute(&reserved(ARRAY), layout.word()), at.place);
        }
        let described = *at
            .owner
            .members
            .get(usize::from(element))
            .ok_or_else(|| bad(u64::from(at.address), Malformed::ArrayInfo))?;
        let stride = self
            .schema
            .extent(at.owner, &described, 0)
            .ok_or_else(|| bad(u64::from(at.address), Malformed::UndefinedStructure))?;
        self.items(
            tag,
            Items {
                reserved: ARRAY,
                word: layout.word(),
                described,
                base,
                stride,
                count,
            },
            at,
        )
    }

    /// Where an out-of-line array's items are, and how many there are.
    ///
    /// A null pointer with a non-zero count is refused rather than read as
    /// empty: it is a file contradicting itself, and 0 of 1,362,769 pointers in
    /// the corpus do it.
    fn counted(&self, address: u32, count: u16) -> Result<(u32, u16)> {
        match self.data.block_pointer(address)? {
            Some((_, base)) => Ok((base, count)),
            None if count == 0 => Ok((address, 0)),
            None => Err(bad(u64::from(address), Malformed::Pointer)),
        }
    }

    /// Writes an `ATBINARYMAP` and its entries.
    ///
    /// Measured 2026-08-30: the counted pointer at byte 8 of the member lands
    /// on an array of structures whose type is the target block's `nameHash`,
    /// and that structure carries both a `Key` and an `Item` member in 17,560
    /// of 17,560 instances. So a map is an array of key/value structures and
    /// needs no vocabulary of its own beyond saying that it is one.
    fn map(&mut self, tag: &str, at: At<'a>) -> Result<()> {
        let header = at.address.saturating_add(MAP_POINTER_AT);
        let count = self.data.half(header.saturating_add(COUNT_AT))?;
        let Some((block, base)) = self.data.block_pointer(header)? else {
            if count != 0 {
                return Err(bad(u64::from(header), Malformed::Pointer));
            }
            return self.empty(tag, &attribute(&reserved(MAP), ATBINARYMAP), at.place);
        };
        if count == 0 {
            return self.empty(tag, &attribute(&reserved(MAP), ATBINARYMAP), at.place);
        }
        let name = block.name;
        let stride = self
            .schema
            .structure(name)
            .map(|structure| structure.length)
            .ok_or_else(|| bad(u64::from(base), Malformed::UndefinedStructure))?;
        self.open(tag, &attribute(&reserved(MAP), ATBINARYMAP), at.place)?;
        let item = reserved(ITEM);
        for index in 0..u32::from(count) {
            let address = step(base, index, stride)
                .ok_or_else(|| bad(u64::from(base), Malformed::DataRange))?;
            self.structure(name, address, &item, at.place.inside())?;
        }
        self.close(tag, at.place);
        Ok(())
    }

    /// Writes the items of an array.
    fn items(&mut self, tag: &str, items: Items, at: At<'a>) -> Result<()> {
        let attributes = attribute(&reserved(items.reserved), items.word);
        if items.count == 0 {
            return self.empty(tag, &attributes, at.place);
        }
        self.open(tag, &attributes, at.place)?;
        let item = reserved(ITEM);
        for index in 0..u32::from(items.count) {
            let address = step(items.base, index, items.stride)
                .ok_or_else(|| bad(u64::from(items.base), Malformed::DataRange))?;
            self.value(
                items.described.kind,
                &item,
                At {
                    owner: at.owner,
                    address,
                    place: at.place.inside(),
                },
            )?;
        }
        self.close(tag, at.place);
        Ok(())
    }
}

/// One reserved attribute, as it is written.
fn attribute(name: &str, value: &str) -> String {
    format!(" {name}=\"{}\"", escape(value))
}

impl Writer<'_> {
    /// Charges one element against the ceilings.
    ///
    /// Called from [`Writer::empty`] and [`Writer::open`], which is every
    /// element this mapping writes and the only way to write one. Charging at
    /// the structure instead left the whole array path free: an inline array of
    /// an inline array of an inline array declares its own lengths, so 176
    /// bytes of schema asked for 2.8*10^14 items and neither ceiling was ever
    /// consulted.
    fn spend(&mut self, place: Place) -> Result<()> {
        if place.depth > MAX_DEPTH {
            return Err(bad(0, Malformed::TooDeep));
        }
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > MAX_NODES {
            return Err(bad(0, Malformed::TooManyNodes));
        }
        // Charged in bytes as well as in elements, because an element is not a
        // fixed number of bytes: it carries two spaces of indent per level, so
        // a deep million costs several times a shallow million. `MAX_NODES`'s
        // own doc comment claimed the node count bounded the memory; a
        // 5,068-byte payload peaking at 81.8 MB is what said otherwise.
        //
        // Checked before the element rather than after, so the document
        // overshoots by at most the one being written.
        if self.out.len() > self.budget {
            return Err(bad(0, Malformed::TooLarge));
        }
        Ok(())
    }

    /// A stored enum value, sign-extended from its width.
    fn signed(&self, width: Width, address: u32) -> Result<i32> {
        let bytes = self.data.bytes(address, width.bytes())?;
        let gone = || bad(u64::from(address), Malformed::DataRange);
        match width {
            Width::Eight => section::u8(bytes, 0)
                .map(|byte| i32::from(byte.cast_signed()))
                .ok_or_else(gone),
            Width::Sixteen => section::i16(bytes, 0).map(i32::from).ok_or_else(gone),
            Width::ThirtyTwo => section::i32(bytes, 0).ok_or_else(gone),
        }
    }

    /// A stored bitset value, widened from its width.
    fn unsigned(&self, width: Width, address: u32) -> Result<u64> {
        let bytes = self.data.bytes(address, width.bytes())?;
        let gone = || bad(u64::from(address), Malformed::DataRange);
        match width {
            Width::Eight => section::u8(bytes, 0).map(u64::from).ok_or_else(gone),
            Width::Sixteen => section::u16(bytes, 0).map(u64::from).ok_or_else(gone),
            Width::ThirtyTwo => section::u32(bytes, 0).map(u64::from).ok_or_else(gone),
        }
    }

    /// A fixed-width value, as the text of its attribute.
    fn read_scalar(&self, scalar: Scalar, address: u32) -> Result<String> {
        let bytes = self.data.bytes(address, scalar.bytes())?;
        let gone = || bad(u64::from(address), Malformed::DataRange);
        let lanes = |count: usize| -> Result<String> {
            let mut parts = Vec::with_capacity(count);
            for lane in 0..count {
                parts.push(text::float(
                    section::f32(bytes, lane.saturating_mul(4)).ok_or_else(gone)?,
                ));
            }
            Ok(parts.join(", "))
        };
        match scalar {
            Scalar::Bool => Ok(match section::u8(bytes, 0).ok_or_else(gone)? {
                0 => "false".to_owned(),
                1 => "true".to_owned(),
                other => other.to_string(),
            }),
            Scalar::Char => Ok(section::u8(bytes, 0)
                .ok_or_else(gone)?
                .cast_signed()
                .to_string()),
            Scalar::UChar => Ok(section::u8(bytes, 0).ok_or_else(gone)?.to_string()),
            Scalar::Short => Ok(section::i16(bytes, 0).ok_or_else(gone)?.to_string()),
            Scalar::UShort => Ok(section::u16(bytes, 0).ok_or_else(gone)?.to_string()),
            Scalar::Int => Ok(section::i32(bytes, 0).ok_or_else(gone)?.to_string()),
            Scalar::Uint | Scalar::Color => {
                Ok(section::u32(bytes, 0).ok_or_else(gone)?.to_string())
            }
            Scalar::Uint64 => Ok(section::u64(bytes, 0).ok_or_else(gone)?.to_string()),
            Scalar::Float16 => Ok(text::float(section::f16(bytes, 0).ok_or_else(gone)?)),
            Scalar::Float => Ok(text::float(section::f32(bytes, 0).ok_or_else(gone)?)),
            Scalar::Vector2 => lanes(2),
            Scalar::Vector3 | Scalar::Vec3V => lanes(3),
            Scalar::Vector4 | Scalar::Vec4V => lanes(4),
        }
    }

    /// Writes `depth` levels of indentation.
    fn indent(&mut self, depth: usize) {
        for _ in 0..depth {
            self.out.push_str(INDENT);
        }
    }

    /// Writes an empty element carrying one reserved attribute.
    fn leaf(&mut self, tag: &str, reserved: &str, value: &str, place: Place) -> Result<()> {
        let attributes = attribute(reserved, value);
        self.empty(tag, &attributes, place)
    }

    /// Writes an empty element with the attributes already rendered.
    fn empty(&mut self, tag: &str, attributes: &str, place: Place) -> Result<()> {
        self.spend(place)?;
        self.indent(place.indent);
        self.out.push('<');
        self.out.push_str(tag);
        self.out.push_str(attributes);
        self.out.push_str("/>\n");
        Ok(())
    }

    /// Writes an opening tag with the attributes already rendered.
    fn open(&mut self, tag: &str, attributes: &str, place: Place) -> Result<()> {
        self.spend(place)?;
        self.indent(place.indent);
        self.out.push('<');
        self.out.push_str(tag);
        self.out.push_str(attributes);
        self.out.push_str(">\n");
        Ok(())
    }

    /// Writes the closing tag of an element [`Writer::open`] has charged for.
    fn close(&mut self, tag: &str, place: Place) {
        self.indent(place.indent);
        self.out.push_str("</");
        self.out.push_str(tag);
        self.out.push_str(">\n");
    }
}

/// A word, as the reserved name that carries it.
///
/// One spelling of the prefix, in one place, and it is the same constant
/// [`Dictionary::load`] refuses a dictionary name to begin with — so the guard
/// and the vocabulary it guards are one fact rather than two. The words are
/// [`Scalar::word`], [`Text::word`], [`Layout::word`] and the ones this module
/// names.
fn reserved(word: &str) -> String {
    format!("{RESERVED_PREFIX}{word}")
}
