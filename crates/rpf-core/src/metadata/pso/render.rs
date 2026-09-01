//! The walk from the root block to XML, bounds-checked against a depth/node/byte budget.

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

pub(super) const ITEM: &str = "item";

pub(super) const NULL: &str = "null";

pub(super) const STRUCT: &str = "struct";

pub(super) const ARRAY: &str = "array";

pub(super) const MAP: &str = "map";

/// The one `MAP` subtype that occurs: 98 members, all of them subtype 1.
pub(super) const ATBINARYMAP: &str = "atbinarymap";

pub(super) const ENUM: &str = "enum";

pub(super) const BITSET: &str = "bitset";

const INDENT: &str = "  ";

/// Reads a `PSO` payload and writes the XML that describes it.
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
    // The per-element check runs before writing, so the document may overshoot by
    // one; asking again here makes `document_budget` a bound the answer obeys.
    if writer.out.len() > writer.budget {
        return Err(bad(0, Malformed::TooLarge));
    }
    Ok(writer.out.into_bytes())
}

#[derive(Debug)]
struct Writer<'a> {
    data: Data<'a>,
    schema: &'a Schema,
    names: &'a Dictionary,
    out: String,
    nodes: usize,
    budget: usize,
}

#[derive(Debug, Clone, Copy)]
struct Place {
    depth: usize,
    indent: usize,
}

impl Place {
    const fn root() -> Self {
        Self {
            depth: 0,
            indent: 0,
        }
    }

    const fn inside(self) -> Self {
        Self {
            depth: self.depth.saturating_add(1),
            indent: self.indent.saturating_add(1),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct At<'a> {
    /// The structure whose member list an element index resolves against.
    owner: &'a Structure,
    /// Where the value starts, from the start of the `PSIN` section.
    address: u32,
    place: Place,
}

/// Everything the item loop needs, so that it is one argument rather than five.
#[derive(Debug, Clone, Copy)]
struct Items {
    /// The word the container's reserved attribute carries.
    reserved: &'static str,
    /// Its value: which subtype the container is.
    word: &'static str,
    described: Member,
    base: u32,
    stride: u32,
    count: u16,
}

impl<'a> Writer<'a> {
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

    fn enumerated(&mut self, width: Width, table: u32, tag: &str, at: At<'a>) -> Result<()> {
        let value = self.signed(width, at.address)?;
        let rendered = self
            .schema
            .enumerated(table, value)
            .map_or_else(|| value.to_string(), |name| self.names.render(name));
        self.leaf(tag, &reserved(ENUM), &rendered, at.place)
    }

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
            // Never asked for: a `PSCH` may describe structures the data never instantiates.
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

    /// Where an out-of-line array's items are, and how many.
    fn counted(&self, address: u32, count: u16) -> Result<(u32, u16)> {
        match self.data.block_pointer(address)? {
            Some((_, base)) => Ok((base, count)),
            None if count == 0 => Ok((address, 0)),
            None => Err(bad(u64::from(address), Malformed::Pointer)),
        }
    }

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

fn attribute(name: &str, value: &str) -> String {
    format!(" {name}=\"{}\"", escape(value))
}

impl Writer<'_> {
    /// Charges one element against the depth, node, and byte ceilings.
    fn spend(&mut self, place: Place) -> Result<()> {
        if place.depth > MAX_DEPTH {
            return Err(bad(0, Malformed::TooDeep));
        }
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > MAX_NODES {
            return Err(bad(0, Malformed::TooManyNodes));
        }
        // Charged in bytes too, since indent makes an element's size variable;
        // checked before writing, so the document overshoots by at most one.
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

    fn indent(&mut self, depth: usize) {
        for _ in 0..depth {
            self.out.push_str(INDENT);
        }
    }

    fn leaf(&mut self, tag: &str, reserved: &str, value: &str, place: Place) -> Result<()> {
        let attributes = attribute(reserved, value);
        self.empty(tag, &attributes, place)
    }

    fn empty(&mut self, tag: &str, attributes: &str, place: Place) -> Result<()> {
        self.spend(place)?;
        self.indent(place.indent);
        self.out.push('<');
        self.out.push_str(tag);
        self.out.push_str(attributes);
        self.out.push_str("/>\n");
        Ok(())
    }

    fn open(&mut self, tag: &str, attributes: &str, place: Place) -> Result<()> {
        self.spend(place)?;
        self.indent(place.indent);
        self.out.push('<');
        self.out.push_str(tag);
        self.out.push_str(attributes);
        self.out.push_str(">\n");
        Ok(())
    }

    /// Writes the closing tag of an element that `open` already charged for.
    fn close(&mut self, tag: &str, place: Place) {
        self.indent(place.indent);
        self.out.push_str("</");
        self.out.push_str(tag);
        self.out.push_str(">\n");
    }
}

fn reserved(word: &str) -> String {
    format!("{RESERVED_PREFIX}{word}")
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

    const ROOT_NAME: u32 = 0xD98B_B561;
    const MEMBER_NAME: u32 = 0x1234_5678;
    const ARRAYINFO: u32 = 0x0000_0100;

    /// A one-entry `PMAP` block table naming a block of `length` bytes at `offset`.
    fn one_block_pmap(offset: i32, length: i32) -> Vec<u8> {
        let mut pmap = vec![0u8; 8];
        pmap.extend_from_slice(&1i32.to_be_bytes());
        pmap.extend_from_slice(&1i16.to_be_bytes());
        pmap.extend_from_slice(&0u16.to_be_bytes());
        pmap.extend_from_slice(&ROOT_NAME.to_be_bytes());
        pmap.extend_from_slice(&offset.to_be_bytes());
        pmap.extend_from_slice(&0i32.to_be_bytes());
        pmap.extend_from_slice(&length.to_be_bytes());
        pmap
    }

    fn trivial_blocks() -> Blocks {
        Blocks::read(&one_block_pmap(0, 64), 64).expect("a minimal block table reads")
    }

    #[test]
    fn counted_refuses_a_null_pointer_that_declares_a_nonzero_count() {
        let section = vec![0u8; 8];
        let blocks = trivial_blocks();
        let schema = Schema::default();
        let names = Dictionary::default();
        let writer = Writer {
            data: Data {
                section: &section,
                blocks: &blocks,
            },
            schema: &schema,
            names: &names,
            out: String::new(),
            nodes: 0,
            budget: document_budget(section.len()),
        };

        assert_eq!(
            writer
                .counted(0, 0)
                .expect("a null pointer with no items is a legitimately empty array"),
            (0, 0)
        );
        let error = writer
            .counted(0, 1)
            .expect_err("a null pointer with one declared item is a contradiction");
        assert!(
            matches!(
                error,
                Error::BadPso {
                    cause: Malformed::Pointer,
                    ..
                }
            ),
            "{error:?}"
        );
    }

    #[test]
    fn spend_refuses_only_past_the_exact_node_ceiling() {
        let section = Vec::new();
        let blocks = trivial_blocks();
        let schema = Schema::default();
        let names = Dictionary::default();
        let data = Data {
            section: &section,
            blocks: &blocks,
        };

        let mut at_ceiling = Writer {
            data,
            schema: &schema,
            names: &names,
            out: String::new(),
            nodes: MAX_NODES - 1,
            budget: usize::MAX,
        };
        at_ceiling
            .spend(Place::root())
            .expect("the ceiling itself is allowed");
        assert_eq!(at_ceiling.nodes, MAX_NODES);

        let mut past_ceiling = Writer {
            data,
            schema: &schema,
            names: &names,
            out: String::new(),
            nodes: MAX_NODES,
            budget: usize::MAX,
        };
        let error = past_ceiling
            .spend(Place::root())
            .expect_err("one node past the ceiling is refused");
        assert!(
            matches!(
                error,
                Error::BadPso {
                    cause: Malformed::TooManyNodes,
                    ..
                }
            ),
            "{error:?}"
        );
    }

    #[test]
    fn spend_refuses_only_past_the_exact_byte_budget() {
        let section = Vec::new();
        let blocks = trivial_blocks();
        let schema = Schema::default();
        let names = Dictionary::default();
        let data = Data {
            section: &section,
            blocks: &blocks,
        };

        let mut at_budget = Writer {
            data,
            schema: &schema,
            names: &names,
            out: "x".repeat(10),
            nodes: 0,
            budget: 10,
        };
        at_budget
            .spend(Place::root())
            .expect("output exactly at the budget is still allowed");

        let mut past_budget = Writer {
            data,
            schema: &schema,
            names: &names,
            out: "x".repeat(11),
            nodes: 0,
            budget: 10,
        };
        let error = past_budget
            .spend(Place::root())
            .expect_err("one byte past the budget is refused");
        assert!(
            matches!(
                error,
                Error::BadPso {
                    cause: Malformed::TooLarge,
                    ..
                }
            ),
            "{error:?}"
        );
    }

    /// A `PSO` whose one field is a `PointerWithCount` array of one `UINT`.
    fn pointer_with_count_pso() -> Vec<u8> {
        let mut psin = Vec::new();
        psin.extend_from_slice(&section::PSIN);
        psin.extend_from_slice(&28u32.to_be_bytes());
        psin.extend_from_slice(b"pppppppp");
        psin.extend_from_slice(&2u32.to_be_bytes());
        psin.extend_from_slice(&0u32.to_be_bytes());
        psin.extend_from_slice(&42u32.to_be_bytes());

        let mut pmap = Vec::new();
        pmap.extend_from_slice(b"PMAP");
        pmap.extend_from_slice(&48u32.to_be_bytes());
        pmap.extend_from_slice(&1i32.to_be_bytes());
        pmap.extend_from_slice(&2i16.to_be_bytes());
        pmap.extend_from_slice(&0x7070u16.to_be_bytes());
        pmap.extend_from_slice(&ROOT_NAME.to_be_bytes());
        pmap.extend_from_slice(&16i32.to_be_bytes());
        pmap.extend_from_slice(&0i32.to_be_bytes());
        pmap.extend_from_slice(&8i32.to_be_bytes());
        pmap.extend_from_slice(&0x0000_0006u32.to_be_bytes());
        pmap.extend_from_slice(&24i32.to_be_bytes());
        pmap.extend_from_slice(&0i32.to_be_bytes());
        pmap.extend_from_slice(&4i32.to_be_bytes());

        let mut psch = Vec::new();
        psch.extend_from_slice(b"PSCH");
        psch.extend_from_slice(&56u32.to_be_bytes());
        psch.extend_from_slice(&1u32.to_be_bytes());
        psch.extend_from_slice(&ROOT_NAME.to_be_bytes());
        psch.extend_from_slice(&20i32.to_be_bytes());
        psch.extend_from_slice(&2u32.to_be_bytes());
        psch.extend_from_slice(&8i32.to_be_bytes());
        psch.extend_from_slice(&0u32.to_be_bytes());
        psch.extend_from_slice(&MEMBER_NAME.to_be_bytes());
        psch.extend_from_slice(&[0x0D, 0x06]);
        psch.extend_from_slice(&0u16.to_be_bytes());
        psch.extend_from_slice(&((1u32 << 16) | 1).to_be_bytes());
        psch.extend_from_slice(&ARRAYINFO.to_be_bytes());
        psch.extend_from_slice(&[0x06, 0x00]);
        psch.extend_from_slice(&0u16.to_be_bytes());
        psch.extend_from_slice(&0u32.to_be_bytes());

        let mut payload = psin;
        payload.extend_from_slice(&pmap);
        payload.extend_from_slice(&psch);
        payload
    }

    #[test]
    fn a_pointer_with_count_array_reads_through_its_pointer_not_past_it() {
        let payload = pointer_with_count_pso();
        let names = Dictionary::default();
        let xml = String::from_utf8(write(&payload, &names).expect("converts")).expect("utf8");
        assert!(
            xml.contains("pso:uint=\"42\""),
            "the item comes from the block the pointer names, not from the \
             pointer's own bytes: {xml}"
        );
    }

    const FINE_NAME: u32 = 0x4444_4444;

    /// A payload whose root has an inline array of `outer` inline arrays of
    /// `inner` zero-length strings and a fixed inline string of `fine` bytes.
    fn calibrated_pso(outer: u16, inner: u16, fine: u16) -> Vec<u8> {
        let fine = usize::from(fine);
        let mut psin = Vec::new();
        psin.extend_from_slice(&section::PSIN);
        let psin_len = u32::try_from(16 + fine).expect("fine is a u16");
        psin.extend_from_slice(&psin_len.to_be_bytes());
        psin.extend_from_slice(b"pppppppp");
        psin.extend(std::iter::repeat_n(b'a', fine));

        let mut pmap = Vec::new();
        pmap.extend_from_slice(b"PMAP");
        pmap.extend_from_slice(&32u32.to_be_bytes());
        pmap.extend_from_slice(&1i32.to_be_bytes());
        pmap.extend_from_slice(&1i16.to_be_bytes());
        pmap.extend_from_slice(&0x7070u16.to_be_bytes());
        pmap.extend_from_slice(&ROOT_NAME.to_be_bytes());
        pmap.extend_from_slice(&16i32.to_be_bytes());
        pmap.extend_from_slice(&0i32.to_be_bytes());
        pmap.extend_from_slice(&i32::try_from(fine).expect("fine is a u16").to_be_bytes());

        let mut psch = Vec::new();
        psch.extend_from_slice(b"PSCH");
        psch.extend_from_slice(&80u32.to_be_bytes());
        psch.extend_from_slice(&1u32.to_be_bytes());
        psch.extend_from_slice(&ROOT_NAME.to_be_bytes());
        psch.extend_from_slice(&20i32.to_be_bytes());
        psch.extend_from_slice(&4u32.to_be_bytes());
        psch.extend_from_slice(&i32::try_from(fine).expect("fine is a u16").to_be_bytes());
        psch.extend_from_slice(&0u32.to_be_bytes());

        psch.extend_from_slice(&MEMBER_NAME.to_be_bytes());
        psch.extend_from_slice(&[0x0D, 0x01]); // ARRAY, ATFIXEDARRAY
        psch.extend_from_slice(&0u16.to_be_bytes());
        psch.extend_from_slice(&((u32::from(outer) << 16) | 1).to_be_bytes());

        psch.extend_from_slice(&ARRAYINFO.to_be_bytes());
        psch.extend_from_slice(&[0x0D, 0x01]);
        psch.extend_from_slice(&0u16.to_be_bytes());
        psch.extend_from_slice(&((u32::from(inner) << 16) | 2).to_be_bytes());

        psch.extend_from_slice(&ARRAYINFO.to_be_bytes());
        psch.extend_from_slice(&[0x0B, 0x00]); // STRING, MEMBER, zero length
        psch.extend_from_slice(&0u16.to_be_bytes());
        psch.extend_from_slice(&0u32.to_be_bytes());

        psch.extend_from_slice(&FINE_NAME.to_be_bytes());
        psch.extend_from_slice(&[0x0B, 0x00]);
        psch.extend_from_slice(&0u16.to_be_bytes());
        psch.extend_from_slice(&(u32::try_from(fine).expect("fine is a u16") << 16).to_be_bytes());

        let mut payload = psin;
        payload.extend_from_slice(&pmap);
        payload.extend_from_slice(&psch);
        payload
    }

    #[test]
    fn write_refuses_a_document_past_its_budget_but_accepts_it_exactly_at_the_boundary() {
        const OUTER: u16 = 700;
        const PROBE: u16 = 100;

        let names = Dictionary::default();

        // Two renders apart give the exact bytes one more inner item costs at
        // this outer count.
        let probe_low = write(&calibrated_pso(OUTER, PROBE, 0), &names)
            .expect("renders")
            .len();
        let probe_high = write(&calibrated_pso(OUTER, PROBE + 1, 0), &names)
            .expect("renders")
            .len();
        let slope = probe_high - probe_low;
        assert!(slope > 0, "more items must write more bytes");

        let target = document_budget(calibrated_pso(OUTER, PROBE, 0).len());
        let steps = target.saturating_sub(probe_low) / slope;
        let inner = u16::try_from(u32::from(PROBE) + u32::try_from(steps).expect("fits"))
            .expect("stays inside a u16 at this outer count");

        let under = write(&calibrated_pso(OUTER, inner, 0), &names)
            .expect("renders")
            .len();
        assert!(
            under <= target,
            "the coarse search must land at or under the target: {under} vs {target}"
        );
        let gap = target - under;
        let fine = u16::try_from(gap).expect("the coarse search leaves less than a u16's worth");

        let boundary_payload = calibrated_pso(OUTER, inner, fine);
        let boundary_budget = document_budget(boundary_payload.len());
        let boundary_len = write(&boundary_payload, &names)
            .expect("a document exactly at its own budget is accepted")
            .len();
        assert_eq!(
            boundary_len, boundary_budget,
            "the calibration must land exactly on the boundary for the case below to test it"
        );

        let over_payload = calibrated_pso(OUTER, inner, fine + 1);
        let over_budget = document_budget(over_payload.len());
        assert_eq!(
            over_budget, boundary_budget,
            "one more fine-tune byte must not itself move the budget"
        );
        let error = write(&over_payload, &names)
            .expect_err("one byte past its own budget is refused, not merely past MAX_NODES");
        assert!(
            matches!(
                error,
                Error::BadPso {
                    cause: Malformed::TooLarge,
                    ..
                }
            ),
            "{error:?}"
        );
    }
}
