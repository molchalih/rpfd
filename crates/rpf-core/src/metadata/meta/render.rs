//! The walk from the root block, and the XML it writes.

use quick_xml::escape::escape;

use super::{
    BlockTag, Malformed, Member, RESERVED_PREFIX, Structure, TypeCode, bad,
    data::{Spot, Values, spell, until_nul},
    kind::{Field, Kind, MAX_DEPTH, Scalar, document_budget, fits, is_field, node_budget},
};
use crate::{
    error::Result,
    metadata::{hash::Dictionary, text},
};

pub(super) const ITEM: &str = "item";

pub(super) const NULL: &str = "null";

pub(super) const STRUCT: &str = "struct";

pub(super) const ARRAY: &str = "array";

/// The layout of an array that lives behind a pointer.
pub(super) const COUNTED: &str = "counted";

/// The layout of an array that lives in the member's own bytes.
pub(super) const INLINE: &str = "inline";

pub(super) const TEXT: &str = "string";

const INDENT: &str = "  ";

/// An array as both directions see it: its layout, base, and item count.
#[derive(Debug, Clone, Copy)]
pub(super) struct Items<'a> {
    /// The word the layout is written under: `COUNTED` or `INLINE`.
    pub(super) layout: &'static str,
    /// Where the first item is, or `None` when there is none.
    pub(super) base: Option<Spot<'a>>,
    pub(super) count: u32,
}

/// Reads a resource `Meta` payload and writes the XML that describes it.
pub(super) fn write(payload: &[u8], system_len: usize, names: &Dictionary) -> Result<Vec<u8>> {
    let meta = super::parse(payload, system_len)?;
    let root = *meta.root();
    let BlockTag::Structure(name) = root.tag else {
        return Err(bad(0x1C, Malformed::UndefinedStructure));
    };
    let mut writer = Writer {
        values: Values { meta: &meta },
        names,
        out: String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"),
        nodes: 0,
        nodes_allowed: node_budget(payload.len()),
        budget: document_budget(payload.len()),
    };
    let tag = spell(names, name);
    writer.structure(
        name,
        Spot {
            block: root,
            offset: 0,
        },
        &tag,
        Place::root(),
    )?;
    // The per-element check runs before the element is written, so the
    // document may overshoot by the last one; this makes the budget a bound
    // the answer obeys.
    if writer.out.len() > writer.budget {
        return Err(bad(0, Malformed::TooLarge));
    }
    Ok(writer.out.into_bytes())
}

#[derive(Debug)]
struct Writer<'a, 'b> {
    /// The file, and the reads every value needs of it.
    values: Values<'a, 'b>,
    names: &'b Dictionary,
    out: String,
    nodes: usize,
    /// The most elements this payload is allowed to write.
    nodes_allowed: usize,
    /// The most bytes of document this payload is allowed to write.
    budget: usize,
}

/// How deep the walk is, and how far the line is indented.
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

    /// One level deeper, at the same indent, for a pointer hop.
    const fn deeper(self) -> Self {
        Self {
            depth: self.depth.saturating_add(1),
            indent: self.indent,
        }
    }
}

impl<'a> Writer<'a, '_> {
    fn structure(&mut self, name: u32, spot: Spot<'a>, tag: &str, place: Place) -> Result<()> {
        let structure = *self
            .values
            .meta
            .structure(name)
            .ok_or_else(|| bad(spot.address(), Malformed::UndefinedStructure))?;
        let fields: Vec<Member> = structure
            .members()
            .filter(|member| is_field(member.name))
            .collect();
        let own_type = attribute(&reserved(STRUCT), &spell(self.names, name));
        if fields.is_empty() {
            return self.empty(tag, &own_type, place);
        }
        self.open(tag, &own_type, place)?;
        for member in fields {
            let tag = spell(self.names, member.name);
            let field = Field {
                member,
                owner: Some(structure),
            };
            let at = self.field(structure, member, spot)?;
            self.value(field, &tag, at, place.inside())?;
        }
        self.close(tag, place);
        Ok(())
    }

    /// Where a member's value is, checked to lie inside its structure.
    fn field(&self, structure: Structure<'a>, member: Member, spot: Spot<'a>) -> Result<Spot<'a>> {
        let field = Field {
            member,
            owner: Some(structure),
        };
        let width = field.width(self.values.meta, spot.address())?;
        fits(&structure, member.data_offset, width, spot.address())?;
        spot.step(member.data_offset)
    }

    /// Writes one value — a member of a structure, or one item of an array.
    fn value(&mut self, field: Field<'a>, tag: &str, spot: Spot<'a>, place: Place) -> Result<()> {
        // Here as well as in `spend`: a pointer into a block tagged with a
        // bare type code writes no element of its own and recurses.
        if place.depth > MAX_DEPTH {
            return Err(bad(spot.address(), Malformed::TooDeep));
        }
        match field.kind()? {
            Kind::Scalar(scalar) => {
                let value = self.scalar(scalar, spot)?;
                self.leaf(tag, &reserved(scalar.word()), &value, place)
            }
            Kind::Structure(name) => self.structure(name, spot, tag, place),
            Kind::Pointer => match self.values.pointer(spot)? {
                None => self.leaf(tag, &reserved(NULL), STRUCT, place),
                Some(landing) => self.target(landing, tag, place),
            },
            Kind::Array => {
                let (base, count) = self.values.items(spot)?;
                self.items(
                    field,
                    tag,
                    Items {
                        layout: COUNTED,
                        base,
                        count,
                    },
                    place,
                )
            }
            Kind::InlineArray(count) => self.items(
                field,
                tag,
                Items {
                    layout: INLINE,
                    base: Some(spot),
                    count,
                },
                place,
            ),
            Kind::Text => match self.values.counted(spot)? {
                (None, _) => self.leaf(tag, &reserved(NULL), TEXT, place),
                (Some(landing), store) => {
                    let value = text::encode(until_nul(landing.bytes(store)?));
                    self.leaf(tag, &reserved(TEXT), &value, place)
                }
            },
            Kind::InlineText(len) => {
                let value = text::encode(until_nul(spot.bytes(len)?));
                self.leaf(tag, &reserved(TEXT), &value, place)
            }
        }
    }

    fn target(&mut self, landing: Spot<'a>, tag: &str, place: Place) -> Result<()> {
        match landing.block.tag {
            BlockTag::Structure(name) => self.structure(name, landing, tag, place),
            BlockTag::Type(word) => {
                let code = u8::try_from(word)
                    .map_err(|_| bad(landing.address(), Malformed::UndefinedStructure))?;
                // A typed block carries values and no member record, so no
                // structure an `ARRAYINFO` index could resolve against.
                // `deeper` and not `inside`: this hop writes no element of its
                // own, so nothing else charges it against the ceiling.
                self.value(
                    Field {
                        member: typed(code),
                        owner: None,
                    },
                    tag,
                    landing,
                    place.deeper(),
                )
            }
        }
    }

    /// Writes an array of either layout: `items.count` items from `items.base`.
    fn items(&mut self, field: Field<'a>, tag: &str, items: Items<'a>, place: Place) -> Result<()> {
        let attributes = attribute(&reserved(ARRAY), items.layout);
        let (Some(base), true) = (items.base, items.count != 0) else {
            // An empty array's element type is never asked for: a file may
            // describe an element it never instantiates.
            return self.empty(tag, &attributes, place);
        };
        let described = field.element(base.address())?;
        let stride = described.stride(self.values.meta, base.address())?;
        self.open(tag, &attributes, place)?;
        let item = reserved(ITEM);
        for index in 0..items.count {
            let at = base.step(
                index
                    .checked_mul(stride)
                    .ok_or_else(|| bad(base.address(), Malformed::DataRange))?,
            )?;
            self.value(described, &item, at, place.inside())?;
        }
        self.close(tag, place);
        Ok(())
    }

    /// A fixed-width value, as the text of its attribute.
    fn scalar(&self, scalar: Scalar, spot: Spot<'a>) -> Result<String> {
        let bytes = spot.bytes(scalar.bytes())?;
        let gone = || bad(spot.address(), Malformed::DataRange);
        let word = |at: usize| -> Result<u32> { super::u32_at(bytes, at).ok_or_else(gone) };
        let half = |at: usize| -> Result<u16> { super::u16_at(bytes, at).ok_or_else(gone) };
        let byte = |at: usize| -> Result<u8> { bytes.get(at).copied().ok_or_else(gone) };
        let lanes = |count: usize| -> Result<String> {
            let mut parts = Vec::with_capacity(count);
            for lane in 0..count {
                parts.push(text::float(f32::from_bits(word(
                    lane.checked_mul(4).ok_or_else(gone)?,
                )?)));
            }
            Ok(parts.join(", "))
        };
        Ok(match scalar {
            Scalar::Bool => match byte(0)? {
                0 => "false".to_owned(),
                1 => "true".to_owned(),
                other => other.to_string(),
            },
            Scalar::Byte => byte(0)?.cast_signed().to_string(),
            Scalar::UByte | Scalar::ByteEnum => byte(0)?.to_string(),
            Scalar::Short => half(0)?.cast_signed().to_string(),
            Scalar::UShort | Scalar::ShortFlags => half(0)?.to_string(),
            Scalar::Int | Scalar::IntEnum => word(0)?.cast_signed().to_string(),
            Scalar::UInt | Scalar::IntFlags1 | Scalar::IntFlags2 => word(0)?.to_string(),
            Scalar::Float => text::float(f32::from_bits(word(0)?)),
            Scalar::Float3 => lanes(3)?,
            Scalar::Float4 => lanes(4)?,
            Scalar::Hash => spell(self.names, word(0)?),
        })
    }
}

/// A member of no structure, standing for the one value a typed data block holds.
fn typed(code: u8) -> Member {
    Member {
        name: 0,
        data_offset: 0,
        type_code: TypeCode::new(code),
        subtype: 0,
        array_info_index: 0,
        reference_key: 0,
    }
}

fn attribute(name: &str, value: &str) -> String {
    format!(" {name}=\"{}\"", escape(value))
}

/// A word, as the reserved name that carries it.
pub(super) fn reserved(word: &str) -> String {
    format!("{RESERVED_PREFIX}{word}")
}

impl Writer<'_, '_> {
    /// Charges one element against the ceilings.
    fn spend(&mut self, place: Place) -> Result<()> {
        if place.depth > MAX_DEPTH {
            return Err(bad(0, Malformed::TooDeep));
        }
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > self.nodes_allowed {
            return Err(bad(0, Malformed::TooManyNodes));
        }
        // In bytes as well as elements: an element carries two spaces of
        // indent per level, so a deep million costs more than a shallow one.
        if self.out.len() > self.budget {
            return Err(bad(0, Malformed::TooLarge));
        }
        Ok(())
    }

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

    /// Writes the closing tag of an element `open` has charged for.
    fn close(&mut self, tag: &str, place: Place) {
        self.indent(place.indent);
        self.out.push_str("</");
        self.out.push_str(tag);
        self.out.push_str(">\n");
    }
}
