//! The walk from the root block, and the XML it writes.
//!
//! Driven by the file's own three tables and by nothing else, which is what
//! `docs/metadata-encodings.md` measured: 49,614 files walked from their root
//! using only their own tables, 88,171,116 nodes and **0** references a file
//! did not define. So nothing here consults a builtin table and there is none
//! to consult.
//!
//! The mapping is DR-047's, carried across from `PSO` with one prefix of its
//! own: every element carries exactly one reserved `meta:` attribute whose
//! *name* is its type and whose *value* is its value, a structure carries
//! `meta:struct` naming its own type — the only place a pointer's concrete type
//! is written down — and an array's items are `<meta:item>`. `meta:` is a
//! reserved name **prefix** and deliberately not a namespace, for DR-043's
//! reason: what a name may be is decided by a dictionary the user supplied.
//!
//! Every read is bounds-checked against the block it is in, and the walk
//! carries a depth ceiling, a node budget and an output budget, because the
//! block graph is attacker-chosen and can name a cycle or a diamond.

use quick_xml::escape::escape;

use super::{
    BlockTag, Malformed, Member, RESERVED_PREFIX, Structure, TypeCode, bad,
    data::{Spot, Values, hex, spell, until_nul},
    kind::{Field, Kind, MAX_DEPTH, MAX_NODES, Scalar, document_budget, fits, is_field},
};
use crate::{
    error::Result,
    metadata::{hash::Dictionary, text},
};

/// The word an array item is written under.
pub(super) const ITEM: &str = "item";

/// The word a null pointer is written under. Its value is the type word the
/// value would have had.
pub(super) const NULL: &str = "null";

/// The word a structure is written under, in both of the places one is named:
/// on the element of a structure, where its value is that structure's own name,
/// and as the value of `meta:null` for a pointer that is null.
pub(super) const STRUCT: &str = "struct";

/// The word an array is written under.
pub(super) const ARRAY: &str = "array";

/// The one array layout this encoding has: a pointer and two counts.
pub(super) const COUNTED: &str = "counted";

/// The word a string is written under.
pub(super) const TEXT: &str = "string";

/// The word a counted run of bytes is written under.
pub(super) const BYTES: &str = "bytes";

/// How far each level of nesting is indented.
const INDENT: &str = "  ";

/// Reads a resource `Meta` payload and writes the XML that describes it.
///
/// # Errors
///
/// [`crate::Error::BadMeta`] when the file contradicts itself, and
/// [`crate::Error::UnsupportedMeta`] when it is well formed and carries a
/// member type code outside the 23 this build names.
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
    // The per-element check is asked before the element is written, so the
    // document may overshoot by the last one. Asking again here is what makes
    // the budget a bound the answer obeys rather than one the walk aims at —
    // and what lets `apply` refuse a longer document on sight without refusing
    // anything this ever wrote.
    if writer.out.len() > writer.budget {
        return Err(bad(0, Malformed::TooLarge));
    }
    Ok(writer.out.into_bytes())
}

/// The walk in progress.
#[derive(Debug)]
struct Writer<'a, 'b> {
    /// The file, and the reads every value needs of it.
    values: Values<'a, 'b>,
    names: &'b Dictionary,
    out: String,
    nodes: usize,
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

impl<'a> Writer<'a, '_> {
    /// Writes one structure instance as an element named `tag`.
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

    /// Where a member's value is, once it has been checked to lie inside the
    /// structure that declares it.
    fn field(&self, structure: Structure<'a>, member: Member, spot: Spot<'a>) -> Result<Spot<'a>> {
        let kind = Kind::of(member.type_code, member.reference_key)?;
        let width = kind.width(self.values.meta, spot.address())?;
        fits(&structure, member.data_offset, width, spot.address())?;
        spot.step(member.data_offset)
    }

    /// Writes one value — a member of a structure, or one item of an array.
    fn value(&mut self, field: Field<'a>, tag: &str, spot: Spot<'a>, place: Place) -> Result<()> {
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
            Kind::Array => self.array(field, tag, spot, place),
            Kind::Text => match self.values.counted(spot)? {
                (None, _) => self.leaf(tag, &reserved(NULL), TEXT, place),
                (Some(landing), store) => {
                    let value = text::encode(until_nul(landing.bytes(store)?));
                    self.leaf(tag, &reserved(TEXT), &value, place)
                }
            },
            Kind::Bytes => match self.values.counted(spot)? {
                (None, _) => self.leaf(tag, &reserved(NULL), BYTES, place),
                (Some(landing), store) => {
                    let value = hex(landing.bytes(store)?);
                    self.leaf(tag, &reserved(BYTES), &value, place)
                }
            },
        }
    }

    /// Writes what a pointer landed on.
    ///
    /// `docs/metadata-encodings.md`: a block's tag is a structure the file
    /// defines (369,488) or a bare type code (93,454), and **0** resolve to
    /// neither — so the block table is what carries a pointer's target type,
    /// and this asks it rather than an external schema.
    fn target(&mut self, landing: Spot<'a>, tag: &str, place: Place) -> Result<()> {
        match landing.block.tag {
            BlockTag::Structure(name) => self.structure(name, landing, tag, place),
            BlockTag::Type(word) => {
                let code = u8::try_from(word)
                    .map_err(|_| bad(landing.address(), Malformed::UndefinedStructure))?;
                // A typed block carries values and no member record, so there
                // is no structure an `ARRAYINFO` index could resolve against —
                // which is why the owner is an option rather than a borrow of
                // whatever structure happened to be nearby.
                self.value(
                    Field {
                        member: typed(code),
                        owner: None,
                    },
                    tag,
                    landing,
                    place,
                )
            }
        }
    }

    /// Writes an array and its items.
    fn array(&mut self, field: Field<'a>, tag: &str, spot: Spot<'a>, place: Place) -> Result<()> {
        let attributes = attribute(&reserved(ARRAY), COUNTED);
        let (base, count) = self.values.items(spot)?;
        let (Some(base), true) = (base, count != 0) else {
            // An empty array's element type is never asked for: a file may
            // describe an element it never instantiates, which is one of the
            // ways a structure goes unreached.
            return self.empty(tag, &attributes, place);
        };
        let owner = field
            .owner
            .ok_or_else(|| bad(spot.address(), Malformed::ArrayInfo))?;
        let described = Field {
            member: owner
                .member(field.member.array_info_index)
                .ok_or_else(|| bad(spot.address(), Malformed::ArrayInfo))?,
            owner: Some(owner),
        };
        let stride = described.kind()?.width(self.values.meta, spot.address())?;
        self.open(tag, &attributes, place)?;
        let item = reserved(ITEM);
        for index in 0..count {
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

/// A member of no structure, standing for the one value a typed data block
/// holds.
///
/// A block tagged with a bare type code names its element type and nothing
/// else, so there is no member record to read: this is the type word, in the
/// shape the walk takes everywhere else.
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

/// One reserved attribute, as it is written.
fn attribute(name: &str, value: &str) -> String {
    format!(" {name}=\"{}\"", escape(value))
}

/// A word, as the reserved name that carries it.
///
/// One spelling of the prefix, in one place. DR-047: the prefix and the
/// vocabulary it guards are one fact rather than two kept equal by hand.
pub(super) fn reserved(word: &str) -> String {
    format!("{RESERVED_PREFIX}{word}")
}

impl Writer<'_, '_> {
    /// Charges one element against the ceilings.
    ///
    /// Called from [`Writer::empty`] and [`Writer::open`], which is every
    /// element this mapping writes and the only way to write one. Charging at
    /// the structure instead leaves the whole array path free of both, which is
    /// the defect `PSO`'s budget was repaired for.
    fn spend(&mut self, place: Place) -> Result<()> {
        if place.depth > MAX_DEPTH {
            return Err(bad(0, Malformed::TooDeep));
        }
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > MAX_NODES {
            return Err(bad(0, Malformed::TooManyNodes));
        }
        // In bytes as well as in elements, because an element is not a fixed
        // number of bytes: it carries two spaces of indent per level, so a deep
        // million costs several times a shallow million.
        if self.out.len() > self.budget {
            return Err(bad(0, Malformed::TooLarge));
        }
        Ok(())
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
