//! The metadata layer's laws, over documents nobody shipped — the cases a real
//! packer never emits. Each stream is built here by a writer that is not the
//! one under test, so agreement between the two is evidence.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test code; docs/conventions.md §15"
)]

use proptest::prelude::*;
use rpf_core::metadata::{
    hash::Dictionary,
    pso,
    rbf::{self, MAGIC},
};

/// The names a generated document draws from — the ones that make a naive
/// mapping wrong: real attribute names, and one carrying a colon.
const NAMES: [&str; 10] = [
    "a",
    "Item",
    "x",
    "y",
    "z",
    "w",
    "type",
    "content",
    "CriminalCareerDefs::Limits",
    "_9",
];

/// A value, kept as the bits it is written as so a `NaN` payload survives.
#[derive(Debug, Clone)]
enum Value {
    Uint(u32),
    Bool(bool),
    Float(u32),
    Float3([u32; 3]),
    Str(Vec<u8>),
}

#[derive(Debug, Clone)]
enum Content {
    Blob(Vec<u8>),
    Children(Vec<Child>),
}

#[derive(Debug, Clone)]
enum Child {
    Element(Element),
    Value(usize, Value),
}

#[derive(Debug, Clone)]
struct Element {
    name: usize,
    unknown: [u16; 2],
    attributes: Vec<(usize, Value)>,
    content: Content,
}

fn value() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<u32>().prop_map(Value::Uint),
        any::<bool>().prop_map(Value::Bool),
        any::<u32>().prop_map(Value::Float),
        any::<[u32; 3]>().prop_map(Value::Float3),
        prop::collection::vec(any::<u8>(), 0..6).prop_map(Value::Str),
    ]
}

fn element() -> impl Strategy<Value = Element> {
    let leaf = (
        0..NAMES.len(),
        any::<[u16; 2]>(),
        prop::collection::vec((0..NAMES.len(), value()), 0..4),
        prop_oneof![
            prop::collection::vec(any::<u8>(), 1..6).prop_map(Content::Blob),
            Just(Content::Children(Vec::new())),
        ],
    )
        .prop_map(|(name, unknown, attributes, content)| Element {
            name,
            unknown,
            attributes: dedupe(attributes),
            content,
        });

    leaf.prop_recursive(4, 24, 3, |inner| {
        (
            0..NAMES.len(),
            any::<[u16; 2]>(),
            prop::collection::vec((0..NAMES.len(), value()), 0..3),
            prop::collection::vec(
                prop_oneof![
                    inner.prop_map(Child::Element),
                    (0..NAMES.len(), value()).prop_map(|(n, v)| Child::Value(n, v)),
                ],
                0..4,
            ),
        )
            .prop_map(|(name, unknown, attributes, children)| Element {
                name,
                unknown,
                attributes: dedupe(attributes),
                content: Content::Children(children),
            })
    })
}

/// An element cannot carry one name twice, because XML cannot show it.
fn dedupe(attributes: Vec<(usize, Value)>) -> Vec<(usize, Value)> {
    let mut seen = Vec::new();
    let mut kept = Vec::new();
    for (name, value) in attributes {
        if !seen.contains(&name) {
            seen.push(name);
            kept.push((name, value));
        }
    }
    kept
}

/// Writes a generated document as an `RBF` payload, independent of `rpf-core`.
fn encode(root: &Element) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    let mut names: Vec<usize> = Vec::new();
    write_element(&mut out, &mut names, root);
    out
}

fn write_element(out: &mut Vec<u8>, names: &mut Vec<usize>, element: &Element) {
    record(out, names, element.name, 0x00);
    out.extend_from_slice(&element.unknown[0].to_le_bytes());
    out.extend_from_slice(&element.unknown[1].to_le_bytes());
    out.extend_from_slice(&(element.attributes.len() as u16).to_le_bytes());
    for (name, value) in &element.attributes {
        write_value(out, names, *name, value);
    }
    match &element.content {
        Content::Blob(bytes) => {
            out.extend_from_slice(&[0xFD, 0xFF]);
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        Content::Children(children) => {
            for child in children {
                match child {
                    Child::Element(nested) => write_element(out, names, nested),
                    Child::Value(name, value) => write_value(out, names, *name, value),
                }
            }
        }
    }
    out.extend_from_slice(&[0xFF, 0xFF]);
}

fn write_value(out: &mut Vec<u8>, names: &mut Vec<usize>, name: usize, value: &Value) {
    let kind = match value {
        Value::Uint(_) => 0x10,
        Value::Bool(true) => 0x20,
        Value::Bool(false) => 0x30,
        Value::Float(_) => 0x40,
        Value::Float3(_) => 0x50,
        Value::Str(_) => 0x60,
    };
    record(out, names, name, kind);
    match value {
        Value::Uint(number) => out.extend_from_slice(&number.to_le_bytes()),
        Value::Bool(_) => {}
        Value::Float(bits) => out.extend_from_slice(&bits.to_le_bytes()),
        Value::Float3(bits) => {
            for word in bits {
                out.extend_from_slice(&word.to_le_bytes());
            }
        }
        Value::Str(bytes) => {
            out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
            out.extend_from_slice(bytes);
        }
    }
}

/// Writes a record's index and type, and its name on its first use — keyed by
/// name alone, which is how shipped files reproduce.
fn record(out: &mut Vec<u8>, names: &mut Vec<usize>, name: usize, kind: u8) {
    if let Some(index) = names.iter().position(|seen| *seen == name) {
        out.push(index as u8);
        out.push(kind);
    } else {
        out.push(names.len() as u8);
        out.push(kind);
        names.push(name);
        let text = NAMES[name];
        out.extend_from_slice(&(text.len() as u16).to_le_bytes());
        out.extend_from_slice(text.as_bytes());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Unedited in, unedited out, byte-identical.
    #[test]
    fn a_document_survives_the_trip_through_xml(root in element()) {
        let payload = encode(&root);
        let xml = rbf::to_xml(&payload).map_err(|error| {
            TestCaseError::fail(format!("{error} for {payload:02x?}"))
        })?;
        let rebuilt = rbf::from_xml(&xml).map_err(|error| {
            TestCaseError::fail(format!(
                "{error} for {}",
                String::from_utf8_lossy(&xml)
            ))
        })?;
        prop_assert_eq!(
            rebuilt,
            payload,
            "round trip differs; the XML was\n{}",
            String::from_utf8_lossy(&xml)
        );
    }

    /// A metadata payload is third-party data: every one of these is an error
    /// or a document, never a panic.
    #[test]
    fn arbitrary_bytes_are_answered_and_never_crash(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = rbf::to_xml(&bytes);
    }

    /// The same, for bytes that get past the magic and so reach the token loop.
    #[test]
    fn arbitrary_tokens_are_answered_and_never_crash(tail in prop::collection::vec(any::<u8>(), 0..256)) {
        let mut payload = MAGIC.to_vec();
        payload.extend_from_slice(&tail);
        let _ = rbf::to_xml(&payload);
    }

    /// And the other direction: arbitrary text is an error or a payload.
    #[test]
    fn arbitrary_text_is_answered_and_never_crashes(text in ".{0,120}") {
        let _ = rbf::from_xml(text.as_bytes());
    }
}

// The `PSO` generator below produces what the corpus does not: filler that is
// neither zero nor `'p'` in every byte no walk reaches, and the rare member
// shapes. Two laws follow — the identity, and the transfer of one payload's
// document onto another payload of the same schema.

/// The name hash of the root structure; with no dictionary any `u32` does.
const ROOT: u32 = 0xD98B_B561;

/// The name hash the first nested structure takes; each one after it the next.
/// A block's `nameHash` is the only place a pointer's type is written down.
const NESTED: u32 = 0x82D6_FC83;

/// The `ARRAYINFO` sentinel.
const ARRAYINFO: u32 = 0x0000_0100;

/// The `BITSET` "no enum info" sentinel, in place of a member index.
const NO_ENUM: u16 = 0x0FFF;

/// Where the lowest block sits: after `PSIN`'s header and its eight `'p'`s.
const FIRST_BLOCK: u32 = 16;

/// A byte that is neither zero nor `'p'`, so unreached filler is visible.
const FILLER: u8 = 0xA7;

/// One fixed-width value, as the bytes it is stored as, so a `NaN` payload or
/// a `BOOL` of 7 survives the generator.
#[derive(Debug, Clone)]
struct Fixed {
    code: u8,
    subtype: u8,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
enum Field {
    /// A fixed-width value, inline.
    Fixed(Fixed),
    /// `STRING` subtype 0: a fixed inline buffer.
    Inline { len: u16, bytes: Vec<u8> },
    /// `STRING` subtype 7 or 8: a `u32` hash.
    Hash { subtype: u8, value: u32 },
    /// `STRING` subtype 3: the 16-byte counted form, out of line.
    Counted { capacity: u16, content: Vec<u8> },
    /// `STRING` subtype 1 or 2: an 8-byte pointer to NUL-terminated bytes.
    Pointed {
        subtype: u8,
        content: Option<Vec<u8>>,
    },
    /// An enum, at one of its three widths.
    Enumerated {
        width: u8,
        entries: Vec<(i32, u32)>,
        value: i32,
    },
    /// A bitset, with or without an enum naming its bits.
    Bits {
        width: u8,
        entries: Option<Vec<(i32, u32)>>,
        value: u64,
    },
    /// `ARRAY` subtype 1: elements inline at the member's own offset.
    InlineArray { items: Vec<Fixed> },
    /// `ARRAY` subtype 0: the 16-byte counted form, out of line.
    CountedArray { items: Vec<Fixed> },
    /// `STRUCT` subtype 3 or 4: a pointer to a structure, or null.
    Pointer {
        subtype: u8,
        fields: Option<Vec<Fixed>>,
    },
    /// `STRUCT` subtype 0: the structure inline at the member's own offset.
    InlineStruct { fields: Vec<Fixed> },
    /// `ARRAY` subtype 0 whose element is a structure rather than a scalar, so
    /// the stride comes from the schema's `extent` rather than from a width.
    StructArray { rows: Vec<Vec<Fixed>> },
    /// `MAP` subtype 1, `ATBINARYMAP`: a 24-byte header whose counted pointer
    /// lands on an array of key/value structures.
    Map { rows: Vec<Vec<Fixed>> },
    /// `ARRAY` subtype `0x81`: inline, at a `dataOffset` that has wrapped past
    /// the sixteen bits the field has. Carries its own preceding `UINT`, and
    /// must be generated last: its elements sit at 65,536.
    Wrapped { items: Vec<Fixed> },
}

#[derive(Debug, Clone)]
struct Generated {
    fields: Vec<Field>,
}

/// How many bytes one fixed-width value occupies. A `VECTOR3` is sixteen bytes
/// carrying three floats, not twelve; the four spare ones are filler.
fn width_of(code: u8, subtype: u8) -> u32 {
    match (code, subtype) {
        (0x00..=0x02, _) => 1,
        (0x03 | 0x04 | 0x1E, _) => 2,
        (0x05..=0x07, _) => 4,
        (0x08 | 0x20, _) => 8,
        _ => 16,
    }
}

/// Every fixed-width `(type, subtype)` pair a generated file draws from: the
/// sixteen scalar kinds, with `UINT`'s `COLOR` subtype beside its plain one.
const FIXED_KINDS: [(u8, u8); 17] = [
    (0x00, 0),
    (0x01, 0),
    (0x02, 0),
    (0x03, 0),
    (0x04, 0),
    (0x05, 0),
    (0x06, 0),
    (0x06, 1),
    (0x07, 0),
    (0x08, 0),
    (0x09, 0),
    (0x0A, 0),
    (0x14, 0),
    (0x15, 0),
    (0x1E, 0),
    (0x20, 0),
    (0x07, 0),
];

fn fixed() -> impl Strategy<Value = Fixed> {
    (0..FIXED_KINDS.len(), any::<u64>(), any::<u64>()).prop_map(|(which, low, high)| {
        let (code, subtype) = FIXED_KINDS[which];
        let mut bytes = Vec::new();
        while bytes.len() < width_of(code, subtype) as usize {
            bytes.extend_from_slice(&low.to_be_bytes());
            bytes.extend_from_slice(&high.to_be_bytes());
        }
        bytes.truncate(width_of(code, subtype) as usize);
        Fixed {
            code,
            subtype,
            bytes,
        }
    })
}

/// A run of bytes with no NUL in it: a renderer reads up to the first NUL, so
/// a NUL inside the value would not come back.
fn body(len: std::ops::Range<usize>) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(1u8..=255, len)
}

/// An enum or bitset table: distinct keys, and distinct name hashes. Two keys
/// rendering the same name are refused elsewhere, not here.
fn table(bits: u32) -> impl Strategy<Value = Vec<(i32, u32)>> {
    prop::collection::vec(0..bits, 1..6).prop_map(move |keys| {
        let mut seen = Vec::new();
        for key in keys {
            if !seen.contains(&key) {
                seen.push(key);
            }
        }
        seen.iter()
            .map(|key| ((*key).cast_signed(), 0x1000_0000u32 + *key))
            .collect()
    })
}

fn field() -> impl Strategy<Value = Field> {
    prop_oneof![
        fixed().prop_map(Field::Fixed),
        (body(0..7), 0usize..3, any::<bool>()).prop_map(|(bytes, slack, terminated)| {
            // `terminated` false fills the buffer exactly, with no NUL to stop
            // at; the bytes after a NUL are filler that must survive.
            let len = bytes.len() + if terminated { slack + 1 } else { 0 };
            Field::Inline {
                len: u16::try_from(len.max(1)).expect("a test length fits"),
                bytes,
            }
        }),
        (prop_oneof![Just(7u8), Just(8u8)], any::<u32>())
            .prop_map(|(subtype, value)| Field::Hash { subtype, value }),
        (body(0..7), 0usize..3).prop_map(|(content, slack)| Field::Counted {
            capacity: u16::try_from(content.len() + slack).expect("fits"),
            content,
        }),
        (
            prop_oneof![Just(1u8), Just(2u8)],
            prop::option::of(body(0..7))
        )
            .prop_map(|(subtype, content)| Field::Pointed { subtype, content }),
        (prop_oneof![Just(0u8), Just(1u8), Just(2u8)], any::<i32>()).prop_flat_map(
            |(width, value)| {
                let bits = 8u32 << (2 - u32::from(width));
                table(bits).prop_map(move |entries| Field::Enumerated {
                    width,
                    entries,
                    value,
                })
            }
        ),
        (prop_oneof![Just(0u8), Just(1u8), Just(2u8)], any::<u64>()).prop_flat_map(
            |(width, value)| {
                let bits = 8u32 << (2 - u32::from(width));
                let value = if bits >= 64 {
                    value
                } else {
                    value & ((1u64 << bits) - 1)
                };
                prop::option::of(table(bits)).prop_map(move |entries| Field::Bits {
                    width,
                    entries,
                    value,
                })
            }
        ),
        prop::collection::vec(fixed(), 0..3).prop_map(|items| {
            // One array holds one element type, per its `ARRAYINFO` member.
            let items = one_kind(items);
            Field::InlineArray { items }
        }),
        prop::collection::vec(fixed(), 0..3).prop_map(|items| Field::CountedArray {
            items: one_kind(items)
        }),
        (
            prop_oneof![Just(3u8), Just(4u8)],
            prop::option::of(prop::collection::vec(fixed(), 1..3))
        )
            .prop_map(|(subtype, fields)| Field::Pointer { subtype, fields }),
        prop::collection::vec(fixed(), 1..3).prop_map(|fields| Field::InlineStruct { fields }),
        rows(1..3).prop_map(|rows| Field::StructArray { rows }),
        rows(0..3).prop_map(|rows| Field::Map { rows }),
    ]
}

/// Rows of one shape: `count` instances of the same generated structure. One
/// array holds one element type, so every row is forced to the first's members.
fn rows(count: std::ops::Range<usize>) -> impl Strategy<Value = Vec<Vec<Fixed>>> {
    prop::collection::vec(prop::collection::vec(fixed(), 1..3), count).prop_map(|rows| {
        let Some(first) = rows.first().cloned() else {
            return rows;
        };
        rows.into_iter()
            .map(|row| {
                first
                    .iter()
                    .zip(row.into_iter().chain(std::iter::repeat(first[0].clone())))
                    .map(|(shape, mut value)| {
                        value.code = shape.code;
                        value.subtype = shape.subtype;
                        value.bytes.resize(shape.bytes.len(), FILLER);
                        value
                    })
                    .collect()
            })
            .collect()
    })
}

/// The `0x81`-wrapped array a generated document may end with.
fn wrapped() -> impl Strategy<Value = Field> {
    prop::collection::vec(fixed(), 1..3).prop_map(|items| Field::Wrapped {
        items: one_kind(items),
    })
}

/// Every item of one array is of the element type the first one names.
fn one_kind(items: Vec<Fixed>) -> Vec<Fixed> {
    let Some(first) = items.first().cloned() else {
        return items;
    };
    items
        .into_iter()
        .map(|mut item| {
            item.code = first.code;
            item.subtype = first.subtype;
            item.bytes.resize(first.bytes.len(), FILLER);
            item
        })
        .collect()
}

fn generated() -> impl Strategy<Value = Generated> {
    (
        prop::collection::vec(field(), 1..7),
        prop::option::of(wrapped()),
    )
        .prop_map(|(mut fields, tail)| {
            fields.extend(tail);
            Generated { fields }
        })
}

/// One `PSCH` structure member, twelve bytes, `referenceKey` at offset 8.
fn member(name: u32, code: u8, subtype: u8, offset: u16, reference: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&name.to_be_bytes());
    out.push(code);
    out.push(subtype);
    out.extend_from_slice(&offset.to_be_bytes());
    out.extend_from_slice(&reference.to_be_bytes());
    out
}

/// A block of the generated `PSIN`, before its offset is known.
struct Chunk {
    name: u32,
    bytes: Vec<u8>,
}

struct Building {
    root: Vec<u8>,
    /// The blocks that hold everything out of line.
    chunks: Vec<Chunk>,
    /// The root structure's members, field members first.
    members: Vec<Vec<u8>>,
    /// The enum entries each generated table wants, by the name hash the member
    /// references it under.
    enums: Vec<(u32, Vec<(i32, u32)>)>,
    structures: Vec<(u32, Vec<Vec<u8>>, u32)>,
}

/// Writes a value at `offset` into the root instance, growing it with filler.
fn place(root: &mut Vec<u8>, offset: usize, bytes: &[u8]) {
    if root.len() < offset + bytes.len() {
        root.resize(offset + bytes.len(), FILLER);
    }
    root[offset..offset + bytes.len()].copy_from_slice(bytes);
}

/// The 16-byte counted form: the pointer, `count1`, `count2` and a dead word.
/// `count1` is the length; the other two are filler nothing reads.
fn counted(block: u32, count: u16) -> Vec<u8> {
    let mut out = pointer(block, 0);
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&0xBEEFu16.to_be_bytes());
    out.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    out
}

/// A pointer: the block id in the low 12 bits, the item offset in the next 20,
/// and a second word that carries nothing.
fn pointer(block: u32, item: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&(block | (item << 12)).to_be_bytes());
    out.extend_from_slice(&0x1234_5678u32.to_be_bytes());
    out
}

/// Turns a generated document into a `PSO` payload.
fn encode_pso(document: &Generated) -> Vec<u8> {
    let mut build = Building {
        root: Vec::new(),
        chunks: Vec::new(),
        members: Vec::new(),
        enums: Vec::new(),
        structures: Vec::new(),
    };
    let mut offset = 0usize;
    for (index, field) in document.fields.iter().enumerate() {
        let name = 0x2000_0000u32 + u32::try_from(index).expect("fits");
        offset = emit(&mut build, name, offset, field);
        // A gap between members, so a byte no member covers has to survive.
        offset += 3;
    }
    let length = u32::try_from(build.root.len().max(offset)).expect("fits");
    build.root.resize(length as usize, FILLER);

    let mut data = vec![FILLER; FIRST_BLOCK as usize];
    data[..4].copy_from_slice(b"PSIN");
    data[8..16].copy_from_slice(b"pppppppp");
    let mut blocks = vec![(ROOT, FIRST_BLOCK, length)];
    data.extend_from_slice(&build.root);
    for chunk in &build.chunks {
        data.extend_from_slice(&[FILLER; 2]);
        let at = u32::try_from(data.len()).expect("fits");
        blocks.push((
            chunk.name,
            at,
            u32::try_from(chunk.bytes.len()).expect("fits"),
        ));
        data.extend_from_slice(&chunk.bytes);
    }
    // A NUL at the end, so a pointer to NUL-terminated bytes always has one.
    data.push(0);
    let data_len = u32::try_from(data.len()).expect("fits");
    data[4..8].copy_from_slice(&data_len.to_be_bytes());

    let mut out = data;
    out.extend_from_slice(&pmap(&blocks));
    out.extend_from_slice(&psch(&build));
    out.extend_from_slice(&chks());
    stamp(&mut out);
    out
}

/// Writes one field: its bytes into the root, its member into the schema, and
/// whatever it needs out of line into a block. Answers the offset after it.
#[allow(clippy::too_many_lines, reason = "one arm per member shape")]
fn emit(build: &mut Building, name: u32, offset: usize, field: &Field) -> usize {
    let at = u16::try_from(offset).expect("a test offset fits");
    match field {
        Field::Fixed(value) => {
            place(&mut build.root, offset, &value.bytes);
            build
                .members
                .push(member(name, value.code, value.subtype, at, 0));
            offset + value.bytes.len()
        }
        Field::Inline { len, bytes } => {
            let mut room = vec![FILLER; usize::from(*len)];
            room[..bytes.len()].copy_from_slice(bytes);
            if bytes.len() < room.len() {
                room[bytes.len()] = 0;
            }
            place(&mut build.root, offset, &room);
            build
                .members
                .push(member(name, 0x0B, 0, at, u32::from(*len) << 16));
            offset + usize::from(*len)
        }
        Field::Hash { subtype, value } => {
            place(&mut build.root, offset, &value.to_be_bytes());
            build.members.push(member(name, 0x0B, *subtype, at, 0));
            offset + 4
        }
        Field::Counted { capacity, content } => {
            let mut bytes = vec![FILLER; usize::from(*capacity).max(content.len() + 1)];
            bytes[..content.len()].copy_from_slice(content);
            if content.len() < bytes.len() {
                bytes[content.len()] = 0;
            }
            let block = u32::try_from(build.chunks.len() + 2).expect("fits");
            build.chunks.push(Chunk { name: 0x1, bytes });
            place(&mut build.root, offset, &counted(block, *capacity));
            build.members.push(member(name, 0x0B, 3, at, 0));
            offset + 16
        }
        Field::Pointed { subtype, content } => {
            let word = match content {
                None => pointer(0, 0),
                Some(content) => {
                    let mut bytes = content.clone();
                    bytes.push(0);
                    bytes.push(FILLER);
                    let block = u32::try_from(build.chunks.len() + 2).expect("fits");
                    build.chunks.push(Chunk { name: 0x1, bytes });
                    pointer(block, 0)
                }
            };
            place(&mut build.root, offset, &word);
            build.members.push(member(name, 0x0B, *subtype, at, 0));
            offset + 8
        }
        Field::Enumerated {
            width,
            entries,
            value,
        } => {
            let table = 0x3000_0000u32 + u32::try_from(build.enums.len()).expect("fits");
            build.enums.push((table, entries.clone()));
            let bytes = stored(u64::from(value.cast_unsigned()), *width);
            place(&mut build.root, offset, &bytes);
            build.members.push(member(name, 0x0E, *width, at, table));
            offset + bytes.len()
        }
        Field::Bits {
            width,
            entries,
            value,
        } => {
            let reference = match entries {
                None => u32::from(NO_ENUM),
                Some(entries) => {
                    let table = 0x3000_0000u32 + u32::try_from(build.enums.len()).expect("fits");
                    build.enums.push((table, entries.clone()));
                    // The `ARRAYINFO` member goes immediately after this one.
                    u32::try_from(build.members.len() + 1).expect("fits")
                }
            };
            let bytes = stored(*value, *width);
            place(&mut build.root, offset, &bytes);
            build
                .members
                .push(member(name, 0x0F, *width, at, reference));
            if let Some((table, _)) = entries.as_ref().and(build.enums.last()) {
                build.members.push(member(ARRAYINFO, 0x0E, 0, 0, *table));
            }
            offset + bytes.len()
        }
        Field::InlineArray { items } => {
            let stride = items.first().map_or(4, |item| item.bytes.len());
            for (index, item) in items.iter().enumerate() {
                place(&mut build.root, offset + index * stride, &item.bytes);
            }
            let element = u32::try_from(build.members.len() + 1).expect("fits");
            let count = u32::try_from(items.len()).expect("fits");
            build
                .members
                .push(member(name, 0x0D, 1, at, (count << 16) | element));
            array_info(build, items);
            offset + stride * items.len().max(1)
        }
        Field::CountedArray { items } => {
            let stride = items.first().map_or(4, |item| item.bytes.len());
            let mut bytes = vec![FILLER; stride.max(1)];
            for item in items {
                let base = bytes.len();
                bytes.resize(base + stride, FILLER);
                bytes[base..base + stride].copy_from_slice(&item.bytes);
            }
            let block = if items.is_empty() {
                0
            } else {
                // The first `stride` bytes are filler, so the item offset
                // inside the block is not zero either.
                let block = u32::try_from(build.chunks.len() + 2).expect("fits");
                build.chunks.push(Chunk { name: 0x0C, bytes });
                block
            };
            let element = u32::try_from(build.members.len() + 1).expect("fits");
            let word = if block == 0 {
                counted(0, 0)
            } else {
                let mut out = pointer(block, u32::try_from(stride).expect("fits"));
                out.extend_from_slice(&u16::try_from(items.len()).expect("fits").to_be_bytes());
                out.extend_from_slice(&0xBEEFu16.to_be_bytes());
                out.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
                out
            };
            place(&mut build.root, offset, &word);
            build.members.push(member(name, 0x0D, 0, at, element));
            array_info(build, items);
            offset + 16
        }
        Field::Pointer { subtype, fields } => {
            let word = match fields {
                None => pointer(0, 0),
                Some(fields) => {
                    let shape = define(build, fields);
                    let block = u32::try_from(build.chunks.len() + 2).expect("fits");
                    build.chunks.push(Chunk {
                        name: shape.name,
                        bytes: row_bytes(fields, &shape),
                    });
                    pointer(block, 0)
                }
            };
            place(&mut build.root, offset, &word);
            build.members.push(member(name, 0x0C, *subtype, at, 0));
            offset + 8
        }
        Field::InlineStruct { fields } => {
            let shape = define(build, fields);
            place(&mut build.root, offset, &row_bytes(fields, &shape));
            build.members.push(member(name, 0x0C, 0, at, shape.name));
            offset + shape.length as usize
        }
        Field::StructArray { rows } => {
            let shape = define(build, rows.first().map_or(&[][..], Vec::as_slice));
            // The first `length` bytes are filler, so the item offset inside
            // the block is not zero either.
            let mut bytes = vec![FILLER; shape.length.max(1) as usize];
            for row in rows {
                bytes.extend_from_slice(&row_bytes(row, &shape));
            }
            let block = u32::try_from(build.chunks.len() + 2).expect("fits");
            build.chunks.push(Chunk {
                name: shape.name,
                bytes,
            });
            let element = u32::try_from(build.members.len() + 1).expect("fits");
            let mut word = pointer(block, shape.length.max(1));
            word.extend_from_slice(&u16::try_from(rows.len()).expect("fits").to_be_bytes());
            word.extend_from_slice(&0xBEEFu16.to_be_bytes());
            word.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
            place(&mut build.root, offset, &word);
            build.members.push(member(name, 0x0D, 0, at, element));
            // A `STRUCT` subtype 0 element takes its stride from the schema.
            build
                .members
                .push(member(ARRAYINFO, 0x0C, 0, 0, shape.name));
            offset + 16
        }
        Field::Map { rows } => {
            // 24 bytes, laid out as `0x01000000` and 0, then the same 16-byte
            // counted pointer an `ATARRAY` uses.
            place(&mut build.root, offset, &0x0100_0000u32.to_be_bytes());
            place(&mut build.root, offset + 4, &0u32.to_be_bytes());
            let word = if rows.is_empty() {
                counted(0, 0)
            } else {
                let shape = define(build, rows.first().map_or(&[][..], Vec::as_slice));
                let mut bytes = Vec::new();
                for row in rows {
                    bytes.extend_from_slice(&row_bytes(row, &shape));
                }
                let block = u32::try_from(build.chunks.len() + 2).expect("fits");
                build.chunks.push(Chunk {
                    name: shape.name,
                    bytes,
                });
                counted(block, u16::try_from(rows.len()).expect("fits"))
            };
            place(&mut build.root, offset + 8, &word);
            build.members.push(member(name, 0x10, 1, at, 0));
            offset + 24
        }
        Field::Wrapped { items } => {
            // The recovery is unique only when a member before this one ends
            // past the raw offset, so this carries its own `UINT`.
            place(&mut build.root, offset, &0x0000_0001u32.to_be_bytes());
            build.members.push(member(name, 0x06, 0, at, 0));

            let stride = items.first().map_or(4, |item| item.bytes.len());
            for (index, item) in items.iter().enumerate() {
                place(&mut build.root, WRAP + index * stride, &item.bytes);
            }
            let element = u32::try_from(build.members.len() + 1).expect("fits");
            let count = u32::try_from(items.len()).expect("fits");
            build.members.push(member(
                name | 0x0080_0000,
                0x0D,
                0x81,
                0,
                (count << 16) | element,
            ));
            array_info(build, items);
            WRAP + stride * items.len()
        }
    }
}

/// How far one wrap moves a `dataOffset`: the width of the `u16` field it is.
const WRAP: usize = 0x1_0000;

/// A structure the generator defined, as placing an instance of it needs.
struct Shape {
    /// Its name hash, which is also the `nameHash` of every block holding one.
    name: u32,
    length: u32,
    offsets: Vec<usize>,
}

/// Defines a structure whose members are `row`, and answers what places one.
/// The gap after each member is a byte no member covers, which has to survive.
fn define(build: &mut Building, row: &[Fixed]) -> Shape {
    let name = NESTED + u32::try_from(build.structures.len()).expect("fits");
    let mut members = Vec::new();
    let mut offsets = Vec::new();
    let mut inner = 0usize;
    for (index, value) in row.iter().enumerate() {
        offsets.push(inner);
        members.push(member(
            0x4000_0000 + u32::try_from(index).expect("fits"),
            value.code,
            value.subtype,
            u16::try_from(inner).expect("fits"),
            0,
        ));
        inner += value.bytes.len() + 1;
    }
    let length = u32::try_from(inner).expect("fits");
    build.structures.push((name, members, length));
    Shape {
        name,
        length,
        offsets,
    }
}

fn row_bytes(row: &[Fixed], shape: &Shape) -> Vec<u8> {
    let mut bytes = vec![FILLER; shape.length as usize];
    for (value, at) in row.iter().zip(&shape.offsets) {
        bytes[*at..*at + value.bytes.len()].copy_from_slice(&value.bytes);
    }
    bytes
}

/// Adds the `ARRAYINFO` member that describes one element, immediately after
/// the array member that indexes it: an array member does not name its element
/// type, and `referenceKey & 0xFFFF` indexes the member of the same structure
/// whose `entryNameHash` is `0x00000100`.
fn array_info(build: &mut Building, items: &[Fixed]) {
    let (code, subtype) = items
        .first()
        .map_or((0x06, 0), |item| (item.code, item.subtype));
    build.members.push(member(ARRAYINFO, code, subtype, 0, 0));
}

/// A value stored at one of the three enum widths.
fn stored(value: u64, width: u8) -> Vec<u8> {
    match width {
        2 => vec![(value & 0xFF) as u8],
        1 => ((value & 0xFFFF) as u16).to_be_bytes().to_vec(),
        _ => ((value & 0xFFFF_FFFF) as u32).to_be_bytes().to_vec(),
    }
}

/// The `PMAP` section: the root id, the count, `unknown_Eh` and the entries.
fn pmap(blocks: &[(u32, u32, u32)]) -> Vec<u8> {
    let mut out = Vec::from(*b"PMAP");
    let length = 16 + 16 * blocks.len();
    out.extend_from_slice(&u32::try_from(length).expect("fits").to_be_bytes());
    out.extend_from_slice(&1i32.to_be_bytes());
    out.extend_from_slice(&i16::try_from(blocks.len()).expect("fits").to_be_bytes());
    out.extend_from_slice(&0x7070u16.to_be_bytes());
    for (name, offset, length) in blocks {
        out.extend_from_slice(&name.to_be_bytes());
        out.extend_from_slice(&offset.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&length.to_be_bytes());
    }
    out
}

/// The `PSCH` section: the index, then one entry per structure and per enum.
fn psch(build: &Building) -> Vec<u8> {
    let root_length = u32::try_from(build.root.len()).expect("fits");
    let mut entries: Vec<(u32, Vec<u8>)> = Vec::new();

    let mut root = Vec::new();
    let count = build.members.len();
    root.extend_from_slice(&u32::try_from(count).expect("fits").to_be_bytes());
    root.extend_from_slice(&root_length.to_be_bytes());
    root.extend_from_slice(&0u32.to_be_bytes());
    for entry in &build.members {
        root.extend_from_slice(entry);
    }
    entries.push((ROOT, root));

    for (name, members, length) in &build.structures {
        let mut body = Vec::new();
        body.extend_from_slice(&u32::try_from(members.len()).expect("fits").to_be_bytes());
        body.extend_from_slice(&length.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        for entry in members {
            body.extend_from_slice(entry);
        }
        entries.push((*name, body));
    }

    for (name, table) in &build.enums {
        let mut body = Vec::new();
        body.extend_from_slice(
            &(0x0100_0000u32 | u32::try_from(table.len()).expect("fits")).to_be_bytes(),
        );
        for (key, entry) in table {
            body.extend_from_slice(&entry.to_be_bytes());
            body.extend_from_slice(&key.to_be_bytes());
        }
        entries.push((*name, body));
    }

    let index_at = 12;
    let mut at = index_at + 8 * entries.len();
    let mut index = Vec::new();
    let mut bodies = Vec::new();
    for (name, body) in &entries {
        index.extend_from_slice(&name.to_be_bytes());
        index.extend_from_slice(&i32::try_from(at).expect("fits").to_be_bytes());
        at += body.len();
        bodies.extend_from_slice(body);
    }
    let mut out = Vec::from(*b"PSCH");
    out.extend_from_slice(&u32::try_from(at).expect("fits").to_be_bytes());
    out.extend_from_slice(&u32::try_from(entries.len()).expect("fits").to_be_bytes());
    out.extend_from_slice(&index);
    out.extend_from_slice(&bodies);
    out
}

/// An empty `CHKS` section, for [`stamp`] to fill in.
fn chks() -> Vec<u8> {
    let mut out = Vec::from(*b"CHKS");
    out.extend_from_slice(&20u32.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&0x7970_7070u32.to_be_bytes());
    out
}

/// Writes the file's own size and checksum into the `CHKS` it ends with: a
/// Jenkins one-at-a-time hash seeded `0x3FAC7125` over the whole file, each
/// byte taken as a signed `int8`, with the size and the checksum zeroed first.
fn stamp(file: &mut [u8]) {
    let at = file.len() - 20;
    let size = u32::try_from(file.len()).expect("fits");
    file[at + 8..at + 16].fill(0);
    let mut hash: u32 = 0x3FAC_7125;
    for byte in file.iter() {
        hash = hash.wrapping_add(i32::from((*byte).cast_signed()).cast_unsigned());
        hash = hash.wrapping_add(hash << 10);
        hash ^= hash >> 6;
    }
    hash = hash.wrapping_add(hash << 3);
    hash ^= hash >> 11;
    hash = hash.wrapping_add(hash << 15);
    file[at + 8..at + 12].copy_from_slice(&size.to_be_bytes());
    file[at + 12..at + 16].copy_from_slice(&hash.to_be_bytes());
}

/// The generated payload, and the same schema carrying different values.
fn a_pair() -> impl Strategy<Value = (Generated, Generated)> {
    generated().prop_flat_map(|first| {
        let strategy = values_for(&first);
        strategy.prop_map(move |second| (first.clone(), second))
    })
}

fn values_for(shape: &Generated) -> impl Strategy<Value = Generated> + use<> {
    let fields = shape.fields.clone();
    prop::collection::vec(any::<u64>(), fields.len().max(1)).prop_map(move |seeds| Generated {
        fields: fields
            .iter()
            .zip(&seeds)
            .map(|(field, seed)| revalue(field, *seed))
            .collect(),
    })
}

/// The same field with a different value: `from_xml` refuses a change of shape,
/// so every length and every table has to stay identical.
fn revalue(field: &Field, seed: u64) -> Field {
    let refill = |bytes: &Vec<u8>| -> Vec<u8> {
        bytes
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                let mixed = seed.rotate_left((index % 64) as u32) as u8;
                byte ^ mixed
            })
            .collect()
    };
    let renonzero = |bytes: &Vec<u8>| -> Vec<u8> {
        refill(bytes).into_iter().map(|byte| byte.max(1)).collect()
    };
    match field {
        Field::Fixed(value) => Field::Fixed(Fixed {
            code: value.code,
            subtype: value.subtype,
            bytes: refill(&value.bytes),
        }),
        Field::Inline { len, bytes } => Field::Inline {
            len: *len,
            bytes: renonzero(bytes),
        },
        Field::Hash { subtype, value } => Field::Hash {
            subtype: *subtype,
            value: value ^ (seed as u32),
        },
        Field::Counted { capacity, content } => Field::Counted {
            capacity: *capacity,
            content: renonzero(content),
        },
        Field::Pointed { subtype, content } => Field::Pointed {
            subtype: *subtype,
            content: content.as_ref().map(renonzero),
        },
        Field::Enumerated {
            width,
            entries,
            value,
        } => Field::Enumerated {
            width: *width,
            entries: entries.clone(),
            value: value ^ (seed as i32),
        },
        Field::Bits {
            width,
            entries,
            value,
        } => {
            let bits = 8u64 << (2 - u64::from(*width));
            let mask = if bits >= 64 {
                u64::MAX
            } else {
                (1u64 << bits) - 1
            };
            Field::Bits {
                width: *width,
                entries: entries.clone(),
                value: (value ^ seed) & mask,
            }
        }
        Field::InlineArray { items } => Field::InlineArray {
            items: items
                .iter()
                .map(|item| Fixed {
                    code: item.code,
                    subtype: item.subtype,
                    bytes: refill(&item.bytes),
                })
                .collect(),
        },
        Field::CountedArray { items } => Field::CountedArray {
            items: items
                .iter()
                .map(|item| Fixed {
                    code: item.code,
                    subtype: item.subtype,
                    bytes: refill(&item.bytes),
                })
                .collect(),
        },
        Field::Pointer { subtype, fields } => Field::Pointer {
            subtype: *subtype,
            fields: fields.as_ref().map(|fields| revalued(fields, &refill)),
        },
        Field::InlineStruct { fields } => Field::InlineStruct {
            fields: revalued(fields, &refill),
        },
        Field::StructArray { rows } => Field::StructArray {
            rows: rows.iter().map(|row| revalued(row, &refill)).collect(),
        },
        Field::Map { rows } => Field::Map {
            rows: rows.iter().map(|row| revalued(row, &refill)).collect(),
        },
        Field::Wrapped { items } => Field::Wrapped {
            items: revalued(items, &refill),
        },
    }
}

/// The same fixed-width values with new bytes, keeping every type and width.
fn revalued(values: &[Fixed], refill: &impl Fn(&Vec<u8>) -> Vec<u8>) -> Vec<Fixed> {
    values
        .iter()
        .map(|item| Fixed {
            code: item.code,
            subtype: item.subtype,
            bytes: refill(&item.bytes),
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Unedited in, unedited out, byte-identical, over payloads whose every
    /// unreached byte is `0xA7`.
    #[test]
    fn a_pso_payload_survives_the_trip_through_xml(document in generated()) {
        let names = Dictionary::default();
        let payload = encode_pso(&document);
        let xml = pso::to_xml(&payload, &names).map_err(|error| {
            TestCaseError::fail(format!("{error:?} for {payload:02x?}"))
        })?;
        let rebuilt = pso::from_xml(&payload, &xml, &names).map_err(|error| {
            TestCaseError::fail(format!("{error:?} for {}", String::from_utf8_lossy(&xml)))
        })?;
        prop_assert_eq!(
            rebuilt,
            payload,
            "round trip differs; the XML was\n{}",
            String::from_utf8_lossy(&xml)
        );
    }

    /// The law the identity cannot imply: one payload's document applied to
    /// another payload of the same shape has to render back as that document.
    #[test]
    fn a_document_carries_its_values_onto_another_payload((first, second) in a_pair()) {
        let names = Dictionary::default();
        let into = encode_pso(&first);
        let from = encode_pso(&second);
        let wanted = pso::to_xml(&from, &names).map_err(|error| {
            TestCaseError::fail(format!("{error:?}"))
        })?;
        let rebuilt = pso::from_xml(&into, &wanted, &names).map_err(|error| {
            TestCaseError::fail(format!("{error:?} for {}", String::from_utf8_lossy(&wanted)))
        })?;
        let got = pso::to_xml(&rebuilt, &names).map_err(|error| {
            TestCaseError::fail(format!("{error:?}"))
        })?;
        prop_assert_eq!(
            String::from_utf8_lossy(&got).into_owned(),
            String::from_utf8_lossy(&wanted).into_owned(),
            "a value did not survive being written into another payload"
        );
    }

    /// Arbitrary text against a real payload is an error, never a panic.
    #[test]
    fn arbitrary_xml_against_a_payload_is_answered(
        document in generated(),
        text in ".{0,160}",
    ) {
        let names = Dictionary::default();
        let payload = encode_pso(&document);
        let _ = pso::from_xml(&payload, text.as_bytes(), &names);
    }

    /// And arbitrary payload bytes under a real document.
    #[test]
    fn arbitrary_payload_bytes_under_a_document_are_answered(
        document in generated(),
        bytes in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let names = Dictionary::default();
        let payload = encode_pso(&document);
        let xml = pso::to_xml(&payload, &names).expect("a generated payload converts");
        let _ = pso::from_xml(&bytes, &xml, &names);
    }
}

#[test]
fn every_half_float_narrows_back_to_the_bits_it_widened_from() {
    // `FLOAT16` has no `f32` of its own on the pinned toolchain, so both the
    // widening and the narrowing are written by hand and have to be exact.
    let names = Dictionary::default();
    let mut checked = 0usize;
    for bits in 0..=u16::MAX {
        let document = Generated {
            fields: vec![Field::Fixed(Fixed {
                code: 0x1E,
                subtype: 0,
                bytes: bits.to_be_bytes().to_vec(),
            })],
        };
        let payload = encode_pso(&document);
        let xml = pso::to_xml(&payload, &names).expect("a half converts");
        let rebuilt = pso::from_xml(&payload, &xml, &names).expect("and reads back");
        assert_eq!(rebuilt, payload, "half {bits:#06x} did not round-trip");
        checked += 1;
    }
    assert_eq!(checked, 65_536);
}

/// One `UINT` holding `seed`, for building a shape by hand.
fn uint(seed: u32) -> Fixed {
    Fixed {
        code: 0x06,
        subtype: 0,
        bytes: seed.to_be_bytes().to_vec(),
    }
}

/// Every member shape the generator can emit, one document each, with both
/// laws on it — the two above draw at random and reach a rare shape rarely.
#[test]
fn every_member_shape_the_generator_reaches_carries_its_values_and_its_bytes() {
    let names = Dictionary::default();
    for (what, field) in every_shape() {
        // Every shape gets a `UINT` before it: `Field::Wrapped`'s offset
        // recovery needs a member ahead of it.
        let first = Generated {
            fields: vec![Field::Fixed(uint(0xAABB_CCDD)), field.clone()],
        };
        let second = Generated {
            fields: first
                .fields
                .iter()
                .map(|f| revalue(f, 0x5A5A_5A5A))
                .collect(),
        };
        let into = encode_pso(&first);
        let from = encode_pso(&second);

        let xml = pso::to_xml(&into, &names).unwrap_or_else(|e| panic!("{what}: {e:?}"));
        assert_eq!(
            pso::from_xml(&into, &xml, &names).unwrap_or_else(|e| panic!("{what}: {e:?}")),
            into,
            "{what}: unedited in, unedited out"
        );

        let wanted = pso::to_xml(&from, &names).unwrap_or_else(|e| panic!("{what}: {e:?}"));
        let rebuilt =
            pso::from_xml(&into, &wanted, &names).unwrap_or_else(|e| panic!("{what}: {e:?}"));
        let got = pso::to_xml(&rebuilt, &names).unwrap_or_else(|e| panic!("{what}: {e:?}"));
        assert_eq!(
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(&wanted),
            "{what}: a value did not survive being written into another payload"
        );
        assert_ne!(
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(&xml),
            "{what}: the two payloads have to differ for the transfer to mean anything"
        );
    }
}

#[allow(clippy::too_many_lines, reason = "one entry per member shape")]
fn every_shape() -> Vec<(&'static str, Field)> {
    vec![
        ("fixed", Field::Fixed(uint(0x1122_3344))),
        (
            "inline string",
            Field::Inline {
                len: 8,
                bytes: b"abc".to_vec(),
            },
        ),
        (
            "hash string",
            Field::Hash {
                subtype: 7,
                value: 0x0102_0304,
            },
        ),
        (
            "counted string",
            Field::Counted {
                capacity: 6,
                content: b"GTA V".to_vec(),
            },
        ),
        (
            "an empty counted string over a lone NUL",
            Field::Counted {
                capacity: 1,
                content: Vec::new(),
            },
        ),
        (
            "pointed string",
            Field::Pointed {
                subtype: 1,
                content: Some(b"xy".to_vec()),
            },
        ),
        (
            "enum",
            Field::Enumerated {
                width: 0,
                entries: vec![(0, 0x1000_0000), (1, 0x1000_0001)],
                value: 1,
            },
        ),
        (
            "bitset",
            Field::Bits {
                width: 0,
                entries: None,
                value: 0b1011,
            },
        ),
        (
            "inline array of scalars",
            Field::InlineArray {
                items: vec![uint(1), uint(2)],
            },
        ),
        (
            "counted array of scalars",
            Field::CountedArray {
                items: vec![uint(3), uint(4)],
            },
        ),
        (
            "pointer to a structure",
            Field::Pointer {
                subtype: 3,
                fields: Some(vec![uint(5)]),
            },
        ),
        (
            "simple pointer to a structure",
            Field::Pointer {
                subtype: 4,
                fields: Some(vec![uint(6)]),
            },
        ),
        (
            "a null simple pointer",
            Field::Pointer {
                subtype: 4,
                fields: None,
            },
        ),
        (
            "an inline structure",
            Field::InlineStruct {
                fields: vec![uint(7), uint(8)],
            },
        ),
        (
            "an array whose element is a structure",
            Field::StructArray {
                rows: vec![vec![uint(9)], vec![uint(10)]],
            },
        ),
        (
            "an atbinarymap",
            Field::Map {
                rows: vec![vec![uint(11), uint(12)], vec![uint(13), uint(14)]],
            },
        ),
        ("an empty atbinarymap", Field::Map { rows: Vec::new() }),
    ]
}
