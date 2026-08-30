//! The metadata layer's laws, over documents nobody shipped.
//!
//! The corpus is the stronger evidence and `tests/metadata.rs` is where it is
//! used: 391 real files reproduced byte-for-byte says more than any generator
//! can. What a generator adds is the cases Rockstar's packer never emits — a
//! `NaN` with a payload, a name reused at two types, a string that reads as a
//! number, a blob of nothing but spaces — and the assurance that the round trip
//! is a property of the code rather than of the corpus. R5.7,
//! `docs/conventions.md` §14's property-tests row.
//!
//! The stream each case is checked against is built **here**, by a writer that
//! is not the one under test. A reader and a writer that agree with each other
//! and with nothing else would otherwise pass every round-trip test there is.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test code; docs/conventions.md §15"
)]

use proptest::prelude::*;
use rpf_core::metadata::rbf::{self, MAGIC};

/// The names a generated document draws from.
///
/// Deliberately the ones that make a naive mapping wrong: `x`, `y`, `z`, `w`
/// and `type` are real attribute names in the corpus, so none of them can be
/// reserved for a vector or for a type tag; `CriminalCareerDefs::Limits` is the
/// shape of the one real name carrying a colon, which is why the XML uses a
/// reserved prefix and not a namespace.
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

/// A value, kept as the bits it is written as so that a `NaN` payload survives
/// the generator as well as the code under test.
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

/// Writes a generated document as an `RBF` payload.
///
/// Independent of `rpf-core`: `docs/metadata-encodings.md`'s token-stream table
/// transcribed once more, so that agreement between the two is evidence.
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

/// Writes a record's index and type, and its name if this is its first use.
///
/// Keyed by name alone, which is the measurement: 391 of 391 shipped files
/// reproduce that way and 205 of 391 reproduce keyed by name and type.
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

    /// R5.7's law: unedited in, unedited out, byte-identical.
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

    /// §6: a metadata payload is third-party data, and some of it is malformed
    /// on purpose. Every one of these is an error or a document, never a panic.
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
