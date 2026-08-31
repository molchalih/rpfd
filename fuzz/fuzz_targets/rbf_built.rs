//! `rbf::from_xml` over documents an `Arbitrary` script writes.
//!
//! **A mutator handed bytes reaches almost none of this parser.** `rbf_xml.rs`
//! solves that by seeding with real documents; this solves the other half of
//! it, which seeds cannot: everything a shipped file is *not*. The 391 files
//! in the corpus are 391 documents one writer produced, all of them balanced,
//! all of their names legal, none of them 256 deep, none carrying an attribute
//! twice or a name that begins `rbf:` or an escape that is not one. Those are
//! the inputs the refusals exist for, and no amount of mutating a valid
//! document reliably lands on them.
//!
//! The document is generated **flat**, as a script of steps over an element
//! stack, rather than as a recursive tree. Two reasons, both about the mutator
//! rather than about `RBF`: a recursive `Arbitrary` spends input on depth in a
//! way no byte-level mutation maps onto, so flipping one byte in the middle of
//! a tree rewrites everything after it; and an unbalanced script is exactly
//! how the depth cap and the unclosed-element refusals are reached, which a
//! well-formed tree can never produce.
//!
//! What is asserted is [`rbf_law`], stated once there because `rbf_xml.rs`
//! makes the same claim from the other side.

#![no_main]

use std::sync::OnceLock;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rpf_core::metadata::rbf;
use rpf_fuzz::{MAX_INPUT, rbf_law, watched};

/// The reserved name prefix the mapping uses, which is not a namespace.
///
/// `rbf/mod.rs`, and DR-043 for why it is a prefix: a real descriptor name in
/// the corpus is `CriminalCareerDefs::ShoppingCartItemCategoryLimits`, which no
/// namespace-well-formed document can carry.
const RESERVED: &str = "rbf:";

/// The reserved attribute carrying an open element's two meaningless words.
const UNKNOWN: &str = "unknown";

/// Names and values that occur in the corpus, or that the mapping's own
/// documentation uses as its examples.
///
/// **A vocabulary, not a whitelist.** Every one of these is reachable through
/// the arbitrary arm too; having them under one byte is what lets the mutator
/// build a document whose names agree across a rename or a duplicate, which is
/// where the descriptor table's rules live. Two are deliberately not names —
/// the empty string, and the one carrying a dot, which the attribute spelling
/// splits at.
const VOCABULARY: &[&str] = &[
    "Item",
    "CTimeArchetypeDef",
    "CMapTypes",
    "name",
    "lodDist",
    "bbMin",
    "fxOffsetPos",
    "type",
    "CriminalCareerDefs::ShoppingCartItemCategoryLimits",
    "a.b",
    "",
    "100",
    "1.0",
    "true",
    "false",
    "-13.966396, -15.5559, -0.1963501",
    "0x3F800000",
    "des_gasstation01\u{0}",
];

/// The type words, one per value record kind. `rbf/xml.rs` owns the spellings.
const KINDS: [&str; 5] = ["uint", "float", "bool", "float3", "string"];

/// Escape sequences a document may carry, including ones that are not.
///
/// `xml::read` resolves predefined entities and refuses the rest as
/// `NotRbf::BadEscape`, and that arm has no other way to be reached: a value
/// this target escaped itself never carries one.
const ESCAPES: [&str; 6] = ["&amp;", "&lt;", "&#65;", "&#x41;", "&bogus;", "&#xZZ;"];

/// One step of the script, against a stack of open elements.
#[derive(Debug, Arbitrary)]
enum Step<'a> {
    /// Open an element, with attributes and optionally the reserved word pair.
    Open {
        /// The element's name.
        name: Word<'a>,
        /// Its attributes: a name, a value, and the type that decides whether
        /// the attribute is spelled plainly or `rbf:<type>.<name>`.
        attributes: Vec<(Word<'a>, Word<'a>, Option<u8>)>,
        /// The two words, written as `rbf:unknown` when present.
        unknown: Option<(u16, u16)>,
    },
    /// An empty child element carrying one reserved attribute: a value record.
    Value {
        /// The record's name.
        name: Word<'a>,
        /// Which of [`KINDS`] it claims to be.
        kind: u8,
        /// Its text.
        text: Word<'a>,
    },
    /// Text inside whatever is open, which is how a blob is spelled.
    Text(Word<'a>),
    /// An escape sequence out of [`ESCAPES`], written into the text unescaped.
    Escape(u8),
    /// Close the innermost open element.
    Close,
}

/// A string: one out of the vocabulary, or anything at all.
#[derive(Debug, Arbitrary)]
enum Word<'a> {
    /// An index into [`VOCABULARY`], taken modulo its length so that every
    /// byte names one.
    Known(u8),
    /// Where the name and value rules are actually tested.
    Any(&'a str),
}

impl Word<'_> {
    /// The text this word is.
    fn text(&self) -> &str {
        match *self {
            Self::Known(at) => VOCABULARY
                .get(usize::from(at) % VOCABULARY.len())
                .copied()
                .unwrap_or_default(),
            Self::Any(text) => text,
        }
    }
}

/// The most steps one script may carry.
///
/// Each one costs at most a handful of bytes of document, and the render is
/// capped at [`MAX_INPUT`] regardless; this bounds the decode itself, which is
/// a `Vec` the input chose the length of.
const STEP_LIMIT: usize = 4096;

fuzz_target!(|steps: Vec<Step>| {
    // **The generator's vocabulary is a copy, and a copy can go stale.**
    // `RESERVED`, `UNKNOWN` and `KINDS` are spellings `rbf::xml` owns and does
    // not export, so nothing but this makes them agree. If they drift, every
    // document this writes is refused at its first reserved attribute and the
    // target quietly stops asserting anything — which is `docs/backlog.md`'s
    // own lesson about a target that tested the function beside the one
    // clients call, and it cost a campaign. So the vocabulary is checked once
    // per process against the parser itself, and a drift is a loud failure
    // here rather than a silent zero.
    static CHECKED: OnceLock<()> = OnceLock::new();
    CHECKED.get_or_init(canary);

    // The script is input as much as a document would be, and one step decodes
    // into several bytes of one. `MAX_INPUT` bounds the render; this bounds the
    // decode, which is a `Vec` the input chose the length of.
    if steps.len() > STEP_LIMIT {
        return;
    }
    let document = rendered(&steps);

    watched(|| rbf_law(&document));
});

/// One document of each shape the generator writes, all of which `from_xml`
/// must accept.
///
/// # Panics
///
/// If any of them is refused, which means this file's vocabulary and
/// `rbf::xml`'s no longer agree.
fn canary() {
    let shapes: [&[Step]; 4] = [
        // A bare element.
        &[Step::Open {
            name: Word::Known(0),
            attributes: Vec::new(),
            unknown: None,
        }],
        // An element carrying the reserved word pair and both attribute
        // spellings — plain for a string, `rbf:<type>.<name>` for the rest.
        &[Step::Open {
            name: Word::Known(0),
            attributes: vec![
                (Word::Known(3), Word::Known(11), None),
                (Word::Known(4), Word::Known(11), Some(0)),
            ],
            unknown: Some((7, 9)),
        }],
        // A value record of every type, which is where `KINDS` is spent.
        &[
            Step::Open {
                name: Word::Known(0),
                attributes: Vec::new(),
                unknown: None,
            },
            Step::Value {
                name: Word::Known(4),
                kind: 0,
                text: Word::Known(11),
            },
            Step::Value {
                name: Word::Known(4),
                kind: 1,
                text: Word::Known(12),
            },
            Step::Value {
                name: Word::Known(4),
                kind: 2,
                text: Word::Known(13),
            },
            Step::Value {
                name: Word::Known(5),
                kind: 3,
                text: Word::Known(15),
            },
            Step::Value {
                name: Word::Known(3),
                kind: 4,
                text: Word::Known(11),
            },
        ],
        // A blob, which is an element's text.
        &[
            Step::Open {
                name: Word::Known(0),
                attributes: Vec::new(),
                unknown: None,
            },
            Step::Text(Word::Known(17)),
        ],
    ];

    for (at, shape) in shapes.iter().enumerate() {
        let document = rendered(shape);
        assert!(
            rbf::from_xml(&document).is_ok(),
            "shape {at} of this file's vocabulary is not a document `from_xml` reads, \
             so the vocabulary and `rbf::xml`'s no longer agree: {}",
            String::from_utf8_lossy(&document)
        );
    }
}

/// Renders a script into a document.
///
/// Elements still open when the script ends are closed, so an unbalanced
/// script is a deep document rather than a truncated one — truncation is what
/// the [`Input::Raw`] arm is for, and a document that never closes its root
/// tests the syntax check rather than anything about `RBF`.
fn rendered(steps: &[Step]) -> Vec<u8> {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let mut open: Vec<String> = Vec::new();

    for step in steps {
        if out.len() > MAX_INPUT {
            break;
        }
        match *step {
            Step::Open {
                ref name,
                ref attributes,
                unknown,
            } => {
                let name = name.text().to_owned();
                out.push('<');
                out.push_str(&name);
                if let Some((first, second)) = unknown {
                    out.push_str(&format!(" {RESERVED}{UNKNOWN}=\"{first} {second}\""));
                }
                for (attribute, value, kind) in attributes {
                    out.push(' ');
                    if let Some(kind) = *kind {
                        out.push_str(RESERVED);
                        out.push_str(word_of(kind));
                        out.push('.');
                    }
                    out.push_str(attribute.text());
                    out.push_str("=\"");
                    escaped(&mut out, value.text());
                    out.push('"');
                }
                out.push('>');
                open.push(name);
            }
            Step::Value {
                ref name,
                kind,
                ref text,
            } => {
                out.push('<');
                out.push_str(name.text());
                out.push(' ');
                out.push_str(RESERVED);
                out.push_str(word_of(kind));
                out.push_str("=\"");
                escaped(&mut out, text.text());
                out.push_str("\"/>");
            }
            Step::Text(ref text) => escaped(&mut out, text.text()),
            Step::Escape(at) => {
                let at = usize::from(at) % ESCAPES.len();
                out.push_str(ESCAPES.get(at).copied().unwrap_or("&amp;"));
            }
            Step::Close => {
                if let Some(name) = open.pop() {
                    out.push_str("</");
                    out.push_str(&name);
                    out.push('>');
                }
            }
        }
    }

    while let Some(name) = open.pop() {
        out.push_str("</");
        out.push_str(&name);
        out.push('>');
    }
    out.into_bytes()
}

/// The type word this byte names.
fn word_of(kind: u8) -> &'static str {
    KINDS
        .get(usize::from(kind) % KINDS.len())
        .copied()
        .unwrap_or("uint")
}

/// Appends `text` with the five characters XML reserves replaced.
///
/// The document has to be readable for anything past the syntax check to be
/// reached, and an unescaped `"` in an attribute value ends it. What is
/// deliberately *not* escaped is [`Step::Escape`], which writes its sequence
/// straight in — including two that are not sequences.
fn escaped(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(character),
        }
    }
}
