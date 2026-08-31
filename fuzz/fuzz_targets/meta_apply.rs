//! `meta::from_xml` over documents that are *not* what `to_xml` wrote.
//!
//! **The write direction is where this build has been wrong.** `3374139` fixed
//! `apply` writing past the value it was editing and silently dropping edits it
//! had accepted, and that is the whole argument for this target: the read
//! direction answers a `Result` about bytes it borrows, while the write
//! direction copies the payload and *writes into it* at addresses a document
//! chose. Two properties hold it in place — every write is bounded by the block
//! the value lives in, and two elements that address one spot must agree
//! (DR-059) — and neither is checked by anything else here.
//!
//! Two arms, for the reason `rbf_built.rs` gives for having a generator beside
//! a corpus. The [`Attempt::raw`] arm hands `from_xml` arbitrary bytes, which
//! is what the syntax check, the document budget and "this is not my payload"
//! exist for. The edit arm is the one that reaches the writer: it renders the
//! payload's own document — the only bytes that get past the tree walk at all,
//! since every element has to name a structure the file defines — and rewrites
//! chosen **attribute values** in it. Values are where the writer's arithmetic
//! lives: `render` writes every value as `name="…"` (`render::attribute`), and
//! a length, a lane count, a hex run or an offset read back out of one is what
//! decides how many bytes `put` writes and where.
//!
//! The payload arrives as the input's tail, so it is the mutator's to choose,
//! and `meta_split` derives the page boundary from it exactly as the other two
//! targets do. Most payloads are refused by `parse` and the target does nothing
//! with them — that is what seeding with dumped `Meta` files is for.
//!
//! What is asserted, past no panic and the allocation bound: an `Ok` is an edit
//! of the payload it was given and **the same size as it**. A `from_xml` that
//! answers a payload of a different length has moved something structural,
//! which DR-052 says is not editing; a `from_xml` that writes outside the
//! payload does not reach an assertion at all, because the copy it writes into
//! is a `Vec` and the fuzzer's own detectors own that. Byte-for-byte equality
//! is *not* asserted, because an edit is allowed to change bytes — the
//! unmodified document is `meta_trip.rs`'s subject.

#![no_main]

use std::collections::BTreeMap;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rpf_core::metadata::meta;
use rpf_fuzz::{bounded, meta_split, names, names_ready, names_setup, watched};

/// One attempt to apply a document to a payload.
#[derive(Debug, Arbitrary)]
struct Attempt<'a> {
    /// Rewrites over the document `to_xml` writes for [`Attempt::payload`].
    edits: Vec<Edit<'a>>,
    /// Arbitrary bytes offered as the document instead, when present.
    raw: Option<&'a [u8]>,
    /// The payload being edited, which is the rest of the input.
    payload: &'a [u8],
}

/// One attribute value of the rendered document, replaced.
#[derive(Debug, Arbitrary)]
struct Edit<'a> {
    /// Which value, taken modulo how many the document has so that every byte
    /// names one.
    at: u32,
    /// What to put there.
    value: Value<'a>,
}

/// A replacement value: one out of the vocabulary, or anything at all.
#[derive(Debug, Arbitrary)]
enum Value<'a> {
    /// An index into [`VOCABULARY`], modulo its length.
    Known(u8),
    /// Where the parsing and bounds rules are actually tested.
    Any(&'a str),
}

impl Value<'_> {
    /// The text this value is.
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

/// Values worth reaching under one byte.
///
/// **A vocabulary, not a whitelist**: every one of these is reachable through
/// [`Value::Any`] too, and having them cheap is what lets a mutator put a
/// boundary number where the writer expects a count. The edges of the integer
/// widths a member can be, both float spellings the mapping accepts, a lane
/// list of the wrong arity, hex runs of the wrong parity, a name that is not
/// one, and the empty value.
const VOCABULARY: &[&str] = &[
    "",
    "0",
    "-1",
    "1",
    "127",
    "128",
    "255",
    "65535",
    "65536",
    "2147483647",
    "4294967295",
    "4294967296",
    "9223372036854775807",
    "18446744073709551615",
    "18446744073709551616",
    "99999999999999999999999999",
    "0.0",
    "-0.0",
    "3.4028235e38",
    "1e400",
    "NaN",
    "inf",
    "0, 0",
    "0, 0, 0",
    "0, 0, 0, 0",
    ",,,",
    "00",
    "0",
    "0F1E2D",
    "zz",
    "true",
    "false",
    "meta:struct",
    "\u{0}",
    " ",
];

/// The most edits one attempt may carry.
///
/// Each costs a rewrite of one span; this bounds the decode itself, which is a
/// `Vec` the input chose the length of.
const EDIT_LIMIT: usize = 4096;

fuzz_target!(init: names_setup(), |attempt: Attempt| {
    assert!(
        names_ready(),
        "a per-process answer is being computed on this input's clock, not in `init`"
    );

    let Some(payload) = bounded(attempt.payload) else {
        return;
    };
    if attempt.edits.len() > EDIT_LIMIT {
        return;
    }
    if let Some(raw) = attempt.raw
        && bounded(raw).is_none()
    {
        return;
    }
    let system_len = meta_split(payload);

    watched(|| {
        // The rendered document is needed even for the raw arm's payload to be
        // worth anything: a payload `to_xml` refuses is one `from_xml` refuses
        // for the same reason, before it has looked at a document at all.
        let Ok(rendered) = meta::to_xml(payload, system_len, names()) else {
            return;
        };
        let document = match attempt.raw {
            Some(raw) => raw.to_vec(),
            None => match str::from_utf8(&rendered) {
                Ok(rendered) => rewritten(rendered, &attempt.edits),
                // `to_xml` builds its output as a `String`, so this cannot
                // happen; it is a refusal rather than an assertion because
                // what `to_xml` writes is `meta.rs`'s subject.
                Err(_) => return,
            },
        };

        let Ok(edited) = meta::from_xml(payload, system_len, &document, names()) else {
            return;
        };
        assert!(
            edited.len() == payload.len(),
            "`from_xml` answered {} bytes for a payload of {}, so something structural moved \
             (system_len {system_len})",
            edited.len(),
            payload.len()
        );
    });
});

/// The document with the values `edits` name replaced.
///
/// Ascending and once each: the edits are collected into a map keyed by span,
/// so two edits naming one value are the later one rather than a double
/// splice, and the rebuild walks the document forwards.
fn rewritten(document: &str, edits: &[Edit]) -> Vec<u8> {
    let spans = value_spans(document);
    if spans.is_empty() {
        return document.as_bytes().to_vec();
    }

    let mut chosen: BTreeMap<usize, &Value> = BTreeMap::new();
    for edit in edits {
        let at = usize::try_from(edit.at).unwrap_or(usize::MAX) % spans.len();
        chosen.insert(at, &edit.value);
    }

    let mut out = String::with_capacity(document.len());
    let mut cut = 0;
    for (at, value) in chosen {
        let (start, end) = spans[at];
        out.push_str(&document[cut..start]);
        escaped(&mut out, value.text());
        cut = end;
    }
    out.push_str(&document[cut..]);
    out.into_bytes()
}

/// Where each attribute value of `document` begins and ends, exclusive of its
/// quotes.
///
/// A scan for `="` and the next `"` rather than an XML parse, and it is exact
/// for the one document shape it is ever handed: `render::attribute` writes
/// ` name="value"` with the value escaped, so a `"` inside one is `&quot;` and
/// cannot end a span early.
fn value_spans(document: &str) -> Vec<(usize, usize)> {
    let bytes = document.as_bytes();
    let mut spans = Vec::new();
    let mut at = 0;
    while at + 1 < bytes.len() {
        if bytes[at] == b'=' && bytes[at + 1] == b'"' {
            let start = at + 2;
            match bytes[start..].iter().position(|&byte| byte == b'"') {
                Some(len) => {
                    spans.push((start, start + len));
                    at = start + len + 1;
                }
                None => break,
            }
        } else {
            at += 1;
        }
    }
    spans
}

/// Appends `text` with the characters XML reserves replaced.
///
/// The document has to be readable for the writer to be reached at all, and an
/// unescaped `"` in an attribute value ends it early — which would test the
/// syntax check rather than the addresses. What is deliberately not made safe
/// is anything else: a control character, a lone surrogate's escape, or a value
/// of any length all reach the parser as they are.
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
