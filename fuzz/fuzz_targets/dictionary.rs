//! `Dictionary::load` over arbitrary text, and every guarantee it states.
//!
//! **A dictionary file is third-party data too, and it is the one input to the
//! metadata layer that a person edits by hand.** `PSO` member names are Jenkins
//! hashes, so what a name is *spelled* as in the output comes out of this file
//! — the largest published list is 20,300 entries, 40 of which do not hash to
//! the key they claim. `pso.rs` fuzzes the payload with an empty dictionary
//! because the dictionary cannot decide whether a payload converts (R5.5);
//! this fuzzes the half that decides what the document says.
//!
//! Loading never fails, so "no panic" is nearly the whole of what a return
//! value could say. What is worth asserting is the **contract**, which
//! `Dictionary`'s own doc comment states and which the rest of the mapping
//! rests on: every name it kept is a valid XML name, does not begin with the
//! reserved prefix, does not spell a placeholder, and hashes to the key it is
//! filed under — "so `Dictionary::name` can be rendered into a document and
//! read back to the same `u32` unconditionally, which is the whole reason the
//! dictionary is allowed to be optional."
//!
//! Each clause is checked here, and the first one is checked by **writing an
//! element with the name in it and parsing that**, rather than by re-deciding
//! what an XML name is. A second opinion on that question is a second
//! implementation to keep correct (§1's argument, one layer down), and it is
//! the opinion that would be wrong: the point is not that the name matches
//! some rule this file believes, it is that a document carrying it parses.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rpf_core::metadata::hash::{self, Dictionary, RESERVED_PREFIX};
use rpf_fuzz::{bounded, watched, well_formed};

fuzz_target!(|text: &str| {
    let Some(text) = bounded(text.as_bytes()).map(|_| text) else {
        return;
    };

    watched(|| {
        let loaded = Dictionary::load(text);

        // What was offered is recovered from the text rather than read out of
        // the dictionary, because a dictionary does not hand back its keys —
        // and it is the stronger direction anyway. Looking a name up under the
        // hash it was filed at and finding they agree asks nothing; looking it
        // up under the hash of *the name the file gave* is what would catch a
        // name filed under someone else's key.
        for line in text.lines() {
            let body = line.trim();
            if body.is_empty() || body.starts_with('#') {
                continue;
            }
            let name = match body.split_once([' ', '\t', ',', '=']) {
                Some((_, rest)) => rest.trim_matches([' ', '\t', ',', '=']),
                None => body,
            };
            let hash = hash::joaat(name.as_bytes());
            let Some(held) = loaded.dictionary.name(hash) else {
                continue;
            };
            if held != name {
                // An earlier line took this hash, which is that line's
                // business and is checked on its own turn.
                continue;
            }

            assert!(
                !held.starts_with(RESERVED_PREFIX),
                "the dictionary kept {held:?}, which begins with the reserved prefix"
            );
            assert!(
                hash::unplaceholder(held).is_none(),
                "the dictionary kept {held:?}, which spells a placeholder"
            );
            assert_eq!(
                loaded.dictionary.render(hash),
                held,
                "the dictionary renders {hash:#010X} as something other than the name it holds"
            );

            // The clause the whole mapping rests on: a name written into a
            // document is a name a document can carry.
            let element = format!("<{held}/>");
            if let Err(cause) = well_formed(element.as_bytes()) {
                panic!("the dictionary kept {held:?}, which no document can carry: {cause}");
            }
        }

        // A rejection is an answer about a line that exists, and a line number
        // of zero or past the end names none.
        let lines = text.lines().count();
        for rejected in &loaded.rejected {
            assert!(
                rejected.line >= 1 && rejected.line <= lines,
                "a rejection is reported at line {} of a file with {lines} lines",
                rejected.line
            );
        }
        assert!(
            loaded.rejected.len() <= lines,
            "{} rejections from {lines} lines",
            loaded.rejected.len()
        );

        // A placeholder is the one spelling a name may not have, and
        // `unplaceholder` is stated to be the exact inverse of `placeholder`
        // — including for a hash this build could not resolve, which is what
        // lets a rendered name survive the trip back whatever the dictionary
        // says.
        for rejected in &loaded.rejected {
            let hash = hash::joaat(rejected.name.as_bytes());
            if loaded.dictionary.name(hash).is_some() {
                continue;
            }
            let spelled = loaded.dictionary.render(hash);
            assert_eq!(
                hash::unplaceholder(&spelled),
                Some(hash),
                "an unresolved hash renders as {spelled:?}, which does not read back"
            );
        }
    });
});
