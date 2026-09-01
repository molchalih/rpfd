//! `Dictionary::load` over arbitrary text, and every guarantee it states.
//!
//! A dictionary file is third-party data, and the one metadata input a person
//! edits by hand. Loading never fails, so what is asserted is the contract:
//! every name kept is a valid XML name, carries no reserved prefix, spells no
//! placeholder, and hashes to the key it is filed under.
//!
//! The XML clause is checked by writing an element with the name in it and
//! parsing that, rather than by re-deciding what an XML name is.

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

        // Recovered from the text rather than from the dictionary: looking a
        // name up under the hash of the name the file gave is what catches a
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

            // The clause the mapping rests on: a name written into a document
            // is a name a document can carry.
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

        // `unplaceholder` is the exact inverse of `placeholder`, including for
        // an unresolved hash, which is what lets a rendered name survive the
        // trip back whatever the dictionary says.
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
