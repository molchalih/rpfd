//! `rbf::from_xml` over arbitrary bytes offered as a document.
//!
//! Bare bytes rather than a shaped type, so the corpus can be **seeded with
//! the XML `to_xml` writes for every shipped `RBF` file** — 388 documents that
//! this build produced and that `from_xml` is claimed to read back exactly.
//! Starting there is what puts the mutator inside the parser: from nothing it
//! spends its whole budget before the first `<`, and everything `xml::read`
//! decides is past it — which tag is a value record and which an element, what
//! `rbf:float.x` splits into, whether a name is a name, whether an attribute is
//! still owed. `rbf_built.rs` reaches the same parser from the other side,
//! with documents an `Arbitrary` script writes.
//!
//! What is asserted is [`rbf_law`], which is stated once there because both
//! targets make the same claim.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rpf_fuzz::{bounded, rbf_law, watched};

fuzz_target!(|document: &[u8]| {
    let Some(document) = bounded(document) else {
        return;
    };

    watched(|| rbf_law(document));
});
