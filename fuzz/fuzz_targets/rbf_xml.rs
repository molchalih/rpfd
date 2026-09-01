//! `rbf::from_xml` over arbitrary bytes offered as a document.
//!
//! Bare bytes rather than a shaped type, so the corpus can be seeded with the
//! XML `to_xml` writes for the shipped `RBF` files: from nothing a mutator
//! spends its whole budget before the first `<`. Asserts [`rbf_law`].

#![no_main]

use libfuzzer_sys::fuzz_target;
use rpf_fuzz::{bounded, rbf_law, watched};

fuzz_target!(|document: &[u8]| {
    let Some(document) = bounded(document) else {
        return;
    };

    watched(|| rbf_law(document));
});
