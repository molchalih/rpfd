//! `pso::to_xml` over arbitrary bytes.
//!
//! **The target this crate most obviously did not have.** `docs/backlog.md`
//! records three denial-of-service defects found in this parser by hand on the
//! day it landed: a 132-byte payload reaching 4.7 GB resident and never
//! returning, 8 KB of schema costing 6.8 s of CPU, and 64 KB of schema holding
//! 160 MB and answering `Ok`. Two of those are exactly the shape
//! [`watched`](rpf_fuzz::watched) fails on contact — an allocation three
//! orders of magnitude above an input capped at 64 KiB — and the third is what
//! libFuzzer's own `-timeout` is for. All three were found by a reviewer,
//! because nothing here reached the code.
//!
//! The input is bare bytes rather than a shaped type, and that is deliberate:
//! it is what lets the corpus be **seeded with the 9,324 shipped `PSO` files
//! that fit [`MAX_INPUT`](rpf_fuzz::MAX_INPUT)**. A `PSO` is a chain of
//! big-endian sections that must land exactly on the last byte of the payload,
//! over a schema that must define every structure the walk reaches; a mutator
//! starting from nothing spends its whole budget failing `Malformed::Trailing`
//! and never sees `PSCH`. Starting from files that already convert, it spends
//! it on what a packer would never write.
//!
//! The dictionary is [`Dictionary::default`] here, which `pso/mod.rs` says is
//! a complete answer: it is cosmetic by construction (R5.5), so it cannot
//! decide whether a payload converts. What it *can* decide is what the names
//! in the document say, and that is `dictionary.rs`'s subject.
//!
//! Past "no panic" and past the allocation bound, one property: **what it
//! writes is a document.** `Ok` from a writer is a claim that its bytes are
//! XML, and nothing about not panicking checks that claim. `PSO` has no reader
//! on this side to check it with — `rbf.rs` has `from_xml` and gets the
//! stronger round trip instead — so this is the whole of what can be asked of
//! the output, and it is worth asking: the corpus test that asks it
//! (`every_document_the_corpus_produces_is_well_formed_xml`) is gated on a
//! corpus being present, and says nothing about a payload nobody shipped.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rpf_core::metadata::{hash::Dictionary, pso};
use rpf_fuzz::{bounded, watched, well_formed};

fuzz_target!(|payload: &[u8]| {
    let Some(payload) = bounded(payload) else {
        return;
    };

    watched(|| {
        let Ok(document) = pso::to_xml(payload, &Dictionary::default()) else {
            return;
        };
        if let Err(cause) = well_formed(&document) {
            panic!("the XML `to_xml` wrote is not a document: {cause}");
        }
    });
});
