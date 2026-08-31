//! `meta::to_xml` over arbitrary bytes, which is `meta::parse` and the walk.
//!
//! The resource-embedded `Meta` seam had **no** fuzz target at all, and it is
//! the largest of the three metadata encodings by corpus: 49,614 shipped files
//! against `PSO`'s 9,324 and `RBF`'s 391. Everything `pso.rs` says about why
//! the payload direction is worth a target holds here with more force, because
//! this parser resolves *two* address spaces rather than one and walks a block
//! graph the file itself chose — one that can name a cycle, a diamond, or a
//! structure whose members lie outside it.
//!
//! The input is bare bytes rather than a shaped type, so the corpus can be
//! seeded with the dumped payloads `tools/metadata-dump --kinds meta` writes.
//! What such a seed does *not* carry is its page boundary, which lives in its
//! file name; [`meta_split`] is where that is derived instead, and says what
//! the consequence is.
//!
//! Past "no panic", "no hang" and the [`watched`] allocation bound, one
//! property: **what it writes is a document.** `Ok` from a writer is a claim
//! that its bytes are XML and nothing about not panicking checks that claim.
//! `meta_trip.rs` asks the stronger question — the round trip — of the same
//! payloads; this one is what still holds when `from_xml` refuses.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rpf_core::metadata::meta;
use rpf_fuzz::{bounded, meta_split, names, names_ready, names_setup, watched, well_formed};

fuzz_target!(init: names_setup(), |payload: &[u8]| {
    assert!(
        names_ready(),
        "a per-process answer is being computed on this input's clock, not in `init`"
    );

    let Some(payload) = bounded(payload) else {
        return;
    };
    let system_len = meta_split(payload);

    watched(|| {
        let Ok(document) = meta::to_xml(payload, system_len, names()) else {
            return;
        };
        if let Err(cause) = well_formed(&document) {
            panic!("the XML `to_xml` wrote is not a document: {cause}");
        }
    });
});
