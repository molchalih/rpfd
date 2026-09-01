//! `meta::to_xml` over arbitrary bytes, which is `meta::parse` and the walk.
//!
//! Bare bytes, so the corpus can be seeded with dumped `Meta` payloads; a seed
//! does not carry its page boundary, which [`meta_split`] derives instead.
//! Past "no panic" and the [`watched`] bound: what it writes is a document.

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
