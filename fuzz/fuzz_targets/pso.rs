//! `pso::to_xml` over arbitrary bytes.
//!
//! Bare bytes, so the corpus can be seeded with shipped `PSO` files that fit
//! [`MAX_INPUT`](rpf_fuzz::MAX_INPUT): a `PSO` is a chain of big-endian
//! sections that must land exactly on the payload's last byte, so from nothing
//! a mutator only ever fails `Malformed::Section` at the next header and never
//! sees `PSCH`. It never fails `Malformed::Trailing`, which no payload reaches.
//!
//! The dictionary is cosmetic and cannot decide whether a payload converts, so
//! the default one is a complete answer here. `PSO` has no reader on this side,
//! so the property asserted is that what it writes is a document.

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
