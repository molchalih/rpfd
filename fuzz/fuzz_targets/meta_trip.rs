//! The `Meta` round trip: read a payload, write its XML, apply that XML back
//! unmodified, and require the payload to be unchanged.
//!
//! **The law `every_shipped_meta_file_round_trips_byte_for_byte` states, over
//! payloads no corpus holds.** That test is R5.8b's exit criterion and it can
//! only ever speak about the 49,614 files both installs ship; a mutator reaches
//! the files a packer would never write, and the write direction is where this
//! build has already been found wrong — `3374139` fixed `apply` writing past
//! the value it was editing and silently dropping edits it had accepted.
//!
//! Why the round trip and not just "did not panic": `to_xml` and `from_xml` are
//! two halves of one build, and a payload this build wrote a document for that
//! this build then refuses — or applies back to different bytes — is DR-039's
//! shape one layer up from the archive. The document here is `to_xml`'s own
//! output, **unmodified**, so every difference is the library's: the file
//! carries page slack, inter-table padding and the 2.48% of itself no walk
//! reaches (DR-049), none of which the document can carry, so `from_xml` edits
//! the payload it was given and an unmodified document must edit nothing.
//!
//! `meta_apply.rs` attacks the same direction from the other side, with
//! documents that are *not* what `to_xml` wrote.

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

        let back = match meta::from_xml(payload, system_len, &document, names()) {
            Ok(back) => back,
            Err(failure) => panic!(
                "`from_xml` refuses the document `to_xml` wrote for a payload it read \
                 (system_len {system_len}, {} bytes): {failure}",
                payload.len()
            ),
        };
        assert!(
            back.len() == payload.len(),
            "applying an unmodified document resized the payload: {} bytes in, {} out",
            payload.len(),
            back.len()
        );
        if let Some(at) = back.iter().zip(payload).position(|(wrote, was)| wrote != was) {
            panic!(
                "applying an unmodified document changed the payload at offset {at:#X}: \
                 {:#04X} became {:#04X} (system_len {system_len}, {} bytes)",
                payload[at],
                back[at],
                payload.len()
            );
        }
    });
});
