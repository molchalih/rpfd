//! The `Meta` round trip: read a payload, write its XML, apply that XML back
//! unmodified, and require the payload to be unchanged.
//!
//! `to_xml` and `from_xml` are two halves of one build, so a payload this build
//! wrote a document for and then refuses is a defect. The document is `to_xml`'s
//! own output, unmodified, so `from_xml` edits the payload it was given and
//! must edit nothing.

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
