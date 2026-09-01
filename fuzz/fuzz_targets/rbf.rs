//! `rbf::to_xml` over arbitrary bytes, and the round trip back.
//!
//! The round trip is the property and "no panic" is the floor. Shipped streams
//! are canonical by construction, so they say nothing about a stream a packer
//! would never emit — such as one declaring a name at two descriptors, which
//! the reader accepts and the writer normalises away.
//!
//! The corpus is seeded with the shipped files that fit
//! [`MAX_INPUT`](rpf_fuzz::MAX_INPUT).

#![no_main]

use libfuzzer_sys::fuzz_target;
use rpf_core::metadata::rbf;
use rpf_fuzz::{bounded, rbf_law, watched, well_formed};

fuzz_target!(|payload: &[u8]| {
    let Some(payload) = bounded(payload) else {
        return;
    };

    watched(|| {
        let Ok(document) = rbf::to_xml(payload) else {
            return;
        };

        if let Err(cause) = well_formed(&document) {
            panic!("the XML `to_xml` wrote is not a document: {cause}");
        }

        // The document is what survives exactly, not the payload: two
        // descriptors of one name are interchangeable, so the stream that
        // comes back may spell the same document with a smaller table.
        let normalised = match rbf::from_xml(&document) {
            Ok(normalised) => normalised,
            Err(failure) => panic!("`from_xml` refuses the XML `to_xml` wrote: {failure:?}"),
        };
        let again = match rbf::to_xml(&normalised) {
            Ok(again) => again,
            Err(failure) => panic!("`to_xml` refuses the payload `from_xml` built: {failure:?}"),
        };
        assert!(
            again == document,
            "the round trip changed the document: {} bytes of XML in, {} out",
            document.len(),
            again.len()
        );

        // And the payload survives from the normalised form on, which is the
        // byte-for-byte law where it holds.
        rbf_law(&document);
    });
});
