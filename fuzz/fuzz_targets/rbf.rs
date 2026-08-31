//! `rbf::to_xml` over arbitrary bytes, and the round trip back.
//!
//! **The round trip is the property, and "no panic" is the floor.**
//! `docs/metadata-encodings.md` measured byte-perfect re-serialisation over
//! 391 of 391 shipped files, which is what makes this a real serialiser rather
//! than R5.6's differential rebuild. But a corpus is not what checks a law:
//! those 391 streams were all written by one packer and are all canonical by
//! construction, and everything a hostile stream can be and a shipped one is
//! not lies outside what they can say anything about. `metadata_laws.rs`
//! asserts the same law over generated documents and has the same blind spot
//! for the same reason — its generator writes the descriptor table the way the
//! reader would rebuild it, so it cannot produce a stream whose table is not
//! already canonical.
//!
//! Which is the shape of DR-039 exactly, and it found the same kind of thing:
//! within ninety seconds this target produced a stream declaring one name at
//! two descriptors, which the reader accepts and the writer does not
//! reproduce. That is a normalisation rather than a loss — the document is
//! identical and only the table is smaller — so what is asserted below is the
//! law with the condition it actually holds under, and
//! `a_name_two_descriptors_declare_is_read_and_written_back_once` pins the
//! case in the ordinary suite.
//!
//! The corpus is seeded with the 388 shipped files that fit
//! [`MAX_INPUT`](rpf_fuzz::MAX_INPUT), so the mutator starts from streams that
//! already convert and spends its budget on what a packer would never emit.

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

        // **The document is what survives exactly.** A payload need not: two
        // descriptors of one name are interchangeable, so the stream that
        // comes back may spell the same document with a smaller table. What
        // may not change is the document itself, and that is the claim a
        // caller actually depends on — an editor round-tripping a file must
        // see what it saw.
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
        // byte-for-byte law where it holds. `rbf_law` states it once because
        // `rbf_xml.rs` and `rbf_built.rs` make the same claim.
        rbf_law(&document);
    });
});
