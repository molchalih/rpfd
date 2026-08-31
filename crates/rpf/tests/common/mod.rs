//! Real `RBF` and `PSO` payloads, and the documents they convert to.
//!
//! Both frontends have to be shown reading and writing the same two encodings —
//! `docs/conventions.md` §1's test runs both ways — so the fixtures are here
//! rather than written out twice. A second copy of the `PSO` builder in
//! particular would be §3's duplicated constant in scaffolding: a revision to
//! the layout would be applied to one of them, and the stale one would go on
//! building files the parser happens to accept.
//!
//! No game data (DR-006). The `RBF` payload is written by the crate's own
//! serialiser from the document beside it, and the `PSO` one is assembled by
//! hand from `docs/metadata-encodings.md` — there is no `PSO` writer that works
//! from a document alone, which is DR-049's whole subject.
#![allow(
    dead_code,
    reason = "each including test crate gets its own copy of this module and \
              uses the part of it that its frontend needs"
)]
#![allow(
    clippy::expect_used,
    reason = "test scaffolding; a panic is the reporting mechanism. \
              docs/conventions.md §15"
)]

/// The document [`rbf_payload`] is built from, and converts back to.
///
/// One string attribute and one value record — the pair DR-043 records as
/// indistinguishable by spelling, so every type is written down.
pub const RBF_DOCUMENT: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                                <Root name=\"hello\">\n  \
                                <count rbf:uint=\"7\"/>\n\
                                </Root>\n";

/// The same document with its one value changed, which is what an edit is.
pub const RBF_EDITED: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                              <Root name=\"hello\">\n  \
                              <count rbf:uint=\"9\"/>\n\
                              </Root>\n";

/// The document [`minimal_pso`] converts to, with the empty dictionary that is
/// the only one this repository ships (DR-006, R5.5).
pub const PSO_DOCUMENT: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                                <hash_D98BB561 pso:struct=\"hash_D98BB561\">\n  \
                                <hash_12345678 pso:uint=\"7\"/>\n\
                                </hash_D98BB561>\n";

/// The same, with the one value edited.
pub const PSO_EDITED: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                              <hash_D98BB561 pso:struct=\"hash_D98BB561\">\n  \
                              <hash_12345678 pso:uint=\"9\"/>\n\
                              </hash_D98BB561>\n";

/// A real `RBF` payload, written by the crate's own serialiser from `document`.
pub fn rbf_payload(document: &str) -> Vec<u8> {
    rpf_core::metadata::rbf::from_xml(document.as_bytes()).expect("the fixture is an RBF document")
}

/// The name hash of the one structure [`minimal_pso`] defines.
const ROOT_NAME: u32 = 0xD98B_B561;

/// The name hash of its one member.
const MEMBER_NAME: u32 = 0x1234_5678;

/// A minimal valid `PSO`: one block, one structure, one `UINT` member.
///
/// The same fixture `crates/rpf-core/tests/metadata.rs` reasons over, and for
/// the same reason it is built by hand: a payload built by the reader's own
/// model could share the reader's bugs. `docs/metadata-encodings.md`.
pub fn minimal_pso() -> Vec<u8> {
    let mut psin = Vec::new();
    psin.extend_from_slice(&rpf_core::metadata::pso::MAGIC);
    psin.extend_from_slice(&20u32.to_be_bytes());
    psin.extend_from_slice(b"pppppppp"); // docs/metadata-encodings.md: not zero
    psin.extend_from_slice(&7u32.to_be_bytes()); // the member's value

    let mut pmap = Vec::new();
    pmap.extend_from_slice(b"PMAP");
    pmap.extend_from_slice(&32u32.to_be_bytes());
    pmap.extend_from_slice(&1i32.to_be_bytes()); // rootId, 1-based
    pmap.extend_from_slice(&1i16.to_be_bytes()); // entriesCount
    pmap.extend_from_slice(&0x7070u16.to_be_bytes()); // unknown_Eh
    pmap.extend_from_slice(&ROOT_NAME.to_be_bytes());
    pmap.extend_from_slice(&16i32.to_be_bytes()); // offset, from the PSIN header
    pmap.extend_from_slice(&0i32.to_be_bytes()); // unknown_8h
    pmap.extend_from_slice(&4i32.to_be_bytes()); // length

    let mut psch = Vec::new();
    psch.extend_from_slice(b"PSCH");
    psch.extend_from_slice(&44u32.to_be_bytes());
    psch.extend_from_slice(&1u32.to_be_bytes()); // count
    psch.extend_from_slice(&ROOT_NAME.to_be_bytes());
    psch.extend_from_slice(&20i32.to_be_bytes()); // where the entry is
    psch.extend_from_slice(&1u32.to_be_bytes()); // packed: structure, 1 member
    psch.extend_from_slice(&4i32.to_be_bytes()); // structureLength
    psch.extend_from_slice(&0u32.to_be_bytes()); // unk_Ch
    psch.extend_from_slice(&MEMBER_NAME.to_be_bytes());
    psch.extend_from_slice(&[0x06, 0x00]); // UINT, subtype 0
    psch.extend_from_slice(&0u16.to_be_bytes()); // dataOffset
    psch.extend_from_slice(&0u32.to_be_bytes()); // referenceKey

    let mut payload = psin;
    payload.extend_from_slice(&pmap);
    payload.extend_from_slice(&psch);
    payload
}

/// Every encoding a frontend has to show reading and writing as XML, as
/// (payload, document, edited document, the encoding's name on the wire).
pub fn tokenised() -> Vec<(Vec<u8>, &'static str, &'static str, &'static str)> {
    vec![
        (rbf_payload(RBF_DOCUMENT), RBF_DOCUMENT, RBF_EDITED, "rbf"),
        (minimal_pso(), PSO_DOCUMENT, PSO_EDITED, "pso"),
    ]
}
