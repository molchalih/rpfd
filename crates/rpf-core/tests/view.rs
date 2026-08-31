//! Reading an entry as XML and writing a document back into it.
//!
//! R7.4 needs a metadata entry to be *presented* as XML and taken back as one,
//! and `rpf_core::view` is the seam both frontends do it through. What is
//! pinned here is the seam's own decisions: which entries have a view, what a
//! request for a view they have not answers, that a converted write is a write
//! of the entry's own encoding — so DR-050's guardrail neither weakens nor gets
//! in the way — and that a resource is never sniffed for one. DR-053.
//!
//! Corpus-free. The `RBF` payload is built by the crate's own serialiser from a
//! document, which is a fixture with no game data in it (DR-006), and the
//! `PSO` cases here are about routing rather than about a `PSO` file: a real
//! one goes through both frontends in `crates/rpf/tests`.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "an integration test is its own crate with no cfg(test), so the \
              exception docs/conventions.md §15 grants test code is spelled \
              here. A panic is the reporting mechanism"
)]

use std::{io::Cursor, sync::Arc};

use rpf_core::{
    Archive, Bytes, Change, Changes, Dictionary, Encoding, Error, FileKind, FileSpec,
    ResourceFlags, Storage, Unlock, Unwatched, View, metadata::rbf,
};

/// The path every archive here holds its one entry at.
const AT: &str = "data/thing.ymt";

/// The document the `RBF` fixture is built from, and converts back to.
///
/// One string attribute and one value record, which is the pair DR-043 says
/// cannot be told apart by how they are spelled — so a document that survives
/// this survives the thing the mapping exists for.
const DOCUMENT: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                        <Root name=\"hello\">\n  \
                        <count rbf:uint=\"7\"/>\n\
                        </Root>\n";

/// The same document with its one value changed, which is what an edit is.
const EDITED: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                      <Root name=\"hello\">\n  \
                      <count rbf:uint=\"9\"/>\n\
                      </Root>\n";

/// A real `RBF` payload, written by the crate's own serialiser.
fn rbf_payload(document: &str) -> Vec<u8> {
    rbf::from_xml(document.as_bytes()).expect("the fixture document is an RBF document")
}

/// An archive holding one stored binary entry at [`AT`].
fn archive_holding(contents: &[u8]) -> Vec<u8> {
    build_with(
        FileKind::Binary {
            storage: Storage::Stored,
            encryption: 0,
        },
        contents,
    )
}

/// An archive holding one entry of `kind` at [`AT`].
fn build_with(kind: FileKind, contents: &[u8]) -> Vec<u8> {
    let owned = contents.to_vec();
    let mut out = Cursor::new(Vec::new());
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &[FileSpec {
            path: AT.to_owned(),
            kind,
        }],
        &[],
        |_: &str| Ok(Cursor::new(owned.clone())),
        &mut Unwatched,
    )
    .expect("builds");
    out.into_inner()
}

/// The archive, its source, and the index of the one entry in it.
fn opened(bytes: Vec<u8>) -> (Cursor<Vec<u8>>, Archive, u32) {
    let mut src = Cursor::new(bytes);
    let archive = Archive::open(&mut src, &Unlock::unkeyed()).expect("opens");
    let (holder, index) = archive.locate(&mut src, AT).expect("the entry is there");
    assert_eq!(
        holder.entries().len(),
        archive.entries().len(),
        "the fixture nests nothing"
    );
    (src, archive, index)
}

/// Reads the one entry in `bytes` as `view`.
fn read(bytes: Vec<u8>, view: View) -> rpf_core::Result<rpf_core::Viewed> {
    let (mut src, archive, index) = opened(bytes);
    rpf_core::view::read(&mut src, &archive, index, AT, wanted(view))
}

/// The view, with the empty dictionary both frontends offer with it.
fn wanted(view: View) -> rpf_core::view::Wanted<'static> {
    rpf_core::view::Wanted {
        view,
        names: Dictionary::EMPTY,
    }
}

/// The payload a document becomes against the one entry in `bytes`.
fn apply(bytes: Vec<u8>, view: View, offered: &[u8]) -> rpf_core::Result<Vec<u8>> {
    let (mut src, archive, index) = opened(bytes);
    rpf_core::view::apply(
        &mut src,
        &archive,
        index,
        AT,
        wanted(view),
        offered.to_vec(),
    )
}

#[test]
fn the_fixture_is_a_real_rbf_payload_that_the_document_describes() {
    // Every case below is about this payload, so if this stopped holding, all
    // of them would pass for a reason that is not the one they name.
    let payload = rbf_payload(DOCUMENT);
    assert_eq!(&payload[..4], b"RBF0");
    assert_eq!(
        rbf::to_xml(&payload).expect("converts"),
        DOCUMENT.as_bytes()
    );
}

#[test]
fn an_rbf_entry_reads_as_the_document_and_says_what_it_holds() {
    let viewed = read(archive_holding(&rbf_payload(DOCUMENT)), View::Xml).expect("has a view");
    assert!(viewed.xml, "the bytes are the view, and say so");
    assert_eq!(viewed.encoding, Some(Encoding::Rbf));
    assert_eq!(viewed.bytes, DOCUMENT.as_bytes());

    // And `auto` answers the same thing without being told which it will be,
    // which is what a client that must not guess from an extension asks for.
    let automatic = read(archive_holding(&rbf_payload(DOCUMENT)), View::Auto).expect("has a view");
    assert_eq!(automatic, viewed);

    // While `raw` is the entry, untouched, and still names its encoding.
    let raw = read(archive_holding(&rbf_payload(DOCUMENT)), View::Raw).expect("raw");
    assert!(!raw.xml);
    assert_eq!(raw.bytes, rbf_payload(DOCUMENT));
    assert_eq!(raw.encoding, Some(Encoding::Rbf));
}

#[test]
fn a_document_that_was_not_edited_writes_the_identical_payload_back() {
    // The round trip R5.7 measured over 391 and 9,753 files, asserted through
    // the seam a frontend uses rather than through the codec directly: a read
    // and a write with no edit between them must leave the entry alone.
    let payload = rbf_payload(DOCUMENT);
    let viewed = read(archive_holding(&payload), View::Xml).expect("has a view");
    let written = apply(archive_holding(&payload), View::Xml, &viewed.bytes).expect("applies");
    assert_eq!(written, payload);
}

#[test]
fn an_edited_document_becomes_the_binary_encoding_the_entry_holds() {
    let payload = rbf_payload(DOCUMENT);
    let written = apply(archive_holding(&payload), View::Xml, EDITED.as_bytes()).expect("applies");
    assert_ne!(written, payload, "the edit reached the payload");
    assert_eq!(&written[..4], b"RBF0", "and it is still RBF");
    assert_eq!(rbf::to_xml(&written).expect("converts"), EDITED.as_bytes());
    // Which is exactly what the entry itself would have taken, by any route.
    assert_eq!(written, rbf_payload(EDITED));
}

#[test]
fn an_entry_with_no_xml_view_refuses_one_and_auto_gives_its_bytes() {
    for held in [
        &b"a plain line of text\n"[..],
        &[0x00_u8; 32][..],
        &b"\x89PNG\r\n\x1a\n0123456789"[..],
    ] {
        let refused = read(archive_holding(held), View::Xml).expect_err("no view");
        assert_eq!(refused.name(), "NoXmlView", "for {held:?}");
        assert_eq!(refused.category(), rpf_core::Category::Refused);

        let viewed = read(archive_holding(held), View::Auto).expect("auto falls back");
        assert!(!viewed.xml);
        assert_eq!(viewed.bytes, held);
    }
}

#[test]
fn a_resource_entry_does_not_claim_an_xml_view_whatever_its_payload_says() {
    // The payload is plainly XML and the entry is a resource, so the two
    // sources disagree and the entry's row wins — `docs/backlog.md` Q7, and
    // the reason `Classification` has no way to say otherwise. R5.8 is what
    // gives a resource a view, and it will give it one through its own kind
    // rather than by sniffing this.
    let bytes = build_with(
        FileKind::Resource {
            declared: Some(ResourceFlags {
                system: 0xA800_0000,
                graphics: 0x2000_0000,
            }),
        },
        b"<CVehicleModelInfo />",
    );
    let refused = read(bytes.clone(), View::Xml).expect_err("a resource has no view");
    assert_eq!(refused.name(), "NoXmlView");
    let viewed = read(bytes, View::Auto).expect("auto");
    assert!(!viewed.xml);
    assert_eq!(viewed.encoding, None, "a resource's payload is not read");
}

#[test]
fn a_resource_entry_takes_no_document_whatever_its_payload_begins_with() {
    // The write side of the row above, and the half that was missing: `read`
    // asked `Archive::classify` and `apply` asked only whether the entry was a
    // directory, leaving `metadata::view::from_xml` to dispatch on the raw
    // resource payload's own leading bytes. A resource whose first four bytes
    // are `RBF0` would then take the `rbf` arm and a tokenised payload would be
    // written into a resource entry — the one thing `Classification::Resource`
    // carries no encoding to make sayable. Q7, DR-044.
    //
    // Not reachable on the corpus, where every resource is high-entropy at its
    // head, and reachable here in four bytes, which is what a synthetic entry
    // is for.
    let bytes = build_with(
        FileKind::Resource {
            declared: Some(ResourceFlags {
                system: 0xA800_0000,
                graphics: 0x2000_0000,
            }),
        },
        &rbf_payload(DOCUMENT),
    );
    let refused = apply(bytes.clone(), View::Xml, EDITED.as_bytes())
        .expect_err("a resource has no view to write into");
    assert_eq!(refused.name(), "NoXmlView");
    assert_eq!(
        apply(bytes, View::Auto, EDITED.as_bytes()).expect("auto takes the bytes as they are"),
        EDITED.as_bytes(),
        "a document was tokenised against a resource payload"
    );
}

#[test]
fn a_pso_entry_is_asked_of_the_pso_codec_and_not_of_the_other_one() {
    // Routing, and only routing: these bytes announce `PSO` and are not one, so
    // what comes back has to be the `PSO` reader's refusal. `NoXmlView` here
    // would mean the entry was never offered to a codec at all, and `NotRbf`
    // would mean it was offered to the wrong one. A real `PSO` file goes
    // through both frontends in `crates/rpf/tests`.
    let refused = read(
        archive_holding(b"PSIN\x01\x02\x03\x04sections here"),
        View::Xml,
    )
    .expect_err("not a PSO");
    assert_eq!(refused.name(), "BadPso");
}

#[test]
fn a_plain_xml_entry_is_its_own_view_and_an_edit_of_it_is_the_document() {
    let held = b"<CVehicleModelInfo />";
    let viewed = read(archive_holding(held), View::Xml).expect("XML is its own view");
    assert!(viewed.xml);
    assert_eq!(viewed.bytes, held);
    assert_eq!(viewed.encoding, Some(Encoding::Xml));

    let edited = b"<CVehicleModelInfo x=\"1\" />";
    assert_eq!(
        apply(archive_holding(held), View::Xml, edited).expect("applies"),
        edited,
        "an entry that is XML takes the document as it is"
    );
}

#[test]
fn auto_hands_a_payload_that_is_not_a_document_to_the_entry_untouched() {
    // What a client pastes into an entry is not always a document, and `auto`
    // must never turn a write `raw` would take into a refusal. A second `RBF`
    // payload written over the first is the case that would break.
    let held = rbf_payload(DOCUMENT);
    let other = rbf_payload(EDITED);
    assert_eq!(
        apply(archive_holding(&held), View::Auto, &other).expect("takes it"),
        other,
    );
}

/// The write that goes through `edit`, which is where DR-050's rule is asked.
fn commits(archive_bytes: Vec<u8>, payload: &[u8]) -> rpf_core::Result<Vec<u8>> {
    let mut src = Cursor::new(archive_bytes);
    let archive = Archive::open(&mut src, &Unlock::unkeyed()).expect("opens");
    let changes = Changes::one(
        AT,
        Change::Write {
            contents: Arc::new(Bytes::new(payload.to_vec())),
            create: false,
            allow_encoding_change: false,
        },
    );
    let mut out = Cursor::new(Vec::new());
    rpf_core::rewrite(
        &mut src,
        &archive,
        &changes,
        &mut out,
        &mut rpf_core::InMemory,
        &mut Unwatched,
    )?;
    Ok(out.into_inner())
}

#[test]
fn converting_is_not_a_way_round_the_guardrail_that_refuses_a_document() {
    // DR-050 refuses a textual payload into a tokenised entry, and R7.4 must
    // not become a hole in it. Both halves are asserted against one archive:
    // the document itself is still refused, and the payload the *same* document
    // converts to is taken — because it is `RBF`, which is what the entry
    // holds and what the runtime will read. There is no third answer in which
    // XML lands in the entry.
    let held = rbf_payload(DOCUMENT);
    let refused = commits(archive_holding(&held), EDITED.as_bytes())
        .expect_err("a document is not a payload");
    assert_eq!(refused.name(), "WrongEncoding");
    assert_eq!(refused.category(), rpf_core::Category::Refused);

    let converted = apply(archive_holding(&held), View::Xml, EDITED.as_bytes()).expect("converts");
    let rebuilt = commits(archive_holding(&held), &converted).expect("a payload is taken");

    let mut src = Cursor::new(rebuilt);
    let archive = Archive::open(&mut src, &Unlock::unkeyed()).expect("opens");
    let (holder, index) = archive.locate(&mut src, AT).expect("still there");
    assert_eq!(
        holder.classify(&mut src, index).expect("classifies"),
        rpf_core::Classification::Encoded(Encoding::Rbf),
        "the entry still holds RBF after a converted write"
    );
    assert_eq!(holder.extract(&mut src, index).expect("reads"), converted);
}

#[test]
fn a_document_that_does_not_describe_the_entry_is_refused_rather_than_taken() {
    // The other half of the same guarantee: `--as xml` is not a way to smuggle
    // arbitrary bytes past the rule either, because a document that is not one
    // this entry can take never becomes a payload at all.
    let held = rbf_payload(DOCUMENT);
    let refused = apply(
        archive_holding(&held),
        View::Xml,
        b"<?xml version=\"1.0\"?><Root><nonsense rbf:notatype=\"1\"/></Root>",
    )
    .expect_err("not an RBF document");
    assert!(
        matches!(refused, Error::NotRbfXml { .. }),
        "expected a refusal about the document, got {refused:?}"
    );
}
