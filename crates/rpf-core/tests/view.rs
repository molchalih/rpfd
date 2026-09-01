//! Reading an entry as XML and writing a document back into it through
//! `rpf_core::view`: which entries have a view, what a request for one they
//! have not answers, that a converted write is a write of the entry's own
//! encoding, and that a resource is never sniffed for one.
//!
//! Corpus-free; the `PSO` cases here are about routing rather than about a
//! `PSO` file.
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

const AT: &str = "data/thing.ymt";

/// The document the `RBF` fixture is built from, and converts back to: one
/// string attribute and one value record, the pair that cannot be told apart by
/// how they are spelled.
const DOCUMENT: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                        <Root name=\"hello\">\n  \
                        <count rbf:uint=\"7\"/>\n\
                        </Root>\n";

const EDITED: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                      <Root name=\"hello\">\n  \
                      <count rbf:uint=\"9\"/>\n\
                      </Root>\n";

fn rbf_payload(document: &str) -> Vec<u8> {
    rbf::from_xml(document.as_bytes()).expect("the fixture document is an RBF document")
}

fn archive_holding(contents: &[u8]) -> Vec<u8> {
    build_with(
        FileKind::Binary {
            storage: Storage::Stored,
            encryption: 0,
        },
        contents,
    )
}

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

fn read(bytes: Vec<u8>, view: View) -> rpf_core::Result<rpf_core::Viewed> {
    let (mut src, archive, index) = opened(bytes);
    rpf_core::view::read(&mut src, &archive, index, AT, wanted(view))
}

fn wanted(view: View) -> rpf_core::view::Wanted<'static> {
    rpf_core::view::Wanted {
        view,
        names: Dictionary::EMPTY,
    }
}

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

    let automatic = read(archive_holding(&rbf_payload(DOCUMENT)), View::Auto).expect("has a view");
    assert_eq!(automatic, viewed);

    let raw = read(archive_holding(&rbf_payload(DOCUMENT)), View::Raw).expect("raw");
    assert!(!raw.xml);
    assert_eq!(raw.bytes, rbf_payload(DOCUMENT));
    assert_eq!(raw.encoding, Some(Encoding::Rbf));
}

#[test]
fn a_document_that_was_not_edited_writes_the_identical_payload_back() {
    // A read and a write with no edit between them must leave the entry alone.
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
    // The payload is plainly XML and the entry is a resource: the row wins.
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
    // The write side of the row above: dispatching on a resource payload's own
    // leading bytes would write a tokenised payload into a resource entry when
    // its first four bytes happen to be `RBF0`.
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
    // `auto` refuses too: handing the document back for the commit to write
    // would be a silent replacement, not a fallback.
    let refused =
        apply(bytes, View::Auto, EDITED.as_bytes()).expect_err("auto has nothing to apply to");
    assert_eq!(refused.name(), "NoXmlView");
}

#[test]
fn a_pso_entry_is_asked_of_the_pso_codec_and_not_of_the_other_one() {
    // Routing only: `NoXmlView` here would mean the entry reached no codec, and
    // `NotRbf` that it reached the wrong one.
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
    // `auto` must never turn a write `raw` would take into a refusal.
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
    // The document itself is still refused; the payload that same document
    // converts to is taken, because it is `RBF`.
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
    // `--as xml` is not a way to smuggle arbitrary bytes past the rule: a
    // document this entry cannot take never becomes a payload at all.
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

// A resource whose payload comes apart exactly as intended and is not a `Meta`
// has no view, and `auto`'s fallback for "no view" must not hand the offered
// document back as the resource's payload.

/// The flag words of a one-page resource: 512 bytes of system and no graphics.
const RESOURCE_FLAGS: ResourceFlags = ResourceFlags {
    system: 0xA800_0000,
    graphics: 0x2000_0000,
};

/// A resource payload that comes apart and is not a `Meta`: 24 opaque bytes,
/// then 512 zero bytes deflated, inflating to exactly the length
/// [`RESOURCE_FLAGS`] declares.
fn plain_resource(fill: u8) -> Vec<u8> {
    use std::io::Write as _;
    let mut payload = vec![0xFF_u8; 24];
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&vec![fill; 512]).expect("deflates");
    payload.extend_from_slice(&encoder.finish().expect("the encoder finishes"));
    payload
}

fn payload_in(bytes: Vec<u8>) -> Vec<u8> {
    let (mut src, archive, index) = opened(bytes);
    archive.extract(&mut src, index).expect("extracts")
}

/// What lands on disk when `offered` is written into the one entry as `view` —
/// `view::apply` and then the rebuild. Refused or taken, what matters is the
/// payload that ends up in the archive.
fn landed(bytes: Vec<u8>, view: View, offered: &[u8]) -> Vec<u8> {
    match apply(bytes.clone(), view, offered) {
        Ok(payload) => payload_in(commits(bytes, &payload).expect("the archive rebuilds")),
        Err(_) => payload_in(bytes),
    }
}

#[test]
fn a_resource_that_is_not_a_meta_takes_no_document_and_the_bytes_prove_it() {
    let payload = plain_resource(0x00);
    let bytes = build_with(
        FileKind::Resource {
            declared: Some(RESOURCE_FLAGS),
        },
        &payload,
    );

    assert_eq!(payload_in(bytes.clone()), payload, "the fixture's payload");
    let refused = read(bytes.clone(), View::Xml).expect_err("not a Meta");
    assert_eq!(refused.name(), "NoXmlView");
    assert_eq!(
        read(bytes.clone(), View::Auto)
            .expect("auto reads bytes")
            .bytes,
        payload,
        "a read of a resource with no view is still its own bytes"
    );

    for view in [View::Xml, View::Auto] {
        let refused = apply(bytes.clone(), view, DOCUMENT.as_bytes())
            .expect_err("a resource takes no document");
        assert_eq!(refused.name(), "NoXmlView", "as {}", view.name());
        assert_eq!(refused.category(), rpf_core::Category::Refused);
        let after = landed(bytes.clone(), view, DOCUMENT.as_bytes());
        assert_eq!(
            after,
            payload,
            "as {}: the entry's payload was replaced by the document",
            view.name()
        );
        assert_ne!(after.get(..5), Some(&b"<?xml"[..]));
    }

    let other = plain_resource(0x5A);
    for view in [View::Raw, View::Auto] {
        assert_eq!(
            landed(bytes.clone(), view, &other),
            other,
            "as {}: a resource stopped taking its own bytes",
            view.name()
        );
    }
}

#[test]
fn a_resource_whose_row_is_corrupt_refuses_a_write_rather_than_overwriting_it() {
    // The read runs before `auto` decides anything, so a row no reader can
    // follow takes no write: it would put bytes at an offset nobody can name.
    // `--as raw` is the escape hatch.
    let mut bytes = build_with(
        FileKind::Resource {
            declared: Some(RESOURCE_FLAGS),
        },
        &plain_resource(0x00),
    );
    // The entry table follows the 16-byte header and the file's row is the
    // third. A file row's block offset is the 24 bits at 5..8, whose top bit is
    // the resource flag: the row still says "resource" and no longer says where.
    let row = 16 + 16 * 2;
    bytes[row + 5..row + 8].copy_from_slice(&[0xFF, 0xFF, 0xFF]);

    // By name rather than through `Archive::locate`, which reads the entry to
    // see whether it nests an archive and fails on this row first.
    let mut src = Cursor::new(bytes);
    let archive = Archive::open(&mut src, &Unlock::unkeyed()).expect("the archive still opens");
    let index = archive.find(AT).expect("the entry is still listed");
    let out_of_bounds = archive
        .extract(&mut src, index)
        .expect_err("the row points nowhere");
    assert!(
        matches!(out_of_bounds, Error::OutOfBounds { .. }),
        "the fixture is not the case it claims to be: {out_of_bounds:?}"
    );

    let offered = b"\x00\x01\x02 not a document";
    let refused = rpf_core::view::apply(
        &mut src,
        &archive,
        index,
        AT,
        wanted(View::Auto),
        offered.to_vec(),
    )
    .expect_err("a row no reader can follow takes no write");
    assert!(
        matches!(refused, Error::OutOfBounds { .. }),
        "expected the row's own error, got {refused:?}"
    );
    assert_eq!(
        rpf_core::view::apply(
            &mut src,
            &archive,
            index,
            AT,
            wanted(View::Raw),
            offered.to_vec(),
        )
        .expect("raw writes what it is given"),
        offered,
    );
}
