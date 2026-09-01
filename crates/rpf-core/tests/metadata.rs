//! The metadata layer against the metadata both games ship.
//!
//! Unedited in, unedited out, byte-identical, over the shipped corpus rather
//! than over made-up documents. No game data is tracked: payloads are located
//! through `RPF_METADATA` and what is committed is a count and a list of
//! digests. With it unset every test that needs it is `#[ignore]`d.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test code; see the note above"
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::PathBuf,
};

use rpf_core::{
    Category, Error,
    metadata::{
        hash::{self, Dictionary, joaat},
        meta, pso, rbf,
    },
};
use sha2::{Digest, Sha256};

/// What the committed fixture describes.
const FIXTURE: &str = "../../fixtures/rbf-metadata.json";

/// Refuses, naming the test and what it would have read.
///
/// There is no third outcome: `eprintln!` is captured, so a test that skipped
/// quietly would read as a pass, and a missing corpus is `#[ignore]`d first.
fn refuse(test: &str, reason: &str) -> ! {
    panic!("{test} cannot run: {reason}");
}

/// How many payloads of each kind the corpus holds, from the fixture.
fn stated_count(fixture: &str) -> usize {
    let text = fs::read_to_string(fixture).expect("fixture readable");
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("fixture parses");
    usize::try_from(
        parsed["files"]
            .as_u64()
            .expect("the fixture counts its files"),
    )
    .expect("a count fits")
}

/// Every payload under `RPF_METADATA` that opens with `magic`, by file name;
/// recognition is from content, and the count is checked against the fixture's.
fn payloads(test: &str, magic: [u8; 4]) -> BTreeMap<String, Vec<u8>> {
    let Some(root) = env::var_os("RPF_METADATA") else {
        refuse(
            test,
            "RPF_METADATA is not set, so no payload can be located",
        );
    };
    let root = PathBuf::from(root);
    let Ok(listing) = fs::read_dir(&root) else {
        refuse(test, &format!("{} is not a directory", root.display()));
    };
    let mut found = BTreeMap::new();
    for entry in listing {
        let path = entry.expect("directory entry readable").path();
        if !path.is_file() {
            continue;
        }
        let bytes = fs::read(&path).expect("payload readable");
        if bytes.starts_with(&magic) {
            let name = path
                .file_name()
                .expect("a file has a name")
                .to_string_lossy()
                .into_owned();
            found.insert(name, bytes);
        }
    }
    let stated = stated_count(if magic == pso::MAGIC {
        PSO_FIXTURE
    } else {
        FIXTURE
    });
    if found.len() != stated {
        refuse(
            test,
            &format!(
                "{} holds {} payloads beginning {}, and the fixture describes {stated}",
                root.display(),
                found.len(),
                String::from_utf8_lossy(&magic)
            ),
        );
    }
    found
}

fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    hex::encode(digest.finalize())
}

#[test]
#[cfg_attr(no_metadata, ignore = "RPF_METADATA is not set")]
fn every_shipped_rbf_file_round_trips_byte_for_byte() {
    let files = payloads(
        "every_shipped_rbf_file_round_trips_byte_for_byte",
        rbf::MAGIC,
    );
    let mut failed = Vec::new();
    for (name, original) in &files {
        match rbf::to_xml(original).and_then(|xml| rbf::from_xml(&xml)) {
            Ok(rebuilt) if rebuilt == *original => {}
            Ok(rebuilt) => {
                let at = rebuilt
                    .iter()
                    .zip(original)
                    .position(|(a, b)| a != b)
                    .unwrap_or(original.len().min(rebuilt.len()));
                failed.push(format!(
                    "{name}: differs at byte {at} ({} bytes in, {} out)",
                    original.len(),
                    rebuilt.len()
                ));
            }
            Err(error) => failed.push(format!("{name}: {error}")),
        }
    }
    assert!(
        failed.is_empty(),
        "{} of {} payloads did not round-trip:\n{}",
        failed.len(),
        files.len(),
        failed.join("\n")
    );
    eprintln!("{} RBF payloads round-tripped byte-for-byte", files.len());
}

#[test]
#[cfg_attr(no_metadata, ignore = "RPF_METADATA is not set")]
fn the_corpus_is_the_one_the_fixture_describes() {
    // The fixture records the `sha256` of every payload it describes.
    let files = payloads("the_corpus_is_the_one_the_fixture_describes", rbf::MAGIC);
    let fixture: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(FIXTURE).expect("fixture readable"))
            .expect("fixture parses");
    let described: BTreeSet<String> = fixture["sha256"]
        .as_array()
        .expect("sha256 is an array")
        .iter()
        .map(|digest| digest.as_str().expect("a digest is a string").to_owned())
        .collect();
    let present: BTreeSet<String> = files.values().map(|bytes| sha256(bytes)).collect();

    let missing: Vec<&String> = described.difference(&present).collect();
    let extra: Vec<&String> = present.difference(&described).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "the corpus is not the one the fixture describes: \
         {} described payloads absent, {} present payloads undescribed",
        missing.len(),
        extra.len()
    );
    assert_eq!(
        fixture["files"].as_u64(),
        Some(files.len() as u64),
        "the fixture counts a different number of payloads"
    );
}

#[test]
#[cfg_attr(no_metadata, ignore = "RPF_METADATA is not set")]
fn the_xml_is_readable_and_says_what_the_probe_measured() {
    // Every name is literal inline ASCII, and a blob keeps its trailing NUL.
    let files = payloads(
        "the_xml_is_readable_and_says_what_the_probe_measured",
        rbf::MAGIC,
    );
    let mut with_nul = 0usize;
    let mut without_nul = 0usize;
    for original in files.values() {
        let xml = rbf::to_xml(original).expect("a shipped payload converts");
        let text = str::from_utf8(&xml).expect("the XML is UTF-8");
        assert!(
            !text.contains("hash_"),
            "an RBF document has no hashes in it"
        );
        for line in text.lines() {
            if let Some(body) = line.split_once('>').map(|(_, rest)| rest)
                && body.contains("</")
            {
                if body.contains("\\x00<") {
                    with_nul += 1;
                } else {
                    without_nul += 1;
                }
            }
        }
    }
    assert_eq!(
        (with_nul, without_nul),
        (42_366, 5_676),
        "docs/metadata-encodings.md: 42,366 of 48,042 blobs end in NUL and 5,676 do not"
    );
}

/// A minimal valid payload, built by hand rather than by the writer under test.
fn minimal() -> Vec<u8> {
    let mut out = rbf::MAGIC.to_vec();
    out.extend_from_slice(&[0x00, 0x00]); // descriptor 0, open element
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(b"Root");
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // unk1, unk2, attrCount
    out.extend_from_slice(&[0xFF, 0xFF]); // close
    out
}

/// The `cause` of a [`Error::BadRbf`], or a panic naming what was got instead.
fn malformed(payload: &[u8]) -> rbf::Malformed {
    match rbf::to_xml(payload) {
        Err(Error::BadRbf { cause, .. }) => cause,
        other => panic!("expected a malformed RBF, got {other:?}"),
    }
}

/// The `cause` of a [`Error::UnrepresentableRbf`].
fn unrepresentable(payload: &[u8]) -> rbf::Unrepresentable {
    match rbf::to_xml(payload) {
        Err(Error::UnrepresentableRbf { cause }) => cause,
        other => panic!("expected an unrepresentable RBF, got {other:?}"),
    }
}

/// The `cause` of a [`Error::NotRbfXml`].
fn not_xml(document: &str) -> rbf::NotRbf {
    match rbf::from_xml(document.as_bytes()) {
        Err(Error::NotRbfXml { cause, .. }) => cause,
        other => panic!("expected XML that is not an RBF document, got {other:?}"),
    }
}

#[test]
fn the_minimal_payload_is_the_baseline_the_malformed_cases_are_mutations_of() {
    // Every malformed case below breaks this one payload in one way.
    let xml = rbf::to_xml(&minimal()).expect("the minimal payload converts");
    assert_eq!(
        str::from_utf8(&xml).expect("UTF-8"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Root/>\n"
    );
    assert_eq!(rbf::from_xml(&xml).expect("and back"), minimal());
}

#[test]
fn a_payload_that_is_not_rbf_is_refused_by_its_magic() {
    assert_eq!(malformed(b""), rbf::Malformed::NotRbf);
    assert_eq!(malformed(b"RBF"), rbf::Malformed::NotRbf);
    // The fourth byte is 0x30 in all 391 files, so the strict test costs nothing.
    assert_eq!(malformed(b"RBF1\x00\x00"), rbf::Malformed::NotRbf);
    assert_eq!(malformed(b"PSIN\x00\x00"), rbf::Malformed::NotRbf);
}

#[test]
fn a_truncated_token_stream_is_refused_at_every_length() {
    // Every prefix of a valid payload is an error, and none of them is a panic.
    let whole = minimal();
    for len in 4..whole.len() {
        let error = rbf::to_xml(&whole[..len]).expect_err("a prefix is not a document");
        assert_eq!(error.category(), Category::Corrupt, "at length {len}");
    }
    assert_eq!(
        malformed(&whole[..whole.len() - 1]),
        rbf::Malformed::Truncated
    );
}

#[test]
fn a_descriptor_index_past_the_end_of_the_table_is_refused() {
    let mut broken = minimal();
    broken[4] = 1; // the first record introduces descriptor 0, not descriptor 1
    assert_eq!(malformed(&broken), rbf::Malformed::DescriptorIndex);

    let mut absurd = minimal();
    absurd[4] = 0xFE; // the byte the table can never reach
    assert_eq!(malformed(&absurd), rbf::Malformed::DescriptorIndex);

    // And with a non-empty table, so the nearest name is not used instead.
    let mut past = minimal();
    past.truncate(past.len() - 2);
    past.extend_from_slice(&[5, 0x10]); // descriptor 5, of a table holding one
    past.extend_from_slice(&0u32.to_le_bytes());
    past.extend_from_slice(&[0xFF, 0xFF]);
    assert_eq!(malformed(&past), rbf::Malformed::DescriptorIndex);
}

#[test]
fn a_name_length_that_lies_is_refused() {
    let mut broken = minimal();
    broken[6..8].copy_from_slice(&0xFFFFu16.to_le_bytes());
    assert_eq!(malformed(&broken), rbf::Malformed::Truncated);
}

#[test]
fn a_blob_running_past_the_end_is_refused() {
    let mut payload = minimal();
    payload.truncate(payload.len() - 2); // drop the close record
    payload.extend_from_slice(&[0xFD, 0xFF]);
    payload.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    payload.extend_from_slice(b"short");
    payload.extend_from_slice(&[0xFF, 0xFF]);
    assert_eq!(malformed(&payload), rbf::Malformed::Truncated);
}

#[test]
fn a_name_that_is_not_utf8_is_refused() {
    let mut broken = minimal();
    broken[8..12].copy_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]);
    assert_eq!(
        unrepresentable(&broken),
        rbf::Unrepresentable::NameEncoding {
            name: vec![0xFF, 0xFE, 0xFD, 0xFC]
        }
    );
}

#[test]
fn a_name_that_is_not_an_xml_name_is_refused() {
    let mut broken = minimal();
    broken[8..12].copy_from_slice(b"1oot");
    assert_eq!(
        unrepresentable(&broken),
        rbf::Unrepresentable::NameSyntax {
            name: "1oot".to_owned()
        }
    );
}

#[test]
fn a_name_in_the_reserved_prefix_is_refused() {
    let mut broken = rbf::MAGIC.to_vec();
    broken.extend_from_slice(&[0x00, 0x00]);
    broken.extend_from_slice(&7u16.to_le_bytes());
    broken.extend_from_slice(b"rbf:xyz");
    broken.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    broken.extend_from_slice(&[0xFF, 0xFF]);
    assert_eq!(
        unrepresentable(&broken),
        rbf::Unrepresentable::NameReserved {
            name: "rbf:xyz".to_owned()
        }
    );
}

#[test]
fn a_data_type_outside_the_seven_is_refused() {
    // 281,272 records over 391 files, and no byte outside the table of seven.
    let mut payload = minimal();
    payload.truncate(payload.len() - 2);
    payload.extend_from_slice(&[0x01, 0x70]); // descriptor 1, type 0x70
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.extend_from_slice(b"x");
    payload.extend_from_slice(&[0xFF, 0xFF]);
    assert_eq!(malformed(&payload), rbf::Malformed::DataType);
}

#[test]
fn a_close_record_without_its_marker_is_refused() {
    let mut broken = minimal();
    let last = broken.len() - 1;
    broken[last] = 0x00;
    assert_eq!(malformed(&broken), rbf::Malformed::Marker);
}

#[test]
fn bytes_after_the_root_closes_are_refused() {
    // 0 trailing bytes in all 391 files, so a reader may insist on it.
    let mut payload = minimal();
    payload.push(0x00);
    assert_eq!(malformed(&payload), rbf::Malformed::Trailing);
}

#[test]
fn an_attribute_count_larger_than_the_element_holds_is_refused() {
    let mut broken = minimal();
    let len = broken.len();
    broken[len - 4..len - 2].copy_from_slice(&3u16.to_le_bytes());
    assert_eq!(malformed(&broken), rbf::Malformed::AttributeCount);
}

#[test]
fn an_empty_blob_is_refused_because_xml_cannot_show_one() {
    // 0 of the 48,042 corpus blobs are empty, and empty text is no text at all.
    let mut payload = minimal();
    payload.truncate(payload.len() - 2);
    payload.extend_from_slice(&[0xFD, 0xFF]);
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&[0xFF, 0xFF]);
    assert_eq!(unrepresentable(&payload), rbf::Unrepresentable::EmptyBlob);
}

#[test]
fn a_blob_sharing_its_element_is_refused() {
    // All 48,042 corpus blobs are the sole content of their element.
    let blob = |out: &mut Vec<u8>| {
        out.extend_from_slice(&[0xFD, 0xFF]);
        out.extend_from_slice(&1u32.to_le_bytes());
        out.push(b'x');
    };
    let child = |out: &mut Vec<u8>| {
        out.extend_from_slice(&[1, 0x00]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.push(b'c');
        out.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0xFF, 0xFF]);
    };
    for shape in [[0, 0], [0, 1], [1, 0]] {
        let mut payload = minimal();
        payload.truncate(payload.len() - 2);
        for step in shape {
            if step == 0 {
                blob(&mut payload);
            } else {
                child(&mut payload);
            }
        }
        payload.extend_from_slice(&[0xFF, 0xFF]);
        assert_eq!(
            unrepresentable(&payload),
            rbf::Unrepresentable::BlobNotAlone {
                name: "Root".to_owned()
            },
            "for {shape:?}"
        );
    }
}

#[test]
fn elements_nested_past_the_walk_limit_are_refused() {
    // A stack overflow is an abort no `Result` can catch, so depth is bounded.
    let mut payload = rbf::MAGIC.to_vec();
    payload.extend_from_slice(&[0x00, 0x00]);
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.extend_from_slice(b"a");
    payload.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for _ in 0..4096 {
        payload.extend_from_slice(&[0x00, 0x00, 0, 0, 0, 0, 0, 0]);
    }
    assert_eq!(malformed(&payload), rbf::Malformed::TooDeep);
}

#[test]
fn xml_that_is_not_well_formed_is_refused() {
    assert!(matches!(not_xml("<Root>"), rbf::NotRbf::Syntax { .. }));
    assert!(matches!(not_xml("<a></b>"), rbf::NotRbf::Syntax { .. }));
    assert_eq!(not_xml(""), rbf::NotRbf::Empty);
    assert_eq!(not_xml("<a/><b/>"), rbf::NotRbf::SecondRoot);
}

#[test]
fn xml_that_is_well_formed_and_says_the_wrong_thing_is_refused() {
    assert_eq!(
        not_xml("<a rbf:sideways=\"1\"/>"),
        rbf::NotRbf::UnknownReserved {
            name: "rbf:sideways".to_owned()
        }
    );
    assert_eq!(
        not_xml("<a rbf:uint=\"not a number\"/>"),
        rbf::NotRbf::BadValue {
            name: "rbf:uint".to_owned()
        }
    );
    assert_eq!(
        not_xml("<a rbf:uint=\"1\" b=\"c\"/>"),
        rbf::NotRbf::ValueNotAlone {
            name: "a".to_owned()
        }
    );
    assert_eq!(not_xml("<a rbf:uint=\"1\"/>"), rbf::NotRbf::RootNotElement);
    assert_eq!(not_xml("<a>text<b/></a>"), rbf::NotRbf::UnexpectedText);
    assert_eq!(not_xml("<a>\\q</a>"), rbf::NotRbf::BadEscape);
    assert_eq!(
        not_xml("<a rbf:string.b=\"c\"/>"),
        rbf::NotRbf::UnknownReserved {
            name: "rbf:string.b".to_owned()
        }
    );
}

#[test]
fn the_two_meaningless_words_survive_a_round_trip() {
    // The two words are 0 in every shipped element, and are carried anyway.
    let mut payload = minimal();
    payload[12..14].copy_from_slice(&7u16.to_le_bytes());
    payload[14..16].copy_from_slice(&9u16.to_le_bytes());
    let xml = rbf::to_xml(&payload).expect("converts");
    assert!(
        str::from_utf8(&xml)
            .expect("UTF-8")
            .contains("rbf:unknown=\"7 9\""),
        "the words are written down: {}",
        String::from_utf8_lossy(&xml)
    );
    assert_eq!(rbf::from_xml(&xml).expect("and back"), payload);
}

/// The minimal payload with one more child, whose descriptor is `new`: naming
/// the index past the table introduces one, naming an index it holds reuses it.
fn with_second_child(new: bool) -> Vec<u8> {
    let mut out = minimal();
    out.truncate(out.len() - 2); // the close, put back below
    for index in 1_u8..=2 {
        out.extend_from_slice(&[if new { index } else { 1 }, 0x10]); // a u32 value
        if new || index == 1 {
            out.extend_from_slice(&1u16.to_le_bytes());
            out.extend_from_slice(b"a");
        }
        out.extend_from_slice(&0u32.to_le_bytes());
    }
    out.extend_from_slice(&[0xFF, 0xFF]);
    out
}

#[test]
fn a_name_two_descriptors_declare_is_read_and_written_back_once() {
    // The reader accepts a name declared twice; the writer rebuilds the table
    // keyed by name alone, so the second declaration is a dropped duplicate.
    let twice = with_second_child(true);
    let once = with_second_child(false);
    assert_eq!(
        twice.len() - once.len(),
        3,
        "the second declaration is a two-byte length and a one-byte name"
    );

    // The document does not know the difference.
    let from_twice = rbf::to_xml(&twice).expect("converts");
    assert_eq!(from_twice, rbf::to_xml(&once).expect("converts"));

    // The payload does, which is what the round trip gives here.
    assert_eq!(rbf::from_xml(&from_twice).expect("and back"), once);
    assert_ne!(rbf::from_xml(&from_twice).expect("and back"), twice);

    // And normalising is a fixed point: the form the writer chose survives.
    let from_once = rbf::to_xml(&once).expect("converts");
    assert_eq!(rbf::from_xml(&from_once).expect("and back"), once);
}

#[test]
fn a_blob_that_is_only_whitespace_survives() {
    // Spaces are indentation everywhere else, so such a blob needs telling apart.
    let mut payload = minimal();
    payload.truncate(payload.len() - 2);
    payload.extend_from_slice(&[0xFD, 0xFF]);
    payload.extend_from_slice(&3u32.to_le_bytes());
    payload.extend_from_slice(b"   ");
    payload.extend_from_slice(&[0xFF, 0xFF]);
    let xml = rbf::to_xml(&payload).expect("converts");
    assert_eq!(rbf::from_xml(&xml).expect("and back"), payload);
}

#[test]
fn the_categories_are_the_ones_a_caller_acts_on() {
    // A corrupt payload, an unsupported rendering, and a refused document.
    assert_eq!(
        rbf::to_xml(b"nope").expect_err("not RBF").category(),
        Category::Corrupt
    );
    let mut unrenderable = minimal();
    unrenderable[8..12].copy_from_slice(b"1oot");
    assert_eq!(
        rbf::to_xml(&unrenderable)
            .expect_err("not a name")
            .category(),
        Category::Unsupported
    );
    assert_eq!(
        rbf::from_xml(b"<").expect_err("not XML").category(),
        Category::Refused
    );
}

#[test]
#[cfg_attr(no_metadata, ignore = "RPF_METADATA is not set")]
fn every_shipped_pso_file_converts_from_its_own_schema_alone() {
    let files = payloads(
        "every_shipped_pso_file_converts_from_its_own_schema_alone",
        pso::MAGIC,
    );
    let names = Dictionary::default();
    let mut failed = Vec::new();
    for (name, payload) in &files {
        if let Err(error) = pso::to_xml(payload, &names) {
            failed.push(format!("{name}: {error:?}"));
        }
    }
    assert!(
        failed.is_empty(),
        "{} of {} payloads did not convert, so the walk from each file's own \
         PSCH does not reach only what that file defines:\n{}",
        failed.len(),
        files.len(),
        failed
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The name hash of the one structure [`minimal_pso`] defines.
const ROOT_NAME: u32 = 0xD98B_B561;

/// The name hash of its one member.
const MEMBER_NAME: u32 = 0x1234_5678;

/// The `ARRAYINFO` sentinel: the name hash a member carries when it describes
/// another member's element type rather than a field of its own.
const ARRAYINFO: u32 = 0x0000_0100;

/// A minimal valid `PSO`: one block, one structure, one `UINT` member, built by
/// hand so it shares no bug with the reader. Every case below mutates it.
fn minimal_pso() -> Vec<u8> {
    let mut psin = Vec::new();
    psin.extend_from_slice(&pso::MAGIC);
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

/// The `cause` of an [`Error::BadPso`], or a panic naming what was got instead.
fn pso_malformed(payload: &[u8]) -> pso::Malformed {
    match pso::to_xml(payload, &Dictionary::default()) {
        Err(Error::BadPso { cause, .. }) => cause,
        other => panic!("expected a malformed PSO, got {other:?}"),
    }
}

/// The XML a payload converts to, as text.
fn pso_xml(payload: &[u8]) -> String {
    let bytes = pso::to_xml(payload, &Dictionary::default()).expect("converts");
    String::from_utf8(bytes).expect("the XML is UTF-8")
}

#[test]
fn the_minimal_pso_is_the_baseline_the_malformed_cases_are_mutations_of() {
    assert_eq!(
        pso_xml(&minimal_pso()),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <hash_D98BB561 pso:struct=\"hash_D98BB561\">\n  \
         <hash_12345678 pso:uint=\"7\"/>\n\
         </hash_D98BB561>\n"
    );
}

#[test]
fn a_payload_that_is_not_pso_is_refused_by_its_first_section_tag() {
    assert_eq!(pso_malformed(b""), pso::Malformed::NotPso);
    assert_eq!(
        pso_malformed(b"RBF0\x00\x00\x00\x08"),
        pso::Malformed::NotPso
    );
    // The other seven tags are sections *inside* a file and never begin one.
    assert_eq!(
        pso_malformed(b"PMAP\x00\x00\x00\x08"),
        pso::Malformed::NotPso
    );
}

#[test]
fn a_truncated_payload_is_refused_at_every_length() {
    // Every prefix of a valid payload is an error, and none of them is a panic.
    let whole = minimal_pso();
    for len in 0..whole.len() {
        let error = pso::to_xml(&whole[..len], &Dictionary::default())
            .expect_err("a prefix is not a whole file");
        assert!(
            matches!(error.category(), Category::Corrupt | Category::Unsupported),
            "at length {len}: {error:?}"
        );
    }
}

#[test]
fn a_section_length_that_overruns_the_payload_is_refused() {
    let mut broken = minimal_pso();
    broken[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(pso_malformed(&broken), pso::Malformed::Section);
}

#[test]
fn a_section_chain_that_does_not_reach_the_end_is_refused() {
    // Σ(section lengths) == file length in 9,753 of 9,753, so no file trails.
    let mut trailing = minimal_pso();
    trailing.push(0);
    assert_eq!(pso_malformed(&trailing), pso::Malformed::Section);
}

#[test]
fn a_block_that_is_not_inside_the_data_section_is_refused() {
    // The block table is checked against the data section at construction.
    let mut past = minimal_pso();
    let length_at = 20 + 8 + 4 + 2 + 2 + 12;
    past[length_at..length_at + 4].copy_from_slice(&4096i32.to_be_bytes());
    assert_eq!(pso_malformed(&past), pso::Malformed::BlockRange);

    let mut negative = minimal_pso();
    let offset_at = 20 + 8 + 4 + 2 + 2 + 4;
    negative[offset_at..offset_at + 4].copy_from_slice(&(-1i32).to_be_bytes());
    assert_eq!(pso_malformed(&negative), pso::Malformed::BlockRange);
}

#[test]
fn a_root_id_that_names_no_block_is_refused() {
    for id in [0i32, 2, -1, i32::MAX] {
        let mut broken = minimal_pso();
        broken[28..32].copy_from_slice(&id.to_be_bytes());
        assert_eq!(
            pso_malformed(&broken),
            pso::Malformed::RootId,
            "rootId {id}"
        );
    }
}

#[test]
fn a_structure_the_file_does_not_define_is_refused_rather_than_guessed_at() {
    // A walk from a file's own `PSCH` reaches 0 undefined references in 9,753.
    let mut unknown = minimal_pso();
    unknown[20 + 8 + 4 + 2 + 2..20 + 8 + 4 + 2 + 2 + 4]
        .copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    assert_eq!(pso_malformed(&unknown), pso::Malformed::UndefinedStructure);
}

#[test]
fn a_member_type_this_build_does_not_decode_is_unsupported_not_corrupt() {
    // 37 (type, subtype) pairs over 580,044 members: outside them is a gap here.
    let mut alien = minimal_pso();
    let type_at = minimal_pso().len() - 8;
    alien[type_at] = 0x7F;
    let error = pso::to_xml(&alien, &Dictionary::default()).expect_err("not decodable");
    assert_eq!(error.category(), Category::Unsupported);
    assert!(matches!(
        error,
        Error::UnsupportedPso {
            cause: pso::Unsupported::DataType {
                code: 0x7F,
                subtype: 0
            }
        }
    ));
}

#[test]
fn a_document_is_bounded_in_bytes_and_not_only_in_elements() {
    // No node budget can be the memory bound: an element is not a fixed number
    // of bytes, since it carries two spaces of indent per level of depth.
    let payload = nested_arrays_pso(u16::MAX);
    let error =
        pso::to_xml(&payload, &Dictionary::default()).expect_err("a document this size is refused");
    assert!(
        matches!(
            error,
            Error::BadPso {
                cause: pso::Malformed::TooLarge,
                ..
            }
        ),
        "the output budget is what catches it: {error:?}"
    );
    assert_eq!(error.category(), Category::Corrupt);

    // The bound is on the document, not the shape: one size down is inside it.
    let xml = pso_xml(&nested_arrays_pso(64));
    assert!(
        xml.len() <= 16 * 1024 * 1024,
        "a converted document is inside the floor: {} bytes",
        xml.len()
    );
}

#[test]
fn a_cyclic_block_graph_is_refused_rather_than_walked_forever() {
    // A pointer back into its own block is a cycle; the depth limit is the guard.
    let payload = cyclic_pso();
    let error = pso::to_xml(&payload, &Dictionary::default()).expect_err("a cycle is refused");
    assert_eq!(error.category(), Category::Corrupt);
    assert!(
        matches!(
            error,
            Error::BadPso {
                cause: pso::Malformed::TooDeep,
                ..
            }
        ),
        "the depth ceiling is what catches it, before the node budget: {error:?}"
    );
}

#[test]
fn an_inline_array_of_inline_arrays_is_refused_by_the_output_budget() {
    // Three levels deep and declaring its size rather than nesting to it:
    // 2.8*10^14 elements out of 132 bytes, every item at the same address.
    let payload = nested_arrays_pso(u16::MAX);
    assert_eq!(payload.len(), 132);
    let error = pso::to_xml(&payload, &Dictionary::default()).expect_err("a budget refuses it");
    assert_eq!(error.category(), Category::Corrupt);
    assert!(
        matches!(
            error,
            Error::BadPso {
                cause: pso::Malformed::TooLarge,
                ..
            }
        ),
        "a budget is what catches it, not the depth ceiling: {error:?}"
    );
}

#[test]
fn an_array_charges_its_items_against_the_same_budget_a_structure_charges() {
    // Every element the walk writes is charged, so one size smaller finishes.
    let ok = nested_arrays_pso(64);
    let xml = pso_xml(&ok);
    assert_eq!(
        xml.matches("<pso:item").count(),
        64 + 64 * 64 + 64 * 64 * 64,
        "every item of every level is written, and every one of them is charged"
    );
    // Both budgets are charged, and the one in bytes reaches its ceiling first.
    assert!(matches!(
        pso::to_xml(&nested_arrays_pso(200), &Dictionary::default()),
        Err(Error::BadPso {
            cause: pso::Malformed::TooLarge,
            ..
        })
    ));
}

/// A payload whose one field is an inline array of an inline array of an inline
/// array, each `count` long; members 1, 2 and 3 are `ARRAYINFO` descriptors, so
/// the size is entirely in what the schema declares.
fn nested_arrays_pso(count: u16) -> Vec<u8> {
    let mut psin = Vec::new();
    psin.extend_from_slice(&pso::MAGIC);
    psin.extend_from_slice(&20u32.to_be_bytes());
    psin.extend_from_slice(b"pppppppp");
    psin.extend_from_slice(&0u32.to_be_bytes());

    let mut pmap = Vec::new();
    pmap.extend_from_slice(b"PMAP");
    pmap.extend_from_slice(&32u32.to_be_bytes());
    pmap.extend_from_slice(&1i32.to_be_bytes());
    pmap.extend_from_slice(&1i16.to_be_bytes());
    pmap.extend_from_slice(&0x7070u16.to_be_bytes());
    pmap.extend_from_slice(&ROOT_NAME.to_be_bytes());
    pmap.extend_from_slice(&16i32.to_be_bytes());
    pmap.extend_from_slice(&0i32.to_be_bytes());
    pmap.extend_from_slice(&4i32.to_be_bytes());

    let mut psch = Vec::new();
    psch.extend_from_slice(b"PSCH");
    psch.extend_from_slice(&80u32.to_be_bytes());
    psch.extend_from_slice(&1u32.to_be_bytes());
    psch.extend_from_slice(&ROOT_NAME.to_be_bytes());
    psch.extend_from_slice(&20i32.to_be_bytes());
    psch.extend_from_slice(&4u32.to_be_bytes()); // structure, four members
    psch.extend_from_slice(&4i32.to_be_bytes());
    psch.extend_from_slice(&0u32.to_be_bytes());
    // The field, and two descriptors that each describe another array.
    for (name, element) in [(MEMBER_NAME, 1u32), (ARRAYINFO, 2), (ARRAYINFO, 3)] {
        psch.extend_from_slice(&name.to_be_bytes());
        psch.extend_from_slice(&[0x0D, 0x01]); // ARRAY, ATFIXEDARRAY
        psch.extend_from_slice(&0u16.to_be_bytes());
        psch.extend_from_slice(&((u32::from(count) << 16) | element).to_be_bytes());
    }
    // The last descriptor: a zero-length inline string, so the stride is 0.
    psch.extend_from_slice(&ARRAYINFO.to_be_bytes());
    psch.extend_from_slice(&[0x0B, 0x00]); // STRING, MEMBER
    psch.extend_from_slice(&0u16.to_be_bytes());
    psch.extend_from_slice(&0u32.to_be_bytes());

    let mut payload = psin;
    payload.extend_from_slice(&pmap);
    payload.extend_from_slice(&psch);
    payload
}

/// A payload whose one structure holds a pointer into its own block.
fn cyclic_pso() -> Vec<u8> {
    let mut psin = Vec::new();
    psin.extend_from_slice(&pso::MAGIC);
    psin.extend_from_slice(&24u32.to_be_bytes());
    psin.extend_from_slice(b"pppppppp");
    // A pointer to block 1, item offset 0 — which is this very structure.
    psin.extend_from_slice(&1u32.to_be_bytes());
    psin.extend_from_slice(&0u32.to_be_bytes());

    let mut pmap = Vec::new();
    pmap.extend_from_slice(b"PMAP");
    pmap.extend_from_slice(&32u32.to_be_bytes());
    pmap.extend_from_slice(&1i32.to_be_bytes());
    pmap.extend_from_slice(&1i16.to_be_bytes());
    pmap.extend_from_slice(&0x7070u16.to_be_bytes());
    pmap.extend_from_slice(&ROOT_NAME.to_be_bytes());
    pmap.extend_from_slice(&16i32.to_be_bytes());
    pmap.extend_from_slice(&0i32.to_be_bytes());
    pmap.extend_from_slice(&8i32.to_be_bytes());

    let mut psch = Vec::new();
    psch.extend_from_slice(b"PSCH");
    psch.extend_from_slice(&44u32.to_be_bytes());
    psch.extend_from_slice(&1u32.to_be_bytes());
    psch.extend_from_slice(&ROOT_NAME.to_be_bytes());
    psch.extend_from_slice(&20i32.to_be_bytes());
    psch.extend_from_slice(&1u32.to_be_bytes());
    psch.extend_from_slice(&8i32.to_be_bytes());
    psch.extend_from_slice(&0u32.to_be_bytes());
    psch.extend_from_slice(&MEMBER_NAME.to_be_bytes());
    psch.extend_from_slice(&[0x0C, 0x03]); // STRUCT, POINTER
    psch.extend_from_slice(&0u16.to_be_bytes());
    psch.extend_from_slice(&0u32.to_be_bytes());

    let mut payload = psin;
    payload.extend_from_slice(&pmap);
    payload.extend_from_slice(&psch);
    payload
}

#[test]
fn a_pointer_outside_its_own_block_is_refused_rather_than_recovered() {
    // 0 of 1,362,769 corpus pointers are out of range, so one is refused.
    let mut broken = cyclic_pso();
    // Block 1 is eight bytes long; item offset 16 is past its end.
    let pointer = (16u32 << 12) | 1;
    broken[16..20].copy_from_slice(&pointer.to_be_bytes());
    assert_eq!(pso_malformed(&broken), pso::Malformed::Pointer);

    // And a block id the table does not hold.
    let mut absent = cyclic_pso();
    absent[16..20].copy_from_slice(&9u32.to_be_bytes());
    assert_eq!(pso_malformed(&absent), pso::Malformed::Pointer);
}

#[test]
fn a_member_reaching_past_the_data_section_is_refused() {
    // A structure's length and a member's offset are both attacker-chosen.
    let mut past = minimal_pso();
    let offset_at = minimal_pso().len() - 6;
    past[offset_at..offset_at + 2].copy_from_slice(&40000u16.to_be_bytes());
    assert_eq!(pso_malformed(&past), pso::Malformed::DataRange);
}

#[test]
fn an_array_whose_element_index_is_not_an_arrayinfo_member_is_refused() {
    // The `0xFFFF` mask alone gives a valid index in 64,906 of 64,906.
    let mut array = minimal_pso();
    let type_at = minimal_pso().len() - 8;
    array[type_at] = 0x0D; // ARRAY
    array[type_at + 1] = 0x00; // ATARRAY
    // referenceKey's low half indexes a member, and member 0 is this one.
    assert_eq!(pso_malformed(&array), pso::Malformed::ArrayInfo);
}

#[test]
fn a_vector3_is_sixteen_bytes_carrying_three_floats_and_not_twelve() {
    // A single `VECTOR3` shows no difference, so this is an inline array of
    // two, where the size is the stride: at twelve the second reads padding.
    let xml = pso_xml(&vector3_array_pso());
    let items: Vec<&str> = xml
        .match_indices("pso:float3=\"")
        .map(|(at, _)| {
            let rest = &xml[at + "pso:float3=\"".len()..];
            &rest[..rest.find('"').expect("the attribute closes")]
        })
        .collect();
    assert_eq!(items, ["1.0, 2.0, 3.0", "4.0, 5.0, 6.0"], "{xml}");
}

/// A payload whose one field is an inline array of two `VECTOR3`s, laid out
/// sixteen bytes apart.
fn vector3_array_pso() -> Vec<u8> {
    let mut psin = Vec::new();
    psin.extend_from_slice(&pso::MAGIC);
    psin.extend_from_slice(&48u32.to_be_bytes());
    psin.extend_from_slice(b"pppppppp");
    for lane in [1.0f32, 2.0, 3.0, 0.0, 4.0, 5.0, 6.0, 0.0] {
        psin.extend_from_slice(&lane.to_be_bytes());
    }

    let mut pmap = Vec::new();
    pmap.extend_from_slice(b"PMAP");
    pmap.extend_from_slice(&32u32.to_be_bytes());
    pmap.extend_from_slice(&1i32.to_be_bytes());
    pmap.extend_from_slice(&1i16.to_be_bytes());
    pmap.extend_from_slice(&0x7070u16.to_be_bytes());
    pmap.extend_from_slice(&ROOT_NAME.to_be_bytes());
    pmap.extend_from_slice(&16i32.to_be_bytes());
    pmap.extend_from_slice(&0i32.to_be_bytes());
    pmap.extend_from_slice(&32i32.to_be_bytes());

    let mut psch = Vec::new();
    psch.extend_from_slice(b"PSCH");
    psch.extend_from_slice(&56u32.to_be_bytes());
    psch.extend_from_slice(&1u32.to_be_bytes());
    psch.extend_from_slice(&ROOT_NAME.to_be_bytes());
    psch.extend_from_slice(&20i32.to_be_bytes());
    psch.extend_from_slice(&2u32.to_be_bytes()); // structure, two members
    psch.extend_from_slice(&32i32.to_be_bytes()); // two sixteen-byte vectors
    psch.extend_from_slice(&0u32.to_be_bytes());
    psch.extend_from_slice(&MEMBER_NAME.to_be_bytes());
    psch.extend_from_slice(&[0x0D, 0x01]); // ARRAY, ATFIXEDARRAY
    psch.extend_from_slice(&0u16.to_be_bytes());
    psch.extend_from_slice(&((2u32 << 16) | 1).to_be_bytes());
    psch.extend_from_slice(&ARRAYINFO.to_be_bytes());
    psch.extend_from_slice(&[0x09, 0x00]); // VECTOR3
    psch.extend_from_slice(&0u16.to_be_bytes());
    psch.extend_from_slice(&0u32.to_be_bytes());

    let mut payload = psin;
    payload.extend_from_slice(&pmap);
    payload.extend_from_slice(&psch);
    payload
}

#[test]
fn a_payload_missing_a_section_the_walk_needs_is_refused() {
    // The chain is well formed; the block table and the schema are absent.
    let payload = minimal_pso();
    let psin_only = &payload[..20];
    assert_eq!(pso_malformed(psin_only), pso::Malformed::MissingSection);
}

#[test]
fn a_section_too_short_for_its_own_header_is_refused() {
    // A section's own header has to fit inside the length it declared.
    let mut payload = minimal_pso();
    let psch = payload
        .windows(4)
        .position(|word| word == b"PSCH")
        .expect("the schema section");
    payload.truncate(psch + 8);
    payload[psch + 4..psch + 8].copy_from_slice(&8u32.to_be_bytes());
    assert_eq!(pso_malformed(&payload), pso::Malformed::SectionTruncated);
}

#[test]
fn a_schema_entry_that_is_neither_a_structure_nor_an_enum_is_refused() {
    // The packed word's top byte is 0 for a structure and 1 for an enum.
    let mut payload = minimal_pso();
    let packed = payload.len() - 24;
    payload[packed..packed + 4].copy_from_slice(&0x0200_0001u32.to_be_bytes());
    assert_eq!(pso_malformed(&payload), pso::Malformed::SchemaEntry);
}

#[test]
fn a_structure_whose_declared_length_is_negative_is_refused() {
    // `structureLength` is an `i32` in the format and a `u32` everywhere here.
    let mut payload = minimal_pso();
    let length = payload.len() - 20;
    payload[length..length + 4].copy_from_slice(&(-1i32).to_be_bytes());
    assert_eq!(pso_malformed(&payload), pso::Malformed::StructureLength);
}

#[test]
#[cfg_attr(no_metadata, ignore = "RPF_METADATA is not set")]
fn every_document_the_corpus_produces_is_well_formed_xml() {
    // The conversion writes XML by hand rather than through a serialiser.
    let files = payloads(
        "every_document_the_corpus_produces_is_well_formed_xml",
        pso::MAGIC,
    );
    let names = Dictionary::default();
    for (name, payload) in &files {
        let xml = pso::to_xml(payload, &names).expect("a shipped payload converts");
        let mut reader = quick_xml::Reader::from_reader(xml.as_slice());
        let mut buffer = Vec::new();
        loop {
            match reader.read_event_into(&mut buffer) {
                Ok(quick_xml::events::Event::Eof) => break,
                Ok(_) => {}
                Err(error) => panic!("{name} produced XML that does not parse: {error}"),
            }
            buffer.clear();
        }
    }
}

#[test]
#[cfg_attr(no_metadata, ignore = "RPF_METADATA is not set")]
fn a_dictionary_changes_the_spelling_and_never_the_shape() {
    let files = payloads(
        "a_dictionary_changes_the_spelling_and_never_the_shape",
        pso::MAGIC,
    );
    let loaded = Dictionary::load(NAMES_THAT_OCCUR);
    assert!(loaded.rejected.is_empty(), "{:?}", loaded.rejected);
    let bare = Dictionary::default();
    let mut resolved = 0usize;
    for payload in files.values() {
        let plain = pso::to_xml(payload, &bare).expect("converts");
        let named = pso::to_xml(payload, &loaded.dictionary).expect("converts");
        let shape = |xml: &[u8]| {
            String::from_utf8_lossy(xml)
                .lines()
                .map(|line| {
                    (
                        line.len() - line.trim_start().len(),
                        line.matches('<').count(),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(shape(&plain), shape(&named));
        if plain != named {
            resolved = resolved.saturating_add(1);
        }
    }
    assert!(
        resolved > 0,
        "the dictionary resolved nothing, so this test proves nothing"
    );
    eprintln!("{resolved} of {} documents changed spelling", files.len());
}

/// Names measured to occur in the corpus, and not a shipped dictionary.
const NAMES_THAT_OCCUR: &str = "\
CMapTypes
CBaseArchetypeDef
CExtensionDefSpawnPoint
CPackFileMetaData
CCreatureMetaData
Item
Key
name
lodDist
flags
bbMin
bbMax
bsCentre
bsRadius
archetypes
extensions
textureDictionary
physicsDictionary
";

#[test]
#[cfg_attr(no_metadata, ignore = "RPF_METADATA is not set")]
fn every_name_the_corpus_renders_reads_back_to_the_hash_it_came_from() {
    // Whatever a name is spelled as, it names the same `u32` on the way back.
    let files = payloads(
        "every_name_the_corpus_renders_reads_back_to_the_hash_it_came_from",
        pso::MAGIC,
    );
    let loaded = Dictionary::load(NAMES_THAT_OCCUR);
    let mut names = 0usize;
    for payload in files.values() {
        let xml = pso::to_xml(payload, &loaded.dictionary).expect("converts");
        for line in String::from_utf8_lossy(&xml).lines() {
            let Some(tag) = line.trim_start().strip_prefix('<') else {
                continue;
            };
            let tag = tag.trim_start_matches('/');
            let tag = tag.split([' ', '>', '/']).next().unwrap_or_default();
            if tag.is_empty() || tag.starts_with("pso:") || tag.starts_with('?') {
                continue;
            }
            let recovered = hash::unplaceholder(tag).unwrap_or_else(|| joaat(tag.as_bytes()));
            assert_eq!(
                loaded.dictionary.render(recovered),
                tag,
                "{tag} does not read back to the hash it was written for"
            );
            names = names.saturating_add(1);
        }
    }
    assert!(names > 0, "no names were checked");
    eprintln!("{names} rendered names read back to their own hash");
}

#[test]
#[cfg_attr(no_metadata, ignore = "RPF_METADATA is not set")]
fn the_two_cases_the_document_called_undecodable_decode() {
    // Two cases the census once called undecodable both decode. A reader that
    // trusted the wrapped `dataOffset` would render `0.0, 0.0, 0.0` here.
    let files = payloads(
        "the_two_cases_the_document_called_undecodable_decode",
        pso::MAGIC,
    );
    let names = Dictionary::default();
    let mut wrapped = 0usize;
    let mut recovered = 0usize;
    let mut with_maps = 0usize;
    let mut map_instances = 0usize;
    for payload in files.values() {
        let xml = pso::to_xml(payload, &names).expect("converts");
        let text = String::from_utf8_lossy(&xml);
        if text.contains("pso:array=\"wrapped\"") {
            wrapped = wrapped.saturating_add(1);
            if text.contains("57.5, -729.5, 43.25") {
                recovered = recovered.saturating_add(1);
            }
        }
        let maps = text.matches("pso:map=\"atbinarymap\">").count();
        if maps > 0 {
            with_maps = with_maps.saturating_add(1);
        }
        map_instances = map_instances.saturating_add(maps);
    }
    assert_eq!(
        (wrapped, recovered),
        (4, 4),
        "the four `junctions.pso` copies each recover their wrapped offset"
    );
    assert_eq!(
        (with_maps, map_instances),
        (26, 8_286),
        "26 files carry an ATBINARYMAP, and 8,286 instances of one are not empty"
    );
}

/// What the committed `PSO` fixture describes.
const PSO_FIXTURE: &str = "../../fixtures/pso-metadata.json";

#[test]
#[cfg_attr(no_metadata, ignore = "RPF_METADATA is not set")]
fn the_pso_corpus_is_the_one_the_fixture_describes() {
    // The fixture holds one `sha256` of the sorted per-payload digests.
    let files = payloads(
        "the_pso_corpus_is_the_one_the_fixture_describes",
        pso::MAGIC,
    );
    let fixture: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(PSO_FIXTURE).expect("fixture readable"))
            .expect("fixture parses");

    let mut digests: Vec<String> = files.values().map(|bytes| sha256(bytes)).collect();
    digests.sort();
    let rollup = sha256(digests.join("\n").as_bytes());

    assert_eq!(
        fixture["files"].as_u64(),
        Some(files.len() as u64),
        "the fixture counts a different number of payloads"
    );
    assert_eq!(
        fixture["bytes"].as_u64(),
        Some(files.values().map(|bytes| bytes.len() as u64).sum::<u64>()),
        "the fixture describes a different number of bytes"
    );
    assert_eq!(
        fixture["sha256_of_sorted_sha256_lines"].as_str(),
        Some(rollup.as_str()),
        "the corpus is not the one the fixture describes"
    );
}

#[test]
#[cfg_attr(no_metadata, ignore = "RPF_METADATA is not set")]
fn the_section_census_the_document_states_is_what_the_corpus_has() {
    // The eight tags, their counts, and Σ(section lengths) == file length.
    let files = payloads(
        "the_section_census_the_document_states_is_what_the_corpus_has",
        pso::MAGIC,
    );
    let fixture: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(PSO_FIXTURE).expect("fixture readable"))
            .expect("fixture parses");
    let stated = fixture["sections"]
        .as_object()
        .expect("the fixture lists sections");

    let mut seen: BTreeMap<String, u64> = BTreeMap::new();
    for payload in files.values() {
        let mut at = 0usize;
        while at < payload.len() {
            let tag = String::from_utf8_lossy(&payload[at..at + 4]).into_owned();
            let length = u32::from_be_bytes(payload[at + 4..at + 8].try_into().expect("four bytes"))
                as usize;
            *seen.entry(tag).or_default() += 1;
            at += length;
        }
        assert_eq!(
            at,
            payload.len(),
            "the section chain lands exactly on the end of the file"
        );
    }
    for (tag, count) in &seen {
        assert_eq!(
            stated.get(tag).and_then(serde_json::Value::as_u64),
            Some(*count),
            "the corpus carries {count} {tag} sections"
        );
    }
    assert_eq!(seen.len(), stated.len(), "there is no ninth section tag");
}

/// [`minimal_pso`] with its one member re-typed, and its four bytes of data
/// replaced.
fn retyped_pso(code: u8, subtype: u8, reference: u32, data: [u8; 4]) -> Vec<u8> {
    let mut payload = minimal_pso();
    let len = payload.len();
    payload[16..20].copy_from_slice(&data);
    payload[len - 8] = code;
    payload[len - 7] = subtype;
    payload[len - 4..len].copy_from_slice(&reference.to_be_bytes());
    payload
}

/// The value of the one attribute the minimal payload's member renders with.
fn only_value(payload: &[u8], names: &Dictionary) -> String {
    let xml = String::from_utf8(pso::to_xml(payload, names).expect("converts")).expect("UTF-8");
    let line = xml
        .lines()
        .find(|line| line.contains("hash_12345678"))
        .unwrap_or_default()
        .to_owned();
    line.split('"').nth(1).unwrap_or_default().to_owned()
}

#[test]
fn a_fixed_inline_string_stops_at_its_first_nul() {
    // The bytes after a fixed array's terminator are whatever the packer left.
    let payload = retyped_pso(0x0B, 0, 4 << 16, *b"ab\0Z");
    assert_eq!(only_value(&payload, &Dictionary::default()), "ab");
}

#[test]
fn a_null_pointer_is_written_down_rather_than_written_as_empty() {
    // An absent string and an empty one differ, and XML cannot tell them apart.
    let payload = retyped_pso(0x0B, 1, 0, [0, 0, 0, 0]);
    let xml = String::from_utf8(pso::to_xml(&payload, &Dictionary::default()).expect("converts"))
        .expect("UTF-8");
    assert!(
        xml.contains("<hash_12345678 pso:null=\"string.pointer\"/>"),
        "{xml}"
    );
}

#[test]
fn a_hashed_string_is_spelled_by_the_dictionary_and_re_reads_to_its_hash() {
    // 1,120,606 rendered values across the corpus are `u32`s.
    let payload = retyped_pso(0x0B, 7, 0, joaat(b"CMapTypes").to_be_bytes());
    assert_eq!(
        only_value(&payload, &Dictionary::default()),
        "hash_D98BB561"
    );
    let loaded = Dictionary::load("CMapTypes");
    let spelled = only_value(&payload, &loaded.dictionary);
    assert_eq!(spelled, "CMapTypes");
    assert_eq!(joaat(spelled.as_bytes()), 0xD98B_B561);

    // An entry that does not hash to its own key never reaches the document.
    let lying = Dictionary::load("D98BB561 CMapTypes_");
    assert_eq!(lying.rejected.len(), 1);
    assert_eq!(only_value(&payload, &lying.dictionary), "hash_D98BB561");
}

#[test]
fn a_bitset_names_the_bits_its_own_enum_names_and_numbers_the_rest() {
    // A `BITSET`'s `referenceKey` is `(bitCount << 16) | memberIndex`, and an
    // entry key is the bit index, never an enum hash.
    let payload = bitset_pso();
    assert_eq!(
        only_value(&payload, &Dictionary::default()),
        "hash_AF085554 3"
    );
}

/// A payload whose one field is a `BITSET` resolving through an `ARRAYINFO`
/// member of type `ENUM`, with bits 1 and 3 set and only bit 1 named.
fn bitset_pso() -> Vec<u8> {
    const ENUM_NAME: u32 = 0x0BAD_F00D;
    let mut psin = Vec::new();
    psin.extend_from_slice(&pso::MAGIC);
    psin.extend_from_slice(&20u32.to_be_bytes());
    psin.extend_from_slice(b"pppppppp");
    psin.extend_from_slice(&0b1010u32.to_be_bytes());

    let mut pmap = Vec::new();
    pmap.extend_from_slice(b"PMAP");
    pmap.extend_from_slice(&32u32.to_be_bytes());
    pmap.extend_from_slice(&1i32.to_be_bytes());
    pmap.extend_from_slice(&1i16.to_be_bytes());
    pmap.extend_from_slice(&0x7070u16.to_be_bytes());
    pmap.extend_from_slice(&ROOT_NAME.to_be_bytes());
    pmap.extend_from_slice(&16i32.to_be_bytes());
    pmap.extend_from_slice(&0i32.to_be_bytes());
    pmap.extend_from_slice(&4i32.to_be_bytes());

    // Two `PSCH` entries: the structure, and the enum its bitset resolves to.
    let mut psch = Vec::new();
    psch.extend_from_slice(b"PSCH");
    psch.extend_from_slice(&76u32.to_be_bytes());
    psch.extend_from_slice(&2u32.to_be_bytes());
    psch.extend_from_slice(&ROOT_NAME.to_be_bytes());
    psch.extend_from_slice(&28i32.to_be_bytes());
    psch.extend_from_slice(&ENUM_NAME.to_be_bytes());
    psch.extend_from_slice(&64i32.to_be_bytes());
    // The structure: two members, the `ARRAYINFO` enum descriptor and the field.
    psch.extend_from_slice(&2u32.to_be_bytes());
    psch.extend_from_slice(&4i32.to_be_bytes());
    psch.extend_from_slice(&0u32.to_be_bytes());
    psch.extend_from_slice(&ARRAYINFO.to_be_bytes());
    psch.extend_from_slice(&[0x0E, 0x00]); // ENUM, _32BIT
    psch.extend_from_slice(&0u16.to_be_bytes());
    psch.extend_from_slice(&ENUM_NAME.to_be_bytes());
    psch.extend_from_slice(&MEMBER_NAME.to_be_bytes());
    psch.extend_from_slice(&[0x0F, 0x00]); // BITSET, _32BIT
    psch.extend_from_slice(&0u16.to_be_bytes());
    psch.extend_from_slice(&(32u32 << 16).to_be_bytes()); // 32 bits, member 0
    // The enum: one entry, naming bit 1.
    psch.extend_from_slice(&0x0100_0001u32.to_be_bytes()); // kind 1, one entry
    psch.extend_from_slice(&0xAF08_5554u32.to_be_bytes()); // joaat("32BIT")
    psch.extend_from_slice(&1i32.to_be_bytes());

    let mut payload = psin;
    payload.extend_from_slice(&pmap);
    payload.extend_from_slice(&psch);
    payload
}

#[test]
#[cfg_attr(no_metadata, ignore = "RPF_METADATA is not set")]
fn every_shipped_pso_file_round_trips_byte_for_byte() {
    // The trip carries the payload as well as the document: what the document
    // cannot carry — `PSIG`, `STRE`, an unreached `PSIN` byte, the schema — is
    // taken from the payload rather than invented.
    let files = payloads(
        "every_shipped_pso_file_round_trips_byte_for_byte",
        pso::MAGIC,
    );
    let names = Dictionary::default();
    let mut failed = Vec::new();
    for (name, original) in &files {
        match pso::to_xml(original, &names).and_then(|xml| pso::from_xml(original, &xml, &names)) {
            Ok(rebuilt) if rebuilt == *original => {}
            Ok(rebuilt) => {
                let at = rebuilt
                    .iter()
                    .zip(original)
                    .position(|(a, b)| a != b)
                    .unwrap_or(original.len().min(rebuilt.len()));
                failed.push(format!(
                    "{name}: differs at byte {at} ({} bytes in, {} out)",
                    original.len(),
                    rebuilt.len()
                ));
            }
            Err(error) => failed.push(format!("{name}: {error:?}")),
        }
    }
    assert!(
        failed.is_empty(),
        "{} of {} payloads did not round-trip:\n{}",
        failed.len(),
        files.len(),
        failed
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    eprintln!("{} PSO payloads round-tripped byte-for-byte", files.len());
}

#[test]
#[cfg_attr(no_metadata, ignore = "RPF_METADATA is not set")]
fn a_dictionary_does_not_change_what_a_round_trip_produces() {
    let files = payloads(
        "a_dictionary_does_not_change_what_a_round_trip_produces",
        pso::MAGIC,
    );
    let named = Dictionary::load(NAMES_THAT_OCCUR).dictionary;
    let mut differed = Vec::new();
    for (name, original) in files.iter().take(600) {
        let xml = pso::to_xml(original, &named).expect("a shipped payload converts");
        match pso::from_xml(original, &xml, &named) {
            Ok(rebuilt) if rebuilt == *original => {}
            Ok(_) => differed.push(name.clone()),
            Err(error) => differed.push(format!("{name}: {error:?}")),
        }
    }
    assert!(
        differed.is_empty(),
        "a dictionary changed the bytes for {} payloads: {:?}",
        differed.len(),
        differed.iter().take(5).collect::<Vec<_>>()
    );
}

/// The `CHKS` recipe, transcribed a second time so agreement with `rpf-core` is
/// evidence: a Jenkins one-at-a-time hash seeded `0x3FAC7125` over the whole
/// file, each byte signed, with `fileSize` and `checksum` zeroed first.
fn chks_of(file: &[u8]) -> u32 {
    let at = chks_at(file).expect("the file carries a CHKS");
    let mut zeroed = file.to_vec();
    zeroed[at + 8..at + 16].fill(0);
    let mut hash: u32 = 0x3FAC_7125;
    for byte in &zeroed {
        hash = hash.wrapping_add(i32::from(byte.cast_signed()).cast_unsigned());
        hash = hash.wrapping_add(hash << 10);
        hash ^= hash >> 6;
    }
    hash = hash.wrapping_add(hash << 3);
    hash ^= hash >> 11;
    hash.wrapping_add(hash << 15)
}

/// Where a payload's `CHKS` section starts, if it has one.
fn chks_at(payload: &[u8]) -> Option<usize> {
    let mut at = 0usize;
    for (tag, length) in sections_of(payload) {
        if &tag == b"CHKS" {
            return Some(at);
        }
        at += length as usize;
    }
    None
}

#[test]
#[cfg_attr(no_metadata, ignore = "RPF_METADATA is not set")]
fn the_checksum_recipe_reproduces_every_stored_one() {
    // `from_xml` recomputes the checksum rather than copying it, and the recipe
    // here is transcribed from the format notes rather than from `rpf-core`.
    let files = payloads(
        "the_checksum_recipe_reproduces_every_stored_one",
        pso::MAGIC,
    );
    let mut checked = 0usize;
    let mut wrong = Vec::new();
    for (name, payload) in &files {
        let Some(at) = chks_at(payload) else { continue };
        let stored = u32::from_be_bytes(
            payload[at + 12..at + 16]
                .try_into()
                .expect("four bytes of checksum"),
        );
        let size = u32::from_be_bytes(
            payload[at + 8..at + 12]
                .try_into()
                .expect("four bytes of fileSize"),
        );
        let derived = chks_of(payload);
        if derived != stored || size as usize != payload.len() {
            wrong.push(format!(
                "{name}: stored {stored:#010x}, derived {derived:#010x}"
            ));
        }
        checked += 1;
    }
    assert!(
        wrong.is_empty(),
        "the recipe missed {} of {checked}: {:?}",
        wrong.len(),
        wrong.iter().take(5).collect::<Vec<_>>()
    );
    assert_eq!(
        checked, 8_978,
        "docs/metadata-encodings.md: the recipe reproduces 8,978 of 8,978"
    );
}

#[test]
#[cfg_attr(no_metadata, ignore = "RPF_METADATA is not set")]
fn the_corpus_carries_a_checksum_in_the_files_the_encodings_say_it_does() {
    // A census: it says the number the test above quotes was there to check.
    let files = payloads(
        "the_corpus_carries_a_checksum_in_the_files_the_encodings_say_it_does",
        pso::MAGIC,
    );
    let carried = files
        .values()
        .filter(|payload| sections_of(payload).iter().any(|(tag, _)| tag == b"CHKS"))
        .count();
    assert_eq!(
        carried, 8_978,
        "docs/metadata-encodings.md: 8,978 of 9,753 files carry a CHKS"
    );
}

/// Every section of a payload, as its tag and its length.
fn sections_of(payload: &[u8]) -> Vec<([u8; 4], u32)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 8 <= payload.len() {
        let tag: [u8; 4] = payload[at..at + 4].try_into().expect("four bytes");
        let length = u32::from_be_bytes(payload[at + 4..at + 8].try_into().expect("four bytes"));
        if length < 8 {
            break;
        }
        out.push((tag, length));
        at += length as usize;
    }
    out
}

#[test]
#[cfg_attr(no_metadata, ignore = "RPF_METADATA is not set")]
fn an_edited_value_is_that_value_changed_and_nothing_else() {
    // A round trip is only worth something if an edit reaches the bytes: one
    // float, its four bytes and the checksum's four are all that may differ.
    let files = payloads(
        "an_edited_value_is_that_value_changed_and_nothing_else",
        pso::MAGIC,
    );
    let names = Dictionary::default();
    let mut edited = 0usize;
    for original in files.values().take(400) {
        let xml = pso::to_xml(original, &names).expect("a shipped payload converts");
        let text = String::from_utf8(xml).expect("the document is UTF-8");
        let Some(at) = text.find("pso:float=\"") else {
            continue;
        };
        let open = at + "pso:float=\"".len();
        let close = open + text[open..].find('"').expect("the attribute closes");
        if &text[open..close] == "1234.5" {
            continue;
        }
        let changed = format!("{}1234.5{}", &text[..open], &text[close..]);
        let rebuilt =
            pso::from_xml(original, changed.as_bytes(), &names).expect("the edit applies");
        assert_eq!(rebuilt.len(), original.len(), "an edit changes no length");
        let differing = rebuilt.iter().zip(original).filter(|(a, b)| a != b).count();
        assert!(
            (1..=8).contains(&differing),
            "one float and one checksum, not {differing} bytes"
        );
        let back = pso::to_xml(&rebuilt, &names).expect("the edited payload converts");
        assert_eq!(
            String::from_utf8(back).expect("UTF-8"),
            changed,
            "the edit reads back as what was written"
        );
        edited += 1;
        if edited == 50 {
            break;
        }
    }
    assert!(edited > 0, "no document in the sample carried a float");
}

/// The `cause` of an [`Error::NotPsoXml`], or a panic naming what was got.
fn pso_refused(payload: &[u8], document: &str) -> pso::NotPsoXml {
    match pso::from_xml(payload, document.as_bytes(), &Dictionary::default()) {
        Err(Error::NotPsoXml { cause, .. }) => cause,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// The payload [`minimal_pso`] describes, with its one `UINT` set to `value`.
fn pso_with_uint(value: u32) -> Vec<u8> {
    let names = Dictionary::default();
    let payload = minimal_pso();
    let document = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <hash_D98BB561 pso:struct=\"hash_D98BB561\">\n  \
         <hash_12345678 pso:uint=\"{value}\"/>\n\
         </hash_D98BB561>\n"
    );
    pso::from_xml(&payload, document.as_bytes(), &names).expect("the edit applies")
}

#[test]
fn the_minimal_pso_round_trips_and_takes_an_edit() {
    let names = Dictionary::default();
    let payload = minimal_pso();
    let xml = pso::to_xml(&payload, &names).expect("converts");
    assert_eq!(
        pso::from_xml(&payload, &xml, &names).expect("reads back"),
        payload,
        "unedited in, unedited out"
    );
    let edited = pso_with_uint(9);
    assert_eq!(edited.len(), payload.len(), "an edit changes no length");
    assert_eq!(
        pso_xml(&edited),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <hash_D98BB561 pso:struct=\"hash_D98BB561\">\n  \
         <hash_12345678 pso:uint=\"9\"/>\n\
         </hash_D98BB561>\n"
    );
}

#[test]
fn the_schema_comes_from_the_payload_and_the_document_is_checked_against_it() {
    let payload = minimal_pso();
    assert_eq!(
        pso_refused(
            &payload,
            "<hash_D98BB561 pso:struct=\"hash_D98BB561\">\
             <lodDist pso:uint=\"7\"/></hash_D98BB561>"
        ),
        pso::NotPsoXml::Tag {
            wanted: "hash_12345678".to_owned(),
            found: "lodDist".to_owned(),
        }
    );
    // And a type word that is not the one the schema says.
    assert_eq!(
        pso_refused(
            &payload,
            "<hash_D98BB561 pso:struct=\"hash_D98BB561\">\
             <hash_12345678 pso:float=\"7.0\"/></hash_D98BB561>"
        ),
        pso::NotPsoXml::Word {
            wanted: "uint".to_owned(),
            found: "float".to_owned(),
        }
    );
}

#[test]
fn a_member_added_or_removed_is_refused_because_the_shape_is_the_payloads() {
    let payload = minimal_pso();
    assert_eq!(
        pso_refused(&payload, "<hash_D98BB561 pso:struct=\"hash_D98BB561\"/>"),
        pso::NotPsoXml::Children {
            name: "hash_D98BB561".to_owned(),
            wanted: 1,
            found: 0
        }
    );
    assert_eq!(
        pso_refused(
            &payload,
            "<hash_D98BB561 pso:struct=\"hash_D98BB561\">\
             <hash_12345678 pso:uint=\"7\"/>\
             <hash_12345678 pso:uint=\"7\"/></hash_D98BB561>"
        ),
        pso::NotPsoXml::Children {
            name: "hash_D98BB561".to_owned(),
            wanted: 1,
            found: 2
        }
    );
}

#[test]
fn a_value_that_is_not_of_its_own_declared_type_is_refused() {
    let payload = minimal_pso();
    assert_eq!(
        pso_refused(
            &payload,
            "<hash_D98BB561 pso:struct=\"hash_D98BB561\">\
             <hash_12345678 pso:uint=\"-1\"/></hash_D98BB561>"
        ),
        pso::NotPsoXml::Value {
            name: "hash_12345678".to_owned()
        }
    );
}

#[test]
fn an_element_with_no_type_word_is_refused_rather_than_inferred() {
    let payload = minimal_pso();
    assert_eq!(
        pso_refused(
            &payload,
            "<hash_D98BB561 pso:struct=\"hash_D98BB561\">\
             <hash_12345678>7</hash_12345678></hash_D98BB561>"
        ),
        pso::NotPsoXml::Reserved {
            name: "hash_12345678".to_owned()
        }
    );
    assert_eq!(
        pso_refused(&payload, ""),
        pso::NotPsoXml::Empty,
        "an empty document describes nothing"
    );
}

#[test]
fn a_string_longer_than_its_room_is_refused_rather_than_made_to_fit() {
    let payload = string_pso(8);
    let names = Dictionary::default();
    let xml = pso::to_xml(&payload, &names).expect("converts");
    assert_eq!(
        pso::from_xml(&payload, &xml, &names).expect("reads back"),
        payload
    );
    let shorter = String::from_utf8(xml)
        .expect("UTF-8")
        .replace("pso:string=\"abcdefg\"", "pso:string=\"ab\"");
    let edited = pso::from_xml(&payload, shorter.as_bytes(), &names).expect("shortening fits");
    assert!(
        pso_xml(&edited).contains("pso:string=\"ab\""),
        "a shorter string fits where a longer one was"
    );
    // Eight bytes of member, seven of room: the terminator is one of the eight.
    let longer = pso_xml(&payload).replace("pso:string=\"abcdefg\"", "pso:string=\"abcdefgh\"");
    assert_eq!(
        pso_refused(&payload, &longer),
        pso::NotPsoXml::TooLong {
            name: "hash_12345678".to_owned(),
            room: 7,
            len: 8
        }
    );
}

/// A `PSO` whose one member is a fixed inline string of `len` bytes holding
/// `abcdefg`, its NUL, and filler after it that has to survive an edit.
fn string_pso(len: u16) -> Vec<u8> {
    let room = usize::from(len);
    let mut psin = Vec::new();
    psin.extend_from_slice(&pso::MAGIC);
    psin.extend_from_slice(&u32::try_from(16 + room).expect("fits").to_be_bytes());
    psin.extend_from_slice(b"pppppppp");
    psin.extend_from_slice(b"abcdefg\0");
    psin.resize(16 + room, 0xA7);

    let mut pmap = Vec::new();
    pmap.extend_from_slice(b"PMAP");
    pmap.extend_from_slice(&32u32.to_be_bytes());
    pmap.extend_from_slice(&1i32.to_be_bytes());
    pmap.extend_from_slice(&1i16.to_be_bytes());
    pmap.extend_from_slice(&0x7070u16.to_be_bytes());
    pmap.extend_from_slice(&ROOT_NAME.to_be_bytes());
    pmap.extend_from_slice(&16i32.to_be_bytes());
    pmap.extend_from_slice(&0i32.to_be_bytes());
    pmap.extend_from_slice(&i32::from(len).to_be_bytes());

    let mut psch = Vec::new();
    psch.extend_from_slice(b"PSCH");
    psch.extend_from_slice(&44u32.to_be_bytes());
    psch.extend_from_slice(&1u32.to_be_bytes());
    psch.extend_from_slice(&ROOT_NAME.to_be_bytes());
    psch.extend_from_slice(&20i32.to_be_bytes());
    psch.extend_from_slice(&1u32.to_be_bytes());
    psch.extend_from_slice(&i32::from(len).to_be_bytes());
    psch.extend_from_slice(&0u32.to_be_bytes());
    psch.extend_from_slice(&MEMBER_NAME.to_be_bytes());
    // `STRING` subtype 0, its buffer length in the high half of the reference.
    psch.extend_from_slice(&[0x0B, 0x00]);
    psch.extend_from_slice(&0u16.to_be_bytes());
    psch.extend_from_slice(&(u32::from(len) << 16).to_be_bytes());

    let mut payload = psin;
    payload.extend_from_slice(&pmap);
    payload.extend_from_slice(&psch);
    payload
}

#[test]
fn an_enum_two_keys_render_the_same_name_for_is_refused_rather_than_guessed() {
    // Two keys carrying one name make the name ambiguous on the way back.
    let payload = enum_pso(0x1111_1111, 0x1111_1111);
    let names = Dictionary::default();
    let xml = pso::to_xml(&payload, &names).expect("converts");
    match pso::from_xml(&payload, &xml, &names) {
        Err(Error::NotPsoXml {
            cause: pso::NotPsoXml::Ambiguous { name },
            ..
        }) => assert_eq!(name, "hash_11111111"),
        other => panic!("expected an ambiguous refusal, got {other:?}"),
    }
    // The same file with two names is not ambiguous and round-trips.
    let payload = enum_pso(0x1111_1111, 0x2222_2222);
    let xml = pso::to_xml(&payload, &names).expect("converts");
    assert_eq!(
        pso::from_xml(&payload, &xml, &names).expect("reads back"),
        payload
    );
}

/// A `PSO` whose one member is a 32-bit enum over a table of two keys, 0 and 1,
/// named `first` and `second`.
fn enum_pso(first: u32, second: u32) -> Vec<u8> {
    const TABLE: u32 = 0x3000_0000;
    let mut psin = Vec::new();
    psin.extend_from_slice(&pso::MAGIC);
    psin.extend_from_slice(&20u32.to_be_bytes());
    psin.extend_from_slice(b"pppppppp");
    psin.extend_from_slice(&1u32.to_be_bytes()); // the stored value: key 1

    let mut pmap = Vec::new();
    pmap.extend_from_slice(b"PMAP");
    pmap.extend_from_slice(&32u32.to_be_bytes());
    pmap.extend_from_slice(&1i32.to_be_bytes());
    pmap.extend_from_slice(&1i16.to_be_bytes());
    pmap.extend_from_slice(&0x7070u16.to_be_bytes());
    pmap.extend_from_slice(&ROOT_NAME.to_be_bytes());
    pmap.extend_from_slice(&16i32.to_be_bytes());
    pmap.extend_from_slice(&0i32.to_be_bytes());
    pmap.extend_from_slice(&4i32.to_be_bytes());

    let mut psch = Vec::new();
    psch.extend_from_slice(b"PSCH");
    psch.extend_from_slice(&72u32.to_be_bytes());
    psch.extend_from_slice(&2u32.to_be_bytes()); // count
    psch.extend_from_slice(&ROOT_NAME.to_be_bytes());
    psch.extend_from_slice(&28i32.to_be_bytes());
    psch.extend_from_slice(&TABLE.to_be_bytes());
    psch.extend_from_slice(&52i32.to_be_bytes());
    // The structure, at 28.
    psch.extend_from_slice(&1u32.to_be_bytes());
    psch.extend_from_slice(&4i32.to_be_bytes());
    psch.extend_from_slice(&0u32.to_be_bytes());
    psch.extend_from_slice(&MEMBER_NAME.to_be_bytes());
    psch.extend_from_slice(&[0x0E, 0x00]); // ENUM, 32 bit
    psch.extend_from_slice(&0u16.to_be_bytes());
    psch.extend_from_slice(&TABLE.to_be_bytes());
    // The enum, at 52: kind 1, two entries.
    psch.extend_from_slice(&0x0100_0002u32.to_be_bytes());
    psch.extend_from_slice(&first.to_be_bytes());
    psch.extend_from_slice(&0i32.to_be_bytes());
    psch.extend_from_slice(&second.to_be_bytes());
    psch.extend_from_slice(&1i32.to_be_bytes());

    let mut payload = psin;
    payload.extend_from_slice(&pmap);
    payload.extend_from_slice(&psch);
    payload
}

#[test]
fn xml_the_write_direction_refuses_is_a_refusal_and_not_corrupt_data() {
    let payload = minimal_pso();
    assert_eq!(
        pso::from_xml(&payload, b"<", &Dictionary::default())
            .expect_err("not XML")
            .category(),
        Category::Refused
    );
    assert_eq!(
        pso::from_xml(b"nope", b"<a/>", &Dictionary::default())
            .expect_err("not PSO")
            .category(),
        Category::Corrupt
    );
}

/// Where the counted form sits inside [`counted_string_pso`]'s root.
const COUNTED_AT: usize = 16;

/// Where its `count1` sits: the 16-byte counted form is the pointer, then
/// `count1:u16be`, `count2:u16be`, `unk:u32be`.
const COUNT1_AT: usize = COUNTED_AT + 8;

/// The big-endian `u16` at `at`, read straight out rather than through
/// [`pso::to_xml`], which cannot see a `count1` that disagrees with the text.
fn half_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes(bytes[at..at + 2].try_into().expect("two bytes"))
}

/// A `PSO` whose one member is an `ATSTRING`: a counted pointer into a second
/// block holding `GTA V`, its NUL, and filler after it.
fn counted_string_pso() -> Vec<u8> {
    let mut psin = Vec::new();
    psin.extend_from_slice(&pso::MAGIC);
    psin.extend_from_slice(&40u32.to_be_bytes());
    psin.extend_from_slice(b"pppppppp");
    // The counted form at 16: the pointer to block 2, then count1, count2 and
    // the dead word.
    psin.extend_from_slice(&2u32.to_be_bytes());
    psin.extend_from_slice(&0x1234_5678u32.to_be_bytes());
    psin.extend_from_slice(&5u16.to_be_bytes());
    psin.extend_from_slice(&6u16.to_be_bytes());
    psin.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    // Block 2 at 32: the string, its NUL, and filler that has to survive.
    psin.extend_from_slice(b"GTA V\0");
    psin.extend_from_slice(&[0xA7, 0xA7]);

    let mut pmap = Vec::new();
    pmap.extend_from_slice(b"PMAP");
    pmap.extend_from_slice(&48u32.to_be_bytes());
    pmap.extend_from_slice(&1i32.to_be_bytes());
    pmap.extend_from_slice(&2i16.to_be_bytes());
    pmap.extend_from_slice(&0x7070u16.to_be_bytes());
    pmap.extend_from_slice(&ROOT_NAME.to_be_bytes());
    pmap.extend_from_slice(&16i32.to_be_bytes());
    pmap.extend_from_slice(&0i32.to_be_bytes());
    pmap.extend_from_slice(&16i32.to_be_bytes());
    pmap.extend_from_slice(&0x1u32.to_be_bytes());
    pmap.extend_from_slice(&32i32.to_be_bytes());
    pmap.extend_from_slice(&0i32.to_be_bytes());
    pmap.extend_from_slice(&8i32.to_be_bytes());

    let mut psch = Vec::new();
    psch.extend_from_slice(b"PSCH");
    psch.extend_from_slice(&44u32.to_be_bytes());
    psch.extend_from_slice(&1u32.to_be_bytes());
    psch.extend_from_slice(&ROOT_NAME.to_be_bytes());
    psch.extend_from_slice(&20i32.to_be_bytes());
    psch.extend_from_slice(&1u32.to_be_bytes());
    psch.extend_from_slice(&16i32.to_be_bytes());
    psch.extend_from_slice(&0u32.to_be_bytes());
    psch.extend_from_slice(&MEMBER_NAME.to_be_bytes());
    psch.extend_from_slice(&[0x0B, 0x03]); // STRING, ATSTRING
    psch.extend_from_slice(&0u16.to_be_bytes());
    psch.extend_from_slice(&0u32.to_be_bytes());

    let mut payload = psin;
    payload.extend_from_slice(&pmap);
    payload.extend_from_slice(&psch);
    payload
}

#[test]
fn a_shortened_counted_string_leaves_no_stale_length_behind() {
    // `count1` is the length: three bytes under a count of five contradict.
    let names = Dictionary::default();
    let payload = counted_string_pso();
    assert_eq!(half_at(&payload, COUNT1_AT), 5);
    assert_eq!(half_at(&payload, COUNT1_AT + 2), 6);

    let xml = pso_xml(&payload);
    assert!(
        xml.contains("pso:string.counted=\"GTA V\""),
        "the counted string renders: {xml}"
    );
    assert_eq!(
        pso::from_xml(&payload, xml.as_bytes(), &names).expect("reads back"),
        payload,
        "unedited in, unedited out"
    );

    let shorter = xml.replace("\"GTA V\"", "\"GTA\"");
    let edited = pso::from_xml(&payload, shorter.as_bytes(), &names).expect("shortening fits");
    assert_eq!(
        half_at(&edited, COUNT1_AT),
        3,
        "count1 is the length, and the length is now three"
    );
    assert_eq!(
        half_at(&edited, COUNT1_AT + 2),
        6,
        "count2 is the capacity, and the allocation did not change"
    );
    assert_eq!(&edited[32..36], b"GTA\0", "the bytes and their terminator");
    assert_eq!(
        &edited[36..40],
        &payload[36..40],
        "and nothing past the terminator moved"
    );
    assert_eq!(edited.len(), payload.len(), "an edit changes no length");
}

#[test]
fn a_checksum_section_that_is_not_twenty_bytes_is_refused_rather_than_overwritten() {
    // A `CHKS` is twenty bytes in 8,978 of 8,978, and two fields are stamped in.
    let names = Dictionary::default();
    let mut payload = minimal_pso();
    let plain = payload.len();
    payload.extend_from_slice(b"CHKS");
    payload.extend_from_slice(&8u32.to_be_bytes());
    payload.extend_from_slice(b"XXXX");
    payload.extend_from_slice(&12u32.to_be_bytes());
    payload.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

    let xml = pso_xml(&payload);
    match pso::from_xml(&payload, xml.as_bytes(), &names) {
        Err(Error::BadPso { cause, offset }) => {
            assert_eq!(cause, pso::Malformed::Checksum);
            assert_eq!(offset, plain as u64, "and it says where");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }

    // The same file with the twenty bytes it always has is stamped.
    let mut good = minimal_pso();
    let at = good.len();
    good.extend_from_slice(b"CHKS");
    good.extend_from_slice(&20u32.to_be_bytes());
    good.extend_from_slice(&[0; 8]);
    good.extend_from_slice(&0x7970_7070u32.to_be_bytes());
    let xml = pso_xml(&good);
    let stamped = pso::from_xml(&good, xml.as_bytes(), &names).expect("stamps");
    assert_eq!(
        u32::from_be_bytes(stamped[at + 8..at + 12].try_into().expect("four bytes")),
        stamped.len() as u32,
        "fileSize is the file's own length"
    );
    assert_eq!(
        u32::from_be_bytes(stamped[at + 12..at + 16].try_into().expect("four bytes")),
        chks_of(&stamped),
        "and the checksum is the one the recipe gives"
    );
}

#[test]
fn an_array_item_added_or_removed_is_refused_because_the_length_is_the_payloads() {
    // An array's length is where its items are, and moving them is a rebuild.
    const ITEM: &str = "<pso:item pso:string=\"\"/>";

    let payload = nested_arrays_pso(2);
    let names = Dictionary::default();
    let xml = pso_xml(&payload);
    assert_eq!(
        pso::from_xml(&payload, xml.as_bytes(), &names).expect("unedited applies"),
        payload
    );

    assert_eq!(xml.matches(ITEM).count(), 8, "two cubed leaves: {xml}");
    assert_eq!(
        pso_refused(&payload, &xml.replacen(ITEM, "", 1)),
        pso::NotPsoXml::Children {
            name: "pso:item".to_owned(),
            wanted: 2,
            found: 1
        }
    );
    assert_eq!(
        pso_refused(&payload, &xml.replacen(ITEM, &format!("{ITEM}{ITEM}"), 1)),
        pso::NotPsoXml::Children {
            name: "pso:item".to_owned(),
            wanted: 2,
            found: 3
        }
    );
}

/// How many resource `Meta` files both installs ship.
const META_FILES: usize = 49_614;

/// One dumped resource `Meta` payload: its bytes, and the page boundary they do
/// not carry. Every resource pointer resolves against the boundary between
/// system and graphics pages, which the dump records in the file's name.
#[derive(Debug)]
struct Dumped {
    /// The inflated payload, exactly as the archive holds it.
    payload: Vec<u8>,
    /// How many of its leading bytes are system pages.
    system_len: usize,
}

/// Every resource `Meta` payload under `RPF_METADATA`, one at a time, and how
/// many there were: the dump is 2.85 GB, so one is held at a time. Recognition
/// is `meta::identifies`, since a `Meta` has no magic at its front; a dump of
/// the wrong size or without system lengths is refused after the walk.
fn each_meta_payload(test: &str, mut visit: impl FnMut(&str, &Dumped)) -> usize {
    let Some(root) = env::var_os("RPF_METADATA") else {
        refuse(
            test,
            "RPF_METADATA is not set, so no payload can be located",
        );
    };
    let root = PathBuf::from(root);
    let Ok(listing) = fs::read_dir(&root) else {
        refuse(test, &format!("{} is not a directory", root.display()));
    };
    // Sorted, because a message whose order changes between runs cannot be diffed.
    let mut paths: Vec<PathBuf> = listing
        .map(|entry| entry.expect("directory entry readable").path())
        .filter(|path| path.is_file())
        .collect();
    paths.sort();

    let mut found = 0_usize;
    let mut unlabelled = Vec::new();
    for path in paths {
        let bytes = fs::read(&path).expect("payload readable");
        if !meta::identifies(&bytes) {
            continue;
        }
        let name = path
            .file_name()
            .expect("a file has a name")
            .to_string_lossy()
            .into_owned();
        let Some(system_len) = metadata_dump::system_len_of(&name) else {
            unlabelled.push(name);
            continue;
        };
        let dumped = Dumped {
            payload: bytes,
            system_len: usize::try_from(system_len).expect("a length fits"),
        };
        found += 1;
        visit(&name, &dumped);
    }
    if !unlabelled.is_empty() {
        refuse(
            test,
            &format!(
                "{} of the Meta payloads in {} carry no system length in their name, \
                 the first being {}: rerun `tools/metadata-dump --kinds meta`, \
                 which is what writes it",
                unlabelled.len(),
                root.display(),
                unlabelled.first().expect("one is there"),
            ),
        );
    }
    if found != META_FILES {
        refuse(
            test,
            &format!(
                "{} holds {found} inflated resource Meta payloads and the corpus has \
                 {META_FILES}: `tools/metadata-dump --kinds meta` is what puts them there",
                root.display(),
            ),
        );
    }
    found
}

#[test]
#[cfg_attr(no_metadata, ignore = "RPF_METADATA is not set")]
fn every_shipped_meta_file_carries_the_header_the_probe_measured() {
    // Five census rows: the magic word at 0x10, the two version words, the zero
    // at 0x18, a root the block table holds, and the three info-table pointers
    // in system space. The root's value is printed rather than pinned.
    let mut failed = Vec::new();
    let mut versions: BTreeMap<u32, usize> = BTreeMap::new();
    let mut roots: BTreeMap<u16, usize> = BTreeMap::new();
    let read = |name: &str, dumped: &Dumped| {
        match meta::Header::read(&dumped.payload) {
            Ok(header) => {
                *versions.entry(header.version).or_default() += 1;
                *roots.entry(header.root.get()).or_default() += 1;
                for (table, pointer, count) in [
                    ("structures", header.structures, header.structure_count),
                    ("enums", header.enums, header.enum_count),
                    ("blocks", header.blocks, header.block_count),
                ] {
                    // A null pointer is in no space at all.
                    if count == 0 {
                        assert!(
                            pointer.is_null(),
                            "{name}: the {table} table is empty and its pointer is not null"
                        );
                    } else if pointer.space() != Some(meta::Space::System) {
                        failed.push(format!("{name}: the {table} table is not system-space"));
                    }
                }
            }
            Err(error) => failed.push(format!("{name}: {error}")),
        }
    };
    let count = each_meta_payload(
        "every_shipped_meta_file_carries_the_header_the_probe_measured",
        read,
    );
    assert!(
        failed.is_empty(),
        "{} of {count} payloads did not read as the document says:\n{}",
        failed.len(),
        failed.join("\n")
    );
    eprintln!("{count} Meta headers read, versions {versions:?}, roots {roots:?}");
}

#[test]
#[cfg_attr(no_metadata, ignore = "RPF_METADATA is not set")]
fn every_shipped_meta_file_parses_from_the_system_length_its_name_carries() {
    // `meta::parse` needs the page boundary, which is read back out of the
    // dumped file's name; every file is then walked from its own tables.
    let mut failed = Vec::new();
    let mut structures = 0_usize;
    let mut blocks = 0_usize;
    let parse = |name: &str, dumped: &Dumped| match meta::parse(&dumped.payload, dumped.system_len)
    {
        Ok(document) => {
            structures += document.structures().len();
            blocks += document.blocks().len();
        }
        Err(error) => failed.push(format!("{name}: {error}")),
    };
    let count = each_meta_payload(
        "every_shipped_meta_file_parses_from_the_system_length_its_name_carries",
        parse,
    );
    assert!(
        failed.is_empty(),
        "{} of {count} payloads did not parse:\n{}",
        failed.len(),
        failed.join("\n")
    );
    eprintln!("{count} Meta payloads parsed, {structures} structures and {blocks} data blocks");
}

/// A `Meta` payload under construction, so a test states the bytes it means.
struct MetaBytes(Vec<u8>);

impl MetaBytes {
    fn of(len: usize) -> Self {
        Self(vec![0; len])
    }

    fn put(&mut self, at: usize, bytes: &[u8]) -> &mut Self {
        self.0[at..at + bytes.len()].copy_from_slice(bytes);
        self
    }

    fn u16(&mut self, at: usize, value: u16) -> &mut Self {
        self.put(at, &value.to_le_bytes())
    }

    fn u32(&mut self, at: usize, value: u32) -> &mut Self {
        self.put(at, &value.to_le_bytes())
    }

    fn u64(&mut self, at: usize, value: u64) -> &mut Self {
        self.put(at, &value.to_le_bytes())
    }

    fn bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A system-space resource pointer at `offset`.
fn meta_system(offset: u32) -> u64 {
    (5u64 << 28) | u64::from(offset)
}

/// A `Meta` pointer to `offset` of block `id`.
fn meta_pointer(id: u64, offset: u64) -> u64 {
    (offset << 12) | id
}

/// The root structure's name hash.
const META_ROOT: u32 = 0xD98B_B561;
/// The name hash of the structure a pointer member reaches.
const META_CHILD: u32 = 0x1111_0000;
/// The name hashes of the root's members, one per form.
const META_UINT: u32 = 0x1234_5678;
const META_FLOAT: u32 = 0x2222_0000;
const META_HASH: u32 = 0x3333_0000;
const META_STRING: u32 = 0x4444_0000;
const META_ARRAY: u32 = 0x5555_0000;
const META_POINTER: u32 = 0x6666_0000;
const META_INLINE_TEXT: u32 = 0x7777_0000;
const META_INLINE_ARRAY: u32 = 0x8888_0000;
/// The `ARRAYINFO` sentinel a member carries when it describes another
/// member's elements rather than a field of its own.
const META_ARRAYINFO: u32 = 0x0000_0100;

/// The header of a well-formed file with no table in it.
fn meta_header(len: usize) -> MetaBytes {
    let mut payload = MetaBytes::of(len);
    payload
        .u32(0x00, 0xDEAD_BEEF)
        .u32(0x04, 1)
        .u32(0x10, meta::MAGIC)
        .u32(0x14, meta::VERSION_TWO)
        .u32(0x1C, 1);
    payload
}

/// The smallest file that reaches a value: one `UINT` in one data block.
fn minimal_meta() -> Vec<u8> {
    let mut payload = meta_header(0x100);
    payload
        .u64(0x20, meta_system(0x50))
        .u64(0x30, meta_system(0xA0))
        .u16(0x48, 1)
        .u16(0x4C, 1)
        // The structure: name, name2, kind, membersPtr, length, count.
        .u32(0x50, META_ROOT)
        .u32(0x54, META_ROOT)
        .u32(0x58, 0x300)
        .u64(0x60, meta_system(0x70))
        .u32(0x68, 4)
        .u16(0x6E, 1)
        // Its one member: a `UINT` at offset 0.
        .u32(0x70, META_UINT)
        .u32(0x74, 0)
        .put(0x78, &[0x15, 0x00])
        // The block table, and the block.
        .u32(0xA0, META_ROOT)
        .u32(0xA4, 4)
        .u64(0xA8, meta_system(0xB0))
        .u32(0xB0, 7);
    payload.bytes().to_vec()
}

/// A file whose one member is an inline array of elements of no width at all:
/// `referenceKey × 0` is `0` for any count, so every element sits at one address
/// and nothing in the payload grows with the count, which is a 32-bit field.
fn zero_stride_meta(count: u32) -> Vec<u8> {
    let mut payload = meta_header(0x100);
    payload
        .u64(0x20, meta_system(0x50))
        .u64(0x30, meta_system(0x90))
        .u16(0x48, 2)
        .u16(0x4C, 1)
        // The root: two members, four bytes long.
        .u32(0x50, META_ROOT)
        .u32(0x54, META_ROOT)
        .u32(0x58, 0x300)
        .u64(0x60, meta_system(0xB0))
        .u32(0x68, 4)
        .u16(0x6E, 2)
        // The structure its elements are, declared **zero bytes long**.
        .u32(0x70, META_CHILD)
        .u32(0x74, META_CHILD)
        .u32(0x78, 0x300)
        .u64(0x80, meta_system(0xE0))
        .u32(0x88, 0)
        .u16(0x8E, 0)
        // The block table, and the root's block.
        .u32(0x90, META_ROOT)
        .u32(0x94, 4)
        .u64(0x98, meta_system(0xF0))
        // The inline array, and the `ARRAYINFO` member describing its elements.
        .u32(0xB0, META_INLINE_ARRAY)
        .u32(0xB4, 0)
        .put(0xB8, &[0x50, 0x00])
        .u16(0xBA, 1)
        .u32(0xBC, count)
        .u32(0xC0, META_ARRAYINFO)
        .u32(0xC4, 0)
        .put(0xC8, &[0x05, 0x00])
        .u32(0xCC, META_CHILD)
        .u32(0xF0, 7);
    payload.bytes().to_vec()
}

/// A file carrying one of every form this build decodes, with `count1` and
/// `count2` of its counted string chosen by the caller. The codes are the
/// census's: `0x44`/`0x40` string, `0x52`/`0x50` array, `0x59` pointer.
fn rich_meta(count1: u16, count2: u16) -> Vec<u8> {
    let mut payload = meta_header(0x400);
    payload
        .u64(0x20, meta_system(0x50))
        .u64(0x30, meta_system(0x200))
        .u16(0x48, 2)
        .u16(0x4C, 4)
        // The root structure: nine members, 0x60 bytes long.
        .u32(0x50, META_ROOT)
        .u32(0x54, META_ROOT)
        .u32(0x58, 0x300)
        .u64(0x60, meta_system(0x100))
        .u32(0x68, 0x60)
        .u16(0x6E, 9)
        // The child structure: one `UINT`.
        .u32(0x70, META_CHILD)
        .u32(0x74, META_CHILD)
        .u32(0x78, 0x300)
        .u64(0x80, meta_system(0x190))
        .u32(0x88, 4)
        .u16(0x8E, 1);

    let member = |payload: &mut MetaBytes, at: usize, name: u32, offset: u32, code: u8| {
        payload
            .u32(at, name)
            .u32(at + 4, offset)
            .put(at + 8, &[code, 0]);
    };
    member(&mut payload, 0x100, META_UINT, 0x00, 0x15);
    member(&mut payload, 0x110, META_FLOAT, 0x04, 0x21);
    member(&mut payload, 0x120, META_HASH, 0x08, 0x4A);
    member(&mut payload, 0x130, META_STRING, 0x10, 0x44);
    member(&mut payload, 0x140, META_ARRAY, 0x20, 0x52);
    payload.u16(0x14A, 8); // its `ARRAYINFO` member is the ninth
    member(&mut payload, 0x150, META_POINTER, 0x30, 0x59);
    // An inline string of eight bytes, whose length is its `referenceKey`.
    member(&mut payload, 0x160, META_INLINE_TEXT, 0x38, 0x40);
    payload.u32(0x16C, 8);
    // An inline array of two `UINT`, whose count is its `referenceKey`.
    member(&mut payload, 0x170, META_INLINE_ARRAY, 0x40, 0x50);
    payload.u16(0x17A, 8).u32(0x17C, 2);
    member(&mut payload, 0x180, META_ARRAYINFO, 0x00, 0x15);
    member(&mut payload, 0x190, META_UINT, 0x00, 0x15);

    let block = |payload: &mut MetaBytes, at: usize, tag: u32, len: u32, to: u32| {
        payload
            .u32(at, tag)
            .u32(at + 4, len)
            .u64(at + 8, meta_system(to));
    };
    block(&mut payload, 0x200, META_ROOT, 0x60, 0x300);
    block(&mut payload, 0x210, 0x11, 8, 0x380);
    block(&mut payload, 0x220, 0x15, 8, 0x390);
    block(&mut payload, 0x230, META_CHILD, 4, 0x3A0);

    payload
        .u32(0x300, 7)
        .u32(0x304, 0x3FC0_0000)
        .u32(0x308, 0xAABB_CCDD)
        .u64(0x310, meta_pointer(2, 0))
        .u16(0x318, count1)
        .u16(0x31A, count2)
        .u64(0x320, meta_pointer(3, 0))
        .u16(0x328, 2)
        .u16(0x32A, 2)
        .u64(0x330, meta_pointer(4, 0))
        .put(0x338, b"RAGE\0\xA7\xA7\xA7")
        .u32(0x340, 33)
        .u32(0x344, 44)
        // The bytes no walk reaches, which have to survive untouched.
        .put(0x348, &[0xA7; 0x18])
        .put(0x380, b"GTA V\0\xA7\xA7")
        .u32(0x390, 11)
        .u32(0x394, 22)
        .u32(0x3A0, 99);
    payload.bytes().to_vec()
}

/// The document a payload renders, with no dictionary.
fn meta_xml(payload: &[u8]) -> String {
    let bytes = meta::to_xml(payload, payload.len(), &Dictionary::default()).expect("converts");
    String::from_utf8(bytes).expect("UTF-8")
}

/// What a document the payload does not describe is refused with.
fn meta_not_xml(payload: &[u8], document: &str) -> meta::NotMetaXml {
    match meta::from_xml(
        payload,
        payload.len(),
        document.as_bytes(),
        &Dictionary::default(),
    ) {
        Err(Error::NotMetaXml { cause, .. }) => cause,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn the_minimal_meta_is_the_baseline_the_refusals_are_mutations_of() {
    assert_eq!(
        meta_xml(&minimal_meta()),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <hash_D98BB561 meta:struct=\"hash_D98BB561\">\n  \
         <hash_12345678 meta:uint=\"7\"/>\n\
         </hash_D98BB561>\n"
    );
}

#[test]
fn every_form_this_build_decodes_is_named_in_the_document() {
    assert_eq!(
        meta_xml(&rich_meta(6, 6)),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <hash_D98BB561 meta:struct=\"hash_D98BB561\">\n  \
         <hash_12345678 meta:uint=\"7\"/>\n  \
         <hash_22220000 meta:float=\"1.5\"/>\n  \
         <hash_33330000 meta:hash=\"hash_AABBCCDD\"/>\n  \
         <hash_44440000 meta:string=\"GTA V\"/>\n  \
         <hash_55550000 meta:array=\"counted\">\n    \
         <meta:item meta:uint=\"11\"/>\n    \
         <meta:item meta:uint=\"22\"/>\n  \
         </hash_55550000>\n  \
         <hash_66660000 meta:struct=\"hash_11110000\">\n    \
         <hash_12345678 meta:uint=\"99\"/>\n  \
         </hash_66660000>\n  \
         <hash_77770000 meta:string=\"RAGE\"/>\n  \
         <hash_88880000 meta:array=\"inline\">\n    \
         <meta:item meta:uint=\"33\"/>\n    \
         <meta:item meta:uint=\"44\"/>\n  \
         </hash_88880000>\n\
         </hash_D98BB561>\n"
    );
}

#[test]
fn a_hand_built_meta_round_trips_byte_for_byte() {
    // The edit is applied to the payload, so bytes no walk reaches survive.
    for payload in [minimal_meta(), rich_meta(6, 6), rich_meta(6, 5)] {
        let xml = meta_xml(&payload);
        assert_eq!(
            meta::from_xml(
                &payload,
                payload.len(),
                xml.as_bytes(),
                &Dictionary::default()
            )
            .expect("applies back"),
            payload,
            "unedited in, unedited out"
        );
    }
}

#[test]
fn an_edited_value_changes_the_bytes_it_names_and_no_others() {
    let payload = rich_meta(6, 6);
    let edited = meta_xml(&payload).replace("meta:uint=\"7\"", "meta:uint=\"8\"");
    let written = meta::from_xml(
        &payload,
        payload.len(),
        edited.as_bytes(),
        &Dictionary::default(),
    )
    .expect("applies");
    assert_eq!(&written[0x300..0x304], &8u32.to_le_bytes());
    assert_eq!(&written[..0x300], &payload[..0x300]);
    assert_eq!(&written[0x304..], &payload[0x304..]);
}

/// What a payload the document does not fit is refused with, when writing.
fn meta_bad(payload: &[u8], document: &str) -> (u64, meta::Malformed) {
    match meta::from_xml(
        payload,
        payload.len(),
        document.as_bytes(),
        &Dictionary::default(),
    ) {
        Err(Error::BadMeta { offset, cause }) => (offset, cause),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// What the read direction refuses a payload with.
fn meta_bad_read(payload: &[u8]) -> (u64, meta::Malformed) {
    match meta::to_xml(payload, payload.len(), &Dictionary::default()) {
        Err(Error::BadMeta { offset, cause }) => (offset, cause),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_value_outside_the_block_that_holds_it_is_refused_by_both_directions() {
    // A structure instance is checked against its block's declared length as
    // well: a block may be shorter than the structure a pointer puts in it.
    let document = meta_xml(&minimal_meta());
    let mut payload = minimal_meta();
    payload[0xA4] = 3; // the block's declared length, against a four-byte `UINT`

    assert_eq!(meta_bad_read(&payload), (0xB0, meta::Malformed::DataRange));
    assert_eq!(
        meta_bad(&payload, &document),
        (0xB0, meta::Malformed::DataRange),
        "the two directions refuse the same payload at the same address"
    );
}

#[test]
fn an_array_item_outside_the_block_that_holds_it_is_refused_by_both_directions() {
    // The same rule down the array path: two items declared, a block of one.
    let document = meta_xml(&rich_meta(6, 6));
    let mut payload = rich_meta(6, 6);
    payload[0x224] = 4; // the array block's declared length, against two items

    assert_eq!(meta_bad_read(&payload), (0x394, meta::Malformed::DataRange));
    assert_eq!(
        meta_bad(&payload, &document),
        (0x394, meta::Malformed::DataRange),
        "the two directions refuse the same payload at the same address"
    );
}

/// A `Meta` whose root holds two pointers to one value.
fn aliased_meta() -> Vec<u8> {
    let mut payload = meta_header(0x200);
    payload
        .u64(0x20, meta_system(0x50))
        .u64(0x30, meta_system(0x100))
        .u16(0x48, 1)
        .u16(0x4C, 2)
        // The root structure: two pointer members, 16 bytes long.
        .u32(0x50, META_ROOT)
        .u32(0x54, META_ROOT)
        .u32(0x58, 0x300)
        .u64(0x60, meta_system(0x70))
        .u32(0x68, 0x10)
        .u16(0x6E, 2)
        .u32(0x70, META_POINTER)
        .u32(0x74, 0)
        .put(0x78, &[0x59, 0])
        .u32(0x80, META_HASH)
        .u32(0x84, 8)
        .put(0x88, &[0x59, 0])
        // The root's block, and the typed block both its pointers name.
        .u32(0x100, META_ROOT)
        .u32(0x104, 0x10)
        .u64(0x108, meta_system(0x140))
        .u32(0x110, 0x15)
        .u32(0x114, 4)
        .u64(0x118, meta_system(0x160))
        .u64(0x140, meta_pointer(2, 0))
        .u64(0x148, meta_pointer(2, 0))
        .u32(0x160, 7);
    payload.bytes().to_vec()
}

#[test]
fn an_edit_two_elements_disagree_over_is_refused_rather_than_silently_dropped() {
    // Two pointers at one value would let an edit of one alone be dropped.
    let payload = aliased_meta();
    let document = meta_xml(&payload);
    assert_eq!(
        document,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <hash_D98BB561 meta:struct=\"hash_D98BB561\">\n  \
         <hash_66660000 meta:uint=\"7\"/>\n  \
         <hash_33330000 meta:uint=\"7\"/>\n\
         </hash_D98BB561>\n",
        "both pointers render, and both render the same value"
    );

    // Unedited, the two writes agree and the file is written back as it was.
    assert_eq!(
        meta::from_xml(
            &payload,
            payload.len(),
            document.as_bytes(),
            &Dictionary::default()
        )
        .expect("unedited applies"),
        payload
    );

    // Edited on one side alone, the two disagree, and that is the refusal.
    let half = document.replace(
        "<hash_66660000 meta:uint=\"7\"/>",
        "<hash_66660000 meta:uint=\"99\"/>",
    );
    assert_eq!(
        meta_not_xml(&payload, &half),
        meta::NotMetaXml::Aliased {
            name: "hash_33330000".to_owned(),
            address: 0x160,
        }
    );

    // Edited on both, they agree again and the edit lands once.
    let whole = document.replace("meta:uint=\"7\"", "meta:uint=\"99\"");
    let written = meta::from_xml(
        &payload,
        payload.len(),
        whole.as_bytes(),
        &Dictionary::default(),
    )
    .expect("an edit both elements agree on applies");
    assert_eq!(&written[0x160..0x164], &99u32.to_le_bytes());
    assert_eq!(&written[..0x160], &payload[..0x160]);
    assert_eq!(&written[0x164..], &payload[0x164..]);
}

#[test]
fn a_document_that_changes_an_arrays_length_is_refused() {
    let payload = rich_meta(6, 6);
    let shorter = meta_xml(&payload).replace("    <meta:item meta:uint=\"22\"/>\n", "");
    assert_eq!(
        meta_not_xml(&payload, &shorter),
        meta::NotMetaXml::Children {
            name: "hash_55550000".to_owned(),
            wanted: 2,
            found: 1,
        }
    );
}

#[test]
fn a_document_that_changes_a_structures_member_list_is_refused() {
    let payload = minimal_meta();
    let extra = meta_xml(&payload).replace(
        "  <hash_12345678 meta:uint=\"7\"/>\n",
        "  <hash_12345678 meta:uint=\"7\"/>\n  <hash_12345678 meta:uint=\"7\"/>\n",
    );
    assert_eq!(
        meta_not_xml(&payload, &extra),
        meta::NotMetaXml::Children {
            name: "hash_D98BB561".to_owned(),
            wanted: 1,
            found: 2,
        }
    );
}

#[test]
fn a_document_naming_a_member_the_file_does_not_have_is_refused() {
    let payload = minimal_meta();
    let renamed = meta_xml(&payload).replace("hash_12345678", "hash_00000001");
    assert_eq!(
        meta_not_xml(&payload, &renamed),
        meta::NotMetaXml::Tag {
            wanted: "hash_12345678".to_owned(),
            found: "hash_00000001".to_owned(),
        }
    );
}

#[test]
fn a_type_word_that_is_not_the_one_the_file_declares_is_refused() {
    let payload = minimal_meta();
    let retyped = meta_xml(&payload).replace("meta:uint", "meta:int");
    assert_eq!(
        meta_not_xml(&payload, &retyped),
        meta::NotMetaXml::Word {
            wanted: "uint".to_owned(),
            found: "int".to_owned(),
        }
    );
}

#[test]
fn a_value_that_does_not_read_back_as_its_own_type_is_refused() {
    let payload = minimal_meta();
    let nonsense = meta_xml(&payload).replace("meta:uint=\"7\"", "meta:uint=\"seven\"");
    assert_eq!(
        meta_not_xml(&payload, &nonsense),
        meta::NotMetaXml::Value {
            name: "hash_12345678".to_owned(),
        }
    );
}

#[test]
fn a_reserved_words_value_is_checked_and_not_only_the_word_itself() {
    // The reserved word says what kind of record an element is and its value
    // says which one, so another type or layout describes another payload.
    let payload = rich_meta(6, 6);
    let xml = meta_xml(&payload);

    let retyped = xml.replace(
        "meta:struct=\"hash_D98BB561\"",
        "meta:struct=\"hash_11110000\"",
    );
    assert_eq!(
        meta_not_xml(&payload, &retyped),
        meta::NotMetaXml::Word {
            wanted: "hash_D98BB561".to_owned(),
            found: "hash_11110000".to_owned(),
        },
        "the structure the file declares, and not another one it also declares"
    );

    let relaid = xml.replace("meta:array=\"counted\"", "meta:array=\"inline\"");
    assert_eq!(
        meta_not_xml(&payload, &relaid),
        meta::NotMetaXml::Word {
            wanted: "counted".to_owned(),
            found: "inline".to_owned(),
        },
        "an array's layout is the file's and not the document's"
    );
}

/// [`rich_meta`] with its pointer member null, so that one element of the
/// document it renders stands for an absent value.
fn null_pointer_meta() -> Vec<u8> {
    let mut payload = rich_meta(6, 6);
    payload[0x330..0x338].fill(0);
    payload
}

#[test]
fn a_null_pointer_written_down_as_an_empty_value_of_its_type_is_refused() {
    // An absent value and an empty one differ, so a null is written down.
    let payload = null_pointer_meta();
    let xml = meta_xml(&payload);
    assert!(
        xml.contains("<hash_66660000 meta:null=\"struct\"/>"),
        "the null pointer is written down as one: {xml}"
    );
    assert_eq!(
        meta::from_xml(
            &payload,
            payload.len(),
            xml.as_bytes(),
            &Dictionary::default()
        )
        .expect("unedited applies"),
        payload
    );

    let emptied = xml.replace(
        "<hash_66660000 meta:null=\"struct\"/>",
        "<hash_66660000 meta:struct=\"hash_11110000\"/>",
    );
    assert_eq!(
        meta_not_xml(&payload, &emptied),
        meta::NotMetaXml::Word {
            wanted: "null".to_owned(),
            found: "struct".to_owned(),
        }
    );
}

/// A little-endian `u16` at `at` of `bytes`, read straight out rather than
/// through [`meta_xml`], which cannot see a count that disagrees with the text.
fn meta_half_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("two bytes"))
}

#[test]
fn a_shortened_counted_string_is_terminated_where_it_now_ends() {
    // An eight-byte store holding five bytes leaves a shorter value its NUL.
    let payload = rich_meta(8, 8);
    let xml = meta_xml(&payload);
    assert!(xml.contains("meta:string=\"GTA V\""), "{xml}");

    let shorter = xml.replace("meta:string=\"GTA V\"", "meta:string=\"GTA\"");
    let edited = meta::from_xml(
        &payload,
        payload.len(),
        shorter.as_bytes(),
        &Dictionary::default(),
    )
    .expect("shortening fits");
    assert_eq!(
        &edited[0x380..0x384],
        b"GTA\0",
        "the bytes and their terminator"
    );
    assert_eq!(
        &edited[0x384..0x388],
        &payload[0x384..0x388],
        "and nothing past the terminator moved"
    );
}

#[test]
fn a_counted_string_that_fills_its_room_is_not_terminated_past_that_room() {
    // A value filling the store exactly ends at its last byte, with nowhere for
    // a NUL: what terminates it is the count, and the byte past it is not ours.
    let payload = rich_meta(8, 8);
    let filled = meta_xml(&payload).replace("meta:string=\"GTA V\"", "meta:string=\"1111111\"");
    let edited = meta::from_xml(
        &payload,
        payload.len(),
        filled.as_bytes(),
        &Dictionary::default(),
    )
    .expect("a value of exactly its room fits");
    assert_eq!(&edited[0x380..0x387], b"1111111");
    assert_eq!(
        edited[0x387], payload[0x387],
        "the store's last byte is not written over with a terminator it has no room for"
    );
    assert_eq!(
        meta_half_at(&edited, 0x318),
        7,
        "the count is what says where the value ends"
    );
}

#[test]
fn a_shortened_meta_counted_string_leaves_no_stale_length_behind() {
    // `count1` changes with the bytes; `count2` is the allocation's capacity.
    let payload = rich_meta(8, 8);
    assert_eq!(meta_half_at(&payload, 0x318), 8);
    assert_eq!(meta_half_at(&payload, 0x31A), 8);

    let shorter = meta_xml(&payload).replace("meta:string=\"GTA V\"", "meta:string=\"GTA\"");
    let edited = meta::from_xml(
        &payload,
        payload.len(),
        shorter.as_bytes(),
        &Dictionary::default(),
    )
    .expect("shortening fits");
    assert_eq!(
        meta_half_at(&edited, 0x318),
        3,
        "count1 is the length, and the length is now three"
    );
    assert_eq!(
        meta_half_at(&edited, 0x31A),
        8,
        "count2 is the capacity, and the allocation did not change"
    );
    assert_eq!(edited.len(), payload.len(), "an edit changes no length");
}

#[test]
fn an_inline_array_of_elements_with_no_width_is_refused_rather_than_walked() {
    // An element of width 0 makes an array of any count occupy no bytes, so the
    // walk writes one element per count out of a payload that never grows.
    let error = meta::to_xml(
        &zero_stride_meta(4_000_000_000),
        zero_stride_meta(0).len(),
        &Dictionary::default(),
    )
    .expect_err("an array of elements with no width is refused");
    assert!(
        matches!(
            error,
            Error::BadMeta {
                cause: meta::Malformed::ZeroStride,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(error.category(), Category::Corrupt);
    // An array of no elements is not refused: a file may declare and not use.
    let empty = zero_stride_meta(0);
    meta::to_xml(&empty, empty.len(), &Dictionary::default())
        .expect("an empty array asks nothing of its element type");
}

#[test]
fn a_type_code_outside_the_table_is_refused_rather_than_guessed_at() {
    // The 23 codes are the census of every member of all 49,614 files.
    let mut payload = minimal_meta();
    payload[0x78] = 0x7F;
    let error = meta::to_xml(&payload, payload.len(), &Dictionary::default())
        .expect_err("an unnamed type code is not decoded");
    assert!(
        matches!(
            error,
            Error::UnsupportedMeta {
                cause: meta::Unsupported::DataType { code: 0x7F }
            }
        ),
        "{error:?}"
    );
    assert_eq!(error.category(), Category::Unsupported);
}

#[test]
fn a_member_that_does_not_fit_its_own_structure_is_refused() {
    // A member's value has to lie inside the structure the file declares.
    let mut payload = minimal_meta();
    payload[0x68] = 3; // structLength, against a four-byte `UINT` at offset 0
    let error = meta::to_xml(&payload, payload.len(), &Dictionary::default())
        .expect_err("a member past its structure is refused");
    assert!(
        matches!(
            error,
            Error::BadMeta {
                cause: meta::Malformed::MemberExtent,
                ..
            }
        ),
        "{error:?}"
    );
}

#[test]
fn an_array_whose_element_member_its_structure_does_not_have_is_refused() {
    // 925,473 `ARRAYINFO` indices resolved across the corpus, 0 unresolvable.
    let mut payload = rich_meta(6, 6);
    payload[0x14A] = 10; // the array's element index, past the nine members
    let error = meta::to_xml(&payload, payload.len(), &Dictionary::default())
        .expect_err("an element index that names no member is refused");
    assert!(
        matches!(
            error,
            Error::BadMeta {
                cause: meta::Malformed::ArrayInfo,
                ..
            }
        ),
        "{error:?}"
    );
}

#[test]
fn an_inline_structure_the_file_does_not_define_is_refused() {
    // The read is driven by the file's own tables and by nothing else.
    let mut payload = minimal_meta();
    payload[0x78] = 0x05; // an inline structure, whose `referenceKey` is 0
    let error = meta::to_xml(&payload, payload.len(), &Dictionary::default())
        .expect_err("a structure the file does not define is refused");
    assert!(
        matches!(
            error,
            Error::BadMeta {
                cause: meta::Malformed::UndefinedStructure,
                ..
            }
        ),
        "{error:?}"
    );
}

#[test]
fn a_null_pointer_that_still_declares_a_count_is_a_file_contradicting_itself() {
    // A null pointer says the value is not there and a count above zero says
    // how much of it there is; nothing in the corpus says both.
    let mut string = rich_meta(1, 1);
    string[0x310..0x318].copy_from_slice(&0u64.to_le_bytes());
    assert_eq!(
        meta_bad_read(&string),
        (0x310, meta::Malformed::Pointer),
        "a counted string of one byte and no pointer"
    );

    // The array shape of it, whose count is `count1` alone.
    let mut array = rich_meta(6, 6);
    array[0x320..0x328].copy_from_slice(&0u64.to_le_bytes());
    assert_eq!(
        meta_bad_read(&array),
        (0x320, meta::Malformed::Pointer),
        "an array of two items and no pointer"
    );
}

#[test]
fn a_null_pointer_that_declares_nothing_is_read_rather_than_refused() {
    // Null and counting nothing is what an absent value looks like.
    let mut empty = rich_meta(0, 0);
    empty[0x310..0x318].copy_from_slice(&0u64.to_le_bytes());
    empty[0x320..0x328].copy_from_slice(&0u64.to_le_bytes());
    empty[0x328..0x32C].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(
        meta_xml(&empty),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <hash_D98BB561 meta:struct=\"hash_D98BB561\">\n  \
         <hash_12345678 meta:uint=\"7\"/>\n  \
         <hash_22220000 meta:float=\"1.5\"/>\n  \
         <hash_33330000 meta:hash=\"hash_AABBCCDD\"/>\n  \
         <hash_44440000 meta:null=\"string\"/>\n  \
         <hash_55550000 meta:array=\"counted\"/>\n  \
         <hash_66660000 meta:struct=\"hash_11110000\">\n    \
         <hash_12345678 meta:uint=\"99\"/>\n  \
         </hash_66660000>\n  \
         <hash_77770000 meta:string=\"RAGE\"/>\n  \
         <hash_88880000 meta:array=\"inline\">\n    \
         <meta:item meta:uint=\"33\"/>\n    \
         <meta:item meta:uint=\"44\"/>\n  \
         </hash_88880000>\n\
         </hash_D98BB561>\n"
    );
}

/// How many bytes of text every item of [`counted_strings_meta`] reads from.
const META_TEXT_LEN: usize = 56_000;

/// A file whose one array is `stores.len()` counted strings, each reading the
/// bytes its own row names out of one shared block of text, then a `UINT` at
/// offset 16 of the root's block. One block read once per item is what lets a
/// 60 KB payload write a 16 MB document; at a `root_len` of 16 the block ends
/// before the `UINT`, which is then unreadable.
fn counted_strings_meta(stores: &[u16], root_len: u32) -> Vec<u8> {
    const ITEMS_AT: usize = 0x300;
    let items_len = stores.len() * 16;
    let text_at = ITEMS_AT + items_len;
    let offset = |at: usize| u32::try_from(at).expect("a payload this size");
    let count = u16::try_from(stores.len()).expect("a count that fits");
    let mut payload = meta_header(text_at + META_TEXT_LEN);
    payload
        .u64(0x20, meta_system(0x50))
        .u64(0x30, meta_system(0xA0))
        .u16(0x48, 1)
        .u16(0x4C, 3)
        // The root structure: three members, twenty bytes long.
        .u32(0x50, META_ROOT)
        .u32(0x54, META_ROOT)
        .u32(0x58, 0x300)
        .u64(0x60, meta_system(0x100))
        .u32(0x68, 20)
        .u16(0x6E, 3)
        // The counted array at offset 0, the `ARRAYINFO` member naming its
        // elements as counted strings, and the `UINT` at offset 16.
        .u32(0x100, META_ARRAY)
        .u32(0x104, 0)
        .put(0x108, &[0x52, 0x00])
        .u16(0x10A, 1)
        .u32(0x110, META_ARRAYINFO)
        .u32(0x114, 0)
        .put(0x118, &[0x44, 0x00])
        .u32(0x120, META_UINT)
        .u32(0x124, 16)
        .put(0x128, &[0x15, 0x00])
        // The root's block, the items' block and the text's.
        .u32(0xA0, META_ROOT)
        .u32(0xA4, root_len)
        .u64(0xA8, meta_system(0x200))
        .u32(0xB0, 0x15)
        .u32(0xB4, offset(items_len))
        .u64(0xB8, meta_system(offset(ITEMS_AT)))
        .u32(0xC0, 0x11)
        .u32(0xC4, offset(META_TEXT_LEN))
        .u64(0xC8, meta_system(offset(text_at)))
        // The array itself.
        .u64(0x200, meta_pointer(2, 0))
        .u16(0x208, count)
        .u16(0x20A, count);
    for (index, store) in stores.iter().enumerate() {
        let at = ITEMS_AT + index * 16;
        payload
            .u64(at, meta_pointer(3, 0))
            .u16(at + 8, *store)
            .u16(at + 10, *store);
    }
    payload.put(text_at, &vec![b'A'; META_TEXT_LEN]);
    payload.bytes().to_vec()
}

#[test]
fn a_meta_document_is_bounded_in_bytes_at_the_byte_the_budget_names() {
    // 16 MB of document out of 60 KB of payload with three hundred elements:
    // far under the element ceiling and exactly on the byte one. The charge is
    // taken before each element, so the two cases answer differently.
    const BUDGET: usize = 16 * 1024 * 1024;

    // What the document costs before its first item, and an item around its text.
    let one = meta_xml(&counted_strings_meta(&[8], 20));
    let two = meta_xml(&counted_strings_meta(&[8, 8], 20));
    let item_at = one.find("<meta:item").expect("an item is written");
    let prefix = one[..item_at].rfind('\n').expect("a line before it") + 1;
    let overhead = two.len() - one.len() - 8;

    // The stores that put the last item's charge exactly on the budget.
    let whole = (BUDGET - prefix + META_TEXT_LEN) / (overhead + META_TEXT_LEN);
    let remainder = BUDGET - prefix - whole * overhead - (whole - 1) * META_TEXT_LEN;
    assert!(
        remainder < META_TEXT_LEN,
        "the remainder is a run of the text block: {remainder}"
    );
    let stores = |over: usize| {
        let mut stores = vec![u16::try_from(remainder + over).expect("a store that fits")];
        stores.resize(
            whole,
            u16::try_from(META_TEXT_LEN).expect("a store that fits"),
        );
        stores.push(8);
        stores
    };

    // The budget is the payload's, so it has to be inside the floor.
    let payload = counted_strings_meta(&stores(0), 16);
    assert!(
        payload.len() * 256 <= BUDGET,
        "the floor is what a payload this size is entitled to: {} bytes",
        payload.len()
    );

    // Exactly on the budget the walk goes on, and the read after it stops it.
    assert_eq!(
        meta_bad_read(&payload),
        (0x210, meta::Malformed::DataRange),
        "a document of exactly the budget is written, and the `UINT` after it is not"
    );

    // One byte over, the last item is never written at all.
    assert_eq!(
        meta_bad_read(&counted_strings_meta(&stores(1), 16)),
        (0, meta::Malformed::TooLarge),
        "one byte past the budget is one byte too many"
    );
}

#[test]
#[cfg_attr(no_metadata, ignore = "RPF_METADATA is not set")]
fn every_shipped_meta_file_round_trips_byte_for_byte() {
    // Narrower than it looks: `from_xml` applies the document `to_xml` just
    // wrote, so nothing is written and equality is the payload handed back. It
    // says the walk reached every value, not that a member's width is right.
    let mut failed = Vec::new();
    let names = Dictionary::default();
    let mut trip = |name: &str, dumped: &Dumped| {
        let xml = match meta::to_xml(&dumped.payload, dumped.system_len, &names) {
            Ok(xml) => xml,
            Err(error) => {
                failed.push(format!("{name}: to_xml: {error}"));
                return;
            }
        };
        match meta::from_xml(&dumped.payload, dumped.system_len, &xml, &names) {
            Ok(written) if written == dumped.payload => {}
            Ok(_) => failed.push(format!("{name}: applied back to different bytes")),
            Err(error) => failed.push(format!("{name}: from_xml: {error}")),
        }
    };
    let count = each_meta_payload(
        "every_shipped_meta_file_round_trips_byte_for_byte",
        &mut trip,
    );
    assert!(
        failed.is_empty(),
        "{} of {count} payloads did not round-trip:\n{}",
        failed.len(),
        failed.join("\n")
    );
    eprintln!("{count} Meta payloads round-tripped byte for byte");
}
