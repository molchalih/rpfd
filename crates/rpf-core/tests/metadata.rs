//! The metadata layer against the metadata both games ship.
//!
//! R5.7's harness: unedited in, unedited out, byte-identical. The claim it
//! makes is not that the round trip holds for made-up documents but that it
//! holds for **the 391 `RBF` files in the corpus**, which is what
//! `docs/metadata-encodings.md` measured byte-perfect re-serialisation against.
//!
//! No game data is tracked. Payloads are located through `RPF_METADATA`, a
//! directory of files already extracted from their archives; what is committed
//! is `fixtures/rbf-metadata.json`, a count and a list of `sha256` digests.
//! With `RPF_METADATA` unset every test that needs it is `#[ignore]`d by
//! `build.rs`, so the harness names each one as skipped. R0.2, R8.4.
//!
//! `clippy.toml`'s `allow-*-in-tests` settings reach `#[cfg(test)]` modules and
//! not this directory — an integration test is compiled as its own crate, with
//! no `cfg(test)`. `docs/conventions.md` §15's exception is therefore spelled
//! out here: in a test a panic is the reporting mechanism, not a crash.
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
    metadata::rbf::{self, MAGIC, Malformed, NotRbf, Unrepresentable},
};
use sha2::{Digest, Sha256};

/// What the committed fixture describes.
const FIXTURE: &str = "../../fixtures/rbf-metadata.json";

/// Reports a skip, naming the test and what it would have read.
///
/// The ordinary case — no `RPF_METADATA` at all — never reaches here:
/// `build.rs` turns that into `#[ignore]`, which the harness reports by name
/// whether or not output is captured. What is left is a directory that was
/// pointed at and does not hold what the test needs.
fn skip<T>(test: &str, reason: &str) -> Option<T> {
    assert!(
        env::var_os("RPF_REQUIRE_METADATA").is_none(),
        "RPF_REQUIRE_METADATA is set, but {test} would have skipped: {reason}",
    );
    eprintln!("SKIP {test}: {reason}");
    None
}

/// Every `RBF` payload under `RPF_METADATA`, by file name.
///
/// Recognition is from content and never from an extension, which is what
/// `docs/rpf-format.md` says the container does: 388 of the 391 are `.ymt` and
/// 3 are `.ymf`, and the same extensions carry `PSO` far more often.
fn payloads(test: &str) -> Option<BTreeMap<String, Vec<u8>>> {
    let Some(root) = env::var_os("RPF_METADATA") else {
        return skip(
            test,
            "RPF_METADATA is not set, so no payload can be located",
        );
    };
    let root = PathBuf::from(root);
    let Ok(listing) = fs::read_dir(&root) else {
        return skip(test, &format!("{} is not a directory", root.display()));
    };
    let mut found = BTreeMap::new();
    for entry in listing {
        let path = entry.expect("directory entry readable").path();
        if !path.is_file() {
            continue;
        }
        let bytes = fs::read(&path).expect("payload readable");
        if bytes.starts_with(&MAGIC) {
            let name = path
                .file_name()
                .expect("a file has a name")
                .to_string_lossy()
                .into_owned();
            found.insert(name, bytes);
        }
    }
    if found.is_empty() {
        return skip(test, &format!("{} holds no RBF payload", root.display()));
    }
    Some(found)
}

fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    hex::encode(digest.finalize())
}

#[test]
#[cfg_attr(no_metadata, ignore = "RPF_METADATA is not set")]
fn every_shipped_rbf_file_round_trips_byte_for_byte() {
    // The whole of R5.7. `docs/metadata-encodings.md` measured that a
    // name-keyed re-serialiser reproduces 391 of 391 shipped files; this is
    // that measurement, through XML rather than through a tree, and it is what
    // says R5.6's differential rebuild is not needed for `RBF`.
    let Some(files) = payloads("every_shipped_rbf_file_round_trips_byte_for_byte") else {
        return;
    };
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
    // A file with the right name is not the same file. §12: the fixture records
    // the `sha256` of every payload it describes, and this confirms that before
    // the round trip above is allowed to mean anything about *these* 391 files.
    let Some(files) = payloads("the_corpus_is_the_one_the_fixture_describes") else {
        return;
    };
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
    // Two of `docs/metadata-encodings.md`'s `RBF` rows, as a test that fails if
    // they stop being true (§12): every name is literal inline ASCII, so the
    // XML carries no hash anywhere; and a blob keeps its trailing NUL rather
    // than having it stripped.
    let Some(files) = payloads("the_xml_is_readable_and_says_what_the_probe_measured") else {
        return;
    };
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

/// A minimal valid payload: `<Root/>`, built by hand rather than by the writer
/// under test, so that a bug shared by reader and writer still shows.
fn minimal() -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&[0x00, 0x00]); // descriptor 0, open element
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(b"Root");
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // unk1, unk2, attrCount
    out.extend_from_slice(&[0xFF, 0xFF]); // close
    out
}

/// The `cause` of a [`Error::BadRbf`], or a panic naming what was got instead.
fn malformed(payload: &[u8]) -> Malformed {
    match rbf::to_xml(payload) {
        Err(Error::BadRbf { cause, .. }) => cause,
        other => panic!("expected a malformed RBF, got {other:?}"),
    }
}

/// The `cause` of a [`Error::UnrepresentableRbf`].
fn unrepresentable(payload: &[u8]) -> Unrepresentable {
    match rbf::to_xml(payload) {
        Err(Error::UnrepresentableRbf { cause }) => cause,
        other => panic!("expected an unrepresentable RBF, got {other:?}"),
    }
}

/// The `cause` of a [`Error::NotRbfXml`].
fn not_xml(document: &str) -> NotRbf {
    match rbf::from_xml(document.as_bytes()) {
        Err(Error::NotRbfXml { cause, .. }) => cause,
        other => panic!("expected XML that is not an RBF document, got {other:?}"),
    }
}

#[test]
fn the_minimal_payload_is_the_baseline_the_malformed_cases_are_mutations_of() {
    // Every case below breaks this one payload in one way. If this stopped
    // being valid, all of them would pass for the wrong reason.
    let xml = rbf::to_xml(&minimal()).expect("the minimal payload converts");
    assert_eq!(
        str::from_utf8(&xml).expect("UTF-8"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Root/>\n"
    );
    assert_eq!(rbf::from_xml(&xml).expect("and back"), minimal());
}

#[test]
fn a_payload_that_is_not_rbf_is_refused_by_its_magic() {
    assert_eq!(malformed(b""), Malformed::NotRbf);
    assert_eq!(malformed(b"RBF"), Malformed::NotRbf);
    // docs/metadata-encodings.md: the fourth byte is 0x30 in all 391 files, so
    // the strict four-byte test costs nothing. `RBF1` is not an RBF file here.
    assert_eq!(malformed(b"RBF1\x00\x00"), Malformed::NotRbf);
    assert_eq!(malformed(b"PSIN\x00\x00"), Malformed::NotRbf);
}

#[test]
fn a_truncated_token_stream_is_refused_at_every_length() {
    // Not one truncation but all of them: every prefix of a valid payload is
    // an error, and none of them is a panic. §6.
    let whole = minimal();
    for len in 4..whole.len() {
        let error = rbf::to_xml(&whole[..len]).expect_err("a prefix is not a document");
        assert_eq!(error.category(), Category::Corrupt, "at length {len}");
    }
    assert_eq!(malformed(&whole[..whole.len() - 1]), Malformed::Truncated);
}

#[test]
fn a_descriptor_index_past_the_end_of_the_table_is_refused() {
    let mut broken = minimal();
    broken[4] = 1; // the first record introduces descriptor 0, not descriptor 1
    assert_eq!(malformed(&broken), Malformed::DescriptorIndex);

    let mut absurd = minimal();
    absurd[4] = 0xFE; // the byte the table can never reach
    assert_eq!(malformed(&absurd), Malformed::DescriptorIndex);

    // And with a table that is not empty, so that "past the end" is refused
    // rather than quietly answered with whichever name is nearest.
    let mut past = minimal();
    past.truncate(past.len() - 2);
    past.extend_from_slice(&[5, 0x10]); // descriptor 5, of a table holding one
    past.extend_from_slice(&0u32.to_le_bytes());
    past.extend_from_slice(&[0xFF, 0xFF]);
    assert_eq!(malformed(&past), Malformed::DescriptorIndex);
}

#[test]
fn a_name_length_that_lies_is_refused() {
    let mut broken = minimal();
    broken[6..8].copy_from_slice(&0xFFFFu16.to_le_bytes());
    assert_eq!(malformed(&broken), Malformed::Truncated);
}

#[test]
fn a_blob_running_past_the_end_is_refused() {
    let mut payload = minimal();
    payload.truncate(payload.len() - 2); // drop the close record
    payload.extend_from_slice(&[0xFD, 0xFF]);
    payload.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    payload.extend_from_slice(b"short");
    payload.extend_from_slice(&[0xFF, 0xFF]);
    assert_eq!(malformed(&payload), Malformed::Truncated);
}

#[test]
fn a_name_that_is_not_utf8_is_refused() {
    let mut broken = minimal();
    broken[8..12].copy_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]);
    assert_eq!(
        unrepresentable(&broken),
        Unrepresentable::NameEncoding {
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
        Unrepresentable::NameSyntax {
            name: "1oot".to_owned()
        }
    );
}

#[test]
fn a_name_in_the_reserved_prefix_is_refused() {
    let mut broken = MAGIC.to_vec();
    broken.extend_from_slice(&[0x00, 0x00]);
    broken.extend_from_slice(&7u16.to_le_bytes());
    broken.extend_from_slice(b"rbf:xyz");
    broken.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    broken.extend_from_slice(&[0xFF, 0xFF]);
    assert_eq!(
        unrepresentable(&broken),
        Unrepresentable::NameReserved {
            name: "rbf:xyz".to_owned()
        }
    );
}

#[test]
fn a_data_type_outside_the_seven_is_refused() {
    // docs/metadata-encodings.md: 281,272 records over 391 files and not one
    // byte outside the table of seven.
    let mut payload = minimal();
    payload.truncate(payload.len() - 2);
    payload.extend_from_slice(&[0x01, 0x70]); // descriptor 1, type 0x70
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.extend_from_slice(b"x");
    payload.extend_from_slice(&[0xFF, 0xFF]);
    assert_eq!(malformed(&payload), Malformed::DataType);
}

#[test]
fn a_close_record_without_its_marker_is_refused() {
    let mut broken = minimal();
    let last = broken.len() - 1;
    broken[last] = 0x00;
    assert_eq!(malformed(&broken), Malformed::Marker);
}

#[test]
fn bytes_after_the_root_closes_are_refused() {
    // docs/metadata-encodings.md: 0 trailing bytes in all 391 files, so a
    // reader may insist on it — and this one does.
    let mut payload = minimal();
    payload.push(0x00);
    assert_eq!(malformed(&payload), Malformed::Trailing);
}

#[test]
fn an_attribute_count_larger_than_the_element_holds_is_refused() {
    let mut broken = minimal();
    let len = broken.len();
    broken[len - 4..len - 2].copy_from_slice(&3u16.to_le_bytes());
    assert_eq!(malformed(&broken), Malformed::AttributeCount);
}

#[test]
fn an_empty_blob_is_refused_because_xml_cannot_show_one() {
    // 0 of the 48,042 blobs in the corpus are empty, and an element whose text
    // is empty is indistinguishable from one with no text.
    let mut payload = minimal();
    payload.truncate(payload.len() - 2);
    payload.extend_from_slice(&[0xFD, 0xFF]);
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&[0xFF, 0xFF]);
    assert_eq!(unrepresentable(&payload), Unrepresentable::EmptyBlob);
}

#[test]
fn a_blob_sharing_its_element_is_refused() {
    // All 48,042 blobs in the corpus are the sole content of their element.
    // Three ways for that to stop being true, and each has to be refused: a
    // second blob, a blob before a child element, and a blob after one.
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
            Unrepresentable::BlobNotAlone {
                name: "Root".to_owned()
            },
            "for {shape:?}"
        );
    }
}

#[test]
fn elements_nested_past_the_walk_limit_are_refused() {
    // A stack overflow is an abort no `Result` can catch, so the depth is
    // bounded before the tree is built rather than after.
    let mut payload = MAGIC.to_vec();
    payload.extend_from_slice(&[0x00, 0x00]);
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.extend_from_slice(b"a");
    payload.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for _ in 0..4096 {
        payload.extend_from_slice(&[0x00, 0x00, 0, 0, 0, 0, 0, 0]);
    }
    assert_eq!(malformed(&payload), Malformed::TooDeep);
}

#[test]
fn xml_that_is_not_well_formed_is_refused() {
    assert!(matches!(not_xml("<Root>"), NotRbf::Syntax { .. }));
    assert!(matches!(not_xml("<a></b>"), NotRbf::Syntax { .. }));
    assert_eq!(not_xml(""), NotRbf::Empty);
    assert_eq!(not_xml("<a/><b/>"), NotRbf::SecondRoot);
}

#[test]
fn xml_that_is_well_formed_and_says_the_wrong_thing_is_refused() {
    assert_eq!(
        not_xml("<a rbf:sideways=\"1\"/>"),
        NotRbf::UnknownReserved {
            name: "rbf:sideways".to_owned()
        }
    );
    assert_eq!(
        not_xml("<a rbf:uint=\"not a number\"/>"),
        NotRbf::BadValue {
            name: "rbf:uint".to_owned()
        }
    );
    assert_eq!(
        not_xml("<a rbf:uint=\"1\" b=\"c\"/>"),
        NotRbf::ValueNotAlone {
            name: "a".to_owned()
        }
    );
    assert_eq!(not_xml("<a rbf:uint=\"1\"/>"), NotRbf::RootNotElement);
    assert_eq!(not_xml("<a>text<b/></a>"), NotRbf::UnexpectedText);
    assert_eq!(not_xml("<a>\\q</a>"), NotRbf::BadEscape);
    assert_eq!(
        not_xml("<a rbf:string.b=\"c\"/>"),
        NotRbf::UnknownReserved {
            name: "rbf:string.b".to_owned()
        }
    );
}

#[test]
fn the_two_meaningless_words_survive_a_round_trip() {
    // `docs/metadata-encodings.md`: `unk1` and `unk2` are 0 in all 106,193 open
    // elements, so a writer emitting zeroes is byte-faithful for every shipped
    // file. They are carried anyway, so that the round trip is a property of
    // the code rather than of the corpus — which is the difference between a
    // law and a coincidence.
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

#[test]
fn a_blob_that_is_only_whitespace_survives() {
    // A text node of nothing but spaces is indentation everywhere else in the
    // document, so a blob made only of spaces has to be written in a way that
    // cannot be mistaken for it.
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
    // §10, R6.3: the variant set is the public contract and the exit code comes
    // from the category. A malformed payload is corrupt data; a payload this
    // build cannot render is unsupported; XML the caller wrote is refused.
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
