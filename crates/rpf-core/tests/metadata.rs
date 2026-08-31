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
    metadata::{
        hash::{self, Dictionary, joaat},
        pso, rbf,
    },
};
use sha2::{Digest, Sha256};

/// What the committed fixture describes.
const FIXTURE: &str = "../../fixtures/rbf-metadata.json";

/// Refuses, naming the test and what it would have read.
///
/// **There is no third outcome a test can reach for.** `eprintln!` is captured
/// by default, so a corpus test that reported a skip and returned early was
/// reported as `ok` in exactly the log a real pass produces: measured
/// 2026-08-30, with `RPF_METADATA` pointed at a directory holding no payloads
/// the suite said `48 passed; 0 failed; 0 ignored` in 0.00 s. That is §12's
/// "most expensive possible bug: a green suite that tested nothing", and it is
/// the same shape as the `PSIN`-misspelling incident.
///
/// The skip §12 asks for is `#[ignore]`, which `build.rs` applies when
/// `RPF_METADATA` is unset and which the harness names whether or not output is
/// captured — so the missing-corpus case is a loud skip and never reaches here.
/// What is left is a variable that **was** set and does not name the corpus,
/// which is a misconfiguration rather than a missing corpus, and the only
/// honest thing to do with it is say so.
fn refuse(test: &str, reason: &str) -> ! {
    panic!("{test} cannot run: {reason}");
}

/// How many payloads of each kind the corpus holds, from the fixture that
/// describes it.
///
/// §12: a file with the right name is not the same corpus, and neither is one
/// file of 9,753. Without this the whole-corpus tests passed against a
/// directory containing a single payload — the counts reached only a captured
/// `eprintln!`.
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

/// Every payload under `RPF_METADATA` that opens with `magic`, by file name.
///
/// Recognition is from content and never from an extension, which is what
/// `docs/rpf-format.md` says the container does: 388 of the 391 `RBF` files are
/// `.ymt` and 3 are `.ymf`, and the same extensions carry `PSO` far more often
/// — 4,378 `.ymt`, 3,623 `.ymf` and 1,738 `.cut`.
/// The count is checked against the fixture's, so that a directory holding one
/// payload cannot satisfy a test whose whole claim is about 9,753 of them.
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
    // The whole of R5.7. `docs/metadata-encodings.md` measured that a
    // name-keyed re-serialiser reproduces 391 of 391 shipped files; this is
    // that measurement, through XML rather than through a tree, and it is what
    // says a differential rebuild is not needed for `RBF`.
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
    // A file with the right name is not the same file. §12: the fixture records
    // the `sha256` of every payload it describes, and this confirms that before
    // the round trip above is allowed to mean anything about *these* 391 files.
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
    // Two of `docs/metadata-encodings.md`'s `RBF` rows, as a test that fails if
    // they stop being true (§12): every name is literal inline ASCII, so the
    // XML carries no hash anywhere; and a blob keeps its trailing NUL rather
    // than having it stripped.
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

/// A minimal valid payload: `<Root/>`, built by hand rather than by the writer
/// under test, so that a bug shared by reader and writer still shows.
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
    assert_eq!(malformed(b""), rbf::Malformed::NotRbf);
    assert_eq!(malformed(b"RBF"), rbf::Malformed::NotRbf);
    // docs/metadata-encodings.md: the fourth byte is 0x30 in all 391 files, so
    // the strict four-byte test costs nothing. `RBF1` is not an RBF file here.
    assert_eq!(malformed(b"RBF1\x00\x00"), rbf::Malformed::NotRbf);
    assert_eq!(malformed(b"PSIN\x00\x00"), rbf::Malformed::NotRbf);
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

    // And with a table that is not empty, so that "past the end" is refused
    // rather than quietly answered with whichever name is nearest.
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
    // docs/metadata-encodings.md: 281,272 records over 391 files and not one
    // byte outside the table of seven.
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
    // docs/metadata-encodings.md: 0 trailing bytes in all 391 files, so a
    // reader may insist on it — and this one does.
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
    // 0 of the 48,042 blobs in the corpus are empty, and an element whose text
    // is empty is indistinguishable from one with no text.
    let mut payload = minimal();
    payload.truncate(payload.len() - 2);
    payload.extend_from_slice(&[0xFD, 0xFF]);
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&[0xFF, 0xFF]);
    assert_eq!(unrepresentable(&payload), rbf::Unrepresentable::EmptyBlob);
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
            rbf::Unrepresentable::BlobNotAlone {
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

/// The minimal payload with one more child, whose descriptor is `new`.
///
/// `new` is written as the descriptor index the record names. Passing the
/// table's length introduces a descriptor and carries its name; naming an
/// index the table already holds reuses it and carries nothing.
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
    // Found by `fuzz/fuzz_targets/rbf.rs` on 2026-08-31, in a mutation of a
    // shipped file that declared `AnimName` at descriptor 15 and again at 37.
    //
    // **The reader accepts it and the writer does not reproduce it**, because
    // a descriptor is introduced whenever a record names the index one past
    // the end of the table, while `token::write` rebuilds the table keyed by
    // name alone — which `docs/metadata-encodings.md` measured as the keying
    // that reproduces 391 of 391 shipped files where name-and-type reproduces
    // 205. So the second declaration of a name is dropped, and the payload
    // comes back shorter than it went in.
    //
    // That is a **normalisation and not a loss**: the two descriptors are
    // interchangeable by construction, so the document is identical and only
    // the table that spells it is smaller. It is pinned rather than refused
    // for the reason `docs/backlog.md` gives for orphan entries — refusing a
    // shape on the strength of a corpus that does not contain it risks
    // rejecting a real file — and `rbf::to_xml`'s doc comment now states the
    // law with the condition it actually holds under.
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

    // The payload does. This is the exact claim, and it is what the round trip
    // gives rather than what a stronger reading of it would.
    assert_eq!(rbf::from_xml(&from_twice).expect("and back"), once);
    assert_ne!(rbf::from_xml(&from_twice).expect("and back"), twice);

    // And normalising is a fixed point: the form the writer chose survives.
    let from_once = rbf::to_xml(&once).expect("converts");
    assert_eq!(rbf::from_xml(&from_once).expect("and back"), once);
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

// ---------------------------------------------------------------------------
// `PSO` — R5.3 and R5.5
// ---------------------------------------------------------------------------

#[test]
#[cfg_attr(no_metadata, ignore = "RPF_METADATA is not set")]
fn every_shipped_pso_file_converts_from_its_own_schema_alone() {
    // R5.3's claim, and R1.7's measurement reproduced through the layer rather
    // than through a probe: every one of the 9,753 files converts driven only
    // by its own `PSCH`, with no dictionary and no builtin table of any kind.
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
    // The count of `UndefinedStructure` failures is not asserted separately:
    // every failure is in `failed`, so an assertion that there are none of that
    // one kind is implied by the assertion that there are none at all. The
    // claim it stood for — a walk from each file's own `PSCH` reaches 0
    // references the file does not define — is what this message says.
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
///
/// `docs/metadata-encodings.md`, The `ARRAYINFO` indirection. The library names
/// it too, and does not export it — this layer's constants are `pub(super)`.
const ARRAYINFO: u32 = 0x0000_0100;

/// A minimal valid `PSO`: one block, one structure, one `UINT` member.
///
/// Built by hand rather than by a writer — there is no `PSO` writer yet, and a
/// payload built by the reader's own model could share the reader's bugs. Every
/// malformed case below is one mutation of this, so
/// `the_minimal_pso_is_the_baseline_the_malformed_cases_are_mutations_of` has to
/// keep passing for any of them to mean anything.
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
    // Not one truncation but all of them: every prefix of a valid payload is an
    // error or a refusal, and none of them is a panic. §6.
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
    // Σ(section lengths) == file length in 9,753 of 9,753, so a trailer is not
    // something a shipped file has and not something this reads past.
    let mut trailing = minimal_pso();
    trailing.push(0);
    assert_eq!(pso_malformed(&trailing), pso::Malformed::Section);
}

#[test]
fn a_block_that_is_not_inside_the_data_section_is_refused() {
    // The block table is checked against the data section at construction, so
    // no later read has to re-check it (§5).
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
    // R1.7's measurement is that this reaches 0 in 9,753 files, which is what
    // says no builtin fallback table is needed. Reaching one is therefore an
    // error and never a reason to consult a table.
    let mut unknown = minimal_pso();
    unknown[20 + 8 + 4 + 2 + 2..20 + 8 + 4 + 2 + 2 + 4]
        .copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    assert_eq!(pso_malformed(&unknown), pso::Malformed::UndefinedStructure);
}

#[test]
fn a_member_type_this_build_does_not_decode_is_unsupported_not_corrupt() {
    // `docs/metadata-encodings.md` measured 37 (type, subtype) pairs over
    // 580,044 members. A pair outside them is a gap here, not damage there, and
    // the category is what a caller acts on.
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
    // Found by `fuzz/fuzz_targets/pso.rs` on 2026-08-31, on the first campaign
    // that ever reached this parser: a 5,068-byte payload allocated
    // **81,794,124 bytes** — 16,139 times its input, and past the 64 MiB
    // `fuzz/`'s counting allocator holds a 64 KiB input to — and then answered
    // `DataRange`. A refusal, arrived at by way of 81 MB.
    //
    // `MAX_NODES` was documented as bounding the memory, on the grounds that
    // the walk's peak is its output. The second half is true and the first does
    // not follow: an element is not a fixed number of bytes, because it carries
    // two spaces of indent per level of `MAX_DEPTH`, so the same million
    // elements cost several times as much when they are deep.
    //
    // **No node budget can be the memory bound, and that is what this pins.**
    // At the worst element width the ceiling would have to be about 220,000
    // elements to stay inside 64 MiB; the largest shipped file already writes
    // 137,120, and `MAX_NODES` is deliberately eight times that. The two
    // requirements do not both fit in one number, so the bound has to be
    // charged in the unit it is about. `MAX_OUTPUT_RATIO` and `MIN_OUTPUT` are
    // that, and this is the case that fails if either stops being charged.
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

    // And the bound is a bound on the document rather than on the shape: the
    // same payload one size down converts, and what it writes is inside the
    // floor. 16 MiB is `MIN_OUTPUT`, restated here because a test that pins a
    // constant has to name it — if the floor moves, this is what asks whether
    // it was meant to.
    let xml = pso_xml(&nested_arrays_pso(64));
    assert!(
        xml.len() <= 16 * 1024 * 1024,
        "a converted document is inside the floor: {} bytes",
        xml.len()
    );

    // **No wall-clock assertion here, deliberately.** The finding had a time
    // half too — 141 ms spent building the 81 MB before throwing it away, now
    // 9.5 ms — and a test that measured it would be the load-sensitive kind
    // `docs/backlog.md` already records one of. It would also assert little
    // that the refusal above does not: what bounds the time is what bounds the
    // document, because the walk's cost is the walk's output.
}

#[test]
fn a_cyclic_block_graph_is_refused_rather_than_walked_forever() {
    // The block graph is attacker-chosen. A structure holding a pointer back
    // into its own block is a cycle, and a depth limit is what stands between
    // it and a stack overflow no `Result` can catch. DR-011.
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
    // The depth ceiling does not reach this one: the payload is three levels
    // deep and declares its size rather than nesting to it. One structure, one
    // field, and three `ATFIXEDARRAY` descriptors chained through `ARRAYINFO`
    // — `0xFFFF` items of `0xFFFF` items of `0xFFFF` items — is 2.8*10^14
    // elements out of 132 bytes, and the element type bottoms out at a
    // zero-length inline string so every item lands at the same address and no
    // range check fires either. `Malformed::TooManyNodes` is the only thing
    // between that and a walk that does not return.
    //
    // **Renamed on 2026-08-31, because the budget that catches it changed.**
    // It was the node budget; it is now the output budget, which is charged in
    // the same place and fires first here because 1,048,576 elements of this
    // shape are more than 16 MiB of document. The property the test is for is
    // unchanged — 2.8*10^14 elements out of 132 bytes is refused rather than
    // walked — and which ceiling reports it is not what the case is about.
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
    // The budget is spent by every element the walk writes, which is the whole
    // of the fix above: with the same payload one size smaller the walk
    // finishes, so the refusal is the ceiling and not the shape.
    let ok = nested_arrays_pso(64);
    let xml = pso_xml(&ok);
    assert_eq!(
        xml.matches("<pso:item").count(),
        64 + 64 * 64 + 64 * 64 * 64,
        "every item of every level is written, and every one of them is charged"
    );
    // The same shape one size larger is refused. `TooLarge` rather than
    // `TooManyNodes` since 2026-08-31: both budgets are charged here and the
    // one measured in bytes reaches its ceiling first.
    assert!(matches!(
        pso::to_xml(&nested_arrays_pso(200), &Dictionary::default()),
        Err(Error::BadPso {
            cause: pso::Malformed::TooLarge,
            ..
        })
    ));
}

/// A payload whose one field is an inline array of an inline array of an
/// inline array, each `count` long.
///
/// Members 1, 2 and 3 are `ARRAYINFO` descriptors, which is what
/// [`resolve`](pso) demands of an element index, so the schema is well formed
/// at construction and the size is entirely in what it declares.
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
    // `CodeWalker`'s `if (offset >= block.Length) { offset = offset >> 8; }
    // //how to tell when to do this??` is never needed: 0 of 1,362,769 pointers
    // in the corpus are out of range, so a reader should refuse rather than
    // guess.
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
    // A structure that claims a length, a member that claims an offset: both
    // are attacker-chosen, and the read is bounds-checked rather than trusted.
    let mut past = minimal_pso();
    let offset_at = minimal_pso().len() - 6;
    past[offset_at..offset_at + 2].copy_from_slice(&40000u16.to_be_bytes());
    assert_eq!(pso_malformed(&past), pso::Malformed::DataRange);
}

#[test]
fn an_array_whose_element_index_is_not_an_arrayinfo_member_is_refused() {
    // `docs/metadata-encodings.md`: the `0xFFFF` mask alone gives a valid index
    // in 64,906 of 64,906, so this is checked at construction and
    // `CodeWalker`'s `0xFFF` re-mask fallback is not implemented.
    let mut array = minimal_pso();
    let type_at = minimal_pso().len() - 8;
    array[type_at] = 0x0D; // ARRAY
    array[type_at + 1] = 0x00; // ATARRAY
    // referenceKey's low half indexes a member; there is only member 0, and it
    // is this one, whose name is not `ARRAYINFO`.
    assert_eq!(pso_malformed(&array), pso::Malformed::ArrayInfo);
}

#[test]
fn a_vector3_is_sixteen_bytes_carrying_three_floats_and_not_twelve() {
    // `docs/metadata-encodings.md`'s census, `verified`, and §12 wants the fact
    // to have a test. Nothing about a single `VECTOR3` shows the difference —
    // three floats are read either way — so this is an inline array of two of
    // them, where the size is the stride. At twelve the second item would read
    // the four bytes of padding and the first two floats of the second vector,
    // and render `0.0, 4.0, 5.0` rather than `4.0, 5.0, 6.0`.
    //
    // The mutation matters because it is silent: changed to 12, all 48 tests
    // stayed green while the rendered XML of 1,483 of the 9,753 shipped files
    // changed, all four `junctions.pso` among them. The files still convert and
    // still parse; only the values move.
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
    // The chain is well formed and lands exactly on the end; what is absent is
    // the block table and the schema, without which there is nothing to walk.
    let payload = minimal_pso();
    let psin_only = &payload[..20];
    assert_eq!(pso_malformed(psin_only), pso::Malformed::MissingSection);
}

#[test]
fn a_section_too_short_for_its_own_header_is_refused() {
    // The section chain checks a section against the payload; this is the
    // check that a section's own header fits inside the length it declared.
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
    // `docs/metadata-encodings.md` records no third kind, so a file claiming
    // one is not a file Rockstar's packer wrote.
    let mut payload = minimal_pso();
    let packed = payload.len() - 24;
    payload[packed..packed + 4].copy_from_slice(&0x0200_0001u32.to_be_bytes());
    assert_eq!(pso_malformed(&payload), pso::Malformed::SchemaEntry);
}

#[test]
fn a_structure_whose_declared_length_is_negative_is_refused() {
    // `structureLength` is an `i32` in the format and a `u32` everywhere here,
    // so the conversion is where a negative one has to be refused rather than
    // wrapped into four billion.
    let mut payload = minimal_pso();
    let length = payload.len() - 20;
    payload[length..length + 4].copy_from_slice(&(-1i32).to_be_bytes());
    assert_eq!(pso_malformed(&payload), pso::Malformed::StructureLength);
}

#[test]
#[cfg_attr(no_metadata, ignore = "RPF_METADATA is not set")]
fn every_document_the_corpus_produces_is_well_formed_xml() {
    // The conversion writes XML by hand rather than through a serialiser, so
    // that the output is exactly the mapping DR-045 states. This is what says
    // it is still XML: every one of the 9,753 documents parses.
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
    // R5.5's claim, as a measurement rather than an assertion: the dictionary
    // is cosmetic. Two conversions of the same payload, one with names and one
    // without, differ in what the elements are called and in nothing else.
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

/// Names measured to occur in the corpus, as a dictionary file.
///
/// **Not a shipped dictionary.** DR-006: a 20,300-entry name list derived from
/// the game is not ours to redistribute. These are the handful the probe of
/// 2026-08-30 confirmed against real `PSCH` hashes, here so that the test above
/// resolves something rather than proving nothing.
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
    // The property R5.5 rests on, over real documents: whatever a name is
    // spelled as, it names the same `u32` on the way back. A dictionary name
    // does because `Dictionary::load` checked `joaat(name) == key`; a
    // `hash_XXXXXXXX` does without the hash function being invoked at all.
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
    // `docs/metadata-encodings.md` recorded 102 `MAP` members and the `ARRAY`
    // subtype `0x81` as the cases the corpus walk could not decode. Measured
    // 2026-08-30 while R5.3 was written: both decode, and this is the evidence.
    //
    // The wrapped `dataOffset` is the sharper of the two. The document says the
    // one real member's elements "genuinely begin at byte 170,416", decoding to
    // plausible world coordinates there and to zeros at the `0x99B0` the field
    // holds. So the coordinates are what says the multiple was recovered: a
    // reader that trusted the field would render `0.0, 0.0, 0.0` here.
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
    // §12: a file with the right name is not the same file. The fixture holds
    // one `sha256` of the sorted per-payload digests rather than 9,753 of them
    // — 391 is a list and 9,753 is a file of its own — and it binds the same
    // claim: that everything above ran against these bytes.
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
    // `docs/metadata-encodings.md`, Sections, `verified`. §12 wants a test that
    // fails if a `verified` row stops being true, and this is that row: the
    // eight tags, their counts, and Σ(section lengths) == file length.
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
    // A `STRING` subtype 0 is a fixed character array — 7,866 members — and the
    // bytes after its terminator are whatever the packer left there. Reading
    // the whole field instead would put them in the document.
    let payload = retyped_pso(0x0B, 0, 4 << 16, *b"ab\0Z");
    assert_eq!(only_value(&payload, &Dictionary::default()), "ab");
}

#[test]
fn a_null_pointer_is_written_down_rather_than_written_as_empty() {
    // An absent string and an empty one are different things, and XML gives no
    // way to tell an empty attribute from a missing value. DR-047.
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
    // 64,755 `ATNONFINALHASHSTRING` members and 557 `ATFINALHASHSTRING` ones —
    // 1,120,606 rendered values across the corpus — are `u32`s, so this is
    // where a dictionary earns its keep and where a wrong one would corrupt.
    let payload = retyped_pso(0x0B, 7, 0, joaat(b"CMapTypes").to_be_bytes());
    assert_eq!(
        only_value(&payload, &Dictionary::default()),
        "hash_D98BB561"
    );
    let loaded = Dictionary::load("CMapTypes");
    let spelled = only_value(&payload, &loaded.dictionary);
    assert_eq!(spelled, "CMapTypes");
    assert_eq!(joaat(spelled.as_bytes()), 0xD98B_B561);

    // And an entry that does not hash to its own key never reaches the
    // document, so it cannot spell this member as something else. R5.5.
    let lying = Dictionary::load("D98BB561 CMapTypes_");
    assert_eq!(lying.rejected.len(), 1);
    assert_eq!(only_value(&payload, &lying.dictionary), "hash_D98BB561");
}

#[test]
fn a_bitset_names_the_bits_its_own_enum_names_and_numbers_the_rest() {
    // `docs/metadata-encodings.md`: a `BITSET`'s `referenceKey` is never an
    // enum hash — 0 of 1,526 — it is `(bitCount << 16) | memberIndex` through
    // the `ARRAYINFO` indirection, and the enum's entry key is the bit index.
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
    // R5.7 for `PSO`, and the exit criterion `docs/backlog.md` states: unedited
    // in, unedited out, byte-identical, over every `PSO` file in the corpus.
    //
    // The trip carries the payload as well as the document, which is DR-049 and
    // not a weakening of the claim: what is measured here is that the document
    // describes the payload completely enough for the walk to be replayed
    // against it — every element in the right place, every type word the one
    // the schema says, every value readable back to the bytes it came from —
    // and that the `CHKS` recipe reproduces its own stored value. What the
    // document cannot carry is `PSIG`, `STRE`, an unreached `PSIN` byte and the
    // schema itself, and none of those is invented.
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
    // R5.5's "cosmetic, not load-bearing" from the write side. The names the
    // dictionary spells are re-hashed by `from_xml`, so a dictionary that
    // changes the spelling and changes the bytes would be exactly the silent
    // corruption `Dictionary::load`'s check exists to prevent.
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

/// The `CHKS` recipe, transcribed here a second time so that agreement with
/// `rpf-core` is evidence rather than a tautology.
///
/// `docs/metadata-encodings.md`, `CHKS`: a Jenkins one-at-a-time hash seeded
/// `0x3FAC7125` over the **whole file**, each byte taken as a signed `int8`,
/// with the `fileSize` and `checksum` fields of the trailing `CHKS` zeroed
/// first. The magic is not reversed and the length field is not overwritten.
///
/// Panics if the file carries no `CHKS`, which is a caller's error and not a
/// checksum of zero.
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
    // `docs/metadata-encodings.md`, `CHKS`: a Jenkins one-at-a-time hash seeded
    // 0x3FAC7125 over the whole file with each byte signed, the size and the
    // checksum zeroed first, reproducing the stored value in 8,978 of 8,978
    // files that carry one. `from_xml` recomputes rather than copies it, so the
    // recipe being wrong is every file this tool writes being wrong.
    //
    // The recipe is computed here, from `docs/metadata-encodings.md` and not
    // from `rpf-core`. Counting how many files carry a `CHKS` is a census of
    // the corpus and constrains no code — it is
    // `the_corpus_carries_a_checksum_in_the_files_the_encodings_say_it_does`,
    // under the name of what it actually checks.
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
    // A census of the corpus, and named as one. It constrains nothing in
    // `rpf-core`; what it is worth is that the number the test above quotes is
    // the number of files that were actually there to check.
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
    // The other half of the write path: a round trip that reproduces the file
    // is only worth something if an edit reaches the bytes. One float is
    // changed in the first document that has one, and exactly the four bytes
    // behind it — plus the four the `CHKS` covers — may differ.
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

// ---------------------------------------------------------------------------
// `PSO` — R5.4, the write direction
// ---------------------------------------------------------------------------

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
    // R5.4's own wording — "adopting the schema of the file being edited" — as
    // a test. The document names a member the file's schema does not have there,
    // and nothing in the document can make that member exist.
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
    // And a type word that is not the one the schema says. DR-047 writes the
    // type down on every record precisely so that this is caught here rather
    // than turning into four bytes of a different shape.
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
    // A structure's member list and an array's length are facts about the
    // payload. Changing either needs room the edit cannot make, and DR-052 is
    // why that is a permanent refusal rather than a missing feature. The
    // refusal names the element, so a caller is told which one changed.
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
    // DR-047: every record's type is written down. An element without one is
    // not a document this mapping wrote, and guessing from the spelling is what
    // DR-043 killed for `RBF` on three measurements.
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
    // A fixed inline string lives in the bytes the structure gave it. Making it
    // longer moves everything after it, which is a rebuild.
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
    // Eight bytes of member, seven of room: the terminator is one of the eight,
    // and 116,507 of 116,507 shipped member strings leave it one. DR-052.
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
    // The one place the inverse of a rendering is not a function. Rendering goes
    // value to name; two keys carrying one name make the name ambiguous, and
    // picking one would write a value nobody asked for. 0 shipped files do it,
    // which is why this is a built case and not a corpus one.
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
    // §10, R6.3, one encoding over: the payload being wrong is `Corrupt`, the
    // document being wrong is `Refused`, and the two reach different exit codes.
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

/// Where the counted form sits inside [`counted_string_pso`]'s root, from the
/// start of the payload.
const COUNTED_AT: usize = 16;

/// Where its `count1` sits, from the start of the payload.
///
/// `docs/metadata-encodings.md`, Pointers: the 16-byte counted form is the
/// pointer, then `count1:u16be`, `count2:u16be`, `unk:u32be`.
const COUNT1_AT: usize = COUNTED_AT + 8;

/// The big-endian `u16` at `at`, read straight out of the bytes.
///
/// Deliberately not through [`pso::to_xml`]. The reader answers an `ATSTRING`
/// as `until_nul` of the bytes `count1` covers, so it cannot see a `count1` that
/// disagrees with what was written — which is exactly the class of error this
/// pins, and why §8's "every write path has a read path that checks it" needs a
/// check the read path is not blind to by construction.
fn half_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes(bytes[at..at + 2].try_into().expect("two bytes"))
}

/// A `PSO` whose one member is an `ATSTRING`: a counted pointer into a second
/// block holding `GTA V`, its NUL, and filler after it.
///
/// The shape `metadata/03698_x64a.rpf_data_levels.ymt` carries at file offset
/// 984 — `count1 = 5`, `count2 = 6` — reduced to one member.
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
    // `docs/metadata-encodings.md`, Pointers: `count1` is the length. DR-049
    // blesses shortening, so shortening is the intended edit path — and a
    // writer that wrote three bytes and left `count1` saying five would ship a
    // file that contradicts itself. Every assertion here reads the stored
    // counts out of the bytes rather than through `to_xml`, which answers
    // `until_nul` of the bytes `count1` covers and therefore cannot see this.
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
    // `docs/metadata-encodings.md`, `CHKS`: twenty bytes in 8,978 of 8,978. The
    // write direction stamps `fileSize` and `checksum` into it, so a chain
    // declaring a shorter one would put eight bytes over the tag and length of
    // whatever follows — and answer a payload whose own section chain no longer
    // parses.
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

    // The same file with the twenty bytes it always has is stamped, not
    // refused, and the stamp is the recipe.
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
    // The second of the three shapes an edit in place cannot change: an array's
    // length is where its items are, and moving them is a rebuild. DR-052 is
    // why that is permanent. The refusal names the element the document spells,
    // which for an array of arrays is the `pso:item` that holds the wrong
    // number of children.
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
