//! R3.7: what an entry is, decided from its bytes and its row and from nothing
//! else.
//!
//! Almost all of it is **synthetic**, and deliberately: a sixteen-byte head is
//! easy to write down, so the arms that no archive in `assets/` exercises —
//! `RBF`, a resource whose payload reads as XML, a payload that does not read
//! back at all — are built here rather than waited for. That keeps the suite
//! honest on a machine with no game data, which is every machine but one
//! (§12, R8.4).
//!
//! The gated half adds what synthesis cannot: real `PSO` bytes, and a real
//! resource whose payload does not begin with `RSC7`.
//!
//! `clippy.toml`'s `allow-*-in-tests` settings reach `#[cfg(test)]` modules and
//! not this directory — an integration test is its own crate with no
//! `cfg(test)` — so `docs/conventions.md` §15's exception is spelled out here:
//! in a test a panic is the reporting mechanism rather than a crash.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "test code; see the note above"
)]

use std::{
    env, fs,
    io::{Cursor, Write as _},
    path::{Path, PathBuf},
    sync::Arc,
};

use rpf_core::{
    Archive, Classification, Encoding, Listed, ListedKind, Material, Unlock, Unwatched,
    format::rpf7::RESOURCE_FLAG,
};

mod common;

use common::{BLOCK_LEN, archive_bytes, directory_row, file_row};

/// Raw deflate of `plain`, which is what a compressed payload is.
fn deflate(plain: &[u8]) -> Vec<u8> {
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(plain).expect("deflates");
    encoder.finish().expect("finishes")
}

/// An archive of one directory over one file, whose payload sits at block 1.
///
/// `word8` is the uncompressed length for a binary entry and the system flags
/// for a resource one, which is the whole of why they are different variants.
fn one_file_archive(payload: &[u8], declared: u32, block_flag: u32, word8: u32) -> Vec<u8> {
    let rows = [
        directory_row(0, 1, 1),
        file_row(1, declared, 1 | block_flag, word8, 0),
    ];
    let mut bytes = archive_bytes(&rows, b"\0a\0", 4_096);
    bytes[BLOCK_LEN as usize..BLOCK_LEN as usize + payload.len()].copy_from_slice(payload);
    bytes
}

/// An archive holding one **stored** binary entry with exactly these contents.
fn stored(contents: &[u8]) -> Vec<u8> {
    one_file_archive(contents, 0, 0, contents.len() as u32)
}

/// An archive holding one **deflated** binary entry with exactly these
/// contents.
fn deflated(contents: &[u8]) -> Vec<u8> {
    let payload = deflate(contents);
    one_file_archive(&payload, payload.len() as u32, 0, contents.len() as u32)
}

/// What one entry of a one-file archive classifies as.
fn classified(bytes: &[u8], index: u32) -> Classification {
    let mut src = Cursor::new(bytes.to_vec());
    let archive = Archive::open(&mut src, &Unlock::unkeyed()).expect("well formed");
    archive
        .classify(&mut src, index)
        .expect("the entry is there")
}

/// The four heads the corpus recognises, and one it does not, each as the
/// sixteen bytes a real payload begins with.
const HEADS: &[(&[u8], Option<Encoding>)] = &[
    (b"<?xml version=\"1", Some(Encoding::Xml)),
    (b"RBF0\x00\x0eCMapType", Some(Encoding::Rbf)),
    (b"PSIN\x00\x00\x10\x00pppppppp", Some(Encoding::Pso)),
    (b"handling.dat 6.0", Some(Encoding::Text)),
    (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", None),
];

#[test]
fn every_encoding_is_recognised_through_the_deflate_stream_that_holds_it() {
    // The head is read from an entry's **contents**, so a compressed payload is
    // classified by what it is rather than by what its first deflate block
    // happens to look like. Reading the payload where it sits on disk answers
    // `Binary` for all five, which is what this pins.
    for &(contents, expected) in HEADS {
        let stored_as = classified(&stored(contents), 1);
        let deflated_as = classified(&deflated(contents), 1);
        let wanted = expected.map_or(Classification::Binary, Classification::Encoded);
        assert_eq!(stored_as, wanted, "stored {:?}", &contents[..4]);
        assert_eq!(deflated_as, wanted, "deflated {:?}", &contents[..4]);
    }
}

/// The resource payload the sample's own third-party packer writes: an `RSC7`
/// header, then a deflate stream of one 512-byte system page.
///
/// `docs/rpf-format.md`, Resource page flags and Compression, `verified`.
fn resource_payload(contents: &[u8]) -> Vec<u8> {
    let mut bytes = b"RSC7".to_vec();
    bytes.extend_from_slice(&162_u32.to_le_bytes());
    bytes.extend_from_slice(&0xA800_0000_u32.to_le_bytes());
    bytes.extend_from_slice(&0x2000_0000_u32.to_le_bytes());
    let mut page = contents.to_vec();
    page.resize(512, 0);
    bytes.extend_from_slice(&deflate(&page));
    bytes
}

#[test]
fn a_resource_is_classified_by_its_row_and_its_payload_is_never_read() {
    // Two resources, because there are two ways to read a resource's payload
    // and a sniff would have to be refused on both. `Archive::extracted` hands
    // out a resource as the **file** it is — the `RSC7` header and the deflated
    // body — while `Archive::read` inflates it, so:
    //
    //   * the first is what Rockstar ships, where those sixteen bytes are not a
    //     readable header at all (`docs/backlog.md` Q7) and can read as
    //     anything, here as plain XML;
    //   * the second is the sample's packer, whose header is real and whose
    //     *contents* are XML — which is what a resource `Meta` nearly is, and
    //     what 2,745 resources in the corpus look like from their first byte.
    //
    // Neither is looked at. The row decides.
    let inflating_to_xml = resource_payload(b"<?xml version=\"1.0\"?><CMapTypes/>");
    let beginning_with_xml = b"<?xml version=\"1.0\"?><CMapTypes/>          ".to_vec();

    for payload in [inflating_to_xml, beginning_with_xml] {
        let bytes = one_file_archive(&payload, payload.len() as u32, RESOURCE_FLAG, 0xA800_0000);

        assert_eq!(classified(&bytes, 1), Classification::Resource);
        assert_eq!(
            classified(&bytes, 1).encoding(),
            None,
            "a resource has no payload-derived encoding to report"
        );

        // And the listing says the same, because the variant that carries a
        // length for a resource has nowhere to put an encoding.
        let mut src = Cursor::new(bytes.clone());
        let archive = Archive::open(&mut src, &Unlock::unkeyed()).expect("well formed");
        let rows = Listed::at(&mut src, &archive, "", true).expect("lists");
        assert!(
            matches!(rows[0].kind, ListedKind::Resource { .. }),
            "{:?}",
            rows[0]
        );
    }
}

#[test]
fn the_window_is_sixteen_bytes_and_a_shorter_one_calls_more_payloads_text() {
    // The window is a measured constant, not a round number: judging eight
    // bytes rather than sixteen calls 292 more binary entries text over the
    // corpus, and they are `.bik` and `.awc` payloads whose ASCII magic runs
    // out after four. This is one of them, in miniature.
    let mut contents = b"ADATabcdefghijkl".to_vec();
    assert_eq!(
        classified(&stored(&contents), 1),
        Classification::Encoded(Encoding::Text)
    );

    contents[15] = 0x88;
    assert_eq!(
        classified(&stored(&contents), 1),
        Classification::Binary,
        "the sixteenth byte is inside the window"
    );
    assert_eq!(
        classified(&deflated(&contents), 1),
        Classification::Binary,
        "and stays inside it through a deflate stream"
    );
}

#[test]
fn a_payload_that_begins_rsc7_does_not_make_a_binary_entry_a_resource() {
    // The trap, from the other side. Q7 measured 694,470 Rockstar resources
    // whose payload does not begin `RSC7`; this is the entry with the magic and
    // without the bit, which the same measurement found zero of and which
    // nothing stops a third party from writing. The bit decides, both ways.
    let payload = resource_payload(b"anything at all");
    let bytes = stored(&payload);

    let mut src = Cursor::new(bytes.clone());
    let archive = Archive::open(&mut src, &Unlock::unkeyed()).expect("well formed");
    assert!(
        archive
            .payload_is_resource(&mut src, 1)
            .expect("the payload is readable"),
        "the payload does begin with the magic"
    );
    assert_ne!(
        archive.classify(&mut src, 1).expect("the entry is there"),
        Classification::Resource,
        "the magic must not promote a binary entry to a resource"
    );
}

#[test]
fn a_short_or_empty_payload_names_something_or_nothing_and_never_panics() {
    // Third-party bytes, and some of them are malformed deliberately (§6).
    assert_eq!(classified(&stored(b""), 1), Classification::Binary);
    assert_eq!(
        classified(&stored(b"<"), 1),
        Classification::Encoded(Encoding::Text),
        "one angle bracket opens no tag"
    );
    assert_eq!(
        classified(&stored(&[b'<'; 64]), 1),
        Classification::Encoded(Encoding::Text),
        "a payload that is all angle brackets is text and nothing worse"
    );
    assert_eq!(
        classified(&stored(&[0x00, 0xFF]), 1),
        Classification::Binary,
        "two bytes are fewer than any signature"
    );
    assert_eq!(
        classified(&stored(b"RBF"), 1),
        Classification::Encoded(Encoding::Text),
        "three of the four magic bytes are three text bytes"
    );
}

#[test]
fn a_directory_is_the_one_entry_with_no_payload_to_classify() {
    assert_eq!(classified(&stored(b"hello"), 0), Classification::Directory);
}

#[test]
fn a_payload_that_does_not_read_back_is_unknown_binary_rather_than_a_failure() {
    // A deflate stream that is not one. Every walk over an archive asks this of
    // every entry, so a listing that stopped at the first unreadable payload
    // would be useless — `Archive::nested_at`'s rule, for its reason. `verify`
    // is where the payload is reported, and this asserts it still is.
    let bytes = one_file_archive(b"<?xml version=\"1", 16, 0, 4_096);

    assert_eq!(classified(&bytes, 1), Classification::Binary);

    let mut src = Cursor::new(bytes.clone());
    let archive = Archive::open(&mut src, &Unlock::unkeyed()).expect("well formed");
    assert_eq!(
        Listed::at(&mut src, &archive, "", true)
            .expect("a listing does not fail on a payload that does not read")
            .len(),
        1,
        "the entry is still listed, and as itself"
    );
    let problems = rpf_core::Verified::of(&mut src, &archive, &mut Unwatched)
        .expect("the walk itself does not fail")
        .problems;
    assert_eq!(
        problems.len(),
        1,
        "the unreadable payload is still verify's to report: {problems:?}"
    );
}

#[test]
fn a_listing_row_carries_what_the_head_named() {
    let bytes = stored(b"<?xml version=\"1.0\"?>");
    let mut src = Cursor::new(bytes);
    let archive = Archive::open(&mut src, &Unlock::unkeyed()).expect("well formed");
    let rows = Listed::at(&mut src, &archive, "", true).expect("lists");
    assert_eq!(
        rows[0].kind,
        ListedKind::Binary {
            len: 21,
            encoding: Some(Encoding::Xml)
        }
    );
}

// ------------------------------------------------------------------ gated ---

/// The unencrypted sample, by the relative path that addresses it.
/// `docs/corpus.md`.
const SAMPLE: &str = "rmrp_bp16_meringls63amg24/dlc.rpf";

/// The AES-encrypted archive, which is the only one in `assets/` holding a real
/// binary metadata payload. `docs/corpus.md`.
const AES_ARCHIVE: &str = "gtav_aes/des_canister.rpf";

/// Reports a skip, naming the test, the gate that was not there and what it
/// would have read; `RPF_REQUIRE_<GATE>` turns that gate's absence into a
/// failure, so "the suite was green" and "the suite ran" stay different claims
/// (§12).
fn skip<T>(test: &str, gate: &str, reason: &str) -> Option<T> {
    let required = format!("RPF_REQUIRE_{}", gate.trim_start_matches("RPF_"));
    assert!(
        env::var_os(&required).is_none(),
        "{required} is set, but {test} would have skipped: {reason}",
    );
    eprintln!("SKIP {test}: {reason}");
    None
}

/// One corpus archive by its fixed relative path.
fn archive_path(test: &str, relative: &str) -> Option<PathBuf> {
    let Some(root) = env::var_os("RPF_CORPUS") else {
        return skip(test, "RPF_CORPUS", "RPF_CORPUS is not set");
    };
    let path = Path::new(&root).join(relative);
    if path.is_file() {
        Some(path)
    } else {
        skip(
            test,
            "RPF_CORPUS",
            &format!("{} is not a file", path.display()),
        )
    }
}

/// The material a game executable carries: the AES key, and none of the NG
/// values. DR-040.
fn executable_material(test: &str) -> Option<Arc<Material>> {
    let Some(root) = env::var_os("RPF_GAME_EXE") else {
        return skip(test, "RPF_GAME_EXE", "RPF_GAME_EXE is not set");
    };
    let path = Path::new(&root).join("GTA5.exe");
    if !path.is_file() {
        return skip(
            test,
            "RPF_GAME_EXE",
            &format!("{} is not a file", path.display()),
        );
    }
    let mut file = fs::File::open(&path).expect("the executable is readable");
    match Material::extract(&mut file, &mut Unwatched) {
        Ok(material) => Some(Arc::new(material)),
        Err(error) => skip(
            test,
            "RPF_GAME_EXE",
            &format!("{} yielded nothing: {error}", path.display()),
        ),
    }
}

/// Every row of an archive, recursively, as (path, kind name, encoding).
fn walked(bytes: Vec<u8>, unlock: &Unlock) -> Vec<(String, &'static str, Option<Encoding>)> {
    let mut src = Cursor::new(bytes);
    let archive = Archive::open(&mut src, unlock).expect("the archive opens");
    Listed::at(&mut src, &archive, "", true)
        .expect("it lists")
        .into_iter()
        .map(|row| match row.kind {
            ListedKind::Directory { .. } => (row.path, "directory", None),
            ListedKind::Binary { encoding, .. } => (row.path, "binary", encoding),
            ListedKind::Resource { .. } => (row.path, "resource", None),
        })
        .collect()
}

#[test]
#[cfg_attr(no_corpus, ignore = "RPF_CORPUS must name a directory of archives")]
fn the_samples_five_metadata_entries_are_all_plain_xml() {
    // `docs/rpf-format.md`, Metadata encodings: the sample holds none of the
    // binary encodings, and `setup2.xml` carries a byte-order mark. It is the
    // classifier's negative control, and the one archive whose 20 resources do
    // begin with `RSC7` — which changes nothing about how they are classified.
    let test = "the_samples_five_metadata_entries_are_all_plain_xml";
    let Some(path) = archive_path(test, SAMPLE) else {
        return;
    };
    let rows = walked(
        fs::read(&path).expect("the archive is readable"),
        &Unlock::unkeyed(),
    );

    let xml: Vec<&str> = rows
        .iter()
        .filter(|(_, _, encoding)| *encoding == Some(Encoding::Xml))
        .map(|(path, _, _)| path.as_str())
        .collect();
    assert_eq!(
        xml,
        [
            "content.xml",
            "data/carvariations.meta",
            "data/dlctext.meta",
            "data/vehicles.meta",
            "setup2.xml",
        ]
    );

    // The byte-order mark is one of them, and the head is read past it.
    let marked = fs::read(&path).expect("readable");
    let mut src = Cursor::new(marked);
    let archive = Archive::open(&mut src, &Unlock::unkeyed()).expect("opens");
    let (holder, index) = archive.locate(&mut src, "setup2.xml").expect("it is there");
    let contents = holder.extract(&mut src, index).expect("it reads");
    assert_eq!(
        &contents[..3],
        &[0xEF, 0xBB, 0xBF],
        "setup2.xml carries one"
    );

    assert_eq!(
        rows.iter()
            .filter(|(_, kind, _)| *kind == "resource")
            .count(),
        20,
        "and every resource is one by its row, with no encoding of its own"
    );
    assert!(
        rows.iter()
            .all(|(_, kind, encoding)| *kind == "binary" || encoding.is_none())
    );
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn the_aes_archives_manifest_is_a_pso_and_its_resources_are_resources() {
    // The first real binary metadata payload this suite has ever classified:
    // `_manifest.ymf` inside the AES archive is `PSO`, which is exactly what
    // `docs/metadata-encodings.md` measured `.ymf` to carry — 3,623 of them —
    // and what no extension rule would have said, since the same measurement
    // found `.ymf` also carrying `RBF`.
    let test = "the_aes_archives_manifest_is_a_pso_and_its_resources_are_resources";
    let Some(path) = archive_path(test, AES_ARCHIVE) else {
        return;
    };
    let Some(material) = executable_material(test) else {
        return;
    };
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .expect("a corpus path names a file");
    let rows = walked(
        fs::read(&path).expect("the archive is readable"),
        &Unlock::held(material, name),
    );

    assert_eq!(
        rows.iter()
            .filter(|(_, _, encoding)| *encoding == Some(Encoding::Pso))
            .map(|(path, _, _)| path.as_str())
            .collect::<Vec<&str>>(),
        ["_manifest.ymf"]
    );
    assert_eq!(
        rows.iter()
            .filter(|(_, kind, _)| *kind == "resource")
            .count(),
        9,
        "and Rockstar's own resources are resources by their rows alone"
    );
}
