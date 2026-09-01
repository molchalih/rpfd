//! An encrypted archive opens, and says so honestly when it does not.
//!
//! The gated half needs `RPF_CORPUS` and a source of key material, which is
//! extracted from the user's own installation and never travels. An NG
//! archive's key is chosen by its file name and its length, so the corpus
//! archives are addressed by fixed paths and their own file names matter.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; a panic is the reporting mechanism. See the note above"
)]

use std::{
    collections::BTreeMap,
    env, fs,
    io::{Cursor, Read as _, Seek as _, SeekFrom, Write as _},
    path::{Path, PathBuf},
    sync::Arc,
};

use rpf_core::{
    Archive, Bytes, Category, Change, Changes, EntryKind, Error, Manifest, NoWrite, Unlock,
    Unwatched, Verified,
    format::{Version, crypto, rpf7},
    keys::Material,
};

/// The NG-encrypted archive in the corpus, by the path that addresses it.
const NG_ARCHIVE: &str = "gtav_ng/dlc.rpf";

/// The AES-encrypted archive in the corpus, likewise.
const AES_ARCHIVE: &str = "gtav_aes/des_canister.rpf";

/// The AES-encrypted archive whose resources carry a 24-byte header rather than
/// the 16 every other archive here uses.
const AES_24_ARCHIVE: &str = "gtav_aes/des_hosp_ceil2.rpf";

/// The archive whose resources are under its own transform: neither begins a
/// deflate stream in the clear at any measured boundary.
const AES_KEYED_ARCHIVE: &str = "gtav_aes/script_release.rpf";

/// The two resources [`AES_KEYED_ARCHIVE`] holds, and what each inflates to.
const KEYED_RESOURCES: [(&str, usize); 2] = [
    ("pilot_school.ysc", 458_752),
    ("pilotschool_dlc_startup.ysc", 8_192),
];

/// Which of the 101 NG expanded keys `abigail1.ysc` is decrypted with, and
/// which one the binary-entry rule would have chosen for it: the index is
/// `(hash(name) + length + 61) % 101`, so the two lengths choose different keys.
const ON_DISK_KEY: usize = 85;
const CONTENTS_KEY: usize = 13;

/// The two builds of the launcher's own archive — the only archives here under
/// the launcher key — each a path, an entry, directory and file count.
const LAUNCHER_ARCHIVES: [(&str, usize, usize, usize); 2] = [
    ("rockstar_launcher/Launcher.rpf", 118, 19, 99),
    ("rockstar_launcher/Launcher.updated.rpf", 120, 20, 100),
];

/// The executable the launcher key comes from, inside `RPF_GAME_EXE`.
const LAUNCHER_EXE: &str = "Launcher.exe";

/// Reports a skip naming the test, the gate that was not there, and what it
/// would have read; `RPF_REQUIRE_<GATE>` turns that gate's absence into a
/// failure and no other's.
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

/// The key material the memory image carries, scanned once for the whole test
/// binary: an image carries every value this pass looks for but the launcher
/// key, which is in `Launcher.exe` alone. Nothing is written anywhere.
fn scanned() -> Result<Arc<Material>, String> {
    static HELD: std::sync::OnceLock<Result<Arc<Material>, String>> = std::sync::OnceLock::new();
    HELD.get_or_init(|| {
        let named = env::var_os("RPF_GAME_IMAGE").ok_or("RPF_GAME_IMAGE is not set")?;
        let path = PathBuf::from(named);
        if !path.is_file() {
            return Err(format!("{} is not a file", path.display()));
        }
        let mut file =
            fs::File::open(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        match Material::extract(&mut file, &mut Unwatched) {
            Ok(material) if material.ng().is_some() => Ok(Arc::new(material)),
            Ok(_) => Err("the image carries no NG material".to_owned()),
            Err(error) => Err(format!(
                "{} did not yield material: {error}",
                path.display()
            )),
        }
    })
    .clone()
}

/// The same, as a skip that names the test when there is no image.
fn material(test: &str) -> Option<Arc<Material>> {
    match scanned() {
        Ok(material) => Some(material),
        Err(reason) => skip(test, "RPF_GAME_IMAGE", &reason),
    }
}

/// Everything one gated test needs: the archive's bytes, its own file name, and
/// the material.
struct Encrypted {
    bytes: Vec<u8>,
    name: String,
    material: Arc<Material>,
}

impl Encrypted {
    /// The corpus archive at `relative`, with material, or a loud skip.
    fn of(test: &str, relative: &str) -> Option<Self> {
        let path = archive_path(test, relative)?;
        let material = material(test)?;
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .expect("a corpus path names a file");
        Some(Self {
            bytes: fs::read(&path).expect("the archive is readable"),
            name,
            material,
        })
    }

    /// The corpus archive at `relative`, with the material a game executable
    /// carries: the AES key is in every source, so no memory image is needed.
    fn under_aes(test: &str, relative: &str) -> Option<Self> {
        let path = archive_path(test, relative)?;
        let material = executable_material(test)?;
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .expect("a corpus path names a file");
        Some(Self {
            bytes: fs::read(&path).expect("the archive is readable"),
            name,
            material,
        })
    }

    /// What opens it: this material, under this archive's own name.
    fn unlock(&self) -> Unlock {
        Unlock::held(Arc::clone(&self.material), self.name.clone())
    }
}

#[test]
fn an_encrypted_archive_with_no_material_says_it_needs_a_key() {
    // Nothing past the tag is read: the refusal happens first, over sixteen
    // bytes that describe an entry table which is not there.
    for tag in [
        rpf7::ENCRYPTION_NG,
        rpf7::ENCRYPTION_AES,
        rpf7::ENCRYPTION_AES_LAUNCHER,
    ] {
        let mut header = Vec::with_capacity(16);
        header.extend_from_slice(&Version::Rpf7.magic());
        header.extend_from_slice(&1_u32.to_le_bytes());
        header.extend_from_slice(&0_u32.to_le_bytes());
        header.extend_from_slice(&tag.to_le_bytes());

        let error = Archive::open(&mut Cursor::new(header), &Unlock::unkeyed())
            .expect_err("an encrypted archive does not open without a key");
        assert!(
            matches!(error, Error::NeedsKey { tag: found } if found == tag),
            "tag {tag:#010x} gave {error:?}"
        );
        assert_eq!(error.category(), Category::NeedsKey);
        assert_eq!(error.name(), "NeedsKey");
    }
}

#[test]
fn a_tag_names_a_transform_and_the_key_that_runs_it() {
    // `0x0FFFFFF9` and `0x0FFFFFF7` are the same cipher under two different
    // 32-byte keys: the tag selects a key, not an algorithm.
    assert_eq!(
        Version::Rpf7.scheme(rpf7::ENCRYPTION_AES),
        Some(crypto::Scheme::Aes(crypto::AesKey::Rage))
    );
    assert_eq!(
        Version::Rpf7.scheme(rpf7::ENCRYPTION_AES_LAUNCHER),
        Some(crypto::Scheme::Aes(crypto::AesKey::Launcher))
    );
    assert_eq!(
        Version::Rpf7.scheme(rpf7::ENCRYPTION_NG),
        Some(crypto::Scheme::Ng)
    );
    assert!(!Version::Rpf7.is_open(rpf7::ENCRYPTION_AES_LAUNCHER));

    // An unknown tag has no transform and neither has an open one: two
    // situations `None` covers and `is_open` tells apart.
    assert_eq!(Version::Rpf7.scheme(0x0FFF_FFF0), None);
    assert_eq!(Version::Rpf7.scheme(Version::Rpf7.open()), None);

    assert_ne!(
        crypto::Scheme::Aes(crypto::AesKey::Rage).named(),
        crypto::Scheme::Aes(crypto::AesKey::Launcher).named()
    );
}

#[test]
fn an_unkeyed_seam_names_no_archive_and_offers_nothing() {
    let unlock = Unlock::unkeyed();
    assert!(unlock.is_unkeyed());
    assert_eq!(unlock.name(), "");
    // A nested archive takes its own name and keeps its holder's source.
    assert_eq!(unlock.renamed("vehicles.rpf").name(), "vehicles.rpf");
    assert!(unlock.renamed("vehicles.rpf").is_unkeyed());
}

#[test]
fn nothing_the_seam_renders_is_a_key() {
    let rendered = format!("{:?}", Unlock::unkeyed().renamed("dlc.rpf"));
    assert!(rendered.contains("dlc.rpf"), "{rendered}");
    assert!(rendered.contains("Unkeyed"), "{rendered}");
}

#[test]
#[cfg_attr(
    any(no_corpus, no_game_image),
    ignore = "RPF_CORPUS and RPF_GAME_IMAGE must both be set"
)]
fn the_ng_archive_opens_and_every_entry_reads_back() {
    let test = "the_ng_archive_opens_and_every_entry_reads_back";
    let Some(held) = Encrypted::of(test, NG_ARCHIVE) else {
        return;
    };
    let unlock = held.unlock();
    let mut source = Cursor::new(held.bytes.clone());
    let archive = Archive::open(&mut source, &unlock).expect("the NG archive opens");

    assert_eq!(archive.encryption(), rpf7::ENCRYPTION_NG);
    assert_eq!(archive.scheme(), Some("NG"));
    // Seven entries, four of them directories.
    assert_eq!(archive.entries().len(), 7);

    // A wrong key gives neither a name that resolves nor XML.
    let index = archive.find("content.xml").expect("resolves");
    let contents = archive.read(&mut source, index).expect("reads");
    assert!(
        contents.starts_with(b"<?xml"),
        "content.xml did not decrypt to XML"
    );
    assert_eq!(contents.len(), 888, "the declared length is the real one");

    Verified::of(&mut source, &archive, &mut Unwatched)
        .expect("verifies")
        .outcome()
        .expect("every entry of the NG archive reads back");
}

#[test]
#[cfg_attr(
    any(no_corpus, no_game_image),
    ignore = "RPF_CORPUS and RPF_GAME_IMAGE must both be set"
)]
fn a_nested_ng_archive_opens_under_its_own_name() {
    // The key is chosen by the *nested* archive's name and length, not by its
    // holder's, so this fails if the name does not travel with the material.
    let test = "a_nested_ng_archive_opens_under_its_own_name";
    let Some(held) = Encrypted::of(test, NG_ARCHIVE) else {
        return;
    };
    let unlock = held.unlock();
    let mut source = Cursor::new(held.bytes.clone());
    let archive = Archive::open(&mut source, &unlock).expect("opens");

    let (inner, index) = archive
        .locate(&mut source, "x64/levels/gta5/vehicles.rpf/cyclone2.ytd")
        .expect("descends into the nested archive");
    assert_eq!(inner.encryption(), rpf7::ENCRYPTION_NG);
    // A resource whose deflate stream sits in the clear sixteen bytes in.
    let contents = inner.read(&mut source, index).expect("reads");
    assert_eq!(contents.len(), 16_384);
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn the_aes_archive_opens_and_every_entry_reads_back() {
    let test = "the_aes_archive_opens_and_every_entry_reads_back";
    let Some(held) = Encrypted::under_aes(test, AES_ARCHIVE) else {
        return;
    };
    let unlock = held.unlock();
    let mut source = Cursor::new(held.bytes.clone());
    let archive = Archive::open(&mut source, &unlock).expect("the AES archive opens");

    assert_eq!(archive.encryption(), rpf7::ENCRYPTION_AES);
    assert_eq!(archive.scheme(), Some("AES-256"));
    // Ten file entries, one binary and nine resources.
    assert_eq!(archive.entries().len(), 11);

    let index = archive.find("_manifest.ymf").expect("resolves");
    assert_eq!(archive.read(&mut source, index).expect("reads").len(), 852);

    Verified::of(&mut source, &archive, &mut Unwatched)
        .expect("verifies")
        .outcome()
        .expect("every entry of the AES archive reads back");
}

/// The flag words of every resource entry, by path.
fn resource_rows(bytes: &[u8], unlock: &Unlock) -> BTreeMap<String, (u32, u32)> {
    let mut source = Cursor::new(bytes.to_vec());
    let archive = Archive::open(&mut source, unlock).expect("the archive opens");
    (1..u32::try_from(archive.entries().len()).expect("fits"))
        .filter_map(|index| match archive.entry(index).expect("in range").kind {
            EntryKind::Resource {
                system_flags,
                graphics_flags,
                ..
            } => Some((
                archive.path(index).expect("named"),
                (system_flags, graphics_flags),
            )),
            _ => None,
        })
        .collect()
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn the_aes_archives_nine_resources_extract_and_pack_back_with_their_flag_words() {
    // The nine resources carry no `RSC7` header of their own, so the manifest
    // has to record what their rows declared.
    let test = "the_aes_archives_nine_resources_extract_and_pack_back_with_their_flag_words";
    let Some(held) = Encrypted::under_aes(test, AES_ARCHIVE) else {
        return;
    };
    let unlock = held.unlock();
    let mut source = Cursor::new(held.bytes.clone());
    let archive = Archive::open(&mut source, &unlock).expect("the AES archive opens");

    let manifest = Manifest::of(&archive).expect("the manifest derives");
    assert_eq!(
        manifest
            .entries
            .iter()
            .filter(|entry| entry.flags.is_some())
            .count(),
        9,
        "every resource of the archive records its own words"
    );

    // The tree, as `extract` writes it: a resource's file is its payload.
    let mut tree = BTreeMap::new();
    let mut headerless = 0_usize;
    for (spec, index) in rpf_core::specs_of(&archive).expect("specs") {
        let extracted = archive.extract(&mut source, index).expect("extracts");
        let kind = archive.entry(index).expect("in range").kind;
        if matches!(kind, EntryKind::Resource { .. }) && extracted.get(0..4) != Some(b"RSC7") {
            headerless += 1;
        }
        tree.insert(spec.path, extracted);
    }
    assert_eq!(
        headerless, 9,
        "every resource here would carry its own flags, and the manifest's \
         would not be what the pack read"
    );

    let mut out = Cursor::new(Vec::new());
    let held_tree = tree.clone();
    manifest
        .pack_into(
            &mut out,
            &unlock,
            move |wanted: &str| {
                Ok(Cursor::new(
                    held_tree.get(wanted).cloned().unwrap_or_default(),
                ))
            },
            &mut Unwatched,
        )
        .expect("the extracted tree packs back");
    let packed = out.into_inner();

    assert_eq!(
        resource_rows(&packed, &unlock),
        resource_rows(&held.bytes, &unlock),
        "a rebuilt row must declare what the row it came from declared"
    );

    let mut source = Cursor::new(packed);
    let archive = Archive::open(&mut source, &unlock).expect("the packed archive opens again");
    assert_eq!(archive.encryption(), rpf7::ENCRYPTION_AES);
    for (path, expected) in &tree {
        let index = archive.find(path).expect("the entry resolves");
        let extracted = archive.extract(&mut source, index).expect("extracts");
        assert_eq!(&extracted, expected, "{path} changed across the round trip");
    }
    Verified::of(&mut source, &archive, &mut Unwatched)
        .expect("walks")
        .outcome()
        .expect("every entry of the packed archive reads back against its row");
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn a_resource_whose_header_is_twenty_four_bytes_reads_back() {
    // Both resources begin their deflate stream 24 bytes in and neither at 16,
    // which is why the header length is a set rather than a constant.
    let test = "a_resource_whose_header_is_twenty_four_bytes_reads_back";
    let Some(held) = Encrypted::under_aes(test, AES_24_ARCHIVE) else {
        return;
    };
    let unlock = held.unlock();
    let mut source = Cursor::new(held.bytes.clone());
    let archive = Archive::open(&mut source, &unlock).expect("the archive opens");

    // A root, one binary `.ytyp` and two resources.
    assert_eq!(archive.entries().len(), 4);
    for (name, len) in [
        ("des_hosp_ceil2.ydr", 16_384),
        ("des_hosp_ceil2_txd.ytd", 8_192),
    ] {
        let index = archive.find(name).expect("resolves");
        let read = archive
            .read(&mut source, index)
            .unwrap_or_else(|error| panic!("{name} did not read back: {error}"));
        assert_eq!(read.len(), len, "{name} inflated to the wrong length");

        // The stream begins 24 bytes in and nowhere else.
        let payload = archive.extract(&mut source, index).expect("extracts");
        let mut short = flate2::bufread::DeflateDecoder::new(&payload[16..]);
        let mut sunk = Vec::new();
        assert!(
            std::io::copy(&mut short, &mut sunk).is_err(),
            "{name} inflated from 16 as well, so 24 is not what settles it"
        );
    }

    Verified::of(&mut source, &archive, &mut Unwatched)
        .expect("verifies")
        .outcome()
        .expect("every entry of the 24-byte-header archive reads back");
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn a_resource_under_the_archives_own_transform_reads_back() {
    // Both resources here are under the archive's AES transform, so
    // `Archive::resource_stream` recovers a transform as well as a boundary.
    let test = "a_resource_under_the_archives_own_transform_reads_back";
    let Some(held) = Encrypted::under_aes(test, AES_KEYED_ARCHIVE) else {
        return;
    };
    let unlock = held.unlock();
    let mut source = Cursor::new(held.bytes.clone());
    let archive = Archive::open(&mut source, &unlock).expect("the archive opens");

    // A root and two resources, and no binary entry.
    assert_eq!(archive.entries().len(), 3);
    for (name, len) in KEYED_RESOURCES {
        let index = archive.find(name).expect("resolves");
        let read = archive
            .read(&mut source, index)
            .unwrap_or_else(|error| panic!("{name} did not read back: {error}"));
        assert_eq!(read.len(), len, "{name} inflated to the wrong length");

        // With no key applied, neither boundary inflates to the declared
        // length, so it is the transform and not a boundary that settles it.
        let payload = archive.extract(&mut source, index).expect("extracts");
        for header in [16_usize, 24] {
            let stream = payload.get(header..).expect("inside the payload");
            assert_ne!(
                inflated(stream).len(),
                len,
                "{name} inflated in the clear from {header}, so a transform is \
                 not what settles it"
            );
        }
    }

    Verified::of(&mut source, &archive, &mut Unwatched)
        .expect("verifies")
        .outcome()
        .expect("every entry of the keyed-resource archive reads back");
}

#[test]
#[cfg_attr(no_game_image, ignore = "RPF_GAME_IMAGE must be set")]
fn a_resources_ng_key_is_chosen_by_its_length_on_disk() {
    // The NG script archives stay out of the corpus, so what is pinned is the
    // field the key is chosen by: a binary entry keys by the other length.
    let test = "a_resources_ng_key_is_chosen_by_its_length_on_disk";
    let Some(material) = material(test) else {
        return;
    };
    let keyed = |len: u64| {
        crypto::Cipher::new(crypto::Scheme::Ng, &material, "abigail1.ysc", len)
            .expect("the material carries the NG half")
            .key_index()
    };
    assert_ne!(
        keyed(90_775),
        keyed(229_376),
        "the two lengths choose one key, so this test could not tell them apart"
    );
    assert_eq!(keyed(90_775), Some(ON_DISK_KEY), "the on-disk length's key");
    assert_eq!(keyed(229_376), Some(CONTENTS_KEY), "the contents' key");
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn one_pass_of_aes_opens_it_and_a_second_pass_does_not() {
    // Four implementations attest sixteen successive passes for RPF2 through
    // RPF6; RPF7 is one. Decrypting the table of contents in the buffer here
    // makes opening the archive decrypt it a second time.
    let test = "one_pass_of_aes_opens_it_and_a_second_pass_does_not";
    let Some(held) = Encrypted::under_aes(test, AES_ARCHIVE) else {
        return;
    };
    assert_eq!(crypto::AES_PASSES, 1);

    let unlock = held.unlock();
    let cipher = crypto::Cipher::new(
        crypto::Scheme::Aes(crypto::AesKey::Rage),
        &held.material,
        &held.name,
        0,
    )
    .expect("the AES key is in every source");

    // The table of contents begins immediately after the header and the block
    // is sixteen bytes, so the region and the blocks line up.
    let mut twice = held.bytes.clone();
    let table_at = usize::try_from(Version::Rpf7.header_len()).expect("sixteen");
    cipher.apply(twice.get_mut(table_at..).expect("past the header"));

    assert!(
        Archive::open(&mut Cursor::new(held.bytes.clone()), &unlock).is_ok(),
        "one pass is what opens it"
    );
    let error = Archive::open(&mut Cursor::new(twice), &unlock)
        .expect_err("a second pass must not open it");
    assert!(matches!(error, Error::WrongKey { .. }), "{error:?}");
}

#[test]
#[cfg_attr(
    any(no_corpus, no_game_image),
    ignore = "RPF_CORPUS and RPF_GAME_IMAGE must both be set"
)]
fn a_renamed_ng_archive_says_the_material_does_not_open_it() {
    // The material is real and complete; the name it is keyed by is wrong.
    let test = "a_renamed_ng_archive_says_the_material_does_not_open_it";
    let Some(held) = Encrypted::of(test, NG_ARCHIVE) else {
        return;
    };
    let bytes = held.bytes.clone();
    let unlock = Unlock::held(held.material, "not-its-name.rpf");
    let error = Archive::open(&mut Cursor::new(bytes), &unlock)
        .expect_err("the wrong key does not open it");
    let Error::WrongKey { tag, scheme, tried } = error else {
        panic!("expected WrongKey, got {error:?}");
    };
    assert_eq!(tag, rpf7::ENCRYPTION_NG);
    assert_eq!(scheme, "NG");
    assert_eq!(tried, 1);
}

/// The material one named executable inside `RPF_GAME_EXE` carries.
fn material_of(test: &str, named: &str) -> Option<Arc<Material>> {
    let Some(root) = env::var_os("RPF_GAME_EXE") else {
        return skip(test, "RPF_GAME_EXE", "RPF_GAME_EXE is not set");
    };
    let path = Path::new(&root).join(named);
    if !path.is_file() {
        return skip(
            test,
            "RPF_GAME_EXE",
            &format!("{} is not a file", path.display()),
        );
    }
    let mut file = fs::File::open(&path).expect("the executable is readable");
    Some(Arc::new(
        Material::extract(&mut file, &mut Unwatched).expect("the executable carries the material"),
    ))
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn the_launcher_archives_open_and_every_entry_reads_back() {
    // Both builds: a key holding across a repack is what makes it a key.
    let test = "the_launcher_archives_open_and_every_entry_reads_back";
    let Some(material) = material_of(test, LAUNCHER_EXE) else {
        return;
    };
    for (relative, entries, directories, files) in LAUNCHER_ARCHIVES {
        let Some(path) = archive_path(test, relative) else {
            return;
        };
        let bytes = fs::read(&path).expect("the archive is readable");
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .expect("a corpus path names a file");
        let unlock = Unlock::held(Arc::clone(&material), name);
        let mut source = Cursor::new(bytes);
        let archive = Archive::open(&mut source, &unlock).expect("the launcher archive opens");

        assert_eq!(archive.encryption(), rpf7::ENCRYPTION_AES_LAUNCHER);
        assert_eq!(archive.scheme(), Some("AES-256 (launcher)"));
        assert_eq!(archive.entries().len(), entries, "{relative}");

        // Names resolve only if the names blob was decrypted from its own
        // start rather than as part of the entry table.
        let index = archive
            .find("metadata/rdr2/title.rgl")
            .expect("a path the tree holds");
        assert!(!archive.read(&mut source, index).expect("reads").is_empty());
        let index = archive.find("stats.xml").expect("a path the tree holds");
        let stats = archive.read(&mut source, index).expect("reads");
        assert!(
            stats.starts_with(b"<?xml version=\"1.0\" encoding=\"utf-8\"?>"),
            "{relative}: stats.xml does not read as XML"
        );

        let checked = Verified::of(&mut source, &archive, &mut Unwatched).expect("verifies");
        checked
            .outcome()
            .expect("every entry of the launcher archive reads back");
        assert_eq!(
            usize::try_from(checked.checked).expect("fits"),
            files,
            "{relative}"
        );

        let mut dirs = 0_usize;
        let mut binaries = 0_usize;
        for index in 0..u32::try_from(archive.entries().len()).expect("fits") {
            match archive.entry(index).expect("an entry the table holds").kind {
                rpf_core::EntryKind::Directory { .. } => dirs += 1,
                rpf_core::EntryKind::Binary { .. } => binaries += 1,
                rpf_core::EntryKind::Resource { .. } => {
                    panic!("{relative} entry {index} is a resource")
                }
            }
        }
        assert_eq!((dirs, binaries), (directories, files), "{relative}");
    }
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn a_game_install_without_the_launcher_needs_a_key_rather_than_holding_a_wrong_one() {
    // The RAGE key is right there and is not this archive's key, so `WrongKey`
    // would be true and useless: what the holder does is find the launcher.
    let test = "a_game_install_without_the_launcher_needs_a_key_rather_than_holding_a_wrong_one";
    let Some(material) = material_of(test, "GTA5.exe") else {
        return;
    };
    let (relative, ..) = LAUNCHER_ARCHIVES[0];
    let Some(path) = archive_path(test, relative) else {
        return;
    };
    assert!(
        material.launcher().is_none(),
        "a game executable carries the launcher key, so this test proves nothing"
    );

    let bytes = fs::read(&path).expect("the archive is readable");
    let unlock = Unlock::held(material, "Launcher.rpf");
    let error = Archive::open(&mut Cursor::new(bytes), &unlock)
        .expect_err("the RAGE key does not open a launcher archive");
    assert!(
        matches!(error, Error::NeedsKey { tag } if tag == rpf7::ENCRYPTION_AES_LAUNCHER),
        "{error:?}"
    );
    assert_eq!(error.name(), "NeedsKey", "{error:?}");
    assert_eq!(error.category(), Category::NeedsKey);
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn the_tag_chooses_the_key_and_the_rage_key_is_not_it() {
    // `Launcher.exe` carries both keys, so the two transforms below differ in
    // the key alone. Only one of them puts the root directory marker at row 0.
    let test = "the_tag_chooses_the_key_and_the_rage_key_is_not_it";
    let Some(material) = material_of(test, LAUNCHER_EXE) else {
        return;
    };
    let (relative, ..) = LAUNCHER_ARCHIVES[0];
    let Some(path) = archive_path(test, relative) else {
        return;
    };
    let bytes = fs::read(&path).expect("the archive is readable");
    let header = usize::try_from(Version::Rpf7.header_len()).expect("sixteen");
    let row = bytes
        .get(header..header + crypto::CIPHER_BLOCK_LEN)
        .expect("the first entry row");

    let marker_of = |which| {
        let cipher = crypto::Cipher::new(crypto::Scheme::Aes(which), &material, "Launcher.rpf", 0)
            .expect("Launcher.exe carries both keys");
        let mut block = <[u8; crypto::CIPHER_BLOCK_LEN]>::try_from(row).expect("a whole block");
        cipher.apply(&mut block);
        u32::from_le_bytes(
            <[u8; 4]>::try_from(block.get(4..8).expect("the second word")).expect("four bytes"),
        )
    };

    assert_eq!(
        marker_of(crypto::AesKey::Launcher),
        rpf7::DIRECTORY_MARKER,
        "the launcher key does not decrypt the root directory row"
    );
    assert_ne!(
        marker_of(crypto::AesKey::Rage),
        rpf7::DIRECTORY_MARKER,
        "the RAGE key decrypts it too, so the tag chooses nothing"
    );
}

/// The material a game executable carries: no NG values, the rest of it.
fn executable_scanned() -> Result<Arc<Material>, String> {
    static HELD: std::sync::OnceLock<Result<Arc<Material>, String>> = std::sync::OnceLock::new();
    HELD.get_or_init(|| {
        let root = env::var_os("RPF_GAME_EXE").ok_or("RPF_GAME_EXE is not set")?;
        let path = Path::new(&root).join("GTA5.exe");
        if !path.is_file() {
            return Err(format!("{} is not a file", path.display()));
        }
        let mut file =
            fs::File::open(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        Material::extract(&mut file, &mut Unwatched)
            .map(Arc::new)
            .map_err(|error| format!("{} yielded nothing: {error}", path.display()))
    })
    .clone()
}

/// The same, as a skip that names the test when there is no executable.
fn executable_material(test: &str) -> Option<Arc<Material>> {
    match executable_scanned() {
        Ok(material) => Some(material),
        Err(reason) => skip(test, "RPF_GAME_EXE", &reason),
    }
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn material_without_the_ng_half_is_no_candidate_for_an_ng_archive() {
    // An executable carries none of the NG values, so an NG archive is "no
    // material available" rather than "the wrong material".
    let test = "material_without_the_ng_half_is_no_candidate_for_an_ng_archive";
    let Some(path) = archive_path(test, NG_ARCHIVE) else {
        return;
    };
    let Some(from_executable) = executable_material(test) else {
        return;
    };
    assert!(
        from_executable.ng().is_none(),
        "an executable is not supposed to carry the NG material (DR-040)"
    );
    let unlock = Unlock::held(from_executable, "dlc.rpf");
    let mut file = fs::File::open(&path).expect("the archive is readable");
    let error = Archive::open(&mut file, &unlock)
        .expect_err("an AES-only source does not open an NG archive");
    assert!(
        matches!(error, Error::NeedsKey { tag } if tag == rpf7::ENCRYPTION_NG),
        "{error:?}"
    );
}

#[test]
#[cfg_attr(
    any(no_corpus, no_game_image),
    ignore = "RPF_CORPUS and RPF_GAME_IMAGE must both be set"
)]
fn a_truncated_encrypted_table_of_contents_is_refused_rather_than_decoded() {
    // The header still claims seven entries and a names blob; the bytes are gone.
    let test = "a_truncated_encrypted_table_of_contents_is_refused_rather_than_decoded";
    let Some(held) = Encrypted::of(test, NG_ARCHIVE) else {
        return;
    };
    let unlock = held.unlock();
    let mut bytes = held.bytes.clone();
    bytes.truncate(24);
    let error = Archive::open(&mut Cursor::new(bytes), &unlock)
        .expect_err("a truncated archive is not one");
    assert!(
        matches!(error.category(), Category::Corrupt | Category::Io),
        "{error:?}"
    );
}

#[test]
#[cfg_attr(
    any(no_corpus, no_game_image),
    ignore = "RPF_CORPUS and RPF_GAME_IMAGE must both be set"
)]
fn a_tag_that_claims_encryption_over_a_body_that_is_not_says_the_key_is_wrong() {
    // The material is real and it decrypts plaintext into nonsense, which the
    // root directory row catches — so this is `WrongKey`, not a walked tree.
    let test = "a_tag_that_claims_encryption_over_a_body_that_is_not_says_the_key_is_wrong";
    let Some(material) = material(test) else {
        return;
    };
    let Some(sample) = archive_path(test, "rmrp_bp16_meringls63amg24/dlc.rpf") else {
        return;
    };
    let mut file = fs::File::open(&sample).expect("the sample opens");
    let mut head = vec![0_u8; 64 * 1024];
    file.read_exact(&mut head).expect("the sample is not tiny");
    head.get_mut(12..16)
        .expect("a header is sixteen bytes")
        .copy_from_slice(&rpf7::ENCRYPTION_NG.to_le_bytes());

    let unlock = Unlock::held(material, "dlc.rpf");
    let error = Archive::open(&mut Cursor::new(head), &unlock)
        .expect_err("plaintext under an NG tag is not an NG archive");
    assert!(matches!(error, Error::WrongKey { .. }), "{error:?}");
    assert_eq!(error.category(), Category::NeedsKey);
    assert_eq!(error.name(), "WrongKey");
}

#[test]
#[cfg_attr(
    any(no_corpus, no_game_image),
    ignore = "RPF_CORPUS and RPF_GAME_IMAGE must both be set"
)]
fn an_encrypted_payload_streams_and_seeks_the_same_bytes_it_reads_whole() {
    // The decrypting layer holds one block, so the two forms have to agree.
    let test = "an_encrypted_payload_streams_and_seeks_the_same_bytes_it_reads_whole";
    let Some(held) = Encrypted::of(test, NG_ARCHIVE) else {
        return;
    };
    let unlock = held.unlock();
    let bytes = held.bytes.clone();
    let mut source = Cursor::new(bytes.clone());
    let archive = Archive::open(&mut source, &unlock).expect("opens");
    let index = archive.find("setup2.xml").expect("resolves");

    let whole = archive.read(&mut source, index).expect("reads");
    assert!(whole.len() > 64, "a payload worth seeking into");

    let mut streamed = Vec::new();
    archive
        .extracted(Cursor::new(bytes.clone()), index)
        .expect("streams")
        .read_to_end(&mut streamed)
        .expect("streams to the end");
    assert_eq!(streamed, whole, "the stream and the buffer disagree");

    let mut seeked = archive
        .extracted(Cursor::new(bytes), index)
        .expect("streams");
    seeked.seek(SeekFrom::Start(33)).expect("seeks");
    let mut tail = Vec::new();
    seeked.read_to_end(&mut tail).expect("reads the tail");
    assert_eq!(
        tail.as_slice(),
        whole.get(33..).expect("past the start"),
        "a seek into a decrypted payload landed somewhere else"
    );
}

#[test]
#[cfg_attr(no_corpus, ignore = "RPF_CORPUS is not set")]
fn a_cache_is_read_only_when_an_archive_turns_out_to_need_it() {
    // An unencrypted archive opens without the cache directory being looked in.
    let test = "a_cache_is_read_only_when_an_archive_turns_out_to_need_it";
    let Some(sample) = archive_path(test, "rmrp_bp16_meringls63amg24/dlc.rpf") else {
        return;
    };
    let scratch = tempfile::tempdir().expect("a temporary directory");
    let absent = scratch.path().join("never-made");
    let cache = rpf_core::keys::Cache::at(&absent);

    let mut file = fs::File::open(&sample).expect("the sample opens");
    let unlock = Unlock::cached(cache, "dlc.rpf");
    Archive::open(&mut file, &unlock).expect("the unencrypted sample still opens");
    assert!(
        !absent.exists(),
        "opening an unencrypted archive created a key cache"
    );
}

#[test]
#[cfg_attr(
    any(no_corpus, no_game_image),
    ignore = "RPF_CORPUS and RPF_GAME_IMAGE must both be set"
)]
fn a_cache_holding_the_material_opens_the_archive_with_no_flag_anywhere() {
    // Nothing here names a key: only which archive, and where a cache is.
    let test = "a_cache_holding_the_material_opens_the_archive_with_no_flag_anywhere";
    let Some(held) = Encrypted::of(test, NG_ARCHIVE) else {
        return;
    };
    let scratch = tempfile::tempdir().expect("a temporary directory");
    let cache = rpf_core::keys::Cache::at(scratch.path());
    let digest =
        rpf_core::keys::SourceDigest::of(&mut Cursor::new(b"a source".to_vec())).expect("digests");
    cache.store(&digest, &held.material).expect("stores");

    let mut source = Cursor::new(held.bytes);
    let unlock = Unlock::cached(cache, held.name);
    let archive = Archive::open(&mut source, &unlock).expect("the cache opened it");
    assert_eq!(archive.scheme(), Some("NG"));
    assert_eq!(
        archive
            .read(&mut source, archive.find("content.xml").expect("resolves"))
            .expect("reads")
            .len(),
        888
    );
}

#[test]
#[cfg_attr(
    any(no_corpus, no_game_image),
    ignore = "RPF_CORPUS and RPF_GAME_IMAGE must both be set"
)]
fn nothing_an_open_encrypted_archive_prints_is_a_key() {
    // An `Archive` holds the material that opened it and is `Debug`.
    let test = "nothing_an_open_encrypted_archive_prints_is_a_key";
    let Some(held) = Encrypted::of(test, NG_ARCHIVE) else {
        return;
    };
    let aes = *held.material.keys().aes_key();
    let lut = *held.material.keys().hash_lut();
    let ng_key = held
        .material
        .ng()
        .and_then(|ng| ng.expanded_key(0))
        .expect("an image carries the expanded keys")
        .to_vec();
    let table = held
        .material
        .ng()
        .and_then(|ng| ng.decrypt_table(0, 0))
        .expect("an image carries the decrypt tables")
        .to_vec();

    let unlock = held.unlock();
    let mut source = Cursor::new(held.bytes.clone());
    let archive = Archive::open(&mut source, &unlock).expect("opens");
    let printed = format!("{archive:?} {unlock:?}");

    for value in [aes.as_slice(), lut.as_slice(), &ng_key, &table] {
        for encoded in [
            String::from_utf8_lossy(value).into_owned(),
            hex_lower(value),
            hex_lower(value).to_uppercase(),
        ] {
            let probe = encoded.get(..32.min(encoded.len())).unwrap_or_default();
            assert!(
                probe.is_empty() || !printed.contains(probe),
                "a key reached a Debug rendering"
            );
        }
    }
}

/// Lower-case hexadecimal, without depending on a crate the library does not.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[test]
#[cfg_attr(
    any(no_corpus, no_game_image),
    ignore = "RPF_CORPUS and RPF_GAME_IMAGE must both be set"
)]
fn an_encrypted_archive_extracts_the_bytes_a_second_read_agrees_with() {
    let test = "an_encrypted_archive_extracts_the_bytes_a_second_read_agrees_with";
    let Some(held) = Encrypted::of(test, NG_ARCHIVE) else {
        return;
    };
    let unlock = held.unlock();
    let mut source = Cursor::new(held.bytes.clone());
    let archive = Archive::open(&mut source, &unlock).expect("opens");
    let index = archive.find("setup2.xml").expect("resolves");
    let first = archive.read(&mut source, index).expect("reads");
    let second = archive.extract(&mut source, index).expect("extracts");
    assert_eq!(first, second, "the two framings disagree on a binary entry");

    let mut sink = tempfile::NamedTempFile::new().expect("temp file");
    sink.write_all(&first).expect("written");
    assert_eq!(
        fs::read(sink.path()).expect("readable"),
        first,
        "what was written is not what was read"
    );
}

/// The entry of the NG corpus archive every refusal below is asked about.
const NG_ENTRY: &str = "content.xml";

/// What every write path answers about an archive that cannot be written back.
fn refuses_the_write(what: &str, error: &Error, tag: u32, reason: NoWrite) {
    assert!(
        matches!(
            *error,
            Error::CannotWriteEncrypted { tag: found, reason: why }
                if found == tag && why == reason
        ),
        "{what} answered {error:?}"
    );
    assert_eq!(error.category(), Category::Unsupported, "{what}");
    assert_eq!(error.name(), "CannotWriteEncrypted", "{what}");
    // The message names the reason and not only the tag.
    assert!(
        error.to_string().contains(&reason.to_string()),
        "{what}: {error} does not name its reason"
    );
}

#[test]
#[cfg_attr(
    any(no_corpus, no_game_image),
    ignore = "RPF_CORPUS and RPF_GAME_IMAGE must both be set"
)]
fn the_ng_write_refusal_names_material_that_is_missing() {
    // `NoWrite::NoInverse` means this build has nothing to derive the transform
    // from, not that the transform has no forward direction.
    let test = "the_ng_write_refusal_names_material_that_is_missing";
    let Some(held) = Encrypted::of(test, NG_ARCHIVE) else {
        return;
    };
    let unlock = held.unlock();
    let mut source = Cursor::new(held.bytes.clone());
    let archive = Archive::open(&mut source, &unlock).expect("the NG archive opens");
    let tag = archive.encryption();
    assert_eq!(tag, rpf7::ENCRYPTION_NG);

    // With the material the archive is writable and hands out a transform.
    archive
        .writable()
        .expect("an NG archive with its material is writable");
    assert!(
        archive.seal().expect("a seal is derivable").is_some(),
        "an NG archive with its material handed out no forward transform"
    );

    // `pack` opens no archive, so a manifest naming the NG tag is the write
    // path a caller can still reach with no material at all.
    let manifest = rpf_core::Manifest::of(&archive).expect("a manifest describes it");
    let mut out = Cursor::new(Vec::new());
    let error = manifest
        .pack_into(
            &mut out,
            &Unlock::unkeyed(),
            |_: &str| Ok(Cursor::new(Vec::new())),
            &mut Unwatched,
        )
        .expect_err("a pack with nothing to derive the transform from must refuse");
    refuses_the_write("pack", &error, tag, NoWrite::NoInverse);
    assert!(out.into_inner().is_empty(), "a refused pack wrote bytes");

    // `NoInverse` rather than `NeedsKey`: telling an automation to extract a
    // key that is only in a running game's memory is a loop it never leaves.
    assert_ne!(error.category(), Category::NeedsKey);

    // A manifest carries no material, so the tag alone cannot answer.
    let read_back = rpf_core::Manifest::from_json(&manifest.to_json().expect("renders"))
        .expect("an NG manifest reads back rather than being refused at parse time");
    assert_eq!(read_back, manifest);

    // Nothing above wrote anything into the archive's own bytes.
    assert_eq!(
        source.into_inner(),
        held.bytes,
        "a refused write changed the archive"
    );
}

#[test]
#[cfg_attr(
    any(no_corpus, no_game_image),
    ignore = "RPF_CORPUS and RPF_GAME_IMAGE must both be set"
)]
fn an_ng_archive_patched_in_place_opens_again_and_reads_the_new_bytes() {
    // The new contents are deliberately a different length: the NG key index is
    // `(hash(name) + length + 61) % 101`, so the payload goes back under a key
    // the entry did not have before.
    let test = "an_ng_archive_patched_in_place_opens_again_and_reads_the_new_bytes";
    let Some(held) = Encrypted::of(test, NG_ARCHIVE) else {
        return;
    };
    let unlock = held.unlock();
    let mut source = Cursor::new(held.bytes.clone());
    let archive = Archive::open(&mut source, &unlock).expect("the NG archive opens");
    let index = archive.find(NG_ENTRY).expect("content.xml resolves");
    let was = archive.read(&mut source, index).expect("reads");

    // Not compressible, not a whole number of cipher blocks, not the old length.
    let wanted: Vec<u8> = (0..401_u32)
        .map(|n| u8::try_from(n % 251).expect("a byte"))
        .collect();
    assert_ne!(
        wanted.len(),
        was.len(),
        "the new contents are the old length"
    );

    let mut changes = Changes::new();
    changes.set(
        NG_ENTRY,
        Change::Write {
            contents: Arc::new(Bytes::new(wanted.clone())),
            create: false,
            allow_encoding_change: false,
        },
    );
    let plan = rpf_core::plan(&mut source, &archive, &changes).expect("an NG patch is planned");
    let rpf_core::Plan::Fits(patches) = plan else {
        panic!("the edit does not fit: {plan:?}");
    };
    patches.apply(&mut source).expect("the patch applies");

    let reopened = Archive::open(&mut source, &unlock).expect("the patched archive opens again");
    assert_eq!(reopened.encryption(), rpf7::ENCRYPTION_NG);
    let index = reopened.find(NG_ENTRY).expect("resolves");
    assert_eq!(
        reopened.read(&mut source, index).expect("reads"),
        wanted,
        "the patched entry did not read back"
    );
    Verified::of(&mut source, &reopened, &mut Unwatched)
        .expect("verifies")
        .outcome()
        .expect("every entry of the patched NG archive still reads back");
}

#[test]
#[cfg_attr(
    any(no_corpus, no_game_image),
    ignore = "RPF_CORPUS and RPF_GAME_IMAGE must both be set"
)]
fn an_ng_archive_rebuilt_opens_again_with_every_entry_intact() {
    // A rebuild changes the archive's own length, which the table of contents
    // and the names blob are keyed by. The claim is per entry contents.
    let test = "an_ng_archive_rebuilt_opens_again_with_every_entry_intact";
    let Some(held) = Encrypted::of(test, NG_ARCHIVE) else {
        return;
    };
    let unlock = held.unlock();
    let mut source = Cursor::new(held.bytes.clone());
    let archive = Archive::open(&mut source, &unlock).expect("the NG archive opens");

    let mut before = Vec::new();
    let mut fields = Vec::new();
    for index in 0..u32::try_from(archive.entries().len()).expect("small") {
        let entry = archive.entry(index).expect("in range");
        if entry.is_directory() {
            continue;
        }
        let path = archive.path(index).expect("resolves");
        if let rpf_core::EntryKind::Binary { encryption, .. } = entry.kind {
            fields.push((path.clone(), encryption));
        }
        let bytes = archive.extract(&mut source, index).expect("extracts");
        before.push((path, bytes));
    }
    assert!(
        fields.iter().any(|&(_, encryption)| encryption != 0),
        "no binary entry of the NG archive is under the transform, so this \
         claim would hold for a writer that zeroed every field"
    );

    let added = b"added by a rebuild of an NG archive".to_vec();
    let mut changes = Changes::new();
    changes.set(
        "added.txt",
        Change::Write {
            contents: Arc::new(Bytes::new(added.clone())),
            create: true,
            allow_encoding_change: false,
        },
    );

    let mut out = Cursor::new(Vec::new());
    rpf_core::rewrite(
        &mut source,
        &archive,
        &changes,
        &mut out,
        &mut rpf_core::InMemory,
        &mut Unwatched,
    )
    .expect("an NG archive rebuilds");

    // A rebuild that wrote it in the clear would open under `Unlock::unkeyed`.
    let rebuilt = out.into_inner();
    let error = Archive::open(&mut Cursor::new(rebuilt.clone()), &Unlock::unkeyed())
        .expect_err("the rebuilt archive is not in the clear");
    assert!(
        matches!(error, Error::NeedsKey { tag } if tag == rpf7::ENCRYPTION_NG),
        "{error:?}"
    );

    let mut source = Cursor::new(rebuilt);
    let opened = Archive::open(&mut source, &unlock).expect("the rebuilt archive opens");
    assert_eq!(opened.encryption(), rpf7::ENCRYPTION_NG);
    for (path, expected) in &before {
        let index = opened
            .find(path)
            .unwrap_or_else(|error| panic!("{path} is gone: {error}"));
        assert_eq!(
            &opened.extract(&mut source, index).expect("extracts"),
            expected,
            "{path} came back different"
        );
    }
    let index = opened.find("added.txt").expect("the added entry is there");
    assert_eq!(opened.read(&mut source, index).expect("reads"), added);
    for (path, encryption) in &fields {
        let index = opened.find(path).expect("resolves");
        let rpf_core::EntryKind::Binary {
            encryption: found, ..
        } = opened.entry(index).expect("in range").kind
        else {
            panic!("{path} stopped being a binary entry");
        };
        assert_eq!(found, *encryption, "{path}'s encryption field changed");
    }
    Verified::of(&mut source, &opened, &mut Unwatched)
        .expect("verifies")
        .outcome()
        .expect("every entry of the rebuilt NG archive reads back");
}

#[test]
#[cfg_attr(
    any(no_corpus, no_game_image),
    ignore = "RPF_CORPUS and RPF_GAME_IMAGE must both be set"
)]
fn a_tree_extracted_from_an_ng_archive_packs_back_and_opens_again() {
    // The table of contents, the names blob and every payload, each keyed by
    // its own name and its own new length.
    let test = "a_tree_extracted_from_an_ng_archive_packs_back_and_opens_again";
    let Some(held) = Encrypted::of(test, NG_ARCHIVE) else {
        return;
    };
    let unlock = held.unlock();
    let mut source = Cursor::new(held.bytes.clone());
    let archive = Archive::open(&mut source, &unlock).expect("the NG archive opens");
    let manifest = rpf_core::Manifest::of(&archive).expect("a manifest describes it");

    let mut held_files: Vec<(String, Vec<u8>)> = Vec::new();
    for index in 0..u32::try_from(archive.entries().len()).expect("small") {
        if archive.entry(index).expect("in range").is_directory() {
            continue;
        }
        let path = archive.path(index).expect("resolves");
        let bytes = archive.extract(&mut source, index).expect("extracts");
        held_files.push((path, bytes));
    }

    let mut out = Cursor::new(Vec::new());
    let files = held_files.clone();
    manifest
        .pack_into(
            &mut out,
            &unlock,
            move |wanted: &str| {
                let found = files
                    .iter()
                    .find(|(path, _)| path == wanted)
                    .map(|(_, bytes)| bytes.clone())
                    .unwrap_or_default();
                Ok(Cursor::new(found))
            },
            &mut Unwatched,
        )
        .expect("an NG tree packs back");

    let mut packed = Cursor::new(out.into_inner());
    let opened = Archive::open(&mut packed, &unlock).expect("the packed archive opens");
    assert_eq!(opened.encryption(), rpf7::ENCRYPTION_NG);
    for (path, expected) in &held_files {
        let index = opened
            .find(path)
            .unwrap_or_else(|error| panic!("{path} is gone: {error}"));
        assert_eq!(
            &opened.extract(&mut packed, index).expect("extracts"),
            expected,
            "{path} came back different"
        );
    }
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn a_tree_extracted_from_an_aes_archive_packs_back_and_opens_again() {
    // The launcher's is the only archive here with no resource entry, and a
    // tree holding a Rockstar resource does not pack back at all.
    let test = "a_tree_extracted_from_an_aes_archive_packs_back_and_opens_again";
    let Some(material) = material_of(test, LAUNCHER_EXE) else {
        return;
    };
    let (relative, ..) = LAUNCHER_ARCHIVES[0];
    let Some(path) = archive_path(test, relative) else {
        return;
    };
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .expect("a corpus path names a file");
    let unlock = Unlock::held(Arc::clone(&material), name);
    let mut source = Cursor::new(fs::read(&path).expect("the archive is readable"));
    let archive = Archive::open(&mut source, &unlock).expect("the AES archive opens");
    assert_eq!(archive.encryption(), rpf7::ENCRYPTION_AES_LAUNCHER);

    let manifest = rpf_core::Manifest::of(&archive).expect("a manifest describes it");
    let mut tree: Vec<(String, Vec<u8>)> = Vec::new();
    for entry in &manifest.entries {
        let index = archive.find(&entry.path).expect("the entry resolves");
        let bytes = archive.extract(&mut source, index).expect("extracts");
        tree.push((entry.path.clone(), bytes));
    }

    // Through the JSON, because that is what a tree on disk carries.
    let manifest = rpf_core::Manifest::from_json(&manifest.to_json().expect("renders"))
        .expect("an AES manifest is no longer refused at parse time");

    let mut out = Cursor::new(Vec::new());
    manifest
        .pack_into(
            &mut out,
            &unlock,
            |wanted: &str| {
                let found = tree
                    .iter()
                    .find(|(path, _)| path == wanted)
                    .map(|(_, bytes)| bytes.clone())
                    .unwrap_or_default();
                Ok(Cursor::new(found))
            },
            &mut Unwatched,
        )
        .expect("the tree packs back");

    // A pack that wrote it in the clear would open under no material at all.
    let packed = out.into_inner();
    let error = Archive::open(&mut Cursor::new(packed.clone()), &Unlock::unkeyed())
        .expect_err("the packed archive is not in the clear");
    assert!(
        matches!(error, Error::NeedsKey { tag } if tag == rpf7::ENCRYPTION_AES_LAUNCHER),
        "{error:?}"
    );

    let mut source = Cursor::new(packed);
    let opened = Archive::open(&mut source, &unlock).expect("the packed archive opens");
    assert_eq!(opened.encryption(), rpf7::ENCRYPTION_AES_LAUNCHER);
    for (path, expected) in &tree {
        let index = opened
            .find(path)
            .unwrap_or_else(|error| panic!("{path} is gone: {error}"));
        assert_eq!(
            &opened.extract(&mut source, index).expect("extracts"),
            expected,
            "{path} did not survive the pack"
        );
    }
    Verified::of(&mut source, &opened, &mut Unwatched)
        .expect("verifies")
        .outcome()
        .expect("every entry of the packed archive reads back");
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn a_tree_extracted_from_an_aes_archive_needs_a_key_to_pack_back() {
    // With no material, `pack` must refuse rather than write a plaintext
    // archive carrying an encrypted tag, which would open for nobody.
    let test = "a_tree_extracted_from_an_aes_archive_needs_a_key_to_pack_back";
    let Some(held) = Encrypted::under_aes(test, AES_ARCHIVE) else {
        return;
    };
    let mut source = Cursor::new(held.bytes.clone());
    let archive = Archive::open(&mut source, &held.unlock()).expect("opens");
    let manifest = rpf_core::Manifest::of(&archive).expect("a manifest describes it");

    let mut out = Cursor::new(Vec::new());
    let error = manifest
        .pack_into(
            &mut out,
            &Unlock::unkeyed(),
            |_: &str| Ok(Cursor::new(Vec::new())),
            &mut Unwatched,
        )
        .expect_err("a pack with no material does not write an archive");
    assert!(
        matches!(error, Error::NeedsKey { tag } if tag == rpf7::ENCRYPTION_AES),
        "{error:?}"
    );
    assert_eq!(error.category(), Category::NeedsKey);
    assert!(out.into_inner().is_empty(), "a refused pack wrote bytes");
}

/// The AES archive, its unlock, and a cursor over a copy of its bytes; the
/// corpus file itself is never opened for writing.
fn aes_copy(test: &str) -> Option<(Encrypted, Unlock, Cursor<Vec<u8>>)> {
    let held = Encrypted::under_aes(test, AES_ARCHIVE)?;
    let unlock = held.unlock();
    let source = Cursor::new(held.bytes.clone());
    Some((held, unlock, source))
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn a_resource_put_back_leaves_an_aes_archive_byte_identical() {
    // A resource is written through untouched, so its row has to be sealed
    // back to the exact sixteen bytes the producer wrote. Nothing re-deflates.
    let test = "a_resource_put_back_leaves_an_aes_archive_byte_identical";
    let Some((held, unlock, mut source)) = aes_copy(test) else {
        return;
    };
    let original = held.bytes.clone();
    let archive = Archive::open(&mut source, &unlock).expect("the AES archive opens");

    // Every resource of it, which is nine of the ten file entries.
    let mut changes = Changes::new();
    let mut resources = 0_u32;
    for index in 0..u32::try_from(archive.entries().len()).expect("small") {
        let entry = archive.entry(index).expect("in range");
        if !matches!(entry.kind, rpf_core::EntryKind::Resource { .. }) {
            continue;
        }
        let path = archive.path(index).expect("resolves");
        let bytes = archive.extract(&mut source, index).expect("extracts");
        changes.set(
            path,
            Change::Write {
                contents: Arc::new(Bytes::new(bytes)),
                create: false,
                allow_encoding_change: false,
            },
        );
        resources = resources.saturating_add(1);
    }
    assert_eq!(resources, 9, "the corpus archive's shape changed");

    let plan = rpf_core::plan(&mut source, &archive, &changes).expect("an AES patch is planned");
    let rpf_core::Plan::Fits(patches) = plan else {
        panic!("putting a resource back does not fit: {plan:?}");
    };
    patches.apply(&mut source).expect("the patch applies");

    assert_eq!(
        source.get_ref(),
        &original,
        "putting every resource back changed the archive's bytes"
    );
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn an_aes_archive_patched_in_place_opens_again_and_reads_the_new_bytes() {
    // `_manifest.ymf` is the one binary entry, it is deflated, and its own
    // encryption field says it is under the transform.
    let test = "an_aes_archive_patched_in_place_opens_again_and_reads_the_new_bytes";
    let Some((_, unlock, mut source)) = aes_copy(test) else {
        return;
    };
    let archive = Archive::open(&mut source, &unlock).expect("the AES archive opens");
    let index = archive.find("_manifest.ymf").expect("resolves");
    let was = archive.read(&mut source, index).expect("reads");
    assert_eq!(was.len(), 852);

    // Not compressible and not a multiple of the cipher block, so the tail runs.
    let wanted: Vec<u8> = (0..401_u32)
        .map(|n| u8::try_from(n % 251).unwrap())
        .collect();
    let mut changes = Changes::new();
    changes.set(
        "_manifest.ymf",
        Change::Write {
            contents: Arc::new(Bytes::new(wanted.clone())),
            create: false,
            allow_encoding_change: false,
        },
    );

    let plan = rpf_core::plan(&mut source, &archive, &changes).expect("an AES patch is planned");
    let rpf_core::Plan::Fits(patches) = plan else {
        panic!("the edit does not fit: {plan:?}");
    };
    patches.apply(&mut source).expect("the patch applies");

    // A table of contents whose row was not resealed does not parse, and a
    // payload that was not sealed does not inflate.
    let reopened = Archive::open(&mut source, &unlock).expect("the patched archive opens again");
    assert_eq!(reopened.encryption(), rpf7::ENCRYPTION_AES);
    let index = reopened.find("_manifest.ymf").expect("resolves");
    assert_eq!(
        reopened.read(&mut source, index).expect("reads"),
        wanted,
        "the patched entry did not read back"
    );
    Verified::of(&mut source, &reopened, &mut Unwatched)
        .expect("verifies")
        .outcome()
        .expect("every entry of the patched archive still reads back");
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn an_aes_archive_rebuilt_opens_again_with_every_entry_intact() {
    // A rebuild lays the archive out afresh, so it seals three kinds of region.
    // The claim is per entry contents: the bytes differ by construction.
    let test = "an_aes_archive_rebuilt_opens_again_with_every_entry_intact";
    let Some((_, unlock, mut source)) = aes_copy(test) else {
        return;
    };
    let archive = Archive::open(&mut source, &unlock).expect("the AES archive opens");

    let mut before = Vec::new();
    let mut fields = Vec::new();
    for index in 0..u32::try_from(archive.entries().len()).expect("small") {
        let entry = archive.entry(index).expect("in range");
        if entry.is_directory() {
            continue;
        }
        let path = archive.path(index).expect("resolves");
        if let rpf_core::EntryKind::Binary { encryption, .. } = entry.kind {
            fields.push((path.clone(), encryption));
        }
        let bytes = archive.extract(&mut source, index).expect("extracts");
        before.push((path, bytes));
    }
    // The field itself is compared, not only the bytes: a writer that zeroed it
    // and wrote in the clear would round-trip through our own reader.
    assert!(
        fields.iter().any(|&(_, encryption)| encryption != 0),
        "no binary entry of the AES archive is under the transform, so this \
         claim would hold for a writer that zeroed every field"
    );

    let added = b"added by a rebuild of an encrypted archive".to_vec();
    let mut changes = Changes::new();
    changes.set(
        "added.txt",
        Change::Write {
            contents: Arc::new(Bytes::new(added.clone())),
            create: true,
            allow_encoding_change: false,
        },
    );

    let mut out = Cursor::new(Vec::new());
    rpf_core::rewrite(
        &mut source,
        &archive,
        &changes,
        &mut out,
        &mut rpf_core::InMemory,
        &mut Unwatched,
    )
    .expect("an AES archive rebuilds");

    // A rebuild that wrote it in the clear would open under `Unlock::unkeyed`.
    let rebuilt = out.into_inner();
    let error = Archive::open(&mut Cursor::new(rebuilt.clone()), &Unlock::unkeyed())
        .expect_err("the rebuilt archive is not in the clear");
    assert!(
        matches!(error, Error::NeedsKey { tag } if tag == rpf7::ENCRYPTION_AES),
        "{error:?}"
    );

    let mut source = Cursor::new(rebuilt);
    let opened = Archive::open(&mut source, &unlock).expect("the rebuilt archive opens");
    assert_eq!(opened.encryption(), rpf7::ENCRYPTION_AES);
    for (path, expected) in &before {
        let index = opened
            .find(path)
            .unwrap_or_else(|error| panic!("{path} is gone: {error}"));
        assert_eq!(
            &opened.extract(&mut source, index).expect("extracts"),
            expected,
            "{path} did not survive the rebuild"
        );
    }
    for (path, encryption) in &fields {
        let index = opened.find(path).expect("resolves");
        assert!(
            matches!(
                opened.entry(index).expect("in range").kind,
                rpf_core::EntryKind::Binary { encryption: wrote, .. } if wrote == *encryption
            ),
            "{path}'s per-entry encryption field was not carried through"
        );
    }
    let index = opened.find("added.txt").expect("the added entry resolves");
    assert_eq!(opened.read(&mut source, index).expect("reads"), added);

    Verified::of(&mut source, &opened, &mut Unwatched)
        .expect("verifies")
        .outcome()
        .expect("every entry of the rebuilt archive reads back");
}

/// [`AES_KEYED_ARCHIVE`], its unlock, and a cursor over a copy of its bytes:
/// [`aes_copy`]'s counterpart for the one archive whose resources are keyed.
fn keyed_copy(test: &str) -> Option<(Encrypted, Unlock, Cursor<Vec<u8>>)> {
    let held = Encrypted::under_aes(test, AES_KEYED_ARCHIVE)?;
    let unlock = held.unlock();
    let source = Cursor::new(held.bytes.clone());
    Some((held, unlock, source))
}

/// Each of [`KEYED_RESOURCES`] as it sits on disk, and the change set that
/// writes every one of them back unaltered.
fn keyed_resources_put_back(
    archive: &Archive,
    source: &mut Cursor<Vec<u8>>,
) -> (Vec<(&'static str, Vec<u8>)>, Changes) {
    let mut on_disk = Vec::new();
    let mut changes = Changes::new();
    for (name, len) in KEYED_RESOURCES {
        let index = archive.find(name).expect("resolves");
        assert!(
            matches!(
                archive.entry(index).expect("in range").kind,
                rpf_core::EntryKind::Resource { .. }
            ),
            "{name} is not a resource, so this test is about something else"
        );
        assert_eq!(
            archive.read(source, index).expect("reads").len(),
            len,
            "{name} did not read back before anything was written"
        );
        let payload = archive.extract(source, index).expect("extracts");
        changes.set(
            archive.path(index).expect("resolves"),
            Change::Write {
                contents: Arc::new(Bytes::new(payload.clone())),
                create: false,
                allow_encoding_change: false,
            },
        );
        on_disk.push((name, payload));
    }
    (on_disk, changes)
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn a_keyed_resource_crosses_both_write_paths_as_it_sits_on_disk() {
    // `build::is_sealed` answers `false` for a resource because the writer is
    // handed the payload as it sits on disk, not because it is in the clear —
    // and here those bytes are under the archive's own transform.
    let test = "a_keyed_resource_crosses_both_write_paths_as_it_sits_on_disk";
    let Some((held, unlock, mut source)) = keyed_copy(test) else {
        return;
    };
    let original = held.bytes.clone();
    let archive = Archive::open(&mut source, &unlock).expect("the keyed archive opens");
    assert_eq!(
        archive.entries().len(),
        3,
        "the corpus archive's shape changed"
    );

    // The payload bytes are the same bytes, so the archive is the same archive.
    let (on_disk, changes) = keyed_resources_put_back(&archive, &mut source);

    let plan = rpf_core::plan(&mut source, &archive, &changes).expect("a keyed patch is planned");
    let rpf_core::Plan::Fits(patches) = plan else {
        panic!("putting a keyed resource back does not fit: {plan:?}");
    };
    patches.apply(&mut source).expect("the patch applies");
    assert_eq!(
        source.get_ref(),
        &original,
        "putting a keyed resource back changed the archive's bytes"
    );

    // The other write path: the added entry is what makes it structural.
    let added = b"added by a rebuild of a keyed-resource archive".to_vec();
    let mut changes = Changes::new();
    changes.set(
        "added.txt",
        Change::Write {
            contents: Arc::new(Bytes::new(added.clone())),
            create: true,
            allow_encoding_change: false,
        },
    );
    let mut out = Cursor::new(Vec::new());
    rpf_core::rewrite(
        &mut source,
        &archive,
        &changes,
        &mut out,
        &mut rpf_core::InMemory,
        &mut Unwatched,
    )
    .expect("a keyed-resource archive rebuilds");

    let rebuilt = out.into_inner();
    let error = Archive::open(&mut Cursor::new(rebuilt.clone()), &Unlock::unkeyed())
        .expect_err("the rebuilt archive is not in the clear");
    assert!(
        matches!(error, Error::NeedsKey { tag } if tag == rpf7::ENCRYPTION_AES),
        "{error:?}"
    );

    let mut source = Cursor::new(rebuilt);
    let opened = Archive::open(&mut source, &unlock).expect("the rebuilt archive opens");
    for (name, payload) in &on_disk {
        let index = opened
            .find(name)
            .unwrap_or_else(|error| panic!("{name} is gone: {error}"));
        assert_eq!(
            &opened.extract(&mut source, index).expect("extracts"),
            payload,
            "{name} was not written back as it sat on disk"
        );
    }
    // The payload still decrypts and inflates: a resource, not a matching blob.
    for (name, len) in KEYED_RESOURCES {
        let index = opened.find(name).expect("resolves");
        assert_eq!(
            opened.read(&mut source, index).expect("reads").len(),
            len,
            "{name} no longer inflates to what its flag words declare"
        );
    }
    let index = opened.find("added.txt").expect("the added entry resolves");
    assert_eq!(opened.read(&mut source, index).expect("reads"), added);

    Verified::of(&mut source, &opened, &mut Unwatched)
        .expect("verifies")
        .outcome()
        .expect("every entry of the rebuilt keyed-resource archive reads back");
}

/// An unencrypted archive holding one encrypted one — the shape every AES
/// archive on this machine is in, and one the corpus has no example of.
fn holding(inner: &[u8], named: &str) -> Vec<u8> {
    let files = vec![rpf_core::FileSpec {
        path: named.to_owned(),
        kind: rpf_core::FileKind::Binary {
            storage: rpf_core::Storage::Stored,
            encryption: 0,
        },
    }];
    let mut out = Cursor::new(Vec::new());
    let payload = inner.to_vec();
    rpf_core::build(
        &mut out,
        Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(payload.clone())),
        &mut Unwatched,
    )
    .expect("the outer archive builds");
    out.into_inner()
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn an_encrypted_archive_nested_in_a_plain_one_is_counted_whether_it_opens_or_not() {
    // The count is a fact about the archive, `locked` one about this machine.
    let test = "an_encrypted_archive_nested_in_a_plain_one_is_counted_whether_it_opens_or_not";
    let Some(held) = Encrypted::under_aes(test, AES_ARCHIVE) else {
        return;
    };
    let outer = holding(&held.bytes, "des_canister.rpf");

    // With the material: it opens, and everything inside it is walked.
    let mut source = Cursor::new(outer.clone());
    let unlock = Unlock::held(Arc::clone(&held.material), "outer.rpf");
    let archive = Archive::open(&mut source, &unlock).expect("the outer archive opens");
    let summary = rpf_core::Summary::of(&mut source, &archive, "").expect("summarises");
    assert_eq!(summary.nested_archives, 1);
    assert_eq!(summary.locked_archives, 0);
    let rows = rpf_core::Listed::at(&mut source, &archive, "", true).expect("lists");
    assert_eq!(rows.len(), 11, "one entry, and the ten inside it");
    Verified::of(&mut source, &archive, &mut Unwatched)
        .expect("verifies")
        .outcome()
        .expect("everything nested reads back");

    // Without it: the same count, and the refusal named rather than swallowed.
    let mut source = Cursor::new(outer);
    let archive = Archive::open(&mut source, &Unlock::unkeyed()).expect("the outer archive opens");
    let summary = rpf_core::Summary::of(&mut source, &archive, "").expect("summarises");
    assert_eq!(
        summary.nested_archives, 1,
        "the count is the archive's, not the cache's"
    );
    assert_eq!(summary.locked_archives, 1);

    let rows = rpf_core::Listed::at(&mut source, &archive, "", true).expect("lists");
    assert_eq!(
        rows.len(),
        1,
        "the archive it could not open is still a file"
    );

    let verified = Verified::of(&mut source, &archive, &mut Unwatched).expect("verifies");
    let problem = verified
        .problems
        .first()
        .unwrap_or_else(|| panic!("a verify that never descended reported clean"));
    assert_eq!(problem.path, "des_canister.rpf");
    assert!(
        matches!(problem.error, Error::NeedsKey { tag } if tag == rpf7::ENCRYPTION_AES),
        "{:?}",
        problem.error
    );
    // Exit 5 and not 4: the archive is intact.
    let outcome = verified
        .outcome()
        .expect_err("a verify that skipped is not clean");
    assert_eq!(outcome.category(), Category::NeedsKey);
    assert_eq!(outcome.name(), "NeedsKey");
}

/// Raw DEFLATE, as the format uses it: no zlib header, a window of -15.
fn inflated(stream: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut decoder = flate2::read::DeflateDecoder::new(stream);
    let _ = decoder.read_to_end(&mut out);
    out
}

/// What one entry's sub-block tail is worth: the on-disk length, what the read
/// inflates to with it carried through, and with it padded to a whole block.
fn tail_two_ways(held: &Encrypted, scheme: crypto::Scheme, named: &str) -> (u64, usize, usize) {
    let mut source = Cursor::new(held.bytes.clone());
    let archive = Archive::open(&mut source, &held.unlock()).expect("opens");
    let index = archive.find(named).expect("resolves");
    let (at, on_disk) = archive.payload_at(index).expect("span");
    let contents = archive.read(&mut source, index).expect("reads");

    let start = usize::try_from(at).expect("fits");
    let end = start
        .checked_add(usize::try_from(on_disk).expect("fits"))
        .expect("fits");
    let payload = held.bytes.get(start..end).expect("inside the archive");
    // The key for a payload is the entry's base name and uncompressed length.
    let cipher = crypto::Cipher::new(
        scheme,
        &held.material,
        named,
        u64::try_from(contents.len()).expect("fits"),
    )
    .expect("the material runs this transform");

    let mut carried = payload.to_vec();
    cipher.apply(&mut carried);

    // The other reading: the tail zero-padded to a whole block, decrypted, and
    // the first `tail` bytes taken back.
    let tail = usize::try_from(on_disk % 16).expect("under sixteen");
    let mut padded = carried.clone();
    let mut block = [0_u8; 16];
    let from = payload.len().checked_sub(tail).expect("a tail is shorter");
    block
        .get_mut(..tail)
        .expect("a block holds a tail")
        .copy_from_slice(payload.get(from..).expect("the tail"));
    cipher.apply(&mut block);
    padded
        .get_mut(from..)
        .expect("the tail")
        .copy_from_slice(block.get(..tail).expect("as many bytes back"));

    assert_eq!(
        contents.len(),
        inflated(&carried).len(),
        "{named}: the archive's own read is not the carried-through reading"
    );
    (on_disk, inflated(&carried).len(), inflated(&padded).len())
}

#[test]
#[cfg_attr(
    any(no_corpus, no_game_image),
    ignore = "RPF_CORPUS and RPF_GAME_IMAGE must both be set"
)]
fn a_sub_block_tail_is_carried_through_rather_than_padded() {
    // Two of the three payloads in the NG archive end mid-block, and the two
    // readings disagree: carried through inflates to the declared length.
    let test = "a_sub_block_tail_is_carried_through_rather_than_padded";
    let Some(ng) = Encrypted::of(test, NG_ARCHIVE) else {
        return;
    };
    assert_eq!(
        tail_two_ways(&ng, crypto::Scheme::Ng, "content.xml"),
        (358, 888, 857),
        "content.xml: 358 bytes on disk, a 6-byte tail"
    );
    assert_eq!(
        tail_two_ways(&ng, crypto::Scheme::Ng, "setup2.xml"),
        (415, 940, 934),
        "setup2.xml: 415 bytes on disk, a 15-byte tail"
    );

    let Some(aes) = Encrypted::of(test, AES_ARCHIVE) else {
        return;
    };
    assert_eq!(
        tail_two_ways(
            &aes,
            crypto::Scheme::Aes(crypto::AesKey::Rage),
            "_manifest.ymf"
        ),
        (311, 852, 886),
        "_manifest.ymf: 311 bytes on disk, a 7-byte tail"
    );
}

/// Every archive reachable from `archive` to any depth, with entry 0 checked.
fn root_rows<R: std::io::Read + std::io::Seek>(
    src: &mut R,
    archive: &Archive,
    at: &str,
) -> (u32, u32) {
    let (mut seen, mut directories) = (1_u32, 0_u32);
    if archive.entry(0).is_ok_and(rpf_core::Entry::is_directory) {
        directories += 1;
    } else {
        eprintln!("{at}: entry 0 is not the root directory");
    }
    for index in 0..u32::try_from(archive.entries().len()).unwrap_or(u32::MAX) {
        let nested = archive.nested_at(src, index).expect("sniffs");
        if let rpf_core::archive::Nested::Open(nested) = nested {
            let path = archive.path(index).unwrap_or_default();
            let (below, roots) = root_rows(src, &nested, &format!("{at}/{path}"));
            seen += below;
            directories += roots;
        }
    }
    (seen, directories)
}

#[test]
#[cfg_attr(
    any(no_corpus, no_game_image),
    ignore = "RPF_CORPUS and RPF_GAME_IMAGE must both be set"
)]
fn entry_zero_is_the_root_directory_in_every_archive_here() {
    // `Archive::parse` decides a key by one 32-bit word, at row 0, that no file
    // entry can produce.
    let test = "entry_zero_is_the_root_directory_in_every_archive_here";
    let Some(material) = material(test) else {
        return;
    };
    let Some(root) = env::var_os("RPF_CORPUS") else {
        return;
    };

    let mut archives = 0_u32;
    let mut roots = 0_u32;
    let mut files = 0_u32;
    let mut unopened = 0_u32;
    let mut stack = vec![PathBuf::from(&root)];
    while let Some(directory) = stack.pop() {
        let Ok(reading) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in reading.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|kind| kind != "rpf") {
                continue;
            }
            files += 1;
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            let mut file = fs::File::open(&path).expect("readable");
            let unlock = Unlock::held(Arc::clone(&material), name);
            // The launcher tag is the one this walk does not open: a memory
            // image carries no launcher key. Those archives are counted.
            let Ok(archive) = Archive::open(&mut file, &unlock) else {
                unopened += 1;
                continue;
            };
            let (seen, directories) = root_rows(&mut file, &archive, &path.display().to_string());
            archives += seen;
            roots += directories;
        }
    }

    eprintln!(
        "{files} files ({unopened} that this material does not open), {archives} \
         archives, {roots} with a root directory at entry 0"
    );
    assert!(files >= 3, "the corpus holds fewer archives than expected");
    assert_eq!(
        archives, roots,
        "an archive here does not put the root directory at entry 0"
    );
}

/// A sixteen-byte RPF7 header and nothing after it, under `tag`.
fn empty_archive(tag: u32) -> Vec<u8> {
    let mut header = Vec::with_capacity(16);
    header.extend_from_slice(&Version::Rpf7.magic());
    header.extend_from_slice(&0_u32.to_le_bytes());
    header.extend_from_slice(&0_u32.to_le_bytes());
    header.extend_from_slice(&tag.to_le_bytes());
    header
}

#[test]
#[cfg_attr(no_executables, ignore = "RPF_GAME_EXE is not set")]
fn an_encrypted_archive_with_no_entries_answers_what_an_open_one_answers() {
    // `entryCount == 0` leaves no root directory row for a key to be judged by,
    // and a key failure would be reported about an archive no key applies to.
    let test = "an_encrypted_archive_with_no_entries_answers_what_an_open_one_answers";
    let Some(material) = executable_material(test) else {
        return;
    };

    let unlock = Unlock::held(material, "empty.rpf");
    let mut encrypted = Cursor::new(empty_archive(rpf7::ENCRYPTION_AES));
    let archive =
        Archive::open(&mut encrypted, &unlock).expect("an empty archive is not a refusal");
    assert_eq!(archive.encryption(), rpf7::ENCRYPTION_AES);
    assert_eq!(archive.scheme(), Some("AES-256"));
    assert_eq!(archive.entries().len(), 0);

    // The same header under `OPEN`, which is the answer this one has to match.
    let mut open = Cursor::new(empty_archive(Version::Rpf7.open()));
    let plain = Archive::open(&mut open, &Unlock::unkeyed()).expect("opens");
    assert_eq!(plain.entries().len(), 0);

    let refused = archive.entry(0).expect_err("there is no entry 0");
    let plainly = plain.entry(0).expect_err("there is no entry 0");
    assert_eq!(refused.name(), plainly.name());
    assert_eq!(refused.category(), plainly.category());
    assert_eq!(refused.to_string(), plainly.to_string());
    assert!(
        matches!(
            refused,
            Error::NoSuchEntry {
                index: 0,
                entry_count: 0
            }
        ),
        "{refused:?}"
    );
}

#[test]
#[cfg_attr(
    any(no_corpus, no_game_image),
    ignore = "RPF_CORPUS and RPF_GAME_IMAGE must both be set"
)]
fn the_hash_chooses_the_key_a_brute_force_over_all_of_them_finds() {
    // The index is `(hash(name) + length + 61) % 101`, checked against a brute
    // force; it is linear in the length, so `len + delta` selects each key once.
    let test = "the_hash_chooses_the_key_a_brute_force_over_all_of_them_finds";
    let Some(held) = Encrypted::of(test, NG_ARCHIVE) else {
        return;
    };
    let len = u64::try_from(held.bytes.len()).expect("fits");
    assert_eq!(len, 6_144, "the corpus NG archive is not the one measured");

    let header = usize::try_from(Version::Rpf7.header_len()).expect("sixteen");
    let row = held
        .bytes
        .get(header..header.saturating_add(16))
        .expect("the first entry row");

    let mut opened: Vec<usize> = Vec::new();
    let mut chosen: Vec<usize> = Vec::new();
    for delta in 0..101_u64 {
        let cipher =
            crypto::Cipher::new(crypto::Scheme::Ng, &held.material, "dlc.rpf", len + delta)
                .expect("the material carries the NG half");
        let key = cipher.key_index().expect("an NG cipher chose a key");
        chosen.push(key);

        let mut probe = [0_u8; 16];
        probe.copy_from_slice(row);
        cipher.apply(&mut probe);
        let marker = u32::from_le_bytes([probe[4], probe[5], probe[6], probe[7]]);
        if marker == rpf7::DIRECTORY_MARKER {
            opened.push(key);
        }
    }

    chosen.sort_unstable();
    chosen.dedup();
    assert_eq!(chosen.len(), 101, "the 101 keys are not all reachable");
    assert_eq!(
        opened,
        vec![62],
        "exactly one of the 101 keys puts the root directory row at entry 0"
    );

    // The hash folds case — the lookup table's doing — so either spelling works.
    for name in ["dlc.rpf", "DLC.RPF", "Dlc.Rpf"] {
        let cipher = crypto::Cipher::new(crypto::Scheme::Ng, &held.material, name, len)
            .expect("the material carries the NG half");
        assert_eq!(cipher.key_index(), Some(62), "{name}");
    }
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn a_resource_in_the_clear_is_not_read_through_the_archives_key() {
    // The control for the keyed-resource test: every resource here is in the
    // clear, so the reader's bytes are what it inflates to with no key applied.
    let test = "a_resource_in_the_clear_is_not_read_through_the_archives_key";
    let Some(held) = Encrypted::under_aes(test, AES_ARCHIVE) else {
        return;
    };
    let mut source = Cursor::new(held.bytes.clone());
    let archive = Archive::open(&mut source, &held.unlock()).expect("opens");
    assert_eq!(
        archive.scheme(),
        Some("AES-256"),
        "not an encrypted archive"
    );

    let mut resources = 0_u32;
    for index in 0..u32::try_from(archive.entries().len()).expect("fits") {
        let rpf_core::EntryKind::Resource { compressed_len, .. } =
            archive.entry(index).expect("an entry the table holds").kind
        else {
            continue;
        };
        resources += 1;
        let (at, _) = archive.payload_at(index).expect("span");
        let header = usize::try_from(rpf_core::format::resource::RESOURCE_HEADER_LEN).expect("16");
        let from = usize::try_from(at).expect("fits").saturating_add(header);
        let len = usize::try_from(compressed_len)
            .expect("fits")
            .saturating_sub(header);
        let stream = held
            .bytes
            .get(from..from.saturating_add(len))
            .expect("inside the archive");

        let contents = archive.read(&mut source, index).expect("reads");
        assert_eq!(
            inflated(stream),
            contents,
            "entry {index} is not what its payload inflates to in the clear"
        );

        // The same bytes with the transform applied, as a keyed binary entry.
        let cipher = crypto::Cipher::new(
            crypto::Scheme::Aes(crypto::AesKey::Rage),
            &held.material,
            archive.name(index).expect("named"),
            u64::try_from(contents.len()).expect("fits"),
        )
        .expect("the AES key is in every source");
        let mut decrypted = stream.to_vec();
        cipher.apply(&mut decrypted);
        assert_ne!(
            inflated(&decrypted).len(),
            contents.len(),
            "entry {index}: decrypting a resource gave the same answer, so this proves nothing"
        );
    }
    assert_eq!(resources, 9, "the AES archive holds nine resource entries");
}
