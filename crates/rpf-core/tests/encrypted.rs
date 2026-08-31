//! R3.6: an encrypted archive opens, and says so honestly when it does not.
//!
//! Two halves, and they are different kinds of evidence.
//!
//! The **ungated** half runs everywhere and is about the contract: what an
//! encrypted archive answers when no key material is available, what the seam
//! offers when there is none, and that none of the new surface can print a key.
//! None of it needs a key or an archive.
//!
//! The **gated** half runs only where `RPF_CORPUS` names a directory holding
//! the two encrypted archives `docs/corpus.md` lists and `RPF_GAME_IMAGE` names
//! a memory image carrying the NG material. That is one machine, for DR-006's
//! reason: key material is extracted from the user's own installation and never
//! travels, so continuous integration can never run this half. The backlog
//! plans around that rather than discovering it late.
//!
//! **The archives are addressed by a fixed relative path, and their own file
//! names matter.** An NG archive's key is chosen by its file name and its
//! length (`docs/rpf-format.md`, Encryption), so a corpus entry that is renamed
//! stops opening — which is why `gtav_ng/dlc.rpf` is a directory named for the
//! pack around a file still called `dlc.rpf`.
//!
//! `clippy.toml`'s `allow-*-in-tests` settings reach `#[cfg(test)]` modules and
//! not this directory: an integration test is its own crate with no
//! `cfg(test)`. `docs/conventions.md` §15's exception is spelled out here.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; a panic is the reporting mechanism. See the note above"
)]

use std::{
    env, fs,
    io::{Cursor, Read as _, Seek as _, SeekFrom, Write as _},
    path::{Path, PathBuf},
    sync::Arc,
};

use rpf_core::{
    Archive, Bytes, Category, Change, Changes, Error, Unlock, Unwatched, Verified,
    format::{Version, crypto, rpf7},
    keys::Material,
};

/// The NG-encrypted archive in the corpus, by the relative path that addresses
/// it. `docs/corpus.md`.
const NG_ARCHIVE: &str = "gtav_ng/dlc.rpf";

/// The AES-encrypted archive in the corpus, likewise.
const AES_ARCHIVE: &str = "gtav_aes/des_canister.rpf";

/// The AES-encrypted archive whose resources carry a **24-byte** header rather
/// than the 16 every other archive here uses. `docs/corpus.md`.
///
/// It is in the corpus for one reason: it is the smallest archive on either
/// install, 4,096 bytes, whose payloads begin their deflate stream anywhere but
/// 16 bytes in. `docs/backlog.md` Q14, population 1.
const AES_24_ARCHIVE: &str = "gtav_aes/des_hosp_ceil2.rpf";

/// The two builds of the Rockstar Games Launcher's own archive, which are the
/// only archives here under the launcher key. `docs/corpus.md`.
///
/// Each row is the path, the entry count, the directories and the files, all
/// measured 2026-08-30. The pair is one fixture: it is what established the
/// block size and the absence of chaining before any key was in hand.
const LAUNCHER_ARCHIVES: [(&str, usize, usize, usize); 2] = [
    ("rockstar_launcher/Launcher.rpf", 118, 19, 99),
    ("rockstar_launcher/Launcher.updated.rpf", 120, 20, 100),
];

/// The executable the launcher key comes from, inside `RPF_GAME_EXE`.
const LAUNCHER_EXE: &str = "Launcher.exe";

/// Reports a skip, naming the test, the gate that was not there, and what it
/// would have read.
///
/// `RPF_REQUIRE_<GATE>` turns **that** gate's absence into a failure and no
/// other's, which is what stops a green suite from being confused with a suite
/// that ran (§12). It used to require all three at once, so asking for a corpus
/// failed a test that only wanted an image and the message named neither.
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

/// The key material the memory image carries, scanned **once** for the whole
/// test binary.
///
/// One pass over a 65 MB image is about five seconds at `--release` and a good
/// deal longer unoptimised (DR-040), and every gated test below wants the same
/// material. An image carries 375 of the 376 values this pass looks for: the
/// launcher key is in `Launcher.exe` and nowhere else (DR-042). Nothing is written anywhere: the material lives in this process
/// and dies with it, which is what DR-006 is about.
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
    /// The corpus archive at `relative`, with material, or `None` and a loud
    /// skip.
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

    /// The corpus archive at `relative`, with the material a game
    /// **executable** carries.
    ///
    /// The AES key is in every source there is, so an AES archive needs no
    /// memory image and this gate is `RPF_CORPUS` with `RPF_GAME_EXE`. DR-040.
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

// ---------------------------------------------------------------- ungated ---

#[test]
fn an_encrypted_archive_with_no_material_says_it_needs_a_key() {
    // The state every machine without a game install is in, and the one R2.6
    // rests on. Nothing past the tag is read: the sixteen bytes below describe
    // an entry table that is not there, and the refusal happens first.
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
    // `0x0FFFFFF9` and `0x0FFFFFF7` are the **same** cipher under two different
    // 32-byte keys — the tag selects a key, not an algorithm
    // (`docs/rpf-format.md`, Encryption, `verified`; DR-042). Both are the AES
    // scheme, and they are not the same scheme, which is the whole of the
    // routing this build does.
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

    // A tag that means nothing here still has no transform, and an unencrypted
    // one has none either — two situations `None` covers and `is_open` tells
    // apart.
    assert_eq!(Version::Rpf7.scheme(0x0FFF_FFF0), None);
    assert_eq!(Version::Rpf7.scheme(Version::Rpf7.open()), None);

    // Named apart, because a caller told the key it has is the wrong one has
    // two different things to do about it.
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
    // DR-020, at the surface this change added. `Unlock` is the only new public
    // type that can hold material, and the only thing it will say about itself
    // is which archive it is for.
    let rendered = format!("{:?}", Unlock::unkeyed().renamed("dlc.rpf"));
    assert!(rendered.contains("dlc.rpf"), "{rendered}");
    assert!(rendered.contains("Unkeyed"), "{rendered}");
}

// ------------------------------------------------------------------ gated ---

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
    // Measured 2026-08-30 on `update/x64/dlcpacks/patchday28g9ecng/dlc.rpf`,
    // 6,144 bytes: seven entries, four of them directories.
    assert_eq!(archive.entries().len(), 7);

    // The decrypted names are names, and the decrypted payload is XML — which
    // is the whole claim. A wrong key gives neither.
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
    // A resource: 16,384 bytes of texture dictionary, whose deflate stream sits
    // in the clear sixteen bytes into the payload.
    let contents = inner.read(&mut source, index).expect("reads");
    assert_eq!(contents.len(), 16_384);
}

#[test]
// The AES key is in every source there is, executables included (DR-040), so
// what an AES archive needs is `RPF_GAME_EXE` and not the memory image. Both of
// these were gated on the image, which meant the Q3 measurement below never ran
// on a machine that had everything it needed to check it.
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
    // Measured 2026-08-30: ten file entries, one binary and nine resources.
    assert_eq!(archive.entries().len(), 11);

    let index = archive.find("_manifest.ymf").expect("resolves");
    assert_eq!(archive.read(&mut source, index).expect("reads").len(), 852);

    Verified::of(&mut source, &archive, &mut Unwatched)
        .expect("verifies")
        .outcome()
        .expect("every entry of the AES archive reads back");
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn a_resource_whose_header_is_twenty_four_bytes_reads_back() {
    // `docs/backlog.md` Q14, population 1, and the reason
    // `format::resource::RESOURCE_HEADER_LENS` is a set rather than a constant.
    // Both resources here begin their deflate stream 24 bytes into the payload,
    // and neither begins one at 16: a reader that assumed the `RSC7` header's
    // own length read nothing out of this archive at all.
    //
    // The synthetic half of this is `crates/rpf-core/tests/resource.rs`, which
    // runs with no corpus. This is the archive the measurement came from.
    let test = "a_resource_whose_header_is_twenty_four_bytes_reads_back";
    let Some(held) = Encrypted::under_aes(test, AES_24_ARCHIVE) else {
        return;
    };
    let unlock = held.unlock();
    let mut source = Cursor::new(held.bytes.clone());
    let archive = Archive::open(&mut source, &unlock).expect("the archive opens");

    // Measured 2026-08-30: a root, one binary `.ytyp` and two resources.
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

        // The stream begins 24 bytes in and nowhere else: the payload as the
        // archive holds it does not inflate from 16.
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
fn one_pass_of_aes_opens_it_and_a_second_pass_does_not() {
    // `docs/backlog.md` Q3, enforced rather than stated. Sixteen successive
    // passes is the reading four implementations attest for RPF2 through RPF6;
    // RPF7 is **one**, measured on all 43 archives here that carry the tag.
    //
    // The experiment: decrypt this archive's table of contents in the buffer,
    // so that opening it decrypts a second time. If two passes were right, the
    // doubly-decrypted form would be the one that opens. It is not.
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
    // The failure DR-041 exists to separate from `NeedsKey`. The material is
    // real and complete; the name it is keyed by is wrong, which is exactly
    // what renaming an NG archive does. Nothing here is malformed, so reporting
    // it as corrupt would name the wrong person (DR-010).
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
///
/// `Launcher.exe` is an executable in a directory of executables, read by the
/// same scan for the same kind of value as `GTA5.exe`, so it is gated on the
/// same variable rather than on a fourth one. What tells the two apart is the
/// per-file skip below, which names the file that was not there — a machine
/// with a game and no launcher skips loudly and passes. DR-042.
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
    // R3.6 for the tag that was unidentified until 2026-08-30. Both builds,
    // because the key holding across a repack is the claim that makes it a key
    // rather than a coincidence, and because the pair is the corpus row.
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

        // Names resolve, which is the names blob having been decrypted from its
        // own start rather than as part of the entry table — and a payload
        // reads as itself, which no wrong key produces.
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
    // The answer a machine with a game and no Rockstar Games Launcher gets, and
    // the one thing about this change that is a decision rather than a
    // measurement. The RAGE key is right there and it is not this archive's
    // key, so `WrongKey` would be true of the material and useless as an
    // instruction: what the holder does is install the launcher or point at its
    // executable, which is extraction. DR-010, DR-041, DR-042.
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
    // The fact the whole change rests on, checked where nothing else can check
    // it: `Launcher.exe` carries **both** keys, so the two transforms below
    // differ in the key alone — same cipher, same mode, same one pass. Only one
    // of them puts the root directory marker at row 0. A build that quietly
    // handed back the RAGE key for either tag would pass every other test here
    // and fail this one.
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

/// The material a game executable carries, which is the AES key and the hash
/// lookup table and none of the NG values.
///
/// A third gate, because it names a third thing: `RPF_GAME_EXE` is a directory
/// of executables and `RPF_GAME_IMAGE` is one memory image, and a machine can
/// have either without the other. DR-040.
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
    // An executable's material carries the AES key and none of the NG values
    // (DR-040), so pointing it at an NG archive is "no material available"
    // rather than "the wrong material" — there is nothing to try. `NeedsKey` is
    // the honest answer, and it is the one that says what to go and do.
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
    // §12: the malformed case on a parsing surface reached before every check
    // that already existed. The header still claims seven entries and a names
    // blob; the bytes that would hold them are gone.
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
    // §12 again, from the other side: an unencrypted table of contents behind
    // an encrypted tag. The material is real and it decrypts plaintext into
    // nonsense, which the root directory row catches — so this is `WrongKey`
    // and not a tree walked out of garbage.
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
    // §7 and R3.9: the decrypting layer holds one block, so the streaming form
    // and the whole-buffer form have to agree byte for byte, and a seek into
    // the middle has to land where the whole read says it does.
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
// Only the unencrypted sample, so only `RPF_CORPUS`: the whole claim is that a
// cache is *not* read, and material would prove nothing about that.
#[cfg_attr(no_corpus, ignore = "RPF_CORPUS is not set")]
fn a_cache_is_read_only_when_an_archive_turns_out_to_need_it() {
    // The property `Unlock::cached` exists for, and the one that keeps R2.6
    // true now that the library can consult a cache at all: an unencrypted
    // archive opens without the cache directory being so much as looked in.
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
    // §1 and DR-041: the seam a frontend uses. Nothing here names a key — the
    // caller says which archive and where a cache is, and the archive opens.
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
    // DR-020 re-checked at the one place a key now reaches: an `Archive` holds
    // the material that opened it, and it is `Debug`. Every value the image
    // carries is searched for in what it prints, raw and in three encodings.
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

/// Lower-case hexadecimal, so a test can say what it looked for without
/// depending on a crate the library does not.
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
    // §8's rule applied to the new path: what comes out has to be stable, and
    // the two framings have to agree about a binary entry — for which the file
    // outside the archive is what it means.
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

// ------------------------------------------------------- the write refusal ---

/// Every change a write path can be asked for, by the name a report uses.
///
/// One table so that a path added later has to be added here rather than
/// quietly go unchecked.
fn every_change() -> Vec<(&'static str, Changes)> {
    let mut replace = Changes::new();
    replace.set(
        "_manifest.ymf",
        Change::Write {
            contents: Arc::new(Bytes::new(b"plain text".to_vec())),
            create: false,
            allow_encoding_change: false,
        },
    );
    let mut create = Changes::new();
    create.set(
        "added.txt",
        Change::Write {
            contents: Arc::new(Bytes::new(b"plain text".to_vec())),
            create: true,
            allow_encoding_change: false,
        },
    );
    let mut remove = Changes::new();
    remove.set("_manifest.ymf", Change::Remove { recursive: false });
    let mut rename = Changes::new();
    rename.set("_manifest.ymf", Change::RenameTo("renamed.ymf".to_owned()));
    let mut directory = Changes::new();
    directory.set("added", Change::MakeDirectory);
    vec![
        ("write", replace),
        ("create", create),
        ("remove", remove),
        ("rename", rename),
        ("mkdir", directory),
    ]
}

/// What every write path answers about an archive that cannot be written back.
fn refuses_the_write(what: &str, error: &Error, tag: u32) {
    assert!(
        matches!(*error, Error::CannotWriteEncrypted { tag: found } if found == tag),
        "{what} answered {error:?}"
    );
    assert_eq!(error.category(), Category::Unsupported, "{what}");
    assert_eq!(error.name(), "CannotWriteEncrypted", "{what}");
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn no_write_path_touches_an_encrypted_archive() {
    // The failure this exists for: `plan` decided a patch fitted, `apply`
    // wrote plaintext into a region the format requires to be ciphertext, and
    // the command exited 0 over an archive that no longer opened. R4.7 is the
    // inverse transform and it is unwritten, so every write path refuses ahead
    // of the first byte. DR-041.
    let test = "no_write_path_touches_an_encrypted_archive";
    let Some(held) = Encrypted::under_aes(test, AES_ARCHIVE) else {
        return;
    };
    let unlock = held.unlock();
    let original = held.bytes.clone();
    let mut source = Cursor::new(held.bytes.clone());
    let archive = Archive::open(&mut source, &unlock).expect("the AES archive opens");
    let tag = archive.encryption();
    assert_eq!(tag, rpf7::ENCRYPTION_AES);

    for (what, changes) in every_change() {
        // Patching in place, which is the one that wrote into the live file.
        let error = rpf_core::plan(&mut source, &archive, &changes)
            .err()
            .unwrap_or_else(|| panic!("{what}: plan did not refuse"));
        refuses_the_write(&format!("plan {what}"), &error, tag);

        // Rebuilding, which would have written the archive out as `OPEN` with
        // every payload in the clear.
        let mut out = Cursor::new(Vec::new());
        let error = rpf_core::rewrite(
            &mut source,
            &archive,
            &changes,
            &mut out,
            &mut rpf_core::InMemory,
            &mut Unwatched,
        )
        .err()
        .unwrap_or_else(|| panic!("{what}: rewrite did not refuse"));
        refuses_the_write(&format!("rewrite {what}"), &error, tag);
        assert!(
            out.into_inner().is_empty(),
            "{what}: a refused rebuild wrote bytes"
        );
    }

    // The resolution the daemon accepts a buffered change by, so an editor is
    // told at the edit rather than at the save.
    for (what, changes) in every_change() {
        for (path, change) in &changes {
            let error = rpf_core::allows(&mut source, &archive, &Changes::new(), path, change)
                .err()
                .unwrap_or_else(|| panic!("{what}: allows did not refuse"));
            refuses_the_write(&format!("allows {what}"), &error, tag);
        }
    }

    // "Returned an error" and "did not write" are different claims, so both
    // are made. The source is the archive's own bytes and nothing here has a
    // handle on anything else.
    assert_eq!(
        source.into_inner(),
        original,
        "a refused write changed the archive"
    );
}

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn a_tree_extracted_from_an_encrypted_archive_will_not_pack_back() {
    // `pack` never opens the archive it replaces — it builds from a tree — so
    // the refusal is the manifest's, which records the tag the tree came out
    // of. Exit 9 and not 5: no key material writes this back.
    let test = "a_tree_extracted_from_an_encrypted_archive_will_not_pack_back";
    let Some(held) = Encrypted::under_aes(test, AES_ARCHIVE) else {
        return;
    };
    let mut source = Cursor::new(held.bytes.clone());
    let archive = Archive::open(&mut source, &held.unlock()).expect("opens");
    let manifest = rpf_core::Manifest::of(&archive).expect("a manifest describes it");
    let error = rpf_core::Manifest::from_json(&manifest.to_json().expect("renders"))
        .expect_err("an encrypted manifest does not pack back");
    refuses_the_write("manifest", &error, archive.encryption());
}

// -------------------------------------------------- the nested archive gap ---

/// An unencrypted archive holding one encrypted one, which is the shape every
/// AES archive on this machine is in: all 43 of them are nested, and not one
/// sits on a disk in its own right (`docs/rpf-format.md`, Encryption).
///
/// Built here rather than taken from the corpus, because the corpus has no
/// unencrypted archive holding an encrypted one and this is the arrangement the
/// answer depends on.
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
    // The sniff answered `None` for every failure but `TooDeep`, so an
    // encrypted nested archive was invisible: `info` said `nested 0`, `ls -R`
    // stopped at it and `verify` reported clean over the largest entry there
    // was. Before key material could be present that was uniformly true; after
    // it, the same walk gave two different answers depending on what a cache
    // held. Now the count is a fact about the archive and `locked` is the fact
    // about this machine. DR-041.
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
    // Exit 5 and not 4: the archive is intact and the person holding it is the
    // one who can act. DR-010.
    let outcome = verified
        .outcome()
        .expect_err("a verify that skipped is not clean");
    assert_eq!(outcome.category(), Category::NeedsKey);
    assert_eq!(outcome.name(), "NeedsKey");
}

// -------------------------------------------------------------- the tail ---

/// Raw DEFLATE, as the format uses it: a zlib stream with the two-byte header
/// removed, inflated with a window of -15. `docs/rpf-format.md`, Compression.
fn inflated(stream: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut decoder = flate2::read::DeflateDecoder::new(stream);
    let _ = decoder.read_to_end(&mut out);
    out
}

/// What one entry's sub-block tail is worth, measured two ways.
///
/// Answers the entry's on-disk length, what the archive's own read inflates to
/// — the tail carried through — and what it inflates to if the tail is
/// decrypted as though it had been padded to a whole block. Two readings of the
/// same bytes, and only one of them can be the format's.
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
    // The key for a payload is the entry's own base name and its uncompressed
    // length. `docs/rpf-format.md`, Encryption.
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
    // the first `tail` bytes taken back. `Cipher::apply` transforms a whole
    // block and leaves a tail, so a sixteen-byte buffer is how that reading is
    // spelled with the same cipher.
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
    // `docs/rpf-format.md`, Encryption, promoted from `secondary` on 2026-08-30
    // by this test. It was written as unmeasurable — "every `namesLength`
    // observed here is a multiple of 16" — which is true of the names blob and
    // says nothing about payloads, and a payload is where the rule is exercised
    // constantly: two of the three payloads in the NG archive end mid-block.
    //
    // The experiment is decisive because the two readings disagree about the
    // deflate stream: carried through, it inflates to exactly the length the
    // entry declares; padded, it inflates to a different length entirely.
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

// ------------------------------------------------- the root directory row ---

/// Every archive reachable from `archive`, counted, with entry 0 checked.
///
/// The walk is the archive itself and every archive nested in it, to any depth.
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
    // The fact `Archive::parse` decides a key by: one 32-bit word no file entry
    // can produce, at row 0 (DR-041). It was cited in the source and in the
    // decision record as `verified` while `docs/rpf-format.md` carried it as a
    // bare sentence under the Layout table with no Status column at all —
    // which is the citation `AGENTS.md` forbids, on the one check that decides
    // whether a decryption was right.
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
            // The Rockstar Games Launcher's `0x0FFFFFF7` is the one tag this
            // walk does not open, and since 2026-08-30 that is a fact about the
            // material rather than about the tag: a memory image carries the
            // RAGE key and the NG values and **not** the launcher key, which is
            // in `Launcher.exe` alone (DR-042). The archives it cannot open are
            // counted and named rather than passed over.
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

// ------------------------------------------------------ the empty archive ---

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
    // `entryCount == 0` gives an empty entry table, so there is no root
    // directory row and nothing for a key to be judged by. That left the
    // candidate loop into `Error::WrongKey` carrying `tried: 1` — a count taken
    // before any candidate ran — so a caller was told "the material you have is
    // wrong" about an archive no material has anything to do with, at exit 5,
    // which is the number that tells an automation to run `keys extract` again.
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

    // The same header under `OPEN`, which is the answer this one has to match:
    // both are archives with no entries, and neither is a key failure.
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

// ----------------------------------------------------------- the key index ---

#[test]
#[cfg_attr(
    any(no_corpus, no_game_image),
    ignore = "RPF_CORPUS and RPF_GAME_IMAGE must both be set"
)]
fn the_hash_chooses_the_key_a_brute_force_over_all_of_them_finds() {
    // `docs/rpf-format.md`, Encryption: the index is
    // `(hash(name) + length + 61) % 101`, and the hash's own five constants are
    // what compute it. Established the way the row says it was — by brute force
    // first and arithmetic second — so this is the arithmetic being checked
    // against an answer that did not come from it.
    //
    // Every one of the 101 keys is reachable through the public seam without a
    // second spelling of the transform: the index is linear in the length, so
    // `len + delta` for `delta` in `0..101` selects each key exactly once.
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

    // And the arithmetic agrees with the brute force, which is the whole claim.
    // The hash folds case — the lookup table's doing, since nothing in the code
    // lower-cases anything — so the same name in either spelling chooses it.
    for name in ["dlc.rpf", "DLC.RPF", "Dlc.Rpf"] {
        let cipher = crypto::Cipher::new(crypto::Scheme::Ng, &held.material, name, len)
            .expect("the material carries the NG half");
        assert_eq!(cipher.key_index(), Some(62), "{name}");
    }
}

// ------------------------------------------------ the resource in the clear ---

#[test]
#[cfg_attr(
    any(no_corpus, no_executables),
    ignore = "RPF_CORPUS and RPF_GAME_EXE must both be set"
)]
fn a_resource_payload_is_never_under_the_archives_transform() {
    // `docs/rpf-format.md`, Encryption, `verified`, and the rule was encoded in
    // `archive.rs` twice with no test at all — so a change that started
    // decrypting resources would have shown up as an archive that stopped
    // loading rather than as a red test.
    //
    // The experiment is the raw one: inflate the payload straight out of the
    // file, sixteen bytes in, with no key applied at all, and compare it with
    // what the archive answers. Then apply the transform and show that it does
    // *not* inflate — so the first result is a fact and not a coincidence.
    let test = "a_resource_payload_is_never_under_the_archives_transform";
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

        // The same bytes with the transform applied, which is what would happen
        // if a resource were treated like a keyed binary entry.
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
