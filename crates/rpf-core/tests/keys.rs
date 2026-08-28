//! Key extraction: what a game executable is asked for, and what it answers.
//!
//! Two halves, and they are not the same kind of evidence.
//!
//! The **corpus-free** half runs everywhere. It is about the contract: a source
//! carrying none of the anchored values is refused by name and by count, never
//! answered with half a value, and the failure classifies as something a caller
//! can act on.
//!
//! The **executable-gated** half runs only where `RPF_GAME_EXE` names a
//! directory holding the game executables, which is one machine. It is the
//! measurement: which values are in them, where, and whether two builds of the
//! same game agree. It asserts on **digests and offsets** and never on a key —
//! DR-006, which is also why no test here writes anything it extracted to a
//! path the repository can reach.
//!
//! `clippy.toml`'s `allow-*-in-tests` settings reach `#[cfg(test)]` modules and
//! not this directory: an integration test is its own crate with no
//! `cfg(test)`. `docs/conventions.md` §15's exception is therefore spelled here.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; a panic is the reporting mechanism. See the note above"
)]

use std::{
    env, fs,
    io::Cursor,
    path::{Path, PathBuf},
};

use rpf_core::{
    Category, Error,
    keys::{
        AES_KEY_LEN, Cache, HASH_LUT_LEN, Keys, NG_COLUMNS, NG_DECRYPT_TABLE_COUNT,
        NG_DECRYPT_TABLE_LEN, NG_EXPANDED_KEY_COUNT, NG_EXPANDED_KEY_LEN, NG_ROUNDS, NgKeys,
        SourceDigest,
    },
};
use sha2::{Digest, Sha256};

/// The digest a test is allowed to say out loud about a key.
fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Reports a skip, naming the test and what it would have read.
///
/// The same shape as the corpus tests use, and for the same reason: a green
/// suite and a suite that ran must not be different claims.
/// `RPF_REQUIRE_GAME_EXE` turns the skip into a failure.
fn skip<T>(test: &str, reason: &str) -> Option<T> {
    assert!(
        env::var_os("RPF_REQUIRE_GAME_EXE").is_none(),
        "RPF_REQUIRE_GAME_EXE is set, but {test} would have skipped: {reason}",
    );
    eprintln!("SKIP {test}: {reason}");
    None
}

/// One of the game executables, or `None` with a reason on stderr.
fn executable(test: &str, name: &str) -> Option<PathBuf> {
    let Some(root) = env::var_os("RPF_GAME_EXE") else {
        return skip(test, "RPF_GAME_EXE is not set");
    };
    let path = Path::new(&root).join(name);
    if path.is_file() {
        Some(path)
    } else {
        skip(test, &format!("{} is not a file", path.display()))
    }
}

/// What [`Keys::extract`] found in one executable, said in what may be said.
struct Measured {
    aes_key: String,
    aes_key_offset: u64,
    hash_lut: String,
    hash_lut_offset: u64,
}

fn measure(test: &str, name: &str) -> Option<Measured> {
    let path = executable(test, name)?;
    let bytes = fs::read(&path).expect("the executable is readable");
    let keys = Keys::extract(&mut Cursor::new(bytes)).expect("the executable carries the material");
    let measured = Measured {
        aes_key: digest(keys.aes_key()),
        aes_key_offset: keys.aes_key_offset(),
        hash_lut: digest(keys.hash_lut()),
        hash_lut_offset: keys.hash_lut_offset(),
    };
    eprintln!(
        "{name}: aes key sha256 {} at {:#x}; hash lut sha256 {} at {:#x}",
        measured.aes_key, measured.aes_key_offset, measured.hash_lut, measured.hash_lut_offset
    );
    Some(measured)
}

#[test]
fn a_source_carrying_nothing_is_refused_by_name_and_by_count() {
    let nothing = vec![0_u8; 1 << 16];
    let refused = Keys::extract(&mut Cursor::new(nothing));
    match refused {
        Err(Error::UnrecognisedExecutable {
            what,
            found,
            wanted,
        }) => {
            assert_eq!(found, 0);
            assert_eq!(wanted, 2);
            assert!(
                what.contains("AES key"),
                "the failure does not name the material: {what}"
            );
        }
        other => panic!("expected UnrecognisedExecutable, got {other:?}"),
    }
}

#[test]
fn an_unrecognised_executable_is_not_the_callers_fault_to_fix() {
    // The file is intact and this build is what cannot read it, which is the
    // same shape as an RPF version we do not implement. DR-010.
    let refused = Keys::extract(&mut Cursor::new(vec![0_u8; 4096]))
        .expect_err("nothing is in an empty buffer");
    assert_eq!(refused.category(), Category::Unsupported);
}

#[test]
fn an_empty_source_is_refused_rather_than_read_past() {
    let refused = Keys::extract(&mut Cursor::new(Vec::new()));
    assert!(matches!(
        refused,
        Err(Error::UnrecognisedExecutable { found: 0, .. })
    ));
}

#[test]
fn the_lengths_are_the_ones_the_format_uses() {
    // §3: the lengths are format facts and are defined once. A test that reads
    // them back is what stops a definition drifting silently.
    assert_eq!(AES_KEY_LEN, 32, "AES-256 takes a 32-byte key");
    assert_eq!(HASH_LUT_LEN, 256, "the NG hash lookup table is 256 bytes");
    assert_eq!(
        NG_EXPANDED_KEY_LEN, 272,
        "an expanded key is 17 rounds of 16"
    );
    assert_eq!(NG_EXPANDED_KEY_COUNT, 101);
    assert_eq!(
        NG_DECRYPT_TABLE_LEN, 1024,
        "a table is 256 words of four bytes"
    );
    assert_eq!(
        NG_DECRYPT_TABLE_COUNT,
        NG_ROUNDS * NG_COLUMNS,
        "the table count is one per column per round, not a number of its own"
    );
    assert_eq!(NG_DECRYPT_TABLE_COUNT, 272);
}

#[test]
fn the_ng_material_is_refused_whole_rather_than_in_part() {
    let refused = NgKeys::extract(&mut Cursor::new(vec![0_u8; 1 << 16]));
    match refused {
        Err(Error::UnrecognisedExecutable {
            what,
            found,
            wanted,
        }) => {
            assert_eq!(found, 0);
            assert_eq!(
                wanted,
                u32::try_from(NG_EXPANDED_KEY_COUNT + NG_DECRYPT_TABLE_COUNT).unwrap(),
                "the count asked for is not the number of values there are"
            );
            assert!(what.contains("NG"), "the failure does not name NG: {what}");
        }
        other => panic!("expected UnrecognisedExecutable, got {other:?}"),
    }
}

#[test]
#[cfg_attr(no_executables, ignore = "RPF_GAME_EXE is not set")]
fn the_legacy_executable_carries_the_material() {
    let test = "the_legacy_executable_carries_the_material";
    let Some(measured) = measure(test, "GTA5.exe") else {
        return;
    };
    assert!(
        measured.aes_key_offset > 0 && measured.hash_lut_offset > 0,
        "a value was reported at offset zero, which is the PE header"
    );
}

#[test]
#[cfg_attr(no_executables, ignore = "RPF_GAME_EXE is not set")]
fn the_enhanced_executable_carries_the_material() {
    let test = "the_enhanced_executable_carries_the_material";
    let Some(measured) = measure(test, "GTA5_Enhanced.exe") else {
        return;
    };
    assert!(measured.aes_key_offset > 0 && measured.hash_lut_offset > 0);
}

#[test]
#[cfg_attr(no_executables, ignore = "RPF_GAME_EXE is not set")]
fn an_extracted_key_never_prints_itself() {
    // DR-006 is about what leaves this machine, and a derived `Debug` is one of
    // the ways it would: a log line, a panic message, a `--json` payload. The
    // check is against the key's own rendering, so nothing here says a key.
    let test = "an_extracted_key_never_prints_itself";
    let Some(path) = executable(test, "GTA5.exe") else {
        return;
    };
    let bytes = fs::read(&path).expect("the executable is readable");
    let keys = Keys::extract(&mut Cursor::new(bytes)).expect("carries the material");

    let rendered = format!("{keys:?}");
    assert!(
        !rendered.contains(&format!("{:?}", keys.aes_key())),
        "the AES key is in the Debug rendering"
    );
    assert!(
        !rendered.contains(&format!("{:?}", keys.hash_lut())),
        "the hash lookup table is in the Debug rendering"
    );
    assert!(rendered.contains("aes_key_offset"));
}

#[test]
#[cfg_attr(no_executables, ignore = "RPF_GAME_EXE is not set")]
fn legacy_and_enhanced_share_one_key_at_two_offsets() {
    // Q6 and R2.5. The backlog recorded, at `secondary`, that Enhanced takes
    // "keys from gta5_enhanced.exe", which reads as key material of its own.
    // Measured here: the key is the same value in both, and only its address
    // moved. So the Enhanced flag in the reference implementation selects a
    // file name, not a key.
    let test = "legacy_and_enhanced_share_one_key_at_two_offsets";
    let (Some(legacy), Some(enhanced)) = (
        measure(test, "GTA5.exe"),
        measure(test, "GTA5_Enhanced.exe"),
    ) else {
        return;
    };

    assert_eq!(
        legacy.aes_key, enhanced.aes_key,
        "Legacy and Enhanced carry different AES keys"
    );
    assert_eq!(
        legacy.hash_lut, enhanced.hash_lut,
        "Legacy and Enhanced carry different hash lookup tables"
    );
    assert_ne!(
        legacy.aes_key_offset, enhanced.aes_key_offset,
        "the two builds put the key at one offset; the search could have been \
         an offset after all"
    );
}

#[test]
#[cfg_attr(no_executables, ignore = "RPF_GAME_EXE is not set")]
fn no_executable_here_carries_the_ng_material() {
    // R2.2, and the answer is a negative one. The search that finds the AES key
    // in the same file finds none of the 373 NG values in any of the three, at
    // every byte offset rather than only on the eight-byte stride. Recorded as
    // a test rather than as a note, so that an executable which does carry them
    // makes this fail and say so.
    //
    // It hashes 373 anchors over three executables and takes about three
    // minutes unoptimised, which is why it is behind `RPF_GAME_EXE` and
    // `#[ignore]`d without it rather than merely slow for everyone.
    let test = "no_executable_here_carries_the_ng_material";
    for name in ["GTA5.exe", "GTA5_Enhanced.exe", "RDR2.exe"] {
        let Some(path) = executable(test, name) else {
            return;
        };
        let bytes = fs::read(&path).expect("the executable is readable");
        let refused = NgKeys::extract(&mut Cursor::new(bytes));
        match refused {
            Err(Error::UnrecognisedExecutable { found, wanted, .. }) => {
                eprintln!("{name}: {found} of {wanted} NG values");
                assert_eq!(found, 0, "{name} carries some of the NG material now");
            }
            other => panic!("{name}: expected UnrecognisedExecutable, got {other:?}"),
        }
    }
}

#[test]
fn the_platform_cache_is_an_absolute_directory_of_this_tool_s_own() {
    // Read-only: it must not create anything, because a command that never
    // needed a key must not leave a directory behind. R2.6.
    let Some(cache) = Cache::platform() else {
        eprintln!(
            "SKIP the_platform_cache_is_an_absolute_directory_of_this_tool_s_own: \
                   the environment does not say where a configuration directory is"
        );
        return;
    };
    assert!(
        cache.directory().is_absolute(),
        "{} is relative, so the cache would follow the working directory",
        cache.directory().display()
    );
    assert_eq!(
        cache.directory().file_name().and_then(|name| name.to_str()),
        Some("rpf"),
        "{}",
        cache.directory().display()
    );
}

#[test]
#[cfg_attr(no_executables, ignore = "RPF_GAME_EXE is not set")]
fn material_extracted_from_an_executable_reads_back_from_the_cache() {
    // R2.4 end to end, on the one input that is not synthetic. The cache goes
    // in a temporary directory rather than the platform one, so running the
    // suite does not populate the machine's own cache.
    let test = "material_extracted_from_an_executable_reads_back_from_the_cache";
    let Some(path) = executable(test, "GTA5.exe") else {
        return;
    };
    let bytes = fs::read(&path).expect("the executable is readable");
    let source = SourceDigest::of(&mut Cursor::new(&bytes)).expect("digests");
    let keys = Keys::extract(&mut Cursor::new(&bytes)).expect("carries the material");

    let directory = tempfile::tempdir().expect("a temporary directory");
    let cache = Cache::at(directory.path());
    assert!(cache.load(&source).expect("reads").is_none());
    cache.store(&source, &keys).expect("stores");

    let cached = cache.load(&source).expect("reads").expect("was stored");
    assert_eq!(digest(cached.aes_key()), digest(keys.aes_key()));
    assert_eq!(digest(cached.hash_lut()), digest(keys.hash_lut()));
    assert_eq!(cached.aes_key_offset(), keys.aes_key_offset());
    assert_eq!(cached.hash_lut_offset(), keys.hash_lut_offset());
    eprintln!("GTA5.exe sha256 {}", source.hex());
}
