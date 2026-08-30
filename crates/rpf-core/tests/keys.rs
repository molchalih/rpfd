//! Key extraction: what a source is asked for, and what it answers.
//!
//! Three halves, and they are not the same kind of evidence.
//!
//! The **corpus-free** part runs everywhere. It is about the contract: a source
//! carrying none of the anchored values is refused by name and by count, never
//! answered with half a value, and the failure classifies as something a caller
//! can act on.
//!
//! The **executable-gated** part runs only where `RPF_GAME_EXE` names a
//! directory holding the game executables, which is one machine. It is the
//! measurement: which values are in them, where, and whether two builds of the
//! same game agree — including the negative that no executable carries the NG
//! material.
//!
//! The **image-gated** part runs only where `RPF_GAME_IMAGE` names a memory
//! image of a running game. It is the positive the negative above is the
//! counterpart to, and the only place the NG material has ever been found in
//! the clear. DR-040.
//!
//! Every part asserts on **counts, digests and offsets** and never on a key —
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
    io::{Cursor, Seek as _},
    path::{Path, PathBuf},
};

use rpf_core::{
    Category, Error, Flow, Step, Unwatched, Watch,
    keys::{
        AES_KEY_LEN, Cache, HASH_LUT_LEN, Keys, Material, NG_COLUMNS, NG_DECRYPT_TABLE_COUNT,
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
    let keys = Keys::extract(&mut Cursor::new(bytes), &mut Unwatched)
        .expect("the executable carries the material");
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
    let refused = Keys::extract(&mut Cursor::new(nothing), &mut Unwatched);
    match refused {
        Err(Error::UnrecognisedExecutable {
            what,
            missing,
            found,
            wanted,
        }) => {
            assert_eq!(found, 0);
            assert_eq!(wanted, 2);
            assert!(
                what.contains("AES key"),
                "the failure does not name the material: {what}"
            );
            assert_eq!(
                missing,
                ["the AES key", "the hash lookup table"],
                "a count is not which value was missing"
            );
        }
        other => panic!("expected UnrecognisedExecutable, got {other:?}"),
    }
}

#[test]
fn a_failure_says_which_value_was_missing_and_never_what_it_holds() {
    // "1 of 2" is not something a caller acts on. Which of the two it was, is.
    // Rendered rather than matched here, because the rendering is what reaches
    // a bug report — and the rendering is the path a key would leak down.
    let refused = Keys::extract(&mut Cursor::new(vec![0_u8; 1 << 16]), &mut Unwatched)
        .expect_err("a buffer of zeroes carries no key material");
    let message = refused.to_string();
    assert!(message.contains("0 of 2"), "{message}");
    assert!(
        message.contains("missing the AES key and the hash lookup table"),
        "{message}"
    );

    let ng = NgKeys::extract(&mut Cursor::new(vec![0_u8; 1 << 16]), &mut Unwatched)
        .expect_err("a buffer of zeroes carries no NG material");
    let message = ng.to_string();
    assert!(message.contains("0 of 373"), "{message}");
    assert!(
        message.contains("missing the expanded keys and the decrypt tables"),
        "{message}"
    );
}

#[test]
#[cfg_attr(no_executables, ignore = "RPF_GAME_EXE is not set")]
fn an_executable_carrying_one_value_is_told_which_one_it_is_short_of() {
    // The half-found case, on the only input that can produce it: a real
    // executable cut off after the first of its two values. Nothing is planted,
    // nothing is written, and the assertion is on a name and a count.
    let test = "an_executable_carrying_one_value_is_told_which_one_it_is_short_of";
    let Some(path) = executable(test, "GTA5.exe") else {
        return;
    };
    let bytes = fs::read(&path).expect("the executable is readable");
    let whole = Keys::extract(&mut Cursor::new(&bytes), &mut Unwatched).expect("carries both");

    // Cut just past the earlier of the two, so the later one is not there.
    let (first, first_len, later) = if whole.aes_key_offset() < whole.hash_lut_offset() {
        (whole.aes_key_offset(), AES_KEY_LEN, "the hash lookup table")
    } else {
        (whole.hash_lut_offset(), HASH_LUT_LEN, "the AES key")
    };
    let cut = usize::try_from(first).expect("fits") + first_len;
    let mut short = bytes;
    short.truncate(cut);

    match Keys::extract(&mut Cursor::new(short), &mut Unwatched) {
        Err(Error::UnrecognisedExecutable {
            missing,
            found,
            wanted,
            ..
        }) => {
            assert_eq!(found, 1, "the truncation removed both values");
            assert_eq!(wanted, 2);
            assert_eq!(missing, [later]);
        }
        other => panic!("expected UnrecognisedExecutable, got {other:?}"),
    }
}

#[test]
fn an_unrecognised_executable_is_not_the_callers_fault_to_fix() {
    // The file is intact and this build is what cannot read it, which is the
    // same shape as an RPF version we do not implement. DR-010.
    let refused = Keys::extract(&mut Cursor::new(vec![0_u8; 4096]), &mut Unwatched)
        .expect_err("nothing is in an empty buffer");
    assert_eq!(refused.category(), Category::Unsupported);
}

#[test]
fn an_empty_source_is_refused_rather_than_read_past() {
    let refused = Keys::extract(&mut Cursor::new(Vec::new()), &mut Unwatched);
    assert!(matches!(
        refused,
        Err(Error::UnrecognisedExecutable { found: 0, .. })
    ));
}

/// A watcher that counts what it was told and can stop the scan.
struct Counting {
    steps: u32,
    named: Option<String>,
    stop_after: Option<u32>,
}

impl Watch for Counting {
    fn step(&mut self, step: Step<'_>) -> Flow {
        self.steps += 1;
        self.named = Some(step.path.to_owned());
        assert!(step.done <= step.total, "{} of {}", step.done, step.total);
        match self.stop_after {
            Some(after) if self.steps >= after => Flow::Stop,
            _ => Flow::Continue,
        }
    }
}

#[test]
fn an_extraction_can_be_watched_and_stopped_from_outside_the_crate() {
    // DR-008's seam, reachable. DR-020 decided the *command* stays unwatched
    // because one pass over one executable is about a second; that stands and
    // is its call to make. What could not be done at all was passing a watcher,
    // and this is the test that it now can be — from outside the crate, which
    // is where the frontends and the NG survey are.
    let mut watching = Counting {
        steps: 0,
        named: None,
        stop_after: None,
    };
    let refused = Keys::extract(&mut Cursor::new(vec![0_u8; 3 << 20]), &mut watching);
    assert!(refused.is_err(), "a buffer of zeroes carried key material");
    assert_eq!(watching.steps, 3, "one step per block of the source");
    assert_eq!(
        watching.named.as_deref(),
        Some("AES key and hash lookup table"),
        "the step does not name the material being looked for"
    );

    let mut stopping = Counting {
        steps: 0,
        named: None,
        stop_after: Some(1),
    };
    let stopped = Keys::extract(&mut Cursor::new(vec![0_u8; 3 << 20]), &mut stopping);
    match stopped {
        Err(Error::Cancelled { done, total }) => {
            assert_eq!(done, 1);
            assert_eq!(total, 3);
        }
        other => panic!("expected Cancelled, got {other:?}"),
    }
    assert_eq!(
        stopped_category(),
        Category::Cancelled,
        "a stop is the caller's, not a refusal of ours"
    );
}

/// The category a stopped scan carries, said once so the test above reads.
fn stopped_category() -> Category {
    let mut stopping = Counting {
        steps: 0,
        named: None,
        stop_after: Some(1),
    };
    Keys::extract(&mut Cursor::new(vec![0_u8; 2 << 20]), &mut stopping)
        .expect_err("the watcher said stop")
        .category()
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
    let refused = NgKeys::extract(&mut Cursor::new(vec![0_u8; 1 << 16]), &mut Unwatched);
    match refused {
        Err(Error::UnrecognisedExecutable {
            what,
            missing,
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
            assert_eq!(
                missing,
                ["the expanded keys", "the decrypt tables"],
                "the two kinds are what a caller can act on, not 373 names"
            );
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
    let keys =
        Keys::extract(&mut Cursor::new(bytes), &mut Unwatched).expect("carries the material");

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
    // R2.2, and the answer is a negative one — **about executables, and only
    // about executables**. Narrowed 2026-08-30: this used to stand for "no
    // source we have carries the NG material", and that reading is now false.
    // A memory image of `GTA5.exe` taken while the game was running carries all
    // 373 values, which the test below this one measures. What survives, and is
    // worth keeping, is the narrower claim: the file on disk carries none of
    // them, which is exactly why finding them took until 2026-08-30 and why
    // every tool in this ecosystem ships a bundled copy instead. DR-040.
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
        let refused = NgKeys::extract(&mut Cursor::new(bytes), &mut Unwatched);
        match refused {
            Err(Error::UnrecognisedExecutable { found, wanted, .. }) => {
                eprintln!("{name}: {found} of {wanted} NG values");
                assert_eq!(found, 0, "{name} carries some of the NG material now");
            }
            other => panic!("{name}: expected UnrecognisedExecutable, got {other:?}"),
        }
    }
}

/// The memory image the NG material is in, or `None` with a reason on stderr.
///
/// One file rather than a directory: `RPF_GAME_IMAGE` names the image itself,
/// because there is no convention about what such a file is called and no
/// second one to pick between.
fn game_image(test: &str) -> Option<PathBuf> {
    let Some(named) = env::var_os("RPF_GAME_IMAGE") else {
        return skip_image(test, "RPF_GAME_IMAGE is not set");
    };
    let path = PathBuf::from(named);
    if path.is_file() {
        Some(path)
    } else {
        skip_image(test, &format!("{} is not a file", path.display()))
    }
}

/// Reports a skip of an image-gated test, naming what it would have read.
fn skip_image<T>(test: &str, reason: &str) -> Option<T> {
    assert!(
        env::var_os("RPF_REQUIRE_GAME_IMAGE").is_none(),
        "RPF_REQUIRE_GAME_IMAGE is set, but {test} would have skipped: {reason}",
    );
    eprintln!("SKIP {test}: {reason}");
    None
}

#[test]
#[cfg_attr(no_game_image, ignore = "RPF_GAME_IMAGE is not set")]
fn a_memory_image_of_the_running_game_carries_the_ng_material() {
    // The positive that the test above is the negative of, and the first input
    // on which `NgKeys::extract` has ever succeeded. Measured 2026-08-30
    // against the mapped image of `GTA5.exe` carved out of a dump of the
    // running game: 101 of 101 expanded keys and 272 of 272 decrypt tables,
    // each identified by the SHA-1 of its own bytes, which is why a match is
    // its own proof and why this test can assert on the material without
    // holding any of it.
    //
    // It asserts on **counts, lengths and offsets** and never on a value.
    // DR-006, which is also why the offsets are printed and the bytes are not.
    let test = "a_memory_image_of_the_running_game_carries_the_ng_material";
    let Some(path) = game_image(test) else {
        return;
    };
    let mut file = fs::File::open(&path).expect("the image is readable");
    let material = Material::extract(&mut file, &mut Unwatched).expect("carries the material");
    let ng = material
        .ng()
        .expect("a memory image carries the NG material");

    for index in 0..NG_EXPANDED_KEY_COUNT {
        assert_eq!(
            ng.expanded_key(index).map(<[u8]>::len),
            Some(NG_EXPANDED_KEY_LEN),
            "expanded key {index}"
        );
    }
    assert!(
        ng.expanded_key(NG_EXPANDED_KEY_COUNT).is_none(),
        "there is a 102nd expanded key"
    );
    for round in 0..NG_ROUNDS {
        for column in 0..NG_COLUMNS {
            assert_eq!(
                ng.decrypt_table(round, column).map(<[u8]>::len),
                Some(NG_DECRYPT_TABLE_LEN),
                "decrypt table {round}/{column}"
            );
        }
    }
    assert!(ng.decrypt_table(NG_ROUNDS, 0).is_none());
    assert!(ng.decrypt_table(0, NG_COLUMNS).is_none());

    eprintln!(
        "{}: {NG_EXPANDED_KEY_COUNT} expanded keys at {:#x}, \
         {NG_DECRYPT_TABLE_COUNT} decrypt tables at {:#x}, \
         aes key at {:#x}, hash lut at {:#x}",
        path.display(),
        ng.expanded_keys_offset(),
        ng.decrypt_tables_offset(),
        material.keys().aes_key_offset(),
        material.keys().hash_lut_offset(),
    );
}

#[test]
#[cfg_attr(no_executables, ignore = "RPF_GAME_EXE is not set")]
fn the_launcher_executable_carries_a_second_aes_key_no_game_executable_has() {
    // DR-042's measurement, re-established by `cargo test` on any machine with
    // the launcher installed. Three claims, and the third is what makes the
    // first two worth having: the value is there, it is **not** the RAGE key,
    // and no game executable carries it — so an archive tagged `0x0FFFFFF7` is
    // not simply the RAGE key under a second name.
    let test = "the_launcher_executable_carries_a_second_aes_key_no_game_executable_has";
    let Some(path) = executable(test, "Launcher.exe") else {
        return;
    };
    let mut file = fs::File::open(&path).expect("the executable is readable");
    let material = Material::extract(&mut file, &mut Unwatched).expect("carries the material");
    let launcher = material
        .launcher()
        .expect("Launcher.exe carries the launcher key");

    assert_eq!(launcher.key().len(), AES_KEY_LEN, "an AES-256 key");
    assert_ne!(
        digest(launcher.key()),
        digest(material.keys().aes_key()),
        "the launcher key is the RAGE key, so the tag chooses nothing"
    );
    assert_eq!(
        launcher.offset() % 8,
        0,
        "off the scan's stride, and it could not have been found at all"
    );
    eprintln!(
        "Launcher.exe: launcher key sha256 {} at {:#x}; rage key at {:#x}",
        digest(launcher.key()),
        launcher.offset(),
        material.keys().aes_key_offset(),
    );

    // Nothing it prints is a key. DR-020 on the type that holds this one, and
    // on the type that holds *that* — `Material` derives its `Debug`, so the
    // hand-written one below it is the only thing between a key and a log line.
    for (what, rendered) in [
        ("LauncherKey", format!("{launcher:?}")),
        ("Material", format!("{material:?}")),
    ] {
        // The rendering is never in the message. A failure here means it holds
        // a key, and printing it to say so would be the leak it is reporting.
        assert!(
            !rendered.contains(&format!("{:?}", launcher.key())),
            "{what} renders the launcher key"
        );
        assert!(
            !rendered.contains(&hex::encode(launcher.key())),
            "{what} renders the launcher key as hexadecimal"
        );
        assert!(rendered.contains("offset"), "{what} renders nothing at all");
    }

    for game in ["GTA5.exe", "GTA5_Enhanced.exe", "RDR2.exe"] {
        let Some(path) = executable(test, game) else {
            continue;
        };
        let mut file = fs::File::open(&path).expect("the executable is readable");
        let material = Material::extract(&mut file, &mut Unwatched).expect("carries the material");
        assert!(
            material.launcher().is_none(),
            "{game} carries the launcher key, which DR-042 says nothing but the \
             launcher does"
        );
    }
}

#[test]
#[cfg_attr(no_executables, ignore = "RPF_GAME_EXE is not set")]
fn the_launcher_key_reaches_the_cache_and_comes_back_the_same() {
    // The cache gained a third shape (`keys::cache`), and this is the one place
    // it is exercised on material that was extracted rather than assembled. An
    // entry that lost the launcher key on the way through would show up as an
    // archive that opens once and never again.
    let test = "the_launcher_key_reaches_the_cache_and_comes_back_the_same";
    let Some(path) = executable(test, "Launcher.exe") else {
        return;
    };
    let bytes = fs::read(&path).expect("the executable is readable");
    let source = SourceDigest::of(&mut Cursor::new(&bytes)).expect("digests");
    let material =
        Material::extract(&mut Cursor::new(&bytes), &mut Unwatched).expect("carries the material");
    let launcher = material.launcher().expect("carries the launcher key");

    let directory = tempfile::tempdir().expect("a temporary directory");
    let cache = Cache::at(directory.path());
    cache.store(&source, &material).expect("stores");
    let read_back = cache.load(&source).expect("reads").expect("was stored");
    let cached = read_back
        .launcher()
        .expect("the cache kept the launcher key");

    assert_eq!(digest(cached.key()), digest(launcher.key()));
    assert_eq!(cached.offset(), launcher.offset());
    assert_eq!(
        digest(read_back.keys().aes_key()),
        digest(material.keys().aes_key()),
        "the value beside it did not survive"
    );
    assert!(
        read_back.ng().is_none(),
        "NG material appeared in the cache"
    );
}

#[test]
#[cfg_attr(no_game_image, ignore = "RPF_GAME_IMAGE is not set")]
fn the_ng_material_never_prints_itself() {
    // DR-006 on the type that holds 305 KB of it. The check is against the
    // material's own rendering, so nothing here says a value: a `Debug` that
    // leaked would put 373 values in a log line, a panic message or a `--json`
    // payload.
    let test = "the_ng_material_never_prints_itself";
    let Some(path) = game_image(test) else {
        return;
    };
    let mut file = fs::File::open(&path).expect("the image is readable");
    let material = Material::extract(&mut file, &mut Unwatched).expect("carries the material");
    let ng = material.ng().expect("carries the NG material");

    let rendered = format!("{ng:?}");
    for index in 0..NG_EXPANDED_KEY_COUNT {
        let key = ng.expanded_key(index).expect("is there");
        assert!(
            !rendered.contains(&format!("{key:?}")),
            "expanded key {index} is in the Debug rendering"
        );
    }
    let table = ng.decrypt_table(0, 0).expect("is there");
    assert!(
        !rendered.contains(&format!("{table:?}")),
        "a decrypt table is in the Debug rendering"
    );
    assert!(rendered.contains("expanded_keys_offset"), "{rendered}");

    // And the same for the whole, which is the object a command holds.
    let whole = format!("{material:?}");
    assert!(
        !whole.contains(&format!("{:?}", material.keys().aes_key())),
        "the AES key is in the Debug rendering of the material"
    );
}

#[test]
#[cfg_attr(no_game_image, ignore = "RPF_GAME_IMAGE is not set")]
fn ng_material_extracted_from_an_image_reads_back_from_the_cache() {
    // R2.4 for the half the cache gained on 2026-08-30, on the only input that
    // produces it. A 305 KB entry has to survive the round trip value for value
    // and in order, because the index into the expanded keys is chosen by the
    // name and length of what is being decrypted (`docs/ng-scheme.md`) — a
    // rotation would be well-formed and would decrypt nothing.
    let test = "ng_material_extracted_from_an_image_reads_back_from_the_cache";
    let Some(path) = game_image(test) else {
        return;
    };
    let mut file = fs::File::open(&path).expect("the image is readable");
    let source = SourceDigest::of(&mut file).expect("digests");
    file.rewind().expect("rewinds");
    let material = Material::extract(&mut file, &mut Unwatched).expect("carries the material");

    let directory = tempfile::tempdir().expect("a temporary directory");
    let cache = Cache::at(directory.path());
    cache.store(&source, &material).expect("stores");
    let cached = cache.load(&source).expect("reads").expect("was stored");

    let (stored, read) = (
        material.ng().expect("carries NG material"),
        cached.ng().expect("the entry carried it back"),
    );
    assert_eq!(
        read.expanded_keys_offset(),
        stored.expanded_keys_offset(),
        "the position the expanded keys were found at did not survive"
    );
    assert_eq!(read.decrypt_tables_offset(), stored.decrypt_tables_offset());
    for index in 0..NG_EXPANDED_KEY_COUNT {
        assert_eq!(
            digest(read.expanded_key(index).expect("is there")),
            digest(stored.expanded_key(index).expect("is there")),
            "expanded key {index} did not survive the cache"
        );
    }
    for round in 0..NG_ROUNDS {
        for column in 0..NG_COLUMNS {
            assert_eq!(
                digest(read.decrypt_table(round, column).expect("is there")),
                digest(stored.decrypt_table(round, column).expect("is there")),
                "decrypt table {round}/{column} did not survive the cache"
            );
        }
    }
    assert_eq!(cache.clear().expect("clears"), 1, "the entry stayed behind");
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
    // Below the application's configuration directory rather than being it. A
    // cache directory that *is* the configuration directory puts any later
    // configuration file inside the thing `keys invalidate` empties. DR-024.
    assert_eq!(
        cache.directory().file_name().and_then(|name| name.to_str()),
        Some("keys"),
        "{}",
        cache.directory().display()
    );
    assert_eq!(
        cache
            .directory()
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str()),
        Some("rpf"),
        "{}",
        cache.directory().display()
    );
}

#[test]
fn a_caller_can_enumerate_and_empty_the_cache_without_knowing_how_it_names_files() {
    // §1 and §3 together. A frontend that has to work out for itself which
    // files under the directory are entries has taken over a rule the cache
    // owns, and it took it over wrongly: counting regular files counts anything
    // that happens to be there. This is the API that makes that unnecessary,
    // pinned from outside the crate because outside the crate is where it is
    // needed.
    let directory = tempfile::tempdir().expect("a temporary directory");
    let absent = directory.path().join("never-written");
    let cache = Cache::at(&absent);

    assert!(cache.entries().expect("reads").is_empty());
    assert_eq!(cache.clear().expect("clears"), 0, "an empty cache removed");
    assert!(!absent.exists(), "asking about a cache created one");

    let populated = Cache::at(directory.path());
    let beside = directory.path().join("settings.json");
    fs::write(&beside, b"{}").expect("writable");
    fs::create_dir(directory.path().join("held")).expect("creatable");
    assert!(
        populated.entries().expect("reads").is_empty(),
        "a file beside the entries was counted as one"
    );
    assert_eq!(populated.clear().expect("clears"), 0);
    assert_eq!(
        fs::read(&beside).expect("readable"),
        b"{}",
        "a file the cache did not write was removed"
    );
    assert!(directory.path().join("held").is_dir());
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
    let material =
        Material::extract(&mut Cursor::new(&bytes), &mut Unwatched).expect("carries the material");
    let keys = material.keys();
    assert!(
        material.ng().is_none(),
        "an executable carries the NG material now; DR-040 and the negative \
         test beside this one both need rewriting"
    );

    let directory = tempfile::tempdir().expect("a temporary directory");
    let cache = Cache::at(directory.path());
    assert!(cache.load(&source).expect("reads").is_none());
    cache.store(&source, &material).expect("stores");

    let read_back = cache.load(&source).expect("reads").expect("was stored");
    let cached = read_back.keys();
    assert_eq!(digest(cached.aes_key()), digest(keys.aes_key()));
    assert_eq!(digest(cached.hash_lut()), digest(keys.hash_lut()));
    assert_eq!(cached.aes_key_offset(), keys.aes_key_offset());
    assert_eq!(cached.hash_lut_offset(), keys.hash_lut_offset());
    assert!(
        read_back.ng().is_none(),
        "NG material appeared in the cache"
    );
    eprintln!("GTA5.exe sha256 {}", source.hex());

    // The entry is addressable by the digest it was stored under, and clearing
    // takes it off the machine. Real material rather than a fixture, because
    // this is the one place both ends of R2.4 are the real thing.
    let held: Vec<String> = cache
        .entries()
        .expect("reads")
        .iter()
        .map(SourceDigest::hex)
        .collect();
    assert_eq!(held, vec![source.hex()]);
    assert_eq!(cache.clear().expect("clears"), 1);
    assert!(cache.entries().expect("reads").is_empty());
    assert!(cache.load(&source).expect("reads").is_none());
}
