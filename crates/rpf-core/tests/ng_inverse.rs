//! R4.7: whether the NG transform's forward direction derives from the decrypt
//! tables this build already holds.
//!
//! `docs/ng-scheme.md`, "The inverse is published", records that the reference
//! implementation derives its encrypt material from nothing but the decrypt
//! tables — Gaussian elimination over GF(2) for rounds 0, 1 and 16, a 2^32
//! sweep for rounds 2 through 15 — and that **none of it had been run here**.
//! This file is the run. It is the decisive part and not the whole of R4.7: no
//! write path asks for an NG seal, and rounds 2 through 15 are not derived.
//!
//! The derivation itself is measured with no key material at all, in
//! `crates/rpf-core/src/format/crypto.rs`'s own tests: a solver over a
//! synthetic invertible matrix, and a round trip over synthetic affine tables.
//! What only real material can answer is whether **these** tables have the
//! shape the derivation needs, and that is what is gated here.
//!
//! `RPF_GAME_IMAGE` names the memory image the NG material is scanned from
//! (DR-040) and `RPF_CORPUS` names the directory holding `gtav_ng/dlc.rpf`,
//! whose bytes are the real ciphertext the round trip runs over. That is one
//! machine, for DR-006's reason: key material is extracted from the user's own
//! installation and never travels.
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

use std::{env, fs, path::PathBuf, sync::Arc};

use rpf_core::{
    Unwatched,
    format::crypto::{self, NgForward, NgRound},
    keys::{Material, NG_EXPANDED_KEY_LEN, NG_ROUNDS},
};

/// The NG-encrypted archive in the corpus, by the relative path that addresses
/// it. `docs/corpus.md`.
const NG_ARCHIVE: &str = "gtav_ng/dlc.rpf";

/// How long one round key is, which is the block.
const ROUND_KEY_LEN: usize = crypto::CIPHER_BLOCK_LEN;

/// How many blocks of the archive the round trip runs over.
///
/// The whole file would do and would say nothing more: what is being measured
/// is a property of the tables, and every block exercises the same four maps.
/// This many is enough that a table wrong in one byte value is hit.
const BLOCKS: usize = 4096;

/// Reports a skip, naming the test and the gate that was not there.
///
/// The same shape `crates/rpf-core/tests/encrypted.rs` uses, and for the same
/// reason: `RPF_REQUIRE_<GATE>` turns that gate's absence into a failure, so a
/// green suite cannot be confused with a suite that ran (§12).
fn skip<T>(test: &str, gate: &str, reason: &str) -> Option<T> {
    let required = format!("RPF_REQUIRE_{}", gate.trim_start_matches("RPF_"));
    assert!(
        env::var_os(&required).is_none(),
        "{required} is set, but {test} would have skipped: {reason}",
    );
    eprintln!("SKIP {test}: {reason}");
    None
}

/// The key material the memory image carries, scanned once for this binary.
///
/// Nothing is written anywhere: the material lives in this process and dies
/// with it, which is what DR-006 is about.
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

/// The corpus NG archive's bytes and its own file name.
fn ng_archive(test: &str) -> Option<(Vec<u8>, String)> {
    let Some(root) = env::var_os("RPF_CORPUS") else {
        return skip(test, "RPF_CORPUS", "RPF_CORPUS is not set");
    };
    let path = std::path::Path::new(&root).join(NG_ARCHIVE);
    if !path.is_file() {
        return skip(
            test,
            "RPF_CORPUS",
            &format!("{} is not a file", path.display()),
        );
    }
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .expect("a corpus path names a file");
    Some((fs::read(&path).expect("the archive is readable"), name))
}

/// One round key out of an expanded key.
fn round_key(expanded: &[u8], round: usize) -> [u8; ROUND_KEY_LEN] {
    let at = round * ROUND_KEY_LEN;
    expanded
        .get(at..at + ROUND_KEY_LEN)
        .expect("an expanded key holds one round key per round")
        .try_into()
        .expect("a round key is a block")
}

#[test]
#[cfg_attr(no_game_image, ignore = "RPF_GAME_IMAGE must be set")]
fn every_round_of_the_transform_derives_from_the_decrypt_tables_alone() {
    // **All seventeen, and not the three the reference implementation solves.**
    // Its `GTAKeys.cs` solves rounds 0, 1 and 16 by elimination and brute-forces
    // the other fourteen with a 2^32 sweep each; the factorisation
    // `NgRound::solve` uses finds what those sweeps are searching for, so the
    // whole transform derives in milliseconds from the same input.
    //
    // If a round ever stops deriving, this names it and says what shape its
    // tables had — which is the difference between "the material changed" and
    // "the derivation is wrong".
    let test = "every_round_of_the_transform_derives_from_the_decrypt_tables_alone";
    let Some(material) = material(test) else {
        return;
    };
    let ng = material.ng().expect("the image carries the NG half");
    for round in 0..NG_ROUNDS {
        let derived = NgRound::solve(ng, round)
            .unwrap_or_else(|why| panic!("round {round} did not derive: {why:?}"));
        assert_eq!(derived.round(), round);
    }
    NgForward::derive(ng).expect("the whole transform derives");
}

#[test]
#[cfg_attr(
    any(no_corpus, no_game_image),
    ignore = "RPF_CORPUS and RPF_GAME_IMAGE must both be set"
)]
fn a_derived_round_undoes_the_decrypt_round_on_bytes_from_an_ng_archive() {
    // **The experiment R4.7 turns on.** Real decrypt tables, out of the user's
    // own running game; a real expanded key, the one this archive's name and
    // length choose; and real ciphertext, the bytes of `dlc.rpf` as they sit on
    // disk. For each of the three linear rounds, what the decrypt round turns a
    // block into, the forward round derived from that round's own tables turns
    // back — and the other way about, which is the direction a writer runs.
    //
    // Bytes off the disk rather than random ones because that is what the claim
    // is about: not that the algebra closes, which the ungated tests in
    // `format::crypto` already say over synthetic tables, but that it closes
    // over the material and the blocks this tool actually meets.
    let test = "a_derived_round_undoes_the_decrypt_round_on_bytes_from_an_ng_archive";
    let Some(material) = material(test) else {
        return;
    };
    let Some((bytes, name)) = ng_archive(test) else {
        return;
    };
    let ng = material.ng().expect("the image carries the NG half");

    // The key this archive's own table of contents is read under, chosen by its
    // name and its length exactly as `Cipher` chooses it — so the round keys
    // below are the ones the archive was written with and not an arbitrary
    // index. `docs/rpf-format.md`, Encryption.
    let index = crypto::Cipher::new(
        crypto::Scheme::Ng,
        &material,
        &name,
        u64::try_from(bytes.len()).expect("an archive length is a u64"),
    )
    .expect("the material carries the NG half")
    .key_index()
    .expect("an NG cipher chose a key");
    let expanded = ng.expanded_key(index).expect("the index the hash chose");
    assert_eq!(expanded.len(), NG_EXPANDED_KEY_LEN);

    let (whole, _) = bytes.as_chunks::<{ crypto::CIPHER_BLOCK_LEN }>();
    let blocks: Vec<[u8; crypto::CIPHER_BLOCK_LEN]> = whole.iter().copied().take(BLOCKS).collect();
    assert!(
        blocks.len() > 1,
        "the archive is shorter than two blocks, so nothing was measured"
    );

    for round in 0..NG_ROUNDS {
        let derived = NgRound::solve(ng, round)
            .unwrap_or_else(|why| panic!("round {round} did not solve: {why:?}"));
        let key = round_key(expanded, round);
        let mut moved = 0_usize;
        for (at, block) in blocks.iter().enumerate() {
            let mut opened = *block;
            derived.open(&key, &mut opened);
            if opened != *block {
                moved += 1;
            }
            let mut back = opened;
            derived.seal(&key, &mut back);
            assert_eq!(
                back, *block,
                "round {round} did not come back at block {at} of {name}"
            );

            let mut sealed = *block;
            derived.seal(&key, &mut sealed);
            let mut reopened = sealed;
            derived.open(&key, &mut reopened);
            assert_eq!(
                reopened, *block,
                "round {round} did not seal and reopen at block {at} of {name}"
            );
        }
        assert_eq!(
            moved,
            blocks.len(),
            "round {round} left a block unchanged, so the round trip proved nothing there"
        );
    }
}

#[test]
#[cfg_attr(no_game_image, ignore = "RPF_GAME_IMAGE must be set")]
fn a_derived_round_undoes_the_decrypt_round_under_every_key_the_material_holds() {
    // The round key is exclusive-ored in, so a derivation that got the affine
    // part wrong could still round-trip under one key and fail under another.
    // All 101 of them, over blocks that cover every byte value in every column.
    let test = "a_derived_round_undoes_the_decrypt_round_under_every_key_the_material_holds";
    let Some(material) = material(test) else {
        return;
    };
    let ng = material.ng().expect("the image carries the NG half");
    let mut state = 0x9E37_79B9_u32;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        u8::try_from(state >> 24).unwrap_or(0)
    };

    for round in 0..NG_ROUNDS {
        let derived = NgRound::solve(ng, round).expect("a linear round solves");
        for index in 0..rpf_core::keys::NG_EXPANDED_KEY_COUNT {
            let expanded = ng.expanded_key(index).expect("an index the material has");
            let key = round_key(expanded, round);
            for _ in 0..16 {
                let block: [u8; crypto::CIPHER_BLOCK_LEN] = std::array::from_fn(|_| next());
                let mut opened = block;
                derived.open(&key, &mut opened);
                let mut back = opened;
                derived.seal(&key, &mut back);
                assert_eq!(back, block, "round {round} under key {index}");
            }
        }
    }
}

/// The rank over GF(2) of a set of words: how many of them are independent.
fn rank(words: &[u32]) -> usize {
    let mut pivots: Vec<u32> = Vec::new();
    for &word in words {
        let mut left = word;
        for &pivot in &pivots {
            left = left.min(left ^ pivot);
        }
        if left != 0 {
            pivots.push(left);
            pivots.sort_unstable_by(|a, b| b.cmp(a));
        }
    }
    pivots.len()
}

#[test]
#[cfg_attr(no_game_image, ignore = "RPF_GAME_IMAGE must be set")]
fn a_rounds_table_differences_are_an_eight_dimensional_space_in_every_column() {
    // **What decides whether rounds 2 through 15 need a 2^32 sweep at all.**
    //
    // A round's output word is the exclusive-or of four table lookups, and the
    // map from the four bytes to the word is a bijection. If, for each column,
    // the 256 differences `T[b] ^ T[0]` are 256 *distinct* words spanning an
    // eight-dimensional subspace, then that table is a byte permutation
    // followed by an injection into a subspace — an AES-shaped T-box — the four
    // subspaces of a group are independent, and the round inverts by the same
    // Gaussian elimination the linear rounds use plus one 256-byte permutation
    // per column. If instead a column's differences span more than eight
    // dimensions, or repeat, no such factorisation exists and the inverse has to
    // be swept for.
    //
    // This test is the measurement, and it is written to report the shape it
    // found rather than merely to fail.
    let test = "a_rounds_table_differences_are_an_eight_dimensional_space_in_every_column";
    let Some(material) = material(test) else {
        return;
    };
    let ng = material.ng().expect("the image carries the NG half");
    let mut shapes: std::collections::BTreeSet<(usize, usize)> = std::collections::BTreeSet::new();
    for round in 0..NG_ROUNDS {
        for column in 0..rpf_core::keys::NG_COLUMNS {
            let table = ng.decrypt_table(round, column).expect("a round's table");
            let (words, _) = table.as_chunks::<4>();
            let read = |at: usize| u32::from_le_bytes(*words.get(at).expect("256 words"));
            let base = read(0);
            let differences: Vec<u32> = (0..256).map(|value| read(value) ^ base).collect();
            let distinct: std::collections::BTreeSet<u32> = differences.iter().copied().collect();
            shapes.insert((rank(&differences), distinct.len()));
        }
    }
    assert_eq!(
        shapes,
        std::collections::BTreeSet::from([(8_usize, 256_usize)]),
        "the shapes found across all 272 tables, as (rank, distinct differences)"
    );
}

#[test]
#[cfg_attr(
    any(no_corpus, no_game_image),
    ignore = "RPF_CORPUS and RPF_GAME_IMAGE must both be set"
)]
fn the_derived_transform_undoes_the_whole_decrypt_transform_on_an_ng_archives_bytes() {
    // **The whole of R4.7's blocker, measured.** Not one round but all
    // seventeen, run backwards, over the bytes of `dlc.rpf` as they sit on
    // disk and under the expanded key that archive's own name and length
    // choose. What `Cipher` turns a block into, the derived transform turns
    // back — which is the statement "an NG archive can be written back".
    let test = "the_derived_transform_undoes_the_whole_decrypt_transform_on_an_ng_archives_bytes";
    let Some(material) = material(test) else {
        return;
    };
    let Some((bytes, name)) = ng_archive(test) else {
        return;
    };
    let ng = material.ng().expect("the image carries the NG half");
    let forward = NgForward::derive(ng).expect("the transform derives");

    let len = u64::try_from(bytes.len()).expect("an archive length is a u64");
    let cipher = crypto::Cipher::new(crypto::Scheme::Ng, &material, &name, len)
        .expect("the material carries the NG half");
    let index = cipher.key_index().expect("an NG cipher chose a key");
    let expanded: [u8; NG_EXPANDED_KEY_LEN] = ng
        .expanded_key(index)
        .expect("the index the hash chose")
        .try_into()
        .expect("an expanded key is its own length");

    let (whole, _) = bytes.as_chunks::<{ crypto::CIPHER_BLOCK_LEN }>();
    let blocks: Vec<[u8; crypto::CIPHER_BLOCK_LEN]> = whole.iter().copied().take(BLOCKS).collect();
    assert!(blocks.len() > 1, "nothing was measured");

    for (at, block) in blocks.iter().enumerate() {
        let mut opened = *block;
        cipher.apply(&mut opened);
        assert_ne!(opened, *block, "block {at} of {name} decrypted to itself");
        let mut back = opened;
        forward.block(&expanded, &mut back);
        assert_eq!(back, *block, "block {at} of {name} did not come back");

        // And the direction a writer runs: encrypt a plaintext block, then read
        // it back through the reader this tool already ships.
        let mut sealed = *block;
        forward.block(&expanded, &mut sealed);
        let mut reopened = sealed;
        cipher.apply(&mut reopened);
        assert_eq!(
            reopened, *block,
            "block {at} of {name} did not seal and reopen"
        );
    }
}
