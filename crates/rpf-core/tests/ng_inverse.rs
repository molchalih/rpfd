//! Whether the NG transform's forward direction derives from the decrypt tables
//! this build already holds. Gated: `RPF_GAME_IMAGE` names the memory image the
//! material is scanned from, `RPF_CORPUS` the directory holding the real
//! ciphertext.
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
/// it.
const NG_ARCHIVE: &str = "gtav_ng/dlc.rpf";

const ROUND_KEY_LEN: usize = crypto::CIPHER_BLOCK_LEN;

/// How many blocks of the archive the round trip runs over: enough that a table
/// wrong in one byte value is hit.
const BLOCKS: usize = 4096;

/// Reports a skip, naming the test and the gate that was not there;
/// `RPF_REQUIRE_<GATE>` turns that gate's absence into a failure.
fn skip<T>(test: &str, gate: &str, reason: &str) -> Option<T> {
    let required = format!("RPF_REQUIRE_{}", gate.trim_start_matches("RPF_"));
    assert!(
        env::var_os(&required).is_none(),
        "{required} is set, but {test} would have skipped: {reason}",
    );
    eprintln!("SKIP {test}: {reason}");
    None
}

/// The key material the memory image carries, scanned once for this binary and
/// never written anywhere.
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

fn material(test: &str) -> Option<Arc<Material>> {
    match scanned() {
        Ok(material) => Some(material),
        Err(reason) => skip(test, "RPF_GAME_IMAGE", &reason),
    }
}

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
    // All seventeen: the factorisation `NgRound::solve` uses finds what the
    // reference implementation sweeps 2^32 values for on rounds 2 through 15.
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
    // Real tables, a real expanded key and real ciphertext: the claim is that
    // the algebra closes over the material this tool actually meets, not merely
    // over synthetic tables.
    let test = "a_derived_round_undoes_the_decrypt_round_on_bytes_from_an_ng_archive";
    let Some(material) = material(test) else {
        return;
    };
    let Some((bytes, name)) = ng_archive(test) else {
        return;
    };
    let ng = material.ng().expect("the image carries the NG half");

    // Chosen by name and length exactly as `Cipher` chooses it, so the round
    // keys below are the ones the archive was written with.
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
    // 256 distinct differences spanning eight dimensions means the table is a
    // byte permutation into a subspace — an AES-shaped T-box — and the round
    // inverts by elimination plus one 256-byte permutation per column. Anything
    // else and the inverse has to be swept for.
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
    // All seventeen rounds run backwards over real bytes: the statement "an NG
    // archive can be written back".
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
