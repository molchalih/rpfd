//! The encrypted read path: `decrypt_table_of_contents`, `Plain::Keyed`,
//! `Decrypting`, and the NG arm of `Cipher::block`.
//!
//! No key material is consulted: `Material::over_bytes` is `#[cfg(fuzzing)]`
//! and takes bytes the caller already has. With every round key zero and the
//! table for byte position `c` set to `T[c][b] = b << 8·(c mod 4)`, each round
//! is a byte permutation and the rounds compose to one fixed permutation, which
//! [`transform`] measures and [`sealed`] inverts. Every region an archive
//! decrypts starts on a cipher block boundary of the file, so sealing blockwise
//! from the end of the header seals all of them.
//!
//! It says nothing about the transform's values: the round keys are zero, so a
//! defect in key selection is invisible here.

#![no_main]

use std::io::{Cursor, Read, copy, sink};
use std::sync::{Arc, OnceLock};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rpf_core::{
    Archive, Unlock, Version,
    format::crypto::{CIPHER_BLOCK_LEN, Cipher, Scheme},
    keys::{
        AES_KEY_LEN, HASH_LUT_LEN, Material, NG_COLUMNS, NG_DECRYPT_TABLE_COUNT,
        NG_DECRYPT_TABLE_LEN, NG_EXPANDED_KEY_COUNT, NG_EXPANDED_KEY_LEN, NG_ROUNDS,
    },
};
use rpf_fuzz::{DRAIN_LIMIT, bounded, nested_to_the_bound, watched};

/// How many `u32` words one cipher block holds.
///
/// Derived rather than written: it is what `ng_round` splits a block and a
/// round key into, and the lane a table feeds is a position within it.
const WORDS: usize = CIPHER_BLOCK_LEN / size_of::<u32>();

/// The fill the synthetic AES key is made of.
///
/// Any bytes at all: it is here so the AES-tagged arms have a key to fail
/// against, reaching the table-of-contents decrypt and its refusal.
const AES_FILL: u8 = 0x11;

/// The fill the synthetic hash lookup table is made of.
///
/// The NG name hash folds each byte through it, so it decides which expanded
/// key a name chooses. A constant fill makes that choice a function of the
/// name's length alone, which is enough: the keys are identical.
const LUT_FILL: u8 = 0x22;

/// An archive, the name its key is derived from, and what to tag it.
#[derive(Debug, Arbitrary)]
struct Input<'a> {
    /// Which transform to tag the archive with, as an index into what
    /// [`tags`] found. Not a tag: the values belong to `format::rpf7` and are
    /// read out of the crate rather than copied into it.
    scheme: u8,
    /// The archive's own file name, which with its length is what an NG key
    /// index is a function of. A renamed archive does not open, and that is
    /// the format's behaviour rather than ours.
    name: &'a str,
    /// The archive.
    data: &'a [u8],
}

/// The key material every input is opened with. [`synthetic`].
static MATERIAL: OnceLock<Arc<Material>> = OnceLock::new();

/// The permutation the transform is, and its inverse. [`transform`].
static SHAPE: OnceLock<([u8; CIPHER_BLOCK_LEN], [u8; CIPHER_BLOCK_LEN])> = OnceLock::new();

/// The encryption tags this build recognises. [`tags`].
static TAGS: OnceLock<Vec<u32>> = OnceLock::new();

/// Where the encryption tag sits in a header. [`tag_offset`].
static TAG_AT: OnceLock<usize> = OnceLock::new();

/// Everything this target answers once per process, answered before the first
/// input rather than on its clock.
///
/// `init` is `LLVMFuzzerInitialize`, called before the fuzzing loop, so nothing
/// here is charged to a unit's `-timeout`; lazily, the [`tags`] scan was, and
/// read as a hang on the first input of every worker.
fn setup() {
    let _ = synthetic();
    let _ = transform();
    let _ = tags();
    let _ = header_len();
}

/// Whether [`setup`] has already run, which is what the target asserts on every
/// input.
///
/// A value still empty means a per-process answer is being computed on some
/// input's clock.
fn ready() -> bool {
    MATERIAL.get().is_some()
        && SHAPE.get().is_some()
        && TAGS.get().is_some()
        && TAG_AT.get().is_some()
}

fuzz_target!(init: setup(), |input: Input| {
    assert!(
        ready(),
        "a per-process answer is being computed on this input's clock, not in `init`"
    );

    let Some(data) = bounded(input.data) else {
        return;
    };
    let Some(name) = bounded(input.name.as_bytes()).map(|_| input.name) else {
        return;
    };

    // Once per process, outside the watched region: it is the same answer
    // every time and not what any input is about.
    let material = Arc::clone(synthetic());
    let (forward, backward) = *transform();

    watched(|| {
        let Some(&tag) = tags().get(usize::from(input.scheme) % tags().len()) else {
            return;
        };

        let mut sealed_bytes = data.to_vec();
        stamped(&mut sealed_bytes, tag);
        // Sealing an archive that will be refused for its key anyway keeps one
        // code path here rather than two.
        sealed(&mut sealed_bytes, &backward);

        // The cipher this input's own name and length choose, checked before
        // anything is opened so it is checked on every input. The key index
        // must not change the transform — every expanded key here is one key —
        // because a `forward` that moved means the seal no longer matches the
        // opener, and the target silently stops testing.
        let mut probe = ladder();
        let cipher = Cipher::new(Scheme::Ng, synthetic(), name, sealed_len(&sealed_bytes))
            .expect("the synthetic material carries the NG half");
        cipher.apply(&mut probe);
        assert_eq!(
            probe, forward,
            "the NG transform for {name:?} is not the permutation it was at startup"
        );

        let unlock = Unlock::held(material, name);
        let mut src = Cursor::new(sealed_bytes.as_slice());
        let Ok(archive) = Archive::open(&mut src, &unlock) else {
            return;
        };

        // Past here the table of contents decrypted and its root row carried
        // the marker, so this is an archive reached through
        // `decrypt_table_of_contents` rather than around it.
        let _ = archive.check_names();
        let _ = archive.payload_extents();

        let count = u32::try_from(archive.entries().len()).unwrap_or(u32::MAX);
        for index in 0..count {
            let _ = archive.entry(index);
            let _ = archive.path(index);
            let _ = archive.allocation(index);
            let _ = archive.payload_at(index);
            let _ = archive.payload_is_resource(&mut src, index);

            // The streaming decrypt: a keyed entry is read through
            // `Decrypting`, an open one through `Clear`.
            if let Ok(stream) = archive.extracted(Cursor::new(sealed_bytes.as_slice()), index) {
                let _ = copy(&mut stream.take(DRAIN_LIMIT), &mut sink());
            }
        }
    });
});

/// The archive's length as `Archive::open` computes it.
fn sealed_len(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

/// The block `0, 1, … 15`, which names each position with its own index.
fn ladder() -> [u8; CIPHER_BLOCK_LEN] {
    let mut block = [0_u8; CIPHER_BLOCK_LEN];
    for (at, cell) in block.iter_mut().enumerate() {
        *cell = u8::try_from(at).unwrap_or(0);
    }
    block
}

/// The material every input is opened with, built once.
fn synthetic() -> &'static Arc<Material> {
    MATERIAL.get_or_init(|| {
        // Zero, so every expanded key is one key and each round contributes
        // only its table lookups: a non-zero round key would make the transform
        // affine rather than a permutation.
        let expanded = vec![0_u8; NG_EXPANDED_KEY_COUNT.saturating_mul(NG_EXPANDED_KEY_LEN)];
        Arc::new(
            Material::over_bytes(
                [AES_FILL; AES_KEY_LEN],
                [LUT_FILL; HASH_LUT_LEN],
                Some((expanded, network())),
                Some([AES_FILL; AES_KEY_LEN]),
            )
            .expect("the two halves are the lengths `NgKeys` promises"),
        )
    })
}

/// The decrypt tables, as a network that permutes bytes and mixes nothing.
///
/// `T[round][column][byte] = byte << 8·(column mod WORDS)`. Every position
/// feeding one output word lands in a distinct lane of it, whichever four
/// positions those are, so each round is a bijection and no table entry is
/// anything but one of the sixteen input bytes moved.
fn network() -> Vec<u8> {
    let mut tables = vec![0_u8; NG_DECRYPT_TABLE_COUNT.saturating_mul(NG_DECRYPT_TABLE_LEN)];
    for round in 0..NG_ROUNDS {
        for column in 0..NG_COLUMNS {
            let table = round.saturating_mul(NG_COLUMNS).saturating_add(column);
            let base = table.saturating_mul(NG_DECRYPT_TABLE_LEN);
            let lane = column % WORDS;
            for byte in 0_u32..=u32::from(u8::MAX) {
                let word = byte << (u8::BITS * u32::try_from(lane).unwrap_or(0));
                let at = base.saturating_add(
                    usize::try_from(byte)
                        .unwrap_or(0)
                        .saturating_mul(size_of::<u32>()),
                );
                if let Some(slot) = tables.get_mut(at..at.saturating_add(size_of::<u32>())) {
                    slot.copy_from_slice(&word.to_le_bytes());
                }
            }
        }
    }
    tables
}

/// The permutation the transform is, and its inverse, measured once.
///
/// `forward[at]` is the position whose byte the decrypt moves to `at`. So
/// sealing writes the plaintext byte at `at` into `forward[at]` of the
/// ciphertext, which is what `backward` records directly.
///
/// # Panics
///
/// If what came back is not a permutation, or if sealing does not round-trip
/// through it: either means the transform is no longer the shape this target
/// is built on.
fn transform() -> &'static ([u8; CIPHER_BLOCK_LEN], [u8; CIPHER_BLOCK_LEN]) {
    SHAPE.get_or_init(|| {
        let cipher = Cipher::new(Scheme::Ng, synthetic(), "", 0)
            .expect("the synthetic material carries the NG half");

        let mut forward = ladder();
        cipher.apply(&mut forward);

        let mut backward = [0_u8; CIPHER_BLOCK_LEN];
        let mut seen = [false; CIPHER_BLOCK_LEN];
        for (at, &from) in forward.iter().enumerate() {
            let from = usize::from(from);
            assert!(
                from < CIPHER_BLOCK_LEN && !seen[from],
                "the NG transform over this table network is not a permutation: {forward:?}"
            );
            seen[from] = true;
            backward[from] = u8::try_from(at).unwrap_or(0);
        }

        // The property the target rests on, stated once and checked once.
        let plain = ladder();
        let mut check = plain;
        permuted(&mut check, &backward);
        cipher.apply(&mut check);
        assert_eq!(
            check, plain,
            "sealing a block does not survive decrypting it"
        );

        (forward, backward)
    })
}

/// Every encryption tag `Version::scheme` names, found by asking it.
///
/// Not written down: a copy of `rpf7`'s tag values would go stale silently and
/// leave this stamping a word the crate no longer recognises. `Version::scheme`
/// is a public total function over `u32`, so the tags are looked for instead.
///
/// The scan costs seconds of process startup under AddressSanitizer, which is
/// why it is paid in [`setup`] rather than on an input's clock.
fn tags() -> &'static [u32] {
    TAGS.get_or_init(|| {
        let version = Version::Rpf7;
        let mut found: Vec<(u32, Scheme)> = Vec::new();
        for tag in 0..=u32::MAX {
            let Some(scheme) = version.scheme(tag) else {
                continue;
            };
            if found.iter().all(|(_, held)| *held != scheme) {
                found.push((tag, scheme));
            }
            // Every scheme an `AesKey` and the NG arm can name. Asserted below
            // so a scheme added later fails here rather than going unstamped.
            if found.len() == 3 {
                break;
            }
        }
        assert_eq!(
            found.len(),
            3,
            "`Version::scheme` names {} transforms, not the three this stamps",
            found.len()
        );
        found.into_iter().map(|(tag, _)| tag).collect()
    })
}

/// Where an archive's own encryption tag sits in its header, found rather than
/// written down.
///
/// `build` writes `Version::open()` there. Asserted unique, so a header that
/// grew a second field of the same value fails here instead of leaving the tag
/// stamped over something else.
fn tag_offset() -> usize {
    *TAG_AT.get_or_init(|| {
        let header = nested_to_the_bound();
        let open = Version::Rpf7.open().to_le_bytes();
        let hits: Vec<usize> = (0..CIPHER_BLOCK_LEN)
            .filter(|at| header.get(*at..at.saturating_add(open.len())) == Some(&open[..]))
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "the tag this build writes is at {hits:?} of its own header, not at one place"
        );
        hits.first().copied().unwrap_or(0)
    })
}

/// How long a header is, which is where the encrypted regions begin.
///
/// The tag is the header's last field. Asserted to be a whole number of cipher
/// blocks, which is the claim [`sealed`] rests on: every region an archive
/// decrypts then starts on a cipher block boundary of the file.
fn header_len() -> usize {
    let end = tag_offset().saturating_add(size_of::<u32>());
    assert_eq!(
        end % CIPHER_BLOCK_LEN,
        0,
        "a header of {end} bytes does not end on a cipher block, so no region is aligned"
    );
    end
}

/// Writes `tag` into the archive's encryption field.
fn stamped(data: &mut [u8], tag: u32) {
    let at = tag_offset();
    if let Some(slot) = data.get_mut(at..at.saturating_add(size_of::<u32>())) {
        slot.copy_from_slice(&tag.to_le_bytes());
    }
}

/// Applies the inverse transform to every whole cipher block past the header.
///
/// A tail shorter than a block is left exactly as it stands, which is the
/// format's own rule and `Cipher::apply`'s: the tail is neither padded nor
/// transformed.
fn sealed(data: &mut [u8], backward: &[u8; CIPHER_BLOCK_LEN]) {
    let Some(body) = data.get_mut(header_len()..) else {
        return;
    };
    let (blocks, _tail) = body.as_chunks_mut::<CIPHER_BLOCK_LEN>();
    for block in blocks {
        permuted(block, backward);
    }
}

/// Moves each byte of `block` to the position `order` names for it.
fn permuted(block: &mut [u8; CIPHER_BLOCK_LEN], order: &[u8; CIPHER_BLOCK_LEN]) {
    let source = *block;
    for (at, &to) in order.iter().enumerate() {
        if let (Some(cell), Some(byte)) = (block.get_mut(usize::from(to)), source.get(at)) {
            *cell = *byte;
        }
    }
}
