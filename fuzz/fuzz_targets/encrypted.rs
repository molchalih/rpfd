//! The encrypted read path: `decrypt_table_of_contents`, `Plain::Keyed`,
//! `Decrypting`, and the NG arm of `Cipher::block`.
//!
//! **Every other target here passes `Unlock::unkeyed()`, so every other target
//! stops at `NeedsKey`.** Five of them open archives and none has ever
//! decrypted a byte: the whole of `format::crypto`'s NG half, the table of
//! contents decrypt, and the streaming decrypt an entry is read through were
//! unreached by roughly three billion inputs. DR-048 argues why that was worth
//! opening a seam for and why this is the seam that costs nothing.
//!
//! # How a fuzz target holds a key
//!
//! It does not. `Material::over_bytes` — `#[cfg(fuzzing)]`, so it is in no
//! release build and in nothing a dependent compiles — takes bytes the caller
//! already has, and what this passes is a fill pattern and a table network
//! built below. No anchor is consulted and nothing is searched for, so this
//! reaches none of `keys::anchors` and says nothing about any real
//! installation. DR-006 is untouched: it is about where a real key comes from
//! and about what this repository carries, and neither is in question.
//!
//! # How an archive gets encrypted without an encryptor
//!
//! The library decrypts and never encrypts, so a target that wanted a real
//! ciphertext would have to write the inverse of a white-box transform, which
//! is not a thing that can be written. It does not have to: **the transform is
//! driven entirely by tables the material carries, and the material here is
//! ours.**
//!
//! `ng_round` makes each output word the exclusive-or of four table lookups
//! and a round-key word. Give every round key zero, and give the table for
//! byte position `c` the entry `T[c][b] = b << 8·(c mod 4)`, and each round
//! becomes a **byte permutation**: the four positions feeding one output word
//! land in four distinct lanes of it, so nothing is lost and nothing is mixed.
//! Seventeen such rounds compose to one fixed permutation of the sixteen
//! positions, whatever order the rounds read them in — which matters, because
//! the two orders are private to `crypto` and this deliberately does not
//! restate them (§3).
//!
//! So the permutation is **measured rather than derived**: decrypt the block
//! `0, 1, … 15` and read off where each position went. [`sealed`] applies the
//! inverse. [`transform`] asserts that what came back is a permutation at all
//! and that sealing round-trips, so a change to the round orders, the round
//! count or the table layout fails this target loudly instead of leaving it
//! quietly fuzzing an archive nothing will open.
//!
//! Sealing the whole file past its header seals every region's **body**
//! without knowing where any region is, which is the other thing that makes
//! this cheap: the permutation is applied to each aligned block of a region
//! independently, the header is one cipher block long, and every region an
//! archive decrypts — the entry table, the names blob, a payload at a block
//! offset — therefore starts on a cipher block boundary of the file itself.
//!
//! **A region whose length is not a whole number of blocks is a different
//! matter, and the seeds are what answer it.** The tail shorter than a block
//! is neither padded nor transformed — the format's rule, which `Cipher::apply`
//! and `Decrypting` both keep — so the reader leaves those bytes alone while a
//! seal that walks the file blockwise does not. Sealing them is not a defect
//! and needs no correcting: a names blob or a payload whose last few bytes are
//! not what the packer put there is hostile data, which is the whole supply
//! this target is fed. It matters only for the **seeds**, because a seed whose
//! names do not survive is a seed that reaches nothing past `check_names`. So
//! the seeds are built with every region a whole number of blocks — searched
//! for rather than reasoned about, and each one verified to read back its
//! plaintext byte for byte before it was written down. Measured: four seeds,
//! covering a stored payload, a deflated one, a mixed archive with a nested
//! directory and an open entry beside keyed ones, and a payload of exactly one
//! block.
//!
//! # What this does and does not say
//!
//! It says the encrypted **framing** holds against hostile bytes: which bytes
//! are transformed, where a block begins, what a short tail does, what a
//! stream hands out, and what the table-of-contents decrypt does with a table
//! that lies. That is the same thing `Cipher::over_zeros` is for in the
//! crate's own tests, one level up.
//!
//! It says nothing about the transform's **values**. The round keys are zero,
//! so all 101 of them are one key and `ng_key_index`'s answer does not change
//! what comes out — a defect in key *selection* is invisible here and is
//! pinned by `crypto`'s own tests and by the corpus NG archive instead.

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
/// Any bytes at all. It is here so that the AES-tagged arms have a key to fail
/// against — they reach the table-of-contents decrypt and its refusal, which
/// is the arm real archives take when a user points the tool at the wrong
/// executable.
const AES_FILL: u8 = 0x11;

/// The fill the synthetic hash lookup table is made of.
///
/// The NG name hash folds each byte through it, so it decides which of the 101
/// expanded keys a name chooses. A constant fill makes that choice a function
/// of the name's length alone, which is enough: the keys are identical.
const LUT_FILL: u8 = 0x22;

/// An archive, the name its key is derived from, and what to tag it.
#[derive(Debug, Arbitrary)]
struct Input<'a> {
    /// Which transform to tag the archive with, as an index into what
    /// [`tags`] found. Not a tag: the tag values belong to `format::rpf7` and
    /// are read out of the crate rather than copied into it (§3).
    scheme: u8,
    /// The archive's own file name, which with its length is what an NG key
    /// index is a function of. A renamed archive does not open, and that is
    /// the format's behaviour rather than ours.
    name: &'a str,
    /// The archive.
    data: &'a [u8],
}

fuzz_target!(|input: Input| {
    let Some(data) = bounded(input.data) else {
        return;
    };
    let Some(name) = bounded(input.name.as_bytes()).map(|_| input.name) else {
        return;
    };

    // Once per process, outside the watched region, for the reason
    // `nested.rs` builds its chain outside one: it is the same answer every
    // time and it is not what any input is about.
    let material = Arc::clone(synthetic());
    let (forward, backward) = *transform();

    watched(|| {
        let Some(&tag) = tags().get(usize::from(input.scheme) % tags().len()) else {
            return;
        };

        let mut sealed_bytes = data.to_vec();
        stamped(&mut sealed_bytes, tag);
        // Sealing an archive that will be refused for its key anyway costs
        // nothing and keeps one code path here rather than two. The AES arms
        // are refused; the NG arm opens.
        sealed(&mut sealed_bytes, &backward);

        // **The cipher this input's own name and length choose**, checked
        // before anything is opened so that it is checked on every input and
        // not only on the ones that open. `ng_key_index` is a function of both
        // — this is the one place it is reached with a name a fuzzer wrote —
        // and the answer must not change the transform, because all 101
        // expanded keys here are zero and therefore one key. A `forward` that
        // moved would mean the seal below no longer matches the opener, which
        // is the failure that would otherwise show up as nothing at all: an
        // archive that silently stops opening and a target that silently stops
        // testing.
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

            // The streaming decrypt. An entry whose own encryption field says
            // keyed is read through `Decrypting`; one that says open is read
            // through `Clear`, and which it is is the archive's to say.
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
    static MATERIAL: OnceLock<Arc<Material>> = OnceLock::new();
    MATERIAL.get_or_init(|| {
        // Zero, so that all 101 expanded keys are one key and each round
        // contributes only its table lookups. A non-zero round key would make
        // the transform affine rather than a permutation, and the inverse
        // would then have to be measured in two steps instead of one.
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
/// through it. Either means the transform is no longer the shape this target
/// is built on, and a target that carried on would be fuzzing archives that
/// cannot open.
fn transform() -> &'static ([u8; CIPHER_BLOCK_LEN], [u8; CIPHER_BLOCK_LEN]) {
    static SHAPE: OnceLock<([u8; CIPHER_BLOCK_LEN], [u8; CIPHER_BLOCK_LEN])> = OnceLock::new();
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
/// **Not written down.** `rpf7`'s tag values are that module's fact and §3
/// gives them one home; a copy here would go stale silently and leave this
/// target stamping a word the crate no longer recognises, which is exactly the
/// failure `docs/backlog.md` records for the target that fuzzed `rebuild`
/// where clients call `rewrite`. `Version::scheme` is a public total function
/// over `u32`, so the tags can simply be looked for.
///
/// The scan stops at the first tag naming each distinct scheme, which takes
/// 0.27 billion words. **Measured 2026-08-31 on the campaign box: 2.68 s of
/// process startup against 0.02 s for a target without it** — the cost is the
/// scan under AddressSanitizer, which instruments every one of those
/// comparisons.
///
/// Paid anyway, and the arithmetic is worth writing down rather than
/// re-deciding: libFuzzer's fork mode restarts a worker about every 45 s, so
/// this is roughly six percent of the target's time. What it buys is that a
/// tag value cannot go stale here without going stale in `rpf7` too — and
/// `docs/backlog.md` records what a fuzz target that has quietly stopped
/// testing what it claims costs, which is a whole campaign. The same trade
/// `nested_to_the_bound` makes, at a higher price.
fn tags() -> &'static [u32] {
    static TAGS: OnceLock<Vec<u32>> = OnceLock::new();
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
            // rather than assumed, so a scheme added later is a failure here
            // instead of an arm this target silently stops stamping.
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
/// `build` writes `Version::open()` there, so the offset is the one place in a
/// header **this build wrote** that holds the tag it wrote. Asserted unique,
/// so a header that grew a second field of the same value fails here instead
/// of leaving the tag stamped over something else.
fn tag_offset() -> usize {
    static AT: OnceLock<usize> = OnceLock::new();
    *AT.get_or_init(|| {
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
/// The tag is the header's last field, so the header ends four bytes after it.
/// Asserted to be a whole number of cipher blocks, because that is the claim
/// [`sealed`] rests on: every region an archive decrypts starts on a cipher
/// block boundary of the file, so sealing from here blockwise seals all of
/// them without knowing where any of them is.
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
