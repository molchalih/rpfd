//! The two transforms an RPF7 archive's bytes can be under.
//!
//! Both are block transforms with no chaining, which is what lets a bounded
//! region be decrypted where it is read and a payload be decrypted a block at a
//! time as it streams — an entry costs a block rather than its length (§7,
//! R3.9). [`CIPHER_BLOCK_LEN`] is the block, and what happens to what is left over.
//!
//! Which transform applies is the archive's tag, and the key is chosen by the
//! **name and length of the thing being decrypted** — the archive's own file
//! name and length for its table of contents, an entry's own name and
//! uncompressed length for its payload. `docs/rpf-format.md`, Encryption.
//!
//! Nothing here holds a key of its own, and nothing here prints one: a
//! [`Cipher`]'s `Debug` says which transform and which of the 101 expanded
//! keys, never a byte of either (DR-020).

use std::{fmt, sync::Arc};

use aes::Aes256;
use cipher::{BlockCipherDecrypt, KeyInit};

use crate::keys::{
    AES_KEY_LEN, HASH_LUT_LEN, LauncherKey, Material, NG_EXPANDED_KEY_COUNT, NG_EXPANDED_KEY_LEN,
    NG_ROUNDS, NgKeys,
};

/// The block both transforms work in, in bytes.
///
/// Named for the cipher because `rpf7::BLOCK_LEN` is 512 and is the unit
/// payload offsets are counted in — two numbers a reader would otherwise carry
/// a translation table for, in the same file (§9).
///
/// `docs/rpf-format.md`, Encryption, `verified`.
pub const CIPHER_BLOCK_LEN: usize = 16;

/// How many times the AES transform runs over each block.
///
/// **One**, measured — not the sixteen four implementations attest for RPF2
/// through RPF6. `docs/rpf-format.md`, Encryption, `verified`: 43 of 43
/// archives carrying the AES tag decode their root directory row after exactly
/// one AES-256-ECB decrypt, and none does after any other count in either
/// direction.
pub const AES_PASSES: usize = 1;

/// What the NG key index adds before it takes its remainder.
///
/// `docs/rpf-format.md`, Encryption, `verified`.
const NG_KEY_BIAS: u32 = 61;

/// The multiplier the NG name hash folds each byte with.
///
/// This and the four below are one fact — the hash that chooses the key —
/// and `docs/rpf-format.md`, Encryption, `verified` is where it is measured:
/// a brute force over all 101 expanded keys finds one that opens the corpus NG
/// archive, and this arithmetic answers the same number.
const NG_HASH_MULTIPLIER: u32 = 1025;

/// How far the NG name hash shifts each intermediate before folding it back.
const NG_HASH_SHIFT: u32 = 6;

/// The multiplier the NG name hash finishes with.
const NG_HASH_FINAL_MULTIPLIER: u32 = 9;

/// How far the NG name hash shifts its finished value before folding it back.
const NG_HASH_FINAL_SHIFT: u32 = 11;

/// The multiplier the NG name hash scales its finished value by.
const NG_HASH_SCALE: u32 = 32769;

/// How many bytes one round of the NG transform takes from the expanded key.
///
/// The block, not the column count. The two are both 16 and they are two facts:
/// a round key is as long as the block it is exclusive-ored into, and it would
/// stay that length if the transform read its bytes in some other number of
/// groups.
const NG_ROUND_KEY_LEN: usize = CIPHER_BLOCK_LEN;

/// Which of the sixteen input bytes each of the four output words is made of,
/// in the rounds that read them in column order.
///
/// Rounds 0, 1 and 16. `docs/rpf-format.md`, Encryption, `verified`.
const NG_COLUMN_ORDER: [[usize; 4]; 4] =
    [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]];

/// The same, in the rounds that read them through a shift-rows permutation.
///
/// Rounds 2 through 15. `docs/rpf-format.md`, Encryption, `verified`.
const NG_SHIFTED_ORDER: [[usize; 4]; 4] =
    [[0, 7, 10, 13], [1, 4, 11, 14], [2, 5, 8, 15], [3, 6, 9, 12]];

/// The last round, which reads in column order again.
const NG_LAST_ROUND: usize = NG_ROUNDS.saturating_sub(1);

/// How many rounds read in column order before the permuted ones begin.
const NG_LEADING_ROUNDS: usize = 2;

/// Which AES-256 key an archive's tag chose.
///
/// **The tag selects a key, not an algorithm**: `0x0FFFFFF9` and `0x0FFFFFF7`
/// are the same cipher, the same mode and the same pass count, and they differ
/// only in which 32-byte key runs it. `docs/rpf-format.md`, Encryption,
/// `verified`; DR-042.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AesKey {
    /// The RAGE key, which every source carries and which opens every
    /// `0x0FFFFFF9` archive there is.
    Rage,
    /// The Rockstar Games Launcher's own key, which only `Launcher.exe`
    /// carries.
    Launcher,
}

impl AesKey {
    /// The key itself, out of the material that carries it, or `None` where it
    /// does not.
    fn of(self, material: &Material) -> Option<&[u8; AES_KEY_LEN]> {
        match self {
            Self::Rage => Some(material.keys().aes_key()),
            Self::Launcher => material.launcher().map(LauncherKey::key),
        }
    }
}

/// Which transform an archive's bytes are under.
///
/// Named by the archive's encryption tag, which is the version's to read:
/// [`crate::Version::scheme`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// The RAGE AES-256 transform. One ECB pass, no chaining, and the key its
    /// tag names.
    Aes(AesKey),
    /// The NG white-box transform. Seventeen rounds of table lookups, and one
    /// of 101 expanded keys chosen by what is being decrypted.
    Ng,
}

impl Scheme {
    /// What this transform is called where a message has to name it.
    ///
    /// The AES arms are named apart because a caller told its key is the wrong
    /// one has two different things to do about it: extract from a game
    /// executable, or from the launcher's. DR-010, DR-041.
    #[must_use]
    pub const fn named(self) -> &'static str {
        match self {
            Self::Aes(AesKey::Rage) => "AES-256",
            Self::Aes(AesKey::Launcher) => "AES-256 (launcher)",
            Self::Ng => "NG",
        }
    }

    /// Whether `material` carries what this transform needs.
    ///
    /// Every source carries the RAGE key; only a memory image carries the NG
    /// expanded keys and decrypt tables (DR-040), and only `Launcher.exe`
    /// carries the launcher key (DR-042). So an executable's material opens an
    /// AES archive under the RAGE key and neither of the others.
    #[must_use]
    pub fn is_in(self, material: &Material) -> bool {
        match self {
            Self::Aes(which) => which.of(material).is_some(),
            Self::Ng => material.ng().is_some(),
        }
    }
}

/// One buffer's or one payload's decryption, with its key already chosen.
///
/// Owned rather than borrowed: [`crate::Extracted`] has no lifetime to borrow
/// through, because §7 hands it the source by value and it is read long after
/// the call that made it.
#[derive(Clone)]
pub struct Cipher {
    inner: Inner,
}

/// The transform, and whatever running it needs.
#[derive(Clone)]
enum Inner {
    /// An AES key, expanded once, and which one it was. Boxed because the
    /// expansion is a kilobyte and the other arm is two words, and this enum is
    /// inside every stream.
    Aes {
        /// Which key the tag chose. Carried so that `Debug` names the transform
        /// this cipher actually is — a discriminant, never a key: DR-020.
        which: AesKey,
        /// The expanded key schedule.
        aes: Box<Aes256>,
    },
    /// The decrypt tables, the expanded key this buffer chose, and which one it
    /// was.
    Ng {
        /// Where the decrypt tables live. 278 KB, shared by every cipher over
        /// the same material.
        tables: Arc<NgKeys>,
        /// Which expanded key, in `0..NG_EXPANDED_KEY_COUNT`. An index for
        /// [`Cipher`]'s `Debug` to print, never a key: DR-020.
        key: usize,
        /// **The key itself, resolved here rather than at every block.**
        ///
        /// It used to be looked up per block and a miss returned the block
        /// undecrypted, with no error — plausible garbage handed back as
        /// contents, which is the one answer §4 rules out. A cipher that exists
        /// has its key, so there is no miss left to be silent about.
        expanded: Box<[u8; NG_EXPANDED_KEY_LEN]>,
    },
}

impl Cipher {
    /// The transform for `scheme`, keyed by the name and length of what is
    /// being decrypted, or `None` when `material` does not carry what the
    /// transform needs.
    ///
    /// `name` is the archive's own file name for its table of contents and the
    /// entry's own name for a payload; `len` is that archive's length or that
    /// entry's uncompressed length. Both are what the key index is a function
    /// of, so a renamed archive does not open — the format's behaviour and not
    /// ours (`docs/rpf-format.md`, Encryption). [`Scheme::is_in`] is the `None`
    /// case asked before a source is chosen.
    #[must_use]
    pub fn new(scheme: Scheme, material: &Material, name: &str, len: u64) -> Option<Self> {
        let inner = match scheme {
            Scheme::Aes(which) => Inner::Aes {
                which,
                aes: Box::new(Aes256::new_from_slice(which.of(material)?).ok()?),
            },
            Scheme::Ng => {
                let key = ng_key_index(material.keys().hash_lut(), name.as_bytes(), len);
                let tables = Arc::clone(material.ng_shared()?);
                let expanded = Box::new((*tables.expanded_key(key)?).try_into().ok()?);
                Inner::Ng {
                    tables,
                    key,
                    expanded,
                }
            }
        };
        Some(Self { inner })
    }

    /// Which of the 101 NG expanded keys this chose, where it chose one.
    ///
    /// An index, never a key: DR-020.
    #[must_use]
    pub const fn key_index(&self) -> Option<usize> {
        match self.inner {
            Inner::Aes { .. } => None,
            Inner::Ng { key, .. } => Some(key),
        }
    }

    /// Decrypts `buf` in place, leaving a tail shorter than [`CIPHER_BLOCK_LEN`]
    /// exactly as it stands.
    ///
    /// **The tail is neither padded nor transformed**, which is a separate fact
    /// from the block length and not a consequence of it: a block cipher of
    /// sixteen bytes says nothing about what a packer did with the last six.
    /// `docs/rpf-format.md`, Encryption, `verified` — `content.xml` in the
    /// corpus NG archive is 358 bytes on disk, and reading it this way inflates
    /// to the 888 its entry declares, where decrypting the 6-byte tail as
    /// though it had been padded gives 857.
    ///
    /// The one statement of that rule. `archive::Decrypting` is the same rule
    /// streaming rather than buffered, and points here for it.
    pub fn apply(&self, buf: &mut [u8]) {
        let (blocks, _tail) = buf.as_chunks_mut::<CIPHER_BLOCK_LEN>();
        for block in blocks {
            self.block(block);
        }
    }

    /// Decrypts one whole block in place.
    ///
    /// The one implementation of either transform, so the buffered form above
    /// and the streaming form in `archive` cannot come to disagree (§3).
    pub(crate) fn block(&self, block: &mut [u8; CIPHER_BLOCK_LEN]) {
        match self.inner {
            Inner::Aes { ref aes, .. } => {
                for _ in 0..AES_PASSES {
                    let mut wide = (*block).into();
                    aes.decrypt_block(&mut wide);
                    *block = wide.into();
                }
            }
            Inner::Ng {
                ref tables,
                ref expanded,
                ..
            } => ng_block(tables, expanded, block),
        }
    }
}

#[cfg(test)]
impl Cipher {
    /// The AES transform over a key of thirty-two zero bytes.
    ///
    /// For testing the **framing** — which bytes are transformed, where a block
    /// begins, what a stream hands out — rather than the values. No key
    /// material is involved, which is what DR-006 is about, and it is
    /// `#[cfg(test)]` so it is not part of the crate's surface.
    ///
    /// One spelling, here, because two modules want it: this module's own tests
    /// and `archive`'s, which have no other way to reach the streaming path
    /// without a game installation (§4).
    pub(crate) fn over_zeros() -> Self {
        Self {
            inner: Inner::Aes {
                which: AesKey::Rage,
                aes: Box::new(
                    Aes256::new_from_slice(&[0_u8; AES_KEY_LEN]).expect("thirty-two bytes"),
                ),
            },
        }
    }
}

/// By hand, so that no key can reach a log, a panic message or a `--json`
/// payload by being printed. DR-020.
impl fmt::Debug for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.inner {
            Inner::Aes { which, .. } => f
                .debug_struct("Cipher")
                .field("scheme", &Scheme::Aes(which))
                .finish_non_exhaustive(),
            Inner::Ng { key, .. } => f
                .debug_struct("Cipher")
                .field("scheme", &Scheme::Ng)
                .field("key_index", &key)
                .finish_non_exhaustive(),
        }
    }
}

/// The NG name hash, over the 256-byte lookup table the material carries.
///
/// It folds case: the same name in either case answers the same value, which is
/// the table's doing and is measured rather than assumed —
/// `docs/rpf-format.md`, Encryption, `verified`.
fn ng_hash(lut: &[u8; HASH_LUT_LEN], name: &[u8]) -> u32 {
    let mut result: u32 = 0;
    for &byte in name {
        let folded = u32::from(lut.get(usize::from(byte)).copied().unwrap_or(byte));
        let mixed = NG_HASH_MULTIPLIER.wrapping_mul(folded.wrapping_add(result));
        result = (mixed >> NG_HASH_SHIFT) ^ mixed;
    }
    let scaled = result.wrapping_mul(NG_HASH_FINAL_MULTIPLIER);
    NG_HASH_SCALE.wrapping_mul((scaled >> NG_HASH_FINAL_SHIFT) ^ scaled)
}

/// Which of the 101 expanded keys a name of this length chose.
///
/// `docs/rpf-format.md`, Encryption, `verified`.
fn ng_key_index(lut: &[u8; HASH_LUT_LEN], name: &[u8], len: u64) -> usize {
    // The length is a 32-bit field in the packer that chose the key, so a
    // longer one wraps rather than saturating: saturating would pick a
    // different key from the one that wrote the archive.
    let len = u32::try_from(len & u64::from(u32::MAX)).unwrap_or(u32::MAX);
    let mixed = ng_hash(lut, name)
        .wrapping_add(len)
        .wrapping_add(NG_KEY_BIAS);
    // The modulus is `keys::NG_EXPANDED_KEY_COUNT` and not a second spelling of
    // 101: it is what the anchors array, the cache layout and
    // `NgKeys::expanded_key`'s own bound are written against, so an index this
    // produces is an index that material has (§3).
    usize::try_from(mixed).unwrap_or(0) % NG_EXPANDED_KEY_COUNT
}

/// The little-endian `u32` at `at` in `bytes`, or `None` when it does not fit.
fn word_at(bytes: &[u8], at: usize) -> Option<u32> {
    let word = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([
        *word.first()?,
        *word.get(1)?,
        *word.get(2)?,
        *word.get(3)?,
    ]))
}

/// The word a decrypt table holds for one input byte.
fn table_word(table: &[u8], byte: u8) -> Option<u32> {
    word_at(table, usize::from(byte).checked_mul(4)?)
}

/// One round: four output words, each the exclusive-or of four table lookups
/// and one round-key word.
fn ng_round(
    ng: &NgKeys,
    round: usize,
    round_key: &[u8; NG_ROUND_KEY_LEN],
    order: &[[usize; 4]; 4],
    block: &mut [u8; CIPHER_BLOCK_LEN],
) {
    let source = *block;
    // Four words in and four out, by construction rather than by a bound check
    // that could fall through and leave a word as it was.
    let (round_words, _) = round_key.as_chunks::<4>();
    let (out_words, _) = block.as_chunks_mut::<4>();
    for ((columns, key_word), out) in order.iter().zip(round_words).zip(out_words) {
        let mut word = u32::from_le_bytes(*key_word);
        for &column in columns {
            let (Some(table), Some(byte)) = (ng.decrypt_table(round, column), source.get(column))
            else {
                continue;
            };
            word ^= table_word(table, *byte).unwrap_or_default();
        }
        *out = word.to_le_bytes();
    }
}

/// The whole NG transform over one block: two rounds in column order, fourteen
/// permuted, and one in column order again.
///
/// `docs/rpf-format.md`, Encryption, `verified`.
fn ng_block(ng: &NgKeys, expanded: &[u8; NG_EXPANDED_KEY_LEN], block: &mut [u8; CIPHER_BLOCK_LEN]) {
    // 272 bytes divide into exactly 17 round keys of 16, which is what
    // `a_round_key_is_the_block_and_the_key_holds_one_per_round` pins. So the
    // rounds are the chunks, and there is no arm in which a round runs without
    // its key.
    let (round_keys, _) = expanded.as_chunks::<NG_ROUND_KEY_LEN>();
    for (round, round_key) in round_keys.iter().enumerate() {
        let order = if round < NG_LEADING_ROUNDS || round == NG_LAST_ROUND {
            &NG_COLUMN_ORDER
        } else {
            &NG_SHIFTED_ORDER
        };
        ng_round(ng, round, round_key, order, block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `ng_key_index` answers for `dlc.rpf` at 6,144 bytes over a lookup
    /// table of the identity. Measured, and the number the real table gives for
    /// this name too — see the gated brute force named below.
    const GOLDEN_DLC: usize = 62;
    /// The same for `content.xml` at 888 bytes.
    const GOLDEN_CONTENT: usize = 66;
    /// The same for the empty name at length zero, which is the bias alone.
    const GOLDEN_EMPTY: usize = 61;

    /// As [`Cipher::over_zeros`], under the name these tests read by.
    fn framing_only() -> Cipher {
        Cipher::over_zeros()
    }

    #[test]
    fn the_two_orders_are_the_ones_the_format_uses() {
        // The permutation test below says only that each order reads all
        // sixteen bytes once, which `[0, 13, 10, 7]` also satisfies. These are
        // the rows themselves: `docs/rpf-format.md`, Encryption, `verified` —
        // rounds 0, 1 and 16 read `0,1,2,3 / 4,5,6,7 / 8,9,10,11 /
        // 12,13,14,15`, and rounds 2 through 15 read `0,7,10,13 / 1,4,11,14 /
        // 2,5,8,15 / 3,6,9,12`.
        assert_eq!(
            NG_COLUMN_ORDER,
            [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]]
        );
        assert_eq!(
            NG_SHIFTED_ORDER,
            [[0, 7, 10, 13], [1, 4, 11, 14], [2, 5, 8, 15], [3, 6, 9, 12]]
        );
    }

    #[test]
    fn the_two_orders_are_permutations_of_the_same_sixteen_bytes() {
        // A round that read a byte twice, or missed one, would still decrypt
        // most of a block and corrupt the rest — which is the failure that
        // shows up as one wrong entry rather than as a refusal.
        for order in [NG_COLUMN_ORDER, NG_SHIFTED_ORDER] {
            let mut seen = [false; CIPHER_BLOCK_LEN];
            for group in order {
                for column in group {
                    assert!(!seen[column], "column {column} is read twice");
                    seen[column] = true;
                }
            }
            assert!(seen.iter().all(|&hit| hit), "a column is never read");
        }
    }

    #[test]
    fn the_permuted_rounds_are_the_middle_fourteen() {
        // Rounds 0, 1 and 16 read in column order; 2 through 15 do not.
        // `docs/rpf-format.md`, Encryption.
        let permuted = |round: usize| round >= NG_LEADING_ROUNDS && round != NG_LAST_ROUND;
        assert_eq!(NG_ROUNDS, 17);
        assert_eq!(NG_LAST_ROUND, 16);
        assert_eq!((0..NG_ROUNDS).filter(|&r| permuted(r)).count(), 14);
        for round in [0, 1, 16] {
            assert!(
                !permuted(round),
                "round {round} should read in column order"
            );
        }
        assert_ne!(NG_COLUMN_ORDER, NG_SHIFTED_ORDER);
    }

    #[test]
    fn the_hash_arithmetic_is_pinned_byte_for_byte() {
        // Golden values over a lookup table of the identity, which is what
        // makes the hash a pure function of the bytes with no key material in
        // the repository (DR-006). Every constant the hash is made of reaches
        // these numbers, `NG_KEY_BIAS` included: changing 61 to 62 used to turn
        // nothing red anywhere in the suite.
        //
        // These pin **drift**. What pins the constants being *right* is
        // `crates/rpf-core/tests/encrypted.rs`'s
        // `the_hash_chooses_the_key_a_brute_force_over_all_of_them_finds`,
        // which checks them against an answer the arithmetic did not produce.
        let lut: [u8; HASH_LUT_LEN] =
            std::array::from_fn(|index| u8::try_from(index & 0xFF).unwrap_or_default());
        for (name, len, index) in [
            (&b"dlc.rpf"[..], 6_144_u64, GOLDEN_DLC),
            (&b"content.xml"[..], 888, GOLDEN_CONTENT),
            (&b""[..], 0, GOLDEN_EMPTY),
        ] {
            assert_eq!(ng_key_index(&lut, name, len), index, "{name:?} {len}");
        }
    }

    #[test]
    fn the_key_index_is_a_function_of_both_the_name_and_the_length() {
        // The lookup table is not in this repository (DR-006), so this pins the
        // arithmetic around it rather than the values it produces: a table of
        // the identity makes the hash a pure function of the bytes.
        let lut: [u8; HASH_LUT_LEN] =
            std::array::from_fn(|index| u8::try_from(index & 0xFF).unwrap_or_default());
        assert_ne!(
            ng_key_index(&lut, b"dlc.rpf", 6_144),
            ng_key_index(&lut, b"dlc.rpf", 6_145),
            "the length has to reach the index"
        );
        assert_ne!(
            ng_key_index(&lut, b"dlc.rpf", 6_144),
            ng_key_index(&lut, b"dlc.rpg", 6_144),
            "the name has to reach the index"
        );
    }

    #[test]
    fn the_key_index_never_leaves_the_range_the_material_has() {
        // An index past the keys read no key at all, and the block used to come
        // back undecrypted for it with no error. The bound is
        // `NG_EXPANDED_KEY_COUNT` rather than a literal because that is the one
        // that `NgKeys::expanded_key` is written against (§3).
        let lut: [u8; HASH_LUT_LEN] = [0; HASH_LUT_LEN];
        for len in [0_u64, 1, 101, u64::from(u32::MAX), u64::MAX] {
            assert!(ng_key_index(&lut, b"a.rpf", len) < NG_EXPANDED_KEY_COUNT);
        }
        for name in ["", "a", &"z".repeat(4096)] {
            assert!(ng_key_index(&lut, name.as_bytes(), 7) < NG_EXPANDED_KEY_COUNT);
        }
    }

    #[test]
    fn the_index_reaches_every_key_the_material_holds_and_no_other() {
        // The modulus and `NgKeys::expanded_key`'s bound were two constants,
        // and a drift between them was silent: `expanded_key` answered `None`,
        // `ng_block` returned early, and the block was handed back in the clear
        // as though it had been decrypted. One owner, and this says the range
        // it produces is exactly the range the material has.
        let lut: [u8; HASH_LUT_LEN] =
            std::array::from_fn(|index| u8::try_from(index & 0xFF).unwrap_or_default());
        let reached: std::collections::BTreeSet<usize> = (0..4096_u64)
            .map(|len| ng_key_index(&lut, b"dlc.rpf", len))
            .collect();
        assert_eq!(reached.len(), NG_EXPANDED_KEY_COUNT);
        assert_eq!(
            reached.iter().copied().max(),
            NG_EXPANDED_KEY_COUNT.checked_sub(1)
        );
    }

    #[test]
    fn a_round_key_is_a_block_and_an_expanded_key_holds_one_per_round() {
        // What `ng_block` divides the expanded key by. 272 bytes is 17 round
        // keys of 16 exactly, with nothing left over — which is why the rounds
        // can be the chunks and no round can run without its key.
        assert_eq!(NG_ROUND_KEY_LEN, CIPHER_BLOCK_LEN);
        assert_eq!(
            NG_EXPANDED_KEY_LEN,
            NG_ROUNDS.saturating_mul(NG_ROUND_KEY_LEN),
        );
        assert_eq!(NG_EXPANDED_KEY_LEN % NG_ROUND_KEY_LEN, 0);
    }

    #[test]
    fn a_length_past_the_field_wraps_rather_than_saturating() {
        // The packer's own arithmetic is 32-bit, so a hypothetical 4 GiB
        // archive picks the key its low word chooses, not the one `u32::MAX`
        // would.
        let lut: [u8; HASH_LUT_LEN] = [0; HASH_LUT_LEN];
        assert_eq!(
            ng_key_index(&lut, b"a.rpf", 4_294_967_296),
            ng_key_index(&lut, b"a.rpf", 0)
        );
    }

    #[test]
    fn a_word_is_read_little_endian_and_in_bounds() {
        let table = [0x01_u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(table_word(&table, 0), Some(0x0403_0201));
        assert_eq!(table_word(&table, 1), Some(0x0807_0605));
        assert_eq!(table_word(&table, 2), None);
        assert_eq!(word_at(&table, 5), None);
    }

    #[test]
    fn a_tail_shorter_than_a_block_is_carried_through() {
        // The rule the format sets, and what a buffer whose length is not a
        // multiple of sixteen depends on.
        let cipher = framing_only();
        let mut buf = [1_u8, 2, 3, 4, 5];
        let before = buf;
        cipher.apply(&mut buf);
        assert_eq!(buf, before, "a sub-block tail is not transformed");

        let mut whole = [9_u8; CIPHER_BLOCK_LEN + 5];
        cipher.apply(&mut whole);
        assert_ne!(
            whole.get(..CIPHER_BLOCK_LEN),
            Some([9_u8; CIPHER_BLOCK_LEN].as_slice()),
            "the whole block is transformed"
        );
        assert_eq!(
            whole.get(CIPHER_BLOCK_LEN..),
            Some([9_u8; 5].as_slice()),
            "and the tail after it is not"
        );
    }

    #[test]
    fn nothing_a_cipher_prints_is_a_key() {
        // DR-020, checked where it is easiest to lose.
        let rendered = format!("{:?}", framing_only());
        assert!(rendered.contains("Aes"), "{rendered}");
        assert!(!rendered.contains("00"), "{rendered}");
    }

    #[test]
    fn an_empty_buffer_decrypts_to_itself() {
        let mut nothing: [u8; 0] = [];
        framing_only().apply(&mut nothing);
    }
}
