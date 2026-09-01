//! The two transforms an RPF7 archive's bytes can be under.
//!
//! Both are block transforms with no chaining. The transform is the archive's
//! tag; the key is chosen by the name and length of what is being decrypted —
//! the archive's own for its table of contents, an entry's own for a payload.

use std::{fmt, sync::Arc};

use aes::Aes256;
use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

use crate::keys::{
    AES_KEY_LEN, HASH_LUT_LEN, LauncherKey, Material, NG_COLUMNS, NG_EXPANDED_KEY_COUNT,
    NG_EXPANDED_KEY_LEN, NG_ROUNDS, NgKeys,
};

/// The block both transforms work in, in bytes. Not `rpf7::BLOCK_LEN`, which
/// is 512 and is the unit payload offsets are counted in.
pub const CIPHER_BLOCK_LEN: usize = 16;

/// How many times the AES transform runs over each block: one, not the
/// sixteen older RPF versions use.
pub const AES_PASSES: usize = 1;

/// What the NG key index adds before it takes its remainder.
const NG_KEY_BIAS: u32 = 61;

/// The multiplier the NG name hash folds each byte with.
///
/// This and the four below are one fact: the hash that chooses the key.
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
/// The block, not the column count: both are 16, but they are two facts.
const NG_ROUND_KEY_LEN: usize = CIPHER_BLOCK_LEN;

/// Which of the sixteen input bytes each of the four output words is made of,
/// in the rounds that read them in column order: rounds 0, 1 and 16.
const NG_COLUMN_ORDER: [[usize; 4]; 4] =
    [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]];

/// The same, in the rounds that read them through a shift-rows permutation:
/// rounds 2 through 15.
const NG_SHIFTED_ORDER: [[usize; 4]; 4] =
    [[0, 7, 10, 13], [1, 4, 11, 14], [2, 5, 8, 15], [3, 6, 9, 12]];

/// The last round, which reads in column order again.
const NG_LAST_ROUND: usize = NG_ROUNDS.saturating_sub(1);

/// How many rounds read in column order before the permuted ones begin.
const NG_LEADING_ROUNDS: usize = 2;

/// Which AES-256 key an archive's tag chose: `0x0FFFFFF9` and `0x0FFFFFF7`
/// are the same cipher and mode under different 32-byte keys.
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

/// Which transform an archive's bytes are under, named by its encryption tag.
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
    /// What this transform is called where a message has to name it. The AES
    /// arms are named apart because their keys come from different files.
    #[must_use]
    pub const fn named(self) -> &'static str {
        match self {
            Self::Aes(AesKey::Rage) => "AES-256",
            Self::Aes(AesKey::Launcher) => "AES-256 (launcher)",
            Self::Ng => "NG",
        }
    }

    /// Whether this transform can be run forwards over `material`, so that an
    /// archive under it can be written back. AES is symmetric and keyed by the
    /// tag; NG seals when the decrypt tables are here to derive it from.
    #[must_use]
    pub fn seals(self, material: Option<&Material>) -> bool {
        match self {
            Self::Aes(_) => true,
            Self::Ng => material.is_some_and(|held| held.ng().is_some()),
        }
    }

    /// Whether an archive under this transform is keyed by the name it is
    /// found under. AES takes its key from the tag alone; every NG region is
    /// keyed by `(hash(name) + length + 61) % 101`.
    #[must_use]
    pub const fn keyed_by_name(self) -> bool {
        match self {
            Self::Aes(_) => false,
            Self::Ng => true,
        }
    }

    /// Whether `material` carries what this transform needs: every source has
    /// the RAGE key, only a memory image the NG tables, only `Launcher.exe`
    /// the launcher key.
    #[must_use]
    pub fn is_in(self, material: &Material) -> bool {
        match self {
            Self::Aes(which) => which.of(material).is_some(),
            Self::Ng => material.ng().is_some(),
        }
    }
}

/// One buffer's or one payload's decryption, with its key already chosen.
/// Owned, because it is read long after the call that made it.
#[derive(Clone)]
pub struct Cipher {
    inner: Inner,
}

/// The transform, and whatever running it needs.
#[derive(Clone)]
enum Inner {
    /// An AES key, expanded once, and which one it was. Boxed because the
    /// expansion is a kilobyte and this enum is inside every stream.
    Aes {
        /// Which key the tag chose: a discriminant, never a key.
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
        /// Which expanded key, in `0..NG_EXPANDED_KEY_COUNT`. An index, never
        /// a key.
        key: usize,
        /// The key itself, resolved here rather than at every block, so no
        /// per-block miss can hand a block back undecrypted.
        expanded: Box<[u8; NG_EXPANDED_KEY_LEN]>,
    },
}

impl Cipher {
    /// The transform for `scheme`, keyed by the name and length of what is
    /// being decrypted, or `None` when `material` lacks what it needs. The key
    /// index is a function of both, so a renamed archive does not open.
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
    #[must_use]
    pub const fn key_index(&self) -> Option<usize> {
        match self.inner {
            Inner::Aes { .. } => None,
            Inner::Ng { key, .. } => Some(key),
        }
    }

    /// Decrypts `buf` in place, leaving a tail shorter than [`CIPHER_BLOCK_LEN`]
    /// exactly as it stands: neither padded nor transformed.
    pub fn apply(&self, buf: &mut [u8]) {
        let (blocks, _tail) = buf.as_chunks_mut::<CIPHER_BLOCK_LEN>();
        for block in blocks {
            self.block(block);
        }
    }

    /// Decrypts one whole block in place: the one implementation of either
    /// transform, shared with the streaming form in `archive`.
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

/// What mints a [`Seal`] for one region of one archive: the forward transform
/// is derived once, and one [`Seal`] minted per region, since the NG key index
/// is a function of that region's name and length.
pub struct Sealer {
    inner: SealerInner,
}

/// The forward transform, and whatever minting a key for a region needs.
enum SealerInner {
    /// An AES key, expanded once. It takes neither a name nor a length: the key
    /// is the tag's and nothing else.
    Aes {
        /// Which key the tag chose: a discriminant, never a key.
        which: AesKey,
        /// The expanded key schedule, shared by every region's seal.
        aes: Arc<Aes256>,
    },
    /// The derived forward transform, and what a region's key is chosen out of.
    Ng {
        /// The material's own expanded keys, one of which each region picks.
        tables: Arc<NgKeys>,
        /// All seventeen rounds, derived once from the decrypt tables in
        /// `tables` and shared by every region's seal.
        forward: Arc<NgForward>,
        /// The name-hash lookup table, which is half of the key index.
        lut: Box<[u8; HASH_LUT_LEN]>,
    },
}

impl Sealer {
    /// The forward transform for `scheme` over `material`, or `None` where
    /// `material` carries no key of the tag's kind, or NG tables that do not
    /// derive.
    #[must_use]
    pub fn new(scheme: Scheme, material: &Material) -> Option<Self> {
        let inner = match scheme {
            Scheme::Aes(which) => SealerInner::Aes {
                which,
                aes: Arc::new(Aes256::new_from_slice(which.of(material)?).ok()?),
            },
            Scheme::Ng => {
                let tables = Arc::clone(material.ng_shared()?);
                let forward = Arc::new(NgForward::derive(&tables).ok()?);
                SealerInner::Ng {
                    tables,
                    forward,
                    lut: Box::new(*material.keys().hash_lut()),
                }
            }
        };
        Some(Self { inner })
    }

    /// Which transform this runs.
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        match self.inner {
            SealerInner::Aes { which, .. } => Scheme::Aes(which),
            SealerInner::Ng { .. } => Scheme::Ng,
        }
    }

    /// The seal for one region, keyed by the name and length of what is being
    /// written. `len` is the region's **new** length: sealing under the old
    /// one writes an archive that parses and does not load.
    #[must_use]
    pub fn seal(&self, name: &str, len: u64) -> Option<Seal> {
        let inner = match self.inner {
            SealerInner::Aes { which, ref aes } => SealInner::Aes {
                which,
                aes: Arc::clone(aes),
            },
            SealerInner::Ng {
                ref tables,
                ref forward,
                ref lut,
            } => {
                let key = ng_key_index(lut, name.as_bytes(), len);
                SealInner::Ng {
                    forward: Arc::clone(forward),
                    key,
                    expanded: Box::new((*tables.expanded_key(key)?).try_into().ok()?),
                }
            }
        };
        Some(Seal { inner })
    }
}

/// By hand, so that no key can reach a log or a panic message by being
/// printed.
impl fmt::Debug for Sealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealer")
            .field("scheme", &self.scheme())
            .finish_non_exhaustive()
    }
}

/// One region's or one payload's encryption: the inverse of a [`Cipher`]. Keyed
/// for one region and not [`Clone`], because the NG key index is a function of
/// that region's name and length.
pub struct Seal {
    inner: SealInner,
}

/// The forward transform, keyed for one region.
enum SealInner {
    /// The expanded AES key schedule, and which key the tag chose.
    Aes {
        /// A discriminant, never a key.
        which: AesKey,
        /// The expanded key schedule.
        aes: Arc<Aes256>,
    },
    /// The derived transform and the expanded key this region chose.
    Ng {
        /// All seventeen rounds, shared with every other region's seal.
        forward: Arc<NgForward>,
        /// Which expanded key, in `0..NG_EXPANDED_KEY_COUNT`. An index, never
        /// a key.
        key: usize,
        /// The key itself, resolved when the seal was minted rather than at
        /// every block.
        expanded: Box<[u8; NG_EXPANDED_KEY_LEN]>,
    },
}

impl Seal {
    /// [`Sealer::new`] and [`Sealer::seal`] in one call, for a caller sealing
    /// a single region; one sealing a whole archive holds the [`Sealer`] so
    /// the transform is derived once rather than per payload.
    #[must_use]
    pub fn new(scheme: Scheme, material: &Material, name: &str, len: u64) -> Option<Self> {
        Sealer::new(scheme, material)?.seal(name, len)
    }

    /// Which of the 101 NG expanded keys this chose, where it chose one.
    #[must_use]
    pub const fn key_index(&self) -> Option<usize> {
        match self.inner {
            SealInner::Aes { .. } => None,
            SealInner::Ng { key, .. } => Some(key),
        }
    }

    /// Encrypts `buf` in place, leaving a tail shorter than
    /// [`CIPHER_BLOCK_LEN`] exactly as it stands, as [`Cipher::apply`] does.
    /// `buf` is one whole region, counted from its own start.
    pub fn apply(&self, buf: &mut [u8]) {
        let (blocks, _tail) = buf.as_chunks_mut::<CIPHER_BLOCK_LEN>();
        for block in blocks {
            self.block(block);
        }
    }

    /// Encrypts one whole block in place: the one implementation of the
    /// forward transform, shared with the streaming form in [`crate::build`].
    pub(crate) fn block(&self, block: &mut [u8; CIPHER_BLOCK_LEN]) {
        match self.inner {
            SealInner::Aes { ref aes, .. } => {
                for _ in 0..AES_PASSES {
                    let mut wide = (*block).into();
                    aes.encrypt_block(&mut wide);
                    *block = wide.into();
                }
            }
            SealInner::Ng {
                ref forward,
                ref expanded,
                ..
            } => forward.block(expanded, block),
        }
    }
}

#[cfg(test)]
impl Seal {
    /// The AES transform over a key of thirty-two zero bytes, forwards: the
    /// counterpart of [`Cipher::over_zeros`], for testing framing.
    pub(crate) fn over_zeros() -> Self {
        Self {
            inner: SealInner::Aes {
                which: AesKey::Rage,
                aes: Arc::new(
                    Aes256::new_from_slice(&[0_u8; AES_KEY_LEN]).expect("thirty-two bytes"),
                ),
            },
        }
    }
}

/// By hand, so that no key can reach a log or a panic message by being
/// printed.
impl fmt::Debug for Seal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.inner {
            SealInner::Aes { which, .. } => f
                .debug_struct("Seal")
                .field("scheme", &Scheme::Aes(which))
                .finish_non_exhaustive(),
            SealInner::Ng { key, .. } => f
                .debug_struct("Seal")
                .field("scheme", &Scheme::Ng)
                .field("key_index", &key)
                .finish_non_exhaustive(),
        }
    }
}

#[cfg(test)]
impl Cipher {
    /// The AES transform over a key of thirty-two zero bytes, for testing
    /// which bytes are transformed rather than the values.
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

/// By hand, so that no key can reach a log or a panic message by being
/// printed.
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
/// The table folds case, so either case answers the same value.
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
fn ng_key_index(lut: &[u8; HASH_LUT_LEN], name: &[u8], len: u64) -> usize {
    // The packer's field is 32-bit, so a longer length wraps rather than
    // saturating; saturating would pick a different key.
    let len = u32::try_from(len & u64::from(u32::MAX)).unwrap_or(u32::MAX);
    let mixed = ng_hash(lut, name)
        .wrapping_add(len)
        .wrapping_add(NG_KEY_BIAS);
    // The modulus is `NG_EXPANDED_KEY_COUNT` and not a second spelling of 101,
    // so an index this produces is an index the material has.
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
/// and one round-key word. `lookup` answers what a column's table holds for a
/// byte, so [`NgRound`] can run the very round it inverts through this loop.
fn ng_round_over(
    lookup: impl Fn(usize, u8) -> u32,
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
            let Some(byte) = source.get(column) else {
                continue;
            };
            word ^= lookup(column, *byte);
        }
        *out = word.to_le_bytes();
    }
}

/// One round of the decrypt direction, over the material's own tables.
fn ng_round(
    ng: &NgKeys,
    round: usize,
    round_key: &[u8; NG_ROUND_KEY_LEN],
    order: &[[usize; 4]; 4],
    block: &mut [u8; CIPHER_BLOCK_LEN],
) {
    ng_round_over(
        |column, byte| {
            ng.decrypt_table(round, column)
                .and_then(|table| table_word(table, byte))
                .unwrap_or_default()
        },
        round_key,
        order,
        block,
    );
}

/// Which of the two column orders a round reads its bytes in: the one owner of
/// that split, since a round whose inverse read the other inverts nothing.
const fn ng_order(round: usize) -> &'static [[usize; 4]; 4] {
    if round < NG_LEADING_ROUNDS || round == NG_LAST_ROUND {
        &NG_COLUMN_ORDER
    } else {
        &NG_SHIFTED_ORDER
    }
}

/// The whole NG transform over one block: two rounds in column order, fourteen
/// permuted, and one in column order again.
fn ng_block(ng: &NgKeys, expanded: &[u8; NG_EXPANDED_KEY_LEN], block: &mut [u8; CIPHER_BLOCK_LEN]) {
    // 272 bytes divide into exactly 17 round keys of 16, so the rounds are the
    // chunks and no round can run without its key.
    let (round_keys, _) = expanded.as_chunks::<NG_ROUND_KEY_LEN>();
    for (round, round_key) in round_keys.iter().enumerate() {
        ng_round(ng, round, round_key, ng_order(round), block);
    }
}

/// How many words one decrypt table holds — one per value the byte it reads
/// can take. [`crate::keys::NG_DECRYPT_TABLE_LEN`] is the same fact in bytes.
const NG_TABLE_ENTRIES: usize = 0x100;

/// How many bits one output word of a round is made of, which is how many
/// unknowns one group's system has.
const NG_WORD_BITS: usize = 32;

/// How many bits of a word one column supplies.
const NG_COLUMN_BITS: usize = 8;

/// How many output words a block is, which is how many independent systems a
/// round is.
const NG_WORDS: usize = NG_COLUMN_ORDER.len();

/// One round's sixteen tables, as words rather than as bytes.
type RoundTables = [[u32; NG_TABLE_ENTRIES]; NG_COLUMNS];

/// One round's sixteen byte permutations.
type RoundBytes = [[u8; NG_TABLE_ENTRIES]; NG_COLUMNS];

/// A linear map on the thirty-two bits of one word over GF(2), as the images
/// of its thirty-two unit vectors. [`inverse_of`] answers the same form.
type WordMap = [u32; NG_WORD_BITS];

/// Why a round's forward tables could not be derived from its decrypt tables.
/// Not a [`crate::Error`]: these say what is wrong with key material rather
/// than with an archive, and no exit code is derived from them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NgNotInvertible {
    /// There is no such round: the transform has [`crate::keys::NG_ROUNDS`] of
    /// them, or the material is short of one of this round's tables.
    NoSuchRound {
        /// The round that was asked for.
        round: usize,
    },
    /// A column's table is not a byte permutation into an eight-dimensional
    /// space, so the round does not factor. A real table's 256 entries differ
    /// from the first by 256 distinct words spanning exactly eight dimensions.
    NotASubstitution {
        /// The round whose table it is.
        round: usize,
        /// Which of the sixteen columns.
        column: usize,
        /// How many dimensions its differences actually span. Eight is the
        /// only value that factors.
        rank: usize,
        /// How many of the 256 differences are distinct. Fewer than 256 means
        /// two input bytes are indistinguishable in the output.
        distinct: usize,
    },
    /// The four columns of one output word span the word between them but not
    /// independently, so the round loses information and has no inverse.
    Singular {
        /// The round whose map it is.
        round: usize,
        /// Which of the four output words.
        word: usize,
    },
}

/// One round of the NG transform, in both directions.
///
/// Every round factors: a decrypt table is a byte permutation followed by an
/// injection into an eight-dimensional GF(2) subspace, so the round is a byte
/// substitution and an invertible linear map, and its inverse is the
/// substitutions read backwards and the map inverted over GF(2).
pub struct NgRound {
    /// Which round, which is also which of the two column orders it reads in.
    round: usize,
    /// The round's decrypt tables, copied out of the material as words so the
    /// round and its derived inverse cannot read different tables.
    opening: Box<RoundTables>,
    /// The inverse of each column's linear part, in the decrypt tables' own
    /// shape: what the forward direction looks a byte of the stripped output
    /// word up in.
    sealing: Box<RoundTables>,
    /// The inverse of each column's byte substitution: what turns a recovered
    /// coordinate back into the byte the decrypt round read.
    substitution: Box<RoundBytes>,
    /// What each output word carries when the round key is zero: the affine
    /// part, held apart because only the linear part is inverted. The forward
    /// direction removes it, and the round key, before it looks anything up.
    constants: [u32; NG_WORDS],
}

impl NgRound {
    /// Derives the forward direction of `round` from the decrypt tables in
    /// `ng`.
    ///
    /// # Errors
    ///
    /// Whichever [`NgNotInvertible`] names the round or column that has no
    /// such table, does not factor, or does not span its word independently.
    pub fn solve(ng: &NgKeys, round: usize) -> Result<Self, NgNotInvertible> {
        let absent = NgNotInvertible::NoSuchRound { round };
        let opening = round_tables(ng, round).ok_or(absent)?;
        let order = ng_order(round);
        let mut sealing = Box::new([[0_u32; NG_TABLE_ENTRIES]; NG_COLUMNS]);
        let mut substitution = Box::new([[0_u8; NG_TABLE_ENTRIES]; NG_COLUMNS]);
        let mut constants = [0_u32; NG_WORDS];

        for (word, columns) in order.iter().enumerate() {
            // The map of one output word: bit `8 * place + bit` of its space
            // is basis vector `bit` of the column at `columns[place]`.
            let mut map = [0_u32; NG_WORD_BITS];
            let mut constant = 0_u32;
            for (place, &column) in columns.iter().enumerate() {
                let table = opening.get(column).ok_or(absent)?;
                let base = *table.first().ok_or(absent)?;
                constant ^= base;
                let start = place.checked_mul(NG_COLUMN_BITS).ok_or(absent)?;
                let shape = NgNotInvertible::NotASubstitution {
                    round,
                    column,
                    rank: rank_of(table, base),
                    distinct: distinct_of(table, base),
                };
                if distinct_of(table, base) != NG_TABLE_ENTRIES {
                    return Err(shape);
                }
                let basis = basis_of(table, base).ok_or(shape)?;
                for (bit, vector) in basis.iter().enumerate() {
                    let at = start.checked_add(bit).ok_or(absent)?;
                    *map.get_mut(at).ok_or(absent)? = *vector;
                }

                // The substitution backwards: the forward direction recovers
                // entry `b`'s coordinates and has to hand `b` back.
                let inverse = substitution.get_mut(column).ok_or(absent)?;
                for (value, entry) in table.iter().enumerate() {
                    let byte = u8::try_from(value).map_err(|_| absent)?;
                    let coordinates = coordinates_of(&basis, entry ^ base).ok_or(shape)?;
                    *inverse.get_mut(usize::from(coordinates)).ok_or(absent)? = byte;
                }
            }

            let inverse = inverse_of(&map).ok_or(NgNotInvertible::Singular { round, word })?;
            *constants.get_mut(word).ok_or(absent)? = constant;

            // The inverse applied to that column's byte in its own place, so
            // a word's four lookups give the inverse of the whole word.
            for (place, &column) in columns.iter().enumerate() {
                let shift = u32::try_from(place.checked_mul(NG_COLUMN_BITS).ok_or(absent)?)
                    .map_err(|_| absent)?;
                let table = sealing.get_mut(column).ok_or(absent)?;
                for (value, slot) in table.iter_mut().enumerate() {
                    let byte = u8::try_from(value).map_err(|_| absent)?;
                    *slot = image_of(&inverse, u32::from(byte).wrapping_shl(shift));
                }
            }
        }

        Ok(Self {
            round,
            opening,
            sealing,
            substitution,
            constants,
        })
    }

    /// Which round this is.
    #[must_use]
    pub const fn round(&self) -> usize {
        self.round
    }

    /// Runs the round's decrypt direction over one block, through the same
    /// code and tables the whole transform runs.
    pub fn open(&self, round_key: &[u8; NG_ROUND_KEY_LEN], block: &mut [u8; CIPHER_BLOCK_LEN]) {
        ng_round_over(
            |column, byte| entry_of(&self.opening, column, byte),
            round_key,
            ng_order(self.round),
            block,
        );
    }

    /// Runs the round's encrypt direction over one block: the exact inverse of
    /// [`NgRound::open`]. The round key and the affine constant come off first,
    /// because only what is left is linear, and each recovered byte lands at
    /// the column the decrypt round read it from.
    pub fn seal(&self, round_key: &[u8; NG_ROUND_KEY_LEN], block: &mut [u8; CIPHER_BLOCK_LEN]) {
        let source = *block;
        let (source_words, _) = source.as_chunks::<4>();
        let (key_words, _) = round_key.as_chunks::<4>();
        for (((columns, source_word), key_word), constant) in ng_order(self.round)
            .iter()
            .zip(source_words)
            .zip(key_words)
            .zip(self.constants)
        {
            let stripped =
                u32::from_le_bytes(*source_word) ^ u32::from_le_bytes(*key_word) ^ constant;
            let mut recovered = 0_u32;
            for (&column, &byte) in columns.iter().zip(stripped.to_le_bytes().iter()) {
                recovered ^= entry_of(&self.sealing, column, byte);
            }
            for (&column, &coordinates) in columns.iter().zip(recovered.to_le_bytes().iter()) {
                let byte = self
                    .substitution
                    .get(column)
                    .and_then(|table| table.get(usize::from(coordinates)))
                    .copied()
                    .unwrap_or_default();
                let Some(slot) = block.get_mut(column) else {
                    continue;
                };
                *slot = byte;
            }
        }
    }
}

/// By hand, so that no derived table can reach a log or a panic message: a
/// table solved for is as much key material as one that was scanned.
impl fmt::Debug for NgRound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NgRound")
            .field("scheme", &Scheme::Ng)
            .field("round", &self.round)
            .finish_non_exhaustive()
    }
}

/// The whole NG transform's forward direction: all seventeen rounds, derived
/// from the decrypt tables and run round 16 first and round 0 last.
pub struct NgForward {
    /// One derived round per round of the transform, in the decrypt
    /// direction's order.
    rounds: Vec<NgRound>,
}

impl NgForward {
    /// Derives every round from the decrypt tables in `ng`.
    ///
    /// # Errors
    ///
    /// Whatever [`NgRound::solve`] answers for the first round that does not
    /// derive: the whole transform or none of it.
    pub fn derive(ng: &NgKeys) -> Result<Self, NgNotInvertible> {
        let mut rounds = Vec::with_capacity(NG_ROUNDS);
        for round in 0..NG_ROUNDS {
            rounds.push(NgRound::solve(ng, round)?);
        }
        Ok(Self { rounds })
    }

    /// Encrypts one whole block in place: the exact inverse of the decrypt
    /// transform [`Cipher`] runs under the same `expanded` key.
    pub fn block(&self, expanded: &[u8; NG_EXPANDED_KEY_LEN], block: &mut [u8; CIPHER_BLOCK_LEN]) {
        let (round_keys, _) = expanded.as_chunks::<NG_ROUND_KEY_LEN>();
        for (round, round_key) in self.rounds.iter().zip(round_keys).rev() {
            round.seal(round_key, block);
        }
    }
}

/// By hand, for the reason [`NgRound`]'s is.
impl fmt::Debug for NgForward {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NgForward")
            .field("scheme", &Scheme::Ng)
            .field("rounds", &self.rounds.len())
            .finish_non_exhaustive()
    }
}

/// A basis of the space one column's entries differ from its first by, in
/// echelon form and highest leading bit first, or `None` where that space is
/// not eight-dimensional.
fn basis_of(table: &[u32; NG_TABLE_ENTRIES], base: u32) -> Option<[u32; NG_COLUMN_BITS]> {
    let mut slots = [0_u32; NG_WORD_BITS];
    let mut found = 0_usize;
    for entry in table {
        let mut left = entry ^ base;
        while left != 0 {
            let at = usize::try_from(leading_bit(left)).ok()?;
            let slot = slots.get_mut(at)?;
            if *slot == 0 {
                *slot = left;
                found = found.checked_add(1)?;
                break;
            }
            left ^= *slot;
        }
        if found > NG_COLUMN_BITS {
            return None;
        }
    }
    if found != NG_COLUMN_BITS {
        return None;
    }
    let mut basis = [0_u32; NG_COLUMN_BITS];
    let mut filled = basis.iter_mut();
    for vector in slots.iter().rev() {
        if *vector == 0 {
            continue;
        }
        *filled.next()? = *vector;
    }
    Some(basis)
}

/// Which bit of `word` is its highest set one. Zero for zero, which no caller
/// asks about.
const fn leading_bit(word: u32) -> u32 {
    u32::BITS
        .saturating_sub(1)
        .saturating_sub(word.leading_zeros())
}

/// The coordinates of `vector` in `basis`, or `None` where it is not in the
/// space the basis spans. The basis is in echelon form with leading bits
/// descending, so one pass reduces the vector and reads its coordinates off.
fn coordinates_of(basis: &[u32; NG_COLUMN_BITS], vector: u32) -> Option<u8> {
    let mut left = vector;
    let mut coordinates = 0_u8;
    for (bit, &pivot) in basis.iter().enumerate() {
        if pivot == 0 || left == 0 || leading_bit(left) != leading_bit(pivot) {
            continue;
        }
        left ^= pivot;
        coordinates |= 1_u8.wrapping_shl(u32::try_from(bit).unwrap_or(u32::MAX));
    }
    (left == 0).then_some(coordinates)
}

/// How many dimensions a column's differences span, for a refusal to say so.
fn rank_of(table: &[u32; NG_TABLE_ENTRIES], base: u32) -> usize {
    let mut slots = [0_u32; NG_WORD_BITS];
    let mut found = 0_usize;
    for entry in table {
        let mut left = entry ^ base;
        while left != 0 {
            let Ok(at) = usize::try_from(leading_bit(left)) else {
                break;
            };
            let Some(slot) = slots.get_mut(at) else {
                break;
            };
            if *slot == 0 {
                *slot = left;
                found = found.saturating_add(1);
                break;
            }
            left ^= *slot;
        }
    }
    found
}

/// How many of a column's differences are distinct, for the same reason.
fn distinct_of(table: &[u32; NG_TABLE_ENTRIES], base: u32) -> usize {
    let mut seen: Vec<u32> = table.iter().map(|entry| entry ^ base).collect();
    seen.sort_unstable();
    seen.dedup();
    seen.len()
}

/// What one round's table for `column` holds for `byte`.
fn entry_of(tables: &RoundTables, column: usize, byte: u8) -> u32 {
    tables
        .get(column)
        .and_then(|table| table.get(usize::from(byte)))
        .copied()
        .unwrap_or_default()
}

/// One round's sixteen decrypt tables as words, or `None` where the material
/// has no such round.
fn round_tables(ng: &NgKeys, round: usize) -> Option<Box<RoundTables>> {
    let mut tables = Box::new([[0_u32; NG_TABLE_ENTRIES]; NG_COLUMNS]);
    for (column, slot) in tables.iter_mut().enumerate() {
        let table = ng.decrypt_table(round, column)?;
        for (value, word) in slot.iter_mut().enumerate() {
            *word = table_word(table, u8::try_from(value).ok()?)?;
        }
    }
    Some(tables)
}

/// The image of `vector` under `map`: the exclusive-or of the images of the
/// bits it has set.
fn image_of(map: &WordMap, vector: u32) -> u32 {
    let mut out = 0_u32;
    for (bit, image) in map.iter().enumerate() {
        let shift = u32::try_from(bit).unwrap_or(u32::MAX);
        if vector.wrapping_shr(shift) & 1 == 1 {
            out ^= *image;
        }
    }
    out
}

/// The inverse of `map` over GF(2), or `None` where it is singular.
///
/// Gauss-Jordan elimination whose every step preserves
/// `map(source[row]) == image[row]`.
fn inverse_of(map: &WordMap) -> Option<WordMap> {
    let mut image = *map;
    let mut source: WordMap =
        std::array::from_fn(|bit| 1_u32.wrapping_shl(u32::try_from(bit).unwrap_or(u32::MAX)));
    for bit in 0..NG_WORD_BITS {
        let shift = u32::try_from(bit).ok()?;
        let set = |word: &u32| word.wrapping_shr(shift) & 1 == 1;
        let pivot = (bit..NG_WORD_BITS).find(|&row| image.get(row).is_some_and(set))?;
        image.swap(bit, pivot);
        source.swap(bit, pivot);
        let lead_image = *image.get(bit)?;
        let lead_source = *source.get(bit)?;
        for row in 0..NG_WORD_BITS {
            if row == bit || !image.get(row).is_some_and(set) {
                continue;
            }
            *image.get_mut(row)? ^= lead_image;
            *source.get_mut(row)? ^= lead_source;
        }
    }
    Some(source)
}

/// Synthetic NG material, for tests that need the transform and no key
/// material. Outside `mod tests` because `build`'s tests want it too; every
/// value is drawn from a named seed rather than from any key.
#[cfg(test)]
pub(crate) mod synthetic {
    use super::*;
    use crate::keys::{NG_COLUMNS, NG_DECRYPT_TABLE_COUNT, NG_DECRYPT_TABLE_LEN};

    /// A decrypt table set of the length [`NgKeys`] promises, answering zero
    /// for every input byte of every round and column.
    pub(crate) fn no_tables() -> Vec<u8> {
        vec![0; NG_DECRYPT_TABLE_COUNT.saturating_mul(NG_DECRYPT_TABLE_LEN)]
    }

    /// An expanded key set of the promised length, all zero.
    pub(crate) fn no_expanded() -> Vec<u8> {
        vec![0; NG_EXPANDED_KEY_COUNT.saturating_mul(NG_EXPANDED_KEY_LEN)]
    }

    /// Where one decrypt table begins, in the order `NgKeys::decrypt_table`
    /// reads them.
    pub(crate) fn table_at(round: usize, column: usize) -> usize {
        round
            .saturating_mul(NG_COLUMNS)
            .saturating_add(column)
            .saturating_mul(NG_DECRYPT_TABLE_LEN)
    }

    /// Material of exactly these tables and expanded keys.
    pub(crate) fn ng_over(tables: Vec<u8>, expanded: Vec<u8>) -> NgKeys {
        NgKeys::restored(expanded, tables, 0, 0).expect("the lengths this type promises")
    }

    /// A deterministic stream of words, so that "random tables" is a fixture
    /// rather than a flake.
    pub(crate) struct Stream(pub(crate) u32);

    impl Stream {
        /// The next word.
        pub(crate) fn next(&mut self) -> u32 {
            let mut state = self.0;
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            self.0 = state;
            state
        }

        /// The next byte, off the top of a word so that the low bits of the
        /// generator are not what a block is made of.
        pub(crate) fn byte(&mut self) -> u8 {
            u8::try_from(self.next() >> 24).unwrap_or(0)
        }

        /// The next block.
        pub(crate) fn block(&mut self) -> [u8; CIPHER_BLOCK_LEN] {
            std::array::from_fn(|_| self.byte())
        }
    }

    /// Writes a table for `round` and `column`: entry `b` is `base`
    /// exclusive-ored with the images of the bits set in `substitution[b]`,
    /// which is the shape every real table has.
    pub(crate) fn answers_by_substitution(
        tables: &mut [u8],
        round: usize,
        column: usize,
        base: u32,
        images: &[u32; NG_COLUMN_BITS],
        substitution: &[u8; NG_TABLE_ENTRIES],
    ) {
        let start = table_at(round, column);
        for (value, &substituted) in substitution.iter().enumerate() {
            let coordinates = usize::from(substituted);
            let mut word = base;
            for (bit, image) in images.iter().enumerate() {
                if coordinates >> bit & 1 == 1 {
                    word ^= *image;
                }
            }
            let at = start.saturating_add(value.saturating_mul(4));
            let Some(slot) = tables.get_mut(at..at.saturating_add(4)) else {
                continue;
            };
            slot.copy_from_slice(&word.to_le_bytes());
        }
    }

    /// How many singular draws one column tolerates before [`table_set`] gives
    /// up. A random map is invertible about 29% of the time, so two hundred
    /// failures in a row mean the derivation has stopped inverting.
    const MOST_DRAWS: u32 = 200;

    /// A whole table set whose every round derives, built and retried one
    /// output word at a time; the retry is bounded so a broken `inverse_of`
    /// fails rather than spins. `substituted` gives the shape of rounds 2
    /// through 15, the identity that of rounds 0, 1 and 16.
    pub(crate) fn table_set(seed: u32, substituted: bool) -> Vec<u8> {
        let mut stream = Stream(seed);
        let mut tables = no_tables();
        for round in 0..NG_ROUNDS {
            for columns in ng_order(round) {
                let mut drawn = 0_u32;
                loop {
                    drawn = drawn.saturating_add(1);
                    assert!(
                        drawn <= MOST_DRAWS,
                        "round {round}: {MOST_DRAWS} draws in a row were singular, which is not \
                         luck — `inverse_of` has stopped inverting"
                    );
                    let bases: [u32; 4] = std::array::from_fn(|_| stream.next());
                    let images: [[u32; NG_COLUMN_BITS]; 4] =
                        std::array::from_fn(|_| std::array::from_fn(|_| stream.next()));
                    let map: WordMap = std::array::from_fn(|bit| {
                        images[bit / NG_COLUMN_BITS][bit % NG_COLUMN_BITS]
                    });
                    if inverse_of(&map).is_none() {
                        continue;
                    }
                    for ((&column, base), image) in columns.iter().zip(bases).zip(&images) {
                        let substitution = if substituted {
                            shuffle(&mut stream)
                        } else {
                            std::array::from_fn(|value| u8::try_from(value).unwrap_or(0))
                        };
                        answers_by_substitution(
                            &mut tables,
                            round,
                            column,
                            base,
                            image,
                            &substitution,
                        );
                    }
                    break;
                }
            }
        }
        tables
    }

    /// A permutation of the 256 byte values, drawn from `stream`.
    pub(crate) fn shuffle(stream: &mut Stream) -> [u8; NG_TABLE_ENTRIES] {
        let mut values: [u8; NG_TABLE_ENTRIES] =
            std::array::from_fn(|value| u8::try_from(value).unwrap_or(0));
        for at in (1..NG_TABLE_ENTRIES).rev() {
            let with = usize::try_from(stream.next())
                .unwrap_or(0)
                .checked_rem(at.saturating_add(1))
                .unwrap_or(0);
            values.swap(at, with);
        }
        values
    }

    /// The affine table set, which is what most of these tests want.
    pub(crate) fn affine_tables(seed: u32) -> Vec<u8> {
        table_set(seed, false)
    }

    /// One hundred and one distinct expanded keys, so that a region keyed to a
    /// different index is written under different bytes — the only way a test
    /// can tell a re-keyed write from one that forgot to re-key.
    pub(crate) fn distinct_expanded(seed: u32) -> Vec<u8> {
        let mut stream = Stream(seed);
        let mut out = no_expanded();
        for slot in &mut out {
            *slot = stream.byte();
        }
        out
    }

    /// Material of the shape only a memory image carries, drawn from `seed`
    /// rather than from any key: it makes the whole NG write path testable
    /// with no game installation.
    pub(crate) fn ng_material(seed: u32) -> Material {
        let mut stream = Stream(seed);
        let mut lut = [0_u8; HASH_LUT_LEN];
        for slot in &mut lut {
            *slot = stream.byte();
        }
        Material::over_ng(
            lut,
            ng_over(
                table_set(seed, true),
                distinct_expanded(seed.wrapping_add(1)),
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::synthetic::*;
    use super::*;
    use crate::keys::{NG_COLUMNS, NG_DECRYPT_TABLE_LEN};

    /// What `ng_key_index` answers for `dlc.rpf` at 6,144 bytes over a lookup
    /// table of the identity.
    const GOLDEN_DLC: usize = 62;
    /// The same for `content.xml` at 888 bytes.
    const GOLDEN_CONTENT: usize = 66;
    /// The same for the empty name at length zero, which is the bias alone.
    const GOLDEN_EMPTY: usize = 61;

    /// As [`Cipher::over_zeros`], under the name these tests read by.
    fn framing_only() -> Cipher {
        Cipher::over_zeros()
    }

    /// Makes the table for `round` and `column` answer `word` whatever byte it
    /// is asked about.
    fn answers(tables: &mut [u8], round: usize, column: usize, word: u32) {
        let base = table_at(round, column);
        for byte in 0..0x100_usize {
            let at = base.saturating_add(byte.saturating_mul(4));
            let Some(slot) = tables.get_mut(at..at.saturating_add(4)) else {
                continue;
            };
            slot.copy_from_slice(&word.to_le_bytes());
        }
    }

    /// Makes the table for `round` and `column` answer the byte it was asked
    /// about, placed at byte `at` of the word.
    fn answers_its_byte(tables: &mut [u8], round: usize, column: usize, at: usize) {
        let base = table_at(round, column);
        for byte in 0..0x100_usize {
            let word = u32::try_from(byte).unwrap_or(0)
                << (8_u32).saturating_mul(u32::try_from(at).unwrap_or(0));
            let start = base.saturating_add(byte.saturating_mul(4));
            let Some(slot) = tables.get_mut(start..start.saturating_add(4)) else {
                continue;
            };
            slot.copy_from_slice(&word.to_le_bytes());
        }
    }

    /// The four little-endian words of a block.
    fn words(block: &[u8; CIPHER_BLOCK_LEN]) -> [u32; 4] {
        let (chunks, _) = block.as_chunks::<4>();
        let mut out = [0_u32; 4];
        for (slot, chunk) in out.iter_mut().zip(chunks) {
            *slot = u32::from_le_bytes(*chunk);
        }
        out
    }

    #[test]
    fn the_two_orders_are_the_ones_the_format_uses() {
        // The rows themselves, not merely that each order reads all sixteen
        // bytes once.
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
        // A lookup table of the identity makes the hash a pure function of
        // the bytes; every constant it is made of reaches these numbers.
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
        // The bound is `NG_EXPANDED_KEY_COUNT` because that is what
        // `NgKeys::expanded_key` is written against.
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
        // A drift between the modulus and `expanded_key`'s bound would hand
        // blocks back in the clear as though they had been decrypted.
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
        // 272 bytes is 17 round keys of 16 exactly, which is why `ng_block`
        // can make the rounds the chunks.
        assert_eq!(NG_ROUND_KEY_LEN, CIPHER_BLOCK_LEN);
        assert_eq!(
            NG_EXPANDED_KEY_LEN,
            NG_ROUNDS.saturating_mul(NG_ROUND_KEY_LEN),
        );
        assert_eq!(NG_EXPANDED_KEY_LEN % NG_ROUND_KEY_LEN, 0);
    }

    #[test]
    fn a_length_past_the_field_wraps_rather_than_saturating() {
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
    fn a_seal_is_the_ciphers_exact_inverse_over_the_same_extent() {
        // A mismatch of extent corrupts every region whose length is not a
        // multiple of sixteen.
        let cipher = Cipher::over_zeros();
        let seal = Seal::over_zeros();
        for len in 0..=(CIPHER_BLOCK_LEN * 3 + 1) {
            let plain: Vec<u8> = (0..len)
                .map(|n| u8::try_from(n % 251).unwrap_or(0))
                .collect();
            let mut sealed = plain.clone();
            seal.apply(&mut sealed);
            assert_eq!(sealed.len(), len, "sealing changed the length at {len}");

            let tail = len - len % CIPHER_BLOCK_LEN;
            assert_eq!(
                sealed.get(tail..),
                plain.get(tail..),
                "the tail was transformed at {len}"
            );
            if len >= CIPHER_BLOCK_LEN {
                assert_ne!(
                    sealed.get(..CIPHER_BLOCK_LEN),
                    plain.get(..CIPHER_BLOCK_LEN),
                    "the first block was left alone at {len}"
                );
            }

            let mut back = sealed;
            cipher.apply(&mut back);
            assert_eq!(back, plain, "sealing then opening lost bytes at {len}");
        }
    }

    #[test]
    fn nothing_a_sealer_prints_is_a_key() {
        // It has to name the transform and nothing else.
        let material = ng_material(0x0BAD_C0DE);
        let sealer = Sealer::new(Scheme::Ng, &material).expect("the tables derive");
        let rendered = format!("{sealer:?}");
        assert!(rendered.contains("Sealer"), "{rendered}");
        assert!(rendered.contains("Ng"), "{rendered}");
        let ng = material.ng().expect("carries the NG material");
        for index in 0..NG_EXPANDED_KEY_COUNT {
            let key = ng.expanded_key(index).expect("is there");
            assert!(
                !rendered.contains(&format!("{key:?}")),
                "expanded key {index} is in the Debug rendering"
            );
        }
        assert!(
            !rendered.contains(&format!("{:?}", material.keys().hash_lut())),
            "the hash lookup table is in the Debug rendering"
        );

        let plain = Material::over_zeros();
        let sealer = Sealer::new(Scheme::Aes(AesKey::Rage), &plain).expect("carries the RAGE key");
        let rendered = format!("{sealer:?}");
        assert!(rendered.contains("Sealer"), "{rendered}");
        assert!(rendered.contains("Aes"), "{rendered}");
        assert!(rendered.contains("Rage"), "{rendered}");
        assert!(
            !rendered.contains(&format!("{:?}", plain.keys().aes_key())),
            "the AES key is in the Debug rendering"
        );
    }

    #[test]
    fn nothing_a_seal_prints_is_a_key() {
        let rendered = format!("{:?}", Seal::over_zeros());
        assert!(rendered.contains("Aes"), "{rendered}");
        assert!(!rendered.contains("00"), "{rendered}");
    }

    #[test]
    fn a_tail_shorter_than_a_block_is_carried_through() {
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
        let rendered = format!("{:?}", framing_only());
        assert!(rendered.contains("Aes"), "{rendered}");
        assert!(!rendered.contains("00"), "{rendered}");
    }

    #[test]
    fn an_empty_buffer_decrypts_to_itself() {
        let mut nothing: [u8; 0] = [];
        framing_only().apply(&mut nothing);
    }

    #[test]
    fn a_round_reads_the_four_columns_its_own_order_names() {
        // Each column's table answers a bit of its own, so an output word is
        // the set of columns that reached it.
        for (order, expected) in [
            (NG_COLUMN_ORDER, [0xF_u32, 0xF0, 0xF00, 0xF000]),
            (NG_SHIFTED_ORDER, [0x2481_u32, 0x4812, 0x8124, 0x1248]),
        ] {
            let mut tables = no_tables();
            for column in 0..NG_COLUMNS {
                answers(&mut tables, 0, column, 1_u32 << column);
            }
            let ng = ng_over(tables, no_expanded());
            let mut block = [0_u8; CIPHER_BLOCK_LEN];
            ng_round(&ng, 0, &[0_u8; NG_ROUND_KEY_LEN], &order, &mut block);
            assert_eq!(words(&block), expected, "{order:?}");
        }
    }

    #[test]
    fn the_four_lookups_and_the_round_key_are_combined_by_exclusive_or() {
        // The tables overlap on purpose: `^` gives 0x00FF_FF00 where `|`
        // gives 0xFFFF_FF00, and an OR would not be invertible.
        let mut tables = no_tables();
        answers(&mut tables, 0, 0, 0xFFFF_0000);
        answers(&mut tables, 0, 1, 0xFF00_FF00);
        let ng = ng_over(tables, no_expanded());

        let mut block = [0_u8; CIPHER_BLOCK_LEN];
        ng_round(
            &ng,
            0,
            &[0_u8; NG_ROUND_KEY_LEN],
            &NG_COLUMN_ORDER,
            &mut block,
        );
        assert_eq!(words(&block)[0], 0x00FF_FF00);

        // A key word sharing bits with the lookups has to cancel them.
        let mut key = [0_u8; NG_ROUND_KEY_LEN];
        key[..4].copy_from_slice(&0x00FF_0000_u32.to_le_bytes());
        let mut tables = no_tables();
        answers(&mut tables, 0, 0, 0x00FF_0000);
        let ng = ng_over(tables, no_expanded());
        let mut block = [0_u8; CIPHER_BLOCK_LEN];
        ng_round(&ng, 0, &key, &NG_COLUMN_ORDER, &mut block);
        assert_eq!(
            words(&block)[0],
            0,
            "a lookup equal to its round key word did not cancel it"
        );
    }

    #[test]
    fn a_round_key_word_lands_in_the_output_word_of_its_own_position() {
        let ng = ng_over(no_tables(), no_expanded());
        let key: [u8; NG_ROUND_KEY_LEN] =
            std::array::from_fn(|index| u8::try_from(index).unwrap_or(0).wrapping_mul(17));
        let mut block = [0xAA_u8; CIPHER_BLOCK_LEN];
        ng_round(&ng, 0, &key, &NG_COLUMN_ORDER, &mut block);
        assert_eq!(block, key);
    }

    #[test]
    fn a_column_looks_its_own_byte_up_in_its_own_table() {
        // Column 0's byte and column 1's position in its table differ on
        // purpose, so neither can pass for the other.
        for (column, byte, at) in [(1_usize, 0x99_u8, 0_usize), (3, 0x7E, 2)] {
            let mut tables = no_tables();
            answers_its_byte(&mut tables, 0, column, at);
            let ng = ng_over(tables, no_expanded());

            let mut block = [0_u8; CIPHER_BLOCK_LEN];
            block[0] = 0x5A;
            block[column] = byte;
            ng_round(
                &ng,
                0,
                &[0_u8; NG_ROUND_KEY_LEN],
                &NG_COLUMN_ORDER,
                &mut block,
            );

            let shift = (8_u32).saturating_mul(u32::try_from(at).unwrap_or(0));
            assert_eq!(
                words(&block)[0],
                u32::from(byte) << shift,
                "column {column} did not read its own byte through its own table"
            );
        }
    }

    #[test]
    fn the_transform_runs_one_round_per_round_key_and_ends_on_the_last() {
        // Tables that answer zero make every round its own round key, so the
        // transform answers the last round key and nothing else.
        let expanded: Vec<u8> = (0..NG_EXPANDED_KEY_LEN)
            .map(|index| {
                u8::try_from(index.checked_div(NG_ROUND_KEY_LEN).unwrap_or(0)).unwrap_or(0)
            })
            .collect();
        let key: [u8; NG_EXPANDED_KEY_LEN] = expanded
            .clone()
            .try_into()
            .expect("the expanded key length");
        let mut whole = no_expanded();
        whole
            .get_mut(..NG_EXPANDED_KEY_LEN)
            .expect("room for one key")
            .copy_from_slice(&expanded);

        let ng = ng_over(no_tables(), whole);
        let mut block = [0xC3_u8; CIPHER_BLOCK_LEN];
        ng_block(&ng, &key, &mut block);

        let last = u8::try_from(NG_ROUNDS.saturating_sub(1)).unwrap_or(0);
        assert_eq!(block, [last; CIPHER_BLOCK_LEN], "not the last round key");
    }

    #[test]
    fn the_permuted_rounds_are_the_middle_fourteen_of_the_transform() {
        // Every table answers its own byte at its own position, so the whole
        // transform is the permutation applied once per permuted round.
        let mut tables = no_tables();
        for round in 0..NG_ROUNDS {
            for column in 0..NG_COLUMNS {
                answers_its_byte(&mut tables, round, column, column % 4);
            }
        }
        let ng = ng_over(tables, no_expanded());

        let start: [u8; CIPHER_BLOCK_LEN] =
            std::array::from_fn(|index| u8::try_from(index).unwrap_or(0));
        let mut block = start;
        ng_block(&ng, &[0_u8; NG_EXPANDED_KEY_LEN], &mut block);

        assert_eq!(
            block,
            shifted_times(start, 14),
            "not fourteen permuted rounds"
        );
        assert_ne!(block, shifted_times(start, 13), "one round too few");
        assert_ne!(block, shifted_times(start, 15), "one round too many");
        assert_ne!(block, start, "no round permuted anything");
    }

    #[test]
    fn a_decrypt_table_holds_one_word_per_value_of_the_byte_it_reads() {
        // The same fact in two units; a drift reads a table short.
        assert_eq!(NG_DECRYPT_TABLE_LEN, NG_TABLE_ENTRIES.saturating_mul(4));
        assert_eq!(NG_TABLE_ENTRIES, usize::from(u8::MAX).saturating_add(1));
        assert_eq!(NG_WORD_BITS, NG_COLUMN_BITS.saturating_mul(4));
        assert_eq!(NG_WORDS, 4);
    }

    #[test]
    fn the_order_a_round_reads_in_has_one_owner() {
        // Rounds 0, 1 and 16 read in column order, 2 through 15 permuted.
        for round in 0..NG_ROUNDS {
            let column_order = round < NG_LEADING_ROUNDS || round == NG_LAST_ROUND;
            assert_eq!(
                *ng_order(round) == NG_COLUMN_ORDER,
                column_order,
                "round {round}"
            );
        }
    }

    #[test]
    fn a_vector_that_reduces_to_zero_early_still_has_its_coordinates_read_off() {
        // `leading_bit` is zero both for the vector `1` and for the zero a
        // vector reduces to, so a pass must stop at zero.
        let basis: [u32; NG_COLUMN_BITS] = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01];
        assert_eq!(coordinates_of(&basis, 0x80), Some(0b0000_0001));
        assert_eq!(coordinates_of(&basis, 0x00), Some(0));
        assert_eq!(coordinates_of(&basis, 0x01), Some(0b1000_0000));
        assert_eq!(coordinates_of(&basis, 0xC3), Some(0b1100_0011));
        assert_eq!(coordinates_of(&basis, 0x100), None);
    }

    #[test]
    fn a_columns_rank_is_the_dimension_its_entries_differ_from_the_first_over() {
        // The rank is the whole of what a `NotASubstitution` reports about a
        // table's shape, and nothing else reads it back.
        let base = 0x2C_u32;
        // Eight independent differences from the first entry, which is what
        // every real table is.
        let mut table = [base; NG_TABLE_ENTRIES];
        for bit in 0..NG_COLUMN_BITS {
            table[bit.saturating_add(1)] = base ^ (1_u32 << bit);
        }
        assert_eq!(rank_of(&table, base), NG_COLUMN_BITS);

        table[NG_COLUMN_BITS.saturating_add(1)] = base ^ 0x100;
        assert_eq!(rank_of(&table, base), NG_COLUMN_BITS + 1);

        assert_eq!(rank_of(&[base; NG_TABLE_ENTRIES], base), 0);
    }

    #[test]
    fn the_solver_inverts_an_invertible_map_and_refuses_a_singular_one() {
        let mut stream = Stream(0x1234_5678);
        let mut inverted = 0_usize;
        for _ in 0..64 {
            let map: WordMap = std::array::from_fn(|_| stream.next());
            let Some(inverse) = inverse_of(&map) else {
                continue;
            };
            inverted += 1;
            for _ in 0..64 {
                let vector = stream.next();
                assert_eq!(
                    image_of(&inverse, image_of(&map, vector)),
                    vector,
                    "the inverse did not undo the map"
                );
                assert_eq!(
                    image_of(&map, image_of(&inverse, vector)),
                    vector,
                    "the map did not undo the inverse"
                );
            }
        }
        assert!(inverted > 0, "no map in the sample was invertible");

        // A map with two equal images loses a bit, so no inverse exists and
        // one must not be invented.
        let mut singular: WordMap =
            std::array::from_fn(|bit| 1_u32 << u32::try_from(bit).unwrap_or(0));
        singular[3] = singular[7];
        assert_eq!(inverse_of(&singular), None);

        let identity: WordMap = std::array::from_fn(|bit| 1_u32 << u32::try_from(bit).unwrap_or(0));
        assert_eq!(inverse_of(&identity), Some(identity));
    }

    #[test]
    fn a_derived_round_is_the_exact_inverse_of_the_decrypt_round_it_came_from() {
        // Both a column-order round and a permuted one, since a `seal` that
        // ignored the permutation passes the first and fails the second.
        let tables = affine_tables(0x9E37_79B9);
        let ng = ng_over(tables, no_expanded());
        let mut stream = Stream(0x0BAD_F00D);
        for round in [0_usize, 1, 5, NG_LAST_ROUND] {
            let derived = NgRound::solve(&ng, round).expect("affine and invertible");
            assert_eq!(derived.round(), round);
            for _ in 0..64 {
                let round_key: [u8; NG_ROUND_KEY_LEN] = std::array::from_fn(|_| stream.byte());
                let plain = stream.block();

                let mut opened = plain;
                derived.open(&round_key, &mut opened);
                assert_ne!(opened, plain, "round {round} changed nothing");

                let mut back = opened;
                derived.seal(&round_key, &mut back);
                assert_eq!(back, plain, "round {round} did not come back");

                let mut sealed = plain;
                derived.seal(&round_key, &mut sealed);
                let mut reopened = sealed;
                derived.open(&round_key, &mut reopened);
                assert_eq!(reopened, plain, "round {round} did not seal and reopen");
            }
        }
    }

    #[test]
    fn a_round_that_substitutes_its_bytes_inverts_without_any_sweep() {
        // These tables are not affine on the byte they read, which is what
        // rounds 2 through 15 are. An affine fixture would prove nothing.
        let substituted = table_set(0x00C0_FFEE, true);
        assert_ne!(
            substituted,
            table_set(0x00C0_FFEE, false),
            "the substituted fixture is the affine one, so nothing new is measured"
        );
        let ng = ng_over(substituted, no_expanded());
        let mut stream = Stream(0x1CE1_CE1C);
        for round in 0..NG_ROUNDS {
            let derived = NgRound::solve(&ng, round).expect("a substitution round derives");
            for _ in 0..32 {
                let round_key: [u8; NG_ROUND_KEY_LEN] = std::array::from_fn(|_| stream.byte());
                let plain = stream.block();
                let mut opened = plain;
                derived.open(&round_key, &mut opened);
                let mut back = opened;
                derived.seal(&round_key, &mut back);
                assert_eq!(back, plain, "round {round} did not come back");
            }
        }
    }

    #[test]
    fn the_derived_transform_undoes_the_whole_decrypt_transform() {
        // Running the rounds the decrypt way round inverts each round and none
        // of the composition.
        let ng = ng_over(table_set(0x5150_5150, true), no_expanded());
        let forward = NgForward::derive(&ng).expect("every round derives");
        let mut stream = Stream(0x7E57_7E57);
        let expanded: [u8; NG_EXPANDED_KEY_LEN] = std::array::from_fn(|_| stream.byte());
        for _ in 0..64 {
            let plain = stream.block();
            let mut opened = plain;
            ng_block(&ng, &expanded, &mut opened);
            assert_ne!(opened, plain, "the transform changed nothing");
            let mut back = opened;
            forward.block(&expanded, &mut back);
            assert_eq!(back, plain, "the whole transform did not come back");
        }
    }

    #[test]
    fn nothing_a_derived_transform_prints_is_a_table() {
        let ng = ng_over(affine_tables(0xFEED_FACE), no_expanded());
        let rendered = format!("{:?}", NgForward::derive(&ng).expect("every round derives"));
        assert!(rendered.contains("Ng"), "{rendered}");
        assert!(!rendered.contains("00"), "{rendered}");
    }

    #[test]
    fn a_derived_rounds_decrypt_is_the_transforms_own_round() {
        // The same tables, order and answer as `ng_round`, so a round trip
        // measures the derivation rather than two implementations agreeing.
        let ng = ng_over(affine_tables(0x5EED_1234), no_expanded());
        let mut stream = Stream(0x2468_ACE0);
        for round in [0_usize, 5, NG_LAST_ROUND] {
            let derived = NgRound::solve(&ng, round).expect("affine and invertible");
            let round_key: [u8; NG_ROUND_KEY_LEN] = std::array::from_fn(|_| stream.byte());
            let start = stream.block();

            let mut theirs = start;
            ng_round(&ng, round, &round_key, ng_order(round), &mut theirs);
            let mut ours = start;
            derived.open(&round_key, &mut ours);
            assert_eq!(ours, theirs, "round {round}");
        }
    }

    #[test]
    fn a_table_that_is_not_a_substitution_is_named_with_the_shape_it_has() {
        // Differences over more than eight dimensions mean the round does not
        // factor; repeated ones mean two bytes are indistinguishable.
        let mut tables = affine_tables(0x1357_9BDF);
        let at = table_at(3, 9).saturating_add(usize::from(0xC3_u8).saturating_mul(4));
        tables[at] ^= 0x40;
        let ng = ng_over(tables, no_expanded());
        match NgRound::solve(&ng, 3) {
            Err(NgNotInvertible::NotASubstitution {
                round,
                column,
                rank,
                distinct,
            }) => {
                assert_eq!((round, column), (3, 9));
                // Nine, and not merely "not eight".
                assert_eq!(rank, NG_COLUMN_BITS + 1, "the rank is what is wrong");
                assert_eq!(distinct, NG_TABLE_ENTRIES);
            }
            other => panic!("{other:?}"),
        }
        assert!(NgRound::solve(&ng, 0).is_ok());
    }

    #[test]
    fn a_round_that_loses_information_is_refused_rather_than_inverted_wrongly() {
        // The one answer that must never be given is a table set: every block
        // written under it reads back as noise.
        let mut tables = affine_tables(0x0F0F_0F0F);
        // Column 1's table becomes column 0's, so the word collapses to
        // twenty-four bits.
        let (from, to) = (table_at(0, 0), table_at(0, 1));
        let copied = tables
            .get(from..from.saturating_add(NG_DECRYPT_TABLE_LEN))
            .expect("a whole table")
            .to_vec();
        tables
            .get_mut(to..to.saturating_add(NG_DECRYPT_TABLE_LEN))
            .expect("a whole table")
            .copy_from_slice(&copied);
        let ng = ng_over(tables, no_expanded());
        assert_eq!(
            NgRound::solve(&ng, 0).err(),
            Some(NgNotInvertible::Singular { round: 0, word: 0 })
        );
    }

    #[test]
    fn there_is_no_eighteenth_round_to_derive() {
        let ng = ng_over(no_tables(), no_expanded());
        assert_eq!(
            NgRound::solve(&ng, NG_ROUNDS).err(),
            Some(NgNotInvertible::NoSuchRound { round: NG_ROUNDS })
        );
    }

    #[test]
    fn a_round_of_tables_answering_zero_is_refused_rather_than_derived() {
        // The all-zero fixture is what a solver that read no table at all
        // would answer.
        let ng = ng_over(no_tables(), no_expanded());
        assert_eq!(
            NgRound::solve(&ng, 0).err(),
            Some(NgNotInvertible::NotASubstitution {
                round: 0,
                column: 0,
                rank: 0,
                distinct: 1,
            })
        );
    }

    #[test]
    fn nothing_a_derived_round_prints_is_a_table() {
        let ng = ng_over(affine_tables(0xDEAD_BEEF), no_expanded());
        let derived = NgRound::solve(&ng, 0).expect("affine and invertible");
        let rendered = format!("{derived:?}");
        assert!(rendered.contains("Ng"), "{rendered}");
        assert!(rendered.contains("round"), "{rendered}");
        assert!(!rendered.contains("00"), "{rendered}");
    }

    /// `block` with the shift-rows permutation applied `times` times, read
    /// straight off [`NG_SHIFTED_ORDER`].
    fn shifted_times(block: [u8; CIPHER_BLOCK_LEN], times: usize) -> [u8; CIPHER_BLOCK_LEN] {
        let mut current = block;
        for _ in 0..times {
            let source = current;
            for (word, columns) in NG_SHIFTED_ORDER.iter().enumerate() {
                for &column in columns {
                    let at = word.saturating_mul(4).saturating_add(column % 4);
                    current[at] = source[column];
                }
            }
        }
        current
    }
}
