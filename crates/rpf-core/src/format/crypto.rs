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
use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

use crate::keys::{
    AES_KEY_LEN, HASH_LUT_LEN, LauncherKey, Material, NG_COLUMNS, NG_EXPANDED_KEY_COUNT,
    NG_EXPANDED_KEY_LEN, NG_ROUNDS, NgKeys,
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

    /// Whether this transform can be run **forwards** over `material`, so
    /// that an archive under it can be written back.
    ///
    /// AES-256 is symmetric: the same key and the same one ECB pass that
    /// decrypt a table of contents encrypt one, and the key is the tag's, so
    /// the AES arm answers `true` whatever is in hand — a caller with no key
    /// is answered by [`Error::WrongKey`](crate::Error::WrongKey), which says
    /// something different.
    ///
    /// **The NG arm is a question about the material and no longer about the
    /// tag.** [`NgForward`] derives the whole seventeen-round forward
    /// transform from the decrypt tables alone, in milliseconds, with nothing
    /// bundled and nothing stored (DR-062) — so NG seals exactly when the
    /// decrypt tables are here to derive it from, and refuses when they are
    /// not. That is what [`NoWrite::NoInverse`](crate::NoWrite::NoInverse) now
    /// means.
    ///
    /// The one place that asymmetry is decided: [`crate::Archive::writable`]
    /// asks it, and no write path decides it again (§3).
    #[must_use]
    pub fn seals(self, material: Option<&Material>) -> bool {
        match self {
            Self::Aes(_) => true,
            Self::Ng => material.is_some_and(|held| held.ng().is_some()),
        }
    }

    /// Whether an archive under this transform is keyed by **the name it is
    /// found under**.
    ///
    /// AES takes its key from the tag alone, so an AES archive renamed, moved
    /// or written at another size is still under the key it was read under. An
    /// NG archive's every region is keyed by `(hash(name) + length + 61) % 101`
    /// — `docs/rpf-format.md`, Encryption — so what it is *called* is part of
    /// what it is, and a nested one whose holder renames it is left keyed by a
    /// name it no longer has.
    ///
    /// The one place that asymmetry is decided for a rename, as
    /// [`Scheme::seals`] is for a write (`docs/conventions.md` §3). DR-064.
    #[must_use]
    pub const fn keyed_by_name(self) -> bool {
        match self {
            Self::Aes(_) => false,
            Self::Ng => true,
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

/// What mints a [`Seal`] for one **region** of one archive.
///
/// The forward transform is a property of the archive; the key is a property of
/// the region, because the NG key index is a function of the **name and length**
/// of what is being written (Q2). So the material-derived half is made once —
/// for NG that is [`NgForward::derive`], all seventeen rounds, milliseconds and
/// nothing on disk (DR-062) — and one [`Seal`] is minted per table of contents,
/// per names blob and per payload.
///
/// **That split is what keeps the wrong key out of a write path's shape.** A
/// single seal carried through a rebuild would be keyed by the length the
/// archive had before it was rebuilt, and an NG archive sealed under it parses
/// and does not load. A `Sealer` cannot seal anything without being handed a
/// name and a length, so a value that travels — held in a struct, cloned across
/// a session, returned from the call that derived the transform — is this one
/// and never a [`Seal`].
///
/// It is not a proof, and DR-063 is what taught the difference. A `Seal` is
/// still a value some caller holds for the length of one call, and one minted
/// from the length of the bytes it was *read* from and applied to the bytes
/// being *written* is the wrong key with nothing to say so. What the type can
/// do it does: a `Seal` is not [`Clone`], so it cannot outlive the write that
/// minted it, and every seam that seals bytes it produced itself mints the
/// seal from those bytes.
///
/// Nothing here holds a key of its own and nothing here prints one: `Debug`
/// says which transform, never a byte of it (DR-020).
pub struct Sealer {
    inner: SealerInner,
}

/// The forward transform, and whatever minting a key for a region needs.
enum SealerInner {
    /// An AES key, expanded once. It takes neither a name nor a length: the key
    /// is the tag's and nothing else, so an archive written longer, shorter or
    /// under another file name is written under the key it was read under.
    Aes {
        /// Which key the tag chose, for `Debug` to name. A discriminant, never
        /// a key: DR-020.
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
    /// this build cannot run one.
    ///
    /// `None` has exactly two causes, and a caller has to tell them apart
    /// because they name different things to do about it:
    ///
    /// - `material` does not carry what the transform needs — no AES key of the
    ///   tag's kind, or no NG decrypt tables. For NG that is the whole of
    ///   [`NoWrite::NoInverse`](crate::NoWrite::NoInverse)'s meaning since
    ///   DR-062: **this build has nothing to derive the transform from**, not
    ///   that the transform has no inverse.
    /// - the decrypt tables are there and do not derive, which
    ///   [`NgNotInvertible`] would name and which no material measured here
    ///   has ever been.
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
    /// written.
    ///
    /// `name` is the archive's own file name for its table of contents and its
    /// names blob, and the entry's own name for a payload; `len` is that
    /// archive's **new** length or that entry's **new** uncompressed length.
    /// Both are what the NG key index is a function of, and both are what the
    /// reader will choose the key by — [`Cipher::new`] is the same two
    /// arguments on the other side. An entry rewritten at a different size
    /// picks a different key, and picking the old one writes an archive that
    /// parses and does not load.
    ///
    /// `None` only where the material holds no key at the index the name and
    /// length chose, which material of the shape [`NgKeys`] promises never is.
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

/// By hand, so that no key can reach a log, a panic message or a `--json`
/// payload by being printed. DR-020.
impl fmt::Debug for Sealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealer")
            .field("scheme", &self.scheme())
            .finish_non_exhaustive()
    }
}

/// One region's or one payload's **encryption**: the inverse of a [`Cipher`].
///
/// It exists for both transforms since DR-062: the AES arm is the same key and
/// the same single ECB pass that decrypt, and the NG arm is [`NgForward`], all
/// seventeen rounds derived from the decrypt tables the user's own material
/// already carries and run backwards. Nothing is bundled, nothing is fetched
/// and nothing derived touches disk (DR-006).
///
/// **It is keyed for one region and cannot be reused across regions**, because
/// the NG key index is a function of a name and a length. [`Sealer`] is what
/// mints one, and is the value a write path holds.
///
/// Nothing here holds a key of its own and nothing here prints one: `Debug`
/// says which transform and which of the 101 expanded keys, never a byte of
/// either (DR-020).
///
/// **Not [`Clone`]**, since DR-063. A seal that could be copied out of the
/// write that minted it could be applied to bytes of another length, which for
/// NG is the wrong key — and that is exactly what a converted resource write
/// did with one.
pub struct Seal {
    inner: SealInner,
}

/// The forward transform, keyed for one region.
enum SealInner {
    /// The expanded AES key schedule, and which key the tag chose.
    Aes {
        /// A discriminant, never a key: DR-020.
        which: AesKey,
        /// The expanded key schedule.
        aes: Arc<Aes256>,
    },
    /// The derived transform and the expanded key this region chose.
    Ng {
        /// All seventeen rounds, shared with every other region's seal.
        forward: Arc<NgForward>,
        /// Which expanded key, in `0..NG_EXPANDED_KEY_COUNT`. An index for
        /// `Debug` to print, never a key: DR-020.
        key: usize,
        /// The key itself, resolved when the seal was minted rather than at
        /// every block — the rule [`Cipher`]'s own arm states.
        expanded: Box<[u8; NG_EXPANDED_KEY_LEN]>,
    },
}

impl Seal {
    /// The forward transform for `scheme`, keyed by the name and length of
    /// what is being written, or `None` where this build cannot run one.
    ///
    /// [`Sealer::new`] and [`Sealer::seal`] in one call, for a caller that
    /// seals a single region and has the material in hand. A caller sealing a
    /// whole archive holds the [`Sealer`] instead, so that seventeen rounds are
    /// derived once rather than per payload.
    #[must_use]
    pub fn new(scheme: Scheme, material: &Material, name: &str, len: u64) -> Option<Self> {
        Sealer::new(scheme, material)?.seal(name, len)
    }

    /// Which of the 101 NG expanded keys this chose, where it chose one.
    ///
    /// An index, never a key: DR-020.
    #[must_use]
    pub const fn key_index(&self) -> Option<usize> {
        match self.inner {
            SealInner::Aes { .. } => None,
            SealInner::Ng { key, .. } => Some(key),
        }
    }

    /// Encrypts `buf` in place, leaving a tail shorter than
    /// [`CIPHER_BLOCK_LEN`] exactly as it stands.
    ///
    /// The same extent rule as [`Cipher::apply`], and it has to be: what a
    /// reader leaves alone a writer must leave alone, or what it wrote is not
    /// what it reads back. `docs/rpf-format.md`, Encryption, `verified`.
    ///
    /// `buf` is one whole region — a table of contents, a names blob, or one
    /// payload — counted from **its own start**, because neither transform
    /// chains between blocks and both run from the start of what they cover.
    pub fn apply(&self, buf: &mut [u8]) {
        let (blocks, _tail) = buf.as_chunks_mut::<CIPHER_BLOCK_LEN>();
        for block in blocks {
            self.block(block);
        }
    }

    /// Encrypts one whole block in place.
    ///
    /// The one implementation of the forward transform, so the buffered form
    /// above and the streaming form in [`crate::build`] cannot come to
    /// disagree (§3).
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
    /// The AES transform over a key of thirty-two zero bytes, forwards.
    ///
    /// The counterpart of [`Cipher::over_zeros`], and for the same reason: it
    /// tests the **framing** with no key material anywhere (DR-006).
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

/// By hand, so that no key can reach a log, a panic message or a `--json`
/// payload by being printed. DR-020.
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
///
/// `lookup` answers what the round's table for a column holds for one byte.
/// The round is written over that rather than over [`NgKeys`] because
/// [`NgRound`] runs the very round it inverts, and a second spelling of
/// this loop is a second implementation to keep correct (§3).
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

/// Which of the two column orders a round reads its bytes in.
///
/// The one owner of that split (§3): [`ng_block`] and [`NgRound`] both
/// ask it, and a round whose inverse read the other order would invert nothing.
const fn ng_order(round: usize) -> &'static [[usize; 4]; 4] {
    if round < NG_LEADING_ROUNDS || round == NG_LAST_ROUND {
        &NG_COLUMN_ORDER
    } else {
        &NG_SHIFTED_ORDER
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
        ng_round(ng, round, round_key, ng_order(round), block);
    }
}

/// How many words one decrypt table holds — one per value the byte it reads
/// can take.
///
/// [`crate::keys::NG_DECRYPT_TABLE_LEN`] is the same fact in bytes, and
/// `a_decrypt_table_holds_one_word_per_value_of_the_byte_it_reads` is what
/// stops the two drifting (§3).
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
/// of its thirty-two unit vectors.
///
/// A map in this form is applied by [`image_of`] and inverted by
/// [`inverse_of`], and the inverse comes back in the same form — which is what
/// lets the derived tables be built by applying it to one shifted byte at a
/// time.
type WordMap = [u32; NG_WORD_BITS];

/// Why a round's forward tables could not be derived from its decrypt tables.
///
/// Not a [`crate::Error`], and deliberately: the variants say what is wrong
/// with a *table*, which is a fact about key material rather than about an
/// archive, and no exit code is derived from them (§2, §10). A caller that
/// wires this into a write path converts it at that seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NgNotInvertible {
    /// There is no such round: the transform has [`crate::keys::NG_ROUNDS`] of
    /// them, or the material is short of one of this round's tables.
    NoSuchRound {
        /// The round that was asked for.
        round: usize,
    },
    /// A column's table is not a byte permutation into an eight-dimensional
    /// space, so the round does not factor and no inverse can be built from it.
    ///
    /// Measured against the real material, all 272 tables are: their 256
    /// entries differ from the first by 256 **distinct** words spanning
    /// **eight** dimensions. A table that is not is either not this cipher's
    /// or was read wrong, and both are worth naming rather than sweeping for.
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
/// **Every round factors, and this is measured rather than assumed.** Each of
/// a round's sixteen decrypt tables turns the byte it reads into one of 256
/// distinct words, and those words differ from the table's first entry by an
/// eight-dimensional GF(2) subspace — so a table is a byte permutation
/// followed by an injection into a subspace, the shape an AES T-box has. The
/// four columns of an output word contribute four independent subspaces that
/// span the word, so a round is a byte substitution and an invertible linear
/// map, and its inverse is the substitutions read backwards and the map
/// inverted by Gaussian elimination over GF(2).
///
/// **Its only input is the decrypt tables this build already holds** — no
/// second key, no scraped constant, nothing bundled and nothing downloaded.
/// DR-006, and `docs/ng-scheme.md`. It costs milliseconds, so a derived round
/// is a value a caller makes when it needs one rather than an artefact anyone
/// has to store.
///
/// That is a stronger result than the reference implementation's, which solves
/// rounds 0, 1 and 16 this way and brute-forces the other fourteen with a 2^32
/// sweep each. The sweep is unnecessary: what it is searching for is the
/// substitution this derives.
///
/// Nothing here prints a table: `Debug` says which round, never a word or a
/// byte of either direction (DR-020).
pub struct NgRound {
    /// Which round, which is also which of the two column orders it reads in.
    round: usize,
    /// The round's decrypt tables, copied out of the material as words.
    ///
    /// Copied rather than borrowed so that the round and the inverse derived
    /// from it cannot come to read different tables (§3), and so that a
    /// derived round outlives the scan that produced it.
    opening: Box<RoundTables>,
    /// The inverse of each column's linear part, in the decrypt tables' own
    /// shape: what the forward direction looks a byte of the stripped output
    /// word up in.
    sealing: Box<RoundTables>,
    /// The inverse of each column's byte substitution: what turns a recovered
    /// coordinate back into the byte the decrypt round read.
    substitution: Box<RoundBytes>,
    /// What each output word carries when the round key is zero: the
    /// exclusive-or of the four tables' entries for a zero byte.
    ///
    /// The affine part, held apart from the linear part because only the
    /// linear part is inverted. The forward direction removes it, and the
    /// round key, before it looks anything up.
    constants: [u32; NG_WORDS],
}

impl NgRound {
    /// Derives the forward direction of `round` from the decrypt tables in
    /// `ng`.
    ///
    /// # Errors
    ///
    /// [`NgNotInvertible::NoSuchRound`] where the material holds no such
    /// round; [`NgNotInvertible::NotASubstitution`] naming the column whose
    /// table does not factor, and by how much; and
    /// [`NgNotInvertible::Singular`] where the four columns of a word do not
    /// span it independently.
    ///
    /// Milliseconds: sixteen eliminations of 256 words each, and four of
    /// thirty-two.
    pub fn solve(ng: &NgKeys, round: usize) -> Result<Self, NgNotInvertible> {
        let absent = NgNotInvertible::NoSuchRound { round };
        let opening = round_tables(ng, round).ok_or(absent)?;
        let order = ng_order(round);
        let mut sealing = Box::new([[0_u32; NG_TABLE_ENTRIES]; NG_COLUMNS]);
        let mut substitution = Box::new([[0_u8; NG_TABLE_ENTRIES]; NG_COLUMNS]);
        let mut constants = [0_u32; NG_WORDS];

        for (word, columns) in order.iter().enumerate() {
            // The map of one output word, as the images of the thirty-two
            // coordinates the four columns contribute — bit `8 * place + bit`
            // of the word's own space is basis vector `bit` of the column at
            // `columns[place]`.
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

                // The substitution, backwards: the coordinates of entry `b` in
                // this column's own basis are what the forward direction
                // recovers, and `b` is what it has to hand back. Read the other
                // way round it is also the check that the table is a
                // permutation — every coordinate is written exactly once, and
                // `basis_of` has already said there are 256 distinct ones.
                let inverse = substitution.get_mut(column).ok_or(absent)?;
                for (value, entry) in table.iter().enumerate() {
                    let byte = u8::try_from(value).map_err(|_| absent)?;
                    let coordinates = coordinates_of(&basis, entry ^ base).ok_or(shape)?;
                    *inverse.get_mut(usize::from(coordinates)).ok_or(absent)? = byte;
                }
            }

            let inverse = inverse_of(&map).ok_or(NgNotInvertible::Singular { round, word })?;
            *constants.get_mut(word).ok_or(absent)? = constant;

            // The forward table for a column is the inverse applied to that
            // column's own byte, in that column's own place in the word — so a
            // word's four lookups exclusive-or to the inverse of the whole
            // word, which is what makes the forward direction the same shape
            // as the backward one.
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

    /// Runs the round's **decrypt** direction over one block.
    ///
    /// The same code the whole transform runs — `ng_round_over` — over the
    /// same tables the inverse was derived from, so that a round trip measures
    /// the derivation rather than two implementations agreeing (§3).
    pub fn open(&self, round_key: &[u8; NG_ROUND_KEY_LEN], block: &mut [u8; CIPHER_BLOCK_LEN]) {
        ng_round_over(
            |column, byte| entry_of(&self.opening, column, byte),
            round_key,
            ng_order(self.round),
            block,
        );
    }

    /// Runs the round's **encrypt** direction over one block: the exact
    /// inverse of [`NgRound::open`] under the same round key.
    ///
    /// The round key and the affine constant come off the output word first,
    /// because only what is left is linear; then four lookups rebuild the
    /// word's coordinates, the substitution turns each coordinate back into
    /// the byte it came from, and each byte lands at the column the decrypt
    /// round read it from — which for a permuted round is not the word's own
    /// four bytes.
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

/// By hand, so that no derived table can reach a log or a panic message by
/// being printed. DR-020, which is about material and not about where it came
/// from: a table solved for is as much key material as one that was scanned.
impl fmt::Debug for NgRound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NgRound")
            .field("scheme", &Scheme::Ng)
            .field("round", &self.round)
            .finish_non_exhaustive()
    }
}

/// The whole NG transform's **forward** direction: all seventeen rounds,
/// derived from the decrypt tables.
///
/// The decrypt direction runs round 0 first and round 16 last, so this runs
/// round 16 first and round 0 last. That is the only thing it adds to
/// [`NgRound`], and it is the thing a writer must not get wrong.
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
    /// derive — the whole transform or none of it, because a transform missing
    /// one round writes an archive nothing reads (§4).
    pub fn derive(ng: &NgKeys) -> Result<Self, NgNotInvertible> {
        let mut rounds = Vec::with_capacity(NG_ROUNDS);
        for round in 0..NG_ROUNDS {
            rounds.push(NgRound::solve(ng, round)?);
        }
        Ok(Self { rounds })
    }

    /// Encrypts one whole block in place, under `expanded`.
    ///
    /// The exact inverse of the decrypt transform [`Cipher`] runs, under the
    /// same expanded key.
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
///
/// Eight dimensions and 256 distinct differences together are the whole
/// factorisation: 256 distinct vectors in a space of exactly 256 elements are
/// all of it, so the coordinate map is a bijection and the table is a
/// permutation of the 256 coordinate values. [`coordinates_of`] is the half
/// that reads one out; [`distinct_of`] is where the second half is checked.
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
/// space the basis spans.
///
/// The basis is in echelon form with its leading bits descending, so one pass
/// in that order both reduces the vector and reads its coordinates off.
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
/// Gauss-Jordan elimination on thirty-two rows, each carried alongside the
/// unit vector it started as. The invariant every step preserves is
/// `map(source[row]) == image[row]`: exclusive-oring one row into another is
/// linear, so it holds on both sides at once. When elimination has turned
/// every `image[row]` into that row's unit vector, `source[row]` is what `map`
/// sends to it — which is the inverse in the same form.
///
/// This is the port of the reference implementation's `RandomGauss.Solve`, and
/// it is not a transcription of it: that one feeds random blocks through the
/// decrypt round and collects pivots for 128 systems of 1024 unknowns, where
/// each output word here depends on four bytes and no more, so the basis
/// vectors give the map directly and the systems are four of thirty-two.
/// `docs/ng-scheme.md`.
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
/// material.
///
/// Outside `mod tests` because two modules want it: this module's own tests and
/// `build`'s, which is where an NG-tagged archive is written and read back with
/// nothing extracted from anything. `#[cfg(test)]`, so none of it is in a
/// release build or in anything a dependent compiles — the same confinement
/// DR-048 puts on the fuzz seam and `Material::over_zeros` on its own.
///
/// **None of it is key material and none of it came from any** (DR-006): every
/// value is drawn from a named seed by three lines of arithmetic, and what the
/// tables pin is that the derivation inverts whatever tables of the measured
/// shape it is handed.
#[cfg(test)]
pub(crate) mod synthetic {
    use super::*;
    use crate::keys::{NG_COLUMNS, NG_DECRYPT_TABLE_COUNT, NG_DECRYPT_TABLE_LEN};

    /// A decrypt table set of the length [`NgKeys`] promises, answering zero
    /// for every input byte of every round and column.
    ///
    /// The NG transform used to be reachable only with the real material, so
    /// every fact about it below this line was defensible on the one machine
    /// that has a memory image and nowhere else. `NgKeys::restored` takes the
    /// tables as bytes, so tables chosen to make the wiring readable cost no
    /// key material at all and are not any (DR-006): what they pin is which
    /// byte reaches which word, and that is arithmetic rather than a value.
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
    ///
    /// No key material is involved and none could be: what these tests measure
    /// is that the derivation inverts *whatever* affine tables it is given, and
    /// that is arithmetic (DR-006).
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
    /// exclusive-ored with the images of the bits set in `substitution[b]`.
    ///
    /// Which is the shape every one of the 272 real tables has —
    /// `a_rounds_table_differences_are_an_eight_dimensional_space_in_every_column`
    /// in `crates/rpf-core/tests/ng_inverse.rs` is where that is measured. A
    /// `substitution` of the identity is the special case rounds 0, 1 and 16
    /// are: affine on the byte, and so linear on the block.
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
    /// up and says why.
    ///
    /// A random 32 x 32 matrix over GF(2) is invertible about 29% of the time,
    /// so two hundred consecutive failures land near 10^-30 and mean the
    /// derivation has stopped inverting rather than that the draws were
    /// unlucky.
    const MOST_DRAWS: u32 = 200;

    /// A whole table set whose every round derives.
    ///
    /// Built one output word at a time, and **retried per word**: a random
    /// 32 x 32 matrix over GF(2) is invertible about 29% of the time, so a
    /// draw that is singular is discarded and the next taken. Retrying a whole
    /// round instead would be a 0.7% chance a hundred and thirty-six times
    /// over, which is a test that never finishes.
    ///
    /// `substituted` says whether each column's byte substitution is a shuffle
    /// or the identity. The identity gives affine tables — what rounds 0, 1
    /// and 16 are — and a shuffle gives what rounds 2 through 15 are.
    ///
    /// The retry is **bounded**, and that is a fix rather than a decoration: a
    /// helper that cannot fail can only spin. Unbounded, three mutations of
    /// `inverse_of` — which make it answer `None` for every map — turned this
    /// loop into a program that never stops, and a mutation sweep spent its
    /// full per-mutant timeout on each of them instead of recording a kill. A
    /// reader with a genuinely broken `inverse_of` would have spent an
    /// afternoon on the same silence.
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
    /// different index is written under **different bytes** rather than the
    /// same bytes under another name — which is the only way a test can tell a
    /// re-keyed write from one that forgot to re-key.
    pub(crate) fn distinct_expanded(seed: u32) -> Vec<u8> {
        let mut stream = Stream(seed);
        let mut out = no_expanded();
        for slot in &mut out {
            *slot = stream.byte();
        }
        out
    }

    /// Material of the shape only a memory image carries, with **no key
    /// material in it**: substituted decrypt tables that derive, 101 expanded
    /// keys, an AES key and a hash lookup table, all drawn from `seed`.
    ///
    /// What it makes testable is the whole NG write path with no game
    /// installation and no memory image anywhere — the counterpart of
    /// [`Material::over_zeros`](crate::keys::Material::over_zeros) for the arm
    /// that one deliberately leaves empty. Nothing here is or came from a key
    /// (DR-006): the tables are arithmetic, and what they pin is that the
    /// derivation inverts whatever tables it is given.
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
    fn a_seal_is_the_ciphers_exact_inverse_over_the_same_extent() {
        // The whole of what makes an AES archive writable: the same key runs
        // both directions, and both leave the same tail alone. A seal that
        // covered a byte the cipher does not — or the other way round — writes
        // an archive that reads back as nonsense from the first short region,
        // which is every names blob whose length is not a multiple of sixteen.
        let cipher = Cipher::over_zeros();
        let seal = Seal::over_zeros();
        for len in 0..=(CIPHER_BLOCK_LEN * 3 + 1) {
            let plain: Vec<u8> = (0..len)
                .map(|n| u8::try_from(n % 251).unwrap_or(0))
                .collect();
            let mut sealed = plain.clone();
            seal.apply(&mut sealed);
            assert_eq!(sealed.len(), len, "sealing changed the length at {len}");

            // The tail is the bytes past the last whole block, in both
            // directions.
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
        // DR-020, on the type a write path holds for the whole of a rebuild.
        // Both directions, because the second is satisfied by an
        // implementation that prints nothing at all — and so, therefore, would
        // it be by a derived one that prints everything, since neither is what
        // the suite reads. It has to **name the transform**, so that a log
        // line or a panic says which one was running, and it has to name
        // nothing else, because what it is over is 305 KB of material.
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

        // And the AES arm, which names its key by a discriminant and holds a
        // whole expanded schedule behind it.
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
        // DR-020, on the type the write path holds.
        let rendered = format!("{:?}", Seal::over_zeros());
        assert!(rendered.contains("Aes"), "{rendered}");
        assert!(!rendered.contains("00"), "{rendered}");
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

    #[test]
    fn a_round_reads_the_four_columns_its_own_order_names() {
        // `the_two_orders_are_the_ones_the_format_uses` says what the two
        // arrays hold. Nothing said the round *reads* them: a round that took
        // its columns from the other order, or from the output word's own four
        // bytes, decrypts most of a block and corrupts the rest, and the only
        // thing that noticed was a machine with a memory image on it.
        //
        // Each column's table answers a bit of its own, so an output word is
        // the set of columns that reached it, written down.
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
        // Every other test here gives each column a bit of its own, so the
        // four terms of a word are disjoint — and over disjoint operands
        // exclusive-or and inclusive-or agree. `^=` could become `|=` and all
        // of them stayed green, which is the equivalence in the tests rather
        // than in the code: an OR is not invertible, so a payload decrypted
        // with one would never come back.
        //
        // These two tables overlap on purpose, and the three answers are three
        // different words: `^` gives 0x00FF_FF00, `|` gives 0xFFFF_FF00 and `&`
        // gives 0.
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

        // And the round key is folded in the same way: a key word that shares
        // bits with the lookups has to cancel them, not add to them.
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
        // With every table answering zero, a round is its round key and
        // nothing else — so this says the sixteen key bytes reach the sixteen
        // output bytes in order, and that the round key is exclusive-ored in
        // rather than dropped.
        let ng = ng_over(no_tables(), no_expanded());
        let key: [u8; NG_ROUND_KEY_LEN] =
            std::array::from_fn(|index| u8::try_from(index).unwrap_or(0).wrapping_mul(17));
        let mut block = [0xAA_u8; CIPHER_BLOCK_LEN];
        ng_round(&ng, 0, &key, &NG_COLUMN_ORDER, &mut block);
        assert_eq!(block, key);
    }

    #[test]
    fn a_column_looks_its_own_byte_up_in_its_own_table() {
        // One table that answers the byte it was asked about, and fifteen that
        // answer zero. The one is **column 1**, and its own byte is the second
        // of the block: a lookup that read a fixed byte, or the first one,
        // answers the first byte here and is told so. Column 0's byte is a
        // different value on purpose, and so is column 1's position in its
        // table, so neither can pass for the other.
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

            // Column `column` is in the first row of the column order, so its
            // lookup reaches the first output word, at the byte the table put
            // it in.
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
        // block a whole transform answers is the *last* round key and nothing
        // else. A transform that stopped a round early would answer the
        // sixteenth, which is a block of fifteens rather than sixteens.
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
        // `the_permuted_rounds_are_the_middle_fourteen` states the rule over a
        // copy of the condition written in the test itself, so moving the real
        // one — `NG_LEADING_ROUNDS`, or the `== NG_LAST_ROUND` that lets the
        // sixteenth round back into column order — changed no answer anywhere
        // without a memory image present. This runs the transform.
        //
        // Every table answers the byte it was asked about, placed at that
        // column's own position in a word. A round reading in column order is
        // then the identity, and a round reading through the shift-rows
        // permutation is that permutation exactly — so the whole transform is
        // the permutation applied once per permuted round, and the count is
        // readable off the answer.
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

        // Fourteen, from `docs/rpf-format.md`, Encryption: rounds 2 through 15
        // read through the permutation and rounds 0, 1 and 16 do not.
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
        // `NG_TABLE_ENTRIES` and `NG_DECRYPT_TABLE_LEN` are the same fact in
        // two units, and the solver counts in the first while the material is
        // stored in the second (§3). A drift between them reads a table short
        // and derives an inverse for a map that is not the round's.
        assert_eq!(NG_DECRYPT_TABLE_LEN, NG_TABLE_ENTRIES.saturating_mul(4));
        assert_eq!(NG_TABLE_ENTRIES, usize::from(u8::MAX).saturating_add(1));
        assert_eq!(NG_WORD_BITS, NG_COLUMN_BITS.saturating_mul(4));
        assert_eq!(NG_WORDS, 4);
    }

    #[test]
    fn the_order_a_round_reads_in_has_one_owner() {
        // `ng_block` and `NgRound` both ask `ng_order`, and a forward round
        // that read the other order would invert nothing. This says the one
        // owner answers what `docs/rpf-format.md`, Encryption, records: rounds
        // 0, 1 and 16 in column order, 2 through 15 permuted.
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
        // `basis_of` and `coordinates_of` are reached only through a whole
        // table's factorisation, so a basis written down here is the only way
        // to say what one of them answers for one vector. The case worth
        // writing down is a basis holding the vector `1`: `leading_bit` is zero
        // both for `1` and for the zero a vector reduces to, so a pass that did
        // not stop at zero would reduce a spanned vector a second time, come
        // out at `1` rather than at zero, and answer `None` for a vector the
        // basis plainly spans.
        //
        // The identity basis, in the echelon form and the order `basis_of`
        // hands back: leading bits descending, so bit `n` of the coordinates is
        // the `n`th vector here.
        let basis: [u32; NG_COLUMN_BITS] = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01];
        // Reduced to zero by the first vector, with seven slots still to go.
        assert_eq!(coordinates_of(&basis, 0x80), Some(0b0000_0001));
        // Zero itself, which is at the origin of every space there is.
        assert_eq!(coordinates_of(&basis, 0x00), Some(0));
        // The last vector, which is the one that reduces nothing early.
        assert_eq!(coordinates_of(&basis, 0x01), Some(0b1000_0000));
        // And a vector that takes four of the eight.
        assert_eq!(coordinates_of(&basis, 0xC3), Some(0b1100_0011));
        // A vector outside the space the basis spans has no coordinates, which
        // is the answer `distinct_of` and the rank both hang off.
        assert_eq!(coordinates_of(&basis, 0x100), None);
    }

    #[test]
    fn a_columns_rank_is_the_dimension_its_entries_differ_from_the_first_over() {
        // The rank is the whole of what a `NotASubstitution` says about the
        // *shape* of a table that does not factor, and it is a number nothing
        // else in this build reads back — so a table perturbed inside a whole
        // round measures that the refusal fires and cannot measure what number
        // it carries out, since a rank arrived at wrongly is unequal to eight
        // just as the right one is. Written down here instead: three columns
        // whose differences are counted by hand.
        let base = 0x2C_u32;
        // Eight independent differences from the first entry, and nothing
        // else — which is what every one of the 272 real tables is.
        let mut table = [base; NG_TABLE_ENTRIES];
        for bit in 0..NG_COLUMN_BITS {
            table[bit.saturating_add(1)] = base ^ (1_u32 << bit);
        }
        assert_eq!(rank_of(&table, base), NG_COLUMN_BITS);

        // A ninth takes it to nine, which is the number a table one bit away
        // from factoring reports.
        table[NG_COLUMN_BITS.saturating_add(1)] = base ^ 0x100;
        assert_eq!(rank_of(&table, base), NG_COLUMN_BITS + 1);

        // And a column whose every entry is the first differs from it over
        // nothing at all, which is the all-zero fixture's answer.
        assert_eq!(rank_of(&[base; NG_TABLE_ENTRIES], base), 0);
    }

    #[test]
    fn the_solver_inverts_an_invertible_map_and_refuses_a_singular_one() {
        // The Gaussian elimination on its own, over a matrix that is no part of
        // any cipher — the one half of this work that needs no game material of
        // any kind, and so the one half a machine with no memory image can
        // still be told is wrong.
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

        // A map with two equal images loses a bit, so no inverse exists and one
        // must not be invented: an invented one silently corrupts every block.
        let mut singular: WordMap =
            std::array::from_fn(|bit| 1_u32 << u32::try_from(bit).unwrap_or(0));
        singular[3] = singular[7];
        assert_eq!(inverse_of(&singular), None);

        // And the identity is its own inverse, which is the one answer that can
        // be written down rather than checked.
        let identity: WordMap = std::array::from_fn(|bit| 1_u32 << u32::try_from(bit).unwrap_or(0));
        assert_eq!(inverse_of(&identity), Some(identity));
    }

    #[test]
    fn a_derived_round_is_the_exact_inverse_of_the_decrypt_round_it_came_from() {
        // **The experiment, with no key material in it.** Affine tables of the
        // shape rounds 0, 1 and 16 have, a round key that is not zero, and the
        // round trip that decides R4.7: what the decrypt round turns a block
        // into, the derived forward round turns back.
        //
        // Both a column-order round and a permuted one, because the forward
        // direction has to put each recovered byte back at the column the
        // decrypt round read it from — and for a permuted round that is not the
        // word's own four bytes. A `seal` that ignored the permutation passes
        // the first of these and fails the second.
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

                // And the other way round, which is the direction a writer
                // actually runs: seal first, then open.
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
        // **The result that removes the 2^32 sweep from R4.7.** These tables
        // are not affine on the byte they read — each puts the byte through a
        // shuffle first, which is what rounds 2 through 15 do and what the
        // reference implementation brute-forces the inverse of. The
        // factorisation finds the shuffle instead, and the round trip closes
        // in milliseconds.
        //
        // The fixture is checked for being what it claims: an affine table set
        // would pass this test while proving nothing about the substituted
        // case, so the two are compared and must differ.
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
        // Seventeen rounds, in the order a writer runs them: round 16 first
        // and round 0 last, which is the decrypt order reversed. A forward
        // transform that ran them the same way round as the decrypt one
        // inverts each round and none of the composition, and every test above
        // this line would still pass.
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
        // DR-020 again, on the type that holds all seventeen rounds of it.
        let ng = ng_over(affine_tables(0xFEED_FACE), no_expanded());
        let rendered = format!("{:?}", NgForward::derive(&ng).expect("every round derives"));
        assert!(rendered.contains("Ng"), "{rendered}");
        assert!(!rendered.contains("00"), "{rendered}");
    }

    #[test]
    fn a_derived_rounds_decrypt_is_the_transforms_own_round() {
        // `NgRound::open` exists so that a round trip measures the
        // derivation rather than two implementations of the decrypt round
        // agreeing with each other. This says it is the same round: the same
        // tables, the same order, the same answer as `ng_round`, which is what
        // `ng_block` runs.
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
        // A refusal has to say *what* is wrong with the table, because the two
        // ways it can be wrong have different answers: differences that span
        // more than eight dimensions mean the round does not factor at all,
        // and differences that repeat mean two input bytes are
        // indistinguishable. One entry moved by one bit takes the rank to nine.
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
                // Nine, and not merely "not eight". The rank is the whole of
                // what this refusal reports about the shape, so a number that
                // was garbled on the way out would still satisfy "not the
                // invertible one" and say nothing.
                assert_eq!(rank, NG_COLUMN_BITS + 1, "the rank is what is wrong");
                assert_eq!(distinct, NG_TABLE_ENTRIES);
            }
            other => panic!("{other:?}"),
        }
        // And no other round is disturbed by it.
        assert!(NgRound::solve(&ng, 0).is_ok());
    }

    #[test]
    fn a_round_that_loses_information_is_refused_rather_than_inverted_wrongly() {
        // An affine round whose map is singular has no inverse at all. The one
        // answer that must never be given is a table set: it would be the
        // inverse of some other map, and every block written under it would
        // read back as noise.
        let mut tables = affine_tables(0x0F0F_0F0F);
        // Column 1's table becomes column 0's, so two of the word's eight-bit
        // blocks have the same image and the thirty-two bits collapse to
        // twenty-four.
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
        // The all-zero fixture every other test here uses answers one word for
        // all 256 bytes, so it is neither a permutation nor eight-dimensional.
        // It is worth pinning because it is the fixture a mistake reaches
        // first, and because a solver that read no table at all would answer
        // exactly this.
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
        // DR-020 is about material, not about where it came from: a table
        // solved for is as much key material as one that was scanned, and this
        // is the type that holds both directions of it.
        let ng = ng_over(affine_tables(0xDEAD_BEEF), no_expanded());
        let derived = NgRound::solve(&ng, 0).expect("affine and invertible");
        let rendered = format!("{derived:?}");
        assert!(rendered.contains("Ng"), "{rendered}");
        assert!(rendered.contains("round"), "{rendered}");
        assert!(!rendered.contains("00"), "{rendered}");
    }

    /// `block` with the shift-rows permutation applied `times` times.
    ///
    /// Read straight off [`NG_SHIFTED_ORDER`]: column `c` of the input becomes
    /// the byte of output word `j` that `c` occupies, for the `j` whose row
    /// names it.
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
