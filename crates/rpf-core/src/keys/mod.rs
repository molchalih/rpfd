//! Key material, and finding it in a source from the user's own installation.
//!
//! Nothing here is bundled. DR-006 forbids shipping key material, so the
//! repository carries only the **SHA-1 digest** of each value it knows how to
//! look for (the `anchors` module) and the routine that looks. That makes the search its
//! own proof: bytes that hash to the digest asked for are the value, and
//! nothing weaker than the value hashes to it.
//!
//! A **source** is any file the search is pointed at, and the search knows
//! nothing about its shape — it hashes windows of bytes. That is why one
//! routine finds the AES key in six different binaries, and why it also finds
//! the NG material in a memory image, which is the only place that material has
//! ever been in the clear. DR-040.
//!
//! The container itself never reaches this module. An archive whose encryption
//! tag its version calls open (see [`crate::format::Version::open`]) is refused with
//! [`crate::Error::NeedsKey`] before any key is wanted, which is what keeps
//! every unencrypted path — the whole of the primary workflow — working with no
//! key material present at all. R2.6.

mod anchors;
mod cache;
mod scan;

pub use cache::{Cache, SOURCE_DIGEST_LEN, SourceDigest};

use std::{
    fmt,
    io::{Read, Seek},
    sync::Arc,
};

use scan::{Anchor, Sighting};

use crate::{
    error::{Error, Result},
    format::crypto::Scheme,
    watch::Watch,
};

/// Length of a SHA-1 digest, which is what a value is anchored by.
const ANCHOR_DIGEST_LEN: usize = 20;

/// The stride the search walks the executable in, in bytes.
///
/// A value not beginning on this boundary is not found. Ported from the
/// reference implementation named in the `anchors` module, and every value
/// measured so far sits on it.
const ANCHOR_ALIGN: usize = 8;

/// Length of the RAGE AES-256 key, in bytes.
pub const AES_KEY_LEN: usize = 0x20;

/// Length of the NG hash lookup table, in bytes.
pub const HASH_LUT_LEN: usize = 0x100;

/// Length of one NG expanded key, in bytes.
pub const NG_EXPANDED_KEY_LEN: usize = 0x110;

/// How many NG expanded keys there are.
pub const NG_EXPANDED_KEY_COUNT: usize = 101;

/// Length of one NG decrypt table, in bytes.
pub const NG_DECRYPT_TABLE_LEN: usize = 0x400;

/// How many rounds the NG transform runs.
pub const NG_ROUNDS: usize = 17;

/// How many decrypt tables one round indexes.
pub const NG_COLUMNS: usize = 16;

/// How many NG decrypt tables there are: one per column per round.
pub const NG_DECRYPT_TABLE_COUNT: usize = NG_ROUNDS.saturating_mul(NG_COLUMNS);

/// The key material a game executable carries in the clear.
///
/// Two values, and the whole of what three executables were measured to hold:
/// the AES-256 key the RAGE table-of-contents transform uses, and the hash
/// lookup table the NG cipher indexes. Whole or not at all — a `Keys` that
/// exists carries both, because a caller given one of them has nothing it can
/// finish (`docs/conventions.md` §4).
///
/// It does **not** carry the NG expanded keys or the NG decrypt tables. Those
/// are [`NgKeys`], and no executable measured here holds them at all.
#[derive(Clone)]
pub struct Keys {
    /// The AES-256 key.
    aes: [u8; AES_KEY_LEN],
    /// Where it was found in the executable.
    aes_at: u64,
    /// The NG hash lookup table.
    lut: [u8; HASH_LUT_LEN],
    /// Where it was found in the executable.
    lut_at: u64,
}

/// How many values [`Keys`] is made of, which is also the count an
/// unrecognised source is told it fell short of.
///
/// One definition rather than two: it is the length of [`Keys::anchors`], so a
/// third value could not be looked for while the failure still said "of 2".
const KEYS_WANTED: usize = 2;

/// Names the material in a failure, so a caller is told which search came up
/// short rather than that "a search" did.
const KEYS_NAMED: &str = "AES key and hash lookup table";

/// Names the AES-256 key where a failure has to say it was the one missing.
const AES_KEY_NAMED: &str = "the AES key";

/// Names the hash lookup table, for the same reason.
const HASH_LUT_NAMED: &str = "the hash lookup table";

/// What [`Keys::extract`] did not find, given what it did.
///
/// Both present is not a failure and so does not occur here; it is the arm that
/// names both, because naming neither would be an answer with nothing in it.
const fn keys_missing(aes: bool, lut: bool) -> &'static [&'static str] {
    match (aes, lut) {
        (false, true) => &[AES_KEY_NAMED],
        (true, false) => &[HASH_LUT_NAMED],
        _ => &[AES_KEY_NAMED, HASH_LUT_NAMED],
    }
}

impl Keys {
    /// Finds the key material in a game executable.
    ///
    /// The source is read from its start to its end, or until everything has
    /// been found. It is not required to be a PE image: the search is over the
    /// bytes, so an executable's section table, its packing and its build date
    /// are all beside the point.
    ///
    /// `watch` is told once per block read and can stop the scan, which is
    /// DR-008's seam. A caller that wants neither passes
    /// [`crate::Unwatched`] — the parameter is not optional, because §4 permits
    /// one spelling per operation.
    ///
    /// # Errors
    ///
    /// [`Error::UnrecognisedExecutable`] if either value is missing, naming
    /// which and how many of the two were found; [`Error::Io`] if the source
    /// cannot be read; [`Error::Cancelled`] if the watcher said to stop.
    pub fn extract<S: Read + Seek, W: Watch>(source: &mut S, watch: &mut W) -> Result<Self> {
        let wanted = Self::anchors();
        let found = scan::find(source, &wanted, KEYS_NAMED, watch)?;
        Self::assembled(&found)
    }

    /// What this material is looked for by, in the order [`Keys::assembled`]
    /// reads the answers back.
    const fn anchors() -> [Anchor; KEYS_WANTED] {
        [
            Anchor {
                len: AES_KEY_LEN,
                digest: anchors::AES_KEY,
            },
            Anchor {
                len: HASH_LUT_LEN,
                digest: anchors::HASH_LUT,
            },
        ]
    }

    /// The material a completed search found, or what it was short of.
    ///
    /// The one place a `Keys` is built from sightings, so [`Keys::extract`] and
    /// [`Material::extract`] cannot come to disagree about what a complete
    /// answer is (`docs/conventions.md` §4).
    fn assembled(found: &[Option<Sighting>]) -> Result<Self> {
        let mut found = found.iter();
        let aes = found
            .next()
            .and_then(Option::as_ref)
            .and_then(exactly::<AES_KEY_LEN>);
        let lut = found
            .next()
            .and_then(Option::as_ref)
            .and_then(exactly::<HASH_LUT_LEN>);

        match (aes, lut) {
            (Some((aes, aes_at)), Some((lut, lut_at))) => Ok(Self {
                aes,
                aes_at,
                lut,
                lut_at,
            }),
            (aes, lut) => Err(Error::UnrecognisedExecutable {
                what: KEYS_NAMED,
                missing: keys_missing(aes.is_some(), lut.is_some()),
                found: u32::from(aes.is_some()).saturating_add(u32::from(lut.is_some())),
                wanted: u32::try_from(KEYS_WANTED).unwrap_or(u32::MAX),
            }),
        }
    }

    /// The AES-256 key.
    #[must_use]
    pub const fn aes_key(&self) -> &[u8; AES_KEY_LEN] {
        &self.aes
    }

    /// Where the AES-256 key sits in the executable it came from.
    #[must_use]
    pub const fn aes_key_offset(&self) -> u64 {
        self.aes_at
    }

    /// The NG hash lookup table.
    #[must_use]
    pub const fn hash_lut(&self) -> &[u8; HASH_LUT_LEN] {
        &self.lut
    }

    /// Where the hash lookup table sits in the executable it came from.
    #[must_use]
    pub const fn hash_lut_offset(&self) -> u64 {
        self.lut_at
    }
}

/// Written by hand so that a key cannot reach a log, a panic message or a
/// `--json` payload by being printed. DR-006 is about what leaves this machine,
/// and a derived `Debug` is one of the ways it would.
impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keys")
            .field("aes_key_offset", &self.aes_at)
            .field("hash_lut_offset", &self.lut_at)
            .finish_non_exhaustive()
    }
}

/// A sighting of exactly `N` bytes, with where it was.
fn exactly<const N: usize>(sighting: &Sighting) -> Option<([u8; N], u64)> {
    let bytes = <[u8; N]>::try_from(sighting.bytes.as_slice()).ok()?;
    Some((bytes, sighting.offset))
}

/// What [`NgKeys`] is looking for.
/// Derived rather than written, so it cannot drift from the two counts it has
/// to equal: a literal here would make `hits` unreachable the moment either
/// count changed, and the failure would read "N of 373" while claiming the
/// executable was at fault.
const NG_WANTED: usize = NG_EXPANDED_KEY_COUNT.saturating_add(NG_DECRYPT_TABLE_COUNT);

/// Names the material in a failure.
const NG_NAMED: &str = "NG expanded keys and decrypt tables";

/// Names the expanded keys where a failure has to say they were short.
const NG_EXPANDED_NAMED: &str = "the expanded keys";

/// Names the decrypt tables, for the same reason.
const NG_TABLES_NAMED: &str = "the decrypt tables";

/// Which kinds [`NgKeys::extract`] is short of, given what each found.
///
/// The kind rather than the value: 373 names is not something a caller acts on,
/// and `found` against `wanted` already says how many are missing.
const fn ng_missing(expanded: bool, tables: bool) -> &'static [&'static str] {
    match (expanded, tables) {
        (false, true) => &[NG_EXPANDED_NAMED],
        (true, false) => &[NG_TABLES_NAMED],
        _ => &[NG_EXPANDED_NAMED, NG_TABLES_NAMED],
    }
}

/// The NG key material: 101 expanded keys and 272 decrypt tables.
///
/// **No game executable carries it, and a memory image of one does.** Measured
/// 2026-08-28 against `GTA5.exe`, `GTA5_Enhanced.exe` and `RDR2.exe` at every
/// byte offset: 0 of 101 and 0 of 272 in each. Measured 2026-08-30 against the
/// mapped image of `GTA5.exe` taken from a dump of the running game: 101 of 101
/// and 272 of 272. On disk the values are present but transformed — the bytes
/// at their addresses are non-zero and of near-uniform entropy — and the
/// unpacking happens at load. DR-040 records the measurement; `docs/ng-scheme.md`
/// records why it took until now to look in the right place.
///
/// Separate from [`Keys`] because it is a separate whole: an archive with the
/// AES tag needs [`Keys`] and none of this, and withholding a key that was
/// found because a table that was never there is missing would be a worse
/// answer than either (`docs/conventions.md` §4).
pub struct NgKeys {
    /// The expanded keys, end to end.
    expanded: Box<[u8]>,
    /// The decrypt tables, end to end.
    tables: Box<[u8]>,
    /// The lowest offset an expanded key was found at.
    expanded_at: u64,
    /// The lowest offset a decrypt table was found at.
    tables_at: u64,
}

impl NgKeys {
    /// Finds the NG key material in a game executable.
    ///
    /// # Errors
    ///
    /// [`Error::UnrecognisedExecutable`] unless every one of the 373 values is
    /// there, naming which kinds are short and how many were found;
    /// [`Error::Io`] if the source cannot be read; [`Error::Cancelled`] if the
    /// watcher said to stop.
    ///
    /// This is the survey DR-017 measures at about a minute over 373 anchors,
    /// so it is the call that actually wants a watcher.
    pub fn extract<S: Read + Seek, W: Watch>(source: &mut S, watch: &mut W) -> Result<Self> {
        let wanted = Self::anchors();
        let found = scan::find(source, &wanted, NG_NAMED, watch)?;
        Self::assembled(&found)
    }

    /// What this material is looked for by, in the order [`NgKeys::assembled`]
    /// reads the answers back: the expanded keys, then the decrypt tables.
    fn anchors() -> Vec<Anchor> {
        let mut wanted = Vec::with_capacity(NG_WANTED);
        for digest in anchors::NG_EXPANDED_KEYS {
            wanted.push(Anchor {
                len: NG_EXPANDED_KEY_LEN,
                digest,
            });
        }
        for digest in anchors::NG_DECRYPT_TABLES {
            wanted.push(Anchor {
                len: NG_DECRYPT_TABLE_LEN,
                digest,
            });
        }
        wanted
    }

    /// The material a completed search found, or what it was short of.
    ///
    /// The one place an `NgKeys` is built from sightings, so [`NgKeys::extract`]
    /// and [`Material::extract`] cannot come to disagree about what a complete
    /// answer is (`docs/conventions.md` §4).
    fn assembled(found: &[Option<Sighting>]) -> Result<Self> {
        let mut expanded =
            Vec::with_capacity(NG_EXPANDED_KEY_COUNT.saturating_mul(NG_EXPANDED_KEY_LEN));
        let mut tables =
            Vec::with_capacity(NG_DECRYPT_TABLE_COUNT.saturating_mul(NG_DECRYPT_TABLE_LEN));
        let mut expanded_at = u64::MAX;
        let mut tables_at = u64::MAX;
        let mut expanded_hits = 0_usize;
        let mut table_hits = 0_usize;

        for (index, sighting) in found.iter().enumerate() {
            let Some(sighting) = sighting else { continue };
            if index < NG_EXPANDED_KEY_COUNT {
                if sighting.bytes.len() != NG_EXPANDED_KEY_LEN {
                    continue;
                }
                expanded_hits = expanded_hits.saturating_add(1);
                expanded.extend_from_slice(&sighting.bytes);
                expanded_at = expanded_at.min(sighting.offset);
            } else {
                if sighting.bytes.len() != NG_DECRYPT_TABLE_LEN {
                    continue;
                }
                table_hits = table_hits.saturating_add(1);
                tables.extend_from_slice(&sighting.bytes);
                tables_at = tables_at.min(sighting.offset);
            }
        }

        let hits = expanded_hits.saturating_add(table_hits);
        if hits != NG_WANTED {
            return Err(Error::UnrecognisedExecutable {
                what: NG_NAMED,
                missing: ng_missing(
                    expanded_hits == NG_EXPANDED_KEY_COUNT,
                    table_hits == NG_DECRYPT_TABLE_COUNT,
                ),
                found: u32::try_from(hits).unwrap_or(u32::MAX),
                wanted: u32::try_from(NG_WANTED).unwrap_or(u32::MAX),
            });
        }
        Ok(Self {
            expanded: expanded.into_boxed_slice(),
            tables: tables.into_boxed_slice(),
            expanded_at,
            tables_at,
        })
    }

    /// The material as the cache read it back, with where it was first found.
    ///
    /// The lengths are the ones this type promises, so a payload of any other
    /// length is not `NgKeys` and there is nothing to hand back.
    pub(super) fn restored(
        expanded: Vec<u8>,
        tables: Vec<u8>,
        expanded_at: u64,
        tables_at: u64,
    ) -> Option<Self> {
        if expanded.len() != NG_EXPANDED_KEY_COUNT.saturating_mul(NG_EXPANDED_KEY_LEN)
            || tables.len() != NG_DECRYPT_TABLE_COUNT.saturating_mul(NG_DECRYPT_TABLE_LEN)
        {
            return None;
        }
        Some(Self {
            expanded: expanded.into_boxed_slice(),
            tables: tables.into_boxed_slice(),
            expanded_at,
            tables_at,
        })
    }

    /// The expanded keys end to end, for the cache to write.
    pub(super) const fn expanded_bytes(&self) -> &[u8] {
        &self.expanded
    }

    /// The decrypt tables end to end, for the cache to write.
    pub(super) const fn table_bytes(&self) -> &[u8] {
        &self.tables
    }

    /// Where the expanded keys start in the source they came from.
    #[must_use]
    pub const fn expanded_keys_offset(&self) -> u64 {
        self.expanded_at
    }

    /// Where the decrypt tables start in the source they came from.
    #[must_use]
    pub const fn decrypt_tables_offset(&self) -> u64 {
        self.tables_at
    }

    /// One expanded key, or `None` if there is no such index.
    #[must_use]
    pub fn expanded_key(&self, index: usize) -> Option<&[u8]> {
        let start = index.checked_mul(NG_EXPANDED_KEY_LEN)?;
        self.expanded
            .get(start..start.checked_add(NG_EXPANDED_KEY_LEN)?)
    }

    /// One decrypt table, or `None` if there is no such round or column.
    ///
    /// Indexed `column + NG_COLUMNS * round`, which is the order the reference
    /// implementation named in the `anchors` module fills them in.
    #[must_use]
    pub fn decrypt_table(&self, round: usize, column: usize) -> Option<&[u8]> {
        if round >= NG_ROUNDS || column >= NG_COLUMNS {
            return None;
        }
        let index = round.checked_mul(NG_COLUMNS)?.checked_add(column)?;
        let start = index.checked_mul(NG_DECRYPT_TABLE_LEN)?;
        self.tables
            .get(start..start.checked_add(NG_DECRYPT_TABLE_LEN)?)
    }
}

/// By hand, for the reason [`Keys`]'s is.
impl fmt::Debug for NgKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NgKeys")
            .field("expanded_keys", &NG_EXPANDED_KEY_COUNT)
            .field("expanded_keys_offset", &self.expanded_at)
            .field("decrypt_tables", &NG_DECRYPT_TABLE_COUNT)
            .field("decrypt_tables_offset", &self.tables_at)
            .finish_non_exhaustive()
    }
}

/// How many values [`LauncherKey`] is made of, for the reason [`KEYS_WANTED`]
/// is a constant: it is the length of [`LauncherKey::anchors`], and it is what
/// one pass's answers are split by.
const LAUNCHER_WANTED: usize = 1;

/// The Rockstar Games Launcher's own AES-256 key.
///
/// A second key, not a second cipher: an archive tagged `0x0FFFFFF7` is under
/// exactly the transform `0x0FFFFFF9` names, keyed by this instead of by the
/// RAGE key ([`crate::format::crypto::Scheme`]). `docs/rpf-format.md`,
/// Encryption.
///
/// Optional on [`Material`] rather than a third value in [`Keys`], because
/// **only the launcher's own executable carries it**. `Keys` is whole or not at
/// all on the argument that a caller given one of its two values has nothing it
/// can finish, and that argument does not reach a value most sources do not
/// have at all: it would turn every game executable into an unrecognised one.
/// [`NgKeys`] is the same shape for the same reason. DR-042.
pub struct LauncherKey {
    /// The key.
    key: [u8; AES_KEY_LEN],
    /// Where it was found in the source.
    at: u64,
}

impl LauncherKey {
    /// What this value is looked for by.
    const fn anchors() -> [Anchor; LAUNCHER_WANTED] {
        [Anchor {
            len: AES_KEY_LEN,
            digest: anchors::LAUNCHER_AES_KEY,
        }]
    }

    /// The value a completed search found, or `None` where the source has none.
    ///
    /// An absence is not a failure and cannot be one: a game executable carries
    /// the RAGE key and not this, and refusing its material because a value
    /// that was never there is missing would withhold the key that opens 43
    /// archives in order to report the absence of one that opens two.
    fn assembled(found: &[Option<Sighting>]) -> Option<Self> {
        let (key, at) = found
            .first()
            .and_then(Option::as_ref)
            .and_then(exactly::<AES_KEY_LEN>)?;
        Some(Self { key, at })
    }

    /// The value as the cache read it back, with where it was first found.
    pub(super) const fn restored(key: [u8; AES_KEY_LEN], at: u64) -> Self {
        Self { key, at }
    }

    /// The key itself.
    #[must_use]
    pub const fn key(&self) -> &[u8; AES_KEY_LEN] {
        &self.key
    }

    /// Where it sits in the source it came from.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.at
    }
}

/// By hand, for the reason [`Keys`]'s is.
impl fmt::Debug for LauncherKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LauncherKey")
            .field("offset", &self.at)
            .finish_non_exhaustive()
    }
}

/// Names the whole survey for a watcher, which is what one pass now looks for.
const MATERIAL_NAMED: &str = "key material";

/// Everything one source carries.
///
/// [`Keys`] is required and [`NgKeys`] and [`LauncherKey`] are not, and that
/// asymmetry is the measurement rather than a preference: a game executable
/// carries the first and neither of the others, a memory image of that same
/// executable carries the NG material too, and only the Rockstar Games
/// Launcher's own executable carries the launcher key. A source holding none of
/// it is [`Error::UnrecognisedExecutable`]; a source holding only the first is
/// the ordinary case and is not a failure, because an archive with the AES tag
/// needs nothing else. DR-040, DR-042.
///
/// This is one pass over the source for all 376 values rather than three passes
/// for two, one and 373. The values are found by hashing windows and the
/// windows are the expensive part, so looking for everything at once costs what
/// looking for the largest group alone would.
#[derive(Debug)]
pub struct Material {
    /// The AES key and hash lookup table, which every source must carry.
    keys: Keys,
    /// The NG material, where the source carries it.
    ng: Option<Arc<NgKeys>>,
    /// The launcher's own AES key, where the source carries it.
    launcher: Option<LauncherKey>,
}

impl Material {
    /// Finds everything a source carries.
    ///
    /// The source is read from its start to its end, or until everything has
    /// been found. It is not required to be an executable, or a file of any
    /// particular shape: the search is over the bytes.
    ///
    /// # Errors
    ///
    /// [`Error::UnrecognisedExecutable`] if the AES key or the hash lookup
    /// table is missing, naming which; [`Error::Io`] if the source cannot be
    /// read; [`Error::Cancelled`] if the watcher said to stop.
    pub fn extract<S: Read + Seek, W: Watch>(source: &mut S, watch: &mut W) -> Result<Self> {
        let mut wanted = Vec::with_capacity(
            KEYS_WANTED
                .saturating_add(LAUNCHER_WANTED)
                .saturating_add(NG_WANTED),
        );
        wanted.extend_from_slice(&Keys::anchors());
        wanted.extend_from_slice(&LauncherKey::anchors());
        wanted.append(&mut NgKeys::anchors());

        let found = scan::find(source, &wanted, MATERIAL_NAMED, watch)?;
        // Read back in the order the anchors were asked for, so a slot is read
        // by the value that asked for it (§4).
        let (base, rest) = found.split_at(found.len().min(KEYS_WANTED));
        let (launcher, ng) = rest.split_at(rest.len().min(LAUNCHER_WANTED));

        Ok(Self {
            keys: Keys::assembled(base)?,
            ng: NgKeys::assembled(ng).ok().map(Arc::new),
            launcher: LauncherKey::assembled(launcher),
        })
    }

    /// Material whose every value is zero bytes.
    ///
    /// The counterpart of `crate::format::crypto::Cipher::over_zeros`, one
    /// level up: it makes an AES-tagged archive **writable and readable in the
    /// crate's own tests** with no game installation and no key material of any
    /// kind (DR-006). It carries no NG half, so nothing NG-tagged opens under
    /// it, which is the arm those tests are about.
    ///
    /// `#[cfg(test)]`, so it is in no release build and in nothing a dependent
    /// compiles — the same confinement DR-048 puts on the fuzz seam.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn over_zeros() -> Self {
        Self::restored(
            Keys {
                aes: [0; AES_KEY_LEN],
                aes_at: 0,
                lut: [0; HASH_LUT_LEN],
                lut_at: 0,
            },
            None,
            None,
        )
    }

    /// The material as the cache read it back.
    pub(super) fn restored(keys: Keys, ng: Option<NgKeys>, launcher: Option<LauncherKey>) -> Self {
        Self {
            keys,
            ng: ng.map(Arc::new),
            launcher,
        }
    }

    /// The AES key and hash lookup table.
    #[must_use]
    pub const fn keys(&self) -> &Keys {
        &self.keys
    }

    /// The NG expanded keys and decrypt tables, where the source carried them.
    #[must_use]
    pub fn ng(&self) -> Option<&NgKeys> {
        self.ng.as_deref()
    }

    /// The launcher's own AES key, where the source carried it.
    ///
    /// `None` for every game executable and for a memory image of one: it is in
    /// `Launcher.exe` and in nothing else measured here. DR-042.
    #[must_use]
    pub const fn launcher(&self) -> Option<&LauncherKey> {
        self.launcher.as_ref()
    }

    /// The same, as the handle a [`crate::format::crypto::Cipher`] keeps.
    ///
    /// Shared rather than borrowed because the tables are 278 KB and every
    /// encrypted entry of every archive makes a cipher over the same ones.
    pub(crate) const fn ng_shared(&self) -> Option<&Arc<NgKeys>> {
        self.ng.as_ref()
    }
}

/// The one seam a fuzz target opens, and the whole of it. DR-048.
#[cfg(fuzzing)]
impl Material {
    /// Material made of bytes the caller already holds.
    ///
    /// **Not a way to obtain key material — a way to supply it.** Every value
    /// here comes from the caller, nothing is searched for, and no anchor is
    /// consulted, so this reaches none of `keys::anchors` and answers nothing
    /// about a real installation. The fuzz targets pass fill bytes and a
    /// synthetic table network; DR-006 is about what this repository carries
    /// and about where a real key comes from, and neither is touched.
    ///
    /// It is `#[cfg(fuzzing)]` rather than a feature so that it cannot be
    /// switched on: a feature is a name a dependent can write in its own
    /// manifest, and this is set by `cargo-fuzz` on the whole build or by
    /// nobody. It is absent from every release build, from `cargo doc`, and
    /// from the crate a dependent compiles.
    ///
    /// Why it exists at all, and why the direction it opens is the harmless
    /// one when [`Keys::aes_key`] and [`NgKeys::decrypt_table`] are already
    /// unconditionally public: DR-048.
    ///
    /// `None` when `ng` is given and its two halves are not the lengths
    /// [`NgKeys`] promises — the same check the cache's reader makes, because
    /// it is the same constructor (§4).
    #[must_use]
    pub fn over_bytes(
        aes: [u8; AES_KEY_LEN],
        lut: [u8; HASH_LUT_LEN],
        ng: Option<(Vec<u8>, Vec<u8>)>,
        launcher: Option<[u8; AES_KEY_LEN]>,
    ) -> Option<Self> {
        // The offsets a real search would have reported. Nothing reads them
        // but `Debug`, which prints them precisely because they are not key
        // material (DR-020).
        const NOWHERE: u64 = 0;

        let ng = match ng {
            None => None,
            Some((expanded, tables)) => Some(NgKeys::restored(expanded, tables, NOWHERE, NOWHERE)?),
        };
        Some(Self::restored(
            Keys {
                aes,
                aes_at: NOWHERE,
                lut,
                lut_at: NOWHERE,
            },
            ng,
            launcher.map(|key| LauncherKey::restored(key, NOWHERE)),
        ))
    }
}

/// What an archive is opened with, and the name its key is derived from.
///
/// Three states and no fourth: nothing, one material the caller already has, or
/// a cache **read only if the archive turns out to need it** — so an
/// unencrypted archive never reaches a configuration directory (R2.6, and
/// `crates/rpf-core/tests/no_keys.rs` is what says so).
///
/// The name is the archive's own file name, which is what an NG archive's key
/// is a function of (`docs/rpf-format.md`, Encryption). There is deliberately
/// no `Default`: [`Unlock::unkeyed`] is a claim about the caller's environment
/// and a default would let it be picked up silently.
///
/// Why each of those, rather than the alternatives: DR-041.
#[derive(Debug, Clone)]
pub struct Unlock {
    /// Where material comes from, if it comes from anywhere.
    source: Source,
    /// The name the archive's own key is derived from.
    name: String,
}

/// Where an [`Unlock`]'s material comes from.
#[derive(Debug, Clone)]
enum Source {
    /// Nowhere. An encrypted archive is [`Error::NeedsKey`].
    Unkeyed,
    /// This, already extracted.
    Held(Arc<Material>),
    /// Whatever this cache holds, read on demand.
    Cached(Cache),
}

impl Unlock {
    /// No key material at all.
    ///
    /// Every unencrypted path is exactly what it was, and an encrypted archive
    /// is [`Error::NeedsKey`].
    #[must_use]
    pub const fn unkeyed() -> Self {
        Self {
            source: Source::Unkeyed,
            name: String::new(),
        }
    }

    /// This material, for an archive addressed by this name.
    ///
    /// An [`Arc`] rather than the material itself, and the sharing is explicit
    /// on purpose: the NG half is 305 KB, an archive holds it for as long as it
    /// is open, and every archive nested inside it holds the same one. A
    /// signature that took it by value would copy it per archive and hide that
    /// it had.
    #[must_use]
    pub fn held(material: Arc<Material>, name: impl Into<String>) -> Self {
        Self {
            source: Source::Held(material),
            name: name.into(),
        }
    }

    /// Whatever this cache holds, for an archive addressed by this name.
    ///
    /// The cache is not read here and is not read at all unless an archive
    /// refuses to open without it.
    #[must_use]
    pub fn cached(cache: Cache, name: impl Into<String>) -> Self {
        Self {
            source: Source::Cached(cache),
            name: name.into(),
        }
    }

    /// The name the archive's own key is derived from.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether any material could come out of this.
    ///
    /// Distinguishes "no material is available" from "material is available and
    /// did not open it", which name different things to do about them
    /// (DR-010, DR-041).
    #[must_use]
    pub const fn is_unkeyed(&self) -> bool {
        matches!(self.source, Source::Unkeyed)
    }

    /// The same material, for an archive of another name.
    ///
    /// What a nested archive is opened with: same source, its own name.
    #[must_use]
    pub fn renamed(&self, name: &str) -> Self {
        Self {
            source: self.source.clone(),
            name: name.to_owned(),
        }
    }

    /// The material already in hand, where there is any.
    ///
    /// `Some` for an [`Unlock`] built by [`Unlock::held`] or normalised by
    /// [`Unlock::resolved`] — which is every archive that actually opened under
    /// a key.
    #[must_use]
    pub(crate) const fn held_material(&self) -> Option<&Arc<Material>> {
        match self.source {
            Source::Held(ref material) => Some(material),
            Source::Unkeyed | Source::Cached(_) => None,
        }
    }

    /// This, with whatever it resolved to already in hand.
    ///
    /// An archive that consulted a cache keeps the material it found rather
    /// than the cache it found it in, so reading one of its entries is not a
    /// second pass over the configuration directory.
    #[must_use]
    pub(crate) fn resolved(&self, material: &Arc<Material>) -> Self {
        Self {
            source: Source::Held(Arc::clone(material)),
            name: self.name.clone(),
        }
    }

    /// Every material that could open an archive under `scheme`, in the order
    /// they are to be tried.
    ///
    /// Material that does not carry what the transform needs is not a
    /// candidate: an executable's material has the AES key and none of the NG
    /// values (DR-040), so it is tried for an AES archive and not for an NG
    /// one. An empty answer is "no material is available", which is
    /// [`Error::NeedsKey`] and not a failure of this call.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if a cache directory exists and cannot be read.
    pub(crate) fn candidates(&self, scheme: Scheme) -> Result<Vec<Arc<Material>>> {
        Ok(match self.source {
            Source::Unkeyed => Vec::new(),
            Source::Held(ref material) => {
                if scheme.is_in(material) {
                    vec![Arc::clone(material)]
                } else {
                    Vec::new()
                }
            }
            Source::Cached(ref cache) => cache
                .materials()?
                .into_iter()
                .filter(|material| scheme.is_in(material))
                .map(Arc::new)
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        AES_KEY_LEN, AES_KEY_NAMED, Error, HASH_LUT_LEN, HASH_LUT_NAMED, Keys, LauncherKey,
        Material, NG_DECRYPT_TABLE_COUNT, NG_DECRYPT_TABLE_LEN, NG_EXPANDED_KEY_COUNT,
        NG_EXPANDED_KEY_LEN, NG_EXPANDED_NAMED, NG_TABLES_NAMED, NG_WANTED, NgKeys, Sighting,
        Unlock, anchors, keys_missing, ng_missing,
    };
    use crate::format::crypto::{AesKey, Cipher, Scheme};

    /// A sighting of `len` bytes of `fill`, found at `offset`.
    ///
    /// Not key material and nothing like it: a byte pattern, which is all the
    /// assembly below has to get right. DR-006 keeps the real values out of
    /// this repository, and until this file had these, **every fact about how a
    /// completed search is read back was defensible only on a machine with a
    /// game installed on it** — the search itself is tested here, and what it
    /// answers was assembled nowhere.
    fn seen(len: usize, fill: u8, offset: u64) -> Sighting {
        Sighting {
            offset,
            bytes: vec![fill; len],
        }
    }

    /// The answers a complete [`Keys`] search returns, in the order
    /// `Keys::anchors` asked for them: the AES key, then the hash lookup table.
    fn keys_found() -> Vec<Option<Sighting>> {
        vec![
            Some(seen(AES_KEY_LEN, 0x11, 0x1234_5678)),
            Some(seen(HASH_LUT_LEN, 0x22, 0x00AB_CDEF)),
        ]
    }

    /// The answers a complete [`NgKeys`] search returns: 101 expanded keys and
    /// then 272 decrypt tables, each with an offset of its own so that the
    /// lowest can be told from the first.
    fn ng_found() -> Vec<Option<Sighting>> {
        let mut found = Vec::with_capacity(NG_WANTED);
        for index in 0..NG_EXPANDED_KEY_COUNT {
            let at = 0x1_0000_u64.saturating_add(u64::try_from(index).unwrap_or(0));
            found.push(Some(seen(NG_EXPANDED_KEY_LEN, 0x33, at)));
        }
        for index in 0..NG_DECRYPT_TABLE_COUNT {
            let at = 0x2_0000_u64.saturating_add(u64::try_from(index).unwrap_or(0));
            found.push(Some(seen(NG_DECRYPT_TABLE_LEN, 0x44, at)));
        }
        found
    }

    /// Material of the shape every game executable produces: the two values
    /// and neither optional half.
    fn plain_material(aes: u8) -> Material {
        let found = vec![
            Some(seen(AES_KEY_LEN, aes, 0x1234_5678)),
            Some(seen(HASH_LUT_LEN, 0x22, 0x00AB_CDEF)),
        ];
        Material::restored(
            Keys::assembled(&found).expect("both were found"),
            None,
            None,
        )
    }

    /// The shape only a memory image produces.
    fn ng_material() -> Material {
        Material::restored(
            Keys::assembled(&keys_found()).expect("both were found"),
            Some(NgKeys::assembled(&ng_found()).expect("everything was found")),
            None,
        )
    }

    /// The shape only `Launcher.exe` produces.
    fn launcher_material() -> Material {
        Material::restored(
            Keys::assembled(&keys_found()).expect("both were found"),
            None,
            Some(LauncherKey::restored([0x55; AES_KEY_LEN], 0x005E_E3F0)),
        )
    }

    /// The smallest whole encrypted archive: a header carrying `tag`, one entry
    /// row, and no names blob.
    ///
    /// Whole on purpose. A header alone is refused for **not fitting** before a
    /// key is ever judged, which would test the bounds check rather than the
    /// key check; with the row present the layout is legal and the only thing
    /// left to be wrong about is the key.
    fn encrypted_archive(tag: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        out.extend_from_slice(b"7FPR");
        out.extend_from_slice(&1_u32.to_le_bytes());
        out.extend_from_slice(&0_u32.to_le_bytes());
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&[0_u8; 16]);
        out
    }

    #[test]
    fn material_that_does_not_open_an_archive_says_so_rather_than_asking_for_a_key() {
        // DR-041's distinction, and the reason `Error::WrongKey` exists beside
        // `Error::NeedsKey`: the two name different things to do. `NeedsKey` is
        // answered by going and extracting key material; `WrongKey` cannot be,
        // because the material in hand *is* the material and the archive was
        // renamed, or belongs to another install. Telling an automation to
        // extract a key it already has is a loop it never leaves.
        //
        // What decides it is `is_root_directory`: entry 0 is always the root
        // directory (`docs/rpf-format.md`, Layout, `verified`), and the marker
        // that says so is a whole word no file entry can produce — so a wrong
        // key answers `false` with the odds of a 32-bit coincidence. Forced to
        // `true`, **every key is the right key** and a table of contents is
        // read out of noise.
        //
        // Until now that could only be exercised where a real game install
        // is: `Unlock::held` needs a `Material`, and DR-006 keeps the values
        // out of the repository, so no synthetic source produces one. It needs
        // no source — `Keys::assembled` takes a completed search's answers, and
        // a pattern of bytes is a complete answer. The key below is wrong for
        // this archive because every key is: the payload is sixteen bytes of
        // header and there is nothing it could correctly decrypt to.
        //
        // The test lives here rather than beside `Verified` because this is
        // the only module that can build a `Material` at all.
        const AES_TAG: u32 = 0x0FFF_FFF9;

        let inner = encrypted_archive(AES_TAG);
        let mut out = std::io::Cursor::new(Vec::new());
        crate::build(
            &mut out,
            crate::format::Version::Rpf7,
            &[crate::FileSpec {
                path: "inner.rpf".to_owned(),
                kind: crate::FileKind::Binary {
                    storage: crate::Storage::Stored,
                    encryption: 0,
                },
            }],
            &[],
            |_: &str| Ok(std::io::Cursor::new(inner.clone())),
            &mut crate::Unwatched,
        )
        .expect("the outer archive is plain and builds with no key material");

        let mut src = std::io::Cursor::new(out.into_inner());
        let unlock = Unlock::held(Arc::new(plain_material(0x11)), "outer.rpf");
        let archive = crate::Archive::open(&mut src, &unlock).expect("the outer archive is plain");

        // The walk descends, tries the material it was given, and reports that
        // it did not open the archive — not that there was none to try.
        let verified = crate::Verified::of(&mut src, &archive, &mut crate::Unwatched)
            .expect("the walk itself does not fail");
        let refused = verified
            .outcome()
            .expect_err("an archive the material does not open did not read back whole");
        match refused {
            Error::WrongKey { tag, scheme, tried } => {
                assert_eq!(tag, AES_TAG);
                assert_eq!(
                    scheme, "AES-256",
                    "the caller is told which key to go and get"
                );
                assert_eq!(tried, 1, "one source was available and one was tried");
            }
            other => panic!("expected the key to be reported wrong, got {other:?}"),
        }
        assert_eq!(refused.category(), crate::Category::NeedsKey);
    }

    #[test]
    fn a_transform_is_offered_only_the_material_that_carries_what_it_needs() {
        // DR-040 and DR-042 as an assertion rather than as a paragraph: an
        // executable's material opens an AES archive under the RAGE key and
        // neither of the others, a memory image adds the NG half, and only the
        // launcher's own executable carries the launcher key.
        //
        // Every source carries the RAGE key, so `Scheme::Aes(Rage)` is the one
        // arm that is true of all three — which is what makes a blanket `true`
        // and a blanket `false` both wrong here, and neither was before.
        for (which, material, ng, launcher) in [
            ("an executable", plain_material(0x11), false, false),
            ("a memory image", ng_material(), true, false),
            ("the launcher", launcher_material(), false, true),
        ] {
            assert!(
                Scheme::Aes(AesKey::Rage).is_in(&material),
                "{which} does not carry the RAGE key"
            );
            assert_eq!(Scheme::Ng.is_in(&material), ng, "{which}: NG");
            assert_eq!(
                Scheme::Aes(AesKey::Launcher).is_in(&material),
                launcher,
                "{which}: the launcher key"
            );
        }
    }

    #[test]
    fn a_cipher_is_keyed_by_the_material_it_was_made_from() {
        // `AesKey::of` picks which of a material's keys runs the transform, and
        // nothing asked what it picked: a version that answered a fixed
        // thirty-two bytes for every material decrypts every archive the same
        // wrong way, which is a payload that inflates to nonsense rather than a
        // refusal. Two materials differing only in that key have to disagree.
        let block = [0x5A_u8; 16];
        let mut one = block;
        let mut other = block;
        Cipher::new(
            Scheme::Aes(AesKey::Rage),
            &plain_material(0x11),
            "a.rpf",
            16,
        )
        .expect("every source carries the RAGE key")
        .apply(&mut one);
        Cipher::new(
            Scheme::Aes(AesKey::Rage),
            &plain_material(0x77),
            "a.rpf",
            16,
        )
        .expect("every source carries the RAGE key")
        .apply(&mut other);
        assert_ne!(one, other, "the key the material carries did not reach it");
        assert_ne!(one, block, "the block was not transformed at all");

        // And a transform whose key the material does not carry has no cipher,
        // rather than one over whatever was to hand.
        assert!(
            Cipher::new(
                Scheme::Aes(AesKey::Launcher),
                &plain_material(0x11),
                "a.rpf",
                16
            )
            .is_none(),
            "a launcher cipher was made from material with no launcher key"
        );
        assert!(
            Cipher::new(Scheme::Ng, &plain_material(0x11), "a.rpf", 16).is_none(),
            "an NG cipher was made from material with no NG half"
        );
    }

    #[test]
    fn an_ng_cipher_chooses_a_key_and_an_aes_one_has_none_to_choose() {
        // The index is a function of the name and the length
        // (`docs/rpf-format.md`, Encryption), so two lengths choose two keys.
        // A `key_index` fixed at one value, or absent, says the same thing
        // about every payload in the archive.
        let material = ng_material();
        let first = Cipher::new(Scheme::Ng, &material, "dlc.rpf", 6_144)
            .expect("the material carries the NG half");
        let second = Cipher::new(Scheme::Ng, &material, "dlc.rpf", 6_145)
            .expect("the material carries the NG half");
        assert!(first.key_index().is_some());
        assert_ne!(
            first.key_index(),
            second.key_index(),
            "the length did not reach the key"
        );

        assert_eq!(
            Cipher::new(Scheme::Aes(AesKey::Rage), &material, "dlc.rpf", 6_144)
                .expect("every source carries the RAGE key")
                .key_index(),
            None,
            "an AES cipher chose one of the NG keys"
        );
    }

    #[test]
    fn material_in_hand_is_a_candidate_for_what_it_carries_and_nothing_else() {
        // `Unlock::candidates` is what an archive asks before it believes a
        // byte of its own layout, and an empty answer is `NeedsKey`. Answering
        // empty for material that does open the archive turns a readable
        // archive into one the caller is told to go and find a key for.
        let unlock = Unlock::held(Arc::new(ng_material()), "dlc.rpf");
        assert!(!unlock.is_unkeyed());
        assert_eq!(unlock.name(), "dlc.rpf");
        assert!(unlock.held_material().is_some(), "the material is not held");

        for (scheme, expected) in [
            (Scheme::Aes(AesKey::Rage), 1),
            (Scheme::Ng, 1),
            (Scheme::Aes(AesKey::Launcher), 0),
        ] {
            assert_eq!(
                unlock
                    .candidates(scheme)
                    .expect("held material cannot fail to be read")
                    .len(),
                expected,
                "{scheme:?}"
            );
        }

        // A nested archive keeps the material and takes its own name, which is
        // what its key is chosen by.
        let nested = unlock.renamed("vehicles.rpf");
        assert_eq!(nested.name(), "vehicles.rpf");
        assert!(nested.held_material().is_some());
    }

    #[test]
    fn a_value_a_source_does_not_carry_is_an_absence_and_not_a_failure() {
        // `LauncherKey::assembled` answers `None` for a source with no launcher
        // key, and that is the ordinary case rather than an error — refusing
        // the material would withhold the RAGE key that opens 43 archives in
        // order to report the absence of one that opens two (DR-042). What was
        // untested is the other arm: a source that *does* carry it.
        let key = LauncherKey::assembled(&[Some(seen(AES_KEY_LEN, 0x55, 0x005E_E3F0))])
            .expect("a sighting of the right length is the value");
        assert_eq!(key.key(), &[0x55; AES_KEY_LEN]);
        assert_eq!(key.offset(), 0x005E_E3F0);

        assert!(LauncherKey::assembled(&[None]).is_none(), "nothing found");
        assert!(
            LauncherKey::assembled(&[Some(seen(AES_KEY_LEN.saturating_add(1), 0x55, 0))]).is_none(),
            "a sighting of the wrong length is not the value"
        );
    }

    #[test]
    fn material_restored_from_a_cache_must_be_the_lengths_it_promises() {
        // `NgKeys::restored` is the cache's way back in, and it is the only
        // place a length is taken on trust from a file on disk. Both halves
        // have to be right: a check that accepted either one being wrong would
        // hand `expanded_key` and `decrypt_table` a buffer they slice blindly.
        let expanded = vec![0x33; NG_EXPANDED_KEY_COUNT.saturating_mul(NG_EXPANDED_KEY_LEN)];
        let tables = vec![0x44; NG_DECRYPT_TABLE_COUNT.saturating_mul(NG_DECRYPT_TABLE_LEN)];
        assert!(NgKeys::restored(expanded.clone(), tables.clone(), 0, 0).is_some());

        let mut short = expanded.clone();
        short.pop();
        assert!(
            NgKeys::restored(short, tables.clone(), 0, 0).is_none(),
            "expanded keys one byte short were accepted"
        );

        let mut short = tables;
        short.pop();
        assert!(
            NgKeys::restored(expanded, short, 0, 0).is_none(),
            "decrypt tables one byte short were accepted"
        );
    }

    #[test]
    fn a_complete_search_is_read_back_in_the_order_it_was_asked_for() {
        // `Keys::anchors` asks for the AES key and then the hash lookup table,
        // and `assembled` reads the answers back in that order. The two are 32
        // and 256 bytes, so a swap is not a type error — it is the wrong key
        // handed to the cipher, silently.
        let keys = Keys::assembled(&keys_found()).expect("both were found");
        assert_eq!(keys.aes_key(), &[0x11; AES_KEY_LEN]);
        assert_eq!(keys.hash_lut(), &[0x22; HASH_LUT_LEN]);
        assert_eq!(keys.aes_key_offset(), 0x1234_5678);
        assert_eq!(keys.hash_lut_offset(), 0x00AB_CDEF);
    }

    #[test]
    fn a_sighting_of_the_wrong_length_is_not_the_value_it_was_looked_for() {
        // A digest collision is not the worry; a slot filled from an anchor of
        // another length is. `exactly` is what refuses it, and refusing it is
        // the difference between a missing key and a wrong one.
        for (which, found) in [
            (
                "the aes key",
                vec![
                    Some(seen(AES_KEY_LEN.saturating_sub(1), 0x11, 0)),
                    Some(seen(HASH_LUT_LEN, 0x22, 0)),
                ],
            ),
            (
                "the hash lookup table",
                vec![
                    Some(seen(AES_KEY_LEN, 0x11, 0)),
                    Some(seen(HASH_LUT_LEN.saturating_add(1), 0x22, 0)),
                ],
            ),
        ] {
            match Keys::assembled(&found) {
                Err(Error::UnrecognisedExecutable { found, wanted, .. }) => {
                    assert_eq!(wanted, 2, "{which}");
                    assert_eq!(found, 1, "{which}: the other one was found");
                }
                other => panic!("{which}: expected a short search, got {other:?}"),
            }
        }
    }

    #[test]
    fn nothing_a_key_prints_is_a_key() {
        // DR-006 is about what leaves this machine, and a derived `Debug` is
        // one of the ways it would. Asserted here rather than only in
        // `tests/keys.rs`, which needs a game executable: a fact this project
        // can defend anywhere is worth more than the same fact on one machine.
        let keys = Keys::assembled(&keys_found()).expect("both were found");
        let rendered = format!("{keys:?}");
        // The patterns are `0x11` and `0x22`, which `Debug` renders as decimal.
        assert!(rendered.contains("aes_key_offset"), "{rendered}");
        assert!(
            !rendered.contains("17, 17"),
            "a key was printed: {rendered}"
        );
        assert!(
            !rendered.contains("34, 34"),
            "a table was printed: {rendered}"
        );

        let ng = NgKeys::assembled(&ng_found()).expect("everything was found");
        let rendered = format!("{ng:?}");
        assert!(rendered.contains("expanded_keys"), "{rendered}");
        assert!(
            !rendered.contains("51, 51"),
            "a key was printed: {rendered}"
        );
        assert!(
            !rendered.contains("68, 68"),
            "a table was printed: {rendered}"
        );

        let launcher = LauncherKey::restored([0x55; AES_KEY_LEN], 0x5EE3);
        let rendered = format!("{launcher:?}");
        assert!(rendered.contains("offset"), "{rendered}");
        assert!(
            !rendered.contains("85, 85"),
            "a key was printed: {rendered}"
        );
    }

    #[test]
    fn the_expanded_keys_end_where_the_decrypt_tables_begin() {
        // The one boundary in the NG survey: slots below
        // `NG_EXPANDED_KEY_COUNT` are expanded keys and the rest are decrypt
        // tables. Moving it by one takes the first table for the hundred and
        // second key — and because the two lengths differ, the slot is then
        // dropped for being the wrong length rather than refused, so the
        // failure is "one short" and never "the wrong thing".
        let ng = NgKeys::assembled(&ng_found()).expect("everything was found");
        assert_eq!(
            ng.expanded_key(NG_EXPANDED_KEY_COUNT.saturating_sub(1)),
            Some([0x33; NG_EXPANDED_KEY_LEN].as_slice()),
            "the last expanded key is an expanded key"
        );
        assert_eq!(
            ng.expanded_key(NG_EXPANDED_KEY_COUNT),
            None,
            "there is no key past the last one"
        );
        assert_eq!(
            ng.decrypt_table(0, 0),
            Some([0x44; NG_DECRYPT_TABLE_LEN].as_slice()),
            "the first table is a table"
        );
        assert_eq!(
            ng.expanded_keys_offset(),
            0x1_0000,
            "the lowest offset an expanded key was found at"
        );
        assert_eq!(
            ng.decrypt_tables_offset(),
            0x2_0000,
            "the lowest offset a decrypt table was found at"
        );
    }

    #[test]
    fn a_table_past_the_rounds_or_the_columns_is_no_table() {
        // `ng_round` asks for a table per round and column and drops the term
        // when there is none, so a bound that let an index through would be a
        // block handed back one word short of its transform rather than a
        // refusal.
        //
        // **The column half is the load-bearing one.** Round and column are
        // folded into one index, so a column past the sixteenth is the *next
        // round's* table and is a table that exists — which the slice bound
        // below cannot notice and this assertion can. The round half is
        // belt-and-braces: `round >= NG_ROUNDS` answers `None` with or without
        // the check, because the index it computes is past the end of the
        // tables and the slice refuses it. Stated so the next sweep does not
        // re-litigate a survivor there.
        let ng = NgKeys::assembled(&ng_found()).expect("everything was found");
        assert!(
            ng.decrypt_table(super::NG_ROUNDS.saturating_sub(1), 15)
                .is_some()
        );
        assert!(
            ng.decrypt_table(super::NG_ROUNDS, 0).is_none(),
            "past the rounds"
        );
        assert!(
            ng.decrypt_table(0, super::NG_COLUMNS).is_none(),
            "a column past the sixteenth is the next round's table"
        );
    }

    #[test]
    fn ng_anchors_names_every_expanded_key_then_every_decrypt_table() {
        // `NgKeys::assembled` is tested above against a hand-built `found`, so
        // nothing else here calls through `NgKeys::anchors` to `find` — this is
        // its only exercise. The order is the contract `assembled` reads back
        // by: expanded keys first, decrypt tables after.
        let wanted = NgKeys::anchors();
        assert_eq!(wanted.len(), NG_WANTED);

        let (expanded, tables) = wanted.split_at(NG_EXPANDED_KEY_COUNT);
        assert_eq!(expanded.len(), NG_EXPANDED_KEY_COUNT);
        assert_eq!(tables.len(), NG_DECRYPT_TABLE_COUNT);

        for (anchor, digest) in expanded.iter().zip(anchors::NG_EXPANDED_KEYS) {
            assert_eq!(anchor.len, NG_EXPANDED_KEY_LEN);
            assert_eq!(anchor.digest, digest);
        }
        for (anchor, digest) in tables.iter().zip(anchors::NG_DECRYPT_TABLES) {
            assert_eq!(anchor.len, NG_DECRYPT_TABLE_LEN);
            assert_eq!(anchor.digest, digest);
        }
    }

    #[test]
    fn a_survey_one_value_short_names_the_kind_it_was_short_of() {
        // The count is what a caller acts on, and it used to be derivable two
        // ways that could disagree. One missing expanded key and one missing
        // table, separately, so neither can pass for the other.
        let mut found = ng_found();
        found[0] = None;
        match NgKeys::assembled(&found) {
            Err(Error::UnrecognisedExecutable {
                missing,
                found,
                wanted,
                ..
            }) => {
                assert_eq!(missing, [NG_EXPANDED_NAMED]);
                assert_eq!(wanted, 373);
                assert_eq!(found, 372);
            }
            other => panic!("expected one expanded key short, got {other:?}"),
        }

        let mut found = ng_found();
        found[NG_EXPANDED_KEY_COUNT] = None;
        match NgKeys::assembled(&found) {
            Err(Error::UnrecognisedExecutable { missing, found, .. }) => {
                assert_eq!(missing, [NG_TABLES_NAMED]);
                assert_eq!(found, 372);
            }
            other => panic!("expected one decrypt table short, got {other:?}"),
        }
    }

    #[test]
    fn a_half_found_search_names_the_half_it_did_not_find() {
        // The arm no synthetic source can reach: producing "1 of 2" needs the
        // real value, which DR-006 keeps out of this repository. The decision
        // is a function of two booleans precisely so it can be tested without
        // one.
        assert_eq!(keys_missing(true, false), [HASH_LUT_NAMED]);
        assert_eq!(keys_missing(false, true), [AES_KEY_NAMED]);
        assert_eq!(keys_missing(false, false), [AES_KEY_NAMED, HASH_LUT_NAMED]);
        assert_eq!(ng_missing(true, false), [NG_TABLES_NAMED]);
        assert_eq!(ng_missing(false, true), [NG_EXPANDED_NAMED]);
        assert_eq!(
            ng_missing(false, false),
            [NG_EXPANDED_NAMED, NG_TABLES_NAMED]
        );
    }

    #[test]
    fn nothing_a_failure_names_is_a_value() {
        // DR-006 checked where it is easiest to lose: these strings are the
        // only new thing an `UnrecognisedExecutable` renders, and they are
        // written here rather than derived from anything that was read.
        for name in [
            AES_KEY_NAMED,
            HASH_LUT_NAMED,
            NG_EXPANDED_NAMED,
            NG_TABLES_NAMED,
        ] {
            assert!(
                name.is_ascii() && name.starts_with("the "),
                "a name that is not a name: {name}"
            );
        }
    }

    #[test]
    fn an_unkeyed_unlock_offers_no_candidate_and_reads_nothing() {
        // The state every unencrypted path is in, and the one R2.6 rests on:
        // no cache is named, so none can be read or created.
        let unlock = Unlock::unkeyed();
        assert!(unlock.is_unkeyed());
        assert_eq!(unlock.name(), "");
        for scheme in [
            Scheme::Aes(AesKey::Rage),
            Scheme::Aes(AesKey::Launcher),
            Scheme::Ng,
        ] {
            assert!(
                unlock
                    .candidates(scheme)
                    .expect("no source to fail")
                    .is_empty()
            );
        }
    }

    #[test]
    fn a_nested_archive_keeps_the_source_and_takes_its_own_name() {
        // A nested archive's key is chosen by *its* name, not its holder's.
        let unlock = Unlock::unkeyed().renamed("vehicles.rpf");
        assert_eq!(unlock.name(), "vehicles.rpf");
        assert!(unlock.is_unkeyed());
    }

    #[test]
    fn a_cache_that_is_not_there_is_no_candidate_rather_than_a_failure() {
        let directory = std::env::temp_dir().join("rpf-unlock-absent-cache");
        let _ = std::fs::remove_dir_all(&directory);
        let unlock = Unlock::cached(super::Cache::at(&directory), "dlc.rpf");
        assert!(!unlock.is_unkeyed());
        assert!(
            unlock
                .candidates(Scheme::Ng)
                .expect("an absent directory holds nothing")
                .is_empty()
        );
        assert!(!directory.exists(), "asking must not create a cache");
    }

    #[cfg(fuzzing)]
    #[test]
    fn over_bytes_carries_exactly_the_bytes_it_was_given() {
        let aes = [7_u8; AES_KEY_LEN];
        let lut = [9_u8; HASH_LUT_LEN];
        let material =
            Material::over_bytes(aes, lut, None, None).expect("well-formed bytes assemble");
        assert_eq!(material.keys().aes_key(), &aes);
        assert_eq!(material.keys().hash_lut(), &lut);
        assert!(material.ng().is_none());
        assert!(material.launcher().is_none());
    }

    #[cfg(fuzzing)]
    #[test]
    fn over_bytes_carries_the_ng_half_and_the_launcher_key_when_given_both() {
        let expanded = vec![3_u8; NG_EXPANDED_KEY_COUNT.saturating_mul(NG_EXPANDED_KEY_LEN)];
        let tables = vec![5_u8; NG_DECRYPT_TABLE_COUNT.saturating_mul(NG_DECRYPT_TABLE_LEN)];
        let launcher_key = [11_u8; AES_KEY_LEN];
        let material = Material::over_bytes(
            [0; AES_KEY_LEN],
            [0; HASH_LUT_LEN],
            Some((expanded.clone(), tables.clone())),
            Some(launcher_key),
        )
        .expect("well-formed bytes assemble");

        let ng = material.ng().expect("the ng half was given");
        assert_eq!(ng.expanded_bytes(), expanded.as_slice());
        assert_eq!(ng.table_bytes(), tables.as_slice());
        assert_eq!(
            material
                .launcher()
                .expect("the launcher key was given")
                .key(),
            &launcher_key
        );
    }

    #[cfg(fuzzing)]
    #[test]
    fn over_bytes_refuses_an_ng_half_of_the_wrong_length() {
        assert!(
            Material::over_bytes(
                [0; AES_KEY_LEN],
                [0; HASH_LUT_LEN],
                Some((vec![], vec![])),
                None
            )
            .is_none()
        );
    }
}
