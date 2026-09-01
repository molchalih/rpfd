//! Key material, and finding it in a source from the user's own installation.
//!
//! No key material is bundled: the repository carries only the SHA-1 digest of
//! each value and the routine that hashes windows of a source looking for it.
//! An unencrypted archive never asks this module for anything.

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

/// The key material a game executable carries in the clear: the RAGE AES-256
/// key and the hash lookup table the NG cipher indexes.
///
/// Whole or not at all, since a caller given one of the two can finish nothing.
/// The NG expanded keys and decrypt tables are [`NgKeys`], not this.
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

/// How many values [`Keys`] is made of, and the count an unrecognised source
/// is told it fell short of.
const KEYS_WANTED: usize = 2;

/// Names the material in a failure, so a caller is told which search fell short.
const KEYS_NAMED: &str = "AES key and hash lookup table";

/// Names the AES-256 key where a failure has to say it was the one missing.
const AES_KEY_NAMED: &str = "the AES key";

/// Names the hash lookup table, for the same reason.
const HASH_LUT_NAMED: &str = "the hash lookup table";

/// What [`Keys::extract`] did not find, given what it did.
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

/// Written by hand so that no key can reach a log, a panic message or a
/// `--json` payload by being printed. Offsets only, never bytes.
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

/// What [`NgKeys`] is looking for. Derived rather than written, so it cannot
/// drift from the two counts it has to equal.
const NG_WANTED: usize = NG_EXPANDED_KEY_COUNT.saturating_add(NG_DECRYPT_TABLE_COUNT);

/// Names the material in a failure.
const NG_NAMED: &str = "NG expanded keys and decrypt tables";

/// Names the expanded keys where a failure has to say they were short.
const NG_EXPANDED_NAMED: &str = "the expanded keys";

/// Names the decrypt tables, for the same reason.
const NG_TABLES_NAMED: &str = "the decrypt tables";

/// Which kinds [`NgKeys::extract`] is short of, given what each found.
const fn ng_missing(expanded: bool, tables: bool) -> &'static [&'static str] {
    match (expanded, tables) {
        (false, true) => &[NG_EXPANDED_NAMED],
        (true, false) => &[NG_TABLES_NAMED],
        _ => &[NG_EXPANDED_NAMED, NG_TABLES_NAMED],
    }
}

/// The NG key material: 101 expanded keys and 272 decrypt tables.
///
/// No game executable carries it in the clear; a memory image of a running one
/// does, because the unpacking happens at load. Separate from [`Keys`] because
/// an AES-tagged archive needs none of it.
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

/// How many values [`LauncherKey`] is made of, which is what one pass's
/// answers are split by.
const LAUNCHER_WANTED: usize = 1;

/// The Rockstar Games Launcher's own AES-256 key.
///
/// A second key, not a second cipher: an archive tagged `0x0FFFFFF7` is under
/// the transform `0x0FFFFFF9` names, keyed by this instead of by the RAGE key.
///
/// Optional on [`Material`] rather than a third value in [`Keys`], because only
/// the launcher's own executable carries it.
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
/// [`Keys`] is required and the other two are not: a game executable carries
/// only the first, a memory image adds the NG half, and only the launcher's own
/// executable carries the launcher key.
///
/// One pass over the source for all 376 values: the windows are the expensive
/// part, so looking for everything at once costs what the largest group would.
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
        // by the value that asked for it.
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
    /// Makes an AES-tagged archive readable and writable in this crate's own
    /// tests with no installation and no key material. `#[cfg(test)]`, so it is
    /// in no release build and in nothing a dependent compiles.
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

    /// Material whose AES half is zero bytes and whose NG half is `ng`, over
    /// the name-hash table `lut`.
    ///
    /// The NG counterpart of [`Material::over_zeros`]. What it is handed is
    /// synthetic arithmetic, never key material. `#[cfg(test)]`, so it is in no
    /// release build and in nothing a dependent compiles.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn over_ng(lut: [u8; HASH_LUT_LEN], ng: NgKeys) -> Self {
        Self::restored(
            Keys {
                aes: [0; AES_KEY_LEN],
                aes_at: 0,
                lut,
                lut_at: 0,
            },
            Some(ng),
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
    #[must_use]
    pub const fn launcher(&self) -> Option<&LauncherKey> {
        self.launcher.as_ref()
    }

    /// The same, as the handle a [`crate::format::crypto::Cipher`] keeps.
    pub(crate) const fn ng_shared(&self) -> Option<&Arc<NgKeys>> {
        self.ng.as_ref()
    }
}

/// The one seam a fuzz target opens, and the whole of it.
#[cfg(fuzzing)]
impl Material {
    /// Material made of bytes the caller already holds.
    ///
    /// Not a way to obtain key material but a way to supply it: every value
    /// comes from the caller and no anchor is consulted.
    ///
    /// `#[cfg(fuzzing)]` rather than a feature, so a dependent cannot switch it
    /// on: it is absent from every release build and from `cargo doc`.
    ///
    /// `None` when `ng` is given and its halves are not the lengths [`NgKeys`]
    /// promises.
    #[must_use]
    pub fn over_bytes(
        aes: [u8; AES_KEY_LEN],
        lut: [u8; HASH_LUT_LEN],
        ng: Option<(Vec<u8>, Vec<u8>)>,
        launcher: Option<[u8; AES_KEY_LEN]>,
    ) -> Option<Self> {
        // The offsets a real search would have reported; only `Debug` reads
        // them, and an offset is not key material.
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
/// a cache read only if the archive turns out to need it, so an unencrypted
/// archive never reaches a configuration directory.
///
/// The name is the archive's own file name, which an NG archive's key is a
/// function of. Deliberately no `Default`: [`Unlock::unkeyed`] is a claim about
/// the caller's environment and must be written out.
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
    #[must_use]
    pub const fn unkeyed() -> Self {
        Self {
            source: Source::Unkeyed,
            name: String::new(),
        }
    }

    /// This material, for an archive addressed by this name.
    ///
    /// An [`Arc`] rather than the material itself: the NG half is 305 KB and
    /// every nested archive holds the same one for as long as it is open.
    #[must_use]
    pub fn held(material: Arc<Material>, name: impl Into<String>) -> Self {
        Self {
            source: Source::Held(material),
            name: name.into(),
        }
    }

    /// Whatever this cache holds, for an archive addressed by this name.
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
    #[must_use]
    pub const fn is_unkeyed(&self) -> bool {
        matches!(self.source, Source::Unkeyed)
    }

    /// The same material, for an archive of another name.
    #[must_use]
    pub fn renamed(&self, name: &str) -> Self {
        Self {
            source: self.source.clone(),
            name: name.to_owned(),
        }
    }

    /// The material already in hand, where there is any.
    #[must_use]
    pub(crate) const fn held_material(&self) -> Option<&Arc<Material>> {
        match self.source {
            Source::Held(ref material) => Some(material),
            Source::Unkeyed | Source::Cached(_) => None,
        }
    }

    /// This, with whatever it resolved to already in hand.
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
    /// A byte pattern, never key material: the real values stay out of this
    /// repository.
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

    /// The answers a complete [`NgKeys`] search returns: 101 expanded keys then
    /// 272 decrypt tables, each with an offset of its own.
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

    /// Material of the shape every game executable produces.
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
        // `WrongKey` and `NeedsKey` name different things to do: telling an
        // automation to extract a key it already holds is a loop it never
        // leaves. What decides it is `is_root_directory`, a whole word no file
        // entry can produce, so a wrong key answers `false`.
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
        // Every source carries the RAGE key, a memory image adds the NG half,
        // and only the launcher's own executable carries the launcher key.
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
        // `AesKey::of` picks which of a material's keys runs the transform, so
        // two materials differing only in that key have to disagree.
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
        // The index is a function of the name and the length, so two lengths
        // choose two keys.
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
        // An empty answer is `NeedsKey`, so answering empty for material that
        // does open the archive makes a readable archive unreadable.
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

        let nested = unlock.renamed("vehicles.rpf");
        assert_eq!(nested.name(), "vehicles.rpf");
        assert!(nested.held_material().is_some());
    }

    #[test]
    fn a_value_a_source_does_not_carry_is_an_absence_and_not_a_failure() {
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
        // The only place a length is taken on trust from a file on disk: both
        // halves have to be right, or `expanded_key` and `decrypt_table` slice
        // a buffer blindly.
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
        // The two are 32 and 256 bytes, so a swapped read order is not a type
        // error but the wrong key handed to the cipher, silently.
        let keys = Keys::assembled(&keys_found()).expect("both were found");
        assert_eq!(keys.aes_key(), &[0x11; AES_KEY_LEN]);
        assert_eq!(keys.hash_lut(), &[0x22; HASH_LUT_LEN]);
        assert_eq!(keys.aes_key_offset(), 0x1234_5678);
        assert_eq!(keys.hash_lut_offset(), 0x00AB_CDEF);
    }

    #[test]
    fn a_sighting_of_the_wrong_length_is_not_the_value_it_was_looked_for() {
        // A slot filled from an anchor of another length is the difference
        // between a missing key and a wrong one; `exactly` refuses it.
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
        // A derived `Debug` is one of the ways a key would leave this machine.
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
        // `NG_EXPANDED_KEY_COUNT` are expanded keys and the rest are tables.
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
        // Round and column fold into one index, so a column past the sixteenth
        // is the next round's table, which exists and the slice bound cannot
        // notice.
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
        // The order is the contract `assembled` reads back by: expanded keys
        // first, decrypt tables after.
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
        // Producing "1 of 2" would need a real value, so the decision is a
        // function of two booleans and can be tested without one.
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
        // The state every unencrypted path is in: no cache is named, so none
        // can be read or created.
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
