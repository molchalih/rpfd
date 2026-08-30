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

/// Names the whole survey for a watcher, which is what one pass now looks for.
const MATERIAL_NAMED: &str = "key material";

/// Everything one source carries.
///
/// [`Keys`] is required and [`NgKeys`] is not, and that asymmetry is the
/// measurement rather than a preference: a game executable carries the first
/// and none of the second, while a memory image of that same executable carries
/// both. A source holding neither is [`Error::UnrecognisedExecutable`]; a source
/// holding only the first is the ordinary case and is not a failure, because an
/// archive with the AES tag needs nothing else. DR-040.
///
/// This is one pass over the source for all 375 values rather than two passes
/// for two and 373. The values are found by hashing windows and the windows are
/// the expensive part, so looking for everything at once costs what looking for
/// the larger half alone would.
#[derive(Debug)]
pub struct Material {
    /// The AES key and hash lookup table, which every source must carry.
    keys: Keys,
    /// The NG material, where the source carries it.
    ng: Option<Arc<NgKeys>>,
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
        let mut wanted = Vec::with_capacity(KEYS_WANTED.saturating_add(NG_WANTED));
        wanted.extend_from_slice(&Keys::anchors());
        wanted.append(&mut NgKeys::anchors());

        let found = scan::find(source, &wanted, MATERIAL_NAMED, watch)?;
        let (base, ng) = found.split_at(found.len().min(KEYS_WANTED));

        Ok(Self {
            keys: Keys::assembled(base)?,
            ng: NgKeys::assembled(ng).ok().map(Arc::new),
        })
    }

    /// The material as the cache read it back.
    pub(super) fn restored(keys: Keys, ng: Option<NgKeys>) -> Self {
        Self {
            keys,
            ng: ng.map(Arc::new),
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

    /// The same, as the handle a [`crate::format::crypto::Cipher`] keeps.
    ///
    /// Shared rather than borrowed because the tables are 278 KB and every
    /// encrypted entry of every archive makes a cipher over the same ones.
    pub(crate) const fn ng_shared(&self) -> Option<&Arc<NgKeys>> {
        self.ng.as_ref()
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
    use super::{
        AES_KEY_NAMED, HASH_LUT_NAMED, NG_EXPANDED_NAMED, NG_TABLES_NAMED, Unlock, keys_missing,
        ng_missing,
    };
    use crate::format::crypto::Scheme;

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
        for scheme in [Scheme::Aes, Scheme::Ng] {
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
}
