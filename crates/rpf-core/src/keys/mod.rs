//! Key material, and finding it in the user's own game executable.
//!
//! Nothing here is bundled. DR-006 forbids shipping key material, so the
//! repository carries only the **SHA-1 digest** of each value it knows how to
//! look for (the `anchors` module) and the routine that looks. That makes the search its
//! own proof: bytes that hash to the digest asked for are the value, and
//! nothing weaker than the value hashes to it.
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
};

use scan::{Anchor, Sighting};

use crate::{
    error::{Error, Result},
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

/// What [`Keys`] is looking for, for the count an unrecognised executable
/// reports.
const KEYS_WANTED: u32 = 2;

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
        let wanted = [
            Anchor {
                len: AES_KEY_LEN,
                digest: anchors::AES_KEY,
            },
            Anchor {
                len: HASH_LUT_LEN,
                digest: anchors::HASH_LUT,
            },
        ];
        let mut found = scan::find(source, &wanted, KEYS_NAMED, watch)?.into_iter();
        let aes = found
            .next()
            .flatten()
            .as_ref()
            .and_then(exactly::<AES_KEY_LEN>);
        let lut = found
            .next()
            .flatten()
            .as_ref()
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
                wanted: KEYS_WANTED,
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
/// **No executable this was measured against carries it, so the extraction
/// below has never succeeded on any input.** Measured 2026-08-28 against
/// `GTA5.exe`, `GTA5_Enhanced.exe` and `RDR2.exe`, at every byte offset rather
/// than only on the eight-byte stride: 0 of 101 and 0 of 272 in each. What is
/// here is the search and what it looks for, so that the finding is something
/// the suite re-establishes rather than a note somebody once wrote down, and so
/// that an executable which does carry the material is recognised by this
/// routine rather than by a new one.
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
        let mut wanted =
            Vec::with_capacity(NG_EXPANDED_KEY_COUNT.saturating_add(NG_DECRYPT_TABLE_COUNT));
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

        let found = scan::find(source, &wanted, NG_NAMED, watch)?;
        let mut expanded = Vec::new();
        let mut tables = Vec::new();
        let mut expanded_hits = 0_usize;
        let mut table_hits = 0_usize;
        for (anchor, sighting) in wanted.iter().zip(found.iter()) {
            let Some(sighting) = sighting else { continue };
            if sighting.bytes.len() != anchor.len {
                continue;
            }
            if anchor.len == NG_EXPANDED_KEY_LEN {
                expanded_hits = expanded_hits.saturating_add(1);
                expanded.extend_from_slice(&sighting.bytes);
            } else {
                table_hits = table_hits.saturating_add(1);
                tables.extend_from_slice(&sighting.bytes);
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
        })
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
            .field("decrypt_tables", &NG_DECRYPT_TABLE_COUNT)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AES_KEY_NAMED, HASH_LUT_NAMED, NG_EXPANDED_NAMED, NG_TABLES_NAMED, keys_missing, ng_missing,
    };

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
}
