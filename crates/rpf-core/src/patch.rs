//! Rewriting entries without rewriting the archive.
//!
//! `docs/approach.md`: "Writes prefer in-place patching. Rewriting an entry
//! whose new payload fits its existing block allocation must not rewrite the
//! archive." This is that. It matters most where it is hardest to do without:
//! a 5 KB edit to a 2.7 GB archive should cost 5 KB of writes, not 2.7 GB.
//!
//! Real archives leave room for it. The sample is 82.7% unreferenced bytes, so
//! an entry's allocation almost always exceeds what it holds.
//!
//! **Deciding and writing are separate.** [`plan`] resolves every edit, applies
//! each entry's own storage rule, and checks that all of them fit, without
//! touching the archive; [`Patches::apply`] then writes what was decided. That
//! split is what lets a caller commit several edits at once: patching them one
//! at a time can apply two and then discover the third does not fit, which is
//! not what a commit promises. R4.14.
//!
//! **What the split does not buy is crash atomicity.** A rebuild writes a
//! temporary file and renames it, so an interruption leaves the original
//! intact. A patch writes into the live archive: the payload first, then the
//! entry row, with a flush between. An interruption between the two leaves an
//! archive whose entry describes bytes that are no longer there. That is the
//! price of not rewriting gigabytes, and it is why `verify` exists.

use std::{
    collections::BTreeMap,
    fmt,
    io::{Read, Seek, SeekFrom, Write},
};

use crate::{
    archive::Archive,
    build::{file_row, kind_of, prepare},
    error::{Error, Result},
    format::{BLOCK_LEN, ENTRY_LEN},
};

/// What a plan will do to one entry.
///
/// Carries no payload: this is the description a caller reports, and R6.7's
/// dry-run is exactly this without the [`Patches::apply`] that would follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    /// The path, as it was given.
    pub path: String,
    /// Absolute offset the payload will be written at.
    pub at: u64,
    /// How many bytes will be written there.
    pub len: u64,
    /// How many the entry can hold without moving.
    pub allocation: u64,
}

/// An edit whose new payload is larger than the space its entry sits in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TooLarge {
    /// The path, as it was given.
    pub path: String,
    /// What the entry can hold without moving.
    pub allocation: u64,
    /// What the new payload needs.
    pub needed: u64,
}

/// One entry's replacement, decided in full.
struct Ready {
    planned: Planned,
    payload: Vec<u8>,
    row_at: u64,
    row: [u8; 16],
}

/// A set of edits that all fit, ready to be written.
///
/// A value of this type exists only when every edit in it has been resolved,
/// prepared and checked against the room its entry has, so [`Patches::apply`]
/// has nothing left to decide (§4).
pub struct Patches {
    ready: Vec<Ready>,
}

impl fmt::Debug for Patches {
    /// Shows what would be written, never the bytes: a payload is megabytes,
    /// and this type appears in test failures.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_list()
            .entries(self.ready.iter().map(|ready| &ready.planned))
            .finish()
    }
}

impl Patches {
    /// What each edit will do, in path order.
    pub fn planned(&self) -> impl Iterator<Item = &Planned> {
        self.ready.iter().map(|ready| &ready.planned)
    }

    /// Writes every planned edit.
    ///
    /// Each is written payload first, then its entry row, with a flush between
    /// — see the module documentation for the window that leaves open, and for
    /// why it is accepted here.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] from the archive. Whatever was written before the failure
    /// stays written; nothing here can undo it, which is what `verify` is for.
    pub fn apply<F>(&self, file: &mut F) -> Result<()>
    where
        F: Write + Seek,
    {
        for ready in &self.ready {
            let at = ready.planned.at;
            file.seek(SeekFrom::Start(at))
                .map_err(|source| Error::Io { offset: at, source })?;
            file.write_all(&ready.payload)
                .map_err(|source| Error::Io { offset: at, source })?;
            file.flush()
                .map_err(|source| Error::Io { offset: at, source })?;

            let row_at = ready.row_at;
            file.seek(SeekFrom::Start(row_at))
                .map_err(|source| Error::Io {
                    offset: row_at,
                    source,
                })?;
            file.write_all(&ready.row).map_err(|source| Error::Io {
                offset: row_at,
                source,
            })?;
            file.flush().map_err(|source| Error::Io {
                offset: row_at,
                source,
            })?;
        }
        Ok(())
    }
}

/// What patching a set of edits would come to, decided before anything is
/// written.
#[derive(Debug)]
pub enum Plan {
    /// Every edit fits where its entry already sits.
    Fits(Patches),
    /// At least one does not. The caller has to rebuild instead; nothing was
    /// written, and **no** edit in the set was applied, including those that
    /// would have fitted.
    DoesNotFit(Vec<TooLarge>),
}

/// The bytes one edit claims: the room its payload sits in, and its entry row.
///
/// Claimed rather than written, because the room is what another edit must not
/// reach into. Two entries in one archive have disjoint allocations by
/// construction — an allocation ends where the next payload begins — so this
/// only ever fires for edits that genuinely collide.
struct Claim {
    at: u64,
    len: u64,
}

impl Claim {
    /// Whether the two cover any byte in common.
    fn overlaps(&self, other: &Self) -> bool {
        let end = self.at.saturating_add(self.len);
        let other_end = other.at.saturating_add(other.len);
        self.at < other_end && other.at < end
    }
}

/// Decides what patching every edit would do, without writing anything.
///
/// `edits` maps a path to the file as it exists outside the archive: for a
/// resource, its `RSC7` header and still-deflated body. A path may address
/// through nested archives in one string. Patching inside one needs **no
/// rebuild of any ancestor**: the nested archive's own length is unchanged, so
/// the payload its parent describes is unchanged, so there is nothing above to
/// update. That is the whole reason this is worth having.
///
/// Returns [`Plan::DoesNotFit`] naming every edit that is too large, so a
/// caller reporting a dry run can show all of them rather than the first. Too
/// large for the *entry's room*, that is: a payload too large for the entry's
/// fields to describe at all is an error rather than a rejection, and the same
/// one a rebuild of it would give.
///
/// # Errors
///
/// [`Error::NotFound`] for a path that does not resolve,
/// [`Error::WrongKind`] for a directory, [`Error::NotAResource`] for a resource
/// given a payload that is not one, [`Error::FieldOverflow`] for one no entry
/// row can describe, [`Error::Overlapping`] for two edits that claim the same
/// bytes, and [`Error::Io`] from the archive.
pub fn plan<F>(file: &mut F, archive: &Archive, edits: &BTreeMap<String, Vec<u8>>) -> Result<Plan>
where
    F: Read + Seek,
{
    let mut ready = Vec::new();
    let mut rejected = Vec::new();
    let mut claims: Vec<(&str, Claim)> = Vec::new();

    for (path, contents) in edits {
        let (holder, index) = archive.locate(file, path)?;
        let entry = *holder.entry(index)?;

        // The storage rule is the entry's, not the caller's: one that was
        // deflated stays deflated, and one that was stored stays stored.
        // Changing it would be a different operation than replacing a payload.
        let prepared = prepare(path, kind_of(index, &entry)?, contents.clone())?;
        let allocation = holder.allocation(index)?;
        let needed = u64::try_from(prepared.bytes.len()).unwrap_or(u64::MAX);
        let (at, _) = holder.payload_at(index)?;
        let row_at = holder.row_at(index)?;

        // Built before the fit is considered, so that a payload the entry could
        // never describe is refused outright rather than reported as merely too
        // large for where it sits — which is the verdict a build gives it.
        let block = at
            .checked_sub(holder.base())
            .map(|relative| relative / BLOCK_LEN)
            .ok_or(Error::OutOfBounds {
                region: "payload",
                offset: at,
                len: needed,
                archive_len: holder.len_bytes(),
            })?;
        let row = file_row(path, entry.name_offset, block, &prepared)?;

        // Claimed whether or not it fits, so that the same set of edits always
        // reaches the same verdict rather than one that depends on how well
        // the payloads happened to compress.
        for claim in [
            Claim {
                at,
                len: allocation,
            },
            Claim {
                at: row_at,
                len: ENTRY_LEN,
            },
        ] {
            if let Some((other, _)) = claims
                .iter()
                .find(|(other, staked)| *other != path.as_str() && staked.overlaps(&claim))
            {
                return Err(Error::Overlapping {
                    path: path.clone(),
                    other: (*other).to_owned(),
                });
            }
            claims.push((path, claim));
        }

        if needed > allocation {
            rejected.push(TooLarge {
                path: path.clone(),
                allocation,
                needed,
            });
            continue;
        }

        ready.push(Ready {
            planned: Planned {
                path: path.clone(),
                at,
                len: needed,
                allocation,
            },
            payload: prepared.bytes,
            row_at,
            row,
        });
    }

    if rejected.is_empty() {
        Ok(Plan::Fits(Patches { ready }))
    } else {
        Ok(Plan::DoesNotFit(rejected))
    }
}
