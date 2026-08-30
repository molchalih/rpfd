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
    fmt,
    io::{Cursor, Read, Seek, SeekFrom, Write},
};

use crate::{
    archive::Archive,
    build::{file_row, kind_of, store},
    edit::{Change, Changes, Structural},
    error::{Error, Result},
    format::Row,
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
    row: Row,
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
            file.write_all(ready.row.as_bytes())
                .map_err(|source| Error::Io {
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
    /// At least one change alters what the archive **holds** rather than what
    /// an entry holds, and no patch can express that.
    ///
    /// An entry added or removed changes the entry count, which moves the names
    /// blob and the floor every payload sits above; a rename moves the names
    /// blob the same way. So it is decided for the whole set here, before
    /// anything is compressed, rather than found one entry at a time. R4.10,
    /// DR-026.
    Structural(Vec<Structural>),
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

/// Decides what patching every change would do, without writing anything.
///
/// A [`Change::Write`] to a path the archive holds is the one thing a patch can
/// do: the payload goes where the old one sat, in the storage the entry already
/// carries. Everything else — a path created, an entry removed, an entry
/// renamed, a directory added — is [`Plan::Structural`], because each of them
/// changes the entry count or the names blob and therefore every offset after
/// it. That verdict is reached for the whole set before any payload is
/// compressed.
///
/// A write's contents are the file as it exists outside the archive: for a
/// resource, its `RSC7` header and still-deflated body. A path may address
/// through nested archives in one string. Patching inside one needs **no
/// rebuild of any ancestor**: the nested archive's own length is unchanged, so
/// the payload its parent describes is unchanged, so there is nothing above to
/// update. That is the whole reason this is worth having.
///
/// Returns [`Plan::DoesNotFit`] naming every write that is too large, so a
/// caller reporting a dry run can show all of them rather than the first. Too
/// large for the *entry's room*, that is: a payload too large for the entry's
/// fields to describe at all is an error rather than a rejection, and the same
/// one a rebuild of it would give.
///
/// # Errors
///
/// [`Error::NotFound`] for a path that does not resolve and was not asked to be
/// created, [`Error::WrongKind`] for a directory, [`Error::NotAResource`] for a
/// resource given a payload that is not one, [`Error::FieldOverflow`] for one no
/// entry row can describe, [`Error::Overlapping`] for two edits that claim the
/// same bytes, [`Error::CannotWriteEncrypted`] for an archive this build can
/// read and not write back, and [`Error::Io`] from the archive. Not
/// [`Error::ArchiveTooLarge`], which the same row builder can raise: the block
/// this hands it was decoded out of the entry it is patching, so it already
/// fits the field.
pub fn plan<F>(file: &mut F, archive: &Archive, changes: &Changes) -> Result<Plan>
where
    F: Read + Seek,
{
    // Asked before anything is resolved. A `Plan::Structural` is a value the
    // caller finishes by rebuilding, and an archive that cannot be written back
    // cannot finish it — so answering one here would be handing over a half
    // decision (§4). It covers the archive a path never leaves; the holder a
    // path descends into is asked for itself below.
    archive.writable()?;

    let structural = structural_in(file, archive, changes)?;
    if !structural.is_empty() {
        return Ok(Plan::Structural(structural));
    }

    let mut ready = Vec::new();
    let mut rejected = Vec::new();
    let mut claims: Vec<(&str, Claim)> = Vec::new();

    for (path, change) in changes {
        // Everything else was structural, and structural returned above.
        let Change::Write { ref contents, .. } = *change else {
            continue;
        };
        let (holder, index) = archive.locate(file, path)?;
        // The archive the bytes would land in, asked before a byte of payload
        // is compressed: a patch writes plaintext where the entry already sits,
        // and where that region is under a transform it destroys the archive in
        // place. One answer, `Archive::writable`, shared with the rebuild path.
        // DR-041.
        holder.writable()?;
        let entry = *holder.entry(index)?;

        // The storage rule is the entry's, not the caller's: one that was
        // deflated stays deflated, and one that was stored stays stored.
        // Changing it would be a different operation than replacing a payload.
        //
        // The version is the holder's for the same reason: a patch rewrites one
        // entry of an archive that already exists, so the fields it has to fit
        // are that archive's.
        //
        // A patch holds the payload it is about to write, because it writes it
        // as one edit into a live archive rather than streaming it into a new
        // one. So the sink here is a buffer, and `store` is still the one place
        // the rule is applied.
        let mut buffer = Cursor::new(Vec::new());
        let mut opened = contents.open()?;
        let written = store(
            holder.version(),
            path,
            kind_of(path, &entry)?,
            &mut opened,
            &mut buffer,
        )?;
        let mut payload = buffer.into_inner();
        // A deflated form that did not pay for itself leaves the tail of it
        // zeroed past the plain bytes, which is what a rebuild needs and a
        // patch does not: the entry describes `len` bytes and no more.
        payload.truncate(usize::try_from(written.len).unwrap_or(usize::MAX));

        let allocation = holder.allocation(index)?;
        let needed = written.len;
        let (at, _) = holder.payload_at(index)?;
        let row_at = holder.row_at(index)?;

        // Built before the fit is considered, so that a payload the entry could
        // never describe is refused outright rather than reported as merely too
        // large for where it sits — which is the verdict a build gives it.
        let block = at
            .checked_sub(holder.base())
            .and_then(|relative| relative.checked_div(holder.version().block_len()))
            .ok_or(Error::OutOfBounds {
                region: "payload",
                offset: at,
                len: needed,
                archive_len: holder.len_bytes(),
            })?;
        let row = file_row(holder.version(), path, entry.name_offset, block, &written)?;

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
                len: holder.version().row_len(),
            },
        ] {
            if let Some((other, _)) = claims
                .iter()
                .find(|(other, staked)| *other != path && staked.overlaps(&claim))
            {
                return Err(Error::Overlapping {
                    path: path.to_owned(),
                    other: (*other).to_owned(),
                });
            }
            claims.push((path, claim));
        }

        if needed > allocation {
            rejected.push(TooLarge {
                path: path.to_owned(),
                allocation,
                needed,
            });
            continue;
        }

        ready.push(Ready {
            planned: Planned {
                path: path.to_owned(),
                at,
                len: needed,
                allocation,
            },
            payload,
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

/// Every change in the set that no patch can express.
///
/// A write is the one that depends on the archive rather than on itself, so it
/// is resolved here: a path the archive holds is a patch, and a path it does
/// not is either an addition or [`Error::NotFound`], depending on what the
/// caller asked for. Nothing is compressed on the way.
fn structural_in<F>(file: &mut F, archive: &Archive, changes: &Changes) -> Result<Vec<Structural>>
where
    F: Read + Seek,
{
    let mut structural = Vec::new();
    for (path, change) in changes {
        let exists = match *change {
            Change::Write { create, .. } => match archive.locate(file, path) {
                Ok(_) => true,
                Err(error @ Error::NotFound { .. }) => {
                    if !create {
                        return Err(error);
                    }
                    false
                }
                Err(other) => return Err(other),
            },
            _ => false,
        };
        if let Some(one) = Structural::of(path, change, exists) {
            structural.push(one);
        }
    }
    Ok(structural)
}
