//! Rewriting entries without rewriting the archive.

use std::{
    fmt,
    io::{Cursor, Read, Seek, SeekFrom, Write},
};

use crate::{
    archive::Archive,
    build::{Sealed, file_row, kind_of, store},
    edit::{self, Change, Changes, Structural},
    error::{Error, Result},
    format::Row,
};

/// What a plan will do to one entry.
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

struct Ready {
    planned: Planned,
    payload: Vec<u8>,
    row_at: u64,
    row: Row,
}

/// A set of edits, all already checked to fit their entries' room.
pub struct Patches {
    ready: Vec<Ready>,
}

impl fmt::Debug for Patches {
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

    /// Writes every planned edit, payload first and then its entry row.
    /// # Errors
    /// An I/O error; whatever was written before the failure stays written.
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

/// What patching a set of edits would come to, decided before anything is written.
#[derive(Debug)]
pub enum Plan {
    /// Every edit fits where its entry already sits.
    Fits(Patches),
    /// At least one edit does not fit; nothing was written, not even the rest.
    DoesNotFit(Vec<TooLarge>),
    /// At least one change alters what the archive holds, which no patch can express.
    Structural(Vec<Structural>),
}

struct Claim {
    at: u64,
    len: u64,
}

impl Claim {
    fn overlaps(&self, other: &Self) -> bool {
        let end = self.at.saturating_add(self.len);
        let other_end = other.at.saturating_add(other.len);
        self.at < other_end && other.at < end
    }
}

/// Decides what patching every change would do, without writing anything.
/// # Errors
/// Returns an error for a bad target, encoding, overlap, encryption, size, or I/O failure.
pub fn plan<F>(file: &mut F, archive: &Archive, changes: &Changes) -> Result<Plan>
where
    F: Read + Seek,
{
    // A structural plan is finished by rebuild, so an unwritable archive can't answer it.
    archive.writable()?;

    let structural = structural_in(file, archive, changes)?;
    if !structural.is_empty() {
        return Ok(Plan::Structural(structural));
    }

    let mut ready = Vec::new();
    let mut rejected = Vec::new();
    let mut claims: Vec<(&str, Claim)> = Vec::new();

    for (path, change) in changes {
        // Every other kind of change was structural, and that returned above.
        let Change::Write {
            ref contents,
            allow_encoding_change,
            ..
        } = *change
        else {
            continue;
        };
        let (holder, index) = archive.locate(file, path)?;
        // A patch writes plaintext in place, so a transform this build can't redo is refused first.
        holder.writable()?;
        edit::check_encoding(
            file,
            &holder,
            index,
            path,
            &**contents,
            allow_encoding_change,
        )?;
        // The holder's own transform: a nested archive carries its own tag and key,
        // and an entry row is exactly one aligned cipher block, so rewriting it alone is sound.
        let transform = holder.seal()?;
        let tag = holder.encryption_tag();
        let under = transform.as_ref().map(|forward| Sealed::new(forward, tag));
        let entry = *holder.entry(index)?;

        let mut buffer = Cursor::new(Vec::new());
        let mut opened = contents.open()?;
        let written = store(
            holder.version(),
            path,
            kind_of(path, &entry)?,
            under,
            &mut opened,
            &mut buffer,
        )?;
        let mut payload = buffer.into_inner();
        // A deflated form that didn't pay for itself leaves a zeroed tail past the plain bytes.
        payload.truncate(usize::try_from(written.len).unwrap_or(usize::MAX));

        let allocation = holder.allocation(index)?;
        let needed = written.len;
        let (at, _) = holder.payload_at(index)?;
        let row_at = holder.row_at(index)?;

        // Built before the fit check, so an offset the entry could never describe fails hard.
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
        // Keyed by the archive's name and length, not the entry's; conflating the two
        // writes a row nothing decodes.
        let row = match under {
            None => row,
            Some(under) => row.sealed(&under.of(holder.keyed_name(), holder.len_bytes())?),
        };

        // Claimed regardless of fit, so the verdict doesn't depend on compression luck.
        stake(
            &mut claims,
            path,
            [
                Claim {
                    at,
                    len: allocation,
                },
                Claim {
                    at: row_at,
                    len: holder.version().row_len(),
                },
            ],
        )?;

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

fn stake<'a>(claims: &mut Vec<(&'a str, Claim)>, path: &'a str, staking: [Claim; 2]) -> Result<()> {
    for claim in staking {
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
    Ok(())
}

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
