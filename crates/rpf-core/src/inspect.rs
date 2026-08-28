//! What an archive adds up to, and whether it reads back as it describes
//! itself.
//!
//! `info` and `verify` ask about a whole archive rather than about one entry,
//! and both frontends ask them. They live here because anything one frontend
//! can do the other must be able to do (§1): with this logic in the binary,
//! `serve --stdio` could not answer either question at all, and the editor
//! client reaches the container only through the daemon.
//!
//! Neither renders anything. A [`Summary`] is numbers and a [`Verified`] is a
//! list of failures with the entry each belongs to, so the command line,
//! `--json` and the editor client each say it their own way (§10).

use std::io::{Read, Seek};

use crate::{
    archive::Archive,
    entry::EntryKind,
    error::{Error, Result},
    format::payload_floor,
    watch::{Flow, Step, Watch},
};

/// What one archive contains, and how much of it nothing refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// The archive's own length.
    pub len: u64,
    /// The encryption tag from its header.
    pub encryption: u32,
    /// How many entries the entry table holds.
    pub entries: u32,
    /// How many of them are directories.
    pub directories: u32,
    /// How many are binary files.
    pub binary_files: u32,
    /// How many are resources.
    pub resource_files: u32,
    /// How many entries hold an archive of their own, one level down.
    pub nested_archives: u32,
    /// Bytes of the archive that no region claims.
    pub unreferenced_bytes: u64,
}

impl Summary {
    /// Summarises an archive, sniffing each payload for a nested one.
    ///
    /// # Errors
    ///
    /// [`Error::TooDeep`] when a payload nests past [`crate::MAX_DEPTH`], and
    /// as [`Archive::entry`] for an entry table that contradicts itself.
    pub fn of<R: Read + Seek>(src: &mut R, archive: &Archive) -> Result<Self> {
        let entries = count(archive);
        // The header, the entry table and the names blob are referenced too.
        // `payload_floor` is the one place that sum lives, so this cannot drift
        // from where the reader and the writer put the first payload.
        // `docs/rpf-format.md`, Slack, `verified`.
        let mut referenced = payload_floor(
            u64::from(entries),
            u64::try_from(archive.names_blob().len()).unwrap_or(u64::MAX),
        );

        let mut directories = 0_u32;
        let mut binary_files = 0_u32;
        let mut resource_files = 0_u32;
        let mut nested_archives = 0_u32;
        for index in 0..entries {
            match archive.entry(index)?.kind {
                EntryKind::Directory { .. } => {
                    directories = directories.saturating_add(1);
                    continue;
                }
                EntryKind::Binary {
                    compressed_len,
                    uncompressed_len,
                    ..
                } => {
                    binary_files = binary_files.saturating_add(1);
                    // Compressed size zero means stored, and then the other
                    // field carries what is on disk. `docs/rpf-format.md`,
                    // Compression.
                    let on_disk = if compressed_len == 0 {
                        uncompressed_len
                    } else {
                        compressed_len
                    };
                    referenced = referenced.saturating_add(u64::from(on_disk));
                }
                EntryKind::Resource { compressed_len, .. } => {
                    resource_files = resource_files.saturating_add(1);
                    referenced = referenced.saturating_add(u64::from(compressed_len));
                }
            }
            if archive.nested_at(src, index)?.is_some() {
                nested_archives = nested_archives.saturating_add(1);
            }
        }

        Ok(Self {
            len: archive.len_bytes(),
            encryption: archive.encryption(),
            entries,
            directories,
            binary_files,
            resource_files,
            nested_archives,
            unreferenced_bytes: archive.len_bytes().saturating_sub(referenced),
        })
    }
}

/// One entry that is not as the archive describes it.
///
/// Either it did not read back at all, or it read back and its payload
/// declares bytes its deflate stream never reached — [`Error::TrailingBytes`],
/// which nothing but this walk looks for. R6.10.
#[derive(Debug)]
pub struct Problem {
    /// Where it is, addressed from the outermost archive.
    pub path: String,
    /// What went wrong. The failure itself, not a sentence about it (§10).
    pub error: Error,
}

/// The result of reading every entry back.
#[derive(Debug)]
pub struct Verified {
    /// How many file entries were read, the failing ones included.
    pub checked: u32,
    /// Those that did not come back as the archive promised.
    pub problems: Vec<Problem>,
}

impl Verified {
    /// Reads every entry of an archive, and of every archive nested in it.
    ///
    /// A read is unbounded work in the same way a rebuild is — the format
    /// document names archives of 2.7 GB — so this takes the same [`Watch`]
    /// seam, reports one step per entry and stops when the watcher says to.
    /// DR-008. `done` and `total` count the archive being read now rather than
    /// the whole nesting, for the reason a cascading rebuild does the same.
    ///
    /// # Errors
    ///
    /// [`Error::Cancelled`] when the watcher stops it, and as
    /// [`Archive::entry`] for an entry table that contradicts itself. An entry
    /// that does not read back is a [`Problem`], not an error: the point of
    /// the walk is to find every one of them rather than the first.
    pub fn of<R: Read + Seek>(
        src: &mut R,
        archive: &Archive,
        watch: &mut impl Watch,
    ) -> Result<Self> {
        let mut verified = Self {
            checked: 0,
            problems: Vec::new(),
        };
        verified.walk(src, archive, "", watch, &mut 0)?;
        Ok(verified)
    }

    /// Whether every entry read back, as the failure a frontend reports.
    ///
    /// # Errors
    ///
    /// [`Error::VerifyFailed`] with both counts when anything did not.
    pub fn outcome(&self) -> Result<()> {
        if self.problems.is_empty() {
            return Ok(());
        }
        Err(Error::VerifyFailed {
            checked: self.checked,
            failed: u32::try_from(self.problems.len()).unwrap_or(u32::MAX),
        })
    }

    /// One archive's entries, then the archives nested in them.
    fn walk<R: Read + Seek>(
        &mut self,
        src: &mut R,
        archive: &Archive,
        prefix: &str,
        watch: &mut impl Watch,
        bytes: &mut u64,
    ) -> Result<()> {
        let total = files_in(archive)?;
        let mut done = 0_u32;
        for index in 0..count(archive) {
            if archive.entry(index)?.is_directory() {
                continue;
            }
            // The whole path within this archive, not the entry's own name:
            // a report naming `greeting.txt` for `data/greeting.txt` names
            // nothing a caller can pass back to `cat` or `read`.
            let path = joined(prefix, &archive.path(index)?);

            // Counted before the read, not after it: an entry that failed was
            // still one of the entries checked, and counting only the ones
            // that passed made "1 of 26 entries failed" out of 27. R6.9.
            self.checked = self.checked.saturating_add(1);
            done = done.saturating_add(1);
            let outcome = archive.read_payload(src, index);
            if let Ok(ref payload) = outcome {
                *bytes = bytes.saturating_add(payload.len());
            }

            // Reported whether or not it read back, so that `done` and the
            // entries named agree: an entry skipped on the wire while still
            // counted is a gap the watcher cannot account for.
            if watch.step(Step {
                path: &path,
                done,
                total,
                bytes: *bytes,
            }) == Flow::Stop
            {
                return Err(Error::Cancelled { done, total });
            }

            let payload = match outcome {
                Err(error) => {
                    self.problems.push(Problem { path, error });
                    continue;
                }
                Ok(payload) => payload,
            };

            // Reported and then walked past: the contents are sound, so an
            // archive nested in them is still read back. R6.10.
            if let Err(error) = payload.checked() {
                self.problems.push(Problem {
                    path: path.clone(),
                    error,
                });
            }
            if let Some(nested) = archive.nested_at(src, index)? {
                self.walk(src, &nested, &path, watch, bytes)?;
            }
        }
        Ok(())
    }
}

/// Entries in an archive, saturating rather than truncating.
fn count(archive: &Archive) -> u32 {
    u32::try_from(archive.entries().len()).unwrap_or(u32::MAX)
}

/// How many of them are files, which is what a walk over them reports against.
fn files_in(archive: &Archive) -> Result<u32> {
    let mut files = 0_u32;
    for index in 0..count(archive) {
        if !archive.entry(index)?.is_directory() {
            files = files.saturating_add(1);
        }
    }
    Ok(files)
}

/// A path within the outermost archive, from the prefix that led here.
fn joined(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    }
}
