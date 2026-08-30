//! What an archive holds, what it adds up to, and whether it reads back as it
//! describes itself.
//!
//! `ls`, `info` and `verify` ask about an archive rather than about one entry,
//! and both frontends ask them. They live here because anything one frontend
//! can do the other must be able to do (§1): with this logic in the binary,
//! `serve --stdio` could not answer any of them at all, and the editor client
//! reaches the container only through the daemon.
//!
//! None of them renders anything. A [`Listed`] is a path and what is at it, a
//! [`Summary`] is numbers, and a [`Verified`] is a list of failures with the
//! entry each belongs to, so the command line, `--json` and the editor client
//! each say it their own way (§10).

use std::{
    collections::BTreeMap,
    io::{Read, Seek},
};

use crate::{
    archive::{Archive, Nested},
    entry::EntryKind,
    error::{Error, Result},
    format::resource::resource_len,
    manifest::{Checksum, Manifest},
    watch::{Flow, Step, Watch},
};

/// One entry, as a listing reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    /// Where it is: **the whole path**, addressed from the path that was
    /// listed, in the spelling that path was given in.
    ///
    /// Not a name. Listing `x64/inner.rpf` gives rows whose path is
    /// `x64/inner.rpf/art.yft`, so a row addresses [`Archive::locate`] as it
    /// stands and a caller that joined it onto what it asked for would build
    /// the prefix twice. Components resolve case-insensitively, so the
    /// spelling is the caller's rather than the archive's. DR-028.
    pub path: String,
    /// What it is, and the one number that belongs with it.
    pub kind: ListedKind,
}

/// What a listed entry is, and the number that means something for that kind.
///
/// Three variants rather than one struct with a nullable field, because the
/// number is a child count for one of them and a byte count for the others
/// (§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListedKind {
    /// A directory, and how many children it holds.
    Directory {
        /// Entries directly inside it.
        children: u32,
    },
    /// Plain bytes, and how many of them the file is.
    Binary {
        /// The contents' length, which is what the file is outside the
        /// archive. Either storage choice changes what sits on disk, not what
        /// the file is.
        len: u64,
    },
    /// A resource, and the length its page flags describe.
    Resource {
        /// From [`resource_len`], which is where that fact is decoded.
        len: u64,
    },
}

impl Listed {
    /// Every entry at a path, and everything below it when `recursive`.
    ///
    /// The empty path is the archive's root. A path naming a nested archive
    /// lists what is inside it, because a nested archive is a directory as far
    /// as a path is concerned; a path naming an ordinary file is that one
    /// entry.
    ///
    /// **That last case is what makes this a `stat` as well as a listing**, and
    /// it is the only one there is: a caller tells "this is a file" from "this
    /// directory holds one child" by comparing the row's [`Listed::path`] with
    /// the one it asked for. Equal means the path named that entry. The
    /// comparison is exact — a child's path is its parent's plus a separator
    /// and a name, so it can never equal its parent's — and an empty answer is
    /// unambiguous, because a file always gives one row. DR-028.
    ///
    /// # Errors
    ///
    /// As [`Archive::locate`] for a path that does not resolve,
    /// [`Error::TooDeep`] past [`crate::MAX_DEPTH`], and as [`Archive::entry`]
    /// for an entry table that contradicts itself.
    pub fn at<R: Read + Seek>(
        src: &mut R,
        archive: &Archive,
        path: &str,
        recursive: bool,
    ) -> Result<Vec<Self>> {
        let (holder, at) = archive.locate(src, path)?;
        let mut rows = Vec::new();
        list_into(src, &holder, at, path, recursive, &mut rows)?;
        Ok(rows)
    }

    /// One row: what an entry is, and where it is from the path that was
    /// listed.
    fn of(archive: &Archive, index: u32, path: &str) -> Result<Self> {
        let kind = match archive.entry(index)?.kind {
            EntryKind::Directory { child_count, .. } => ListedKind::Directory {
                children: child_count,
            },
            EntryKind::Binary {
                uncompressed_len, ..
            } => ListedKind::Binary {
                len: u64::from(uncompressed_len),
            },
            // A resource entry carries no uncompressed size; its length is the
            // two flag words decoded. `docs/rpf-format.md`, Resource page
            // flags, `verified`.
            EntryKind::Resource {
                system_flags,
                graphics_flags,
                ..
            } => ListedKind::Resource {
                len: resource_len(system_flags, graphics_flags),
            },
        };
        Ok(Self {
            path: path.to_owned(),
            kind,
        })
    }
}

/// Collects the rows at one index, descending where asked to.
fn list_into<R: Read + Seek>(
    src: &mut R,
    archive: &Archive,
    at: u32,
    prefix: &str,
    recursive: bool,
    rows: &mut Vec<Listed>,
) -> Result<()> {
    // Not a directory? If it is an archive, listing it means listing what is
    // inside it. Anything else is a single entry.
    let Ok(children) = archive.children(at) else {
        // An archive that did not open is listed as the file it also is, which
        // is the only honest row available: its own entries cannot be read.
        // `verify` is where that gap is reported, and `info` is where it is
        // counted.
        if let Nested::Open(nested) = archive.nested_at(src, at)? {
            return list_into(src, &nested, 0, prefix, recursive, rows);
        }
        rows.push(Listed::of(archive, at, prefix)?);
        return Ok(());
    };

    for index in children {
        let path = joined(prefix, archive.name(index)?);
        rows.push(Listed::of(archive, index, &path)?);

        if !recursive {
            continue;
        }
        if archive.entry(index)?.is_directory() {
            list_into(src, archive, index, &path, true, rows)?;
        } else if let Nested::Open(nested) = archive.nested_at(src, index)? {
            list_into(src, &nested, 0, &path, true, rows)?;
        }
    }
    Ok(())
}

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
    ///
    /// Every one of them, whether this build could open it or not, so the
    /// number is a fact about the archive rather than about what a key cache
    /// happens to hold. [`Summary::locked_archives`] is how many of them did
    /// not open.
    pub nested_archives: u32,
    /// How many of [`Summary::nested_archives`] this build could not open for
    /// want of the right key material.
    ///
    /// Never larger than that count, and a caller reporting one number without
    /// the other reports more than was measured. Zero is "everything nested
    /// here was descended into", which is what a walk needs to know before it
    /// believes its own totals.
    pub locked_archives: u32,
    /// Bytes of the archive that no region claims.
    ///
    /// An entry's tail is claimed, so it is not counted here and no other
    /// field counts it either: a summary is silent about an archive holding a
    /// payload whose deflate stream ends early, and that is decided rather
    /// than overlooked. Finding one costs the inflate of every payload, which
    /// is `verify`'s walk — with the watcher DR-008 gives unbounded work, and
    /// which reports each one against its own path. R6.10, and the test named
    /// `a_tail_is_referenced_by_its_entry_and_is_verifys_to_report`.
    pub unreferenced_bytes: u64,
}

impl Summary {
    /// Summarises the archive at `path`, sniffing each payload for a nested
    /// one.
    ///
    /// The empty path is `archive` itself; any other path names an archive
    /// nested inside it, addressed the way every other command addresses one —
    /// `x64/vehicles.rpf`, through as much nesting as it takes. R6.11.
    ///
    /// # Errors
    ///
    /// [`Error::TooDeep`] when a payload nests past [`crate::MAX_DEPTH`], as
    /// [`Archive::locate`] for a path that does not resolve, as
    /// [`Archive::open_nested`] for one that resolves to something that is not
    /// an archive, and as [`Archive::entry`] for an entry table that
    /// contradicts itself.
    pub fn of<R: Read + Seek>(src: &mut R, archive: &Archive, path: &str) -> Result<Self> {
        let holder = archive_at(src, archive, path)?;
        let archive = &holder;
        let entries = count(archive);
        // The header, the entry table and the names blob are referenced too.
        // `payload_floor` is the one place that sum lives, so this cannot drift
        // from where the reader and the writer put the first payload.
        // `docs/rpf-format.md`, Slack, `verified`.
        let mut referenced = archive.version().payload_floor(
            u64::from(entries),
            u64::try_from(archive.names_blob().len()).unwrap_or(u64::MAX),
        );

        let mut directories = 0_u32;
        let mut binary_files = 0_u32;
        let mut resource_files = 0_u32;
        let mut nested_archives = 0_u32;
        let mut locked_archives = 0_u32;
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
            match archive.nested_at(src, index)? {
                Nested::None => {}
                Nested::Open(_) => nested_archives = nested_archives.saturating_add(1),
                Nested::Locked(_) => {
                    nested_archives = nested_archives.saturating_add(1);
                    locked_archives = locked_archives.saturating_add(1);
                }
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
            locked_archives,
            unreferenced_bytes: archive.len_bytes().saturating_sub(referenced),
        })
    }
}

/// The same key failure again, where a problem is carrying one.
///
/// [`Error`] is not `Clone` — it carries an [`std::io::Error`] in two of its
/// variants — and these two are the whole of what a locked nested archive
/// answers, so they are rebuilt from what they carry rather than the enum being
/// widened to allow copying every variant there is.
fn key_failure(error: &Error) -> Option<Error> {
    match *error {
        Error::NeedsKey { tag } => Some(Error::NeedsKey { tag }),
        Error::WrongKey { tag, scheme, tried } => Some(Error::WrongKey { tag, scheme, tried }),
        _ => None,
    }
}

/// One entry that is not as the archive describes it.
///
/// It did not read back at all; or it read back and its payload declares bytes
/// its deflate stream never reached — [`Error::TrailingBytes`], which nothing
/// but this walk looks for, R6.10; or it read back and its contents are not
/// the contents a manifest recorded for it — [`Error::ChecksumMismatch`],
/// DR-023.
#[derive(Debug)]
pub struct Problem {
    /// Where it is, addressed from the outermost archive.
    pub path: String,
    /// What went wrong. The failure itself, not a sentence about it (§10).
    pub error: Error,
}

/// The result of reading every entry back.
///
/// **What a clean result proves depends on which walk produced it.** Every
/// entry is checked against what the archive says about it, and an archive
/// says nothing at all about a stored entry's bytes: no inflated length, no
/// stream that ends. So a clean [`Verified::of`] means every entry read back,
/// which is weaker than every entry being right. [`Verified::contents_checked`]
/// is how far past that a result reaches, and it is zero unless a manifest was
/// given. DR-023.
#[derive(Debug)]
pub struct Verified {
    /// How many file entries were read, the failing ones included.
    pub checked: u32,
    /// How many of them had their contents checked against a recorded
    /// checksum.
    ///
    /// Zero for [`Verified::of`], which is given no manifest, and for a
    /// manifest that recorded none. Never larger than
    /// [`Verified::checked`], and a caller reporting one number without the
    /// other reports more than was measured.
    pub contents_checked: u32,
    /// Those that did not come back as the archive promised.
    pub problems: Vec<Problem>,
}

/// What a [`Verified`] walk carries unchanged from one archive into the ones
/// nested inside it.
///
/// One value rather than five parameters threaded through a recursion: the
/// source, what a checksum was recorded for, the watcher, and how many bytes
/// have come back so far — which is the whole nesting's count, not this
/// archive's.
struct Reading<'a, R, W> {
    /// The source every archive in the nesting is read from.
    src: &'a mut R,
    /// The checksums a manifest recorded, by path. Empty when there is none.
    recorded: &'a BTreeMap<&'a str, Checksum>,
    /// Where progress goes and where a stop comes from. DR-008.
    watch: &'a mut W,
    /// Contents read back so far, across the whole nesting.
    bytes: u64,
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
    /// It is unbounded work and a **bounded** amount of memory: every entry is
    /// read past rather than into memory, so a walk over an archive costs a
    /// buffer per entry rather than the largest entry in it. R3.9, DR-033.
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
        Self::walked(src, archive, &BTreeMap::new(), watch)
    }

    /// [`Verified::of`], and each entry's contents against the checksum the
    /// manifest recorded for its path.
    ///
    /// This is the only walk that can see a **stored** entry's bytes change:
    /// nothing in the archive says what they should be, so nothing in a read
    /// can notice. DR-023.
    ///
    /// Paths are the manifest's own — from the archive's root, as
    /// [`crate::specs_of`] gives them — so a manifest of this archive matches
    /// its entries and a manifest of another matches none of them, which
    /// leaves [`Verified::contents_checked`] at zero rather than reporting
    /// failures. Entries of a *nested* archive are addressed through the file
    /// that holds them and are not in the manifest either; the nested archive
    /// itself is one entry of the outer one, and checking that entry's
    /// contents covers everything inside it at once.
    ///
    /// # Errors
    ///
    /// As [`Verified::of`].
    pub fn against<R: Read + Seek>(
        src: &mut R,
        archive: &Archive,
        manifest: &Manifest,
        watch: &mut impl Watch,
    ) -> Result<Self> {
        Self::walked(src, archive, &manifest.checksums(), watch)
    }

    /// The one walk both entry points are.
    fn walked<R: Read + Seek, W: Watch>(
        src: &mut R,
        archive: &Archive,
        recorded: &BTreeMap<&str, Checksum>,
        watch: &mut W,
    ) -> Result<Self> {
        let mut verified = Self {
            checked: 0,
            contents_checked: 0,
            problems: Vec::new(),
        };
        let mut reading = Reading {
            src,
            recorded,
            watch,
            bytes: 0,
        };
        verified.walk(&mut reading, archive, "")?;
        Ok(verified)
    }

    /// Whether every entry read back, as the failure a frontend reports.
    ///
    /// # Errors
    ///
    /// [`Error::VerifyFailed`] with both counts when anything did not — except
    /// when **every** problem is a key one, which is the archive nested here
    /// that this build could not open. Then the answer is that key failure
    /// itself. DR-010 classifies by who has to act, and the two answers name
    /// different people: `VerifyFailed` is `Category::Corrupt` and says the
    /// bytes are wrong, which they are not.
    pub fn outcome(&self) -> Result<()> {
        let Some(first) = self.problems.first() else {
            return Ok(());
        };
        if let Some(key) = key_failure(&first.error)
            && self
                .problems
                .iter()
                .all(|problem| key_failure(&problem.error).is_some())
        {
            return Err(key);
        }
        Err(Error::VerifyFailed {
            checked: self.checked,
            failed: u32::try_from(self.problems.len()).unwrap_or(u32::MAX),
        })
    }

    /// One archive's entries, then the archives nested in them.
    fn walk<R: Read + Seek, W: Watch>(
        &mut self,
        reading: &mut Reading<'_, R, W>,
        archive: &Archive,
        prefix: &str,
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
            let outcome = archive.read_back(reading.src, index);
            if let Ok(ref payload) = outcome {
                reading.bytes = reading.bytes.saturating_add(payload.len());
            }

            // Reported whether or not it read back, so that `done` and the
            // entries named agree: an entry skipped on the wire while still
            // counted is a gap the watcher cannot account for.
            if reading.watch.step(Step {
                path: &path,
                done,
                total,
                bytes: reading.bytes,
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
            match payload.checked() {
                Err(error) => self.problems.push(Problem {
                    path: path.clone(),
                    error,
                }),
                Ok(()) => self.check_contents(reading, archive, index, &path)?,
            }
            match archive.nested_at(reading.src, index)? {
                Nested::None => {}
                Nested::Open(nested) => self.walk(reading, &nested, &path)?,
                // Reported rather than walked past. DR-033 says a verify reads
                // every entry past, and an archive it could not open is a
                // region it never reached — reporting success over it is the
                // green suite that tested nothing, one layer down.
                Nested::Locked(error) => self.problems.push(Problem { path, error }),
            }
        }
        Ok(())
    }

    /// One entry's contents against the checksum recorded for its path, when
    /// one was.
    ///
    /// What is digested is [`Archive::extracted`]'s answer — the entry as the
    /// file it is outside the archive — which is [`Checksum`]'s own definition
    /// and what makes the value survive a rebuild and match `sha256sum` over an
    /// extracted tree. DR-023.
    ///
    /// That is a second reading of the payload, and a streaming one: the walk
    /// holds no contents to digest, and for a **resource** the two forms differ
    /// anyway — a read inflates it, and the file it is outside the archive
    /// keeps its `RSC7` header and its deflated body. Asking `extracted` for
    /// every kind is one statement of what a recorded checksum is over rather
    /// than two agreeing ones (§3), and it costs the digest rather than the
    /// entry. DR-033.
    ///
    /// # Errors
    ///
    /// As [`Archive::extracted`] for a payload that does not read back the
    /// second time.
    fn check_contents<R: Read + Seek, W: Watch>(
        &mut self,
        reading: &mut Reading<'_, R, W>,
        archive: &Archive,
        index: u32,
        path: &str,
    ) -> Result<()> {
        let Some(&recorded) = reading.recorded.get(path) else {
            return Ok(());
        };
        let found = Checksum::of_stream(&mut archive.extracted(&mut *reading.src, index)?)?;
        self.contents_checked = self.contents_checked.saturating_add(1);
        if found != recorded {
            self.problems.push(Problem {
                path: path.to_owned(),
                error: Error::ChecksumMismatch {
                    entry: index,
                    recorded,
                    found,
                },
            });
        }
        Ok(())
    }
}

/// The archive a path names, from the archive it is addressed within.
///
/// The empty path is `archive` itself, which is what makes one call answer both
/// "summarise this archive" and "summarise the archive at `x64/vehicles.rpf`"
/// (§4). Anything else has to be an archive, so a component that resolves to a
/// directory or to an ordinary file is an error rather than a summary of
/// something that is not one.
///
/// A path that resolves to something that is **not** an archive is refused with
/// the path the caller gave, rather than with the entry index the archive
/// happens to hold it at: `rpf info a.rpf data` reported `entry 1 is a
/// directory, expected a file`, which a caller cannot act on without first
/// working out what entry 1 is. It is the same refusal and the same exit code —
/// one sentence, refilled with the name it was asked by, rather than a second
/// spelling of "this is not an archive" (§3).
///
/// The refill matters most through nesting, where the two differ: an entry
/// inside `x64/inner.rpf` has a path within that archive and a path within the
/// one the caller opened, and only the second is what was typed.
///
/// # Errors
///
/// As [`Archive::locate`] and [`Archive::open_nested`].
fn archive_at<R: Read + Seek>(src: &mut R, archive: &Archive, path: &str) -> Result<Archive> {
    if path.split('/').all(str::is_empty) {
        return Ok(archive.clone());
    }
    let (holder, index) = archive.locate(src, path)?;
    holder.open_nested(src, index).map_err(|error| match error {
        Error::WrongKind { found, wanted, .. } => Error::WrongKind {
            path: path.to_owned(),
            found,
            wanted,
        },
        other => other,
    })
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

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write as _};

    use super::{Listed, ListedKind};
    use crate::{
        archive::Archive,
        build::{FileKind, FileSpec, Storage, build},
        format::Version,
        watch::Unwatched,
    };

    /// A resource whose page flags describe one 512-byte system page and no
    /// graphics pages, followed by a deflate stream of exactly that.
    ///
    /// `docs/rpf-format.md`, Resource page flags, `verified`: the top nibbles
    /// are the header's version field, and the rest decodes to the length.
    fn resource() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"RSC7");
        bytes.extend_from_slice(&162_u32.to_le_bytes());
        bytes.extend_from_slice(&0xA800_0000_u32.to_le_bytes());
        bytes.extend_from_slice(&0x2000_0000_u32.to_le_bytes());
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&vec![0_u8; 512]).expect("deflates");
        bytes.extend_from_slice(&encoder.finish().expect("finishes"));
        bytes
    }

    /// An archive holding one directory, one stored file and one resource.
    fn archive() -> Vec<u8> {
        let files = vec![
            FileSpec {
                path: "data/greeting.txt".to_owned(),
                kind: FileKind::Binary {
                    storage: Storage::Stored,
                    encryption: 0,
                },
            },
            FileSpec {
                path: "art.yft".to_owned(),
                kind: FileKind::Resource,
            },
        ];
        let mut out = Vec::new();
        build(
            &mut Cursor::new(&mut out),
            Version::Rpf7,
            &files,
            &[],
            |wanted: &str| {
                Ok(Cursor::new(if wanted == "art.yft" {
                    resource()
                } else {
                    b"hello there".to_vec()
                }))
            },
            &mut Unwatched,
        )
        .expect("builds");
        out
    }

    #[test]
    fn a_listing_names_each_kind_with_the_number_that_belongs_to_it() {
        let bytes = archive();
        let mut src = Cursor::new(bytes);
        let parsed = Archive::open(&mut src, &crate::keys::Unlock::unkeyed()).expect("parses");

        let rows = Listed::at(&mut src, &parsed, "", true).expect("lists");
        let named = |path: &str| {
            rows.iter()
                .find(|row| row.path == path)
                .unwrap_or_else(|| panic!("{path} is not in {rows:?}"))
                .kind
        };

        // A directory's number is how many children it holds, and a file's is
        // its length: two different facts under one field, which is why they
        // are two variants rather than one nullable number.
        assert_eq!(named("data"), ListedKind::Directory { children: 1 });
        assert_eq!(named("data/greeting.txt"), ListedKind::Binary { len: 11 });

        // The one that cannot be read off the entry row: a resource carries no
        // uncompressed size, so its length is the two flag words decoded.
        // `docs/rpf-format.md`, Resource page flags, `verified`.
        assert_eq!(named("art.yft"), ListedKind::Resource { len: 512 });
    }

    #[test]
    fn a_listing_stops_at_the_directory_it_was_asked_for_unless_told_otherwise() {
        let bytes = archive();
        let mut src = Cursor::new(bytes);
        let parsed = Archive::open(&mut src, &crate::keys::Unlock::unkeyed()).expect("parses");

        let shallow = Listed::at(&mut src, &parsed, "", false).expect("lists");
        let paths: Vec<&str> = shallow.iter().map(|row| row.path.as_str()).collect();
        assert_eq!(paths, ["art.yft", "data"], "the root, and no deeper");

        // And a path names what is under it, addressed from the archive's root
        // rather than from the directory that was asked for.
        let inside = Listed::at(&mut src, &parsed, "data", false).expect("lists");
        let paths: Vec<&str> = inside.iter().map(|row| row.path.as_str()).collect();
        assert_eq!(paths, ["data/greeting.txt"]);
    }
}
