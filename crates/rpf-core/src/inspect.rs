//! What an archive holds, what it adds up to, and whether it reads back as it
//! describes itself: `ls`, `info` and `verify`, for both frontends. None of
//! them renders anything.

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
    metadata::Encoding,
    watch::{Flow, Step, Watch},
};

/// One entry, as a listing reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    /// Where it is: **the whole path**, spelled as the listed path was, so a
    /// row addresses [`Archive::locate`] as it stands.
    pub path: String,
    /// What it is, and the one number that belongs with it.
    pub kind: ListedKind,
}

/// What a listed entry is, and the number that means something for that kind.
///
/// Only [`ListedKind::Binary`] can carry an encoding: a resource's payload is
/// never read, so a listing cannot claim one for it even by mistake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListedKind {
    /// A directory, and how many children it holds.
    Directory {
        /// Entries directly inside it.
        children: u32,
    },
    /// Plain bytes, how many of them the file is, and what those bytes
    /// announce themselves to be.
    Binary {
        /// The contents' length, which is what the file is outside the
        /// archive whichever way it is stored.
        len: u64,
        /// What the first [`Encoding::HEAD_LEN`] bytes name, or `None` for
        /// unknown binary.
        encoding: Option<Encoding>,
    },
    /// A resource, and the length its page flags describe.
    Resource {
        /// Decoded from the row's page flags by [`resource_len`].
        len: u64,
    },
}

impl Listed {
    /// Every entry at a path, and everything below it when `recursive`.
    ///
    /// The empty path is the root, a nested archive lists what is inside it,
    /// and an ordinary file is one row — which makes this a `stat` too, told
    /// apart by comparing that row's path with the one asked for.
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
    /// listed, at the cost of [`Encoding::HEAD_LEN`] bytes for a binary entry.
    fn of<R: Read + Seek>(src: &mut R, archive: &Archive, index: u32, path: &str) -> Result<Self> {
        let kind = match archive.entry(index)?.kind {
            EntryKind::Directory { child_count, .. } => ListedKind::Directory {
                children: child_count,
            },
            EntryKind::Binary {
                uncompressed_len, ..
            } => ListedKind::Binary {
                len: u64::from(uncompressed_len),
                encoding: archive.classify(src, index)?.encoding(),
            },
            // A resource entry carries no uncompressed size; its length is
            // the two flag words decoded.
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
    // Not a directory: an archive is listed by what is inside it, and anything
    // else is a single entry.
    let Ok(children) = archive.children(at) else {
        // An archive that did not open is listed as the file it also is, its
        // own entries being unreadable. `verify` reports that gap.
        if let Nested::Open(nested) = archive.nested_at(src, at)? {
            return list_into(src, &nested, 0, prefix, recursive, rows);
        }
        rows.push(Listed::of(src, archive, at, prefix)?);
        return Ok(());
    };

    for index in children {
        let path = joined(prefix, archive.name(index)?);
        rows.push(Listed::of(src, archive, index, &path)?);

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
    /// How many entries hold an archive of their own, one level down, whether
    /// this build could open it or not.
    pub nested_archives: u32,
    /// How many of [`Summary::nested_archives`] this build could not open for
    /// want of the right key material, and never more than that count.
    pub locked_archives: u32,
    /// Bytes of the archive that no region claims; an entry's tail is claimed,
    /// so a payload whose stream ends early is `verify`'s to find.
    pub unreferenced_bytes: u64,
}

impl Summary {
    /// Summarises the archive at `path`, sniffing each payload for a nested
    /// one; the empty path is `archive` itself.
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
        // The header, the entry table and the names blob are referenced too,
        // and `payload_floor` is the one place that sum lives.
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
                    // field carries what is on disk.
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

/// The same key failure again, rebuilt from what it carries because [`Error`]
/// is not `Clone`.
fn key_failure(error: &Error) -> Option<Error> {
    match *error {
        Error::NeedsKey { tag } => Some(Error::NeedsKey { tag }),
        Error::WrongKey { tag, scheme, tried } => Some(Error::WrongKey { tag, scheme, tried }),
        _ => None,
    }
}

/// One entry that is not as the archive describes it: it did not read back, or
/// its payload declares bytes its stream never reached, or its contents are not
/// what a manifest recorded.
#[derive(Debug)]
pub struct Problem {
    /// Where it is, addressed from the outermost archive.
    pub path: String,
    /// What went wrong: the failure itself, not a sentence about it.
    pub error: Error,
}

/// The result of reading every entry back.
///
/// An archive says nothing about a stored entry's bytes, so a clean
/// [`Verified::of`] means every entry read back and not that every entry is
/// right.
#[derive(Debug)]
pub struct Verified {
    /// How many file entries were read, the failing ones included.
    pub checked: u32,
    /// How many of them had their contents checked against a recorded
    /// checksum, which is zero without a manifest and never more than
    /// [`Verified::checked`].
    pub contents_checked: u32,
    /// How many entries did not read back as the archive describes them, and
    /// so had no contents to check against a recorded checksum; a checksum
    /// that was checked and *mismatched* is not one of these.
    pub unread: u32,
    /// Those that did not come back as the archive promised.
    pub problems: Vec<Problem>,
}

/// What a [`Verified`] walk carries unchanged from one archive into the ones
/// nested inside it, rather than five parameters through a recursion.
struct Reading<'a, R, W> {
    /// The source every archive in the nesting is read from.
    src: &'a mut R,
    /// The checksums a manifest recorded, by path. Empty when there is none.
    recorded: &'a BTreeMap<&'a str, Checksum>,
    /// Where progress goes and where a stop comes from.
    watch: &'a mut W,
    /// Contents read back so far, across the whole nesting.
    bytes: u64,
}

impl Verified {
    /// Reads every entry of an archive, and of every archive nested in it.
    ///
    /// Unbounded work, so it takes a [`Watch`] seam and stops when told to,
    /// counting the archive being read now rather than the whole nesting.
    /// Bounded memory: every entry is read past rather than into memory.
    ///
    /// # Errors
    ///
    /// [`Error::Cancelled`] when the watcher stops it, and as
    /// [`Archive::entry`] for an entry table that contradicts itself. An entry
    /// that does not read back is a [`Problem`] rather than an error.
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
    /// The only walk that can see a **stored** entry's bytes change. Paths are
    /// the manifest's own, so a manifest of another archive matches nothing and
    /// leaves [`Verified::contents_checked`] at zero rather than failing.
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
            unread: 0,
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
    /// when **every** problem is a key one, where the answer is that key
    /// failure itself, the bytes not being what is wrong.
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
            // The whole path within this archive, not the entry's own name,
            // so that a report names something a caller can pass back.
            let path = joined(prefix, &archive.path(index)?);

            // Counted before the read: an entry that failed was still one of
            // the entries checked.
            self.checked = self.checked.saturating_add(1);
            done = done.saturating_add(1);
            let outcome = archive.read_back(reading.src, index);
            if let Ok(ref payload) = outcome {
                reading.bytes = reading.bytes.saturating_add(payload.len());
            }

            // Reported whether or not it read back, so that `done` and the
            // entries named agree.
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
                    self.unread = self.unread.saturating_add(1);
                    self.problems.push(Problem { path, error });
                    continue;
                }
                Ok(payload) => payload,
            };

            // Reported and then walked past: an archive nested in sound
            // contents is still read back.
            match payload.checked() {
                Err(error) => {
                    self.unread = self.unread.saturating_add(1);
                    self.problems.push(Problem {
                        path: path.clone(),
                        error,
                    });
                }
                Ok(()) => self.check_contents(reading, archive, index, &path)?,
            }
            match archive.nested_at(reading.src, index)? {
                Nested::None => {}
                Nested::Open(nested) => self.walk(reading, &nested, &path)?,
                // Reported rather than walked past: an archive that could not
                // be opened is a region the walk never reached.
                Nested::Locked(error) => self.problems.push(Problem { path, error }),
            }
        }
        Ok(())
    }

    /// One entry's contents against the checksum recorded for its path, when
    /// one was.
    ///
    /// What is digested is [`Archive::extracted`]'s answer, the entry as the
    /// file it is outside the archive, which is what makes the value match
    /// `sha256sum` over an extracted tree. That is a second, streaming read,
    /// and for a resource the two forms differ.
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
/// The empty path is `archive` itself; anything else has to be an archive. The
/// refusal is refilled with the path the caller gave rather than the entry
/// index, which through nesting is the only one that was typed.
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

    use super::{Encoding, Listed, ListedKind};
    use crate::{
        archive::Archive,
        build::{FileKind, FileSpec, Storage, build},
        format::Version,
        watch::Unwatched,
    };

    /// A resource whose page flags describe one 512-byte system page and no
    /// graphics pages, followed by a deflate stream of exactly that.
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
                kind: FileKind::Resource { declared: None },
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
        // its length: two facts, and so two variants.
        assert_eq!(named("data"), ListedKind::Directory { children: 1 });
        assert_eq!(
            named("data/greeting.txt"),
            ListedKind::Binary {
                len: 11,
                encoding: Some(Encoding::Text)
            }
        );

        // A resource carries no uncompressed size, so its length is the two
        // flag words decoded, and no encoding, the variant having none.
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

        // And a path names what is under it, from the archive's root.
        let inside = Listed::at(&mut src, &parsed, "data", false).expect("lists");
        let paths: Vec<&str> = inside.iter().map(|row| row.path.as_str()).collect();
        assert_eq!(paths, ["data/greeting.txt"]);
    }
}
