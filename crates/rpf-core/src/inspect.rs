//! What an archive holds, what it adds up to, and whether it reads back as it describes itself.

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
    /// The whole path, spelled as `Archive::locate` can address it directly.
    pub path: String,
    /// What it is, and the one number that belongs with it.
    pub kind: ListedKind,
}

/// What a listed entry is; only `Binary` carries an encoding, its payload actually read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListedKind {
    /// A directory, and how many children it holds.
    Directory {
        /// Entries directly inside it.
        children: u32,
    },
    /// Plain bytes, their length, and what they announce themselves to be.
    Binary {
        /// The contents' length, outside the archive however it is stored.
        len: u64,
        /// What the first bytes name, or `None` for unknown binary.
        encoding: Option<Encoding>,
    },
    /// A resource, and the length its page flags describe.
    Resource {
        /// Decoded from the row's page flags by `resource_len`.
        len: u64,
    },
}

impl Listed {
    /// Every entry at a path, and everything below it when `recursive`.
    /// # Errors
    /// An unresolved path, one nested past `crate::MAX_DEPTH`, or a self-contradicting table.
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
            // A resource carries no uncompressed size; its length is the two flag words.
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

fn list_into<R: Read + Seek>(
    src: &mut R,
    archive: &Archive,
    at: u32,
    prefix: &str,
    recursive: bool,
    rows: &mut Vec<Listed>,
) -> Result<()> {
    let Ok(children) = archive.children(at) else {
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
    /// How many entries hold an archive of their own, one level down.
    pub nested_archives: u32,
    /// How many of `nested_archives` this build could not open for want of a key.
    pub locked_archives: u32,
    /// Bytes of the archive that no region claims.
    pub unreferenced_bytes: u64,
}

impl Summary {
    /// Summarises the archive at `path`, sniffing each payload for a nested one.
    /// # Errors
    /// A path too deep, unresolved, not an archive, or a self-contradicting table.
    pub fn of<R: Read + Seek>(src: &mut R, archive: &Archive, path: &str) -> Result<Self> {
        let holder = archive_at(src, archive, path)?;
        let archive = &holder;
        let entries = count(archive);
        // `payload_floor` covers the header, entry table and names blob too.
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
                    // Zero means stored, and the other field carries what's on disk.
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

fn key_failure(error: &Error) -> Option<Error> {
    match *error {
        Error::NeedsKey { tag } => Some(Error::NeedsKey { tag }),
        Error::WrongKey { tag, scheme, tried } => Some(Error::WrongKey { tag, scheme, tried }),
        _ => None,
    }
}

/// One entry that is not as the archive describes it.
#[derive(Debug)]
pub struct Problem {
    /// Where it is, addressed from the outermost archive.
    pub path: String,
    /// What went wrong: the failure itself, not a sentence about it.
    pub error: Error,
}

/// The result of reading every entry back; clean means read, not that every byte is right.
#[derive(Debug)]
pub struct Verified {
    /// How many file entries were read, the failing ones included.
    pub checked: u32,
    /// How many had their contents checked against a recorded checksum.
    pub contents_checked: u32,
    /// How many entries did not read back as the archive describes them.
    pub unread: u32,
    /// Those that did not come back as the archive promised.
    pub problems: Vec<Problem>,
}

struct Reading<'a, R, W> {
    src: &'a mut R,
    recorded: &'a BTreeMap<&'a str, Checksum>,
    watch: &'a mut W,
    bytes: u64,
}

impl Verified {
    /// Reads every entry of an archive, and of every archive nested in it.
    /// # Errors
    /// The watcher stops it, or a table contradicts itself; a bad entry is a `Problem`, not this.
    pub fn of<R: Read + Seek>(
        src: &mut R,
        archive: &Archive,
        watch: &mut impl Watch,
    ) -> Result<Self> {
        Self::walked(src, archive, &BTreeMap::new(), watch)
    }

    /// `Verified::of`, checked against a manifest's checksums; a mismatched one matches nothing.
    /// # Errors
    /// As `Verified::of`.
    pub fn against<R: Read + Seek>(
        src: &mut R,
        archive: &Archive,
        manifest: &Manifest,
        watch: &mut impl Watch,
    ) -> Result<Self> {
        Self::walked(src, archive, &manifest.checksums(), watch)
    }

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
    /// # Errors
    /// `VerifyFailed` with both counts, or the key failure itself if every problem was one.
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
            let path = joined(prefix, &archive.path(index)?);

            // Counted before the read: a failed entry was still one that was checked.
            self.checked = self.checked.saturating_add(1);
            done = done.saturating_add(1);
            let outcome = archive.read_back(reading.src, index);
            if let Ok(ref payload) = outcome {
                reading.bytes = reading.bytes.saturating_add(payload.len());
            }

            // Reported whether or not it read back, so `done` and the names agree.
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

            // Reported, then walked past: an archive nested in sound contents still gets read.
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
                Nested::Locked(error) => self.problems.push(Problem { path, error }),
            }
        }
        Ok(())
    }

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

fn count(archive: &Archive) -> u32 {
    u32::try_from(archive.entries().len()).unwrap_or(u32::MAX)
}

fn files_in(archive: &Archive) -> Result<u32> {
    let mut files = 0_u32;
    for index in 0..count(archive) {
        if !archive.entry(index)?.is_directory() {
            files = files.saturating_add(1);
        }
    }
    Ok(files)
}

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

        assert_eq!(named("data"), ListedKind::Directory { children: 1 });
        assert_eq!(
            named("data/greeting.txt"),
            ListedKind::Binary {
                len: 11,
                encoding: Some(Encoding::Text)
            }
        );

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

        let inside = Listed::at(&mut src, &parsed, "data", false).expect("lists");
        let paths: Vec<&str> = inside.iter().map(|row| row.path.as_str()).collect();
        assert_eq!(paths, ["data/greeting.txt"]);
    }
}
