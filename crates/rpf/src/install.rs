//! Detecting a game installation, so that writing into one takes saying so.
//!
//! Editing a shipped archive in place breaks the game's integrity checks, so
//! refusing is an invariant here; this is the detector behind it.

use std::{
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
};

/// Files that only appear in a game installation. Matched case-insensitively.
const EXECUTABLES: &[&str] = &[
    "GTA5.exe",
    "GTA5_Enhanced.exe",
    "PlayGTAV.exe",
    "FiveM.exe",
    "RDR2.exe",
];

/// How far up to look. A `dlc.rpf` sits a few directories below an
/// installation's root; beyond this depth a match is likely a coincidence.
const MAX_ASCENT: usize = 8;

/// What the ascent above an archive found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Detected {
    /// A directory holding a file only a game installation holds.
    Installation(PathBuf),
    /// A directory on the way up that the filesystem would not answer for, so
    /// whether an installation is there is not knowable from here.
    Unexaminable(PathBuf),
}

/// The installation above `path`, or the directory that stopped the ascent from
/// being able to say.
///
/// A false negative costs a broken installation, so a directory that cannot be
/// examined is reported rather than passed over. [`Detected::Installation`]
/// wins over [`Detected::Unexaminable`] wherever both are found.
pub fn detect(path: &Path) -> Option<Detected> {
    let from = resolved(path).unwrap_or_else(|| path.to_path_buf());
    let mut current = from.parent()?;
    let mut unexaminable: Option<PathBuf> = None;
    for _ in 0..MAX_ASCENT {
        match verdict(current) {
            Held::Yes => return Some(Detected::Installation(current.to_path_buf())),
            Held::Unknown if unexaminable.is_none() => {
                unexaminable = Some(current.to_path_buf());
            }
            Held::Unknown | Held::No => {}
        }
        let Some(parent) = current.parent() else {
            break;
        };
        current = parent;
    }
    unexaminable.map(Detected::Unexaminable)
}

/// Whether one directory is an installation, as far as it will say.
fn verdict(directory: &Path) -> Held {
    let named = EXECUTABLES
        .iter()
        .fold(Held::No, |so_far, exe| so_far.or(holds(directory, exe)));
    // A `common.rpf` beside an `x64a.rpf` is a game data directory even when
    // the executable lives a level further up.
    named.or(holds(directory, "common.rpf").and(holds(directory, "x64a.rpf")))
}

/// `path` with the directories above it resolved, so ascending from it climbs
/// the tree the name sits in, or `None` when nothing on the way up resolves.
///
/// A bare `dlc.rpf` would otherwise ascend once and stop, its parent being the
/// empty path. Neither the archive nor any directory above it need exist yet,
/// so the walk climbs until something resolves and joins the rest back on:
/// stopping at the first absent directory leaves a path this cannot ascend,
/// and an installation below it unseen.
pub fn resolved(path: &Path) -> Option<PathBuf> {
    let mut tail: Vec<&OsStr> = Vec::new();
    let mut here: &Path = path;
    for _ in 0..=path.components().count() {
        if let Ok(found) = fs::canonicalize(here) {
            let mut root = found;
            for name in tail.iter().rev() {
                root.push(name);
            }
            return Some(root);
        }
        let name = here.file_name()?;
        tail.push(name);
        here = match here.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
    }
    None
}

/// Whether a name found on disk is the one being looked for.
///
/// The comparison is ours rather than the filesystem's: volumes disagree on
/// folding case, and a case-sensitive one would make this guard fail open.
fn is_named(found: &OsStr, name: &str) -> bool {
    found
        .to_str()
        .is_some_and(|found| found.eq_ignore_ascii_case(name))
}

/// What the filesystem will say about a name in a directory. A question it
/// refuses to answer is not the answer `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    /// The name is there, and is a file.
    Yes,
    /// The name is not there, or is there and is not a file.
    No,
    /// The filesystem would not say.
    Unknown,
}

impl Held {
    /// The stronger of two answers: found beats undiscussable beats absent.
    #[must_use]
    const fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Yes, _) | (_, Self::Yes) => Self::Yes,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::No, Self::No) => Self::No,
        }
    }

    /// Whether both are there, absent only when a half is known to be.
    #[must_use]
    const fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::No, _) | (_, Self::No) => Self::No,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::Yes, Self::Yes) => Self::Yes,
        }
    }
}

/// Whether `directory` holds a file of this name, in any case.
///
/// Listing and comparing by [`is_named`] keeps the answer the same on every
/// platform; a directory that cannot be listed is asked by exact join instead,
/// since the two fail on different permissions. Entries are stat'd through
/// their own path, so a symlinked executable still counts.
fn holds(directory: &Path, name: &str) -> Held {
    let Ok(entries) = fs::read_dir(directory) else {
        return of_path(&directory.join(name));
    };
    entries
        .flatten()
        .filter(|entry| is_named(&entry.file_name(), name))
        .fold(Held::No, |so_far, entry| so_far.or(of_path(&entry.path())))
}

/// What a path says about itself, when it will say anything.
///
/// Only [`io::ErrorKind::NotFound`] is an answer; any other failure is a
/// declined question, and `No` for it would let the guard fail open.
fn of_path(path: &Path) -> Held {
    match path.metadata() {
        Ok(found) if found.is_file() => Held::Yes,
        Ok(_) => Held::No,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Held::No,
        Err(_) => Held::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsStr, fs};

    use super::{Detected, Held, detect, holds, is_named, resolved};

    /// An installation: an executable at the root, an archive below it.
    fn installation(root: &std::path::Path, executable: &str) -> std::path::PathBuf {
        let deep = root.join("mods/update/x64/dlcpacks");
        fs::create_dir_all(&deep).expect("directories");
        fs::write(root.join(executable), b"not really").expect("writable");
        let archive = deep.join("dlc.rpf");
        fs::write(&archive, b"not really").expect("writable");
        archive
    }

    #[test]
    fn directories_that_are_not_there_yet_are_climbed_past_and_joined_back_on() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().canonicalize().expect("canonical");
        let deep = root.join("a/b/c/d/e/dlc.rpf");

        assert_eq!(
            resolved(&deep),
            Some(deep.clone()),
            "five absent directories are still the path under the root",
        );
        fs::create_dir_all(root.join("a/b")).expect("directories");
        assert_eq!(resolved(&deep), Some(deep), "and so are three");
        assert_eq!(
            resolved(std::path::Path::new("")),
            None,
            "nothing resolves for a path that names nothing",
        );
    }

    #[test]
    fn an_executable_is_matched_whatever_case_it_is_spelled_in() {
        for spelling in ["gta5.exe", "GTA5.exe", "GTA5.EXE", "gTa5.ExE"] {
            assert!(
                is_named(OsStr::new(spelling), "GTA5.exe"),
                "{spelling} is the same executable"
            );
        }
        for other in ["GTA4.exe", "GTA5.exe.bak", "GTA5", "xGTA5.exe", ""] {
            assert!(
                !is_named(OsStr::new(other), "GTA5.exe"),
                "{other} is a different file"
            );
        }
    }

    #[test]
    fn an_executable_is_found_through_the_directory_listing() {
        let dir = tempfile::tempdir().expect("temp dir");
        fs::write(dir.path().join("gta5.exe"), b"not really").expect("writable");

        assert_eq!(holds(dir.path(), "GTA5.exe"), Held::Yes);
        assert_eq!(holds(dir.path(), "gta5.exe"), Held::Yes);
        assert_eq!(holds(dir.path(), "GTA4.exe"), Held::No);
        assert_eq!(
            holds(dir.path().join("nowhere").as_path(), "gta5.exe"),
            Held::No,
            "a directory that is not there is an answer, not a refusal to answer",
        );

        // Our fold is ASCII where a case-insensitive volume folds more, so
        // this tells the listing apart from an exact join.
        fs::write(dir.path().join("ÄTA5.exe"), b"not really").expect("writable");
        assert_eq!(
            holds(dir.path(), "äta5.exe"),
            Held::No,
            "the comparison is this crate's rather than the volume's"
        );
    }

    #[test]
    fn a_directory_of_the_right_name_is_not_an_executable() {
        let dir = tempfile::tempdir().expect("temp dir");
        fs::create_dir(dir.path().join("GTA5.exe")).expect("directory");
        assert_eq!(holds(dir.path(), "GTA5.exe"), Held::No);
    }

    #[test]
    fn an_installation_is_found_under_an_executable_spelled_in_any_case() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("Grand Theft Auto V");
        let archive = installation(&root, "gta5.exe");
        assert_eq!(
            detect(&archive),
            Some(Detected::Installation(
                root.canonicalize().expect("canonical")
            )),
        );
    }

    #[test]
    fn an_archive_that_does_not_exist_yet_is_still_placed() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("Grand Theft Auto V");
        let archive = installation(&root, "GTA5.exe");
        let fresh = archive.with_file_name("new.rpf");
        assert!(!fresh.exists());
        assert!(detect(&fresh).is_some());
    }

    /// Directories closed to a question about a name in them. Unix only.
    #[cfg(unix)]
    mod closed {
        use std::{fs, os::unix::fs::PermissionsExt as _, path::Path};

        use super::super::{Detected, Held, detect, holds};

        /// Modes that close a directory to one or both questions [`holds`]
        /// asks.
        const MODES: [u32; 3] = [0o000, 0o111, 0o444];

        /// Sets the mode, and says whether it actually closed the directory:
        /// root and some mounts read a directory whatever its mode says.
        fn closes(directory: &Path, mode: u32) -> bool {
            fs::set_permissions(directory, fs::Permissions::from_mode(mode)).is_ok()
                && (fs::read_dir(directory).is_err()
                    || directory.join("GTA5.exe").metadata().is_err())
        }

        /// A directory holding an executable, at `mode`, if that closes it.
        fn closed_over(mode: u32) -> Option<(tempfile::TempDir, std::path::PathBuf)> {
            let temp = tempfile::tempdir().expect("temp dir");
            let root = temp.path().join("Grand Theft Auto V");
            fs::create_dir(&root).expect("directory");
            fs::write(root.join("GTA5.exe"), b"not really").expect("writable");
            if closes(&root, mode) {
                return Some((temp, root));
            }
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("chmod back");
            None
        }

        #[test]
        fn a_directory_that_cannot_be_examined_is_not_answered_no() {
            for mode in MODES {
                let Some((_temp, root)) = closed_over(mode) else {
                    eprintln!("skipped: mode {mode:04o} does not close a directory here");
                    continue;
                };
                let answer = holds(&root, "GTA5.exe");
                fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("chmod back");
                assert_ne!(
                    answer,
                    Held::No,
                    "mode {mode:04o}: a directory that cannot be examined must not \
                     be reported as one that does not hold the executable"
                );
            }
        }

        #[test]
        fn an_archive_below_a_directory_that_cannot_be_examined_is_still_guarded() {
            for mode in MODES {
                let Some((_temp, root)) = closed_over(mode) else {
                    eprintln!("skipped: mode {mode:04o} does not close a directory here");
                    continue;
                };
                let archive = root.join("dlc.rpf");
                let found = detect(&archive);
                fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("chmod back");
                assert!(
                    matches!(
                        found,
                        Some(Detected::Installation(_) | Detected::Unexaminable(_))
                    ),
                    "mode {mode:04o}: the guard must not wave through what it \
                     could not look at, and got {found:?}"
                );
            }
        }
    }

    #[test]
    fn an_ordinary_directory_is_not_an_installation() {
        let dir = tempfile::tempdir().expect("temp dir");
        let archive = dir.path().join("a/b/c/dlc.rpf");
        fs::create_dir_all(archive.parent().expect("a parent")).expect("directories");
        fs::write(&archive, b"not really").expect("writable");
        assert_eq!(detect(&archive), None);
    }
}
