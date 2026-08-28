//! Detecting a game installation, so that writing into one takes saying so.
//!
//! The tool is driven by automation that will do exactly what it is told, and
//! editing a shipped archive in place breaks the game's own integrity checks.
//! `AGENTS.md` makes refusing an invariant; this is the detector behind it.

use std::{
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
};

/// Files that only appear in a game installation.
///
/// Matched case-insensitively, so the spelling here is only the canonical one.
const EXECUTABLES: &[&str] = &[
    "GTA5.exe",
    "GTA5_Enhanced.exe",
    "PlayGTAV.exe",
    "FiveM.exe",
    "RDR2.exe",
];

/// How far up to look. A `dlc.rpf` sits a few directories below the root of an
/// installation; beyond this depth a match is more likely a coincidence.
const MAX_ASCENT: usize = 8;

/// What the ascent above an archive found.
///
/// Two answers rather than one path, because "this is an installation" and
/// "this could not be looked at" are different things to tell a caller, and a
/// refusal that named the second as the first would assert something nothing
/// measured (§10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Detected {
    /// A directory holding a file only a game installation holds.
    Installation(PathBuf),
    /// A directory on the way up that the filesystem would not answer
    /// questions about, so whether an installation is there is not knowable
    /// from here.
    Unexaminable(PathBuf),
}

/// The installation above `path`, or the directory that stopped the ascent
/// from being able to say.
///
/// Deliberately conservative in one direction only: a false positive costs an
/// explicit override, a false negative costs a broken installation. A
/// directory that cannot be examined is therefore reported rather than passed
/// over — the whole guard is a negative answer, and one that came from a
/// question the filesystem refused is not an answer at all.
///
/// [`Detected::Installation`] wins over [`Detected::Unexaminable`] wherever
/// both are found, because a directory named outright says more than one that
/// could not be looked at below it.
pub fn detect(path: &Path) -> Option<Detected> {
    let resolved = resolve(path);
    let mut current = resolved.parent()?;
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
    // A `common.rpf` beside an `x64a.rpf` is the shape of a game data
    // directory even when the executable lives a level further up.
    named.or(holds(directory, "common.rpf").and(holds(directory, "x64a.rpf")))
}

/// `path` with the directories above it resolved, so that ascending from it
/// climbs the tree the name actually sits in.
///
/// Without this a bare `dlc.rpf` ascends exactly once and stops, because
/// `Path::new("dlc.rpf").parent()` is the empty path — so the guard never saw
/// the installation it was standing in. The archive itself may not exist yet,
/// which is the ordinary case for `pack`, so the directory is resolved rather
/// than the file, and a path that resolves to nothing is ascended as it was
/// given rather than abandoned.
fn resolve(path: &Path) -> PathBuf {
    if let Ok(canonical) = fs::canonicalize(path) {
        return canonical;
    }
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    match (fs::canonicalize(parent), path.file_name()) {
        (Ok(canonical), Some(name)) => canonical.join(name),
        _ => path.to_path_buf(),
    }
}

/// Whether a name found on disk is the one being looked for.
///
/// The comparison is ours rather than the filesystem's, and that is the whole
/// point of it: NTFS and the default macOS volume fold case and ext4 does not,
/// so `directory.join(name).is_file()` gives three answers to one question. A
/// Proton or Wine installation sits on a case-sensitive volume and spells its
/// executable however the copy it came from did, so the exact join misses it —
/// and this guard then fails open, which `detect` above names as the expensive
/// direction. R10.10.
///
/// Separated from [`holds`] because it is the half a test can pin directly. On
/// a case-insensitive volume the filesystem answers `true` for either spelling
/// of an ASCII name, so a test that only asserts `holds(dir, "GTA5.exe")`
/// against a `gta5.exe` passes whether the fold is here or not — which is what
/// the test that used to stand here was doing.
fn is_named(found: &OsStr, name: &str) -> bool {
    found
        .to_str()
        .is_some_and(|found| found.eq_ignore_ascii_case(name))
}

/// What the filesystem will say about a name in a directory.
///
/// Three answers rather than two, because a question the filesystem refuses to
/// answer is not the answer `false` (§4). Every "no" this guard acts on is a
/// reason to write into a directory, so a "no" invented out of a permission
/// error is the one failure direction the module opens with.
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
    /// The stronger of two answers about the same directory: a name found
    /// beats one the filesystem would not discuss, which beats one that is
    /// not there.
    #[must_use]
    const fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Yes, _) | (_, Self::Yes) => Self::Yes,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::No, Self::No) => Self::No,
        }
    }

    /// Whether both are there. A pair is only present when both halves are,
    /// and only absent when a half is known to be.
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
/// The directory is listed and each entry compared by [`is_named`], rather than
/// the name being joined on and stat'd, so the answer is the same on all three
/// platforms.
///
/// A directory that cannot be listed is asked the other way — the exact join
/// this replaced — because the two fail on different permissions and neither
/// subsumes the other. Measured 2026-08-28 on macOS, one `GTA5.exe` inside:
/// mode `111` refuses the listing and answers the join, mode `444` answers the
/// listing and refuses the stat, and mode `000` refuses both. All three used to
/// answer `false`, and the first two are the case-fold's own trade rather than
/// a limit of the filesystem.
///
/// The entry is stat'd through its own path rather than through
/// `DirEntry::file_type`, so a symlinked executable still counts as one.
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
/// Only [`io::ErrorKind::NotFound`] is an answer; every other failure is the
/// filesystem declining the question, and answering `No` for it is what let a
/// directory nobody could look into pass for one with no game in it.
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

    use super::{Detected, Held, detect, holds, is_named};

    /// An installation: an executable at the root, and an archive some way
    /// below it.
    fn installation(root: &std::path::Path, executable: &str) -> std::path::PathBuf {
        let deep = root.join("mods/update/x64/dlcpacks");
        fs::create_dir_all(&deep).expect("directories");
        fs::write(root.join(executable), b"not really").expect("writable");
        let archive = deep.join("dlc.rpf");
        fs::write(&archive, b"not really").expect("writable");
        archive
    }

    #[test]
    fn an_executable_is_matched_whatever_case_it_is_spelled_in() {
        // The fold itself, not a round trip through the filesystem. The test
        // this replaces wrote `gta5.exe` and asserted `holds(dir, "GTA5.exe")`,
        // which on the case-insensitive volume this runs on is `true` for the
        // exact join it was written to replace: it passed either way and so
        // pinned nothing. R10.10.
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

        // The fold is ours and it is ASCII. A case-insensitive volume folds
        // more than that — measured on this one, `ÄTA5.exe` opens as
        // `äta5.exe` — so on the platform where the first assertion above
        // cannot tell the listing from an exact join, this one can.
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
        // `pack` writes an archive that is not there to canonicalise, and the
        // directory it will sit in is what the guard is about.
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("Grand Theft Auto V");
        let archive = installation(&root, "GTA5.exe");
        let fresh = archive.with_file_name("new.rpf");
        assert!(!fresh.exists());
        assert!(detect(&fresh).is_some());
    }

    /// The three ways a directory can be closed to a question about a name in
    /// it. Unix only, because a mode is what makes one.
    #[cfg(unix)]
    mod closed {
        use std::{fs, os::unix::fs::PermissionsExt as _, path::Path};

        use super::super::{Detected, Held, detect, holds};

        /// Measured 2026-08-28 in a tempdir on macOS, one `GTA5.exe` inside:
        ///
        /// | mode | `read_dir` | listed names | join stat | was | is |
        /// |---|---|---|---|---|---|
        /// | `000` | denied | — | denied | `false` | `Unknown` |
        /// | `111` | denied | — | file | `false` | `Yes` |
        /// | `444` | ok | `GTA5.exe` | denied | `false` | `Unknown` |
        ///
        /// Only `111` is the trade the case-fold made — the exact join it
        /// replaced answered `true` there. The other two were never right and
        /// were never noticed; `444` had the name in its hand and threw it away
        /// on a stat it was not allowed to make. What the tests below assert is
        /// the property behind all three: never a confident `No` from a
        /// question that was refused.
        const MODES: [u32; 3] = [0o000, 0o111, 0o444];

        /// Sets the mode, and says whether it actually closed the directory.
        ///
        /// Asked of the filesystem rather than of the user id: root reads
        /// every directory whatever its mode says, and so do some mounts, and
        /// there the test has nothing to reproduce. A directory is closed when
        /// it refuses at least one of the two questions [`holds`] asks.
        fn closes(directory: &Path, mode: u32) -> bool {
            fs::set_permissions(directory, fs::Permissions::from_mode(mode)).is_ok()
                && (fs::read_dir(directory).is_err()
                    || directory.join("GTA5.exe").metadata().is_err())
        }

        /// A directory holding an executable, at `mode`, with what it is worth
        /// asking of it.
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
