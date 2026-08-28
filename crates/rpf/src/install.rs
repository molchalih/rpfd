//! Detecting a game installation, so that writing into one takes saying so.
//!
//! The tool is driven by automation that will do exactly what it is told, and
//! editing a shipped archive in place breaks the game's own integrity checks.
//! `AGENTS.md` makes refusing an invariant; this is the detector behind it.

use std::{
    ffi::OsStr,
    fs,
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

/// The installation root above `path`, if there is one.
///
/// Deliberately conservative in one direction only: a false positive costs an
/// explicit override, a false negative costs a broken installation.
pub fn detect(path: &Path) -> Option<PathBuf> {
    let resolved = resolve(path);
    let mut current = resolved.parent()?;
    for _ in 0..MAX_ASCENT {
        if EXECUTABLES.iter().any(|exe| holds(current, exe)) {
            return Some(current.to_path_buf());
        }
        // A `common.rpf` beside an `x64a.rpf` is the shape of a game data
        // directory even when the executable lives a level further up.
        if holds(current, "common.rpf") && holds(current, "x64a.rpf") {
            return Some(current.to_path_buf());
        }
        current = current.parent()?;
    }
    None
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

/// Whether `directory` holds a file of this name, in any case.
///
/// The directory is listed and each entry compared by [`is_named`], rather than
/// the name being joined on and stat'd, so the answer is the same on all three
/// platforms.
///
/// The entry is stat'd through its own path rather than through
/// `DirEntry::file_type`, so a symlinked executable still counts as one.
fn holds(directory: &Path, name: &str) -> bool {
    let Ok(entries) = fs::read_dir(directory) else {
        return false;
    };
    entries
        .flatten()
        .any(|entry| is_named(&entry.file_name(), name) && entry.path().is_file())
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsStr, fs};

    use super::{detect, holds, is_named};

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

        assert!(holds(dir.path(), "GTA5.exe"));
        assert!(holds(dir.path(), "gta5.exe"));
        assert!(!holds(dir.path(), "GTA4.exe"));
        assert!(!holds(dir.path().join("nowhere").as_path(), "gta5.exe"));

        // The fold is ours and it is ASCII. A case-insensitive volume folds
        // more than that — measured on this one, `ÄTA5.exe` opens as
        // `äta5.exe` — so on the platform where the first assertion above
        // cannot tell the listing from an exact join, this one can.
        fs::write(dir.path().join("ÄTA5.exe"), b"not really").expect("writable");
        assert!(
            !holds(dir.path(), "äta5.exe"),
            "the comparison is this crate's rather than the volume's"
        );
    }

    #[test]
    fn a_directory_of_the_right_name_is_not_an_executable() {
        let dir = tempfile::tempdir().expect("temp dir");
        fs::create_dir(dir.path().join("GTA5.exe")).expect("directory");
        assert!(!holds(dir.path(), "GTA5.exe"));
    }

    #[test]
    fn an_installation_is_found_under_an_executable_spelled_in_any_case() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("Grand Theft Auto V");
        let archive = installation(&root, "gta5.exe");
        assert_eq!(
            detect(&archive).map(|found| found.canonicalize().expect("canonical")),
            Some(root.canonicalize().expect("canonical")),
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

    #[test]
    fn an_ordinary_directory_is_not_an_installation() {
        let dir = tempfile::tempdir().expect("temp dir");
        let archive = dir.path().join("a/b/c/dlc.rpf");
        fs::create_dir_all(archive.parent().expect("a parent")).expect("directories");
        fs::write(&archive, b"not really").expect("writable");
        assert_eq!(detect(&archive), None);
    }
}
