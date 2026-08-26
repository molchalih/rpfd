//! Detecting a game installation, so that writing into one takes saying so.
//!
//! The tool is driven by automation that will do exactly what it is told, and
//! editing a shipped archive in place breaks the game's own integrity checks.
//! `AGENTS.md` makes refusing an invariant; this is the detector behind it.

use std::path::{Path, PathBuf};

/// Files that only appear in a game installation.
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
    let mut current = path.parent()?;
    for _ in 0..MAX_ASCENT {
        if EXECUTABLES.iter().any(|exe| current.join(exe).is_file()) {
            return Some(current.to_path_buf());
        }
        // A `common.rpf` beside an `x64a.rpf` is the shape of a game data
        // directory even when the executable lives a level further up.
        if current.join("common.rpf").is_file() && current.join("x64a.rpf").is_file() {
            return Some(current.to_path_buf());
        }
        current = current.parent()?;
    }
    None
}
