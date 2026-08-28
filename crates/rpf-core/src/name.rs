//! What an entry path may be, so that one archive is one tree everywhere.
//!
//! An archive is third-party data (§6), and its entry names are the part of it
//! that becomes filesystem paths. `extract` joins a name onto a target
//! directory and `pack` joins one onto a source tree, so a name the host
//! resolves as anything other than one file below that directory reads and
//! writes outside it. Measured: an entry named `../escaped.txt` extracted one
//! level above the target and reported `1 files … into <target>`, exit 0, and
//! packing the same manifest read a file from above the tree.
//!
//! Refused by name, never rewritten. A quiet rewrite leaves `extract` and
//! `pack` disagreeing about what a tree holds, which is the silent loss the
//! refusal exists to replace.
//!
//! **Two rules, because they answer two questions.** [`check_tree`] asks
//! whether a path can be one node in an archive's own tree. That is a property
//! of how this crate addresses, so it holds wherever a name is used at all,
//! `build` and `rebuild` included: a name that `Archive::locate` cannot address
//! is unreachable in an archive this tool wrote as much as in one it read.
//! [`check_host`] asks whether the path can be one file on a filesystem. That
//! is a fact about filesystems, and it is asked only where one is touched —
//! `extract` and `pack`, which is [`crate::Manifest`] in both directions. A
//! rebuild is bytes in and bytes out and never names a file, so asking it there
//! bought nothing and cost the ability to repair an archive this tool can
//! otherwise read.
//!
//! **Neither rule consults the platform it is running on.** A name Windows
//! cannot hold is refused on macOS and Linux too, because a name accepted on
//! one and refused on another is one archive extracting to two trees — the
//! divergence R10 exists to remove. The names that platform silently *edits*
//! are refused on the same terms: it trims a trailing dot or space before it
//! opens a path, so `a.txt.` and `a.txt` are one file there, and
//! [`check_host`] refuses the spelling rather than letting one archive become
//! two trees. DR-015.
//!
//! DR-013 and its second amendment, which record what each rule costs and which
//! alternatives each beat, and DR-015 for why the trim is a host rule and not a
//! tree one.

use crate::{
    error::{Error, Result},
    manifest::MANIFEST_NAME,
};

/// The longest one component of an entry path may be, in bytes.
///
/// The component limit of NTFS, APFS and every Linux filesystem in common use,
/// so it is the largest length that means the same thing on all three.
pub const MAX_COMPONENT_LEN: usize = 255;

/// The longest a whole entry path may be, in bytes.
///
/// macOS's `PATH_MAX` is the smallest of the three. A target directory is
/// joined in front of this, so it is a ceiling on the archive's half rather
/// than a promise that any particular extraction fits.
pub const MAX_PATH_LEN: usize = 1024;

/// Names the Win32 API resolves to a device rather than to a file, in any
/// directory and with any extension after them.
///
/// Extending rather than shrinking with time is the safe direction: a name
/// that stops being a device merely stays refused. `CONIN$`, `CONOUT$` and
/// `CLOCK$` were missing and are the list taking its own advice.
const DEVICES: &[&str] = &[
    "con", "prn", "aux", "nul", "conin$", "conout$", "clock$", "com0", "com1", "com2", "com3",
    "com4", "com5", "com6", "com7", "com8", "com9", "lpt0", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5",
    "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Printable characters no NTFS name may hold.
///
/// `/` is absent because it is this crate's separator and never reaches a
/// component. `\` is absent because it is refused earlier, by [`check_tree`],
/// and for a different reason: it is not that a filesystem will not hold it,
/// it is that Windows reads it as a separator, so such a name is not one node
/// of a tree there at all.
const ILLEGAL: &[char] = &[':', '*', '?', '<', '>', '|', '"'];

/// Refuses an entry path that could not be one node in an archive's tree.
///
/// Paths are separated by `/`, which is how this crate addresses (§7), and
/// checked whole: `a/../b` is refused for its second component whether that
/// component arrived as a component or inside one entry's name.
///
/// These are the rules `Archive::locate` needs to be able to address the name
/// at all, so they hold on every path this crate is given — read or written,
/// extracted or rebuilt. A name a host would open as a *different* file is not
/// one of them, however badly it diverges there: it is still one node of this
/// tree, and it is [`check_host`]'s. DR-015.
///
/// # Errors
///
/// [`Error::BadPath`], carrying the path and which of the rules it broke.
pub fn check_tree(path: &str) -> Result<()> {
    if path.is_empty() {
        return refuse(path, "is empty");
    }
    // Both spellings of "from the root": POSIX takes the first, and Windows
    // takes either — `\evil.txt` is the root of the current drive. A drive
    // letter and a UNC share are refused by [`check_host`].
    if path.starts_with('/') || path.starts_with('\\') {
        return refuse(path, "is an absolute path");
    }

    for component in path.split('/') {
        if component.is_empty() {
            return refuse(path, "has an empty component");
        }
        if component == "." || component == ".." {
            return refuse(path, "navigates with . or .. rather than naming a file");
        }
        // Windows reads `\` as a separator, so a component holding one is not
        // one node of a tree there however it reads here. Measured before this
        // was refused: `pack` accepted `..\escaped.txt` as one legal component,
        // exit 0, and `Path::join` would have climbed out of the target with it
        // at whatever depth the name asked for. Whether `\` should instead be
        // *accepted* as a separator is a different question and still open —
        // `docs/backlog.md` R10.6.
        if component.contains('\\') {
            return refuse(
                path,
                "has a component holding \\, which is a separator on Windows",
            );
        }
    }
    Ok(())
}

/// Refuses an entry path that could not be one file below a directory on a
/// host filesystem.
///
/// The rules a filesystem imposes rather than the ones the archive's own tree
/// does, so this is asked where a name becomes a path on disk and nowhere else:
/// `extract` and `pack`, both of which go through [`crate::Manifest`]. It does
/// not repeat [`check_tree`], which every caller of this has already been
/// through.
///
/// # Errors
///
/// [`Error::BadPath`], carrying the path and which of the rules it broke.
pub fn check_host(path: &str) -> Result<()> {
    if path.len() > MAX_PATH_LEN {
        return refuse(path, "is longer than a path may be");
    }
    // `extract` puts the sidecar manifest at the root of the tree it writes,
    // and `pack` reads the manifest from that same name. An entry named it was
    // destroyed by the one and read twice over by the other, both exit 0:
    // measured, `extract` reported "2 files" and the file on disk held the
    // manifest rather than the entry's 218 bytes. A collision with a file this
    // tool puts on the filesystem is a host rule, so it is not `rebuild`'s.
    if path == MANIFEST_NAME {
        return refuse(path, "is the name the sidecar manifest takes in a tree");
    }

    for component in path.split('/') {
        if component.len() > MAX_COMPONENT_LEN {
            return refuse(path, "has a component longer than a name may be");
        }
        if component.contains(ILLEGAL) || component.bytes().any(|byte| byte < 0x20) {
            return refuse(
                path,
                "has a component holding a character no file name may hold",
            );
        }
        if is_device(component) {
            return refuse(path, "has a component that names a Windows device");
        }
        // Windows trims a trailing dot or space from every component before it
        // opens a path, so `a.txt.` and `a.txt ` are the file `a.txt` there and
        // two further entries here — one archive, two trees, which is the
        // divergence R10 exists to remove. Refused rather than trimmed for the
        // reason the module opens with: a trim is a rewrite, and a rewrite
        // leaves `extract` and `pack` disagreeing about what the tree holds.
        // It covers `.. ` and `...` as well, without this having to know which
        // reading Windows gives them, because either reading is refused.
        // DR-015.
        if component.ends_with('.') || component.ends_with(' ') {
            return refuse(
                path,
                "has a component ending in a dot or a space, which Windows trims",
            );
        }
    }
    Ok(())
}

/// The refusal both rules report.
fn refuse(path: &str, reason: &'static str) -> Result<()> {
    Err(Error::BadPath {
        path: path.to_owned(),
        reason,
    })
}

/// Whether the Win32 API would resolve this component to a device.
///
/// The extension is not part of the match — `aux.ytd` opens `AUX` — and
/// trailing spaces are dropped before the name is looked at, so `con ` is
/// `CON` as well.
fn is_device(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component).trim_end();
    DEVICES
        .iter()
        .any(|device| stem.eq_ignore_ascii_case(device))
}

#[cfg(test)]
mod tests {
    use super::{MAX_COMPONENT_LEN, MAX_PATH_LEN, check_host, check_tree};
    use crate::{error::Error, manifest::MANIFEST_NAME};

    /// The reason a rule refused a path for, or `None` if it accepted it.
    fn refusal(rule: fn(&str) -> crate::error::Result<()>, path: &str) -> Option<&'static str> {
        match rule(path) {
            Ok(()) => None,
            Err(Error::BadPath { reason, .. }) => Some(reason),
            Err(other) => panic!("expected BadPath, got {other:?}"),
        }
    }

    /// The reason the tree rule refused a path for.
    fn tree(path: &str) -> Option<&'static str> {
        refusal(check_tree, path)
    }

    /// The reason the host rule refused a path for.
    fn host(path: &str) -> Option<&'static str> {
        refusal(check_host, path)
    }

    /// The refusal for a name Windows would trim, quoted once rather than in
    /// each of the five tests that assert it.
    const TRIMMED: Option<&str> =
        Some("has a component ending in a dot or a space, which Windows trims");

    #[test]
    fn an_ordinary_path_is_accepted_by_both_rules() {
        for path in [
            "a.txt",
            "x64/vehicles.rpf",
            "data/levels/gta5/vehicles.meta",
            "a b.txt",
            "ä.txt",
        ] {
            assert_eq!(tree(path), None, "{path} should be one node in a tree");
            assert_eq!(host(path), None, "{path} should be one file on a host");
        }
    }

    #[test]
    fn a_path_that_climbs_out_of_the_tree_is_refused() {
        // The reproduction: `pack` read a file above the tree it was given and
        // `extract` wrote one above the target, both silently and both exit 0.
        for path in ["..", "../escaped.txt", "a/../../escaped.txt", "a/.."] {
            assert_eq!(
                tree(path),
                Some("navigates with . or .. rather than naming a file"),
                "{path}",
            );
        }
    }

    #[test]
    fn a_dot_component_is_refused_because_two_paths_would_be_one_file() {
        // `./a.txt` and `a.txt` join to the same file, so an archive holding
        // both extracts as one and packs back as two.
        assert_eq!(
            tree("./a.txt"),
            Some("navigates with . or .. rather than naming a file"),
        );
    }

    #[test]
    fn a_component_holding_a_backslash_is_refused() {
        // Reproduced before this was refused: `pack` took `..\\escaped.txt` as
        // one legal component and exited 0. On Windows `Path::join` reads it as
        // two, so `extract` writes above the target and `pack` reads above the
        // tree — the defect DR-013 opens with, at arbitrary depth. It also
        // disarms the device rule, since the stem of `x64\\aux.ytd` is
        // `x64\\aux`, and the component-length rule with it.
        for path in [
            "..\\escaped.txt",
            "a/..\\..\\escaped.txt",
            "x64\\evil.txt",
            "x64\\aux.ytd",
        ] {
            assert_eq!(
                tree(path),
                Some("has a component holding \\, which is a separator on Windows"),
                "{path}",
            );
        }
    }

    #[test]
    fn an_absolute_path_in_either_spelling_is_refused() {
        // `Path::join` discards the base outright for an absolute name, so
        // this is the case that wrote to an absolute path and exited 0.
        for path in ["/etc/passwd", "\\Windows\\evil.txt", "\\\\server\\share\\x"] {
            assert_eq!(tree(path), Some("is an absolute path"), "{path}");
        }
    }

    #[test]
    fn an_empty_path_and_an_empty_component_are_refused() {
        assert_eq!(tree(""), Some("is empty"));
        assert_eq!(tree("a//b.txt"), Some("has an empty component"));
        assert_eq!(tree("a/"), Some("has an empty component"));
    }

    #[test]
    fn a_drive_letter_is_refused_as_an_illegal_character() {
        // `C:/evil.txt` is not caught by the leading-separator rule, and the
        // colon is what makes it a drive rather than a directory named `C`.
        assert_eq!(
            host("C:/evil.txt"),
            Some("has a component holding a character no file name may hold"),
        );
    }

    #[test]
    fn a_windows_device_name_is_refused_whatever_follows_it() {
        for path in [
            "con",
            "AUX",
            "nul.ytd",
            "x64/com1.meta",
            "lpt9.txt",
            "con ",
            "CONIN$",
            "conout$.txt",
            "CLOCK$",
        ] {
            assert_eq!(
                host(path),
                Some("has a component that names a Windows device"),
                "{path}",
            );
        }
    }

    #[test]
    fn a_name_that_merely_starts_like_a_device_is_accepted() {
        for path in ["console.txt", "connect/aux2.meta", "com.txt", "nulls"] {
            assert_eq!(host(path), None, "{path}");
        }
    }

    #[test]
    fn every_character_ntfs_refuses_is_refused() {
        for illegal in [':', '*', '?', '<', '>', '|', '"', '\u{0}', '\u{1f}'] {
            let path = format!("a{illegal}b.txt");
            assert_eq!(
                host(&path),
                Some("has a component holding a character no file name may hold"),
                "{illegal:?}",
            );
        }
    }

    #[test]
    fn an_over_long_path_and_an_over_long_component_are_refused() {
        let component = "n".repeat(MAX_COMPONENT_LEN.saturating_add(1));
        assert_eq!(
            host(&component),
            Some("has a component longer than a name may be"),
        );
        assert_eq!(host(&"n".repeat(MAX_COMPONENT_LEN)), None);

        let deep = vec!["nnnn"; MAX_PATH_LEN].join("/");
        assert_eq!(host(&deep), Some("is longer than a path may be"));
    }

    #[test]
    fn the_sidecar_manifest_s_own_name_is_refused_at_the_root() {
        // `extract` writes every entry and then writes the manifest over the
        // top of whatever is at that name; `pack` reads the same name as the
        // manifest and as an entry payload. Both were exit 0.
        assert_eq!(
            host(MANIFEST_NAME),
            Some("is the name the sidecar manifest takes in a tree"),
        );
        // Only at the root: nothing is written at that name anywhere else.
        assert_eq!(host(&format!("data/{MANIFEST_NAME}")), None);
    }

    #[test]
    fn a_component_ending_in_a_dot_is_refused() {
        // Windows drops trailing dots before it opens a name, so `a.txt.` and
        // `a.txt` are one file there and two entries here: one archive, two
        // trees, which is the divergence R10 exists to remove. Refused rather
        // than trimmed, because a trim is the silent rewrite this module
        // exists to replace. R10.12, DR-015.
        for path in ["a.txt.", "a.txt...", "a.", "x64/vehicles./a.txt", "a.txt ."] {
            assert_eq!(host(path), TRIMMED, "{path}");
        }
    }

    #[test]
    fn a_component_ending_in_a_space_is_refused() {
        // The same trim, in its other spelling: `a.txt ` opens `a.txt`.
        for path in ["a.txt ", "a.txt  ", " ", "x64/vehicles /a.txt", "a.txt. "] {
            assert_eq!(host(path), TRIMMED, "{path}");
        }
    }

    #[test]
    fn a_name_that_would_trim_to_a_climb_out_of_the_tree_is_refused() {
        // `check_tree` refuses `..` as the exact string, and these are not it
        // here. On Windows the trim happens before the path is read, so they
        // may be `..` there. The rule refuses them without having to know
        // which reading that platform gives `...`, which is what lets it be
        // stated without a Windows measurement.
        for path in ["...", ".. ", ". ", "a/.. /b.txt"] {
            assert_eq!(tree(path), None, "{path} is one node in a tree here");
            assert_eq!(host(path), TRIMMED, "{path}");
        }
    }

    #[test]
    fn a_name_that_would_trim_to_the_sidecar_manifest_s_own_name_is_refused() {
        // The manifest rule compares the whole path, so a trailing dot walks
        // past it and Windows puts the file back at the name it guards.
        assert_eq!(host(&format!("{MANIFEST_NAME}.")), TRIMMED);
    }

    #[test]
    fn a_dot_or_a_space_anywhere_but_the_end_is_accepted() {
        // The rule is about what the platform edits, which is the end of a
        // component and nothing else.
        for path in [".gitignore", "a. b.txt", "x64/.hidden/a b.c", " a.txt"] {
            assert_eq!(host(path), None, "{path}");
        }
    }

    #[test]
    fn neither_rule_answers_the_other_s_question() {
        // The split is the point of having two: a name a filesystem cannot hold
        // is still one node of an archive's tree, so a rebuild that never
        // touches a filesystem is not stopped by it. DR-013's second amendment.
        for path in [
            "aux.ytd",
            "a:b.txt",
            "a.txt.",
            "a.txt ",
            &"n".repeat(MAX_COMPONENT_LEN + 1),
        ] {
            assert_eq!(tree(path), None, "{path} is one node in a tree");
            assert!(host(path).is_some(), "{path} is not one file on a host");
        }
        for path in ["../escaped.txt", "/etc/passwd", "a//b.txt"] {
            assert!(tree(path).is_some(), "{path} is not one node in a tree");
        }
    }
}
