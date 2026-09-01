//! What an entry path may be, so that one archive is one tree everywhere.
//!
//! [`check_tree`] asks whether a path can be one node in an archive's own tree
//! and [`check_host`] whether it can be one file on a filesystem; names are
//! refused rather than rewritten, on every platform alike.

use crate::{
    error::{Error, Result},
    manifest::MANIFEST_NAME,
};

/// The longest one component of an entry path may be, in bytes.
///
/// The component limit of NTFS, APFS and every Linux filesystem in common use.
pub const MAX_COMPONENT_LEN: usize = 255;

/// The longest a whole entry path may be, in bytes: macOS's `PATH_MAX`, the
/// smallest of the three, with a target directory still joined in front of it.
pub const MAX_PATH_LEN: usize = 1024;

/// Names the Win32 API resolves to a device rather than to a file, in any
/// directory and with any extension after them.
const DEVICES: &[&str] = &[
    "con", "prn", "aux", "nul", "conin$", "conout$", "clock$", "com0", "com1", "com2", "com3",
    "com4", "com5", "com6", "com7", "com8", "com9", "lpt0", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5",
    "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Printable characters no NTFS name may hold.
///
/// `/` never reaches a component, and `\` is refused earlier by [`check_tree`].
const ILLEGAL: &[char] = &[':', '*', '?', '<', '>', '|', '"'];

/// Refuses an entry path that could not be one node in an archive's tree.
///
/// Paths are separated by `/` and checked whole, on every path this crate is
/// given — read or written, extracted or rebuilt.
///
/// # Errors
///
/// [`Error::BadPath`], carrying the path and which of the rules it broke.
pub fn check_tree(path: &str) -> Result<()> {
    if path.is_empty() {
        return refuse(path, "is empty");
    }
    // Both spellings of "from the root": `\evil.txt` is the root of the
    // current drive on Windows. A drive letter is refused by `check_host`.
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
        // one node of a tree there however it reads here.
        if component.contains('\\') {
            return refuse(
                path,
                "has a component holding \\, which is a separator on Windows",
            );
        }
        // A name in the blob ends at its first NUL, so a NUL inside one is not
        // a name this format can hold.
        if component.contains('\0') {
            return refuse(
                path,
                "has a component holding a NUL, which ends a name in the blob",
            );
        }
    }
    Ok(())
}

/// Refuses an entry path that could not be one file below a directory on a
/// host filesystem, asked only where a name becomes a path on disk.
///
/// # Errors
///
/// [`Error::BadPath`], carrying the path and which of the rules it broke.
pub fn check_host(path: &str) -> Result<()> {
    if path.len() > MAX_PATH_LEN {
        return refuse(path, "is longer than a path may be");
    }
    // `extract` puts the sidecar manifest at the root of the tree it writes and
    // `pack` reads it from that name, so an entry named it collides with both.
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
        // opens a path, so `a.txt.` and `a.txt` are one file there and two
        // entries here.
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

/// Whether the Win32 API would resolve this component to a device, the
/// extension not being part of the match and trailing spaces dropped first.
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

    /// The refusal for a name Windows would trim.
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
        // `./a.txt` and `a.txt` join to the same file.
        assert_eq!(
            tree("./a.txt"),
            Some("navigates with . or .. rather than naming a file"),
        );
    }

    #[test]
    fn a_component_holding_a_nul_is_refused() {
        // A tree rule rather than a host one: a name in the blob ends at its
        // first NUL on every platform.
        for path in ["a\u{0}b", "\u{0}", "x64/a\u{0}.ytd", "a\u{0}/b"] {
            let refused = check_tree(path).expect_err("a NUL cannot be in a name");
            match refused {
                Error::BadPath { reason, .. } => assert!(reason.contains("NUL"), "{reason}"),
                other => panic!("{other:?}"),
            }
        }
        // The byte is refused, not the word.
        check_tree("nul.txt").expect("a file called nul.txt is a name");
    }

    #[test]
    fn a_component_holding_a_backslash_is_refused() {
        // On Windows `Path::join` reads a backslash as a separator, and it also
        // disarms the device rule: the stem of `x64\\aux.ytd` is `x64\\aux`.
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
        // `Path::join` discards the base outright for an absolute name.
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
        // Not caught by the leading-separator rule; the colon is what makes it
        // a drive rather than a directory named `C`.
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
        // `a.txt` are one file there and two entries here.
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
        // `check_tree` refuses `..` as the exact string; on Windows the trim
        // happens first, so these may be `..` there.
        for path in ["...", ".. ", ". ", "a/.. /b.txt"] {
            assert_eq!(tree(path), None, "{path} is one node in a tree here");
            assert_eq!(host(path), TRIMMED, "{path}");
        }
    }

    #[test]
    fn a_name_that_would_trim_to_the_sidecar_manifest_s_own_name_is_refused() {
        // The manifest rule compares the whole path, so a trailing dot walks
        // past it.
        assert_eq!(host(&format!("{MANIFEST_NAME}.")), TRIMMED);
    }

    #[test]
    fn a_dot_or_a_space_anywhere_but_the_end_is_accepted() {
        for path in [".gitignore", "a. b.txt", "x64/.hidden/a b.c", " a.txt"] {
            assert_eq!(host(path), None, "{path}");
        }
    }

    #[test]
    fn neither_rule_answers_the_other_s_question() {
        // A name a filesystem cannot hold is still one node of an archive's
        // tree, so a rebuild is not stopped by it.
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
