//! What to say when a caller spells a path inside an archive the Windows way.
//!
//! DR-016. `/` is the only separator a path inside an archive has, and `\` is
//! an ordinary character in an entry name — measured: an archive holding
//! `x64\evil.txt` lists it, verifies it, `cat`s it and patches it in place,
//! and one holding `x64/evil.txt` beside it addresses each by its own
//! spelling. So a `\` a caller types is never rewritten: `data\greeting.txt`
//! names an entry the archive does not hold, and the answer is not-found.
//!
//! That answer is correct and unhelpful, and this module is the whole of what
//! R10.6 puts at the boundary: the rule, and the caller's own path respelled.
//! It is here rather than in `rpf-core` because it is a rendered sentence,
//! which §10 assigns to the frontend; `Error::NotFound` already carries the
//! path, which is all this needs. Both frontends call it from the one place
//! each of them renders a failure, so the daemon says what the command line
//! says (§1).

use rpf_core::Error;

use crate::exit::Failure;

/// Renders a failure for a caller, saying how paths inside an archive are
/// spelled when that is what went wrong.
pub fn render(failure: &Failure) -> String {
    match respelling(failure) {
        Some(respelt) => format!(
            "{failure} (a path inside an archive separates with / on every \
             platform, and \\ is an ordinary character in an entry name rather \
             than a separator; try {respelt:?})"
        ),
        None => failure.to_string(),
    }
}

/// The path the caller asked for with `\` read as the separator, or `None` when
/// the failure is not one a separator explains.
///
/// Only [`Error::NotFound`], because only there did the path come from the
/// caller. [`Error::BadPath`] also names a path holding `\`, but that one came
/// out of the archive, and respelling it would be advice to rename somebody
/// else's entry.
fn respelling(failure: &Failure) -> Option<String> {
    let Failure::Container(Error::NotFound { ref path, .. }) = *failure else {
        return None;
    };
    path.contains('\\').then(|| path.replace('\\', "/"))
}

#[cfg(test)]
mod tests {
    use rpf_core::Error;

    use super::{render, respelling};
    use crate::exit::Failure;

    /// The failure a caller gets for a path that did not resolve.
    fn not_found(path: &str) -> Failure {
        Failure::Container(Error::NotFound {
            path: path.to_owned(),
            segment: path.to_owned(),
        })
    }

    #[test]
    fn a_backslashed_path_is_respelt_with_the_separator() {
        let rendered = render(&not_found("data\\greeting.txt"));
        assert!(
            rendered.contains("data/greeting.txt"),
            "must offer the spelling that resolves: {rendered}"
        );
        assert!(
            rendered.contains("no entry at"),
            "must still say what failed: {rendered}"
        );
    }

    #[test]
    fn only_the_separators_are_respelt_and_every_component_survives() {
        // Not a `\` swept out of the name: what is offered is the same path
        // read the other way, so a caller can see whether it is what they meant.
        assert_eq!(
            respelling(&not_found("x64\\dlcpacks\\mp\\dlc.rpf")).as_deref(),
            Some("x64/dlcpacks/mp/dlc.rpf"),
        );
        assert_eq!(
            respelling(&not_found("x64/dlcpacks\\dlc.rpf")).as_deref(),
            Some("x64/dlcpacks/dlc.rpf"),
        );
    }

    #[test]
    fn a_not_found_holding_no_backslash_is_rendered_unchanged() {
        let failure = not_found("data/absent.txt");
        assert_eq!(respelling(&failure), None);
        assert_eq!(render(&failure), failure.to_string());
    }

    #[test]
    fn a_name_the_archive_holds_a_backslash_in_is_not_respelt() {
        // The `\` came from the archive rather than from the caller, so there
        // is nothing to suggest. DR-016.
        let failure = Failure::Container(Error::BadPath {
            path: "x64\\evil.txt".to_owned(),
            reason: "has a component holding \\, which is a separator on Windows",
        });
        assert_eq!(respelling(&failure), None);
        assert_eq!(render(&failure), failure.to_string());
    }

    #[test]
    fn a_failure_of_the_command_lines_own_is_rendered_unchanged() {
        let failure = Failure::Refused {
            reason: "serve needs --stdio".to_owned(),
        };
        assert_eq!(respelling(&failure), None);
        assert_eq!(render(&failure), failure.to_string());
    }
}
