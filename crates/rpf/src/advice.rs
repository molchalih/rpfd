//! What a caller is told to do about a failure, beyond what the failure says.
//!
//! `rpf_core::Error` carries what a caller acts on and not a rendered sentence
//! (§10), and a remedy is spelled in the frontend's own vocabulary — a command
//! line switch — so it is added here rather than in the container. Both
//! frontends render through this one function, so the daemon says what the
//! command line says (§1).
//!
//! Two things are added. A path spelled the Windows way is respelt: DR-016
//! makes `/` the only separator a path inside an archive has and `\` an
//! ordinary character in an entry name, so a `\` a caller types is never
//! rewritten and `data\greeting.txt` is simply not-found. That answer is
//! correct and unhelpful, and R10.6 puts the rule and the caller's own path
//! respelt at this boundary. And a refusal with a switch behind it names the
//! switch: DR-050.

use rpf_core::Error;

use crate::exit::Failure;

/// Renders a failure for a caller, with whatever the frontend can add to it.
pub fn render(failure: &Failure) -> String {
    if let Some(respelt) = respelling(failure) {
        return format!(
            "{failure} (a path inside an archive separates with / on every \
             platform, and \\ is an ordinary character in an entry name rather \
             than a separator; try {respelt:?})"
        );
    }
    if let Some(remedy) = remedy(failure) {
        return format!("{failure}. {remedy}");
    }
    failure.to_string()
}

/// The way through a refusal that has one, in the caller's own vocabulary.
///
/// One refusal has one: [`Error::WrongEncoding`]'s override is a switch of its
/// own — `--force` means "write into a detected game install" and says so in
/// its own sentence (DR-050).
///
/// [`rpf_core::NoWrite::NoInverse`] deliberately has none. Since DR-062 it says
/// that this build has nothing to derive the archive's forward transform from —
/// for NG that is a memory image of a running game (DR-040) — and naming a
/// command as the way through would be a lie, because there is not one. `pack`
/// over an
/// AES-tagged tree had one until DR-057 — "edit through the archive instead" —
/// and no longer needs it: it packs, given the material every other command
/// already reaches, and says [`Error::NeedsKey`] when there is none, which is a
/// state a caller acts on rather than a route to another command.
fn remedy(failure: &Failure) -> Option<&'static str> {
    match *failure {
        Failure::Container(Error::WrongEncoding { .. }) => {
            Some("Pass --allow-encoding-change to override, or convert the payload first")
        }
        _ => None,
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

    use super::{remedy, render, respelling};
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

    /// A refusal with a way through names it, in the spelling a caller passes.
    ///
    /// R7.6 wants a message a caller can act on, and `rpf_core::Error` cannot
    /// give one: it knows nothing of command-line switches (§2). DR-050.
    #[test]
    fn a_refusal_with_a_switch_behind_it_names_the_switch() {
        let failure = Failure::Container(Error::WrongEncoding {
            path: "data/thing.ymt".to_owned(),
            held: rpf_core::Encoding::Rbf,
            offered: rpf_core::Encoding::Xml,
        });
        let rendered = render(&failure);
        assert!(
            rendered.contains("--allow-encoding-change"),
            "must name the way through: {rendered}"
        );
        assert!(
            rendered.contains("data/thing.ymt")
                && rendered.contains("rbf")
                && rendered.contains("xml"),
            "must still say what was refused and what of: {rendered}"
        );
    }

    /// The encrypted-write refusal, which is the case where the reason left is
    /// a wall: nothing is offered, because there is nothing to offer.
    /// DR-054, DR-057.
    #[test]
    fn the_encrypted_refusal_that_has_no_way_through_offers_none() {
        // Nothing here derives the transform, and no command changes that:
        // offering one would be a lie. DR-062 re-aimed what the reason means
        // and did not give it a route through.
        let ng = Failure::Container(Error::CannotWriteEncrypted {
            tag: 0x0FEF_FFFF,
            reason: rpf_core::NoWrite::NoInverse,
        });
        assert_eq!(remedy(&ng), None);
        assert_eq!(render(&ng), ng.to_string());
        assert!(
            ng.to_string()
                .contains("derives this archive's forward transform"),
            "{ng}"
        );
        assert!(
            !render(&ng).contains("Edit through the archive"),
            "a walled-off remedy was offered: {ng}"
        );
    }

    /// And nothing else grows one: the sentence is the failure's own.
    #[test]
    fn a_refusal_with_no_switch_behind_it_is_rendered_unchanged() {
        let failure = Failure::Container(Error::WrongKind {
            path: "data".to_owned(),
            found: "directory",
            wanted: "file",
        });
        assert_eq!(remedy(&failure), None);
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
