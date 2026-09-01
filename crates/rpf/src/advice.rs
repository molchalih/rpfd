//! What a caller is told to do about a failure, beyond what the failure says.
//!
//! Both frontends render through this one function, so the daemon says what the
//! command line says. Two things are added: a path spelled with `\` is respelt
//! with the separator, and a refusal with a switch behind it names the switch.

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
/// Only [`Error::WrongEncoding`] has one. [`rpf_core::NoWrite::NoInverse`]
/// deliberately has none: nothing here derives the archive's forward transform,
/// so naming a command as the way through would be a lie.
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
/// caller. [`Error::BadPath`]'s path came out of the archive, and respelling it
/// would be advice to rename somebody else's entry.
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
        // What is offered is the same path read the other way, not a `\`
        // swept out of the name.
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
        // is nothing to suggest.
        let failure = Failure::Container(Error::BadPath {
            path: "x64\\evil.txt".to_owned(),
            reason: "has a component holding \\, which is a separator on Windows",
        });
        assert_eq!(respelling(&failure), None);
        assert_eq!(render(&failure), failure.to_string());
    }

    /// A refusal with a way through names it, in the spelling a caller passes.
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

    /// The encrypted-write refusal: nothing is offered, because there is
    /// nothing to offer.
    #[test]
    fn the_encrypted_refusal_that_has_no_way_through_offers_none() {
        // Nothing here derives the transform, and no command changes that:
        // offering one would be a lie.
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
