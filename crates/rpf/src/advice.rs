//! What a caller is told to do about a failure, beyond what the failure says.
//!
//! Both frontends render through here, so the daemon and the command line agree.

use rpf_core::Error;
use serde_json::{Value, json};

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

/// The object a failure is answered with: code, sentence, and the failure's own
/// symbol.
pub fn object(code: i64, message: &str, reason: &str) -> Value {
    json!({ "code": code, "message": message, "data": { "reason": reason } })
}

/// The object for a failure the command line is about to exit on.
pub fn failed(failure: &Failure) -> Value {
    object(failure.code() as i64, &render(failure), failure.name())
}

/// The way through a refusal that has one. [`rpf_core::NoWrite::NoInverse`] has
/// none: nothing here derives the archive's forward transform.
fn remedy(failure: &Failure) -> Option<&'static str> {
    match *failure {
        Failure::Container(Error::WrongEncoding { .. }) => {
            Some("Pass --allow-encoding-change to override, or convert the payload first")
        }
        _ => None,
    }
}

/// The caller's path with `\` read as the separator. Only [`Error::NotFound`],
/// whose path came from the caller rather than out of the archive.
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
        let failure = Failure::Container(Error::BadPath {
            path: "x64\\evil.txt".to_owned(),
            reason: "has a component holding \\, which is a separator on Windows",
        });
        assert_eq!(respelling(&failure), None);
        assert_eq!(render(&failure), failure.to_string());
    }

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

    #[test]
    fn the_encrypted_refusal_that_has_no_way_through_offers_none() {
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
