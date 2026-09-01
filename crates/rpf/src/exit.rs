//! Exit codes, and the error type they come from.
//!
//! A caller tells the kinds of failure apart without parsing a message. The
//! classification of container failures lives in `rpf-core` so that adding an
//! error variant cannot silently invent an exit code; this adds only what the
//! command line itself can refuse. Each code says what the caller has to do
//! about the failure, not what the code was doing when it noticed.

use std::{io, path::PathBuf};

use rpf_core::Category;

/// Anything that stops a command.
#[derive(Debug, thiserror::Error)]
pub enum Failure {
    /// The container layer failed.
    #[error(transparent)]
    Container(#[from] rpf_core::Error),

    /// The filesystem failed.
    #[error("{path}: {source}")]
    Io {
        /// What was being read or written.
        path: String,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },

    /// The command declined to act.
    #[error("refusing: {reason}")]
    Refused {
        /// Why, in terms the caller can act on.
        reason: String,
    },

    /// The archive is inside a game installation.
    #[error(
        "refusing to write into the game installation at {root}; \
         editing a shipped archive in place breaks its integrity checks. \
         Pass --force to override, or copy the archive out first"
    )]
    GameInstall {
        /// Where the installation was detected.
        root: PathBuf,
    },

    /// A directory above the archive would not say what is in it, so the game
    /// install guard has no answer rather than a negative one.
    ///
    /// Separate from [`Failure::GameInstall`], which names an installation that
    /// was actually found. Both refuse and both take `--force`.
    #[error(
        "refusing to write below {directory}: that directory cannot be \
         examined, so whether this is a game installation cannot be told from \
         here. Pass --force to override, or copy the archive out first"
    )]
    UncertainInstall {
        /// The directory the filesystem would not answer for.
        directory: PathBuf,
    },
}

/// Process exit codes. Stable, and part of the contract.
///
/// `Usage` and `Internal` are declared and not constructed here: `clap` exits 2
/// on its own before any command runs, and 1 is reserved for a failure with no
/// better classification.
#[derive(Debug, Clone, Copy)]
#[repr(i32)]
#[allow(dead_code, reason = "Usage comes from clap; Internal is reserved")]
pub enum Code {
    /// Everything worked.
    Ok = 0,
    /// Something went wrong that has no better classification.
    Internal = 1,
    /// The arguments were wrong. `clap` uses this itself.
    Usage = 2,
    /// The path is not in the archive.
    NotFound = 3,
    /// The archive is malformed, contradicts itself, or does not decompress as
    /// it promises.
    Corrupt = 4,
    /// The archive needs key material that is not available.
    NeedsKey = 5,
    /// The command or the container declined to act, because the request or
    /// its input was wrong.
    Refused = 6,
    /// Reading or writing failed. The source or the sink, and nobody's input.
    Io = 7,
    /// The caller stopped the operation part-way.
    Cancelled = 8,
    /// The archive is intact and this build cannot read it — an RPF version
    /// with no codec here.
    Unsupported = 9,
}

impl Failure {
    /// The exit code for this failure.
    ///
    /// Not `const`, because `rpf_core::Error::category` is not: one container
    /// variant is classified from the bytes it carries.
    #[must_use]
    pub fn code(&self) -> Code {
        match *self {
            Self::Container(ref error) => match error.category() {
                Category::NotFound => Code::NotFound,
                Category::Corrupt => Code::Corrupt,
                Category::NeedsKey => Code::NeedsKey,
                Category::Unsupported => Code::Unsupported,
                Category::Refused => Code::Refused,
                Category::Cancelled => Code::Cancelled,
                Category::Io => Code::Io,
            },
            Self::Io { .. } => Code::Io,
            Self::Refused { .. } | Self::GameInstall { .. } | Self::UncertainInstall { .. } => {
                Code::Refused
            }
        }
    }
}

impl Failure {
    /// This failure's own name, as a stable symbol.
    ///
    /// The exit code says who has to act; this says which failure it was, so a
    /// caller with a distinct answer for one of them need not read the
    /// sentence. The daemon puts it beside `error.code`; a process gets only
    /// the number.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match *self {
            Self::Container(ref error) => error.name(),
            Self::Io { .. } => "Io",
            Self::Refused { .. } => "Refused",
            Self::GameInstall { .. } => "GameInstall",
            Self::UncertainInstall { .. } => "UncertainInstall",
        }
    }
}

/// Result of a command.
pub type Result<T> = std::result::Result<T, Failure>;

#[cfg(test)]
mod tests {
    use rpf_core::Category;

    use super::{Code, Failure};

    /// A container failure of each category, as the binary receives one.
    fn of(category: Category) -> Failure {
        let error = match category {
            Category::NotFound => rpf_core::Error::NoSuchEntry {
                index: 9,
                entry_count: 4,
            },
            Category::Corrupt => rpf_core::Error::Inflate {
                entry: 0,
                source: std::io::Error::other("not deflate"),
            },
            Category::NeedsKey => rpf_core::Error::NeedsKey { tag: 0x0FFF_FFF9 },
            Category::Unsupported => rpf_core::Error::UnsupportedVersion {
                base: 0,
                version: 2,
                found: *b"RPF2",
            },
            Category::Refused => rpf_core::Error::WrongKind {
                path: "data".to_owned(),
                found: "directory",
                wanted: "file",
            },
            Category::Cancelled => rpf_core::Error::Cancelled { done: 1, total: 24 },
            Category::Io => rpf_core::Error::Io {
                offset: 0,
                source: std::io::Error::other("the source failed"),
            },
        };
        Failure::Container(error)
    }

    #[test]
    fn every_category_keeps_the_number_it_is_contracted_to() {
        // The numbers are the contract, so they are written out here rather
        // than derived from the enum they are being checked against.
        for (category, code) in [
            (Category::NotFound, 3),
            (Category::Corrupt, 4),
            (Category::NeedsKey, 5),
            (Category::Refused, 6),
            (Category::Io, 7),
            (Category::Cancelled, 8),
            (Category::Unsupported, 9),
        ] {
            assert_eq!(of(category).code() as i32, code, "{category:?}");
        }
    }

    #[test]
    fn what_the_binary_refuses_for_itself_lands_on_the_same_number() {
        // A refusal the command line makes and a refusal the container makes
        // are one thing to a caller, so they are one number.
        assert_eq!(
            Failure::Refused {
                reason: "no".to_owned(),
            }
            .code() as i32,
            Code::Refused as i32,
        );
    }

    #[test]
    fn both_halves_of_the_install_guard_refuse_on_the_same_number() {
        // The guard has two answers — an installation it found, and a
        // directory it could not look into — and one thing for the caller to
        // do about either.
        for failure in [
            Failure::GameInstall {
                root: "/games/GTAV".into(),
            },
            Failure::UncertainInstall {
                directory: "/games".into(),
            },
        ] {
            assert_eq!(
                failure.code() as i32,
                Code::Refused as i32,
                "{failure} is a refusal",
            );
        }
    }
}
