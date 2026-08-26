//! Exit codes, and the error type they come from.
//!
//! R6.3: a caller has to be able to tell "no such file" from "corrupt" from
//! "needs a key" from "refused" without parsing a message. The classification
//! of container failures lives in `rpf-core` so that adding an error variant
//! cannot silently invent an exit code; this adds only what the command line
//! itself can refuse.

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
}

/// Process exit codes. Stable, and part of the contract.
///
/// `Usage` and `Internal` are declared and not constructed here on purpose.
/// `clap` exits with 2 on its own before any command runs, and 1 is reserved
/// for a failure with no better classification. Leaving gaps in the table would
/// make the contract harder to read than an unused variant does.
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
    /// The archive is malformed, or contradicts itself.
    Corrupt = 4,
    /// The archive needs key material that is not available.
    NeedsKey = 5,
    /// The command declined to act.
    Refused = 6,
    /// Reading or writing failed.
    Io = 7,
}

impl Failure {
    /// The exit code for this failure.
    #[must_use]
    pub const fn code(&self) -> Code {
        match *self {
            Self::Container(ref error) => match error.category() {
                Category::NotFound => Code::NotFound,
                Category::Corrupt => Code::Corrupt,
                Category::NeedsKey => Code::NeedsKey,
                Category::Io => Code::Io,
            },
            Self::Io { .. } => Code::Io,
            Self::Refused { .. } | Self::GameInstall { .. } => Code::Refused,
        }
    }
}

/// Result of a command.
pub type Result<T> = std::result::Result<T, Failure>;
