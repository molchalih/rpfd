//! Reading, editing and rebuilding RAGE Package File (`.rpf`) archives.
//!
//! This crate is the product; the `rpf` binary and the editor client are both
//! clients of it and hold no archive knowledge of their own. See
//! `docs/conventions.md` §1.
//!
//! Every constant and decode in [`format`] cites the row of `docs/rpf-format.md`
//! it comes from. A fact is encoded here exactly once (§3), so that changing it
//! is one edit rather than a search.

pub mod archive;
pub mod build;
pub mod entry;
pub mod error;
pub mod format;
pub mod inspect;
pub mod manifest;
pub mod name;
pub mod patch;
pub mod watch;

pub use archive::{Archive, MAX_DEPTH};
pub use build::{
    FileKind, FileSpec, Report, Storage, build, directories_of, rebuild, replace_at, replace_many,
    specs_of,
};
pub use entry::{Entry, EntryKind};
pub use error::{Category, Error, Result};
pub use inspect::{Listed, ListedKind, Problem, Summary, Verified};
pub use manifest::{MANIFEST_NAME, Manifest};
pub use patch::{Patches, Plan, Planned, TooLarge, plan};
pub use watch::{Flow, Step, Unwatched, Watch};
