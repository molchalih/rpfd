//! Reading, editing and rebuilding RAGE Package File (`.rpf`) archives.
//!
//! This crate is the product; the `rpf` binary and the editor client are both
//! clients of it and hold no archive knowledge of their own. See
//! `docs/conventions.md` §1.
//!
//! Every constant and decode in [`mod@format`] cites the row of `docs/rpf-format.md`
//! it comes from. A fact is encoded here exactly once (§3), so that changing it
//! is one edit rather than a search — and every fact that is one *version's*
//! rather than the container's lives behind [`format::Version`], the seam
//! DR-012 asks for. `RPF7` is its only implementation.

pub mod archive;
pub mod build;
pub mod edit;
pub mod entry;
pub mod error;
pub mod format;
pub mod inspect;
pub mod keys;
pub mod manifest;
pub mod name;
pub mod patch;
pub mod scratch;
pub mod watch;

pub use archive::{Archive, Extracted, MAX_DEPTH};
pub use build::{
    Fetch, FileKind, FileSpec, Payload, Report, Storage, build, directories_of, rebuild, rewrite,
    specs_of,
};
pub use edit::{Change, Changes, Structural, allows};
pub use entry::{Entry, EntryKind};
pub use error::{Category, Error, Result};
pub use format::{Codec, Version};
pub use inspect::{Listed, ListedKind, Problem, Summary, Verified};
pub use manifest::{Checksum, MANIFEST_NAME, Manifest};
pub use patch::{Patches, Plan, Planned, TooLarge, plan};
pub use scratch::{InMemory, Scratch};
pub use watch::{Flow, Step, Unwatched, Watch};
