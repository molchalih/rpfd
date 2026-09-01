//! Reading, editing and rebuilding RAGE Package File (`.rpf`) archives.
//!
//! Version-specific facts live behind [`format::Version`]; `RPF7` is its only
//! implementation.

pub mod archive;
pub mod build;
pub mod edit;
pub mod entry;
pub mod error;
pub mod format;
pub mod inspect;
pub mod keys;
pub mod manifest;
pub mod metadata;
pub mod name;
pub mod patch;
pub mod scratch;
pub mod view;
pub mod watch;

pub use archive::{Archive, Classification, Extracted, MAX_DEPTH};
pub use build::{
    Fetch, FileKind, FileSpec, Payload, Report, ResourceFlags, Storage, build, directories_of,
    rebuild, resolves, rewrite, specs_of,
};
pub use edit::{Bytes, Change, Changes, Contents, Structural, allows};
pub use entry::{Entry, EntryKind};
pub use error::{Category, Error, NoWrite, Result};
pub use format::{Codec, Version};
pub use inspect::{Listed, ListedKind, Problem, Summary, Verified};
pub use keys::{Material, Unlock};
pub use manifest::{Checksum, MANIFEST_NAME, Manifest};
pub use metadata::{Encoding, hash::Dictionary};
pub use patch::{Patches, Plan, Planned, TooLarge, plan};
pub use scratch::{InMemory, Scratch};
pub use view::{View, Viewed};
pub use watch::{Flow, Step, Unwatched, Watch};
