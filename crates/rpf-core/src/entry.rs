//! One row of the entry table, once its version has been decoded away.
//!
//! A directory, a binary file and a resource file are separate variants because
//! the two trailing words of the row mean different things in each (§5). A
//! single struct with an `uncompressed_len` that is secretly two flag words is
//! a bug waiting for its first resource.
//!
//! Version-independent by construction: nothing here knows a width, an offset
//! or a marker. [`crate::format::Version::decode_row`] turns bytes into one of
//! these and [`crate::format::Version::file_row`] turns the fields back into
//! bytes, and both live behind the seam because the row is 16 bytes at `RPF7`,
//! 20 at `RPF6` and 24 at `RPF8`. DR-012.

/// What an entry is, and the fields that only that kind has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A directory. Its children are a contiguous run of the entry table.
    Directory {
        /// Index of the first child entry.
        first_child: u32,
        /// How many children follow it.
        child_count: u32,
    },
    /// A file whose payload is plain bytes, deflated unless stored.
    Binary {
        /// Payload offset, in blocks, from the archive's own base.
        block: u32,
        /// On-disk size. Zero means stored rather than deflated, and then
        /// `uncompressed_len` is the real length.
        compressed_len: u32,
        /// Length the payload inflates to.
        uncompressed_len: u32,
        /// Per-entry encryption field. Zero on every entry measured so far;
        /// its range is Q10 in `docs/backlog.md`.
        encryption: u32,
    },
    /// A file whose payload is an `RSC7` resource.
    ///
    /// Carries no uncompressed length: both trailing words are flags, and the
    /// length comes from [`crate::format::resource::resource_len`].
    Resource {
        /// Payload offset, in blocks, from the archive's own base.
        block: u32,
        /// On-disk size, **including** the 16-byte `RSC7` header.
        compressed_len: u32,
        /// System page flags.
        system_flags: u32,
        /// Graphics page flags.
        graphics_flags: u32,
    },
}

impl EntryKind {
    /// A word for this kind, for error messages.
    #[must_use]
    pub const fn noun(self) -> &'static str {
        match self {
            Self::Directory { .. } => "directory",
            Self::Binary { .. } => "binary file",
            Self::Resource { .. } => "resource file",
        }
    }
}

/// One row of the entry table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// Offset of this entry's name within the names blob.
    pub name_offset: u32,
    /// What the entry is.
    pub kind: EntryKind,
}

impl Entry {
    /// Whether this entry is a directory.
    #[must_use]
    pub const fn is_directory(&self) -> bool {
        matches!(self.kind, EntryKind::Directory { .. })
    }
}
