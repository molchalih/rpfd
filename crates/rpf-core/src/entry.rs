//! One decoded row of the entry table: directory, binary, or resource.

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
        /// On-disk size; zero means stored, and `uncompressed_len` then holds the real length.
        compressed_len: u32,
        /// Length the payload inflates to.
        uncompressed_len: u32,
        /// Non-zero encryption field: the payload is under the archive's own transform.
        encryption: u32,
    },
    /// A file whose payload is an `RSC7` resource; length comes from `resource_len` instead.
    Resource {
        /// Payload offset, in blocks, from the archive's own base.
        block: u32,
        /// On-disk size, including the 16-byte `RSC7` header.
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

#[cfg(test)]
mod tests {
    use super::EntryKind;

    #[test]
    fn each_kind_names_itself_distinctly() {
        let directory = EntryKind::Directory {
            first_child: 0,
            child_count: 0,
        };
        let binary = EntryKind::Binary {
            block: 0,
            compressed_len: 0,
            uncompressed_len: 0,
            encryption: 0,
        };
        let resource = EntryKind::Resource {
            block: 0,
            compressed_len: 0,
            system_flags: 0,
            graphics_flags: 0,
        };
        assert_eq!(directory.noun(), "directory");
        assert_eq!(binary.noun(), "binary file");
        assert_eq!(resource.noun(), "resource file");
    }
}
