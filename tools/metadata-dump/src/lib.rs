//! The layout of the metadata dump `RPF_METADATA` names, stated once.
//!
//! A dumped payload is a file whose **contents are exactly the payload** and
//! whose **name carries what the payload cannot state about itself**. Two
//! things are read back out of a dump: what a file is, which is answered by
//! its own leading bytes, and — for a resource `Meta` — where its system pages
//! end, which is not in the payload at all. It comes from the entry's system
//! flags (`rpf_core::format::resource::size_from_flags`), and a dumped `Meta`
//! without it cannot be parsed: `rpf_core::metadata::meta::parse` takes it as
//! `system_len` and every resource pointer in the file is resolved against it.
//!
//! So the name carries it, as a `sys<bytes>` field between the index and the
//! path. This module is the only place either half of that is written, and
//! `crates/rpf-core/tests/metadata.rs` reads it back through
//! [`system_len_of`] — one owner for one fact (`docs/conventions.md` §3).
//!
//! # Why the name and not a sidecar or a header
//!
//! A **header** would mean the file is no longer the payload. Everything that
//! consumes this dump consumes payload bytes: the fuzz targets seed their
//! corpora straight out of it, `meta::parse` takes a payload, and a header
//! makes every one of those a strip-first. It also makes a dumped file
//! something no archive contains, which is the opposite of what a corpus is
//! for.
//!
//! A **sidecar** — one length file beside each payload, or one index over all
//! of them — can be separated from what it describes. Copy a payload into a
//! fuzz corpus, or into a bug report, and the length is gone; regenerate half
//! the dump and the index describes files that are no longer there. A name
//! travels with its bytes through every one of those, and there is nothing to
//! keep in sync.
//!
//! The cost is that a length is spelled in a file name, which is only legible
//! because the dump's names are already generated rather than chosen.

use std::fmt::Write as _;

/// How many digits the index field is padded to.
///
/// Five, which is what the existing dump uses across its 10,144 files and
/// leaves room for the ~49,614 a `Meta` arm adds. Wider is harmless — the
/// field is read as "the leading digits", not as a fixed width — so this is
/// how names are *written* and nothing depends on it when they are read.
const INDEX_WIDTH: usize = 5;

/// What introduces the system-page length in a name.
///
/// Present on a resource `Meta` payload and on nothing else, so a dump written
/// before the resource arm existed reads back unchanged.
const SYSTEM_TAG: &str = "sys";

/// What separates a name's fields, and what a path separator becomes.
const SEPARATOR: char = '_';

/// The file name one payload is dumped under.
///
/// `index` is its ordinal in the walk, `path` is where it came from — the
/// archive's path under the corpus root, then the entry's path inside it,
/// joined with `/` — and `system_len` is `Some` for a resource `Meta` payload
/// and `None` for a payload of any other encoding.
///
/// The path is flattened by replacing each `/` with `_`, which is what the
/// existing dump does: `common.rpf/data/levels/gta5/junctions.pso` is
/// `00001_common.rpf_data_levels_gta5_junctions.pso`. It is not reversible and
/// is not meant to be — it is a provenance label, and the index is what makes
/// the name unique.
#[must_use]
pub fn dumped_name(index: usize, path: &str, system_len: Option<u64>) -> String {
    let mut name = String::new();
    let _ = write!(name, "{index:0INDEX_WIDTH$}{SEPARATOR}");
    if let Some(len) = system_len {
        let _ = write!(name, "{SYSTEM_TAG}{len}{SEPARATOR}");
    }
    name.push_str(&path.replace('/', &SEPARATOR.to_string()));
    name
}

/// How many bytes of this dumped payload are system pages, or `None` when the
/// name carries no such field.
///
/// `None` is the ordinary answer for a `PSO` or `RBF` payload, which has no
/// pages and needs none: only [`dumped_name`] with a `system_len` writes the
/// field, and it writes it only for a resource `Meta`.
///
/// The field is recognised structurally rather than by searching for `sys`
/// anywhere in the name: the first field must be the index — digits and
/// nothing else — and the second must be `sys` followed by digits and
/// nothing else. A flattened path whose first component happened to read
/// `sys123` would be misread, and that is why the index has to be there first.
#[must_use]
pub fn system_len_of(name: &str) -> Option<u64> {
    let mut fields = name.split(SEPARATOR);
    let index = fields.next()?;
    if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let digits = fields.next()?.strip_prefix(SYSTEM_TAG)?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_carries_the_length_it_was_written_with() {
        let name = dumped_name(1, "gtav/dlc.rpf/x64/data/x.ymt", Some(45_056));
        assert_eq!(name, "00001_sys45056_gtav_dlc.rpf_x64_data_x.ymt");
        assert_eq!(system_len_of(&name), Some(45_056));
    }

    #[test]
    fn a_payload_that_is_not_paged_carries_no_length() {
        let name = dumped_name(1, "common.rpf/data/levels/gta5/junctions.pso", None);
        assert_eq!(name, "00001_common.rpf_data_levels_gta5_junctions.pso");
        assert_eq!(system_len_of(&name), None);
    }

    #[test]
    fn the_existing_dumps_names_read_back_as_unpaged() {
        // The 10,144 files the dump held before the resource arm. None of them
        // may acquire a system length by being read with this.
        for name in [
            "00001_common.rpf_data_levels_gta5_junctions.pso",
            "00003_update.rpf_dlc_patch_mp2025_02_x64_levels_gta5_vehicles_mp2025_02.rpf__manifest.ymf",
            "10144_x.rpf_sys.ymt",
        ] {
            assert_eq!(system_len_of(name), None, "{name}");
        }
    }

    #[test]
    fn a_length_of_zero_is_a_length() {
        // A `Meta` whose pointers are all in graphics space is not a malformed
        // name, and `None` would send `parse` a length it was never given.
        assert_eq!(system_len_of("00007_sys0_a.rpf_b.ymt"), Some(0));
    }

    #[test]
    fn a_field_that_is_not_the_tag_is_not_a_length() {
        for name in [
            "00001_system_a.ymt",
            "00001_sys_a.ymt",
            "00001_sys12a_a.ymt",
            "sys12_00001_a.ymt",
            "_sys12_a.ymt",
            "",
        ] {
            assert_eq!(system_len_of(name), None, "{name}");
        }
    }
}
