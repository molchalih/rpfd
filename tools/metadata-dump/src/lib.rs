//! The layout of the metadata dump's names, stated once.
//!
//! A dumped file's contents are exactly the payload, so anything the payload
//! cannot state about itself goes in the name: for a resource `Meta`, where
//! its system pages end, which `meta::parse` needs and the bytes do not carry.

use std::fmt::Write as _;

/// How many digits the index field is padded to.
///
/// A name is read as "the leading digits", not as a fixed width, so widening
/// this changes only how names are written.
const INDEX_WIDTH: usize = 5;

/// What introduces the system-page length in a name, present on a resource
/// `Meta` payload and on nothing else.
const SYSTEM_TAG: &str = "sys";

/// What separates a name's fields, and what a path separator becomes.
const SEPARATOR: char = '_';

/// The file name one payload is dumped under.
///
/// `index` is its ordinal in the walk, `path` is where it came from, and
/// `system_len` is `Some` only for a resource `Meta` payload.
///
/// The path is flattened by replacing each `/` with `_`, which is not
/// reversible: it is a provenance label, and the index is what makes the name
/// unique.
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
/// pages. The field is recognised structurally — digits, then `sys` and
/// digits — so a flattened path component reading `sys123` is not misread.
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
        // Names written before the resource arm existed must not acquire a
        // system length by being read with this.
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
            // `u64::from_str` takes a leading sign where `is_ascii_digit` does not,
            // so this is the one name the digit guard has to refuse by itself.
            "00001_sys+12_a.ymt",
            "sys12_00001_a.ymt",
            "_sys12_a.ymt",
            "",
        ] {
            assert_eq!(system_len_of(name), None, "{name}");
        }
    }
}
