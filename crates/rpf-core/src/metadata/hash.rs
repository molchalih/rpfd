//! Names are hashes, and the dictionary that renders them is cosmetic.

use std::collections::{BTreeMap, btree_map::Entry};

use super::text::is_xml_name;

/// How an unresolved hash is rendered, before its eight upper-case hex digits.
pub const PLACEHOLDER_PREFIX: &str = "hash_";

const PLACEHOLDER_DIGITS: usize = 8;

/// The reserved XML name prefix a dictionary name is refused for beginning with.
pub const RESERVED_PREFIX: &str = "pso:";

/// The Jenkins one-at-a-time hash, seed 0, over the literal bytes.
#[must_use]
pub fn joaat(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    for byte in bytes {
        hash = hash.wrapping_add(u32::from(*byte));
        hash = hash.wrapping_add(hash << 10);
        hash ^= hash >> 6;
    }
    hash = hash.wrapping_add(hash << 3);
    hash ^= hash >> 11;
    hash.wrapping_add(hash << 15)
}

/// How an unresolved hash is written: `hash_` and eight upper-case hex digits.
#[must_use]
pub fn placeholder(hash: u32) -> String {
    format!("{PLACEHOLDER_PREFIX}{hash:0PLACEHOLDER_DIGITS$X}")
}

/// The hash a placeholder spells, or `None` when `text` is not one.
#[must_use]
pub fn unplaceholder(text: &str) -> Option<u32> {
    let digits = text.strip_prefix(PLACEHOLDER_PREFIX)?;
    if digits.len() != PLACEHOLDER_DIGITS || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(digits, 16).ok()
}

/// A hash-to-name dictionary whose every name is a valid XML name.
#[derive(Debug, Clone, Default)]
pub struct Dictionary {
    names: BTreeMap<u32, Box<str>>,
}

/// What loading a dictionary produced; loading itself never fails.
#[derive(Debug, Clone)]
pub struct Loaded {
    /// Every entry that checked out.
    pub dictionary: Dictionary,
    /// Every entry that did not, in the order the file gave them.
    pub rejected: Vec<Rejected>,
}

/// One entry a dictionary file offered that loading would not take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    /// Which line of the file, counting from 1.
    pub line: usize,
    /// The name as the file spelled it.
    pub name: String,
    /// Why it was not taken.
    pub cause: Rejection,
}

/// Why a dictionary entry was not taken.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rejection {
    /// The line's key field is not hexadecimal, or does not fit a `u32`.
    Key,
    /// The name does not hash to the key the file stated.
    Mismatch {
        /// What the file said the hash was.
        stated: u32,
        /// What the hash of the name actually is.
        computed: u32,
    },
    /// The name is not one this build can write as an XML element name.
    Name,
    /// The name begins with the reserved prefix, or spells a placeholder.
    Reserved,
    /// The key is already taken by a different name.
    Collision {
        /// The name already stored under that key.
        held: String,
    },
}

impl Dictionary {
    /// The empty dictionary, which is a complete answer.
    pub const EMPTY: &'static Self = &Self {
        names: BTreeMap::new(),
    };

    /// Reads a dictionary file and keeps the entries that check out.
    #[must_use]
    pub fn load(text: &str) -> Loaded {
        let mut dictionary = Self::default();
        let mut rejected = Vec::new();
        for (index, raw) in text.lines().enumerate() {
            let line = index.saturating_add(1);
            let body = raw.trim();
            if body.is_empty() || body.starts_with('#') {
                continue;
            }
            let (stated, name) = split(body);
            match dictionary.insert(stated, name) {
                Ok(()) => {}
                Err(cause) => rejected.push(Rejected {
                    line,
                    name: name.to_owned(),
                    cause,
                }),
            }
        }
        Loaded {
            dictionary,
            rejected,
        }
    }

    fn insert(&mut self, stated: Option<&str>, name: &str) -> Result<(), Rejection> {
        let computed = joaat(name.as_bytes());
        if let Some(text) = stated {
            let digits = text
                .strip_prefix("0x")
                .or_else(|| text.strip_prefix("0X"))
                .unwrap_or(text);
            let Ok(key) = u32::from_str_radix(digits, 16) else {
                return Err(Rejection::Key);
            };
            if key != computed {
                return Err(Rejection::Mismatch {
                    stated: key,
                    computed,
                });
            }
        }
        if name.starts_with(RESERVED_PREFIX) || unplaceholder(name).is_some() {
            return Err(Rejection::Reserved);
        }
        if !is_xml_name(name) {
            return Err(Rejection::Name);
        }
        match self.names.entry(computed) {
            Entry::Vacant(slot) => {
                slot.insert(name.into());
                Ok(())
            }
            Entry::Occupied(held) if held.get().as_ref() == name => Ok(()),
            Entry::Occupied(held) => Err(Rejection::Collision {
                held: held.get().as_ref().to_owned(),
            }),
        }
    }

    /// The name this hash resolves to, or `None`.
    #[must_use]
    pub fn name(&self, hash: u32) -> Option<&str> {
        self.names.get(&hash).map(AsRef::as_ref)
    }

    /// How many names it holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether it holds none, which is the no-dictionary case.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// How a hash is written: its name if there is one, else its placeholder.
    #[must_use]
    pub fn render(&self, hash: u32) -> String {
        self.name(hash)
            .map_or_else(|| placeholder(hash), ToOwned::to_owned)
    }
}

fn split(body: &str) -> (Option<&str>, &str) {
    match body.split_once([' ', '\t', ',', '=']) {
        Some((key, rest)) => (Some(key.trim()), rest.trim_matches([' ', '\t', ',', '='])),
        None => (None, body),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hash_is_the_one_three_independent_corpora_agree_on() {
        assert_eq!(joaat(b"32BIT"), 0xAF08_5554);
        assert_eq!(joaat(b"params"), 0x3518_C7D8);
        assert_eq!(joaat(b""), 0);
    }

    #[test]
    fn the_hash_matches_names_that_occur_in_the_corpus_itself() {
        assert_eq!(joaat(b"CMapTypes"), 0xD98B_B561);
        assert_eq!(joaat(b"CCreatureMetaData"), 0x79B7_DCE5);
        assert_eq!(joaat(b"CPackFileMetaData"), 0x93A6_8A2F);
        assert_eq!(joaat(b"CBaseArchetypeDef"), 0x82D6_FC83);
        assert_eq!(joaat(b"CExtensionDefSpawnPoint"), 0xC4B2_F638);
        assert_eq!(joaat(b"Item"), 0x063F_A3F2);
        assert_eq!(joaat(b"Key"), 0x6098_A50E);
    }

    #[test]
    fn it_does_not_fold_case() {
        assert_ne!(joaat(b"CMapTypes"), joaat(b"cmaptypes"));
    }

    #[test]
    fn a_placeholder_round_trips_without_the_hash_function() {
        for hash in [0, 1, 0xAF08_5554, u32::MAX] {
            assert_eq!(unplaceholder(&placeholder(hash)), Some(hash));
        }
        assert_eq!(placeholder(0), "hash_00000000");
        assert_eq!(placeholder(0xAF08_5554), "hash_AF085554");
    }

    #[test]
    fn only_a_full_width_placeholder_is_one() {
        assert_eq!(unplaceholder("hash_0000000"), None);
        assert_eq!(unplaceholder("hash_000000000"), None);
        assert_eq!(unplaceholder("hash_0000000g"), None);
        assert_eq!(unplaceholder("CMapTypes"), None);
        assert_eq!(unplaceholder("hash_"), None);
    }

    #[test]
    fn an_entry_whose_name_does_not_hash_to_its_key_is_rejected() {
        let loaded = Dictionary::load("0x3518C7D8 params_\n0x3518C7D8 params\n");
        assert_eq!(loaded.dictionary.len(), 1);
        assert_eq!(loaded.dictionary.name(0x3518_C7D8), Some("params"));
        assert_eq!(loaded.rejected.len(), 1);
        assert_eq!(loaded.rejected[0].name, "params_");
        assert_eq!(
            loaded.rejected[0].cause,
            Rejection::Mismatch {
                stated: 0x3518_C7D8,
                computed: joaat(b"params_"),
            }
        );
    }

    #[test]
    fn an_entry_that_matches_only_lowercased_is_rejected() {
        let key = joaat(b"cmaptypes");
        let loaded = Dictionary::load(&format!("{key:08X} CMapTypes"));
        assert!(loaded.dictionary.is_empty());
        assert_eq!(
            loaded.rejected[0].cause,
            Rejection::Mismatch {
                stated: key,
                computed: joaat(b"CMapTypes"),
            }
        );
    }

    #[test]
    fn a_name_on_its_own_cannot_disagree_with_its_key() {
        let loaded = Dictionary::load("CMapTypes\nparams_\n");
        assert!(loaded.rejected.is_empty());
        assert_eq!(
            loaded.dictionary.name(joaat(b"CMapTypes")),
            Some("CMapTypes")
        );
        assert_eq!(loaded.dictionary.name(joaat(b"params_")), Some("params_"));
    }

    #[test]
    fn the_key_may_be_written_in_any_of_the_forms_the_lists_use() {
        for line in [
            "0xD98BB561 CMapTypes",
            "0XD98BB561,CMapTypes",
            "D98BB561=CMapTypes",
            "d98bb561\tCMapTypes",
        ] {
            let loaded = Dictionary::load(line);
            assert_eq!(
                loaded.dictionary.name(0xD98B_B561),
                Some("CMapTypes"),
                "{line}"
            );
        }
    }

    #[test]
    fn a_key_that_is_not_hexadecimal_is_rejected() {
        let loaded = Dictionary::load("zzzz CMapTypes");
        assert_eq!(loaded.rejected[0].cause, Rejection::Key);
        assert!(loaded.dictionary.is_empty());
    }

    #[test]
    fn a_name_the_xml_cannot_carry_is_rejected() {
        for name in ["a b", "1leading", "<tag>", "", "a\"b"] {
            let loaded = Dictionary::load(name);
            assert!(
                loaded.dictionary.is_empty(),
                "{name:?} should not be a name"
            );
        }
        assert_eq!(
            Dictionary::load("1leading").rejected[0].cause,
            Rejection::Name
        );
        assert!(matches!(
            Dictionary::load("a b").rejected[0].cause,
            Rejection::Mismatch { stated: 0xa, .. }
        ));
    }

    #[test]
    fn a_name_that_collides_with_the_mappings_own_vocabulary_is_rejected() {
        assert_eq!(
            Dictionary::load("hash_00000000").rejected[0].cause,
            Rejection::Reserved
        );
        assert_eq!(
            Dictionary::load("pso:item").rejected[0].cause,
            Rejection::Reserved
        );
        assert_eq!(Dictionary::load("hash_of_a_thing").rejected.len(), 0);
    }

    #[test]
    fn two_names_under_one_key_keep_the_first_and_report_the_second() {
        let first = joaat(b"CMapTypes");
        let loaded = Dictionary::load(&format!("CMapTypes\n{first:08X} CMapTypes\n"));
        assert!(
            loaded.rejected.is_empty(),
            "the same name twice is not a clash"
        );

        assert_eq!(joaat(b"aqaa"), joaat(b"elue"));
        let loaded = Dictionary::load("aqaa\nelue\n");
        assert_eq!(loaded.dictionary.len(), 1);
        assert_eq!(loaded.dictionary.name(0x18BE_D31F), Some("aqaa"));
        assert_eq!(loaded.rejected.len(), 1);
        assert_eq!(loaded.rejected[0].name, "elue");
        assert_eq!(
            loaded.rejected[0].cause,
            Rejection::Collision {
                held: "aqaa".to_owned(),
            }
        );
    }

    #[test]
    fn len_and_is_empty_track_how_many_names_were_accepted() {
        let empty = Dictionary::default();
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());

        let two = Dictionary::load("CMapTypes\nparams\n").dictionary;
        assert_eq!(two.len(), 2);
        assert!(!two.is_empty());
    }

    #[test]
    fn blank_lines_and_comments_are_not_rejections() {
        let loaded = Dictionary::load("\n  \n# a comment\nCMapTypes\n");
        assert!(loaded.rejected.is_empty());
        assert_eq!(loaded.dictionary.len(), 1);
    }

    #[test]
    fn an_empty_dictionary_renders_every_name_as_its_hash() {
        let empty = Dictionary::default();
        assert!(empty.is_empty());
        assert_eq!(empty.render(0xD98B_B561), "hash_D98BB561");
        assert_eq!(empty.render(0), "hash_00000000");
    }

    #[test]
    fn a_loaded_name_renders_as_itself_and_re_hashes_to_the_same_key() {
        let loaded = Dictionary::load("CMapTypes");
        let rendered = loaded.dictionary.render(0xD98B_B561);
        assert_eq!(rendered, "CMapTypes");
        assert_eq!(joaat(rendered.as_bytes()), 0xD98B_B561);
    }
}
