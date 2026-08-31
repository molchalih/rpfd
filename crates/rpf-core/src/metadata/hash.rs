//! Names are hashes, and the dictionary that renders them is cosmetic.
//!
//! `PSO` stores every structure and member name as a Jenkins one-at-a-time
//! hash rather than as text (`docs/metadata-encodings.md`, Names are hashes).
//! A dictionary turns those back into words so the XML reads; an unresolved
//! hash renders as `hash_XXXXXXXX` and parses straight back to the same `u32`
//! without [`joaat`] being invoked at all, so the dictionary changes how the
//! document *looks* and never what it *means*.
//!
//! That claim is only unconditional if a resolved name re-hashes to the key it
//! was found under. It is not free: over the largest published 20,300-entry
//! list, 40 entries do not — 35 hash correctly only when lowercased and 5 are
//! simply wrong — so roughly 1 entry in 500 renders a name that comes back a
//! different `u32`. [`Dictionary::load`] therefore checks `joaat(name) == key`
//! at load and rejects the entry when it fails, which is what makes the round
//! trip a property of this code rather than of whichever list the user
//! supplied. R5.5, and DR-047.
//!
//! **No dictionary ships with this repository.** DR-006: a name list derived
//! from the game is not ours to redistribute. The dictionary is a file the
//! user brings, and the empty one — [`Dictionary::default`] — is a complete
//! answer that renders every name as its hash.

use std::collections::{BTreeMap, btree_map::Entry};

use super::text::is_xml_name;

/// How an unresolved hash is rendered, before its eight hex digits.
///
/// `docs/rpf-format.md` and `docs/metadata-encodings.md` both spell it
/// `hash_XXXXXXXX`, and so does the reference implementation, in upper case
/// and padded to eight digits.
pub const PLACEHOLDER_PREFIX: &str = "hash_";

/// How many hex digits a placeholder carries: a `u32`, always padded.
const PLACEHOLDER_DIGITS: usize = 8;

/// The reserved XML name prefix the `PSO` mapping uses.
///
/// A dictionary name beginning with it is refused at load, because a rendered
/// member name that collides with the mapping's own vocabulary would make the
/// document ambiguous. DR-047.
pub const RESERVED_PREFIX: &str = "pso:";

/// The Jenkins one-at-a-time hash, seed 0, over the literal bytes.
///
/// No case folding and no terminator: the bytes as they are.
/// `docs/metadata-encodings.md`, Names are hashes — `verified` 2026-08-30
/// against the corpus itself, in which `joaat("CMapTypes") == 0xD98BB561`,
/// `joaat("Item") == 0x063FA3F2` and `joaat("Key") == 0x6098A50E` all occur as
/// real `PSCH` names.
///
/// This is **not** [`crate::format`]'s NG name hash, which folds case through a
/// lookup table the key material carries and answers a different question.
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
///
/// [`unplaceholder`] is the exact inverse, and it does not invoke [`joaat`], so
/// a name this build could not resolve survives the trip back whatever the
/// dictionary says.
#[must_use]
pub fn placeholder(hash: u32) -> String {
    format!("{PLACEHOLDER_PREFIX}{hash:0PLACEHOLDER_DIGITS$X}")
}

/// The hash a [`placeholder`] spells, or `None` when `text` is not one.
///
/// Strict: the prefix, then exactly eight hex digits and
/// nothing else. A dictionary name cannot be mistaken for one, because
/// [`Dictionary::load`] refuses a name that spells a placeholder.
#[must_use]
pub fn unplaceholder(text: &str) -> Option<u32> {
    let digits = text.strip_prefix(PLACEHOLDER_PREFIX)?;
    if digits.len() != PLACEHOLDER_DIGITS || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(digits, 16).ok()
}

/// A hash-to-name dictionary that has been checked.
///
/// Every name in it is a valid XML name, does not begin with
/// [`RESERVED_PREFIX`], does not spell a [`placeholder`], and hashes to the key
/// it is stored under. So [`Dictionary::name`] can be rendered into a document
/// and read back to the same `u32` unconditionally — which is the whole reason
/// the dictionary is allowed to be optional.
#[derive(Debug, Clone, Default)]
pub struct Dictionary {
    names: BTreeMap<u32, Box<str>>,
}

/// What a [`Dictionary::load`] produced: the dictionary, and what it would not
/// carry.
///
/// Loading never fails. An entry that does not check out is dropped and
/// reported, because a dictionary is cosmetic and one bad line is not a reason
/// to render 20,000 good names as hashes. Nothing is left for the caller to
/// finish: `dictionary` is complete and usable whether or not `rejected` is
/// empty (`docs/conventions.md` §4).
#[derive(Debug, Clone)]
pub struct Loaded {
    /// Every entry that checked out.
    pub dictionary: Dictionary,
    /// Every entry that did not, in the order the file gave them.
    pub rejected: Vec<Rejected>,
}

/// One entry a dictionary file offered and [`Dictionary::load`] would not take.
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
    /// The line carried a key field that is not hexadecimal, or does not fit a
    /// `u32`.
    Key,
    /// The name does not hash to the key the file stated.
    ///
    /// The one that matters: a name that renders and comes back as a different
    /// `u32` makes a rebuilt file reference a member that does not exist. 40 of
    /// the 20,300 entries in the largest published list land here.
    Mismatch {
        /// What the file said the hash was.
        stated: u32,
        /// What [`joaat`] of the name actually is.
        computed: u32,
    },
    /// The name is not one this build can write as an XML element name.
    Name,
    /// The name begins with [`RESERVED_PREFIX`], or spells a [`placeholder`].
    Reserved,
    /// The key is already taken by a different name.
    Collision {
        /// The name already stored under that key.
        held: String,
    },
}

impl Dictionary {
    /// The empty dictionary, which is a complete answer.
    ///
    /// A hash no dictionary names is rendered as a [`placeholder`] and read
    /// back as the same `u32`, so what a dictionary changes is legibility and
    /// never the payload (R5.5). It is a constant rather than
    /// [`Dictionary::default`] because a caller with no dictionary of its own
    /// has to be able to *lend* one — both frontends do, to every conversion
    /// they ask for — and a value made on the spot cannot be borrowed for
    /// longer than the call.
    pub const EMPTY: &'static Self = &Self {
        names: BTreeMap::new(),
    };

    /// Reads a dictionary file and keeps the entries that check out.
    ///
    /// One entry per line. A line is a name on its own, in which case its key
    /// is [`joaat`] of it; or a key and a name separated by whitespace, a comma
    /// or an equals sign, in which case the key is read as hexadecimal — with
    /// or without an `0x` prefix — and **checked** against [`joaat`] of the
    /// name. Blank lines, and lines whose first non-space character is `#`, are
    /// ignored and are not rejections.
    ///
    /// The keyed form is the one the published lists use and the only one that
    /// can lie; the bare form cannot, because there is no key for the name to
    /// disagree with.
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

    /// Checks one entry and keeps it.
    ///
    /// `stated` is the key the file gave, or `None` for the bare form.
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

    /// How a hash is written: its name if there is one, else its
    /// [`placeholder`].
    ///
    /// The only place a name reaches a document, so the guarantees
    /// [`Dictionary::load`] checked are the guarantees the document has.
    #[must_use]
    pub fn render(&self, hash: u32) -> String {
        self.name(hash)
            .map_or_else(|| placeholder(hash), ToOwned::to_owned)
    }
}

/// Splits a dictionary line into its optional key and its name.
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
        // `docs/metadata-encodings.md`, Names are hashes. The empty string is
        // the case that decides what a zero name hash means.
        assert_eq!(joaat(b"32BIT"), 0xAF08_5554);
        assert_eq!(joaat(b"params"), 0x3518_C7D8);
        assert_eq!(joaat(b""), 0);
    }

    #[test]
    fn the_hash_matches_names_that_occur_in_the_corpus_itself() {
        // Measured 2026-08-30: each of these is a `PSCH` structure or member
        // name hash present in the 9,753 shipped files, so the hash function is
        // checked against the data rather than against another implementation.
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
        // The measured hole: over the largest published list, 40 of 20,300
        // entries fail this. `params_` is the C# keyword-escape artefact — the
        // key is `joaat("params")` and the name has a trailing underscore, so a
        // rendered `params_` re-hashes to something else entirely.
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
        // 35 of the 40. The hash does not fold case, so the list's own key is
        // of the lowercased spelling while the name it renders is not.
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
        // A line with a separator in it is a key and a name, so a name with a
        // space in it is not one line: it is a key that is not hexadecimal.
        assert_eq!(
            Dictionary::load("1leading").rejected[0].cause,
            Rejection::Name
        );
        // A line with a separator in it is a key and a name, so `a b` is not a
        // name with a space: it is the key `0xa` and the name `b`, which do not
        // agree.
        assert!(matches!(
            Dictionary::load("a b").rejected[0].cause,
            Rejection::Mismatch { stated: 0xa, .. }
        ));
    }

    #[test]
    fn a_name_that_collides_with_the_mappings_own_vocabulary_is_rejected() {
        // A member rendered `hash_00000000` must mean the hash 0 and nothing
        // else, and a name beginning `pso:` would be read as reserved.
        assert_eq!(
            Dictionary::load("hash_00000000").rejected[0].cause,
            Rejection::Reserved
        );
        assert_eq!(
            Dictionary::load("pso:item").rejected[0].cause,
            Rejection::Reserved
        );
        // A name that merely *starts* `hash_` is fine: it is not a placeholder.
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

        // A genuine clash. `joaat` is a 32-bit hash over an unbounded input, so
        // two real names do collide; brute-forcing the four-letter lower-case
        // space finds `joaat("aqaa") == joaat("elue") == 0x18BED31F`, and both
        // are valid XML names. Stating it through the keyed form instead would
        // prove nothing: `insert` checks the key against `joaat` of the name
        // first, so two invented keys are two `Mismatch`es and the entry check
        // below is never reached.
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
