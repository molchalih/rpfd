//! `PSO` — big-endian tagged sections carrying their own schema, and the XML
//! they convert to.
//!
//! Everything here is `docs/metadata-encodings.md`'s `PSO` section, which is
//! `verified` against all 9,753 files both GTA V builds ship. One measurement
//! shapes the whole module: every file was walked from `PMAP.rootId` using
//! **only its own `PSCH`**, and reached **0** references it did not define. So
//! the conversion is driven by the file's own structure info and never by a
//! hardcoded table — R5.3's actual requirement — and `CodeWalker`'s 1.5 MB
//! `PsoTypes` fallback, consulted under `//fallback to builtin...`, would have
//! fired zero times.
//!
//! # The seam
//!
//! [`to_xml`] and [`from_xml`], bytes in and bytes out, exactly as `rbf`'s pair
//! is. Two differences, and each is a fact about `PSO` rather than a widening
//! of the seam. `PSO` names are Jenkins hashes, so a [`Dictionary`] decides
//! whether they render as words or as `hash_XXXXXXXX`; it is cosmetic by
//! construction (R5.5) and [`Dictionary::default`] — the empty one — is a
//! complete answer. And [`from_xml`] takes **the payload the document was
//! written from** as well as the document, because a `PSO` file carries an
//! opaque `PSIG`, an encrypted `STRE`, a schema describing structures the data
//! never instantiates and 2.86% of `PSIN` bytes no walk reaches — none of it
//! in the document and none of it inventable. DR-049. This layer still never
//! seeks, never opens a file, and never learns that archives exist
//! (`docs/conventions.md` §2).
//!
//! # The XML this reads and writes
//!
//! DR-047 argues the mapping. Every member of a structure becomes a child
//! element named for that member, carrying one reserved `pso:` attribute that
//! names its type; a structure carries `pso:struct` naming its own type, which
//! is the only place a pointer's concrete type is written down; an array's
//! items are `<pso:item>`.
//!
//! ```xml
//! <CMapTypes pso:struct="CMapTypes">
//!   <archetypes pso:array="atarray">
//!     <pso:item pso:struct="CTimeArchetypeDef">
//!       <lodDist pso:float="100.0"/>
//!       <name pso:hashstring="des_gasstation01"/>
//!     </pso:item>
//!   </archetypes>
//! </CMapTypes>
//! ```
//!
//! `pso:` is a reserved name prefix and deliberately **not** an XML namespace,
//! for the reason DR-043 gives for `RBF`: what a name may be is decided by a
//! dictionary the user supplied, so namespace well-formedness is not this
//! layer's to promise.

mod apply;
mod data;
mod model;
mod render;
mod schema;
mod section;

pub use model::{Malformed, NotPsoXml, Unsupported};

use crate::{
    error::{Error, Result},
    metadata::hash::Dictionary,
};

/// The four bytes a `PSO` file opens with, ASCII `PSIN`.
///
/// A **section tag**, not a header: bytes 4..7 are that section's big-endian
/// length, and walking the chain lands exactly on the last byte in 9,753 of
/// 9,753 files. `docs/metadata-encodings.md`, Recognition.
pub const MAGIC: [u8; 4] = section::PSIN;

/// Reads a `PSO` payload and writes the XML that describes it.
///
/// R5.3. The output is driven entirely by the payload's own `PSCH` and `PMAP`;
/// `names` decides only how the hashes in it are spelled, and an empty
/// dictionary renders every one as `hash_XXXXXXXX`.
///
/// # Errors
///
/// [`Error::BadPso`] if the file contradicts itself — a section that overruns,
/// a pointer outside its block, a structure the file's own schema does not
/// define — and [`Error::UnsupportedPso`] if it is well formed and carries a
/// member type outside the 37 `(type, subtype)` pairs the corpus has.
pub fn to_xml(payload: &[u8], names: &Dictionary) -> Result<Vec<u8>> {
    render::write(payload, names)
}

/// Reads the XML [`to_xml`] wrote and applies it to the payload it came from.
///
/// R5.4, "adopting the schema of the file being edited" — `payload` **is** that
/// file, and everything the document does not carry comes from it: its `PSCH`,
/// its `PMAP`, its `PSIG`, its `STRE`, and every byte of `PSIN` the walk from
/// the root does not reach. DR-049 argues why that is the only honest shape and
/// what the alternatives cost.
///
/// The walk is [`to_xml`]'s, run backwards: every value the document carries is
/// written at the address [`to_xml`] read it from, and nothing else moves. So
/// `from_xml(payload, to_xml(payload, names), names)` is `payload`, byte for
/// byte — **9,753 of 9,753** shipped files, `docs/metadata-encodings.md` — and
/// an edit that changes a value is that value changed and nothing more. `CHKS`
/// is recomputed rather than copied, so an edited file's checksum is right; the
/// recipe reproduces the stored one in 8,978 of 8,978 files that carry a `CHKS`,
/// which is why recomputing costs the unedited round trip nothing.
///
/// An edit that changes the **shape** — a longer string, another array item, a
/// member added — is refused rather than guessed at. `PSO` editing is
/// value-level and stays that way: DR-052.
///
/// # Errors
///
/// [`Error::BadPso`] and [`Error::UnsupportedPso`] for the payload, exactly as
/// [`to_xml`] answers them, and [`Error::NotPsoXml`] when the document is not
/// XML or does not describe this payload — a member the schema does not have
/// there, a type word that is not the one the schema says, an array of a
/// different length, or a value that will not fit where it has to go.
pub fn from_xml(payload: &[u8], document: &[u8], names: &Dictionary) -> Result<Vec<u8>> {
    apply::write(payload, document, names)
}

/// A refusal about the bytes, at the position they are at.
fn bad(offset: u64, cause: Malformed) -> Error {
    Error::BadPso { offset, cause }
}

/// A refusal about this build rather than about the bytes.
fn unsupported(cause: Unsupported) -> Error {
    Error::UnsupportedPso { cause }
}
