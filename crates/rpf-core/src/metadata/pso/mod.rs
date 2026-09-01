//! `PSO` — big-endian tagged sections carrying their own schema, and the XML
//! they convert to.
//!
//! The conversion is driven entirely by the file's own `PSCH` and `PMAP`, never
//! by a hardcoded type table. [`from_xml`] takes the payload the document was
//! written from as well as the document, because a `PSO` file carries bytes the
//! document does not: an opaque `PSIG`, an encrypted `STRE`, and unreached
//! `PSIN`.
//!
//! Every member becomes a child element named for it, carrying one reserved
//! `pso:` attribute naming its type; a structure carries `pso:struct`, the only
//! place a pointer's concrete type is written down; array items are
//! `<pso:item>`. The `pso:` prefix is reserved and deliberately not an XML
//! namespace, since a user-supplied dictionary decides what a name may be.

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
/// A section tag, not a header: bytes 4..7 are that section's big-endian length.
pub const MAGIC: [u8; 4] = section::PSIN;

/// Reads a `PSO` payload and writes the XML that describes it.
///
/// `names` decides only how the hashes are spelled; an empty dictionary renders
/// every one as `hash_XXXXXXXX`.
///
/// # Errors
///
/// [`Error::BadPso`] if the file contradicts itself, and
/// [`Error::UnsupportedPso`] if it is well formed but carries a member type
/// this build does not know.
pub fn to_xml(payload: &[u8], names: &Dictionary) -> Result<Vec<u8>> {
    render::write(payload, names)
}

/// Reads the XML [`to_xml`] wrote and applies it to the payload it came from.
///
/// Everything the document does not carry comes from `payload`. The walk is
/// [`to_xml`]'s run backwards — each value written at the address it was read
/// from, nothing else moved — so an unedited round trip is byte for byte;
/// `CHKS` is recomputed rather than copied, and an edit changing the shape is
/// refused rather than guessed at.
///
/// # Errors
///
/// [`Error::BadPso`] and [`Error::UnsupportedPso`] for the payload, as
/// [`to_xml`] answers them, and [`Error::NotPsoXml`] when the document is not
/// XML or does not describe this payload.
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
