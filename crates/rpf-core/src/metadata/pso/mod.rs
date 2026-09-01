//! `PSO` — big-endian tagged sections carrying their own schema, and the XML they convert to.

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

/// The four bytes a `PSO` file opens with, ASCII `PSIN` (a section tag, not a header).
pub const MAGIC: [u8; 4] = section::PSIN;

/// Reads a `PSO` payload and writes the XML that describes it; `names` spells the hashes.
/// # Errors
/// Returns an error if the payload is malformed or has an unsupported member type.
pub fn to_xml(payload: &[u8], names: &Dictionary) -> Result<Vec<u8>> {
    render::write(payload, names)
}

/// Reads the XML `to_xml` wrote and applies it back onto the payload it came from.
/// # Errors
/// Returns an error if the payload is malformed or unsupported, or the document doesn't match it.
pub fn from_xml(payload: &[u8], document: &[u8], names: &Dictionary) -> Result<Vec<u8>> {
    apply::write(payload, document, names)
}

fn bad(offset: u64, cause: Malformed) -> Error {
    Error::BadPso { offset, cause }
}

fn unsupported(cause: Unsupported) -> Error {
    Error::UnsupportedPso { cause }
}
