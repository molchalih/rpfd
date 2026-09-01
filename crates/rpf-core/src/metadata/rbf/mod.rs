//! `RBF` — tokenised binary XML, self-describing with no string table and no schema.

mod model;
mod token;
mod xml;

pub use model::{Malformed, NotRbf, Unrepresentable};

use crate::error::Result;

/// The four magic bytes, ASCII `RBF0`.
pub const MAGIC: [u8; 4] = *b"RBF0";

/// Reads an `RBF` payload and writes the XML that describes it.
/// # Errors
/// Returns an error if the token stream is malformed or says something XML cannot.
pub fn to_xml(payload: &[u8]) -> Result<Vec<u8>> {
    Ok(xml::write(&token::read(payload)?))
}

const WHOLE_DOCUMENT: u64 = 0;

/// Reads the XML `to_xml` writes and rebuilds the `RBF` payload.
/// # Errors
/// Returns an error if the XML is malformed or does not describe an `RBF` document.
pub fn from_xml(document: &[u8]) -> Result<Vec<u8>> {
    token::write(&xml::read(document)?).map_err(|cause| crate::Error::NotRbfXml {
        position: WHOLE_DOCUMENT,
        cause: NotRbf::Unrepresentable { cause },
    })
}
