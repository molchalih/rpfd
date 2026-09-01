//! `RBF` — tokenised binary XML, and the XML it converts to and from.
//!
//! The format is completely self-describing — every name is a literal inline
//! ASCII string, with no string table and no schema — so the XML is driven by
//! the file's own tokens and by nothing else.
//!
//! An element becomes an XML element of the same name; an attribute record
//! becomes a plain attribute when it is a string and `rbf:<type>.<name>`
//! otherwise; a value record becomes an empty child carrying one reserved
//! attribute naming its type; a blob is the element's text, trailing NUL and
//! all. `rbf:` is a reserved prefix and deliberately not a namespace, since
//! real descriptor names carry `::`.

mod model;
mod token;
mod xml;

pub use model::{Malformed, NotRbf, Unrepresentable};

use crate::error::Result;

/// The four magic bytes, ASCII `RBF0`.
pub const MAGIC: [u8; 4] = *b"RBF0";

/// Reads an `RBF` payload and writes the XML that describes it.
///
/// Feeding the output back to [`from_xml`] reproduces the input byte for byte,
/// for a stream whose descriptor table introduces each name once. A stream that
/// declares one name at two descriptors comes back with the second declaration
/// gone — the rebuilt table is keyed by name alone — and that normalised form
/// is a fixed point.
///
/// # Errors
///
/// [`crate::Error::BadRbf`] if the token stream is not well formed, and
/// [`crate::Error::UnrepresentableRbf`] if it is well formed but says something
/// XML cannot.
pub fn to_xml(payload: &[u8]) -> Result<Vec<u8>> {
    Ok(xml::write(&token::read(payload)?))
}

/// Where a refusal about the document as a whole is reported at: a document
/// with too many distinct names has no one line to blame, so it is the start.
const WHOLE_DOCUMENT: u64 = 0;

/// Reads the XML [`to_xml`] writes and rebuilds the `RBF` payload.
///
/// The descriptor table is rebuilt from scratch, keyed by name alone, which is
/// what reproduces the shipped files; keying it by name and type does not.
///
/// # Errors
///
/// [`crate::Error::NotRbfXml`] if the XML is not well formed, or is and does
/// not describe an `RBF` document.
pub fn from_xml(document: &[u8]) -> Result<Vec<u8>> {
    token::write(&xml::read(document)?).map_err(|cause| crate::Error::NotRbfXml {
        position: WHOLE_DOCUMENT,
        cause: NotRbf::Unrepresentable { cause },
    })
}
