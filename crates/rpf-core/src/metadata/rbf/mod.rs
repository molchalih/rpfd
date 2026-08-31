//! `RBF` — tokenised binary XML, and the XML it converts to and from.
//!
//! Everything here is `docs/metadata-encodings.md`'s `RBF` section, which is
//! `verified` against all 391 files both GTA V builds ship. Two of its
//! measurements shape the whole module:
//!
//! - **The format is completely self-describing.** Every name is a literal
//!   inline ASCII string, nothing is hashed, and there is no string table and
//!   no schema. So the XML is driven by the file's own tokens and by nothing
//!   else — R5.1.
//! - **Byte-perfect re-serialisation is reachable.** A name-keyed descriptor
//!   table reproduced **391 of 391** shipped files byte-for-byte. That is why
//!   this is a real serialiser and not a differential rebuild.
//!
//! # The seam
//!
//! [`to_xml`] and [`from_xml`], bytes in and bytes out. `docs/conventions.md`
//! §2: this layer never seeks, never opens a file, and never learns that
//! archives exist.
//!
//! # The XML this reads and writes
//!
//! The mapping is argued in full in DR-043; what follows is enough to read the
//! output.
//!
//! An `RBF` element becomes an XML element of the same name. Its attribute
//! records become XML attributes — plainly named when they are strings, which
//! is 50,589 of the 52,397 in the corpus, and prefixed `rbf:<type>.<name>`
//! when they are not. A value record becomes an empty child element carrying
//! one reserved attribute that names its type:
//!
//! ```xml
//! <Item type="CTimeArchetypeDef">
//!   <name>des_gasstation01\x00</name>
//!   <lodDist rbf:uint="100"/>
//!   <bbMin rbf:float3="-13.966396, -15.5559, -0.1963501"/>
//!   <fxOffsetPos rbf:float.x="0.0" rbf:float.y="1.0" rbf:float.z="0.0"/>
//! </Item>
//! ```
//!
//! A raw byte blob is the element's text, with the escape this module's `text`
//! defines — **including its trailing NUL, which is written out rather than
//! assumed.**
//! `docs/metadata-encodings.md` records that `CodeWalker` strips that byte
//! unconditionally and that 5,676 of 48,042 blobs, 11.8%, do not have one; a
//! blob that shows its own bytes cannot reproduce that bug.
//!
//! `rbf:` is a reserved name prefix and deliberately **not** an XML namespace:
//! a real descriptor name in the corpus is
//! `CriminalCareerDefs::ShoppingCartItemCategoryLimits`, which no
//! namespace-well-formed document can carry.

mod model;
mod token;
mod xml;

pub use model::{Malformed, NotRbf, Unrepresentable};

use crate::error::Result;

/// The four magic bytes, ASCII `RBF0`.
///
/// `docs/metadata-encodings.md`, `RBF` Recognition and shape: the fourth byte
/// is `0x30` in all 391 files, so the strict four-byte test costs nothing and
/// the loose three-byte one finds nothing extra.
pub const MAGIC: [u8; 4] = *b"RBF0";

/// Reads an `RBF` payload and writes the XML that describes it.
///
/// The output is driven entirely by the payload's own tokens — R5.1. Feeding
/// it back to [`from_xml`] reproduces the input byte for byte, **for a stream
/// whose descriptor table introduces each name once** — which is all 391
/// shipped files.
///
/// A stream that declares one name at two descriptors comes back with the
/// second declaration gone: the table [`from_xml`] rebuilds is keyed by name
/// alone, so two descriptors of a name collapse into the one they were always
/// interchangeable with. Nothing is lost — the document is identical and only
/// the table spelling it is smaller — and the normalised form is a fixed
/// point. Found by fuzzing on 2026-08-31; pinned by
/// `a_name_two_descriptors_declare_is_read_and_written_back_once`.
///
/// # Errors
///
/// [`crate::Error::BadRbf`] if the token stream is not well formed, and
/// [`crate::Error::UnrepresentableRbf`] if it is well formed but says something
/// XML cannot: a name that is not a name, two attributes that share one, or a
/// blob with no bytes.
pub fn to_xml(payload: &[u8]) -> Result<Vec<u8>> {
    Ok(xml::write(&token::read(payload)?))
}

/// Where a refusal that is about the document as a whole is reported at.
///
/// [`crate::Error::NotRbfXml`] carries a position so that an editor can put the
/// cursor on the line that has to change. A document that has too many distinct
/// names for the token stream to address has no such line — every name is
/// equally responsible — so it is reported at the start.
const WHOLE_DOCUMENT: u64 = 0;

/// Reads the XML [`to_xml`] writes and rebuilds the `RBF` payload.
///
/// R5.2. The descriptor table is rebuilt from scratch, keyed **by name alone**:
/// `docs/metadata-encodings.md` measured that a name-keyed table reproduces
/// 391 of 391 shipped files and a name-and-type-keyed one only 205.
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
