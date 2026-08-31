//! Which encodings have an XML view, and the conversion each of them is.
//!
//! One dispatcher per direction over the encodings [`Encoding`] names, and one
//! more pair for the encoding [`Encoding`] deliberately does not name —
//! resource-embedded `Meta`, which is recognised from the entry's kind and the
//! contents' own magic rather than from a payload's head (R5.8, DR-044). And
//! nothing else: the conversions themselves are [`crate::metadata::rbf`]'s and
//! [`crate::metadata::pso`]'s, and this module holds no signature, no schema
//! and no token. It takes and returns bytes for the reason every module in
//! this layer does (`docs/conventions.md` §2).
//!
//! **The set of encodings with an XML view is written down once, here**, as the
//! arms of [`to_xml`] and the recognition in [`resource_to_xml`]. `None` is the answer for an encoding that has none, and
//! a caller asking whether there is one asks by calling — there is no second
//! predicate to drift from the match (§3). DR-053.
//!
//! [`Encoding::Xml`] is in the set and its conversion is the identity: a
//! payload that is already an XML document is its own XML view. That is not a
//! special case bolted on, it is what the view means — what a caller reads is
//! what it edits and hands back — and it is what keeps a client from having to
//! know which of the three it is looking at.

use crate::{
    error::Result,
    metadata::{Encoding, hash::Dictionary, meta, pso, rbf},
};

/// The XML view of this payload, or `None` when its encoding has none.
///
/// The encoding is the payload's own, by [`Encoding::of`] over its head, so a
/// caller that has not classified anything still gets the right answer. `names`
/// decides only how a `PSO`'s hashes are spelled and is cosmetic by
/// construction (R5.5).
///
/// # Errors
///
/// Whatever the encoding's own converter answers — [`crate::Error::BadRbf`],
/// [`crate::Error::BadPso`], [`crate::Error::UnsupportedPso`] — for a payload
/// that announces an encoding and then contradicts it.
pub fn to_xml(payload: &[u8], names: &Dictionary) -> Result<Option<Vec<u8>>> {
    let head = payload.get(..Encoding::HEAD_LEN).unwrap_or(payload);
    match Encoding::of(head) {
        Some(Encoding::Rbf) => rbf::to_xml(payload).map(Some),
        Some(Encoding::Pso) => pso::to_xml(payload, names).map(Some),
        Some(Encoding::Xml) => Ok(Some(payload.to_vec())),
        Some(Encoding::Text) | None => Ok(None),
    }
}

/// The payload `document` describes, applied to the payload it came from, or
/// `None` when that payload's encoding has no XML view.
///
/// `payload` is the file being edited and not merely a template: `PSO` carries
/// an opaque `PSIG`, an encrypted `STRE`, a schema describing structures the
/// data never instantiates, and 2.86% of `PSIN` bytes no walk reaches, none of
/// it in the document and none of it inventable. DR-049.
///
/// The encoding is `payload`'s, never the document's: what an entry holds is
/// what a write into it has to be, which is the whole of DR-050's rule one
/// layer down.
///
/// # Errors
///
/// [`crate::Error::NotRbfXml`] or [`crate::Error::NotPsoXml`] for a document
/// that does not describe this payload, and the encoding's own refusals for a
/// payload that contradicts itself.
pub fn from_xml(payload: &[u8], document: &[u8], names: &Dictionary) -> Result<Option<Vec<u8>>> {
    let head = payload.get(..Encoding::HEAD_LEN).unwrap_or(payload);
    match Encoding::of(head) {
        Some(Encoding::Rbf) => rbf::from_xml(document).map(Some),
        Some(Encoding::Pso) => pso::from_xml(payload, document, names).map(Some),
        Some(Encoding::Xml) => Ok(Some(document.to_vec())),
        Some(Encoding::Text) | None => Ok(None),
    }
}

/// The XML view of a resource entry's **inflated contents**, or `None` when
/// they are not a `Meta`.
///
/// The second dispatcher, and it is a second one because a resource is not
/// recognised the way a binary payload is. What an entry *is* comes from its
/// row (Q7, DR-044), so a caller reaches this only for an entry the container
/// has already called a resource; what the contents then are is
/// [`meta::identifies`], the `0x50524430` word at offset `0x10` that 49,614 of
/// 49,614 shipped `Meta` files carry and no `.ynv` or `.ytd` of the same
/// resource version does. R5.8.
///
/// `system_len` is how many of `contents` are system pages —
/// `crate::format::resource::size_from_flags` of the entry's system flags. It
/// is a fact about the **entry**, appears nowhere in the payload, and a caller
/// that hands over a payload without the boundary that belongs to it gets a
/// refusal rather than a wrong answer: every resource pointer is resolved
/// against it.
///
/// # Errors
///
/// [`crate::Error::BadMeta`] and [`crate::Error::UnsupportedMeta`], exactly as
/// [`meta::to_xml`] answers them — including for a `Meta` read against a
/// boundary that is not its own.
pub fn resource_to_xml(
    contents: &[u8],
    system_len: usize,
    names: &Dictionary,
) -> Result<Option<Vec<u8>>> {
    if !meta::identifies(contents) {
        return Ok(None);
    }
    meta::to_xml(contents, system_len, names).map(Some)
}

/// The payload `document` describes, applied to the resource contents it came
/// from, or `None` when those contents are not a `Meta`.
///
/// [`resource_to_xml`]'s direction reversed, on [`from_xml`]'s terms: the
/// contents are the file being edited and not a template, because 2.48% of a
/// `Meta` payload is unreached and nonzero and no document carries it (DR-049).
///
/// # Errors
///
/// [`crate::Error::NotMetaXml`] for a document that does not describe these
/// contents, and the payload's own refusals as [`resource_to_xml`] answers
/// them.
pub fn resource_from_xml(
    contents: &[u8],
    system_len: usize,
    document: &[u8],
    names: &Dictionary,
) -> Result<Option<Vec<u8>>> {
    if !meta::identifies(contents) {
        return Ok(None);
    }
    meta::from_xml(contents, system_len, document, names).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_and_unknown_bytes_have_no_xml_view() {
        let names = Dictionary::default();
        for payload in [&b"Version 1\r\nabcdef"[..], &[0_u8; 32][..], b""] {
            assert_eq!(to_xml(payload, &names).expect("no view"), None);
            assert_eq!(from_xml(payload, b"<x/>", &names).expect("no view"), None);
        }
    }

    #[test]
    fn a_plain_xml_payload_is_its_own_view_in_both_directions() {
        let names = Dictionary::default();
        let payload = b"<?xml version=\"1.0\"?><CMapTypes/>";
        assert_eq!(
            to_xml(payload, &names).expect("a view").as_deref(),
            Some(&payload[..])
        );
        // And the document replaces it, which is what an edit of a plain XML
        // entry is.
        let edited = b"<?xml version=\"1.0\"?><CMapTypes><a/></CMapTypes>";
        assert_eq!(
            from_xml(payload, edited, &names)
                .expect("a view")
                .as_deref(),
            Some(&edited[..])
        );
    }

    #[test]
    fn resource_contents_that_are_not_a_meta_have_no_view_in_either_direction() {
        // The resource dispatcher's `None`, which is what an entry the
        // container calls a resource and whose contents carry no `Meta` magic
        // answers. A texture is not a document and does not become one by
        // being asked twice.
        let names = Dictionary::default();
        let contents = vec![0_u8; 512];
        assert_eq!(
            resource_to_xml(&contents, contents.len(), &names).expect("no view"),
            None
        );
        assert_eq!(
            resource_from_xml(&contents, contents.len(), b"<x/>", &names).expect("no view"),
            None
        );
    }

    #[test]
    fn the_dispatch_is_the_payloads_own_encoding_and_never_the_documents() {
        // A document that is XML offered against a payload that has no view is
        // still no view: what the entry holds decides. DR-050 one layer down.
        let names = Dictionary::default();
        let payload = b"Version 1\r\nabcdef";
        assert_eq!(
            from_xml(payload, b"<?xml version=\"1.0\"?><a/>", &names).expect("no view"),
            None
        );
    }
}
