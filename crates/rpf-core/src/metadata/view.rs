//! Which encodings have an XML view, and the conversion each of them is.

use crate::{
    error::Result,
    metadata::{Encoding, hash::Dictionary, meta, pso, rbf},
};

/// The XML view of this payload, or `None` when its encoding has none.
/// # Errors
/// Returns an error if the payload announces an encoding then contradicts it.
pub fn to_xml(payload: &[u8], names: &Dictionary) -> Result<Option<Vec<u8>>> {
    let head = payload.get(..Encoding::HEAD_LEN).unwrap_or(payload);
    match Encoding::of(head) {
        Some(Encoding::Rbf) => rbf::to_xml(payload).map(Some),
        Some(Encoding::Pso) => pso::to_xml(payload, names).map(Some),
        Some(Encoding::Xml) => Ok(Some(payload.to_vec())),
        Some(Encoding::Text) | None => Ok(None),
    }
}

/// The payload `document` describes, applied back, or `None` when there's no XML view.
/// # Errors
/// Returns an error if `document` does not describe this payload.
pub fn from_xml(payload: &[u8], document: &[u8], names: &Dictionary) -> Result<Option<Vec<u8>>> {
    let head = payload.get(..Encoding::HEAD_LEN).unwrap_or(payload);
    match Encoding::of(head) {
        Some(Encoding::Rbf) => rbf::from_xml(document).map(Some),
        Some(Encoding::Pso) => pso::from_xml(payload, document, names).map(Some),
        Some(Encoding::Xml) => Ok(Some(document.to_vec())),
        Some(Encoding::Text) | None => Ok(None),
    }
}

/// The XML view of a resource entry's inflated contents, or `None` when not a `Meta`.
/// # Errors
/// Returns an error if the contents look like a `Meta` but aren't one this build supports.
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

/// The payload `document` describes, applied to those resource contents, or `None` if not a `Meta`.
/// # Errors
/// Returns an error if `document` does not describe these contents.
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
        let names = Dictionary::default();
        let payload = b"Version 1\r\nabcdef";
        assert_eq!(
            from_xml(payload, b"<?xml version=\"1.0\"?><a/>", &names).expect("no view"),
            None
        );
    }
}
