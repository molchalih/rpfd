//! What a payload announces itself to be, from its leading bytes.

pub mod hash;
pub mod meta;
pub mod pso;
pub mod rbf;
pub(crate) mod text;
pub mod view;

/// The `RBF` magic: bytes 0..3 of a tokenised binary XML file.
pub const MAGIC_RBF: [u8; 4] = *b"RBF0";

/// The `PSO` magic: bytes 0..3 of a `PSO` file, the tag of its first section.
pub const MAGIC_PSO: [u8; 4] = *b"PSIN";

/// The UTF-8 byte-order mark a plain XML payload may carry before its first `<`.
pub const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// What an entry's payload announces itself to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Encoding {
    /// Plain XML.
    Xml,
    /// Text that is not XML, judged over `Encoding::HEAD_LEN` bytes.
    Text,
    /// `RBF`, tokenised binary XML.
    Rbf,
    /// `PSO`, a concatenation of tagged big-endian sections.
    Pso,
}

impl Encoding {
    /// Bytes of a payload `of` inspects: four times the longest signature.
    pub const HEAD_LEN: usize = 16;

    /// This encoding's name, in the spelling everything reports it in.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Xml => "xml",
            Self::Text => "text",
            Self::Rbf => "rbf",
            Self::Pso => "pso",
        }
    }

    /// The encoding among `offered` this one refuses, or `None` when it takes it.
    #[must_use]
    pub const fn refuses(self, offered: Option<Self>) -> Option<Self> {
        match (self, offered) {
            (Self::Rbf | Self::Pso, Some(refused @ (Self::Xml | Self::Text))) => Some(refused),
            _ => None,
        }
    }

    /// The encoding these leading bytes announce; `head` must be the true prefix, not padded.
    #[must_use]
    pub fn of(head: &[u8]) -> Option<Self> {
        if head.starts_with(&MAGIC_RBF) {
            return Some(Self::Rbf);
        }
        if head.starts_with(&MAGIC_PSO) {
            return Some(Self::Pso);
        }
        let body = head.strip_prefix(&UTF8_BOM).unwrap_or(head);
        if opens_a_tag(body) {
            return Some(Self::Xml);
        }
        if !body.is_empty() && body.iter().all(|byte| is_text(*byte)) {
            return Some(Self::Text);
        }
        None
    }
}

fn opens_a_tag(body: &[u8]) -> bool {
    let opened = trimmed(body);
    opened
        .strip_prefix(b"<")
        .and_then(<[u8]>::first)
        .is_some_and(|byte| begins_a_tag_name(*byte))
}

fn trimmed(body: &[u8]) -> &[u8] {
    let mut rest = body;
    while let Some((first, tail)) = rest.split_first() {
        if !is_space(*first) {
            break;
        }
        rest = tail;
    }
    rest
}

const fn begins_a_tag_name(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || matches!(byte, b'_' | b':' | b'?' | b'!')
}

const fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

const fn is_text(byte: u8) -> bool {
    byte.is_ascii_graphic() || is_space(byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(prefix: &[u8]) -> Vec<u8> {
        let mut out = prefix.to_vec();
        out.resize(Encoding::HEAD_LEN, 0x00);
        out
    }

    fn text_head(prefix: &[u8]) -> Vec<u8> {
        let mut out = prefix.to_vec();
        out.resize(Encoding::HEAD_LEN, b'A');
        out
    }

    #[test]
    fn the_magics_are_the_bytes_the_format_document_records() {
        assert_eq!(MAGIC_RBF, [b'R', b'B', b'F', b'0']);
        assert_eq!(MAGIC_PSO, [b'P', b'S', b'I', b'N']);
        assert_eq!(UTF8_BOM, [0xEF, 0xBB, 0xBF]);
    }

    #[test]
    fn the_rbf_magic_is_four_bytes_and_the_fourth_is_a_zero() {
        assert_eq!(Encoding::of(&head(b"RBF0")), Some(Encoding::Rbf));
        assert_eq!(Encoding::of(&head(b"RBF1")), None);
        assert_eq!(Encoding::of(&head(b"RBF")), None);
        assert_eq!(Encoding::of(&text_head(b"RBF1")), Some(Encoding::Text));
    }

    #[test]
    fn a_pso_is_its_first_section_tag() {
        assert_eq!(Encoding::of(&head(b"PSIN")), Some(Encoding::Pso));
        // The other tags are sections inside a `PSO` and never begin a file.
        for tag in [b"PMAP", b"PSCH", b"PSIG", b"CHKS", b"STRE", b"STRF"] {
            assert_eq!(Encoding::of(&head(tag)), None, "{:?}", *tag);
        }
    }

    #[test]
    fn plain_xml_is_recognised_with_and_without_a_byte_order_mark() {
        assert_eq!(Encoding::of(&head(b"<?xml version=")), Some(Encoding::Xml));
        let mut marked = UTF8_BOM.to_vec();
        marked.extend_from_slice(b"<?xml version");
        assert_eq!(Encoding::of(&head(&marked)), Some(Encoding::Xml));
        assert_eq!(Encoding::of(&head(b"<CMapTypes>")), Some(Encoding::Xml));
        assert_eq!(Encoding::of(&head(b"<!-- a comment")), Some(Encoding::Xml));
    }

    #[test]
    fn xml_is_recognised_through_the_whitespace_26_files_begin_with() {
        assert_eq!(
            Encoding::of(&head(b"\r\n<?xml version")),
            Some(Encoding::Xml)
        );
        assert_eq!(Encoding::of(&head(b" <?xml version=")), Some(Encoding::Xml));
        assert_eq!(
            Encoding::of(&head(b"\r\n<StatsSetup ve")),
            Some(Encoding::Xml)
        );
    }

    #[test]
    fn an_angle_bracket_before_a_byte_no_tag_name_starts_with_is_not_xml() {
        // An `.awc` payload beginning `0x3c` by chance: its second byte begins
        // no tag name, and the head is not text either.
        let awc = [
            0x3c, 0xeb, 0x08, 0x4f, 0xd1, 0xa6, 0x5e, 0xcf, 0x87, 0xca, 0x5f, 0xbf, 0x57, 0x7e,
            0x5f, 0xc5,
        ];
        assert_eq!(Encoding::of(&awc), None);
    }

    #[test]
    fn text_that_is_not_xml_is_text() {
        assert_eq!(
            Encoding::of(&text_head(b"Version 1\r\n")),
            Some(Encoding::Text)
        );
        assert_eq!(Encoding::of(b"-"), Some(Encoding::Text));
    }

    #[test]
    fn a_head_of_text_followed_by_a_high_byte_is_not_text() {
        // The sixteenth byte decides.
        let mut bytes = b"ADATabcdefghijkl".to_vec();
        assert_eq!(Encoding::of(&bytes), Some(Encoding::Text));
        bytes.pop();
        bytes.push(0x88);
        assert_eq!(Encoding::of(&bytes), None);
    }

    #[test]
    fn a_payload_too_short_to_carry_a_signature_names_something_or_nothing() {
        assert_eq!(Encoding::of(b""), None);
        assert_eq!(Encoding::of(&[0x00]), None);
        assert_eq!(Encoding::of(b"RB"), Some(Encoding::Text));
        assert_eq!(Encoding::of(&UTF8_BOM), None);
    }

    #[test]
    fn a_payload_that_is_all_angle_brackets_is_text_and_does_not_panic() {
        assert_eq!(
            Encoding::of(&[b'<'; Encoding::HEAD_LEN]),
            Some(Encoding::Text)
        );
        assert_eq!(Encoding::of(b"<"), Some(Encoding::Text));
    }

    #[test]
    fn a_nul_run_names_nothing() {
        assert_eq!(Encoding::of(&[0_u8; Encoding::HEAD_LEN]), None);
    }

    #[test]
    fn no_head_of_any_shape_panics() {
        for byte in 0..=u8::MAX {
            for len in 0..=Encoding::HEAD_LEN {
                let bytes = vec![byte; len];
                let _ = Encoding::of(&bytes);
                let mut marked = UTF8_BOM.to_vec();
                marked.extend_from_slice(&bytes);
                let _ = Encoding::of(&marked);
                let mut opened = vec![b'<'];
                opened.extend_from_slice(&bytes);
                let _ = Encoding::of(&opened);
            }
        }
    }
}
