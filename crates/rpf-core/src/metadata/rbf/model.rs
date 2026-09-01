//! The `RBF` document, and the invariants that make it one.
//!
//! Every constraint the two encodings impose is checked in a constructor here,
//! so a value of these types converts to `RBF` bytes and to XML without either
//! conversion being able to fail.

use std::collections::BTreeSet;

use crate::metadata::text::is_xml_name;

/// The reserved XML name prefix, deliberately a prefix and not a namespace:
/// real descriptor names carry `::`, which no namespace can.
pub(super) const RESERVED_PREFIX: &str = "rbf:";

/// The largest descriptor table the one-byte index can address: `0xFD` and
/// `0xFF` are taken by the blob and close records, leaving `0x00`–`0xFC`.
pub(super) const MAX_NAMES: usize = 253;

/// How deeply elements may nest: the format states no limit, but every walk
/// recurses, and a stack overflow is an abort no `Result` catches.
pub(super) const MAX_DEPTH: usize = 256;

/// Why a byte stream is not a well-formed `RBF` token stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Malformed {
    /// The payload does not begin with the four magic bytes.
    NotRbf,
    /// The stream ended in the middle of a record.
    Truncated,
    /// A close or blob record's second byte was not the `0xFF` marker.
    Marker,
    /// A descriptor index named neither an existing descriptor nor the next
    /// one, so there is no name for the record. `0xFE` lands here too.
    DescriptorIndex,
    /// A data-type byte outside the seven records this encoding has.
    DataType,
    /// The first record was not an open element, so there is no root.
    NoRoot,
    /// A record appeared after the root element closed.
    Trailing,
    /// The stream ended with elements still open.
    Unclosed,
    /// An open element declared more attributes than it went on to contain.
    AttributeCount,
    /// Elements nested deeper than this build walks.
    TooDeep,
}

/// Why a well-formed document cannot cross to the other encoding — the same
/// list in both directions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unrepresentable {
    /// A name is not valid UTF-8, so it is not a name XML can carry.
    NameEncoding {
        /// The bytes, as they were read.
        name: Vec<u8>,
    },
    /// A name is not one this build writes: an XML name of ASCII letters,
    /// digits, `_`, `:`, `.` and `-`, starting with a letter, `_` or `:`.
    NameSyntax {
        /// The name.
        name: String,
    },
    /// A name begins with `rbf:`, which the XML reserves.
    NameReserved {
        /// The name.
        name: String,
    },
    /// A name is longer than the `u16` the token stream writes its length in.
    NameTooLong {
        /// How many bytes long.
        len: usize,
    },
    /// Two attributes of one element share a name, which XML cannot carry.
    DuplicateAttribute {
        /// The name they share.
        name: String,
    },
    /// An element has more attributes than the `u16` count can record.
    TooManyAttributes {
        /// How many.
        count: usize,
    },
    /// A string value is longer than the `u16` its length is written in.
    StringTooLong {
        /// How many bytes long.
        len: usize,
    },
    /// A blob is longer than the `u32` its length is written in.
    BlobTooLong {
        /// How many bytes long.
        len: usize,
    },
    /// A blob has no bytes, which XML cannot tell from an element with no text.
    EmptyBlob,
    /// A blob shares its element with child elements, named values or a second
    /// blob, which XML text cannot tell apart from indentation.
    BlobNotAlone {
        /// The element's name.
        name: String,
    },
    /// The document uses more distinct names than the 253 the token stream's
    /// one-byte descriptor index can address.
    TooManyNames {
        /// How many.
        count: usize,
    },
    /// Elements nest deeper than this build walks.
    TooDeep,
}

/// Why an XML document does not describe an `RBF` one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotRbf {
    /// The XML is not well formed. `detail` is what the parser reported, for a
    /// human; `position` on the surrounding error is what a caller acts on.
    Syntax {
        /// The parser's own account of it.
        detail: String,
    },
    /// The document has no element in it.
    Empty,
    /// The document has more than one root element.
    SecondRoot,
    /// The outermost element is a value record. A document's root is an
    /// element, because the token stream's first record is an open element.
    RootNotElement,
    /// A reserved `rbf:` attribute this build does not define.
    UnknownReserved {
        /// The attribute name, prefix included.
        name: String,
    },
    /// An element carrying a value record's reserved attribute also carries
    /// something else. A value record is a name, a type and a value, and
    /// nothing more.
    ValueNotAlone {
        /// The element's name.
        name: String,
    },
    /// A reserved attribute's value is not of the type it names.
    BadValue {
        /// The reserved attribute name, prefix included.
        name: String,
    },
    /// Text appeared where the mapping puts none: in an element that also has
    /// child elements, or outside the root.
    UnexpectedText,
    /// A backslash escape in a string or a blob is not one this encoding
    /// writes: `\\` and `\xNN` are the only two.
    BadEscape,
    /// The document says something the token stream cannot carry.
    Unrepresentable {
        /// Which thing.
        cause: Unrepresentable,
    },
}

/// A descriptor name: an element's, an attribute's or a value's, valid as an
/// XML name and short enough for the token stream's `u16` length.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Name(String);

impl Name {
    /// Checks a name and keeps it.
    pub(super) fn new(text: &str) -> Result<Self, Unrepresentable> {
        if text.len() > usize::from(u16::MAX) {
            return Err(Unrepresentable::NameTooLong { len: text.len() });
        }
        if text.starts_with(RESERVED_PREFIX) {
            return Err(Unrepresentable::NameReserved {
                name: text.to_owned(),
            });
        }
        if !is_xml_name(text) {
            return Err(Unrepresentable::NameSyntax {
                name: text.to_owned(),
            });
        }
        Ok(Self(text.to_owned()))
    }

    /// The name.
    pub(super) fn as_str(&self) -> &str {
        &self.0
    }

    /// The name's bytes, which is what the token stream writes.
    pub(super) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// A `0x60` string value: raw bytes with a `u16` length, not a `String`,
/// because records carry bytes at or above `0x80`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Str(Vec<u8>);

impl Str {
    /// Checks the length and keeps the bytes.
    pub(super) fn new(bytes: Vec<u8>) -> Result<Self, Unrepresentable> {
        if bytes.len() > usize::from(u16::MAX) {
            return Err(Unrepresentable::StringTooLong { len: bytes.len() });
        }
        Ok(Self(bytes))
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A `0xFD` raw byte blob: an element's text, never empty so that an element
/// with text stays distinguishable from one without.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Blob(Vec<u8>);

impl Blob {
    /// Checks the length and keeps the bytes.
    pub(super) fn new(bytes: Vec<u8>) -> Result<Self, Unrepresentable> {
        if bytes.is_empty() {
            return Err(Unrepresentable::EmptyBlob);
        }
        if u32::try_from(bytes.len()).is_err() {
            return Err(Unrepresentable::BlobTooLong { len: bytes.len() });
        }
        Ok(Self(bytes))
    }

    /// The bytes, trailing NUL and all.
    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A value: everything a record can hold that is not an element.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Scalar {
    /// `0x10`, four bytes.
    Uint(u32),
    /// `0x20` and `0x30`, which are the value: no payload follows.
    Bool(bool),
    /// `0x40`, four bytes.
    Float(f32),
    /// `0x50`, twelve bytes, no padding.
    Float3([f32; 3]),
    /// `0x60`, a `u16` length and that many bytes.
    Str(Str),
}

/// One of an element's attribute records.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Attribute {
    pub(super) name: Name,
    pub(super) value: Scalar,
}

/// Something inside an element that is not one of its attributes.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Node {
    Element(Element),
    /// A named value.
    Value {
        /// Its name.
        name: Name,
        /// Its value.
        value: Scalar,
    },
}

/// What an element carries; the two are exclusive, since a blob is the sole
/// content of its element.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Content {
    /// Nested elements and named values, in order. Empty for a leaf.
    Children(Vec<Node>),
    /// One raw byte blob.
    Blob(Blob),
}

/// An open element and everything under it.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Element {
    name: Name,
    unknown: [u16; 2],
    attributes: Vec<Attribute>,
    content: Content,
}

impl Element {
    /// Checks an element and keeps it. `unknown` is the two `u16`s an open
    /// element carries before its attribute count, always 0 but never assumed.
    pub(super) fn new(
        name: Name,
        unknown: [u16; 2],
        attributes: Vec<Attribute>,
        content: Content,
    ) -> Result<Self, Unrepresentable> {
        if u16::try_from(attributes.len()).is_err() {
            return Err(Unrepresentable::TooManyAttributes {
                count: attributes.len(),
            });
        }
        let mut seen = BTreeSet::new();
        for attribute in &attributes {
            if !seen.insert(attribute.name.as_str()) {
                return Err(Unrepresentable::DuplicateAttribute {
                    name: attribute.name.as_str().to_owned(),
                });
            }
        }
        Ok(Self {
            name,
            unknown,
            attributes,
            content,
        })
    }

    /// Its name.
    pub(super) fn name(&self) -> &Name {
        &self.name
    }

    /// The two words an open element carries that mean nothing.
    pub(super) fn unknown(&self) -> [u16; 2] {
        self.unknown
    }

    pub(super) fn attributes(&self) -> &[Attribute] {
        &self.attributes
    }

    pub(super) fn content(&self) -> &Content {
        &self.content
    }
}

/// A whole `RBF` document: one root element.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Document {
    root: Element,
}

impl Document {
    /// Checks that the tree is shallow enough to walk, and keeps it.
    ///
    /// The walk is iterative on purpose: it establishes the depth bound, so it
    /// cannot be the thing that overflows while checking it. [`MAX_NAMES`] is
    /// not checked here — it is the token writer's limit, not the document's.
    pub(super) fn new(root: Element) -> Result<Self, Unrepresentable> {
        let mut pending: Vec<(&Element, usize)> = vec![(&root, 1)];
        while let Some((element, depth)) = pending.pop() {
            if depth > MAX_DEPTH {
                return Err(Unrepresentable::TooDeep);
            }
            if let Content::Children(children) = &element.content {
                for child in children {
                    if let Node::Element(nested) = child {
                        pending.push((nested, depth.saturating_add(1)));
                    }
                }
            }
        }
        Ok(Self { root })
    }

    pub(super) fn root(&self) -> &Element {
        &self.root
    }
}
