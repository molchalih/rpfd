//! The `RBF` document, and the invariants that make it one.
//!
//! Every constraint the two encodings impose is checked in a constructor here,
//! so that a value of these types is convertible to `RBF` bytes and to XML
//! without either conversion being able to fail (`docs/conventions.md` §4, §5).
//! What the token stream cannot express — more than 253 distinct names, a name
//! longer than a `u16` — and what XML cannot express — a name that is not a
//! name, two attributes sharing one, a blob with no bytes — are the same list,
//! checked once, at construction.

use std::collections::BTreeSet;

use crate::metadata::text::is_xml_name;

/// The reserved XML name prefix.
///
/// Deliberately a prefix and **not** a namespace: `docs/metadata-encodings.md`
/// records `CriminalCareerDefs::ShoppingCartItemCategoryLimits` as a real
/// descriptor name, and no namespace-well-formed document can carry it.
pub(super) const RESERVED_PREFIX: &str = "rbf:";

/// The largest descriptor table the one-byte index can address.
///
/// `docs/metadata-encodings.md`, The token stream: `0xFD` and `0xFF` are taken
/// by the blob and close records, so `0x00`–`0xFC` are the indices and there
/// are 253 of them. The corpus reaches 115.
pub(super) const MAX_NAMES: usize = 253;

/// How deeply elements may nest.
///
/// The format states no limit and the corpus reaches 12
/// (`docs/metadata-encodings.md`, What the probe settled). A limit is here
/// because every walk over a document — writing it, and dropping it — recurses,
/// and a stack overflow is an abort that no `Result` can catch, which is worse
/// than the panic `docs/conventions.md` §6 already forbids.
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
    /// one, so there is no name for the record.
    ///
    /// `0xFE` lands here too, and there is no separate case for it: it can only
    /// ever be the 255th index, and the table holds at most 253.
    DescriptorIndex,
    /// A data-type byte outside the seven `docs/metadata-encodings.md` records.
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

/// Why a well-formed document cannot cross to the other encoding.
///
/// The same list in both directions: these are the things one representation
/// can say and the other cannot.
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
    ///
    /// All 6,112 descriptor names in the corpus are of that shape.
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
    /// A blob has no bytes.
    ///
    /// An element whose text is empty is indistinguishable from one with no
    /// text at all, and XML gives no way to tell them apart. 0 of the 48,042
    /// blobs in the corpus are empty.
    EmptyBlob,
    /// A blob shares its element with child elements, with named values, or
    /// with a second blob.
    ///
    /// All 48,042 blobs in the corpus are the **sole** content of their
    /// element. Two adjacent blobs are one text node once written as XML, and
    /// a blob interleaved with elements cannot be told from the indentation
    /// around them, so this is refused rather than silently merged.
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

/// A descriptor name: an element's, an attribute's or a value's.
///
/// Valid as an XML name and short enough for the token stream's `u16` length,
/// because it cannot be built otherwise.
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

/// A `0x60` string value: raw bytes with a `u16` length.
///
/// Bytes, not a `String`. `docs/metadata-encodings.md`: 1,038 records in the
/// corpus carry a byte at or above `0x80`, and `CodeWalker` maps every one of
/// them to `?` by routing them through `Encoding.ASCII`.
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

    /// The bytes.
    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A `0xFD` raw byte blob: an element's text.
///
/// Never empty, so that an element with text is distinguishable from one
/// without once written as XML.
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
    /// Its name.
    pub(super) name: Name,
    /// Its value.
    pub(super) value: Scalar,
}

/// Something inside an element that is not one of its attributes.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Node {
    /// A nested element.
    Element(Element),
    /// A named value.
    Value {
        /// Its name.
        name: Name,
        /// Its value.
        value: Scalar,
    },
}

/// What an element carries.
///
/// The two are exclusive because `docs/metadata-encodings.md` measured them
/// exclusive: a blob is the **sole** content of its element in all 48,042 in
/// the corpus. Modelling it that way is what lets a blob be the element's XML
/// text without whitespace, indentation or a second blob making it ambiguous.
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
    /// Checks an element and keeps it.
    ///
    /// `unknown` is the two `u16`s an open element carries before its attribute
    /// count. `docs/metadata-encodings.md`: both are 0 in all 106,193 open
    /// elements in the corpus, so they carry nothing — but they are kept and
    /// written back rather than assumed, so that the round trip is a property
    /// of the code rather than of the corpus.
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

    /// Its attribute records, in order.
    pub(super) fn attributes(&self) -> &[Attribute] {
        &self.attributes
    }

    /// What it carries.
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
    /// The walk is iterative rather than recursive on purpose: it is what
    /// establishes the depth bound, so it cannot be the thing that overflows
    /// while checking it.
    ///
    /// [`MAX_NAMES`] is **not** checked here, and deliberately. It is a limit
    /// of the token stream's one-byte descriptor index, not of the document —
    /// XML has no such ceiling — so it belongs to the writer that has to
    /// address a descriptor, and `token::write` is where it is reported.
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

    /// Its root element.
    pub(super) fn root(&self) -> &Element {
        &self.root
    }
}
