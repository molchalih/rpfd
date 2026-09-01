//! The `RBF` token stream: magic bytes then records, all little-endian, to `Document` and back.

use std::collections::BTreeMap;

use super::{
    MAGIC,
    model::{
        Attribute, Blob, Content, Document, Element, MAX_DEPTH, MAX_NAMES, Malformed, Name, Node,
        Scalar, Str, Unrepresentable,
    },
};
use crate::error::{Error, Result};

/// What the write path answers: a refusal in the module's own vocabulary.
type Written<T> = std::result::Result<T, Unrepresentable>;

/// The close record, `FF FF`. Pops the stack; with the stack empty the file ends.
const CLOSE: u8 = 0xFF;

/// The raw byte blob record, `FD FF len:u32 bytes[len]`.
const BLOB: u8 = 0xFD;

/// The second byte of both the close record and the blob record.
const MARKER: u8 = 0xFF;

/// `0x00` — open element. Six bytes follow: `unk1:u16 unk2:u16 attrCount:u16`.
const OPEN: u8 = 0x00;
/// `0x10` — `u32`, four bytes.
const UINT: u8 = 0x10;
/// `0x20` — boolean true. The type byte *is* the value; no payload follows.
const TRUE: u8 = 0x20;
/// `0x30` — boolean false.
const FALSE: u8 = 0x30;
/// `0x40` — `f32`, four bytes.
const FLOAT: u8 = 0x40;
/// `0x50` — three `f32`, twelve bytes, no padding.
const FLOAT3: u8 = 0x50;
/// `0x60` — string, `len:u16` then that many bytes, not NUL-terminated.
const STRING: u8 = 0x60;

struct Tokens<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Tokens<'a> {
    fn bad(&self, cause: Malformed) -> Error {
        Error::BadRbf {
            offset: u64::try_from(self.at).unwrap_or(u64::MAX),
            cause,
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(len)
            .ok_or_else(|| self.bad(Malformed::Truncated))?;
        let taken = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| self.bad(Malformed::Truncated))?;
        self.at = end;
        Ok(taken)
    }

    fn byte(&mut self) -> Result<u8> {
        let taken = self.take(1)?;
        taken
            .first()
            .copied()
            .ok_or_else(|| self.bad(Malformed::Truncated))
    }

    /// The next four bytes, as they lie.
    fn word(&mut self) -> Result<[u8; 4]> {
        let taken = self.take(4)?;
        <[u8; 4]>::try_from(taken).map_err(|_| self.bad(Malformed::Truncated))
    }

    /// The next little-endian `u16`.
    fn u16(&mut self) -> Result<u16> {
        let taken = self.take(2)?;
        let pair = <[u8; 2]>::try_from(taken).map_err(|_| self.bad(Malformed::Truncated))?;
        Ok(u16::from_le_bytes(pair))
    }

    /// The next little-endian `u32`.
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.word()?))
    }

    /// The next little-endian `f32`.
    fn f32(&mut self) -> Result<f32> {
        Ok(f32::from_le_bytes(self.word()?))
    }

    fn spent(&self) -> bool {
        self.at >= self.bytes.len()
    }
}

struct Open {
    name: Name,
    unknown: [u16; 2],
    attributes_wanted: usize,
    attributes: Vec<Attribute>,
    children: Vec<Node>,
    blob: Option<Blob>,
}

impl Open {
    fn wants_attribute(&self) -> bool {
        self.attributes.len() < self.attributes_wanted
    }

    fn admits_content(&self, tokens: &Tokens<'_>) -> Result<()> {
        if self.blob.is_some() {
            return Err(unrepresentable(Unrepresentable::BlobNotAlone {
                name: self.name.as_str().to_owned(),
            }));
        }
        if self.wants_attribute() {
            return Err(tokens.bad(Malformed::AttributeCount));
        }
        Ok(())
    }

    fn close(self) -> Result<Element> {
        if self.wants_attribute() {
            return Err(Error::BadRbf {
                offset: 0,
                cause: Malformed::AttributeCount,
            });
        }
        let content = match self.blob {
            Some(blob) if self.children.is_empty() => Content::Blob(blob),
            Some(_) => {
                return Err(unrepresentable(Unrepresentable::BlobNotAlone {
                    name: self.name.as_str().to_owned(),
                }));
            }
            None => Content::Children(self.children),
        };
        Element::new(self.name, self.unknown, self.attributes, content).map_err(unrepresentable)
    }
}

/// Wraps a refusal that is about the document rather than about the bytes.
fn unrepresentable(cause: Unrepresentable) -> Error {
    Error::UnrepresentableRbf { cause }
}

pub(super) fn read(payload: &[u8]) -> Result<Document> {
    let mut tokens = Tokens {
        bytes: payload,
        at: 0,
    };
    if tokens.take(MAGIC.len()).ok() != Some(&MAGIC) {
        return Err(Error::BadRbf {
            offset: 0,
            cause: Malformed::NotRbf,
        });
    }

    let mut descriptors: Vec<Name> = Vec::new();
    let mut stack: Vec<Open> = Vec::new();
    let mut root: Option<Element> = None;

    while root.is_none() {
        let at = tokens.at;
        let first = tokens.byte()?;
        match first {
            CLOSE => {
                expect_marker(&mut tokens)?;
                let Some(open) = stack.pop() else {
                    return Err(tokens.bad(Malformed::NoRoot));
                };
                let element = open.close().map_err(|error| reoffset(error, at))?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(Node::Element(element)),
                    None => root = Some(element),
                }
            }
            BLOB => {
                expect_marker(&mut tokens)?;
                let len =
                    usize::try_from(tokens.u32()?).map_err(|_| tokens.bad(Malformed::Truncated))?;
                let bytes = tokens.take(len)?.to_vec();
                let Some(open) = stack.last() else {
                    return Err(tokens.bad(Malformed::NoRoot));
                };
                open.admits_content(&tokens)?;
                let blob = Blob::new(bytes).map_err(unrepresentable)?;
                if let Some(open) = stack.last_mut() {
                    open.blob = Some(blob);
                }
            }
            index => named(&mut tokens, &mut descriptors, &mut stack, index)?,
        }
        if root.is_none() && tokens.spent() {
            return Err(tokens.bad(Malformed::Unclosed));
        }
    }

    if !tokens.spent() {
        return Err(tokens.bad(Malformed::Trailing));
    }
    let Some(element) = root else {
        return Err(tokens.bad(Malformed::NoRoot));
    };
    Document::new(element).map_err(unrepresentable)
}

/// Reads one named record and its payload, and puts it where it belongs.
fn named(
    tokens: &mut Tokens<'_>,
    descriptors: &mut Vec<Name>,
    stack: &mut Vec<Open>,
    index: u8,
) -> Result<()> {
    let kind = tokens.byte()?;
    let name = descriptor(tokens, descriptors, usize::from(index))?;
    if kind == OPEN {
        if stack.len() >= MAX_DEPTH {
            return Err(tokens.bad(Malformed::TooDeep));
        }
        if let Some(open) = stack.last() {
            open.admits_content(tokens)?;
        }
        let unknown = [tokens.u16()?, tokens.u16()?];
        let attributes_wanted = usize::from(tokens.u16()?);
        stack.push(Open {
            name,
            unknown,
            attributes_wanted,
            attributes: Vec::new(),
            children: Vec::new(),
            blob: None,
        });
        return Ok(());
    }
    let value = scalar(tokens, kind)?;
    let Some(open) = stack.last_mut() else {
        return Err(tokens.bad(Malformed::NoRoot));
    };
    if open.blob.is_some() {
        return Err(unrepresentable(Unrepresentable::BlobNotAlone {
            name: open.name.as_str().to_owned(),
        }));
    }
    if open.wants_attribute() {
        open.attributes.push(Attribute { name, value });
    } else {
        open.children.push(Node::Value { name, value });
    }
    Ok(())
}

fn expect_marker(tokens: &mut Tokens<'_>) -> Result<()> {
    if tokens.byte()? == MARKER {
        Ok(())
    } else {
        Err(tokens.bad(Malformed::Marker))
    }
}

/// Gives an error that was raised without one the position it happened at.
fn reoffset(error: Error, at: usize) -> Error {
    match error {
        Error::BadRbf { cause, .. } => Error::BadRbf {
            offset: u64::try_from(at).unwrap_or(u64::MAX),
            cause,
        },
        other => other,
    }
}

/// The name a record's descriptor index refers to.
fn descriptor(tokens: &mut Tokens<'_>, descriptors: &mut Vec<Name>, index: usize) -> Result<Name> {
    if index == descriptors.len() {
        let len = usize::from(tokens.u16()?);
        let bytes = tokens.take(len)?;
        let text = str::from_utf8(bytes).map_err(|_| {
            unrepresentable(Unrepresentable::NameEncoding {
                name: bytes.to_vec(),
            })
        })?;
        descriptors.push(Name::new(text).map_err(unrepresentable)?);
    }
    descriptors
        .get(index)
        .cloned()
        .ok_or_else(|| tokens.bad(Malformed::DescriptorIndex))
}

fn scalar(tokens: &mut Tokens<'_>, kind: u8) -> Result<Scalar> {
    match kind {
        UINT => Ok(Scalar::Uint(tokens.u32()?)),
        TRUE => Ok(Scalar::Bool(true)),
        FALSE => Ok(Scalar::Bool(false)),
        FLOAT => Ok(Scalar::Float(tokens.f32()?)),
        FLOAT3 => Ok(Scalar::Float3([
            tokens.f32()?,
            tokens.f32()?,
            tokens.f32()?,
        ])),
        STRING => {
            let len = usize::from(tokens.u16()?);
            let bytes = tokens.take(len)?.to_vec();
            Ok(Scalar::Str(Str::new(bytes).map_err(unrepresentable)?))
        }
        _ => Err(tokens.bad(Malformed::DataType)),
    }
}

struct Descriptors<'a>(BTreeMap<&'a str, u8>);

impl<'a> Descriptors<'a> {
    /// The index for `name`, and whether this call introduced it.
    fn index(&mut self, name: &'a Name) -> Written<(u8, bool)> {
        if let Some(&at) = self.0.get(name.as_str()) {
            return Ok((at, false));
        }
        let count = self.0.len();
        let at = u8::try_from(count)
            .ok()
            .filter(|_| count < MAX_NAMES)
            .ok_or(Unrepresentable::TooManyNames { count })?;
        self.0.insert(name.as_str(), at);
        Ok((at, true))
    }
}

pub(super) fn write(document: &Document) -> Written<Vec<u8>> {
    let mut out = MAGIC.to_vec();
    let mut descriptors = Descriptors(BTreeMap::new());
    write_element(&mut out, &mut descriptors, document.root())?;
    Ok(out)
}

/// Writes one element, its attributes, its content and its close record.
fn write_element<'a>(
    out: &mut Vec<u8>,
    descriptors: &mut Descriptors<'a>,
    element: &'a Element,
) -> Written<()> {
    write_record(out, descriptors, element.name(), OPEN)?;
    for word in element.unknown() {
        out.extend_from_slice(&word.to_le_bytes());
    }
    let count = u16::try_from(element.attributes().len()).map_err(|_| {
        Unrepresentable::TooManyAttributes {
            count: element.attributes().len(),
        }
    })?;
    out.extend_from_slice(&count.to_le_bytes());
    for attribute in element.attributes() {
        write_value(out, descriptors, &attribute.name, &attribute.value)?;
    }
    match element.content() {
        Content::Blob(blob) => write_blob(out, blob)?,
        Content::Children(children) => {
            for child in children {
                match child {
                    Node::Element(nested) => write_element(out, descriptors, nested)?,
                    Node::Value { name, value } => write_value(out, descriptors, name, value)?,
                }
            }
        }
    }
    out.push(CLOSE);
    out.push(MARKER);
    Ok(())
}

fn write_value<'a>(
    out: &mut Vec<u8>,
    descriptors: &mut Descriptors<'a>,
    name: &'a Name,
    value: &Scalar,
) -> Written<()> {
    write_record(out, descriptors, name, kind_of(value))?;
    match value {
        Scalar::Uint(number) => out.extend_from_slice(&number.to_le_bytes()),
        Scalar::Bool(_) => {}
        Scalar::Float(number) => out.extend_from_slice(&number.to_le_bytes()),
        Scalar::Float3(numbers) => {
            for number in numbers {
                out.extend_from_slice(&number.to_le_bytes());
            }
        }
        Scalar::Str(text) => {
            let len = u16::try_from(text.as_bytes().len()).map_err(|_| {
                Unrepresentable::StringTooLong {
                    len: text.as_bytes().len(),
                }
            })?;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(text.as_bytes());
        }
    }
    Ok(())
}

/// Writes a record's index and type byte, and its name if this is its first use.
fn write_record<'a>(
    out: &mut Vec<u8>,
    descriptors: &mut Descriptors<'a>,
    name: &'a Name,
    kind: u8,
) -> Written<()> {
    let (index, introduced) = descriptors.index(name)?;
    out.push(index);
    out.push(kind);
    if introduced {
        let len =
            u16::try_from(name.as_bytes().len()).map_err(|_| Unrepresentable::NameTooLong {
                len: name.as_bytes().len(),
            })?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
    }
    Ok(())
}

fn write_blob(out: &mut Vec<u8>, blob: &Blob) -> Written<()> {
    let len = u32::try_from(blob.as_bytes().len()).map_err(|_| Unrepresentable::BlobTooLong {
        len: blob.as_bytes().len(),
    })?;
    out.push(BLOB);
    out.push(MARKER);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(blob.as_bytes());
    Ok(())
}

fn kind_of(value: &Scalar) -> u8 {
    match value {
        Scalar::Uint(_) => UINT,
        Scalar::Bool(true) => TRUE,
        Scalar::Bool(false) => FALSE,
        Scalar::Float(_) => FLOAT,
        Scalar::Float3(_) => FLOAT3,
        Scalar::Str(_) => STRING,
    }
}
