//! The XML read back and applied to the file: `render`'s walk, backwards, so nothing structural changes.

use quick_xml::{
    Reader, XmlVersion,
    events::{BytesStart, Event},
};

use super::{
    bad,
    data::{Data, step, until_nul},
    model::{MAX_DEPTH, Malformed, NotPsoXml, document_budget},
    render::{ARRAY, ATBINARYMAP, BITSET, ENUM, ITEM, MAP, NULL, STRUCT},
    schema::{
        Blocks, CAPACITY_AT, COUNT_AT, Kind, Layout, MAP_POINTER_AT, Member, Nested, Scalar,
        Schema, Structure, Text, Width,
    },
    section,
};
use crate::{
    error::{Error, Result},
    metadata::{
        hash::{Dictionary, RESERVED_PREFIX, joaat, unplaceholder},
        text::{self, unfloat},
    },
};

const BITS_SEPARATOR: char = ' ';

const LANE_SEPARATOR: char = ',';

pub(super) fn write(payload: &[u8], document: &[u8], names: &Dictionary) -> Result<Vec<u8>> {
    let sections = section::chain(payload).map_err(|(at, cause)| bad(at, cause))?;
    let find = |tag: [u8; 4]| sections.iter().find(|section| section.tag == tag).copied();
    let psin = find(section::PSIN).ok_or_else(|| bad(0, Malformed::MissingSection))?;
    let table = find(section::PMAP)
        .ok_or_else(|| bad(0, Malformed::MissingSection))?
        .bytes;
    let described = find(section::PSCH)
        .ok_or_else(|| bad(0, Malformed::MissingSection))?
        .bytes;
    let data = psin.bytes;

    // Before the document is parsed: the whole of it is materialised into a
    // tree before the first comparison against the payload.
    let budget = document_budget(payload.len());
    if document.len() > budget {
        return Err(Error::NotPsoXml {
            position: 0,
            cause: NotPsoXml::TooLarge {
                budget,
                len: document.len(),
            },
        });
    }

    let data_len = u32::try_from(data.len()).map_err(|_| bad(0, Malformed::Section))?;
    let blocks = Blocks::read(table, data_len)?;
    let schema = Schema::read(described)?;
    let root = *blocks.root();

    let tree = read_tree(document)?;
    let mut applier = Applier {
        data: Data {
            section: data,
            blocks: &blocks,
        },
        edited: data.to_vec(),
        schema: &schema,
        names,
    };
    let tag = names.render(root.name);
    applier.structure(root.name, root.offset, &tag, &tree, 0)?;

    let mut out = payload.to_vec();
    let at = psin.at;
    out.get_mut(at..at.saturating_add(applier.edited.len()))
        .ok_or_else(|| bad(0, Malformed::Section))?
        .copy_from_slice(&applier.edited);
    checksum::restamp(&mut out, find(section::CHKS))?;
    Ok(out)
}

/// The `CHKS` section, recomputed as a seeded Jenkins one-at-a-time hash over the whole file.
mod checksum {
    use super::{Malformed, bad, section};
    use crate::error::Result;

    /// The seed. Not zero, unlike `metadata::hash::joaat`'s.
    const SEED: u32 = 0x3FAC_7125;

    /// Where the file size sits inside the section.
    const SIZE_AT: usize = 8;

    /// Where the checksum sits inside the section.
    const CHECKSUM_AT: usize = 12;

    pub(super) fn restamp(file: &mut [u8], chks: Option<section::Section<'_>>) -> Result<()> {
        let Some(chks) = chks else { return Ok(()) };
        let at = chks.at;
        let gone = || bad(u64::try_from(at).unwrap_or(u64::MAX), Malformed::Checksum);
        if chks.bytes.len() != section::CHKS_LEN {
            return Err(gone());
        }
        let size = u32::try_from(file.len()).map_err(|_| gone())?;
        put(file, at, SIZE_AT, 0)?;
        put(file, at, CHECKSUM_AT, 0)?;
        let hash = jenkins(file);
        put(file, at, SIZE_AT, size)?;
        put(file, at, CHECKSUM_AT, hash)
    }

    /// Writes one big-endian `u32` field of the section at `at`, bounded by the section itself.
    fn put(file: &mut [u8], at: usize, field: usize, value: u32) -> Result<()> {
        let gone = || bad(u64::try_from(at).unwrap_or(u64::MAX), Malformed::Checksum);
        let base = at.checked_add(field).ok_or_else(gone)?;
        let end = base.checked_add(4).ok_or_else(gone)?;
        let limit = at.checked_add(section::CHKS_LEN).ok_or_else(gone)?;
        if end > limit {
            return Err(gone());
        }
        let room = file.get_mut(base..end).ok_or_else(gone)?;
        room.copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// The seeded, signed-byte Jenkins one-at-a-time hash.
    fn jenkins(bytes: &[u8]) -> u32 {
        let mut hash: u32 = SEED;
        for byte in bytes {
            hash = hash.wrapping_add(i32::from(byte.cast_signed()).cast_unsigned());
            hash = hash.wrapping_add(hash << 10);
            hash ^= hash >> 6;
        }
        hash = hash.wrapping_add(hash << 3);
        hash ^= hash >> 11;
        hash.wrapping_add(hash << 15)
    }

    #[cfg(test)]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "test code; clippy.toml's allow-*-in-tests settings have no \
                  equivalent for this lint. docs/conventions.md §15"
    )]
    mod tests {
        use super::*;

        #[test]
        fn put_accepts_a_field_that_ends_exactly_on_the_sections_boundary() {
            let mut file = vec![0u8; 40];
            let at = 5;
            let field = section::CHKS_LEN - 4;
            put(&mut file, at, field, 0x1234_5678).expect("the boundary itself fits");
            assert_eq!(
                &file[at + field..at + field + 4],
                &0x1234_5678u32.to_be_bytes()
            );
        }

        #[test]
        fn put_refuses_a_field_that_reaches_one_byte_past_the_boundary() {
            let mut file = vec![0xAAu8; 40];
            let at = 5;
            let field = section::CHKS_LEN - 3;
            let before = file.clone();
            assert!(put(&mut file, at, field, 0xFFFF_FFFF).is_err());
            assert_eq!(file, before, "a refused write leaves the file untouched");
        }
    }
}

#[derive(Debug)]
struct Node {
    /// Where in the document it opened, so a refusal can name a place for the cursor.
    position: u64,
    tag: String,
    /// Its reserved attribute's word, with `RESERVED_PREFIX` removed.
    word: String,
    value: String,
    children: Vec<Node>,
}

fn read_tree(document: &[u8]) -> Result<Node> {
    let mut reader = Reader::from_reader(document);
    reader.config_mut().expand_empty_elements = true;
    let at = |reader: &Reader<&[u8]>, cause: NotPsoXml| Error::NotPsoXml {
        position: reader.buffer_position(),
        cause,
    };
    let mut stack: Vec<Node> = Vec::new();
    let mut root: Option<Node> = None;
    loop {
        let event = reader.read_event().map_err(|error| Error::NotPsoXml {
            position: reader.error_position(),
            cause: NotPsoXml::Syntax {
                detail: error.to_string(),
            },
        })?;
        match event {
            Event::Start(start) => {
                if stack.is_empty() && root.is_some() {
                    return Err(at(&reader, NotPsoXml::SecondRoot));
                }
                // `>` and not `>=`: `stack.len()` is the depth the element
                // about to be pushed will sit at, and both directions accept
                // `MAX_DEPTH` itself.
                if stack.len() > MAX_DEPTH {
                    return Err(at(&reader, NotPsoXml::TooDeep));
                }
                let node = opening(&start, reader.buffer_position())
                    .map_err(|cause| at(&reader, cause))?;
                stack.push(node);
            }
            Event::End(_) => {
                let Some(node) = stack.pop() else {
                    return Err(at(
                        &reader,
                        NotPsoXml::Syntax {
                            detail: "a closing tag with nothing open".to_owned(),
                        },
                    ));
                };
                match stack.last_mut() {
                    Some(parent) => parent.children.push(node),
                    None => root = Some(node),
                }
            }
            Event::Text(chunk) => {
                if !chunk.xml10_content().trim_matches(is_space).is_empty() {
                    return Err(at(&reader, NotPsoXml::UnexpectedText));
                }
            }
            Event::CData(_) => return Err(at(&reader, NotPsoXml::UnexpectedText)),
            Event::Eof => break,
            // `expand_empty_elements` turns every `<a/>` into a start and an
            // end, so `Empty` cannot occur; the rest carry nothing this mapping
            // reads.
            Event::Decl(_)
            | Event::Comment(_)
            | Event::PI(_)
            | Event::DocType(_)
            | Event::GeneralRef(_)
            | Event::Empty(_) => {}
        }
    }
    if !stack.is_empty() {
        return Err(at(
            &reader,
            NotPsoXml::Syntax {
                detail: "the document ended with elements still open".to_owned(),
            },
        ));
    }
    root.ok_or_else(|| at(&reader, NotPsoXml::Empty))
}

fn is_space(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\r' | '\n')
}

fn opening(start: &BytesStart<'_>, position: u64) -> std::result::Result<Node, NotPsoXml> {
    let tag = start.name().into_inner().to_owned();
    let mut reserved: Option<(String, String)> = None;
    for attribute in start.attributes() {
        let attribute = attribute.map_err(|error| NotPsoXml::Syntax {
            detail: error.to_string(),
        })?;
        let key = attribute.key.as_ref();
        let Some(word) = key.strip_prefix(RESERVED_PREFIX) else {
            return Err(NotPsoXml::Reserved {
                name: key.to_owned(),
            });
        };
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|error| NotPsoXml::Syntax {
                detail: error.to_string(),
            })?
            .into_owned();
        if reserved.is_some() {
            return Err(NotPsoXml::Reserved {
                name: key.to_owned(),
            });
        }
        reserved = Some((word.to_owned(), value));
    }
    let (word, value) = reserved.ok_or_else(|| NotPsoXml::Reserved { name: tag.clone() })?;
    Ok(Node {
        position,
        tag,
        word,
        value,
        children: Vec::new(),
    })
}

#[derive(Debug)]
struct Applier<'a> {
    /// The original `PSIN` section, so an edit cannot move the walk.
    data: Data<'a>,
    edited: Vec<u8>,
    schema: &'a Schema,
    names: &'a Dictionary,
}

#[derive(Debug, Clone, Copy)]
struct Array {
    layout: Layout,
    element: u16,
    /// How many, for the forms whose count is in the schema.
    count: u16,
}

#[derive(Debug, Clone, Copy)]
struct At<'a> {
    /// The structure whose member list an element index resolves against.
    owner: &'a Structure,
    /// Where the value starts, from the start of the `PSIN` section.
    address: u32,
    depth: usize,
}

impl<'a> Applier<'a> {
    fn structure(
        &mut self,
        name: u32,
        address: u32,
        tag: &str,
        node: &Node,
        depth: usize,
    ) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(bad(u64::from(address), Malformed::TooDeep));
        }
        let structure = self
            .schema
            .structure(name)
            .ok_or_else(|| bad(u64::from(address), Malformed::UndefinedStructure))?;
        expect(node, tag, STRUCT)?;
        expect_value(node, &self.names.render(name))?;
        let fields: Vec<&Member> = structure
            .members
            .iter()
            .filter(|member| !member.is_arrayinfo())
            .collect();
        let children = expect_children(node, fields.len())?;
        for (member, child) in fields.iter().zip(children) {
            let address = address
                .checked_add(member.offset)
                .ok_or_else(|| bad(u64::from(address), Malformed::DataRange))?;
            let field = self.names.render(member.name);
            self.value(
                member.kind,
                &field,
                At {
                    owner: structure,
                    address,
                    depth: depth.saturating_add(1),
                },
                child,
            )?;
        }
        Ok(())
    }

    fn value(&mut self, kind: Kind, tag: &str, at: At<'a>, node: &Node) -> Result<()> {
        match kind {
            Kind::Scalar(scalar) => {
                expect(node, tag, scalar.word())?;
                self.put_scalar(scalar, at.address, node)
            }
            Kind::Text(form) => self.text(form, tag, at, node),
            Kind::Nested(form) => self.nested(form, tag, at, node),
            Kind::Enumerated { width, table } => {
                expect(node, tag, ENUM)?;
                let value = self.enumerated(table, node)?;
                self.put_signed(width, at.address, value, node)
            }
            Kind::Bits { width, table } => {
                expect(node, tag, BITSET)?;
                let value = self.bits(width, table, node)?;
                self.put_unsigned(width, at.address, value)
            }
            Kind::Array {
                layout,
                element,
                count,
            } => self.array(
                Array {
                    layout,
                    element,
                    count,
                },
                tag,
                at,
                node,
            ),
            Kind::Map => self.map(tag, at, node),
        }
    }

    fn text(&mut self, form: Text, tag: &str, at: At<'a>, node: &Node) -> Result<()> {
        let word = form.word();
        match form {
            Text::AtNonFinalHashString | Text::AtFinalHashString => {
                expect(node, tag, word)?;
                let hash =
                    unplaceholder(&node.value).unwrap_or_else(|| joaat(node.value.as_bytes()));
                self.put(at.address, &hash.to_be_bytes())
            }
            Text::Member(len) => {
                expect(node, tag, word)?;
                let len = u32::from(len);
                // A fixed inline string is `len` bytes and its terminator is
                // one of them, so a string filling all `len` would run on into
                // the next member.
                let was = until_nul(self.data.bytes(at.address, len)?).len();
                self.put_string(at.address, room(len.saturating_sub(1), was), node)?;
                Ok(())
            }
            Text::Pointer | Text::ConstString => match self.data.pointer(at.address)? {
                None => expect_null(node, tag, word),
                Some(address) => {
                    expect(node, tag, word)?;
                    let room = u32::try_from(self.data.terminated(address)?.len())
                        .map_err(|_| bad(u64::from(address), Malformed::DataRange))?;
                    self.put_string(address, room, node)?;
                    Ok(())
                }
            },
            Text::AtString => {
                let count = self.data.half(at.address.saturating_add(COUNT_AT))?;
                // A counted string's characters number `min(count1, count2)`
                // and its terminator is the byte after, so the store is the
                // smaller of the two counts, not `count1`.
                let capacity = self.data.half(at.address.saturating_add(CAPACITY_AT))?;
                let store = u32::from(count.min(capacity));
                match self.data.pointer(at.address)? {
                    None => expect_null(node, tag, word),
                    Some(address) => {
                        expect(node, tag, word)?;
                        // `count1` is the length, so a string that changed
                        // length has to take it with it — but only then, never
                        // merely because the stored count disagrees with what
                        // the bytes read back as.
                        let was = until_nul(self.data.bytes(address, u32::from(count))?).len();
                        let len = self.put_string(address, room(store, was), node)?;
                        if usize::try_from(len).is_ok_and(|written| written == was) {
                            return Ok(());
                        }
                        let stored = u16::try_from(len)
                            .map_err(|_| bad(u64::from(address), Malformed::DataRange))?;
                        self.put(at.address.saturating_add(COUNT_AT), &stored.to_be_bytes())
                    }
                }
            }
        }
    }

    fn nested(&mut self, form: Nested, tag: &str, at: At<'a>, node: &Node) -> Result<()> {
        let (name, address) = match form {
            Nested::Structure(name) => (name, at.address),
            Nested::Pointer | Nested::SimplePointer => {
                let Some((block, address)) = self.data.block_pointer(at.address)? else {
                    return expect_null(node, tag, STRUCT);
                };
                (block.name, address)
            }
        };
        self.structure(name, address, tag, node, at.depth)
    }

    /// The value an enum element names, or the decimal the renderer falls back to.
    fn enumerated(&self, table: u32, node: &Node) -> Result<i32> {
        if let Some(key) = self.keyed(table, &node.value, node)? {
            return Ok(key);
        }
        node.value.parse().map_err(|_| unreadable(node))
    }

    /// The key an enum table gives a rendered name, when exactly one does.
    fn keyed(&self, table: u32, wanted: &str, node: &Node) -> Result<Option<i32>> {
        let Some(entries) = self.schema.enum_table(table) else {
            return Ok(None);
        };
        let mut found = None;
        for (key, name) in entries {
            if self.names.render(*name) != wanted {
                continue;
            }
            if found.is_some() {
                return Err(Error::NotPsoXml {
                    position: node.position,
                    cause: NotPsoXml::Ambiguous {
                        name: wanted.to_owned(),
                    },
                });
            }
            found = Some(*key);
        }
        Ok(found)
    }

    /// The value a bitset element names: every bit it lists, set.
    fn bits(&self, width: Width, table: Option<u32>, node: &Node) -> Result<u64> {
        let mut value: u64 = 0;
        let ceiling = width.bytes().saturating_mul(8);
        for token in node.value.split(BITS_SEPARATOR) {
            if token.is_empty() {
                continue;
            }
            let named = match table {
                Some(table) => self.keyed(table, token, node)?,
                None => None,
            };
            let bit = match named {
                Some(key) => u32::try_from(key).map_err(|_| unreadable(node))?,
                None => token.parse::<u32>().map_err(|_| unreadable(node))?,
            };
            if bit >= ceiling {
                return Err(unreadable(node));
            }
            value |= 1u64 << bit;
        }
        Ok(value)
    }

    fn array(&mut self, array: Array, tag: &str, at: At<'a>, node: &Node) -> Result<()> {
        let Array {
            layout,
            element,
            count,
        } = array;
        expect(node, tag, ARRAY)?;
        expect_value(node, layout.word())?;
        let (base, count) = match layout {
            Layout::AtArray => self.counted(
                at.address,
                self.data.half(at.address.saturating_add(COUNT_AT))?,
            )?,
            Layout::PointerWithCount => self.counted(at.address, count)?,
            _ => (at.address, count),
        };
        let children = expect_children(node, usize::from(count))?;
        if count == 0 {
            return Ok(());
        }
        let described = *at
            .owner
            .members
            .get(usize::from(element))
            .ok_or_else(|| bad(u64::from(at.address), Malformed::ArrayInfo))?;
        let stride = self
            .schema
            .extent(at.owner, &described, 0)
            .ok_or_else(|| bad(u64::from(at.address), Malformed::UndefinedStructure))?;
        let item = reserved_item();
        for (index, child) in children.iter().enumerate() {
            let index =
                u32::try_from(index).map_err(|_| bad(u64::from(base), Malformed::DataRange))?;
            let address = step(base, index, stride)
                .ok_or_else(|| bad(u64::from(base), Malformed::DataRange))?;
            self.value(
                described.kind,
                &item,
                At {
                    owner: at.owner,
                    address,
                    depth: at.depth.saturating_add(1),
                },
                child,
            )?;
        }
        Ok(())
    }

    /// Where an out-of-line array's items are, and how many there are.
    fn counted(&self, address: u32, count: u16) -> Result<(u32, u16)> {
        match self.data.block_pointer(address)? {
            Some((_, base)) => Ok((base, count)),
            None if count == 0 => Ok((address, 0)),
            None => Err(bad(u64::from(address), Malformed::Pointer)),
        }
    }

    fn map(&mut self, tag: &str, at: At<'a>, node: &Node) -> Result<()> {
        expect(node, tag, MAP)?;
        expect_value(node, ATBINARYMAP)?;
        let header = at.address.saturating_add(MAP_POINTER_AT);
        let count = self.data.half(header.saturating_add(COUNT_AT))?;
        let Some((block, base)) = self.data.block_pointer(header)? else {
            if count != 0 {
                return Err(bad(u64::from(header), Malformed::Pointer));
            }
            expect_children(node, 0)?;
            return Ok(());
        };
        let children = expect_children(node, usize::from(count))?;
        if count == 0 {
            return Ok(());
        }
        let name = block.name;
        let stride = self
            .schema
            .structure(name)
            .map(|structure| structure.length)
            .ok_or_else(|| bad(u64::from(base), Malformed::UndefinedStructure))?;
        let item = reserved_item();
        for (index, child) in children.iter().enumerate() {
            let index =
                u32::try_from(index).map_err(|_| bad(u64::from(base), Malformed::DataRange))?;
            let address = step(base, index, stride)
                .ok_or_else(|| bad(u64::from(base), Malformed::DataRange))?;
            self.structure(name, address, &item, child, at.depth.saturating_add(1))?;
        }
        Ok(())
    }
}

/// The writes, each bounds-checked against the section.
impl Applier<'_> {
    fn put(&mut self, address: u32, bytes: &[u8]) -> Result<()> {
        let gone = || bad(u64::from(address), Malformed::DataRange);
        let at = usize::try_from(address).map_err(|_| gone())?;
        let end = at.checked_add(bytes.len()).ok_or_else(gone)?;
        let room = self.edited.get_mut(at..end).ok_or_else(gone)?;
        room.copy_from_slice(bytes);
        Ok(())
    }

    /// Writes a string into its `room` bytes, NUL-terminated when there's a byte to spare.
    fn put_string(&mut self, address: u32, room: u32, node: &Node) -> Result<u32> {
        let bytes = text::decode(&node.value).ok_or(Error::NotPsoXml {
            position: node.position,
            cause: NotPsoXml::BadEscape,
        })?;
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        if len > room {
            return Err(Error::NotPsoXml {
                position: node.position,
                cause: NotPsoXml::TooLong {
                    name: node.tag.clone(),
                    room,
                    len,
                },
            });
        }
        self.put(address, &bytes)?;
        if len < room {
            self.put(address.saturating_add(len), &[0])?;
        }
        Ok(len)
    }

    fn put_signed(&mut self, width: Width, address: u32, value: i32, node: &Node) -> Result<()> {
        match width {
            Width::Eight => {
                let byte = i8::try_from(value).map_err(|_| unreadable(node))?;
                self.put(address, &[byte.cast_unsigned()])
            }
            Width::Sixteen => {
                let half = i16::try_from(value).map_err(|_| unreadable(node))?;
                self.put(address, &half.to_be_bytes())
            }
            Width::ThirtyTwo => self.put(address, &value.to_be_bytes()),
        }
    }

    fn put_unsigned(&mut self, width: Width, address: u32, value: u64) -> Result<()> {
        let bytes = value.to_be_bytes();
        let from = bytes
            .len()
            .saturating_sub(usize::try_from(width.bytes()).unwrap_or(0));
        let tail = bytes
            .get(from..)
            .ok_or_else(|| bad(u64::from(address), Malformed::DataRange))?
            .to_vec();
        self.put(address, &tail)
    }

    fn put_scalar(&mut self, scalar: Scalar, address: u32, node: &Node) -> Result<()> {
        let text = node.value.as_str();
        let bad_value = || unreadable(node);
        let lanes = |count: usize| -> Result<Vec<u8>> {
            let mut parts = text.split(LANE_SEPARATOR);
            let mut out = Vec::with_capacity(count.saturating_mul(4));
            for _ in 0..count {
                let part = parts.next().ok_or_else(bad_value)?;
                let number = unfloat(part.trim()).ok_or_else(bad_value)?;
                out.extend_from_slice(&number.to_bits().to_be_bytes());
            }
            if parts.next().is_some() {
                return Err(bad_value());
            }
            Ok(out)
        };
        let bytes: Vec<u8> = match scalar {
            Scalar::Bool => vec![match text {
                "false" => 0,
                "true" => 1,
                other => other.parse().map_err(|_| bad_value())?,
            }],
            Scalar::Char => vec![text.parse::<i8>().map_err(|_| bad_value())?.cast_unsigned()],
            Scalar::UChar => vec![text.parse::<u8>().map_err(|_| bad_value())?],
            Scalar::Short => text
                .parse::<i16>()
                .map_err(|_| bad_value())?
                .to_be_bytes()
                .to_vec(),
            Scalar::UShort => text
                .parse::<u16>()
                .map_err(|_| bad_value())?
                .to_be_bytes()
                .to_vec(),
            Scalar::Int => text
                .parse::<i32>()
                .map_err(|_| bad_value())?
                .to_be_bytes()
                .to_vec(),
            Scalar::Uint | Scalar::Color => text
                .parse::<u32>()
                .map_err(|_| bad_value())?
                .to_be_bytes()
                .to_vec(),
            Scalar::Uint64 => text
                .parse::<u64>()
                .map_err(|_| bad_value())?
                .to_be_bytes()
                .to_vec(),
            Scalar::Float16 => narrow(unfloat(text).ok_or_else(bad_value)?)
                .ok_or_else(bad_value)?
                .to_be_bytes()
                .to_vec(),
            Scalar::Float => unfloat(text)
                .ok_or_else(bad_value)?
                .to_bits()
                .to_be_bytes()
                .to_vec(),
            Scalar::Vector2 => lanes(2)?,
            Scalar::Vector3 | Scalar::Vec3V => lanes(3)?,
            Scalar::Vector4 | Scalar::Vec4V => lanes(4)?,
        };
        self.put(address, &bytes)
    }
}

/// How many bytes a string may be written into: never less than the `was` bytes already there.
fn room(store: u32, was: usize) -> u32 {
    store.max(u32::try_from(was).unwrap_or(u32::MAX))
}

fn unreadable(node: &Node) -> Error {
    Error::NotPsoXml {
        position: node.position,
        cause: NotPsoXml::Value {
            name: node.tag.clone(),
        },
    }
}

fn reserved_item() -> String {
    format!("{RESERVED_PREFIX}{ITEM}")
}

fn expect(node: &Node, tag: &str, word: &str) -> Result<()> {
    if node.tag != tag {
        return Err(Error::NotPsoXml {
            position: node.position,
            cause: NotPsoXml::Tag {
                wanted: tag.to_owned(),
                found: node.tag.clone(),
            },
        });
    }
    if node.word != word {
        return Err(Error::NotPsoXml {
            position: node.position,
            cause: NotPsoXml::Word {
                wanted: word.to_owned(),
                found: node.word.clone(),
            },
        });
    }
    Ok(())
}

fn expect_value(node: &Node, wanted: &str) -> Result<()> {
    if node.value != wanted {
        return Err(Error::NotPsoXml {
            position: node.position,
            cause: NotPsoXml::Word {
                wanted: wanted.to_owned(),
                found: node.value.clone(),
            },
        });
    }
    Ok(())
}

/// Checks that a null pointer is still written down as one, under `pso:null`.
fn expect_null(node: &Node, tag: &str, word: &str) -> Result<()> {
    expect(node, tag, NULL)?;
    expect_value(node, word)
}

fn expect_children(node: &Node, wanted: usize) -> Result<&[Node]> {
    if node.children.len() != wanted {
        return Err(Error::NotPsoXml {
            position: node.position,
            cause: NotPsoXml::Children {
                name: node.tag.clone(),
                wanted,
                found: node.children.len(),
            },
        });
    }
    Ok(&node.children)
}

/// The half-float `f32` narrows to, or `None` when it doesn't narrow exactly.
fn narrow(number: f32) -> Option<u16> {
    let bits = number.to_bits();
    let sign = u16::try_from(bits >> 31).ok()? << 15;
    let exponent = i32::try_from((bits >> 23) & 0xFF).ok()?;
    let mantissa = bits & 0x007F_FFFF;
    if exponent == 0xFF {
        // An infinity, or a NaN whose payload must survive the ten bits a half
        // has for it.
        if mantissa & 0x1FFF != 0 || (mantissa != 0 && mantissa >> 13 == 0) {
            return None;
        }
        return Some(sign | 0x7C00 | u16::try_from(mantissa >> 13).ok()?);
    }
    if exponent == 0 {
        // Zero, or an `f32` subnormal, which is far below every half but zero.
        return (mantissa == 0).then_some(sign);
    }
    let shifted = exponent.checked_sub(127)?.checked_add(15)?;
    if shifted >= 0x1F {
        return None;
    }
    if shifted > 0 {
        if mantissa & 0x1FFF != 0 {
            return None;
        }
        let exponent = u16::try_from(shifted).ok()? << 10;
        return Some(sign | exponent | u16::try_from(mantissa >> 13).ok()?);
    }
    // A half subnormal is `m * 2^-24` and the `f32` is `full * 2^(exponent-150)`,
    // so `m` is `full >> (14 - shifted)`.
    let drop = u32::try_from(14i32.checked_sub(shifted)?).ok()?;
    if drop >= 32 {
        return None;
    }
    let full = mantissa | 0x0080_0000;
    if full & ((1u32 << drop).checked_sub(1)?) != 0 {
        return None;
    }
    let narrowed = u16::try_from(full >> drop).ok()?;
    (narrowed != 0).then_some(sign | narrowed)
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test code; clippy.toml's allow-*-in-tests settings have no \
              equivalent for this lint. docs/conventions.md §15"
)]
mod tests {
    use super::*;

    const ROOT_NAME: u32 = 0xD98B_B561;
    const MEMBER_NAME: u32 = 0x1234_5678;
    const ARRAYINFO: u32 = 0x0000_0100;

    fn one_block_pmap(offset: i32, length: i32) -> Vec<u8> {
        let mut pmap = vec![0u8; 8];
        pmap.extend_from_slice(&1i32.to_be_bytes()); // rootId
        pmap.extend_from_slice(&1i16.to_be_bytes()); // entriesCount
        pmap.extend_from_slice(&0u16.to_be_bytes()); // unknown_Eh
        pmap.extend_from_slice(&ROOT_NAME.to_be_bytes());
        pmap.extend_from_slice(&offset.to_be_bytes());
        pmap.extend_from_slice(&0i32.to_be_bytes()); // unknown_8h
        pmap.extend_from_slice(&length.to_be_bytes());
        pmap
    }

    fn trivial_blocks() -> Blocks {
        Blocks::read(&one_block_pmap(0, 64), 64).expect("a minimal block table reads")
    }

    fn node(tag: &str, word: &str, value: &str) -> Node {
        Node {
            position: 0,
            tag: tag.to_owned(),
            word: word.to_owned(),
            value: value.to_owned(),
            children: Vec::new(),
        }
    }

    #[test]
    fn text_between_elements_that_is_not_whitespace_is_refused() {
        let error = read_tree(b"<a pso:x=\"y\">not-blank</a>").expect_err("stray text is refused");
        assert!(
            matches!(
                error,
                Error::NotPsoXml {
                    cause: NotPsoXml::UnexpectedText,
                    ..
                }
            ),
            "{error:?}"
        );
    }

    #[test]
    fn text_between_elements_that_is_only_whitespace_is_accepted() {
        read_tree(b"<a pso:x=\"y\">  \n\t\r  </a>").expect("pure whitespace is not content");
    }

    #[test]
    fn counted_refuses_a_null_pointer_that_declares_a_nonzero_count() {
        let section = vec![0u8; 8]; // the word at address 0 is null
        let blocks = trivial_blocks();
        let schema = Schema::default();
        let names = Dictionary::default();
        let applier = Applier {
            data: Data {
                section: &section,
                blocks: &blocks,
            },
            edited: section.clone(),
            schema: &schema,
            names: &names,
        };

        assert_eq!(
            applier
                .counted(0, 0)
                .expect("a null pointer with no items is a legitimately empty array"),
            (0, 0)
        );
        let error = applier
            .counted(0, 1)
            .expect_err("a null pointer with one declared item is a contradiction");
        assert!(
            matches!(
                error,
                Error::BadPso {
                    cause: Malformed::Pointer,
                    ..
                }
            ),
            "{error:?}"
        );
    }

    #[test]
    fn structure_refuses_only_past_the_exact_depth_ceiling() {
        let section = vec![0u8; 8];
        let blocks = trivial_blocks();
        let schema = Schema::default();
        let names = Dictionary::default();
        let mut applier = Applier {
            data: Data {
                section: &section,
                blocks: &blocks,
            },
            edited: section.clone(),
            schema: &schema,
            names: &names,
        };
        let leaf = node("tag", STRUCT, "whatever");

        let at_ceiling = applier.structure(0xDEAD_BEEF, 0, "tag", &leaf, MAX_DEPTH);
        assert!(
            matches!(
                at_ceiling,
                Err(Error::BadPso {
                    cause: Malformed::UndefinedStructure,
                    ..
                })
            ),
            "{at_ceiling:?}"
        );

        let past_ceiling = applier.structure(0xDEAD_BEEF, 0, "tag", &leaf, MAX_DEPTH + 1);
        assert!(
            matches!(
                past_ceiling,
                Err(Error::BadPso {
                    cause: Malformed::TooDeep,
                    ..
                })
            ),
            "{past_ceiling:?}"
        );
    }

    fn one_uint_pso() -> Vec<u8> {
        let mut psin = Vec::new();
        psin.extend_from_slice(&section::PSIN);
        psin.extend_from_slice(&20u32.to_be_bytes());
        psin.extend_from_slice(b"pppppppp");
        psin.extend_from_slice(&7u32.to_be_bytes());

        let mut pmap = Vec::new();
        pmap.extend_from_slice(b"PMAP");
        pmap.extend_from_slice(&32u32.to_be_bytes());
        pmap.extend_from_slice(&1i32.to_be_bytes());
        pmap.extend_from_slice(&1i16.to_be_bytes());
        pmap.extend_from_slice(&0x7070u16.to_be_bytes());
        pmap.extend_from_slice(&ROOT_NAME.to_be_bytes());
        pmap.extend_from_slice(&16i32.to_be_bytes());
        pmap.extend_from_slice(&0i32.to_be_bytes());
        pmap.extend_from_slice(&4i32.to_be_bytes());

        let mut psch = Vec::new();
        psch.extend_from_slice(b"PSCH");
        psch.extend_from_slice(&44u32.to_be_bytes());
        psch.extend_from_slice(&1u32.to_be_bytes());
        psch.extend_from_slice(&ROOT_NAME.to_be_bytes());
        psch.extend_from_slice(&20i32.to_be_bytes());
        psch.extend_from_slice(&1u32.to_be_bytes());
        psch.extend_from_slice(&4i32.to_be_bytes());
        psch.extend_from_slice(&0u32.to_be_bytes());
        psch.extend_from_slice(&MEMBER_NAME.to_be_bytes());
        psch.extend_from_slice(&[0x06, 0x00]);
        psch.extend_from_slice(&0u16.to_be_bytes());
        psch.extend_from_slice(&0u32.to_be_bytes());

        let mut payload = psin;
        payload.extend_from_slice(&pmap);
        payload.extend_from_slice(&psch);
        payload
    }

    #[test]
    fn a_structures_own_type_word_must_match_the_schema_exactly() {
        let payload = one_uint_pso();
        let names = Dictionary::default();
        let xml =
            String::from_utf8(super::super::render::write(&payload, &names).expect("converts"))
                .expect("utf8");
        let root_word = format!("pso:struct=\"{}\"", names.render(ROOT_NAME));
        assert!(xml.contains(&root_word), "{xml}");
        let wrong = xml.replacen(&root_word, "pso:struct=\"somethingelse\"", 1);

        let error = write(&payload, wrong.as_bytes(), &names)
            .expect_err("a structure whose own type word disagrees is refused");
        assert!(
            matches!(
                error,
                Error::NotPsoXml {
                    cause: NotPsoXml::Word { .. },
                    ..
                }
            ),
            "{error:?}"
        );
    }

    fn nullable_struct_pointer_pso() -> Vec<u8> {
        let mut psin = Vec::new();
        psin.extend_from_slice(&section::PSIN);
        psin.extend_from_slice(&20u32.to_be_bytes());
        psin.extend_from_slice(b"pppppppp");
        psin.extend_from_slice(&0u32.to_be_bytes()); // a null pointer

        let mut pmap = Vec::new();
        pmap.extend_from_slice(b"PMAP");
        pmap.extend_from_slice(&32u32.to_be_bytes());
        pmap.extend_from_slice(&1i32.to_be_bytes());
        pmap.extend_from_slice(&1i16.to_be_bytes());
        pmap.extend_from_slice(&0x7070u16.to_be_bytes());
        pmap.extend_from_slice(&ROOT_NAME.to_be_bytes());
        pmap.extend_from_slice(&16i32.to_be_bytes());
        pmap.extend_from_slice(&0i32.to_be_bytes());
        pmap.extend_from_slice(&4i32.to_be_bytes());

        let mut psch = Vec::new();
        psch.extend_from_slice(b"PSCH");
        psch.extend_from_slice(&44u32.to_be_bytes());
        psch.extend_from_slice(&1u32.to_be_bytes());
        psch.extend_from_slice(&ROOT_NAME.to_be_bytes());
        psch.extend_from_slice(&20i32.to_be_bytes());
        psch.extend_from_slice(&1u32.to_be_bytes());
        psch.extend_from_slice(&4i32.to_be_bytes());
        psch.extend_from_slice(&0u32.to_be_bytes());
        psch.extend_from_slice(&MEMBER_NAME.to_be_bytes());
        psch.extend_from_slice(&[0x0C, 0x03]); // STRUCT, POINTER
        psch.extend_from_slice(&0u16.to_be_bytes());
        psch.extend_from_slice(&0u32.to_be_bytes());

        let mut payload = psin;
        payload.extend_from_slice(&pmap);
        payload.extend_from_slice(&psch);
        payload
    }

    #[test]
    fn a_null_pointers_own_word_must_say_null_and_nothing_else() {
        let payload = nullable_struct_pointer_pso();
        let names = Dictionary::default();
        let xml =
            String::from_utf8(super::super::render::write(&payload, &names).expect("converts"))
                .expect("utf8");
        assert!(xml.contains("pso:null=\"struct\""), "{xml}");
        let wrong = xml.replace("pso:null=\"struct\"", "pso:struct=\"whatever\"");

        let error = write(&payload, wrong.as_bytes(), &names)
            .expect_err("a null pointer written as anything but pso:null is refused");
        assert!(
            matches!(
                error,
                Error::NotPsoXml {
                    cause: NotPsoXml::Word { ref wanted, .. },
                    ..
                } if wanted == "null"
            ),
            "{error:?}"
        );
    }

    fn pointer_with_count_pso() -> Vec<u8> {
        let mut psin = Vec::new();
        psin.extend_from_slice(&section::PSIN);
        psin.extend_from_slice(&28u32.to_be_bytes());
        psin.extend_from_slice(b"pppppppp");
        psin.extend_from_slice(&2u32.to_be_bytes()); // pointer to block 2, offset 0
        psin.extend_from_slice(&0u32.to_be_bytes()); // the pointer's dead second word
        psin.extend_from_slice(&42u32.to_be_bytes()); // block 2: one UINT

        let mut pmap = Vec::new();
        pmap.extend_from_slice(b"PMAP");
        pmap.extend_from_slice(&48u32.to_be_bytes());
        pmap.extend_from_slice(&1i32.to_be_bytes());
        pmap.extend_from_slice(&2i16.to_be_bytes());
        pmap.extend_from_slice(&0x7070u16.to_be_bytes());
        pmap.extend_from_slice(&ROOT_NAME.to_be_bytes());
        pmap.extend_from_slice(&16i32.to_be_bytes());
        pmap.extend_from_slice(&0i32.to_be_bytes());
        pmap.extend_from_slice(&8i32.to_be_bytes());
        pmap.extend_from_slice(&0x0000_0006u32.to_be_bytes()); // block 2's tag, unused here
        pmap.extend_from_slice(&24i32.to_be_bytes());
        pmap.extend_from_slice(&0i32.to_be_bytes());
        pmap.extend_from_slice(&4i32.to_be_bytes());

        let mut psch = Vec::new();
        psch.extend_from_slice(b"PSCH");
        psch.extend_from_slice(&56u32.to_be_bytes());
        psch.extend_from_slice(&1u32.to_be_bytes());
        psch.extend_from_slice(&ROOT_NAME.to_be_bytes());
        psch.extend_from_slice(&20i32.to_be_bytes());
        psch.extend_from_slice(&2u32.to_be_bytes());
        psch.extend_from_slice(&8i32.to_be_bytes());
        psch.extend_from_slice(&0u32.to_be_bytes());
        psch.extend_from_slice(&MEMBER_NAME.to_be_bytes());
        psch.extend_from_slice(&[0x0D, 0x06]); // ARRAY, PointerWithCount
        psch.extend_from_slice(&0u16.to_be_bytes());
        psch.extend_from_slice(&((1u32 << 16) | 1).to_be_bytes()); // count 1, element 1
        psch.extend_from_slice(&ARRAYINFO.to_be_bytes());
        psch.extend_from_slice(&[0x06, 0x00]); // UINT
        psch.extend_from_slice(&0u16.to_be_bytes());
        psch.extend_from_slice(&0u32.to_be_bytes());

        let mut payload = psin;
        payload.extend_from_slice(&pmap);
        payload.extend_from_slice(&psch);
        payload
    }

    #[test]
    fn an_edit_to_a_pointer_with_count_item_lands_through_the_pointer() {
        let payload = pointer_with_count_pso();
        let names = Dictionary::default();
        let xml =
            String::from_utf8(super::super::render::write(&payload, &names).expect("converts"))
                .expect("utf8");
        assert!(xml.contains("pso:uint=\"42\""), "{xml}");
        let edited_xml = xml.replace("pso:uint=\"42\"", "pso:uint=\"99\"");

        let edited = write(&payload, edited_xml.as_bytes(), &names).expect("the edit applies");
        assert_eq!(
            &edited[24..28],
            &99u32.to_be_bytes(),
            "the value lands in the block the pointer names"
        );
        assert_eq!(
            &edited[16..20],
            &2u32.to_be_bytes(),
            "and the pointer itself is untouched"
        );
    }

    #[test]
    fn a_nan_whose_low_payload_bits_would_be_lost_is_refused() {
        let bits = (0xFFu32 << 23) | 0x0000_2001;
        let value = f32::from_bits(bits);
        assert!(value.is_nan(), "the chosen bits are a NaN");
        assert_eq!(
            narrow(value),
            None,
            "narrowing would drop the low bit of the payload"
        );
    }
}
