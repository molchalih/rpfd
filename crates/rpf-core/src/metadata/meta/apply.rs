//! The XML read back, and applied to the file it was written from.
//!
//! DR-049 for this encoding, and the argument is the same one `PSO` made. A
//! resource `Meta` carries more than its data: page slack, inter-table padding,
//! the 7.26% of a payload that follows the last data block, and — the row that
//! decides it — **2.48% of the payload that no walk reaches and that is not
//! zero** (`docs/metadata-encodings.md`, What a walk does not reach). None of
//! that is in the document and none of it can be invented, so the write
//! direction **edits** the file it came from.
//!
//! The walk here is [`super::render`]'s walk read backwards: the same tables,
//! the same blocks, the same addresses, in the same order. No structural fact
//! of the file changes: no block moves, no pointer is rewritten, and no page is
//! re-allocated. A value that no longer fits where it was is a refusal
//! ([`NotMetaXml::TooLong`]), and so is an array of a different length or a
//! structure of a different member list. DR-052 is why those are the permanent
//! boundary of editing rather than work not yet done.
//!
//! Two properties make "the same addresses" a checked claim rather than a
//! description of the intent, and [`Applier::put`] is where both are checked:
//! every write is bounded by the **block** the value lives in, which is the
//! bound [`super::render`] reads it under; and two elements that write one
//! address have to agree on what goes there, or the edit is refused
//! ([`NotMetaXml::Aliased`]). DR-059, which is also why a file that points at
//! one value twice still round-trips unedited.

use quick_xml::{
    Reader, XmlVersion,
    events::{BytesStart, Event},
};

use super::{
    BlockTag, Malformed, Member, RESERVED_PREFIX, TypeCode, bad,
    data::{Spot, Values, spell, until_nul},
    kind::{COUNT_AT, Field, Kind, MAX_DEPTH, NotMetaXml, Scalar, document_budget, fits, is_field},
    render::{ARRAY, COUNTED, INLINE, ITEM, Items, NULL, STRUCT, TEXT, reserved},
};
use crate::{
    error::{Error, Result},
    metadata::{
        hash::{Dictionary, joaat, unplaceholder},
        text::{self, unfloat},
    },
};

/// How the lanes of a vector are separated.
const LANE_SEPARATOR: char = ',';

/// Reads the XML [`super::render`] wrote and applies it to the payload it was
/// written from.
///
/// # Errors
///
/// [`Error::BadMeta`] if `payload` contradicts itself, [`Error::UnsupportedMeta`]
/// if it carries a type code this build does not name, and
/// [`Error::NotMetaXml`] if `document` is not XML or does not describe this
/// payload.
pub(super) fn write(
    payload: &[u8],
    system_len: usize,
    document: &[u8],
    names: &Dictionary,
) -> Result<Vec<u8>> {
    // Before the document is parsed, because parsing it is what costs: the
    // whole of it is materialised into a tree before the first comparison
    // against the payload, so a document far larger than the file it edits has
    // to be refusable on sight. The ceiling is the one `render` writes under,
    // so a document `to_xml` wrote always fits.
    let budget = document_budget(payload.len());
    if document.len() > budget {
        return Err(Error::NotMetaXml {
            position: 0,
            cause: NotMetaXml::TooLarge {
                budget,
                len: document.len(),
            },
        });
    }

    let meta = super::parse(payload, system_len)?;
    let root = *meta.root();
    let BlockTag::Structure(name) = root.tag else {
        return Err(bad(0x1C, Malformed::UndefinedStructure));
    };
    let tree = read_tree(document)?;
    let mut applier = Applier {
        values: Values { meta: &meta },
        edited: payload.to_vec(),
        written: vec![false; payload.len()],
        names,
    };
    let tag = spell(names, name);
    applier.structure(
        name,
        Spot {
            block: root,
            offset: 0,
        },
        &tag,
        &tree,
        0,
    )?;
    Ok(applier.edited)
}

/// One element of the document: its name, its one reserved attribute, and its
/// children.
///
/// Every element [`super::render`] writes carries **exactly one** `meta:`
/// attribute, which is what makes this shape total rather than a subset: the
/// type of every record is written down, which is DR-047's central decision.
#[derive(Debug)]
struct Node {
    /// Where in the document it opened, so a refusal names a place an editor
    /// can put a cursor on.
    position: u64,
    /// Its element name.
    tag: String,
    /// Its reserved attribute's word, with [`RESERVED_PREFIX`] removed.
    word: String,
    /// That attribute's value.
    value: String,
    children: Vec<Node>,
}

/// Reads the document into the tree it describes.
fn read_tree(document: &[u8]) -> Result<Node> {
    let mut reader = Reader::from_reader(document);
    reader.config_mut().expand_empty_elements = true;
    let at = |reader: &Reader<&[u8]>, cause: NotMetaXml| Error::NotMetaXml {
        position: reader.buffer_position(),
        cause,
    };
    let mut stack: Vec<Node> = Vec::new();
    let mut root: Option<Node> = None;
    loop {
        let event = reader.read_event().map_err(|error| Error::NotMetaXml {
            position: reader.error_position(),
            cause: NotMetaXml::Syntax {
                detail: error.to_string(),
            },
        })?;
        match event {
            Event::Start(start) => {
                if stack.is_empty() && root.is_some() {
                    return Err(at(&reader, NotMetaXml::SecondRoot));
                }
                // `>` and not `>=`: `stack.len()` is the depth the element about
                // to be pushed will sit at, and both walks accept `MAX_DEPTH`
                // itself. A level's difference here refuses a payload the other
                // direction rendered, and blames the document for it.
                if stack.len() > MAX_DEPTH {
                    return Err(at(&reader, NotMetaXml::TooDeep));
                }
                let node = opening(&start, reader.buffer_position())
                    .map_err(|cause| at(&reader, cause))?;
                stack.push(node);
            }
            Event::End(_) => {
                let Some(node) = stack.pop() else {
                    return Err(at(
                        &reader,
                        NotMetaXml::Syntax {
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
                    return Err(at(&reader, NotMetaXml::UnexpectedText));
                }
            }
            Event::CData(_) => return Err(at(&reader, NotMetaXml::UnexpectedText)),
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
            NotMetaXml::Syntax {
                detail: "the document ended with elements still open".to_owned(),
            },
        ));
    }
    root.ok_or_else(|| at(&reader, NotMetaXml::Empty))
}

/// Whether a character is XML whitespace, and so may be indentation.
fn is_space(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\r' | '\n')
}

/// Reads an opening tag into the node it stands for.
fn opening(start: &BytesStart<'_>, position: u64) -> std::result::Result<Node, NotMetaXml> {
    let tag = start.name().into_inner().to_owned();
    let mut reserved: Option<(String, String)> = None;
    for attribute in start.attributes() {
        let attribute = attribute.map_err(|error| NotMetaXml::Syntax {
            detail: error.to_string(),
        })?;
        let key = attribute.key.as_ref();
        let Some(word) = key.strip_prefix(RESERVED_PREFIX) else {
            return Err(NotMetaXml::Reserved {
                name: key.to_owned(),
            });
        };
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|error| NotMetaXml::Syntax {
                detail: error.to_string(),
            })?
            .into_owned();
        if reserved.is_some() {
            return Err(NotMetaXml::Reserved {
                name: key.to_owned(),
            });
        }
        reserved = Some((word.to_owned(), value));
    }
    let (word, value) = reserved.ok_or_else(|| NotMetaXml::Reserved { name: tag.clone() })?;
    Ok(Node {
        position,
        tag,
        word,
        value,
        children: Vec::new(),
    })
}

/// The walk in progress: the payload it reads and the copy it writes.
#[derive(Debug)]
struct Applier<'a, 'b> {
    /// The original payload, parsed. Every address, count and pointer the walk
    /// follows is read from here, so an edit cannot move the walk.
    values: Values<'a, 'b>,
    /// The copy the values go into.
    edited: Vec<u8>,
    /// Which bytes of it an element has already written.
    ///
    /// One flag per payload byte, because the question it answers is asked per
    /// byte: a file may point at one value twice, and then two elements of the
    /// document write one address. DR-059.
    written: Vec<bool>,
    names: &'b Dictionary,
}

impl<'a> Applier<'a, '_> {
    /// Applies one structure instance.
    fn structure(
        &mut self,
        name: u32,
        spot: Spot<'a>,
        tag: &str,
        node: &Node,
        depth: usize,
    ) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(bad(spot.address(), Malformed::TooDeep));
        }
        let structure = *self
            .values
            .meta
            .structure(name)
            .ok_or_else(|| bad(spot.address(), Malformed::UndefinedStructure))?;
        expect(node, tag, STRUCT)?;
        expect_value(node, &spell(self.names, name))?;
        let fields: Vec<Member> = structure
            .members()
            .filter(|member| is_field(member.name))
            .collect();
        let children = expect_children(node, fields.len())?;
        for (member, child) in fields.iter().zip(children) {
            let field = Field {
                member: *member,
                owner: Some(structure),
            };
            let tag = spell(self.names, member.name);
            let width = field.width(self.values.meta, spot.address())?;
            fits(&structure, member.data_offset, width, spot.address())?;
            let at = spot.step(member.data_offset)?;
            self.value(field, &tag, at, child, depth.saturating_add(1))?;
        }
        Ok(())
    }

    /// Applies one value — a member of a structure, or one item of an array.
    fn value(
        &mut self,
        field: Field<'a>,
        tag: &str,
        spot: Spot<'a>,
        node: &Node,
        depth: usize,
    ) -> Result<()> {
        // The ceiling `structure` states, asked again here for the values that
        // reach no structure: a pointer into a block tagged with a bare type
        // code applies nothing of its own and recurses, which is the cycle
        // `render` refuses at the same place.
        if depth > MAX_DEPTH {
            return Err(bad(spot.address(), Malformed::TooDeep));
        }
        match field.kind()? {
            Kind::Scalar(scalar) => {
                expect(node, tag, scalar.word())?;
                self.put_scalar(scalar, spot, node)
            }
            Kind::Structure(name) => self.structure(name, spot, tag, node, depth),
            Kind::Pointer => match self.values.pointer(spot)? {
                None => expect_null(node, tag, STRUCT),
                Some(landing) => self.target(landing, tag, node, depth),
            },
            Kind::Array => {
                let (base, count) = self.values.items(spot)?;
                self.items(
                    field,
                    tag,
                    Items {
                        layout: COUNTED,
                        base,
                        count,
                    },
                    node,
                    depth,
                )
            }
            Kind::InlineArray(count) => self.items(
                field,
                tag,
                Items {
                    layout: INLINE,
                    base: Some(spot),
                    count,
                },
                node,
                depth,
            ),
            Kind::Text => match self.values.counted(spot)? {
                (None, _) => expect_null(node, tag, TEXT),
                (Some(landing), store) => {
                    // The terminator is one of the bytes the store holds, so a
                    // value may fill the store less one — never less, though,
                    // than the value already there, because an edit moves
                    // nothing it did not change. DR-052.
                    let was = until_nul(landing.bytes(store)?).len();
                    let len = self.put_text(landing, store.saturating_sub(1), was, tag, node)?;
                    match len {
                        None => Ok(()),
                        Some(len) => self.put_count(spot, len, node),
                    }
                }
            },
            Kind::InlineText(store) => {
                // No count to rewrite: the buffer is the member's own bytes and
                // its length is a fact about the structure, so a shortened
                // string is a terminator and nothing else.
                let was = until_nul(spot.bytes(store)?).len();
                self.put_text(spot, store.saturating_sub(1), was, tag, node)
                    .map(|_| ())
            }
        }
    }

    /// Applies what a pointer landed on.
    fn target(&mut self, landing: Spot<'a>, tag: &str, node: &Node, depth: usize) -> Result<()> {
        match landing.block.tag {
            BlockTag::Structure(name) => self.structure(name, landing, tag, node, depth),
            BlockTag::Type(word) => {
                let code = u8::try_from(word)
                    .map_err(|_| bad(landing.address(), Malformed::UndefinedStructure))?;
                // Deepened here and nowhere else on this path, for the reason
                // `render::Writer::target` gives — and by the same level, or a
                // payload one direction writes a document for is one the other
                // refuses.
                self.value(
                    Field {
                        member: typed(code),
                        owner: None,
                    },
                    tag,
                    landing,
                    node,
                    depth.saturating_add(1),
                )
            }
        }
    }

    /// Applies an array of either layout: `items.count` items from
    /// `items.base`.
    fn items(
        &mut self,
        field: Field<'a>,
        tag: &str,
        items: Items<'a>,
        node: &Node,
        depth: usize,
    ) -> Result<()> {
        expect(node, tag, ARRAY)?;
        expect_value(node, items.layout)?;
        let children = expect_children(node, usize::try_from(items.count).unwrap_or(usize::MAX))?;
        let (Some(base), true) = (items.base, items.count != 0) else {
            return Ok(());
        };
        let described = field.element(base.address())?;
        let stride = described.stride(self.values.meta, base.address())?;
        let item = reserved(ITEM);
        for (index, child) in children.iter().enumerate() {
            let index =
                u32::try_from(index).map_err(|_| bad(base.address(), Malformed::DataRange))?;
            let at = base.step(
                index
                    .checked_mul(stride)
                    .ok_or_else(|| bad(base.address(), Malformed::DataRange))?,
            )?;
            self.value(described, &item, at, child, depth.saturating_add(1))?;
        }
        Ok(())
    }
}

/// The writes. Every one is bounded by the block the value lives in — the same
/// bound [`super::render`] reads the same value under — and no two of them
/// disagree over one address.
impl<'a> Applier<'a, '_> {
    /// Writes `bytes` at `spot`.
    ///
    /// Two bounds, and the walk supplies neither:
    ///
    /// - **The block.** [`Spot::bytes`] is what [`super::render`] reads every
    ///   value through, and it is checked against the length the block's own
    ///   row declares. A structure instance longer than the block holding it,
    ///   or an array whose stride runs off the end of one, is a payload the
    ///   read direction refuses — so the write direction refuses it at the same
    ///   address, rather than writing over the 7.26% of the payload that
    ///   follows the last block and the 2.48% that is unreached and nonzero.
    ///   Bounding against `edited` alone bounds against the whole payload,
    ///   which is no bound at all.
    /// - **What another element already wrote.** DR-059: a second write to an
    ///   address is accepted only when it writes the same bytes, which every
    ///   unedited trip over an aliasing file does and a half-made edit does
    ///   not.
    ///
    /// # Errors
    ///
    /// [`Malformed::DataRange`] for the first, and
    /// [`NotMetaXml::Aliased`] for the second.
    fn put(&mut self, spot: Spot<'a>, bytes: &[u8], node: &Node) -> Result<()> {
        let address = spot.address();
        let gone = || bad(address, Malformed::DataRange);
        spot.bytes(u32::try_from(bytes.len()).map_err(|_| gone())?)?;
        let at = usize::try_from(address).map_err(|_| gone())?;
        let end = at.checked_add(bytes.len()).ok_or_else(gone)?;
        let seen = self.written.get(at..end).ok_or_else(gone)?;
        let there = self.edited.get(at..end).ok_or_else(gone)?;
        if seen
            .iter()
            .zip(there)
            .zip(bytes)
            .any(|((was, old), new)| *was && old != new)
        {
            return Err(Error::NotMetaXml {
                position: node.position,
                cause: NotMetaXml::Aliased {
                    name: node.tag.clone(),
                    address,
                },
            });
        }
        self.written.get_mut(at..end).ok_or_else(gone)?.fill(true);
        self.edited
            .get_mut(at..end)
            .ok_or_else(gone)?
            .copy_from_slice(bytes);
        Ok(())
    }

    /// Writes a counted value into the `room` bytes it has, and answers how
    /// many bytes it wrote.
    ///
    /// Nothing past the value is touched, which is what makes an unedited trip
    /// identical rather than merely equivalent: what follows is whatever the
    /// packer left, and the packer's leavings are 2.48% of a `Meta` payload.
    fn put_value(
        &mut self,
        landing: Spot<'a>,
        bytes: &[u8],
        room: u32,
        node: &Node,
    ) -> Result<u32> {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        if len > room {
            return Err(Error::NotMetaXml {
                position: node.position,
                cause: NotMetaXml::TooLong {
                    name: node.tag.clone(),
                    room,
                    len,
                },
            });
        }
        self.put(landing, bytes, node)?;
        Ok(len)
    }

    /// Writes a NUL-terminated string into the `room` bytes it has, and
    /// answers the new length when it is one the caller has to record.
    ///
    /// `was` is how long the string already there is. `None` says the value is
    /// unchanged, which is every unedited trip and is what keeps one
    /// byte-perfect: nothing at all is written past the value, because what
    /// follows is whatever the packer left and the packer's leavings are 2.48%
    /// of a `Meta` payload.
    fn put_text(
        &mut self,
        landing: Spot<'a>,
        store: u32,
        was: usize,
        tag: &str,
        node: &Node,
    ) -> Result<Option<u32>> {
        expect(node, tag, TEXT)?;
        let bytes = text::decode(&node.value).ok_or(Error::NotMetaXml {
            position: node.position,
            cause: NotMetaXml::BadEscape,
        })?;
        let room = room(store, was);
        let len = self.put_value(landing, &bytes, room, node)?;
        if usize::try_from(len).is_ok_and(|written| written == was) {
            return Ok(None);
        }
        if len < room {
            self.put(landing.step(len)?, &[0], node)?;
        }
        Ok(Some(len))
    }

    /// Rewrites the count a shortened value leaves behind.
    ///
    /// `count1` describes the bytes the edit changed, so it changes with them —
    /// DR-049's amendment, which a shortened `ATSTRING` was found contradicting
    /// in `PSO`. `count2` is the capacity of the allocation and is left alone,
    /// because an edit that would change an allocation is refused instead.
    fn put_count(&mut self, spot: Spot<'a>, len: u32, node: &Node) -> Result<()> {
        let stored = u16::try_from(len).map_err(|_| unreadable(node))?;
        self.put(spot.step(COUNT_AT)?, &stored.to_le_bytes(), node)
    }

    /// Writes a fixed-width value, little-endian.
    fn put_scalar(&mut self, scalar: Scalar, spot: Spot<'a>, node: &Node) -> Result<()> {
        let text = node.value.as_str();
        let bad_value = || unreadable(node);
        let lanes = |count: usize| -> Result<Vec<u8>> {
            let mut parts = text.split(LANE_SEPARATOR);
            let mut out = Vec::with_capacity(count.saturating_mul(4));
            for _ in 0..count {
                let part = parts.next().ok_or_else(bad_value)?;
                let number = unfloat(part.trim()).ok_or_else(bad_value)?;
                out.extend_from_slice(&number.to_bits().to_le_bytes());
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
            Scalar::Byte => vec![text.parse::<i8>().map_err(|_| bad_value())?.cast_unsigned()],
            Scalar::UByte | Scalar::ByteEnum => vec![text.parse::<u8>().map_err(|_| bad_value())?],
            Scalar::Short => text
                .parse::<i16>()
                .map_err(|_| bad_value())?
                .to_le_bytes()
                .to_vec(),
            Scalar::UShort | Scalar::ShortFlags => text
                .parse::<u16>()
                .map_err(|_| bad_value())?
                .to_le_bytes()
                .to_vec(),
            Scalar::Int | Scalar::IntEnum => text
                .parse::<i32>()
                .map_err(|_| bad_value())?
                .to_le_bytes()
                .to_vec(),
            Scalar::UInt | Scalar::IntFlags1 | Scalar::IntFlags2 => text
                .parse::<u32>()
                .map_err(|_| bad_value())?
                .to_le_bytes()
                .to_vec(),
            Scalar::Float => unfloat(text)
                .ok_or_else(bad_value)?
                .to_bits()
                .to_le_bytes()
                .to_vec(),
            Scalar::Float3 => lanes(3)?,
            Scalar::Float4 => lanes(4)?,
            Scalar::Hash => {
                let hash = unplaceholder(text).unwrap_or_else(|| joaat(text.as_bytes()));
                hash.to_le_bytes().to_vec()
            }
        };
        self.put(spot, &bytes, node)
    }
}

/// A member of no structure, standing for the one value a typed data block
/// holds.
fn typed(code: u8) -> Member {
    Member {
        name: 0,
        data_offset: 0,
        type_code: TypeCode::new(code),
        subtype: 0,
        array_info_index: 0,
        reference_key: 0,
    }
}

/// How many bytes a value may be written into: the `store` its form gives it,
/// and never less than the `was` bytes already there.
///
/// The second half is DR-049's rule that an edit moves nothing it did not
/// change, applied to a payload whose own value already fills its store. Such a
/// payload is not one this writes, but it is representable and the read
/// direction accepts it, so refusing to write it back unchanged would break the
/// round trip for a shape nobody edited. What the bound refuses is an *edit*
/// that would create the shape.
fn room(store: u32, was: usize) -> u32 {
    store.max(u32::try_from(was).unwrap_or(u32::MAX))
}

/// A value that does not read back as what its type word says it is.
fn unreadable(node: &Node) -> Error {
    Error::NotMetaXml {
        position: node.position,
        cause: NotMetaXml::Value {
            name: node.tag.clone(),
        },
    }
}

/// Checks an element's name and its type word.
fn expect(node: &Node, tag: &str, word: &str) -> Result<()> {
    if node.tag != tag {
        return Err(Error::NotMetaXml {
            position: node.position,
            cause: NotMetaXml::Tag {
                wanted: tag.to_owned(),
                found: node.tag.clone(),
            },
        });
    }
    if node.word != word {
        return Err(Error::NotMetaXml {
            position: node.position,
            cause: NotMetaXml::Word {
                wanted: word.to_owned(),
                found: node.word.clone(),
            },
        });
    }
    Ok(())
}

/// Checks the value of an element's reserved attribute, where the mapping fixes
/// it: a structure's own type, and an array's layout.
fn expect_value(node: &Node, wanted: &str) -> Result<()> {
    if node.value != wanted {
        return Err(Error::NotMetaXml {
            position: node.position,
            cause: NotMetaXml::Word {
                wanted: wanted.to_owned(),
                found: node.value.clone(),
            },
        });
    }
    Ok(())
}

/// Checks that a null pointer is still written down as one.
///
/// DR-047: the reserved word carries the type the value would have had,
/// because an absent value and an empty one are different things.
fn expect_null(node: &Node, tag: &str, word: &str) -> Result<()> {
    expect(node, tag, NULL)?;
    expect_value(node, word)
}

/// Checks that an element has exactly the children the file says it has.
fn expect_children(node: &Node, wanted: usize) -> Result<&[Node]> {
    if node.children.len() != wanted {
        return Err(Error::NotMetaXml {
            position: node.position,
            cause: NotMetaXml::Children {
                name: node.tag.clone(),
                wanted,
                found: node.children.len(),
            },
        });
    }
    Ok(&node.children)
}

#[cfg(test)]
mod tests {
    use super::{Error, NotMetaXml, read_tree};

    // -------------------------------------------------------------------
    // `is_space` — a mutant that always answers `true` would trim a stray
    // word down to nothing and never see it. The same pair `PSO` carries,
    // for the copy of the predicate this module holds.
    // -------------------------------------------------------------------

    /// Text between elements that is not whitespace is a document this
    /// mapping does not write, and is answered rather than dropped.
    #[test]
    fn text_between_elements_that_is_not_whitespace_is_refused() {
        let error = read_tree(b"<a meta:x=\"y\">not-blank</a>").expect_err("stray text is refused");
        assert!(
            matches!(
                error,
                Error::NotMetaXml {
                    cause: NotMetaXml::UnexpectedText,
                    ..
                }
            ),
            "{error:?}"
        );
    }

    /// Text that is only whitespace is the indentation the render writes, and
    /// is not content.
    #[test]
    fn text_between_elements_that_is_only_whitespace_is_accepted() {
        read_tree(b"<a meta:x=\"y\">  \n\t\r  </a>").expect("pure whitespace is not content");
    }
}
