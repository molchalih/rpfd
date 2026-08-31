//! The XML read back, and applied to the file it was written from.
//!
//! R5.4, and DR-049 is why this takes the original payload rather than the
//! document alone. The short version is that a `PSO` file carries more than its
//! data: an opaque `PSIG`, an encrypted `STRE`, a `PSCH` that describes
//! structures the data never instantiates, and 2.86% of `PSIN` bytes no walk
//! from the root ever reaches. None of that is in the document, and none of it
//! can be invented, so the write direction **edits** the file it came from.
//!
//! The walk here is [`super::render`]'s walk read backwards: the same schema,
//! the same block table, the same addresses, in the same order. It is a second
//! spelling of the traversal and not a second spelling of one operation —
//! `rbf`'s `token::read` and `token::write` stand in the same relation — and
//! everything the two genuinely share is [`super::data`].
//!
//! Every address it writes at is one [`super::render`] read from, so no
//! structural fact of the file changes: no block moves, no count changes, no
//! pointer is rewritten. A value that no longer fits where it was is a refusal
//! ([`NotPsoXml::TooLong`]), and so is an array of a different length or a
//! structure of a different member list. DR-052 is why those three are the
//! permanent boundary of `PSO` editing rather than work not yet done, and why
//! the room a string has is the store its form gives it less the byte its
//! terminator needs — never less, though, than the value already there, because
//! an edit moves nothing it did not change.

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

/// How the bits a bitset holds are separated.
const BITS_SEPARATOR: char = ' ';

/// How the lanes of a vector are separated.
const LANE_SEPARATOR: char = ',';

/// Reads the XML [`super::render`] wrote and applies it to the payload it was
/// written from.
///
/// # Errors
///
/// [`Error::BadPso`] if `payload` contradicts itself, [`Error::UnsupportedPso`]
/// if it carries a member type this build does not decode, and
/// [`Error::NotPsoXml`] if `document` is not XML or does not describe this
/// payload.
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

    // Before the document is parsed, because parsing it is what costs: the
    // whole of it is materialised into a tree before the first comparison
    // against the payload, and a 68 MB document against a 172-byte payload
    // reached 652 MB resident on its way to being refused at its first child.
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

/// The `CHKS` section, recomputed over whatever the edit left behind.
///
/// `docs/metadata-encodings.md`, `CHKS`: a Jenkins one-at-a-time hash seeded
/// `0x3FAC7125` over the **whole file**, each byte taken as a signed `int8`,
/// with the `fileSize` and `checksum` fields zeroed first. It reproduces the
/// stored value in 8,978 of 8,978 files that carry one, so an unedited round
/// trip through it is a fixed point and an edited one is correct rather than
/// stale.
mod checksum {
    use super::{Malformed, bad, section};
    use crate::error::Result;

    /// The seed. Not zero, unlike `metadata::hash::joaat`'s.
    const SEED: u32 = 0x3FAC_7125;

    /// Where the file size sits inside the section.
    const SIZE_AT: usize = 8;

    /// Where the checksum sits inside the section.
    const CHECKSUM_AT: usize = 12;

    /// Rewrites the `CHKS` section, if the file has one.
    ///
    /// # Errors
    ///
    /// [`Malformed::Checksum`] when the section is not the twenty bytes
    /// `docs/metadata-encodings.md` records it always is, or when a field of it
    /// would fall outside those twenty bytes. The two writes are bounded by the
    /// section rather than by the file, because a chain declaring a shorter
    /// `CHKS` would otherwise have the next section's tag and length written
    /// over — and a failure is answered rather than swallowed, because the
    /// alternative is emitting a file whose checksum is stale and whose caller
    /// was told nothing (`docs/conventions.md` §4).
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

    /// Writes one big-endian `u32` field of the section at `at`, bounded by the
    /// section's own length rather than by the file's.
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
    ///
    /// The signed byte is the part that was under suspicion and is right: the
    /// unsigned variant matches 0 of 8,978.
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

        /// The write is bounded by the section's own twenty bytes, not by the
        /// file: a field ending exactly on that boundary is the last one a
        /// `CHKS` section can hold, and it must still be accepted.
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

        /// One byte past that boundary is refused rather than written into
        /// whatever follows the section — the defect this bound exists to
        /// prevent, `docs/metadata-encodings.md`, `CHKS`.
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

/// One element of the document: its name, its one reserved attribute, and its
/// children.
///
/// Every element [`super::render`] writes carries **exactly one** `pso:`
/// attribute, which is what makes this shape total rather than a subset: the
/// type of every record is written down, which is DR-047's central decision and
/// what R5.4 was promised.
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
                // about to be pushed will sit at, and `Applier::structure` and
                // `super::render`'s `spend` both accept `MAX_DEPTH` itself. At
                // `>=` this direction stopped one level short of the other, so
                // a payload whose walk is exactly this deep rendered and was
                // then refused — and blamed the document for it.
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

/// Whether a character is XML whitespace, and so may be indentation.
fn is_space(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\r' | '\n')
}

/// Reads an opening tag into the node it stands for.
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

/// The walk in progress: the payload it reads and the copy it writes.
#[derive(Debug)]
struct Applier<'a> {
    /// The original `PSIN` section. Every address, count and pointer the walk
    /// follows is read from here, so an edit cannot move the walk.
    data: Data<'a>,
    /// The copy the values go into.
    edited: Vec<u8>,
    schema: &'a Schema,
    names: &'a Dictionary,
}

/// The three numbers the schema declares about an array, so that applying one
/// is a function of six arguments rather than seven.
#[derive(Debug, Clone, Copy)]
struct Array {
    /// How the elements are reached.
    layout: Layout,
    /// Which member of the owning structure describes one element.
    element: u16,
    /// How many, for the forms whose count is in the schema.
    count: u16,
}

/// Where a value is, and what describes it.
#[derive(Debug, Clone, Copy)]
struct At<'a> {
    /// The structure whose member list an element index resolves against.
    owner: &'a Structure,
    /// Where the value starts, from the start of the `PSIN` section.
    address: u32,
    /// How deep the walk is.
    depth: usize,
}

impl<'a> Applier<'a> {
    /// Applies one structure instance.
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

    /// Applies one value — a member of a structure, or one element of an array.
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

    /// Applies one of the six string forms.
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
                // A fixed inline string is `len` bytes and its terminator is one
                // of them: `docs/metadata-encodings.md`, Pointers — 116,507 of
                // 116,507 shipped member strings end inside their own member,
                // so filling all `len` is a shape no shipped file has and a
                // string the next member continues.
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
                // The bytes a counted string owns are its characters and the
                // NUL after them, and `count1` and `count2` disagree about
                // which of the two they measure: `docs/metadata-encodings.md`,
                // Pointers. Over all 39,469 counted strings the corpus reaches,
                // the characters number `min(count1, count2)` — the 38,683
                // whose capacity is the larger store `count1` and terminate at
                // `count1`, and the 786 whose capacity is the smaller store
                // `count2` and terminate at `count2`. So the store is the
                // smaller of the two, and a write bounded by `count1` alone
                // puts a character over the terminator of those 786.
                let capacity = self.data.half(at.address.saturating_add(CAPACITY_AT))?;
                let store = u32::from(count.min(capacity));
                match self.data.pointer(at.address)? {
                    None => expect_null(node, tag, word),
                    Some(address) => {
                        expect(node, tag, word)?;
                        // `count1` is the length — `schema::COUNT_AT` — so a
                        // string that changed length has to take it with it.
                        // The reader answers `until_nul` of the bytes it
                        // covers and so cannot see it left behind.
                        //
                        // Rewritten only when the length actually changed,
                        // and never merely because the stored count disagrees
                        // with what the bytes read back as. Whether `count1`
                        // counts the terminator is the file's own business —
                        // a payload carrying `count1 = 1` over a lone NUL is
                        // a payload this reads as the empty string — and
                        // DR-049 moves nothing the edit did not.
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

    /// Applies a nested structure, inline or through a pointer.
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

    /// The value an enum element names.
    ///
    /// The inverse of [`super::render`]'s rendering, in the same order: a name
    /// the file's own table carries, and otherwise the decimal the renderer
    /// falls back to. The two cannot be confused — a dictionary name must begin
    /// with a letter, `_` or `:`, and a placeholder begins `hash_`.
    fn enumerated(&self, table: u32, node: &Node) -> Result<i32> {
        if let Some(key) = self.keyed(table, &node.value, node)? {
            return Ok(key);
        }
        node.value.parse().map_err(|_| unreadable(node))
    }

    /// The key an enum table gives a rendered name, when exactly one does.
    ///
    /// More than one is [`NotPsoXml::Ambiguous`] rather than a choice: two keys
    /// whose names render the same are indistinguishable in the document, and
    /// picking one would write a value the reader never wrote.
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

    /// Applies an array and its items.
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

    /// Applies an `ATBINARYMAP` and its entries.
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

/// The writes. Every one is bounds-checked against the section, and every one
/// is at an address [`super::render`] read the same value from.
impl Applier<'_> {
    /// Writes `bytes` at `address`.
    fn put(&mut self, address: u32, bytes: &[u8]) -> Result<()> {
        let gone = || bad(u64::from(address), Malformed::DataRange);
        let at = usize::try_from(address).map_err(|_| gone())?;
        let end = at.checked_add(bytes.len()).ok_or_else(gone)?;
        let room = self.edited.get_mut(at..end).ok_or_else(gone)?;
        room.copy_from_slice(bytes);
        Ok(())
    }

    /// Writes a string into the `room` bytes it has, NUL-terminated when there
    /// is a byte to spare, and answers how many bytes it wrote.
    ///
    /// Nothing past the terminator is touched, which is what makes an unedited
    /// trip identical rather than merely equivalent: a fixed inline string is
    /// read up to its first NUL, and what follows is whatever the packer left.
    ///
    /// The length is answered rather than discarded because a form that stores
    /// its own length has to be told it: an `ATSTRING`'s `count1` describes
    /// these bytes, and a shortened string that left it alone would write a
    /// file saying five where three were written.
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

    /// Writes an enum's value at its stored width.
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

    /// Writes a bitset's value at its stored width.
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

    /// Writes a fixed-width value.
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

/// How many bytes a string may be written into: the `store` its form gives it,
/// and never less than the `was` bytes already there.
///
/// The second half is DR-049's rule that an edit moves nothing it did not
/// change, applied to a payload whose own string already fills its store and
/// leaves no terminator. Such a payload is in neither the corpus nor anything
/// this writes — 0 of 116,507 fixed inline strings and 0 of 39,469 counted ones
/// — but it is representable, and refusing to write it back unchanged would
/// break the round trip for a shape the reader accepts. DR-052.
fn room(store: u32, was: usize) -> u32 {
    store.max(u32::try_from(was).unwrap_or(u32::MAX))
}

/// A value that does not read back as what its type word says it is.
fn unreadable(node: &Node) -> Error {
    Error::NotPsoXml {
        position: node.position,
        cause: NotPsoXml::Value {
            name: node.tag.clone(),
        },
    }
}

/// The element name an array item or a map entry is written under.
fn reserved_item() -> String {
    format!("{RESERVED_PREFIX}{ITEM}")
}

/// Checks an element's name and its type word.
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

/// Checks the value of an element's reserved attribute, where the mapping fixes
/// it: a structure's own type, and an array's or a map's subtype.
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

/// Checks that a null pointer is still written down as one.
///
/// DR-047: `pso:null` carries the type word the value would have had, because
/// an empty string and an absent one are different things.
fn expect_null(node: &Node, tag: &str, word: &str) -> Result<()> {
    expect(node, tag, NULL)?;
    expect_value(node, word)
}

/// Checks that an element has exactly the children the file says it has.
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

/// The half-float `f32` narrows to, or `None` when it does not narrow exactly.
///
/// The inverse of `section::f16`, and it refuses rather than rounds: a value
/// that is not a half is a value the file cannot hold, and silently storing the
/// nearest one would make the document and the payload disagree.
/// `docs/metadata-encodings.md`, the census: `FLOAT16` is 60 of 580,044
/// members, and the pinned toolchain has no `f16`.
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
    // A half subnormal: the implicit one comes back and the whole thing shifts
    // down by however far the exponent is below the half's smallest. A half
    // subnormal is `m * 2^-24` and the `f32` is `full * 2^(exponent-150)`, so
    // `m` is `full >> (14 - shifted)`; 13 is off by a factor of two and every
    // subnormal half is wrong by it.
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

    /// An arbitrary structure name, distinct from any member name used here.
    const ROOT_NAME: u32 = 0xD98B_B561;
    /// An arbitrary member name, distinct from [`ROOT_NAME`] and [`ARRAYINFO`].
    const MEMBER_NAME: u32 = 0x1234_5678;
    /// The `ARRAYINFO` sentinel, `crate::metadata::pso::model`'s own copy not
    /// being imported into this module.
    const ARRAYINFO: u32 = 0x0000_0100;

    /// A one-entry `PMAP` block table naming a block of `length` bytes at
    /// `offset`.
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

    /// A block table naming one block, large enough that a landing anywhere
    /// inside it is in range.
    fn trivial_blocks() -> Blocks {
        Blocks::read(&one_block_pmap(0, 64), 64).expect("a minimal block table reads")
    }

    /// A document node, built directly rather than parsed.
    fn node(tag: &str, word: &str, value: &str) -> Node {
        Node {
            position: 0,
            tag: tag.to_owned(),
            word: word.to_owned(),
            value: value.to_owned(),
            children: Vec::new(),
        }
    }

    // -------------------------------------------------------------------
    // `is_space` — a mutant that always answers `true` would trim a stray
    // word down to nothing and never see it.
    // -------------------------------------------------------------------

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

    // -------------------------------------------------------------------
    // `Applier::counted` — the `None` arm's `count == 0` guard tells an
    // array that is legitimately empty from a null pointer with items
    // nowhere to be, which is the file contradicting itself.
    // -------------------------------------------------------------------

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

    // -------------------------------------------------------------------
    // `Applier::structure` — the depth ceiling accepts a structure exactly
    // `MAX_DEPTH` deep and refuses only past it.
    // -------------------------------------------------------------------

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

        // At the ceiling itself, the depth check must not be what refuses:
        // the schema defines nothing, so what should surface once the depth
        // check is passed is `UndefinedStructure`, not `TooDeep`.
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

    // -------------------------------------------------------------------
    // `expect_value` and `expect_null` — a refusal that never fires is a
    // refusal that does not exist.
    // -------------------------------------------------------------------

    /// A minimal valid `PSO`: one block, one structure, one `UINT` member.
    ///
    /// The same shape `crates/rpf-core/tests/metadata.rs`'s `minimal_pso`
    /// builds, kept local because a test crate and a unit test module share
    /// no code.
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

    /// A `PSO` whose one member is a null `STRUCT` pointer.
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

    // -------------------------------------------------------------------
    // The `Layout::PointerWithCount` arm — deleting it falls through to the
    // inline wildcard, so an edit lands on the pointer's own bytes instead
    // of on the block the pointer names.
    // -------------------------------------------------------------------

    /// A `PSO` whose one field is a `PointerWithCount` array of one `UINT`,
    /// the pointer naming a second block that holds the one item.
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

    // -------------------------------------------------------------------
    // `narrow` — the `||` at the top of the infinity/NaN arm. Its second
    // half is dead in isolation (see the report), but the disjunction as a
    // whole is not: a payload with a low bit that would be dropped and a
    // nonzero high half must still be refused.
    // -------------------------------------------------------------------

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
