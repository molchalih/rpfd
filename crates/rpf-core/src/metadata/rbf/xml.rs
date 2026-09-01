//! The XML an `RBF` document is written as, and read back from.

use quick_xml::{
    Reader, XmlVersion,
    escape::{escape, resolve_predefined_entity},
    events::Event,
};

use super::model::{
    Attribute, Blob, Content, Document, Element, MAX_DEPTH, Name, Node, NotRbf, RESERVED_PREFIX,
    Scalar, Str, Unrepresentable,
};
use crate::{
    error::{Error, Result},
    metadata::text::{self, float, unfloat},
};

/// The reserved attribute that carries an open element's two meaningless words.
const UNKNOWN: &str = "unknown";

const INDENT: &str = "  ";

/// The type words, one per `Scalar` variant.
const UINT: &str = "uint";
const FLOAT: &str = "float";
const BOOL: &str = "bool";
const FLOAT3: &str = "float3";
const STRING: &str = "string";

pub(super) fn write(document: &Document) -> Vec<u8> {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    write_element(&mut out, document.root(), 0);
    out.into_bytes()
}

fn write_element(out: &mut String, element: &Element, depth: usize) {
    indent(out, depth);
    out.push('<');
    out.push_str(element.name().as_str());
    let unknown = element.unknown();
    if unknown != [0, 0] {
        out.push(' ');
        out.push_str(RESERVED_PREFIX);
        out.push_str(UNKNOWN);
        out.push_str("=\"");
        let [first, second] = unknown;
        out.push_str(&first.to_string());
        out.push(' ');
        out.push_str(&second.to_string());
        out.push('"');
    }
    for attribute in element.attributes() {
        out.push(' ');
        if let Scalar::Str(_) = attribute.value {
            out.push_str(attribute.name.as_str());
        } else {
            out.push_str(RESERVED_PREFIX);
            out.push_str(word_of(&attribute.value));
            out.push('.');
            out.push_str(attribute.name.as_str());
        }
        out.push_str("=\"");
        out.push_str(&escape(render(&attribute.value)));
        out.push('"');
    }
    match element.content() {
        Content::Blob(blob) => {
            out.push('>');
            out.push_str(&escape(text::encode(blob.as_bytes())));
            close(out, element.name());
        }
        Content::Children(children) if children.is_empty() => out.push_str("/>\n"),
        Content::Children(children) => {
            out.push_str(">\n");
            for child in children {
                match child {
                    Node::Element(nested) => write_element(out, nested, depth.saturating_add(1)),
                    Node::Value { name, value } => {
                        write_value(out, name, value, depth.saturating_add(1));
                    }
                }
            }
            indent(out, depth);
            close(out, element.name());
        }
    }
}

fn write_value(out: &mut String, name: &Name, value: &Scalar, depth: usize) {
    indent(out, depth);
    out.push('<');
    out.push_str(name.as_str());
    out.push(' ');
    out.push_str(RESERVED_PREFIX);
    out.push_str(word_of(value));
    out.push_str("=\"");
    out.push_str(&escape(render(value)));
    out.push_str("\"/>\n");
}

fn close(out: &mut String, name: &Name) {
    out.push_str("</");
    out.push_str(name.as_str());
    out.push_str(">\n");
}

fn indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str(INDENT);
    }
}

fn word_of(value: &Scalar) -> &'static str {
    match value {
        Scalar::Uint(_) => UINT,
        Scalar::Bool(_) => BOOL,
        Scalar::Float(_) => FLOAT,
        Scalar::Float3(_) => FLOAT3,
        Scalar::Str(_) => STRING,
    }
}

fn render(value: &Scalar) -> String {
    match value {
        Scalar::Uint(number) => number.to_string(),
        Scalar::Bool(flag) => flag.to_string(),
        Scalar::Float(number) => float(*number),
        Scalar::Float3([x, y, z]) => format!("{}, {}, {}", float(*x), float(*y), float(*z)),
        Scalar::Str(string) => text::encode(string.as_bytes()),
    }
}

struct Building {
    name: Name,
    kind: Kind,
    children: Vec<Node>,
    text: String,
}

enum Kind {
    Element {
        unknown: [u16; 2],
        attributes: Vec<Attribute>,
    },
    Value(Scalar),
}

pub(super) fn read(document: &[u8]) -> Result<Document> {
    let mut reader = Reader::from_reader(document);
    reader.config_mut().expand_empty_elements = true;
    let at = |reader: &Reader<&[u8]>, cause: NotRbf| Error::NotRbfXml {
        position: reader.buffer_position(),
        cause,
    };

    let mut stack: Vec<Building> = Vec::new();
    let mut root: Option<Element> = None;

    loop {
        let event = reader.read_event().map_err(|error| Error::NotRbfXml {
            position: reader.error_position(),
            cause: NotRbf::Syntax {
                detail: error.to_string(),
            },
        })?;
        match event {
            Event::Start(start) => {
                if stack.is_empty() && root.is_some() {
                    return Err(at(&reader, NotRbf::SecondRoot));
                }
                if stack.len() >= MAX_DEPTH {
                    return Err(at(
                        &reader,
                        NotRbf::Unrepresentable {
                            cause: Unrepresentable::TooDeep,
                        },
                    ));
                }
                let name = named(start.name().into_inner()).map_err(|cause| at(&reader, cause))?;
                let kind = opening(&start).map_err(|cause| at(&reader, cause))?;
                stack.push(Building {
                    name,
                    kind,
                    children: Vec::new(),
                    text: String::new(),
                });
            }
            Event::End(_) => {
                let Some(building) = stack.pop() else {
                    return Err(at(
                        &reader,
                        NotRbf::Syntax {
                            detail: "a closing tag with nothing open".to_owned(),
                        },
                    ));
                };
                let node = finish(building).map_err(|cause| at(&reader, cause))?;
                match (stack.last_mut(), node) {
                    (Some(parent), node) => parent.children.push(node),
                    (None, Node::Element(element)) => root = Some(element),
                    (None, Node::Value { .. }) => {
                        return Err(at(&reader, NotRbf::RootNotElement));
                    }
                }
            }
            Event::Text(chunk) => {
                push_text(&mut stack, &chunk.xml10_content())
                    .map_err(|cause| at(&reader, cause))?;
            }
            Event::CData(chunk) => {
                push_text(&mut stack, &chunk.into_inner()).map_err(|cause| at(&reader, cause))?;
            }
            Event::GeneralRef(reference) => {
                let resolved = reference
                    .resolve_char_ref()
                    .ok()
                    .flatten()
                    .map(|character| character.to_string())
                    .or_else(|| resolve_predefined_entity(&reference).map(str::to_owned))
                    .ok_or_else(|| {
                        at(
                            &reader,
                            NotRbf::Syntax {
                                detail: format!("unknown entity &{}", reference.as_ref()),
                            },
                        )
                    })?;
                push_text(&mut stack, &resolved).map_err(|cause| at(&reader, cause))?;
            }
            Event::Eof => break,
            // `expand_empty_elements` turns every `<a/>` into a start and an
            // end, so `Empty` cannot occur; the rest carry nothing an `RBF`
            // document can hold.
            Event::Decl(_)
            | Event::Comment(_)
            | Event::PI(_)
            | Event::DocType(_)
            | Event::Empty(_) => {}
        }
    }

    if !stack.is_empty() {
        return Err(at(
            &reader,
            NotRbf::Syntax {
                detail: "the document ended with elements still open".to_owned(),
            },
        ));
    }
    let Some(element) = root else {
        return Err(at(&reader, NotRbf::Empty));
    };
    Document::new(element).map_err(|cause| at(&reader, NotRbf::Unrepresentable { cause }))
}

/// Adds text to the innermost open element.
fn push_text(stack: &mut [Building], chunk: &str) -> std::result::Result<(), NotRbf> {
    match stack.last_mut() {
        Some(building) => {
            building.text.push_str(chunk);
            Ok(())
        }
        None if chunk.trim_matches(is_space).is_empty() => Ok(()),
        None => Err(NotRbf::UnexpectedText),
    }
}

fn is_space(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\r' | '\n')
}

fn named(text: &str) -> std::result::Result<Name, NotRbf> {
    Name::new(text).map_err(|cause| NotRbf::Unrepresentable { cause })
}

/// Reads an opening tag's attributes into what they say the tag is.
fn opening(start: &quick_xml::events::BytesStart<'_>) -> std::result::Result<Kind, NotRbf> {
    let mut unknown = [0u16; 2];
    let mut attributes: Vec<Attribute> = Vec::new();
    let mut marker: Option<Scalar> = None;

    for attribute in start.attributes() {
        let attribute = attribute.map_err(|error| NotRbf::Syntax {
            detail: error.to_string(),
        })?;
        let key = attribute.key.as_ref();
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|error| NotRbf::Syntax {
                detail: error.to_string(),
            })?;
        let Some(reserved) = key.strip_prefix(RESERVED_PREFIX) else {
            attributes.push(Attribute {
                name: named(key)?,
                value: Scalar::Str(text::decode(&value).ok_or(NotRbf::BadEscape).and_then(
                    |bytes| Str::new(bytes).map_err(|cause| NotRbf::Unrepresentable { cause }),
                )?),
            });
            continue;
        };
        if reserved == UNKNOWN {
            unknown = words(&value).ok_or_else(|| NotRbf::BadValue {
                name: key.to_owned(),
            })?;
        } else if let Some((word, name)) = reserved.split_once('.') {
            if word == STRING {
                return Err(NotRbf::UnknownReserved {
                    name: key.to_owned(),
                });
            }
            attributes.push(Attribute {
                name: named(name)?,
                value: scalar(word, &value, key)?,
            });
        } else {
            if marker.is_some() {
                return Err(NotRbf::ValueNotAlone {
                    name: start.name().into_inner().to_owned(),
                });
            }
            marker = Some(scalar(reserved, &value, key)?);
        }
    }

    match marker {
        Some(value) if attributes.is_empty() && unknown == [0, 0] => Ok(Kind::Value(value)),
        Some(_) => Err(NotRbf::ValueNotAlone {
            name: start.name().into_inner().to_owned(),
        }),
        None => Ok(Kind::Element {
            unknown,
            attributes,
        }),
    }
}

fn words(value: &str) -> Option<[u16; 2]> {
    let (first, second) = value.split_once(' ')?;
    Some([first.parse().ok()?, second.parse().ok()?])
}

fn scalar(word: &str, value: &str, key: &str) -> std::result::Result<Scalar, NotRbf> {
    let bad = || NotRbf::BadValue {
        name: key.to_owned(),
    };
    match word {
        UINT => value.parse().map(Scalar::Uint).map_err(|_| bad()),
        BOOL => match value {
            "true" => Ok(Scalar::Bool(true)),
            "false" => Ok(Scalar::Bool(false)),
            _ => Err(bad()),
        },
        FLOAT => unfloat(value).map(Scalar::Float).ok_or_else(bad),
        FLOAT3 => {
            let mut parts = value.split(',');
            let mut numbers = [0f32; 3];
            for slot in &mut numbers {
                *slot = parts
                    .next()
                    .and_then(|part| unfloat(part.trim()))
                    .ok_or_else(bad)?;
            }
            if parts.next().is_some() {
                return Err(bad());
            }
            Ok(Scalar::Float3(numbers))
        }
        STRING => text::decode(value)
            .ok_or(NotRbf::BadEscape)
            .and_then(|bytes| Str::new(bytes).map_err(|cause| NotRbf::Unrepresentable { cause }))
            .map(Scalar::Str),
        _ => Err(NotRbf::UnknownReserved {
            name: key.to_owned(),
        }),
    }
}

/// Turns a closed tag into the node it stands for.
fn finish(building: Building) -> std::result::Result<Node, NotRbf> {
    let Building {
        name,
        kind,
        children,
        text: body,
    } = building;
    let body = body.trim_matches(is_space);
    match kind {
        Kind::Value(value) => {
            if children.is_empty() && body.is_empty() {
                Ok(Node::Value { name, value })
            } else {
                Err(NotRbf::ValueNotAlone {
                    name: name.as_str().to_owned(),
                })
            }
        }
        Kind::Element {
            unknown,
            attributes,
        } => {
            let content =
                if body.is_empty() {
                    Content::Children(children)
                } else if children.is_empty() {
                    Content::Blob(text::decode(body).ok_or(NotRbf::BadEscape).and_then(
                        |bytes| Blob::new(bytes).map_err(|cause| NotRbf::Unrepresentable { cause }),
                    )?)
                } else {
                    return Err(NotRbf::UnexpectedText);
                };
            Element::new(name, unknown, attributes, content)
                .map(Node::Element)
                .map_err(|cause| NotRbf::Unrepresentable { cause })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{NotRbf, read};
    use crate::error::Error;

    /// The cause `read` refused with, or a panic naming what it did instead.
    fn refused(document: &[u8]) -> NotRbf {
        match read(document) {
            Err(Error::NotRbfXml { cause, .. }) => cause,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn whitespace_outside_the_root_is_tolerated_and_anything_else_is_not() {
        read(b"<root></root>\n").expect("trailing whitespace is not text");
        assert_eq!(
            refused(b"<root></root>stray"),
            NotRbf::UnexpectedText,
            "non-whitespace outside the root must be refused"
        );
    }

    #[test]
    fn a_value_element_carrying_stray_text_is_refused_rather_than_read_alone() {
        // `finish` is where a value record's children and body are checked
        // together — either alone is not the empty pair the record promises.
        assert_eq!(
            refused(b"<root><field rbf:uint=\"42\">stray</field></root>"),
            NotRbf::ValueNotAlone {
                name: "field".to_owned()
            },
        );
    }
}
