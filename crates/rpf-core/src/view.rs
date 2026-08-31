//! Which form of an entry a caller reads and writes: its own bytes, or the XML
//! view of them.
//!
//! This is where the container and the metadata layer meet, and it is on this
//! side of the boundary for the reason `edit::check_encoding` is: an entry's
//! encoding comes from [`Archive::classify`], the conversion comes from
//! [`crate::metadata::view`], and neither of the two layers may know about the
//! other (`docs/conventions.md` §2). Nothing here holds a signature, a schema
//! or a token, and nothing here knows what XML *is* — it knows only that an
//! encoding may have a view and that a converter answers it.
//!
//! Both frontends read and write through this one module, so `rpf cat --as xml`
//! and the daemon's `read {"as": "xml"}` are the same bytes by construction
//! (§1). DR-053 argues the shape, and what a client may and may not conclude
//! from it.
//!
//! **What has a view is not a fact this module holds.** It asks
//! [`crate::metadata::view::to_xml`], which answers `None` for an encoding with
//! none, so the set is written down exactly once and one layer down (§3). An
//! entry that gains a view later — a resource carrying `Meta`, R5.8 — gains it
//! there and every caller of this module gains it with no change of its own.

use std::io::{Read, Seek};

use crate::{
    archive::{Archive, Classification},
    error::{Error, Result},
    metadata::{Encoding, hash::Dictionary, view as convert},
};

/// Which form of an entry a caller is asking for.
///
/// The three are a wire contract as well as a type: `"raw"`, `"xml"` and
/// `"auto"` are what `--as` takes and what `read` and `write` carry, and
/// [`View::name`] is the one place they are spelled (§3). DR-053.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum View {
    /// The entry's own bytes, whatever they are.
    ///
    /// The default everywhere, and deliberately: `rpf cat > f` followed by
    /// `rpf put … f` is a round trip through the filesystem that must stay
    /// byte for byte, and a caller that asked for nothing asked for that.
    #[default]
    Raw,
    /// The XML view. An entry that has none is refused.
    Xml,
    /// The XML view where the entry has one, and the entry's own bytes where it
    /// has not.
    ///
    /// What an editor asks for: it presents whatever it is given and must not
    /// guess from an extension which of the two it will be. The answer says
    /// which it got.
    Auto,
}

impl View {
    /// Every view, for a frontend enumerating them.
    pub const ALL: [Self; 3] = [Self::Raw, Self::Xml, Self::Auto];

    /// This view's name, in the one spelling both frontends take and report.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Xml => "xml",
            Self::Auto => "auto",
        }
    }

    /// The view this name spells, or `None` for a name no view has.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|view| view.name() == name)
    }
}

/// What a caller wants of an entry: which form, and how the hashes in it are
/// spelled while it is in that form.
///
/// Grouped rather than passed as two more parameters, for the reason
/// [`crate::Change`]'s options are: a call site reading `apply(src, a, i, p,
/// view, offered, names)` says nothing about which argument is which. The
/// dictionary rides with the view because it is only ever consulted in one —
/// it decides how a `PSO`'s names are rendered and is cosmetic by construction
/// (R5.5), so [`Dictionary::default`] is a complete answer.
#[derive(Debug, Clone, Copy)]
pub struct Wanted<'a> {
    /// Which form of the entry.
    pub view: View,
    /// How a `PSO`'s hashes are spelled in it.
    pub names: &'a Dictionary,
}

/// An entry's bytes, in the form that was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Viewed {
    /// The bytes.
    pub bytes: Vec<u8>,
    /// Whether they are the XML view rather than the entry's own payload.
    ///
    /// A `bool` rather than a [`View`], because [`View::Auto`] is a question
    /// and never an answer: what came back is one of the two forms, and a type
    /// that could say "auto" here would be saying nothing (§5).
    pub xml: bool,
    /// What the entry's payload announces itself to be, or `None` when it
    /// announces nothing, is a resource, or is a directory.
    ///
    /// A resource's `None` means its payload was not read, exactly as a
    /// listing row's does. `docs/backlog.md` Q7, DR-044.
    pub encoding: Option<Encoding>,
}

/// Reads one entry in the form `view` asks for.
///
/// `path` is how the caller spelled the entry, and is what a refusal names.
///
/// **A resource is never sniffed.** The entry's kind decides first, through
/// [`Archive::classify`], so a resource has no view whatever its bytes look
/// like — Q7's trap, and DR-044's answer to it.
///
/// # Errors
///
/// [`Error::NoXmlView`] when [`View::Xml`] is asked of an entry that has none,
/// [`Error::WrongKind`] for a directory, and whatever reading the entry or
/// converting it answers.
pub fn read<R: Read + Seek>(
    src: &mut R,
    archive: &Archive,
    index: u32,
    path: &str,
    wanted: Wanted<'_>,
) -> Result<Viewed> {
    let encoding = match archive.classify(src, index)? {
        Classification::Directory => {
            return Err(Error::WrongKind {
                path: path.to_owned(),
                found: "directory",
                wanted: "file",
            });
        }
        Classification::Encoded(encoding) => Some(encoding),
        Classification::Resource | Classification::Binary => None,
    };
    let bytes = archive.extract(src, index)?;
    of(bytes, encoding, path, wanted)
}

/// The same decision over a payload a caller already holds, which is what the
/// daemon asks of a write it has buffered.
///
/// `encoding` is what the entry holds, and `None` is both "nothing recognised"
/// and "not read". A caller with no entry to ask — a payload on its own — puts
/// the payload's own [`Encoding::of`] here, which is what the conversion would
/// have derived anyway.
///
/// # Errors
///
/// As [`read`], less the directory case, which a payload cannot be.
pub fn of(
    payload: Vec<u8>,
    encoding: Option<Encoding>,
    path: &str,
    wanted: Wanted<'_>,
) -> Result<Viewed> {
    let raw = |bytes: Vec<u8>| Viewed {
        bytes,
        xml: false,
        encoding,
    };
    if wanted.view == View::Raw {
        return Ok(raw(payload));
    }
    // A resource's payload is never handed to a converter, so the classified
    // `None` is the whole of the answer and the bytes are not consulted.
    let converted = if encoding.is_some() {
        convert::to_xml(&payload, wanted.names)?
    } else {
        None
    };
    match (converted, wanted.view) {
        (Some(document), _) => Ok(Viewed {
            bytes: document,
            xml: true,
            encoding,
        }),
        (None, View::Xml) => Err(Error::NoXmlView {
            path: path.to_owned(),
            held: encoding,
        }),
        (None, View::Raw | View::Auto) => Ok(raw(payload)),
    }
}

/// The payload to write into one entry, from bytes offered in the form `view`
/// says they are.
///
/// [`View::Raw`] hands them back untouched. [`View::Xml`] reads them as a
/// document and applies it to the payload the entry holds — DR-049, for `PSO`
/// — and refuses an entry with no view. [`View::Auto`] does that only when the
/// offered bytes announce themselves as XML **and** the entry has a view, and
/// hands them back untouched otherwise: an editor hands back what it was given,
/// and a payload that is not a document is not one.
///
/// What comes back is a payload of the entry's own encoding, which is why a
/// converted write needs no `allow_encoding_change`: there is no encoding
/// change in it. DR-050's rule judges the result, unchanged and unweakened.
///
/// # Errors
///
/// [`Error::NoXmlView`] when [`View::Xml`] is asked of an entry that has none,
/// and [`Error::NotRbfXml`] or [`Error::NotPsoXml`] for a document that does
/// not describe the payload it is applied to.
pub fn applied(held: &[u8], path: &str, wanted: Wanted<'_>, offered: Vec<u8>) -> Result<Vec<u8>> {
    match wanted.view {
        View::Raw => Ok(offered),
        View::Xml => {
            convert::from_xml(held, &offered, wanted.names)?.ok_or_else(|| Error::NoXmlView {
                path: path.to_owned(),
                held: Encoding::of(held.get(..Encoding::HEAD_LEN).unwrap_or(held)),
            })
        }
        View::Auto => {
            let announced = Encoding::of(offered.get(..Encoding::HEAD_LEN).unwrap_or(&offered));
            if announced != Some(Encoding::Xml) {
                return Ok(offered);
            }
            Ok(convert::from_xml(held, &offered, wanted.names)?.unwrap_or(offered))
        }
    }
}

/// The same, reading the payload the entry holds now out of the archive.
///
/// The read is the whole of what makes a `PSO` write possible: DR-049 makes it
/// an **edit** of the file the document came from, so the file has to be to
/// hand. It is read here, in the call that converts, from the handle the caller
/// is already holding open — never asked about first and read later, which is
/// the shape that once corrupted an 80 MB archive.
///
/// # Errors
///
/// As [`applied`], and whatever reading the entry answers.
pub fn apply<R: Read + Seek>(
    src: &mut R,
    archive: &Archive,
    index: u32,
    path: &str,
    wanted: Wanted<'_>,
    offered: Vec<u8>,
) -> Result<Vec<u8>> {
    if wanted.view == View::Raw {
        return Ok(offered);
    }
    if archive.classify(src, index)? == Classification::Directory {
        return Err(Error::WrongKind {
            path: path.to_owned(),
            found: "directory",
            wanted: "file",
        });
    }
    let held = archive.extract(src, index)?;
    applied(&held, path, wanted, offered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_view_names_itself_and_answers_to_its_own_name() {
        for view in View::ALL {
            assert_eq!(View::parse(view.name()), Some(view));
        }
        assert_eq!(View::parse("XML"), None);
        assert_eq!(View::parse(""), None);
        assert_eq!(View::default(), View::Raw);
    }

    #[test]
    fn a_raw_read_of_anything_is_the_bytes_and_says_so() {
        let names = Dictionary::default();
        let viewed = of(
            b"<?xml version=\"1.0\"?><a/>".to_vec(),
            Some(Encoding::Xml),
            "a.xml",
            Wanted {
                view: View::Raw,
                names: &names,
            },
        )
        .expect("raw takes anything");
        assert!(!viewed.xml);
        assert_eq!(viewed.encoding, Some(Encoding::Xml));
    }

    #[test]
    fn an_entry_with_no_view_refuses_xml_and_is_given_its_bytes_by_auto() {
        let names = Dictionary::default();
        let payload = b"Version 1\r\nabcdef".to_vec();
        let refused = of(
            payload.clone(),
            Some(Encoding::Text),
            "notes.txt",
            Wanted {
                view: View::Xml,
                names: &names,
            },
        )
        .expect_err("text has no view");
        assert_eq!(refused.name(), "NoXmlView");
        let viewed = of(
            payload.clone(),
            Some(Encoding::Text),
            "n",
            Wanted {
                view: View::Auto,
                names: &names,
            },
        )
        .expect("auto falls back");
        assert!(!viewed.xml);
        assert_eq!(viewed.bytes, payload);
    }

    #[test]
    fn a_resource_is_not_sniffed_even_when_its_bytes_would_name_something() {
        // `encoding: None` is the classification's answer for a resource, and
        // it is what decides here: the payload below is plainly XML and still
        // has no view, because what an entry *is* comes from its row. Q7.
        let names = Dictionary::default();
        let payload = b"<?xml version=\"1.0\"?><a/>".to_vec();
        let refused = of(
            payload.clone(),
            None,
            "a.ytd",
            Wanted {
                view: View::Xml,
                names: &names,
            },
        )
        .expect_err("a resource has no view");
        assert_eq!(refused.name(), "NoXmlView");
        let viewed = of(
            payload.clone(),
            None,
            "a.ytd",
            Wanted {
                view: View::Auto,
                names: &names,
            },
        )
        .expect("auto");
        assert!(!viewed.xml);
        assert_eq!(viewed.bytes, payload);
    }

    #[test]
    fn auto_hands_back_bytes_that_are_not_a_document_untouched() {
        // What an editor pastes into an entry is not always a document, and
        // `auto` must not turn a payload into a refusal that `raw` would take.
        let names = Dictionary::default();
        let offered = vec![0x00, 0x01, 0x02, 0x03];
        assert_eq!(
            applied(
                b"RBF0\x00\x00\x00\x00",
                "x.ymt",
                Wanted {
                    view: View::Auto,
                    names: &names
                },
                offered.clone()
            )
            .expect("auto takes what it cannot convert"),
            offered
        );
    }

    #[test]
    fn an_xml_write_into_an_entry_with_no_view_is_refused() {
        let names = Dictionary::default();
        let refused = applied(
            b"Version 1\r\nabcdef",
            "notes.txt",
            Wanted {
                view: View::Xml,
                names: &names,
            },
            b"<?xml version=\"1.0\"?><a/>".to_vec(),
        )
        .expect_err("text has no view");
        assert_eq!(refused.name(), "NoXmlView");
    }
}
