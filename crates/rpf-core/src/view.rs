//! Which form of an entry a caller reads and writes: its own bytes, or an XML view of them.

use std::{
    borrow::Cow,
    io::{Read, Seek, Write as _},
    sync::Arc,
};

use flate2::{Compression, write::DeflateEncoder};

use crate::{
    archive::{Archive, Classification},
    build::ResourceFlags,
    entry::EntryKind,
    error::{Error, NoWrite, Result},
    format::{
        Version,
        crypto::{Cipher, Sealer},
        resource::{MAGIC_RSC7, RESOURCE_HEADER_LENS, resource_len, size_from_flags},
        rpf7, u32_at,
    },
    metadata::{Encoding, hash::Dictionary, view as convert},
};

/// Which form of an entry a caller is asking for, and the wire spelling of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum View {
    /// The entry's own bytes, whatever they are.
    #[default]
    Raw,
    /// The XML view. An entry that has none is refused.
    Xml,
    /// The XML view where the entry has one, its own bytes where it has not.
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

/// What a caller wants of an entry: which form, and how its hashes are spelled.
#[derive(Debug, Clone, Copy)]
pub struct Wanted<'a> {
    /// Which form of the entry.
    pub view: View,
    /// How a `PSO`'s hashes are spelled in it.
    pub names: &'a Dictionary,
}

/// What the entry holds, and so whether it has a view; a resource is not an encoding.
#[derive(Debug, Clone)]
pub enum Held {
    /// Nothing recognised — unknown binary — or there is no entry at all.
    Nothing,
    /// A binary entry whose payload announces an encoding.
    Encoded(Encoding),
    /// A resource entry: its flag words, and its transform where an archive can answer it.
    Resource(Resource),
}

/// A resource entry's seam: the row's flag words, and the archive's transform in both directions.
#[derive(Debug, Clone)]
pub struct Resource {
    flags: ResourceFlags,
    cipher: Option<Cipher>,
    /// What mints its inverse, if this build runs the transform forwards; the NG key waits on it.
    sealer: Option<Arc<Sealer>>,
    /// The entry's own name, half of what a key is chosen by, empty where there is none to key.
    name: String,
    /// The archive's encryption tag, which that refusal names.
    tag: u32,
    /// The archive's version, which derives a payload's keying length from its own.
    version: Version,
}

impl Resource {
    /// A resource described by its row alone, with no archive behind it.
    #[must_use]
    pub const fn in_the_clear(flags: ResourceFlags) -> Self {
        Self {
            flags,
            cipher: None,
            sealer: None,
            name: String::new(),
            tag: rpf7::ENCRYPTION_OPEN,
            // Nothing is keyed under it, so this version is never consulted.
            version: Version::Rpf7,
        }
    }

    /// The two flag words the entry's row declares.
    #[must_use]
    pub const fn flags(&self) -> ResourceFlags {
        self.flags
    }

    /// Puts a payload back under the archive's transform from `from`, keyed by its whole length.
    fn seal_from(&self, payload: &mut [u8], from: usize, sealed: bool) -> Result<()> {
        if !sealed {
            return Ok(());
        }
        let no_inverse = || Error::CannotWriteEncrypted {
            tag: self.tag,
            reason: NoWrite::NoInverse,
        };
        let forward = self.sealer.as_ref().ok_or_else(no_inverse)?;
        let len = self
            .version
            .resource_key_len(u64::try_from(payload.len()).unwrap_or(u64::MAX));
        let seal = forward.seal(&self.name, len).ok_or_else(no_inverse)?;
        seal.apply(payload.get_mut(from..).unwrap_or_default());
        Ok(())
    }
}

impl From<Option<Encoding>> for Held {
    fn from(encoding: Option<Encoding>) -> Self {
        encoding.map_or(Self::Nothing, Self::Encoded)
    }
}

impl From<Encoding> for Held {
    fn from(encoding: Encoding) -> Self {
        Self::Encoded(encoding)
    }
}

impl From<ResourceFlags> for Held {
    fn from(flags: ResourceFlags) -> Self {
        Self::Resource(Resource::in_the_clear(flags))
    }
}

impl From<Resource> for Held {
    fn from(resource: Resource) -> Self {
        Self::Resource(resource)
    }
}

impl Held {
    /// What the payload announces on a listing row; `None` for a resource, unread by a listing.
    #[must_use]
    pub const fn encoding(&self) -> Option<Encoding> {
        match *self {
            Self::Encoded(encoding) => Some(encoding),
            Self::Nothing | Self::Resource(_) => None,
        }
    }
}

fn system_len(flags: ResourceFlags) -> usize {
    usize::try_from(size_from_flags(flags.system)).unwrap_or(usize::MAX)
}

struct InHand<'a> {
    prefix: &'a [u8],
    contents: Vec<u8>,
    sealed: bool,
}

/// A payload's inflated contents if these bytes are one, found by the offset that inflates to it.
fn contents_of<'a>(payload: &'a [u8], resource: &Resource) -> Option<InHand<'a>> {
    let flags = resource.flags;
    if payload.get(..MAGIC_RSC7.len()) == Some(&MAGIC_RSC7[..])
        && (u32_at(payload, 8) != Some(flags.system) || u32_at(payload, 12) != Some(flags.graphics))
    {
        return None;
    }
    let expected = usize::try_from(resource_len(flags.system, flags.graphics)).ok()?;
    let bound = u64::try_from(expected).ok()?.saturating_add(1);
    for cipher in std::iter::once(None).chain(resource.cipher.as_ref().map(Some)) {
        for header in RESOURCE_HEADER_LENS {
            let at = usize::try_from(header).unwrap_or(usize::MAX);
            let Some(stream) = payload.get(at..) else {
                continue;
            };
            let stream = match cipher {
                None => Cow::Borrowed(stream),
                Some(cipher) => {
                    let mut deciphered = stream.to_vec();
                    cipher.apply(&mut deciphered);
                    Cow::Owned(deciphered)
                }
            };
            let mut contents = Vec::new();
            let read = flate2::read::DeflateDecoder::new(stream.as_ref())
                .take(bound)
                .read_to_end(&mut contents);
            if read.is_ok() && contents.len() == expected {
                return Some(InHand {
                    prefix: payload.get(..at).unwrap_or_default(),
                    contents,
                    sealed: cipher.is_some(),
                });
            }
        }
    }
    None
}

/// The payload edited contents become: the original opaque prefix, then the contents deflated.
fn exported(prefix: &[u8], contents: &[u8]) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(contents.len());
    payload.extend_from_slice(prefix);
    let mut encoder = DeflateEncoder::new(payload, Compression::default());
    encoder
        .write_all(contents)
        .map_err(|source| Error::Io { offset: 0, source })?;
    encoder
        .finish()
        .map_err(|source| Error::Io { offset: 0, source })
}

fn announces_xml(offered: &[u8]) -> bool {
    Encoding::of(offered.get(..Encoding::HEAD_LEN).unwrap_or(offered)) == Some(Encoding::Xml)
}

fn held_by<R: Read + Seek>(src: &mut R, archive: &Archive, index: u32, path: &str) -> Result<Held> {
    match archive.classify(src, index)? {
        Classification::Directory => Err(Error::WrongKind {
            path: path.to_owned(),
            found: "directory",
            wanted: "file",
        }),
        Classification::Encoded(encoding) => Ok(Held::Encoded(encoding)),
        Classification::Binary => Ok(Held::Nothing),
        Classification::Resource => resource_at(archive, index, None),
    }
}

/// What the resource entry holds: its flags and transform for `in_hand` bytes or its own.
fn resource_at(archive: &Archive, index: u32, in_hand: Option<u64>) -> Result<Held> {
    let EntryKind::Resource {
        system_flags,
        graphics_flags,
        ..
    } = archive.entry(index)?.kind
    else {
        return Ok(Held::Nothing);
    };
    let (cipher, sealer) = archive.resource_transform(index, in_hand)?;
    Ok(Held::Resource(Resource {
        flags: ResourceFlags {
            system: system_flags,
            graphics: graphics_flags,
        },
        cipher,
        sealer,
        name: archive.name(index)?.to_owned(),
        tag: archive.encryption_tag(),
        version: archive.version(),
    }))
}

/// What the entry at `index` holds, for a payload the caller has **in hand**, not the archive's.
/// # Errors
/// As `Archive::classify`.
pub fn held_in_hand<R: Read + Seek>(
    src: &mut R,
    archive: &Archive,
    index: u32,
    payload: &[u8],
) -> Result<Held> {
    match archive.classify(src, index)? {
        Classification::Directory => Ok(Held::Nothing),
        Classification::Encoded(_) | Classification::Binary => Ok(Held::from(Encoding::of(
            payload.get(..Encoding::HEAD_LEN).unwrap_or(payload),
        ))),
        Classification::Resource => resource_at(
            archive,
            index,
            Some(payload.len().try_into().unwrap_or(u64::MAX)),
        ),
    }
}

fn contents_at<R: Read + Seek>(src: &mut R, archive: &Archive, index: u32) -> Option<Vec<u8>> {
    archive.read(src, index).ok()
}

/// An entry's bytes, in the form that was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Viewed {
    /// The bytes.
    pub bytes: Vec<u8>,
    /// Whether they are the XML view rather than the entry's own payload.
    pub xml: bool,
    /// What the payload announces, or `None` for a resource, a directory, or nothing recognised.
    pub encoding: Option<Encoding>,
}

/// Reads one entry in the form `view` asks for, naming `path` in a refusal.
/// # Errors
/// `Error::NoXmlView` for an entry with no view, `Error::WrongKind` for a directory.
pub fn read<R: Read + Seek>(
    src: &mut R,
    archive: &Archive,
    index: u32,
    path: &str,
    wanted: Wanted<'_>,
) -> Result<Viewed> {
    let held = held_by(src, archive, index, path)?;
    // A `Meta` lives in the inflated contents; a converted read falls back otherwise.
    if wanted.view != View::Raw
        && let Held::Resource(ref resource) = held
    {
        let converted = match contents_at(src, archive, index) {
            Some(contents) => {
                convert::resource_to_xml(&contents, system_len(resource.flags), wanted.names)?
            }
            None => None,
        };
        if let Some(document) = converted {
            return Ok(Viewed {
                bytes: document,
                xml: true,
                encoding: None,
            });
        }
        return match wanted.view {
            View::Xml => Err(Error::NoXmlView {
                path: path.to_owned(),
                held: None,
            }),
            View::Raw | View::Auto => Ok(Viewed {
                bytes: archive.extract(src, index)?,
                xml: false,
                encoding: None,
            }),
        };
    }
    let bytes = archive.extract(src, index)?;
    of(bytes, held, path, wanted)
}

/// The same decision over a payload already in hand, which is what a buffered write asks of it.
/// # Errors
/// As `read`, less the directory case, which a payload cannot be.
pub fn of(
    payload: Vec<u8>,
    held: impl Into<Held>,
    path: &str,
    wanted: Wanted<'_>,
) -> Result<Viewed> {
    let held = held.into();
    let encoding = held.encoding();
    let raw = |bytes: Vec<u8>| Viewed {
        bytes,
        xml: false,
        encoding,
    };
    if wanted.view == View::Raw {
        return Ok(raw(payload));
    }
    // A resource's payload is never sniffed: the bytes decide only what is inside its framing.
    let converted = match held {
        Held::Nothing => None,
        Held::Encoded(_) => convert::to_xml(&payload, wanted.names)?,
        Held::Resource(ref resource) => match contents_of(&payload, resource) {
            Some(held) => {
                convert::resource_to_xml(&held.contents, system_len(resource.flags), wanted.names)?
            }
            None => None,
        },
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

/// The payload to write into an entry; a resource takes no document, having no encoding to edit.
/// # Errors
/// `Error::NoXmlView` for an entry with no view, or a `Not*Xml` variant for a bad document.
pub fn applied(
    payload: &[u8],
    held: impl Into<Held>,
    path: &str,
    wanted: Wanted<'_>,
    offered: Vec<u8>,
) -> Result<Vec<u8>> {
    let held = held.into();
    let no_view = || Error::NoXmlView {
        path: path.to_owned(),
        held: held.encoding(),
    };
    match wanted.view {
        View::Raw => Ok(offered),
        View::Xml => match converted(payload, &held, wanted, &offered)? {
            Applied::Payload(payload) => Ok(payload),
            Applied::NoView | Applied::Resource => Err(no_view()),
        },
        View::Auto => {
            if !announces_xml(&offered) {
                return Ok(offered);
            }
            match converted(payload, &held, wanted, &offered)? {
                Applied::Payload(payload) => Ok(payload),
                // No view: the document is bytes like any other, judged by `edit::check_encoding`.
                Applied::NoView => Ok(offered),
                // A resource: the document would otherwise be written in as the payload itself.
                Applied::Resource => Err(no_view()),
            }
        }
    }
}

/// What a document became; three answers, not an `Option`, since `Auto` treats them differently.
enum Applied {
    Payload(Vec<u8>),
    NoView,
    /// A resource whose document did not become its payload — a refusal, never a fallback.
    Resource,
}

/// The payload a document becomes: the write-side dispatch so `applied`'s two arms cannot disagree.
fn converted(payload: &[u8], held: &Held, wanted: Wanted<'_>, offered: &[u8]) -> Result<Applied> {
    Ok(match *held {
        Held::Nothing => Applied::NoView,
        Held::Encoded(_) => convert::from_xml(payload, offered, wanted.names)?
            .map_or(Applied::NoView, Applied::Payload),
        Held::Resource(ref resource) => {
            let Some(held) = contents_of(payload, resource) else {
                return Ok(Applied::Resource);
            };
            match convert::resource_from_xml(
                &held.contents,
                system_len(resource.flags),
                offered,
                wanted.names,
            )? {
                Some(edited) => {
                    let mut payload = exported(held.prefix, &edited)?;
                    resource.seal_from(&mut payload, held.prefix.len(), held.sealed)?;
                    Applied::Payload(payload)
                }
                // It came apart and is not a `Meta`, so there is no view.
                None => Applied::Resource,
            }
        }
    })
}

/// The same, reading the payload the entry holds now; a `PSO` write is an edit off the open handle.
/// # Errors
/// As `applied`, plus `Error::WrongKind` for a directory.
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
    let held = held_by(src, archive, index, path)?;
    match held {
        // Nothing for a document to be applied to, so the payload is neither read nor sniffed.
        Held::Nothing => applied(&[], held, path, wanted, offered),
        Held::Encoded(_) => {
            let payload = archive.extract(src, index)?;
            applied(&payload, held, path, wanted, offered)
        }
        Held::Resource(ref resource) => {
            // `auto` over bytes that are not a document inflates nothing at all.
            if wanted.view == View::Auto && !announces_xml(&offered) {
                return Ok(offered);
            }
            // A payload that will not come apart is a refusal even under `auto`'s usual fallback.
            let Ok(unframed) = archive.resource_unframed(src, index) else {
                return Err(Error::NoXmlView {
                    path: path.to_owned(),
                    held: None,
                });
            };
            match convert::resource_from_xml(
                &unframed.contents,
                system_len(resource.flags),
                &offered,
                wanted.names,
            )? {
                Some(edited) => {
                    let mut payload = exported(&unframed.prefix, &edited)?;
                    resource.seal_from(&mut payload, unframed.prefix.len(), unframed.sealed)?;
                    Ok(payload)
                }
                None => Err(Error::NoXmlView {
                    path: path.to_owned(),
                    held: None,
                }),
            }
        }
    }
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

    /// The flag words of a one-page resource: 512 bytes of system and no graphics.
    const FLAGS: ResourceFlags = ResourceFlags {
        system: 0xA800_0000,
        graphics: 0x2000_0000,
    };

    #[test]
    fn an_option_of_an_encoding_is_what_it_always_was() {
        assert!(matches!(Held::from(None), Held::Nothing));
        assert!(matches!(
            Held::from(Some(Encoding::Rbf)),
            Held::Encoded(Encoding::Rbf)
        ));
        assert_eq!(Held::Nothing.encoding(), None);
        assert_eq!(Held::Encoded(Encoding::Pso).encoding(), Some(Encoding::Pso));
        assert_eq!(Held::from(FLAGS).encoding(), None);
    }

    #[test]
    fn a_resource_payload_in_hand_is_unframed_by_its_own_boundary_or_has_no_view() {
        let contents = vec![0x5A_u8; 512];
        let prefix = [0xFF_u8; 24];
        let payload = exported(&prefix, &contents).expect("frames");
        assert_eq!(payload.get(..prefix.len()), Some(&prefix[..]));
        let held = contents_of(&payload, &Resource::in_the_clear(FLAGS)).expect("unframes");
        assert_eq!(held.contents, contents);
        assert_eq!(held.prefix, &prefix[..]);
        assert!(
            contents_of(
                &payload,
                &Resource::in_the_clear(ResourceFlags {
                    system: 0xA800_0001,
                    graphics: 0x2000_0000
                })
            )
            .is_none()
        );
        assert!(contents_of(&[0xFF_u8; 64], &Resource::in_the_clear(FLAGS)).is_none());

        let names = Dictionary::default();
        let refused = of(
            payload.clone(),
            Held::from(FLAGS),
            "art.ydr",
            Wanted {
                view: View::Xml,
                names: &names,
            },
        )
        .expect_err("a resource that is not a Meta has no view");
        assert_eq!(refused.name(), "NoXmlView");
        let viewed = of(
            payload.clone(),
            Held::from(FLAGS),
            "art.ydr",
            Wanted {
                view: View::Auto,
                names: &names,
            },
        )
        .expect("auto falls back");
        assert!(!viewed.xml);
        assert_eq!(viewed.bytes, payload);
        assert_eq!(viewed.encoding, None);
        let document = b"<?xml version=\"1.0\"?><a/>".to_vec();
        assert_eq!(
            applied(
                &payload,
                Held::from(FLAGS),
                "art.ydr",
                Wanted {
                    view: View::Auto,
                    names: &names
                },
                document.clone()
            )
            .expect_err("a resource takes no document")
            .name(),
            "NoXmlView"
        );
        let bytes = b"\x00\x01\x02 not a document".to_vec();
        assert_eq!(
            applied(
                &payload,
                Held::from(FLAGS),
                "art.ydr",
                Wanted {
                    view: View::Auto,
                    names: &names
                },
                bytes.clone()
            )
            .expect("auto takes bytes that are not a document"),
            bytes
        );
        assert_eq!(
            applied(
                &payload,
                Held::from(FLAGS),
                "art.ydr",
                Wanted {
                    view: View::Xml,
                    names: &names
                },
                document
            )
            .expect_err("no view")
            .name(),
            "NoXmlView"
        );
    }

    #[test]
    fn a_resource_is_not_sniffed_even_when_its_bytes_would_name_something() {
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
        let names = Dictionary::default();
        let offered = vec![0x00, 0x01, 0x02, 0x03];
        assert_eq!(
            applied(
                b"RBF0\x00\x00\x00\x00",
                Some(Encoding::Rbf),
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
    fn auto_converts_recognised_xml_against_an_entry_that_has_a_view() {
        let names = Dictionary::default();
        let offered = b"<root></root>".to_vec();
        let converted = applied(
            b"RBF0\x00\x00\x00\x00",
            Some(Encoding::Rbf),
            "x.ymt",
            Wanted {
                view: View::Auto,
                names: &names,
            },
            offered.clone(),
        )
        .expect("auto converts a document its entry's encoding reads");
        assert_ne!(
            converted, offered,
            "the offered xml passed through unconverted"
        );
    }

    #[test]
    fn an_xml_write_into_an_entry_with_no_view_is_refused() {
        let names = Dictionary::default();
        let refused = applied(
            b"Version 1\r\nabcdef",
            Some(Encoding::Text),
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

    #[test]
    fn a_payload_the_entry_gives_no_encoding_is_not_sniffed_for_one() {
        let names = Dictionary::default();
        let document = b"<?xml version=\"1.0\"?><a/>".to_vec();
        let held = b"RBF0\x00\x00\x00\x00";
        assert_eq!(
            applied(
                held,
                None,
                "x.ytyp",
                Wanted {
                    view: View::Auto,
                    names: &names
                },
                document.clone()
            )
            .expect("auto takes what it cannot convert"),
            document,
            "a document was converted against an entry with no encoding"
        );
        let refused = applied(
            held,
            None,
            "x.ytyp",
            Wanted {
                view: View::Xml,
                names: &names,
            },
            document,
        )
        .expect_err("an entry with no encoding has no view");
        assert_eq!(refused.name(), "NoXmlView");
    }

    /// A converted write of a resource, archive to disk, keyed by thirty-two zero bytes.
    mod converted {
        use std::{io::Cursor, sync::Arc};

        use super::*;
        use crate::{
            archive::Archive,
            build::{FileKind, FileSpec, Under, build_under, entry_name},
            edit::{Bytes, Change, Changes},
            format::{
                Version,
                crypto::{Cipher, Seal, Sealer, synthetic},
                rpf7,
            },
            keys::{Material, Unlock},
            scratch::InMemory,
            watch::Unwatched,
        };

        const AT: &str = "data/thing.ymt";

        /// The sixteen opaque bytes in front of the fixture's deflate stream.
        const PREFIX: [u8; 16] = [0xFF; 16];

        /// The document `meta_page` converts to, and the same with its one value edited.
        const DOCUMENT: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                                <hash_D98BB561 meta:struct=\"hash_D98BB561\">\n  \
                                <hash_12345678 meta:uint=\"7\"/>\n\
                                </hash_D98BB561>\n";
        const EDITED: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                              <hash_D98BB561 meta:struct=\"hash_D98BB561\">\n  \
                              <hash_12345678 meta:uint=\"9\"/>\n\
                              </hash_D98BB561>\n";

        /// A system-space `Meta` pointer at `offset`.
        fn pointer(offset: u32) -> u64 {
            (5_u64 << 28) | u64::from(offset)
        }

        /// The smallest `Meta` that reaches a value, in one 512-byte system page, built by hand.
        fn meta_page() -> Vec<u8> {
            let mut page = vec![0_u8; 512];
            let mut put = |at: usize, bytes: &[u8]| {
                page[at..at.saturating_add(bytes.len())].copy_from_slice(bytes);
            };
            put(0x00, &0xDEAD_BEEF_u32.to_le_bytes());
            put(0x04, &1_u32.to_le_bytes());
            put(0x10, &crate::metadata::meta::MAGIC.to_le_bytes());
            put(0x14, &crate::metadata::meta::VERSION_TWO.to_le_bytes());
            put(0x1C, &1_u32.to_le_bytes());
            put(0x20, &pointer(0x50).to_le_bytes());
            put(0x30, &pointer(0xA0).to_le_bytes());
            put(0x48, &1_u16.to_le_bytes());
            put(0x4C, &1_u16.to_le_bytes());
            put(0x50, &0xD98B_B561_u32.to_le_bytes());
            put(0x54, &0xD98B_B561_u32.to_le_bytes());
            put(0x58, &0x300_u32.to_le_bytes());
            put(0x60, &pointer(0x70).to_le_bytes());
            put(0x68, &4_u32.to_le_bytes());
            put(0x6E, &1_u16.to_le_bytes());
            put(0x70, &0x1234_5678_u32.to_le_bytes());
            put(0x74, &0_u32.to_le_bytes());
            put(0x78, &[0x15, 0x00]);
            put(0xA0, &0xD98B_B561_u32.to_le_bytes());
            put(0xA4, &4_u32.to_le_bytes());
            put(0xA8, &pointer(0xB0).to_le_bytes());
            put(0xB0, &7_u32.to_le_bytes());
            page
        }

        fn deflated(contents: &[u8]) -> Vec<u8> {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(contents).expect("the page deflates");
            encoder.finish().expect("the encoder finishes")
        }

        /// The zero-key AES transform, one seal off it, and the `Unlock` that opens what it wrote.
        fn zeroed(named: &str) -> (Sealer, Seal, Unlock) {
            let material = Arc::new(Material::over_zeros());
            let scheme = Version::Rpf7.scheme(rpf7::ENCRYPTION_AES).expect("AES");
            let sealer = Sealer::new(scheme, &material).expect("AES seals");
            let seal = sealer.seal(named, 0).expect("AES seals");
            (sealer, seal, Unlock::held(material, named))
        }

        /// An AES-sealed archive with one resource under its transform, and its payload on disk.
        fn sealed_archive() -> (Vec<u8>, Unlock, Vec<u8>) {
            sealed_archive_behind(&PREFIX, 0)
        }

        /// The same behind any prefix, sealed from `from`; only 24 bytes sees the stream start.
        fn sealed_archive_behind(prefix: &[u8], from: usize) -> (Vec<u8>, Unlock, Vec<u8>) {
            let (sealer, seal, unlock) = zeroed("meta.rpf");
            let mut payload = prefix.to_vec();
            payload.extend_from_slice(&deflated(&meta_page()));
            seal.apply(payload.get_mut(from..).expect("the stream is there"));
            let held = payload.clone();
            let mut out = Cursor::new(Vec::new());
            build_under(
                &mut out,
                Under::sealed(Version::Rpf7, rpf7::ENCRYPTION_AES, &sealer, "meta.rpf"),
                &[FileSpec {
                    path: AT.to_owned(),
                    kind: FileKind::Resource {
                        declared: Some(FLAGS),
                    },
                }],
                &[],
                |_: &str| Ok(Cursor::new(held.clone())),
                &mut Unwatched,
            )
            .expect("the sealed archive builds");
            (out.into_inner(), unlock, payload)
        }

        /// The synthetic NG forward transform, and the `Unlock` that opens what it wrote.
        fn ng_zeroed(named: &str) -> (Sealer, Unlock) {
            let material = Arc::new(synthetic::ng_material(0x0DE1_2A55));
            let scheme = Version::Rpf7.scheme(rpf7::ENCRYPTION_NG).expect("NG");
            let sealer = Sealer::new(scheme, &material).expect("synthetic tables derive");
            (sealer, Unlock::held(material, named))
        }

        /// An NG-sealed archive with one resource under its transform, its opener, and its payload.
        fn ng_sealed_archive() -> (Vec<u8>, Unlock, Vec<u8>) {
            let (sealer, unlock) = ng_zeroed("meta.rpf");
            let mut payload = PREFIX.to_vec();
            payload.extend_from_slice(&deflated(&meta_page()));
            let len = u64::try_from(payload.len()).expect("a payload this size");
            sealer
                .seal(entry_name(AT), len)
                .expect("the synthetic material holds every key")
                .apply(&mut payload);
            let held = payload.clone();
            let mut out = Cursor::new(Vec::new());
            build_under(
                &mut out,
                Under::sealed(Version::Rpf7, rpf7::ENCRYPTION_NG, &sealer, "meta.rpf"),
                &[FileSpec {
                    path: AT.to_owned(),
                    kind: FileKind::Resource {
                        declared: Some(FLAGS),
                    },
                }],
                &[],
                |_: &str| Ok(Cursor::new(held.clone())),
                &mut Unwatched,
            )
            .expect("the NG archive builds");
            (out.into_inner(), unlock, payload)
        }

        /// The same document with a value that deflates differently, moving the NG sealing key.
        const WIDENED: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                               <hash_D98BB561 meta:struct=\"hash_D98BB561\">\n  \
                               <hash_12345678 meta:uint=\"123456789\"/>\n\
                               </hash_D98BB561>\n";

        /// `meta_page` with its one value edited, which is what `WIDENED` applies.
        fn widened_page() -> Vec<u8> {
            let mut page = meta_page();
            page[0xB0..0xB4].copy_from_slice(&123_456_789_u32.to_le_bytes());
            page
        }

        #[test]
        fn a_converted_write_into_an_ng_archive_is_keyed_for_the_bytes_it_seals() {
            // An NG key is a function of length, so an old-length seal picks the old key.
            let (bytes, unlock, on_disk) = ng_sealed_archive();
            let mut src = Cursor::new(bytes);
            let archive = Archive::open(&mut src, &unlock).expect("the NG archive opens");
            let index = archive.find(AT).expect("the entry is there");
            assert_eq!(
                archive.read(&mut src, index).expect("reads"),
                meta_page(),
                "the fixture does not read back at all"
            );
            for header in [16_usize, 24] {
                assert_ne!(
                    inflated(on_disk.get(header..).unwrap_or_default()).len(),
                    512,
                    "the fixture's payload inflates in the clear, so it is not keyed"
                );
            }

            let names = Dictionary::default();
            let converted = apply(
                &mut src,
                &archive,
                index,
                AT,
                Wanted {
                    view: View::Xml,
                    names: &names,
                },
                WIDENED.as_bytes().to_vec(),
            )
            .expect("the document applies");

            let (sealer, _) = ng_zeroed("meta.rpf");
            let key_for = |len: usize| {
                sealer
                    .seal(entry_name(AT), u64::try_from(len).expect("a length"))
                    .and_then(|seal| seal.key_index())
            };
            assert_ne!(
                converted.len(),
                on_disk.len(),
                "the edited payload is the same length, so this test proves nothing"
            );
            assert_ne!(
                key_for(converted.len()),
                key_for(on_disk.len()),
                "the two lengths chose the same key, so this test proves nothing"
            );

            let changes = Changes::one(
                AT,
                Change::Write {
                    contents: Arc::new(Bytes::new(converted)),
                    create: false,
                    allow_encoding_change: false,
                },
            );
            let mut out = Cursor::new(Vec::new());
            crate::rewrite(
                &mut src,
                &archive,
                &changes,
                &mut out,
                &mut InMemory,
                &mut Unwatched,
            )
            .expect("the archive rebuilds");

            let mut back = Cursor::new(out.into_inner());
            let archive = Archive::open(&mut back, &unlock).expect("the rebuilt archive opens");
            let index = archive.find(AT).expect("the entry is still there");
            assert_eq!(
                archive.read(&mut back, index).expect("the entry loads"),
                widened_page(),
                "the entry does not read back under the key its new length chose"
            );
        }

        /// The largest value the 24-bit compressed-size field holds, the sentinel past that.
        const SATURATED: usize = 0x00FF_FFFF;

        /// Past the field and **not** a whole block, so the recovered room exceeds the payload.
        const PAST_THE_FIELD: usize = 17_828_618;

        /// Where the saturated resource sits: the root, so the next entry is the next payload.
        const BIG: &str = "big.ymt";

        /// An NG archive with a `len`-byte resource sealed as `seal_from` does, plus a second file.
        fn ng_saturated_archive(len: usize) -> (Vec<u8>, Unlock) {
            let (sealer, unlock) = ng_zeroed("meta.rpf");
            let mut payload = PREFIX.to_vec();
            payload.extend_from_slice(&deflated(&meta_page()));
            assert!(payload.len() <= len, "the fixture's stream fits in {len}");
            payload.resize(len, 0);
            let resource = Resource {
                flags: FLAGS,
                cipher: None,
                sealer: Some(Arc::new(sealer)),
                name: entry_name(BIG).to_owned(),
                tag: rpf7::ENCRYPTION_NG,
                version: Version::Rpf7,
            };
            resource
                .seal_from(&mut payload, PREFIX.len(), true)
                .expect("the synthetic material seals");

            let (sealer, _) = ng_zeroed("meta.rpf");
            let mut out = Cursor::new(Vec::new());
            build_under(
                &mut out,
                Under::sealed(Version::Rpf7, rpf7::ENCRYPTION_NG, &sealer, "meta.rpf"),
                &[
                    FileSpec {
                        path: BIG.to_owned(),
                        kind: FileKind::Resource {
                            declared: Some(FLAGS),
                        },
                    },
                    FileSpec {
                        path: "z.bin".to_owned(),
                        kind: FileKind::Binary {
                            storage: crate::build::Storage::Stored,
                            encryption: rpf7::ENTRY_OPEN,
                        },
                    },
                ],
                &[],
                |path: &str| {
                    Ok(Cursor::new(if path == BIG {
                        payload.clone()
                    } else {
                        b"after".to_vec()
                    }))
                },
                &mut Unwatched,
            )
            .expect("the NG archive builds");
            (out.into_inner(), unlock)
        }

        fn saturated_reads_back(len: usize, room: u64) {
            let (bytes, unlock) = ng_saturated_archive(len);
            let mut src = Cursor::new(bytes);
            let archive = Archive::open(&mut src, &unlock).expect("the NG archive opens");
            let index = archive.find(BIG).expect("the entry is there");

            let crate::entry::EntryKind::Resource { compressed_len, .. } =
                archive.entry(index).expect("an entry").kind
            else {
                panic!("the fixture's entry is not a resource");
            };
            assert_eq!(
                u64::from(compressed_len),
                SATURATED as u64,
                "the fixture's row does not carry the sentinel, so it is not the case this test is about"
            );
            assert_eq!(
                archive.payload_at(index).expect("a span").1,
                room,
                "the reader recovered another extent than this test reasons about"
            );
            assert_eq!(
                archive.read(&mut src, index).expect("the entry loads"),
                meta_page(),
                "the entry does not read back under the key the reader chooses"
            );
        }

        #[test]
        fn a_saturated_resource_is_sealed_under_the_key_the_reader_will_choose() {
            let room = (PAST_THE_FIELD as u64).next_multiple_of(512);
            assert_ne!(
                room, PAST_THE_FIELD as u64,
                "an aligned payload would prove nothing"
            );

            let (sealer, _) = ng_zeroed("meta.rpf");
            let key_for = |len: u64| {
                sealer
                    .seal(entry_name(BIG), len)
                    .and_then(|seal| seal.key_index())
            };
            assert_ne!(
                key_for(PAST_THE_FIELD as u64),
                key_for(room),
                "the payload's length and its room chose the same key, so this test proves nothing"
            );

            saturated_reads_back(PAST_THE_FIELD, room);
        }

        #[test]
        fn a_resource_payload_of_exactly_the_field_is_keyed_as_the_sentinel_it_reads_back_as() {
            // The field's largest value is indistinct from the sentinel, so it saturates at `>=`.
            let room = (SATURATED as u64).next_multiple_of(512);
            assert_ne!(room, SATURATED as u64, "the field's value is not aligned");
            saturated_reads_back(SATURATED, room);
        }

        #[test]
        fn a_resource_payload_one_past_the_field_is_keyed_by_the_room_it_exactly_fills() {
            // 16,777,216 is a whole number of blocks, so the room and the payload share a length.
            let room = (SATURATED as u64).saturating_add(1);
            assert_eq!(room % 512, 0, "one past the field is a whole block");
            saturated_reads_back(SATURATED + 1, room);
        }

        fn inflated(stream: &[u8]) -> Vec<u8> {
            let mut contents = Vec::new();
            flate2::read::DeflateDecoder::new(stream)
                .take(4096)
                .read_to_end(&mut contents)
                .ok();
            contents
        }

        fn payload_of(bytes: Vec<u8>, unlock: &Unlock) -> (Vec<u8>, crate::entry::EntryKind) {
            let mut src = Cursor::new(bytes);
            let archive = Archive::open(&mut src, unlock).expect("opens");
            let index = archive.find(AT).expect("the entry is there");
            let payload = archive.extract(&mut src, index).expect("extracts");
            let kind = archive.entry(index).expect("the entry").kind;
            (payload, kind)
        }

        #[test]
        fn a_converted_write_into_a_sealed_archive_lands_as_ciphertext() {
            // `build::is_sealed` answers `false` for every resource, so an unsealed write is plain.
            let (bytes, unlock, on_disk) = sealed_archive();

            let mut src = Cursor::new(bytes.clone());
            let archive = Archive::open(&mut src, &unlock).expect("opens");
            let index = archive.find(AT).expect("the entry is there");
            assert_eq!(
                archive.read(&mut src, index).expect("reads"),
                meta_page(),
                "the fixture does not read back at all"
            );
            for header in [16_usize, 24] {
                assert_ne!(
                    inflated(on_disk.get(header..).unwrap_or_default()).len(),
                    512,
                    "the fixture's payload inflates in the clear, so it is not keyed"
                );
            }

            let names = Dictionary::default();
            let converted = apply(
                &mut src,
                &archive,
                index,
                AT,
                Wanted {
                    view: View::Xml,
                    names: &names,
                },
                EDITED.as_bytes().to_vec(),
            )
            .expect("the document applies");

            let changes = Changes::one(
                AT,
                Change::Write {
                    contents: Arc::new(Bytes::new(converted)),
                    create: false,
                    allow_encoding_change: false,
                },
            );
            let mut out = Cursor::new(Vec::new());
            crate::rewrite(
                &mut src,
                &archive,
                &changes,
                &mut out,
                &mut InMemory,
                &mut Unwatched,
            )
            .expect("the archive rebuilds");

            let (written, kind) = payload_of(out.into_inner(), &unlock);
            for header in [16_usize, 24] {
                assert_ne!(
                    inflated(written.get(header..).unwrap_or_default()).len(),
                    512,
                    "a converted write landed in the clear inside a sealed archive"
                );
            }
            let mut decrypted = written.clone();
            Cipher::over_zeros().apply(&mut decrypted);
            let contents = inflated(decrypted.get(PREFIX.len()..).unwrap_or_default());
            assert_eq!(
                contents.len(),
                512,
                "the written payload does not inflate under the entry's own transform"
            );
            let edited = convert::resource_to_xml(&contents, system_len(FLAGS), &names)
                .expect("converts")
                .expect("a Meta");
            assert_eq!(
                String::from_utf8_lossy(&edited),
                EDITED,
                "the edit did not land"
            );
            match kind {
                crate::entry::EntryKind::Resource {
                    system_flags,
                    graphics_flags,
                    ..
                } => {
                    assert_eq!(system_flags, FLAGS.system);
                    assert_eq!(graphics_flags, FLAGS.graphics);
                }
                other => panic!("the entry stopped being a resource: {other:?}"),
            }
        }

        /// The 24-byte prefix, the only one that can see where sealing starts.
        const WIDE_PREFIX: [u8; 24] = [0xFF; 24];

        #[test]
        fn a_converted_write_behind_a_wide_prefix_seals_from_the_streams_own_start() {
            // A 16-byte prefix is the cipher's block, so the two starts agree; at 24 they differ.
            let (bytes, unlock, on_disk) = sealed_archive_behind(&WIDE_PREFIX, WIDE_PREFIX.len());
            let mut src = Cursor::new(bytes);
            let archive = Archive::open(&mut src, &unlock).expect("opens");
            let index = archive.find(AT).expect("the entry is there");
            assert_eq!(
                archive.read(&mut src, index).expect("reads"),
                meta_page(),
                "the fixture does not read back at all"
            );
            for header in [16_usize, 24] {
                assert_ne!(
                    inflated(on_disk.get(header..).unwrap_or_default()).len(),
                    512,
                    "the fixture's payload inflates in the clear, so it is not keyed"
                );
            }

            let names = Dictionary::default();
            let converted = apply(
                &mut src,
                &archive,
                index,
                AT,
                Wanted {
                    view: View::Xml,
                    names: &names,
                },
                EDITED.as_bytes().to_vec(),
            )
            .expect("the document applies");
            let changes = Changes::one(
                AT,
                Change::Write {
                    contents: Arc::new(Bytes::new(converted)),
                    create: false,
                    allow_encoding_change: false,
                },
            );
            let mut out = Cursor::new(Vec::new());
            crate::rewrite(
                &mut src,
                &archive,
                &changes,
                &mut out,
                &mut InMemory,
                &mut Unwatched,
            )
            .expect("the archive rebuilds");
            let written = out.into_inner();

            let (payload, _) = payload_of(written.clone(), &unlock);
            assert_eq!(
                payload.get(..WIDE_PREFIX.len()),
                on_disk.get(..WIDE_PREFIX.len()),
                "the payload's opaque prefix was rewritten"
            );
            let mut from_stream = payload
                .get(WIDE_PREFIX.len()..)
                .unwrap_or_default()
                .to_vec();
            Cipher::over_zeros().apply(&mut from_stream);
            assert_eq!(
                inflated(&from_stream).len(),
                512,
                "the written payload does not decrypt from the stream's own start"
            );
            let mut from_payload = payload.clone();
            Cipher::over_zeros().apply(&mut from_payload);
            assert_ne!(
                inflated(from_payload.get(WIDE_PREFIX.len()..).unwrap_or_default()).len(),
                512,
                "the written payload was sealed from the payload's start"
            );

            let mut back = Cursor::new(written);
            let archive = Archive::open(&mut back, &unlock).expect("reopens");
            let index = archive.find(AT).expect("the entry is there");
            let viewed = read(
                &mut back,
                &archive,
                index,
                AT,
                Wanted {
                    view: View::Xml,
                    names: &names,
                },
            )
            .expect("the written entry still has its view");
            assert_eq!(String::from_utf8_lossy(&viewed.bytes), EDITED);
        }

        #[test]
        fn a_keyed_payload_in_hand_comes_apart_and_goes_back_sealed() {
            for (prefix, from) in [(&PREFIX[..], 0), (&WIDE_PREFIX[..], 24)] {
                let (bytes, unlock, _) = sealed_archive_behind(prefix, from);
                let mut src = Cursor::new(bytes);
                let archive = Archive::open(&mut src, &unlock).expect("opens");
                let index = archive.find(AT).expect("the entry is there");
                let names = Dictionary::default();
                let wanted = |view| Wanted {
                    view,
                    names: &names,
                };

                let buffered = apply(
                    &mut src,
                    &archive,
                    index,
                    AT,
                    wanted(View::Xml),
                    EDITED.as_bytes().to_vec(),
                )
                .expect("the document applies");
                let held = held_in_hand(&mut src, &archive, index, &buffered)
                    .expect("the entry classifies");

                let viewed = of(buffered.clone(), held.clone(), AT, wanted(View::Xml))
                    .expect("a keyed buffer has a view");
                assert!(viewed.xml);
                assert_eq!(String::from_utf8_lossy(&viewed.bytes), EDITED);

                let again = applied(
                    &buffered,
                    held.clone(),
                    AT,
                    wanted(View::Auto),
                    DOCUMENT.as_bytes().to_vec(),
                )
                .expect("a keyed buffer takes a document");
                assert_ne!(again, DOCUMENT.as_bytes());
                assert_eq!(
                    again.get(..prefix.len()),
                    buffered.get(..prefix.len()),
                    "the opaque prefix was rewritten"
                );
                let mut stream = again.get(prefix.len()..).unwrap_or_default().to_vec();
                Cipher::over_zeros().apply(&mut stream);
                assert_eq!(
                    inflated(&stream).len(),
                    512,
                    "the buffer went back unsealed"
                );
                let viewed =
                    of(again, held, AT, wanted(View::Xml)).expect("and reads back once more");
                assert_eq!(String::from_utf8_lossy(&viewed.bytes), DOCUMENT);
            }
        }

        #[test]
        fn a_converted_write_keeps_the_payloads_opaque_prefix_byte_for_byte() {
            let (bytes, unlock, on_disk) = sealed_archive();
            let mut src = Cursor::new(bytes);
            let archive = Archive::open(&mut src, &unlock).expect("opens");
            let index = archive.find(AT).expect("the entry is there");
            let names = Dictionary::default();
            let converted = apply(
                &mut src,
                &archive,
                index,
                AT,
                Wanted {
                    view: View::Xml,
                    names: &names,
                },
                EDITED.as_bytes().to_vec(),
            )
            .expect("the document applies");
            assert_eq!(
                converted.get(..PREFIX.len()),
                on_disk.get(..PREFIX.len()),
                "the payload's opaque prefix was rewritten"
            );
        }

        #[test]
        fn a_payload_whose_header_contradicts_the_row_has_no_view() {
            // An `RSC7` header's words at 8 and 12 are the row's own two facts.
            let names = Dictionary::default();
            let mut payload = Vec::new();
            payload.extend_from_slice(&MAGIC_RSC7);
            payload.extend_from_slice(
                &crate::format::resource::resource_version(ELSEWHERE.system, ELSEWHERE.graphics)
                    .to_le_bytes(),
            );
            payload.extend_from_slice(&ELSEWHERE.system.to_le_bytes());
            payload.extend_from_slice(&ELSEWHERE.graphics.to_le_bytes());
            payload.extend_from_slice(&deflated(&meta_page()));
            // The two declare the same total length, so only the words themselves tell them apart.
            assert_eq!(
                crate::format::resource::resource_len(FLAGS.system, FLAGS.graphics),
                crate::format::resource::resource_len(ELSEWHERE.system, ELSEWHERE.graphics),
            );
            let refused = of(
                payload.clone(),
                Held::from(FLAGS),
                AT,
                Wanted {
                    view: View::Xml,
                    names: &names,
                },
            )
            .expect_err("the header contradicts the row");
            assert_eq!(refused.name(), "NoXmlView");
            let viewed = of(
                payload.clone(),
                Held::from(FLAGS),
                AT,
                Wanted {
                    view: View::Auto,
                    names: &names,
                },
            )
            .expect("auto falls back");
            assert!(!viewed.xml);
            assert_eq!(viewed.bytes, payload);
        }

        /// A payload with a sixteen-byte `RSC7` header declaring `header`, before `meta_page`.
        fn headed_payload(header: ResourceFlags) -> Vec<u8> {
            let mut payload = Vec::new();
            payload.extend_from_slice(&MAGIC_RSC7);
            payload.extend_from_slice(
                &crate::format::resource::resource_version(header.system, header.graphics)
                    .to_le_bytes(),
            );
            payload.extend_from_slice(&header.system.to_le_bytes());
            payload.extend_from_slice(&header.graphics.to_le_bytes());
            payload.extend_from_slice(&deflated(&meta_page()));
            payload
        }

        #[test]
        fn a_header_that_agrees_with_the_row_is_unframed_and_one_word_apart_is_not() {
            let names = Dictionary::default();
            let viewed = of(
                headed_payload(FLAGS),
                Held::from(FLAGS),
                AT,
                Wanted {
                    view: View::Xml,
                    names: &names,
                },
            )
            .expect("a header that agrees with the row is this entry's own");
            assert!(viewed.xml);
            assert_eq!(String::from_utf8_lossy(&viewed.bytes), DOCUMENT);

            for header in [
                ResourceFlags {
                    system: ELSEWHERE.system,
                    graphics: FLAGS.graphics,
                },
                ResourceFlags {
                    system: FLAGS.system,
                    graphics: ELSEWHERE.graphics,
                },
            ] {
                let refused = of(
                    headed_payload(header),
                    Held::from(FLAGS),
                    AT,
                    Wanted {
                        view: View::Xml,
                        names: &names,
                    },
                )
                .expect_err("one word apart is another entry all the same");
                assert_eq!(refused.name(), "NoXmlView");
            }
        }

        #[test]
        fn a_resource_entry_read_through_the_archive_tells_the_three_views_apart() {
            let (bytes, unlock, on_disk) = sealed_archive();
            let mut src = Cursor::new(bytes);
            let archive = Archive::open(&mut src, &unlock).expect("opens");
            let index = archive.find(AT).expect("the entry is there");
            let names = Dictionary::default();
            let read_as = |src: &mut Cursor<Vec<u8>>, view| {
                read(
                    src,
                    &archive,
                    index,
                    AT,
                    Wanted {
                        view,
                        names: &names,
                    },
                )
                .expect("the entry reads")
            };

            let raw = read_as(&mut src, View::Raw);
            assert!(!raw.xml, "raw converted");
            assert_eq!(
                raw.bytes, on_disk,
                "raw is not the entry's own payload as it sits on disk"
            );
            assert_ne!(
                raw.bytes,
                DOCUMENT.as_bytes(),
                "the fixture's payload is the document, so this test proves nothing"
            );

            for view in [View::Xml, View::Auto] {
                let viewed = read_as(&mut src, view);
                assert!(viewed.xml, "{} did not convert", view.name());
                assert_eq!(String::from_utf8_lossy(&viewed.bytes), DOCUMENT);
            }
        }

        #[test]
        fn the_tag_a_refusal_to_seal_a_resource_names_is_the_archives_own() {
            let (bytes, unlock, _) = sealed_archive();
            let mut src = Cursor::new(bytes);
            let archive = Archive::open(&mut src, &unlock).expect("opens");
            let index = archive.find(AT).expect("the entry is there");
            assert_eq!(archive.encryption_tag(), rpf7::ENCRYPTION_AES);
            let Held::Resource(resource) =
                held_by(&mut src, &archive, index, AT).expect("the entry classifies")
            else {
                panic!("the fixture's entry is not a resource");
            };
            assert_eq!(
                resource.tag,
                rpf7::ENCRYPTION_AES,
                "the entry carries another archive's tag"
            );
            let stranded = Resource {
                sealer: None,
                ..resource
            };
            let mut payload = vec![0_u8; 32];
            let refused = stranded
                .seal_from(&mut payload, 0, true)
                .expect_err("nothing is left to seal it with");
            assert!(
                matches!(
                    refused,
                    Error::CannotWriteEncrypted {
                        tag,
                        reason: NoWrite::NoInverse
                    } if tag == rpf7::ENCRYPTION_AES
                ),
                "the refusal answered {refused:?}"
            );
        }

        /// The same 512 bytes with the boundary declared wrong: no system pages, one graphics page.
        const ELSEWHERE: ResourceFlags = ResourceFlags {
            system: 0x2000_0000,
            graphics: 0xA800_0000,
        };

        #[test]
        fn a_resource_payload_in_hand_is_unframed_at_the_boundary_it_begins_at() {
            let names = Dictionary::default();
            for prefix in [16_usize, 24] {
                let mut payload = vec![0xFF_u8; prefix];
                payload.extend_from_slice(&deflated(&meta_page()));
                let viewed = of(
                    payload,
                    Held::from(FLAGS),
                    AT,
                    Wanted {
                        view: View::Xml,
                        names: &names,
                    },
                )
                .expect("the payload unframes at the boundary it begins at");
                assert!(viewed.xml);
                assert_eq!(String::from_utf8_lossy(&viewed.bytes), DOCUMENT);
            }
        }
    }
}
