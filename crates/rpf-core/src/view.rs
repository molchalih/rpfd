//! Which form of an entry a caller reads and writes: its own bytes, or the XML
//! view of them. The container and the metadata layer meet here; neither layer
//! knows about the other.

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
    /// The XML view where the entry has one, and the entry's own bytes where it
    /// has not.
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
#[derive(Debug, Clone, Copy)]
pub struct Wanted<'a> {
    /// Which form of the entry.
    pub view: View,
    /// How a `PSO`'s hashes are spelled in it.
    pub names: &'a Dictionary,
}

/// What the **entry** holds, which is the whole of whether it has a view.
///
/// A resource is not an encoding: what it is comes from its row, whose flag
/// words are both the boundary `meta` resolves pointers against and the length
/// the payload must inflate to.
#[derive(Debug, Clone)]
pub enum Held {
    /// Nothing recognised — unknown binary — or there is no entry at all.
    Nothing,
    /// A binary entry whose payload announces an encoding.
    Encoded(Encoding),
    /// A resource entry: the flag words its row declares, and the transform its
    /// payload is under where a caller could ask an archive.
    Resource(Resource),
}

/// A **resource** entry as a seam holding its payload needs it: the row's two
/// flag words, and the archive's own transform in both directions.
#[derive(Debug, Clone)]
pub struct Resource {
    /// The entry row's two flag words.
    flags: ResourceFlags,
    /// The archive's decrypting transform, where one was to hand.
    cipher: Option<Cipher>,
    /// What mints its inverse, where this build can run the transform forwards.
    ///
    /// A [`Sealer`] and not a seal: an NG key is chosen by the name and length
    /// of what is being written, so a converted write's key can be chosen only
    /// in [`Resource::seal_from`], once the payload exists.
    sealer: Option<Arc<Sealer>>,
    /// The entry's own name, which is the other half of what a key is chosen
    /// by, and empty where there is no transform to key.
    name: String,
    /// The archive's encryption tag, which that refusal names.
    tag: u32,
    /// The archive's version, which says how a payload's keying length is
    /// derived from its own.
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

    /// Puts a rebuilt payload back under the archive's own transform from
    /// `from` onwards, where `sealed` says the payload it was made from was
    /// found under it.
    ///
    /// `from` is where the stream begins inside the payload, which is where the
    /// reader counts its blocks from. The key is chosen here from the whole
    /// payload in hand, its length put through
    /// [`crate::format::Version::resource_key_len`] because past the row's
    /// 24-bit size field the reader keys by the block-aligned room instead.
    ///
    /// # Errors
    ///
    /// [`Error::CannotWriteEncrypted`] for an archive under a transform this
    /// build cannot run forwards.
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
    /// What the entry's payload announces itself to be, on a listing row's
    /// terms: `None` for a resource, whose payload a listing does not read.
    #[must_use]
    pub const fn encoding(&self) -> Option<Encoding> {
        match *self {
            Self::Encoded(encoding) => Some(encoding),
            Self::Nothing | Self::Resource(_) => None,
        }
    }
}

/// How many of a resource's inflated bytes are system pages.
fn system_len(flags: ResourceFlags) -> usize {
    usize::try_from(size_from_flags(flags.system)).unwrap_or(usize::MAX)
}

/// A resource payload a caller already holds, taken apart at the boundary its
/// stream begins at.
struct InHand<'a> {
    /// The opaque bytes in front of the stream.
    prefix: &'a [u8],
    /// What the stream inflates to.
    contents: Vec<u8>,
    /// Whether the stream was found under the archive's own transform, which
    /// is how what is written back goes back the way it came.
    sealed: bool,
}

/// The inflated contents of a resource payload a caller already holds, or
/// `None` when these bytes are not one.
///
/// The boundary is found rather than declared: a Rockstar payload carries no
/// header, so in front of its stream are 16 or 24 opaque bytes
/// ([`RESOURCE_HEADER_LENS`]) and the row's flag words judge a candidate — the
/// stream has to inflate to exactly the length they declare, in the clear or
/// under the archive's own transform. A payload that does carry an `RSC7`
/// header must agree with the row at offsets 8 and 12 or it is another entry's.
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

/// The payload edited contents become: the payload's **own** opaque prefix,
/// then the contents deflated.
///
/// The prefix is carried across rather than replaced with a header of this
/// build's own: nobody knows what those 16 or 24 bytes are, and what this build
/// cannot interpret still round-trips byte for byte.
///
/// # Errors
///
/// [`Error::Io`] from the encoder, unreachable for a payload in memory.
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

/// Whether these offered bytes announce themselves as an XML document.
fn announces_xml(offered: &[u8]) -> bool {
    Encoding::of(offered.get(..Encoding::HEAD_LEN).unwrap_or(offered)) == Some(Encoding::Xml)
}

/// What the entry at `index` holds, refusing a directory.
///
/// # Errors
///
/// [`Error::WrongKind`] for a directory, and as [`Archive::classify`].
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

/// What the **resource** entry at `index` holds: its row's flag words, and the
/// archive's transform for a payload of `in_hand` bytes — `None` for the one
/// the entry itself carries.
///
/// The length keys the read direction alone; the write direction's key is
/// chosen when the bytes exist, in [`Resource::seal_from`].
fn resource_at(archive: &Archive, index: u32, in_hand: Option<u64>) -> Result<Held> {
    let EntryKind::Resource {
        system_flags,
        graphics_flags,
        ..
    } = archive.entry(index)?.kind
    else {
        // An entry that is not a resource holds no flags and has no view.
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

/// What the entry at `index` holds, for a payload the caller has **in hand**
/// rather than the one the archive carries.
///
/// # Errors
///
/// As [`Archive::classify`].
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

/// A resource entry's inflated contents, or `None` when they do not read back.
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
    /// What the entry's payload announces itself to be, or `None` when it
    /// announces nothing, is a resource, or is a directory.
    pub encoding: Option<Encoding>,
}

/// Reads one entry in the form `view` asks for, naming `path` in a refusal.
///
/// # Errors
///
/// [`Error::NoXmlView`] when [`View::Xml`] is asked of an entry that has none,
/// [`Error::WrongKind`] for a directory, and whatever reading or converting
/// answers.
pub fn read<R: Read + Seek>(
    src: &mut R,
    archive: &Archive,
    index: u32,
    path: &str,
    wanted: Wanted<'_>,
) -> Result<Viewed> {
    let held = held_by(src, archive, index, path)?;
    // A `Meta` lives in the inflated contents, so a converted read asks
    // `Archive::read` and falls back to the framed payload where there is none.
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

/// The same decision over a payload a caller already holds, which is what the
/// daemon asks of a write it has buffered.
///
/// [`Held::Nothing`] is "nothing recognised", "not read" and "there is no entry
/// yet" alike. A resource in hand is the exported form or it is nothing.
///
/// # Errors
///
/// As [`read`], less the directory case, which a payload cannot be.
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
    // A resource's payload is never sniffed: the bytes decide only what is
    // inside the framing its row describes.
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

/// The payload to write into one entry, from bytes offered in the form `view`
/// says they are.
///
/// [`View::Raw`] hands them back untouched. [`View::Xml`] reads them as a
/// document and applies it to the payload the entry holds, refusing an entry
/// with no view. [`View::Auto`] does that only when the offered bytes announce
/// themselves as XML **and** the entry has a view.
///
/// A resource entry is the one entry that does not take a document, whichever
/// view asked: handing one back wrote it into the archive as the payload,
/// silently, because a resource carries no encoding for a change to be seen in.
/// `held` is the whole of whether there is a view; `payload` never decides it.
///
/// # Errors
///
/// [`Error::NoXmlView`] when [`View::Xml`] is asked of an entry that has none,
/// and [`Error::NotRbfXml`], [`Error::NotPsoXml`] or [`Error::NotMetaXml`] for
/// a document that does not describe the payload it is applied to.
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
                // No view and not a resource: the document is bytes like any
                // other, and `edit::check_encoding` judges the write.
                Applied::NoView => Ok(offered),
                // A resource: handing the document back would write it into
                // the entry as the payload, with nothing to see it.
                Applied::Resource => Err(no_view()),
            }
        }
    }
}

/// What a document became against what the entry holds.
///
/// Three answers rather than an `Option`: [`View::Auto`] hands a document back
/// for a binary entry with no view, and refuses it for a resource.
enum Applied {
    /// The payload the document becomes.
    Payload(Vec<u8>),
    /// The entry is not a resource and has no XML view.
    NoView,
    /// The entry is a **resource** and the document did not become a payload
    /// for it, which is a refusal and never a fallback.
    Resource,
}

/// The payload a document becomes against what the entry holds, or `None` when
/// the entry has no view.
///
/// The whole of the write-side dispatch, in one place so that [`applied`]'s two
/// converting arms cannot come to disagree.
///
/// # Errors
///
/// Whatever the encoding's own converter answers, and [`Error::Io`] from
/// framing a resource back up.
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
                // Framed with the prefix it was unframed at and put back
                // under the transform it was found under.
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

/// The same, reading the payload the entry holds now out of the archive.
///
/// A `PSO` write is an **edit** of the file the document came from, so it is
/// read here, in the call that converts, from the handle already open.
///
/// # Errors
///
/// As [`applied`], plus [`Error::WrongKind`] for a directory, and whatever
/// reading the entry answers.
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
        // Nothing for a document to be applied to, so the payload is neither
        // read nor sniffed.
        Held::Nothing => applied(&[], held, path, wanted, offered),
        Held::Encoded(_) => {
            let payload = archive.extract(src, index)?;
            applied(&payload, held, path, wanted, offered)
        }
        // A resource is unframed by the archive, which recovers the boundary
        // and decrypts on the way; what comes back is framed and sealed again.
        Held::Resource(ref resource) => {
            // `auto` over bytes that are not a document converts nothing, so a
            // resource that is not being edited as XML is not inflated at all.
            if wanted.view == View::Auto && !announces_xml(&offered) {
                return Ok(offered);
            }
            // A payload that will not come apart is a refusal in both forms:
            // `auto`'s fallback would write the document in as the payload.
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
                // Came apart and is not a `Meta`: no view, and `auto` refuses
                // here too. `View::Raw` returned at the top of the call.
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

    /// The flag words of a one-page resource: 512 bytes of system and no
    /// graphics.
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
        // And a resource holds no encoding.
        assert_eq!(Held::from(FLAGS).encoding(), None);
    }

    #[test]
    fn a_resource_payload_in_hand_is_unframed_by_its_own_boundary_or_has_no_view() {
        // The prefix crosses both ways: `exported` keeps the one it was given
        // and `contents_of` finds it again by the boundary it begins at.
        let contents = vec![0x5A_u8; 512];
        let prefix = [0xFF_u8; 24];
        let payload = exported(&prefix, &contents).expect("frames");
        assert_eq!(payload.get(..prefix.len()), Some(&prefix[..]));
        let held = contents_of(&payload, &Resource::in_the_clear(FLAGS)).expect("unframes");
        assert_eq!(held.contents, contents);
        assert_eq!(held.prefix, &prefix[..]);
        // The entry's own flag words judge it: a payload that does not inflate
        // to the length they declare is not this entry's.
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

        // And the contents above are not a `Meta`, so the entry has no view
        // however well the framing reads.
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
        // The write side refuses the document in both views rather than handing
        // it back for the commit to write in as the resource's payload.
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
        // And what is not a document still goes in as it always did, which is
        // the write `auto` must never turn into a refusal.
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
        // The payload below is plainly XML and still has no view, because what
        // an entry is comes from its row.
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
        // An entry that carries no encoding has no view whatever its payload
        // begins with; sniffing would write a tokenised payload into it.
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

    /// A converted write of a resource, from the archive it is read out of to
    /// the bytes that land on disk, under a real transform whose key is
    /// thirty-two zero bytes.
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

        /// The path the one entry sits at.
        const AT: &str = "data/thing.ymt";

        /// The sixteen opaque bytes in front of the fixture's deflate stream.
        const PREFIX: [u8; 16] = [0xFF; 16];

        /// The document [`meta_page`] converts to, and the same with its one
        /// value edited.
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

        /// The smallest `Meta` that reaches a value, in one 512-byte system
        /// page, built by hand so that it cannot share the reader's own bugs.
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

        /// `contents` deflated, which is what a resource payload holds.
        fn deflated(contents: &[u8]) -> Vec<u8> {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(contents).expect("the page deflates");
            encoder.finish().expect("the encoder finishes")
        }

        /// The zero-key AES forward transform, one seal off it, and the
        /// [`Unlock`] that opens what it wrote.
        fn zeroed(named: &str) -> (Sealer, Seal, Unlock) {
            let material = Arc::new(Material::over_zeros());
            let scheme = Version::Rpf7.scheme(rpf7::ENCRYPTION_AES).expect("AES");
            let sealer = Sealer::new(scheme, &material).expect("AES seals");
            let seal = sealer.seal(named, 0).expect("AES seals");
            (sealer, seal, Unlock::held(material, named))
        }

        /// An AES-sealed archive holding one resource whose payload is under
        /// the archive's own transform, and that payload as it sits on disk.
        fn sealed_archive() -> (Vec<u8>, Unlock, Vec<u8>) {
            sealed_archive_behind(&PREFIX, 0)
        }

        /// The same behind a prefix of any length, sealed from `from` onwards.
        ///
        /// The reader decrypts a resource from its stream's start and not the
        /// payload's, which only a 24-byte prefix can tell apart.
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

        /// The synthetic NG forward transform, and the [`Unlock`] that opens
        /// what it wrote.
        fn ng_zeroed(named: &str) -> (Sealer, Unlock) {
            let material = Arc::new(synthetic::ng_material(0x0DE1_2A55));
            let scheme = Version::Rpf7.scheme(rpf7::ENCRYPTION_NG).expect("NG");
            let sealer = Sealer::new(scheme, &material).expect("synthetic tables derive");
            (sealer, Unlock::held(material, named))
        }

        /// An NG-sealed archive holding one resource under the archive's own
        /// transform, the material that opens it, and that payload on disk.
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

        /// The same document with a value that deflates to a different length,
        /// which moves the key an NG archive seals the payload under.
        const WIDENED: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                               <hash_D98BB561 meta:struct=\"hash_D98BB561\">\n  \
                               <hash_12345678 meta:uint=\"123456789\"/>\n\
                               </hash_D98BB561>\n";

        /// [`meta_page`] with its one value edited, which is what [`WIDENED`]
        /// applies.
        fn widened_page() -> Vec<u8> {
            let mut page = meta_page();
            page[0xB0..0xB4].copy_from_slice(&123_456_789_u32.to_le_bytes());
            page
        }

        #[test]
        fn a_converted_write_into_an_ng_archive_is_keyed_for_the_bytes_it_seals() {
            // An NG key is a function of the payload being written, so a seal
            // minted from the length before the edit picks the old key.
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

        /// The largest value a resource's 24-bit compressed-size field holds,
        /// and the sentinel it writes when the payload has outgrown it.
        const SATURATED: usize = 0x00FF_FFFF;

        /// A payload past the field that is **not** a whole number of blocks,
        /// so the room the reader recovers is longer than the payload.
        const PAST_THE_FIELD: usize = 17_828_618;

        /// Where the saturated fixture's resource sits: the root, so the entry
        /// after it in the table is the payload after it on disk.
        const BIG: &str = "big.ymt";

        /// An NG archive holding one resource payload of `len` bytes sealed as
        /// [`Resource::seal_from`] seals one, with a second entry after it.
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

        /// The fixture opened again and its saturated entry read back, with
        /// the row's sentinel and the recovered room asserted on the way.
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
            // A payload past the 24-bit field states no extent, so the reader
            // recovers it as the block-aligned room to the next payload.
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
            // A payload of exactly the field's largest value is indistinct
            // from the sentinel, so the field saturates at `>=` and not at `>`.
            let room = (SATURATED as u64).next_multiple_of(512);
            assert_ne!(room, SATURATED as u64, "the field's value is not aligned");
            saturated_reads_back(SATURATED, room);
        }

        #[test]
        fn a_resource_payload_one_past_the_field_is_keyed_by_the_room_it_exactly_fills() {
            // 16,777,216 is a whole number of blocks, so the room and the
            // payload are the same length and so the same key.
            let room = (SATURATED as u64).saturating_add(1);
            assert_eq!(room % 512, 0, "one past the field is a whole block");
            saturated_reads_back(SATURATED + 1, room);
        }

        /// What `stream` inflates to, or nothing at all.
        fn inflated(stream: &[u8]) -> Vec<u8> {
            let mut contents = Vec::new();
            flate2::read::DeflateDecoder::new(stream)
                .take(4096)
                .read_to_end(&mut contents)
                .ok();
            contents
        }

        /// The one entry's payload as it sits on disk.
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
            // `build::is_sealed` answers `false` for every resource, so an
            // unsealed write lands plaintext inside an encrypted archive.
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

            // Over the bytes on disk rather than what the reader makes of
            // them: it tries the clear boundary first and would hide this.
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
            // A 16-byte prefix is the cipher's own block, so the two starts are
            // identical; at 24 they differ, and the reader counts from the stream.
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

            // Sealed from the stream: what is at 24 onwards decrypts and inflates.
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
            // And not from the payload's, which is a different arrangement of
            // the same 16-byte blocks.
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
            // What `apply` produces for a keyed resource is ciphertext, so the
            // seams reading a payload in hand need the entry's own transform.
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

                // Written over again as `auto`: a payload, not the document.
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
            // The bytes in front of a resource's deflate stream are nobody's, so
            // a converted write carries them across rather than replacing them.
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
            // An `RSC7` header's words at 8 and 12 are the row's own two facts,
            // so one declaring the boundary elsewhere is not this entry's.
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
            // The two declare the same total length, so nothing but the words
            // themselves tells them apart.
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
            // And the write side answers the same rather than re-framing it.
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

        /// A resource payload whose sixteen-byte `RSC7` header declares
        /// `header` as its flag words, in front of [`meta_page`]'s stream.
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
            // The refusal is over two facts: a header wrong in either word
            // alone describes another entry, and one right in both reads.
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
            // `raw` is the entry's own framed payload byte for byte; `xml` and
            // `auto` are both the document, a resource with `Meta` having a view.
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
            // The tag travels from the header into the `Resource` a read
            // classifies and out again in `CannotWriteEncrypted`.
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

        /// The same 512 bytes with the boundary declared in the wrong place:
        /// no system pages and one graphics page.
        const ELSEWHERE: ResourceFlags = ResourceFlags {
            system: 0x2000_0000,
            graphics: 0xA800_0000,
        };

        #[test]
        fn a_resource_payload_in_hand_is_unframed_at_the_boundary_it_begins_at() {
            // The boundary is found rather than declared: the stream inflates
            // to exactly the length the row's flag words give, at 16 or at 24.
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
