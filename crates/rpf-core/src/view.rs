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
//! none, so the set is written down exactly once and one layer down (§3). R5.8
//! is that door being used: a resource carrying `Meta` gained its view there,
//! and what this module gained with it is [`Held`] — because a `Meta` is the
//! one view whose conversion needs a fact from the **entry row** rather than
//! from the payload.
//!
//! # What a resource's view costs, and why it is here rather than one layer
//! down
//!
//! A `Meta` lives inside a resource's *inflated* payload, and every pointer in
//! it is resolved against the boundary between the system and the graphics
//! pages. That boundary is `size_from_flags` of the entry's own system flags:
//! it is nowhere in the payload, so a caller that hands the metadata layer a
//! payload without the flags that belong to it is handing over half an entry.
//! [`Held::Resource`] is that half carried, and it is what the two payload-form
//! entry points take instead of an [`Encoding`] a resource does not have.
//!
//! The two framings meet here as well. A resource's payload is framed and
//! deflated; a `Meta` is what it inflates to. So a converted **read** takes
//! [`Archive::read`]'s contents rather than [`Archive::extract`]'s payload, and
//! a converted **write** frames what it produced back up — the payload's own
//! opaque prefix, then the deflated contents, then the archive's transform
//! where the entry was read under one. A converted write is the one write that
//! is not passthrough, and it cannot be: it is a payload this build decoded,
//! edited and encoded again.
//!
//! **What a converted write does and does not preserve** is DR-060, and it is
//! three properties and not four. The document survives the round trip, the row
//! is unchanged apart from `compressed_len`, and the write is idempotent from
//! the second time on. What does **not** hold, and cannot with this design, is
//! archive-level byte identity for an unedited write: the contents are deflated
//! again at [`Compression::default`] rather than at whatever level the producer
//! used, so the payload's length moves even when not one byte of the contents
//! does. Passthrough — `rpf cat` into `rpf put` with no `--as` — is still byte
//! for byte, and that is the property `docs/approach.md` commits to.
//!
//! **A payload in hand is taken apart under the same transform**, and that is
//! DR-061. Because a converted write buffers the payload in the form the entry
//! sits in on disk, the seams that read a payload rather than an archive —
//! [`of`] and [`applied`], which are what the daemon asks of its own buffered
//! write — have to be able to un-seal what [`apply`] sealed. So [`Held`]
//! carries the entry's transform as well as its flag words ([`Resource`]), and
//! [`held_in_hand`] is where a caller with an archive fills it in. What has no
//! transform to give still works exactly as it did: the clear boundary, found
//! rather than declared.
//!
//! The other half of DR-061 is a refusal: **a resource entry does not take a
//! document**. Whether its payload could not be taken apart at all — a corrupt
//! stream, or a keyed one with no key — or came apart and is not a `Meta`,
//! which is 694,470 of the corpus's 696,578 resources, there is nothing for a
//! document to be applied *to*, and [`View::Auto`]'s "hand the bytes back" is
//! the wrong answer for it: it wrote the XML document into the entry as the
//! resource's payload, silently, because a resource carries no encoding for
//! `edit::check_encoding` to see a change in. A resource takes a document only
//! by converting it; its own bytes still go in under [`View::Raw`], and under
//! `auto` for anything that is not a document.

use std::{
    borrow::Cow,
    io::{Read, Seek, Write as _},
};

use flate2::{Compression, write::DeflateEncoder};

use crate::{
    archive::{Archive, Classification},
    build::ResourceFlags,
    entry::EntryKind,
    error::{Error, NoWrite, Result},
    format::{
        crypto::{Cipher, Seal},
        resource::{MAGIC_RSC7, RESOURCE_HEADER_LENS, resource_len, size_from_flags},
        rpf7, u32_at,
    },
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

/// What the **entry** holds, which is the whole of whether it has a view.
///
/// Three answers rather than [`Encoding`]'s four-or-none, because a resource is
/// not an encoding and never becomes one: `docs/backlog.md` Q7 measured that no
/// payload sniff can name one, so what a resource is comes from its row and
/// what it carries comes from the contents inside it (DR-044). A caller that
/// has only an [`Option<Encoding>`] — every caller before R5.8 — converts into
/// this and loses nothing, because that is exactly what a binary entry answers.
///
/// [`Held::Resource`] carries the entry's two flag words rather than a byte
/// count, and carries them for two reasons: the system half is the boundary
/// `meta` resolves every pointer against, and the pair together is the length
/// the payload must inflate to, which is how a payload in hand is unframed
/// without an archive to ask.
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

/// A **resource** entry as a seam holding its payload needs it.
///
/// The row's two flag words, and the archive's own transform in both
/// directions. The transform is here because of what a converted write leaves
/// behind: it produces a payload in the form the entry sits in on disk, which
/// for the 3,022 of 696,578 resources DR-051 measured is ciphertext (DR-054 §3,
/// DR-060 §2). A caller that then reads that payload back — the daemon reading
/// its own buffer — has to be able to take it apart again, and nothing in the
/// bytes says how. DR-061.
///
/// [`Resource::in_the_clear`] is the answer for a caller with no archive to
/// ask, which is every caller that has only flag words to give: a payload under
/// a transform then has no view here, exactly as before.
#[derive(Debug, Clone)]
pub struct Resource {
    /// The entry row's two flag words.
    flags: ResourceFlags,
    /// The archive's transform keyed for this entry, where one was to hand.
    ///
    /// The decrypting direction, which is what takes a payload in hand apart.
    cipher: Option<Cipher>,
    /// Its inverse, where this build can run the transform forwards.
    ///
    /// `None` for an archive under a transform with no inverse — NG — which is
    /// a refusal at the write and not at the read: what is readable stays
    /// readable, and only putting it back is impossible.
    seal: Option<Seal>,
    /// The archive's encryption tag, which that refusal names.
    tag: u32,
}

impl Resource {
    /// A resource described by its row alone, with no archive behind it.
    #[must_use]
    pub const fn in_the_clear(flags: ResourceFlags) -> Self {
        Self {
            flags,
            cipher: None,
            seal: None,
            tag: rpf7::ENCRYPTION_OPEN,
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
    /// **The one place a resource payload this build produced is sealed**, and
    /// the mirror of the probe that took it apart: `build::is_sealed` answers
    /// `false` for every resource because the writer is handed payloads as they
    /// sit on disk, so a payload this build *produced* has to arrive there
    /// already in that form or it arrives in the clear (DR-054 §3, DR-060 §2).
    ///
    /// `from` is where the stream begins inside the payload, which is where the
    /// reader's own `archive::Decrypting` counts its blocks from: a resource is
    /// decrypted from its stream's start and not from the payload's, and the
    /// two differ for the 24-byte headers of [`RESOURCE_HEADER_LENS`]. The tail
    /// shorter than a block goes through as it stands, which is [`Seal::apply`]'s
    /// rule and the reader's alike.
    ///
    /// # Errors
    ///
    /// [`Error::CannotWriteEncrypted`] for an archive under a transform this
    /// build cannot run forwards, which is how a converted write into an NG
    /// archive refuses rather than lands in the clear.
    fn seal_from(&self, payload: &mut [u8], from: usize, sealed: bool) -> Result<()> {
        if !sealed {
            return Ok(());
        }
        let seal = self.seal.as_ref().ok_or(Error::CannotWriteEncrypted {
            tag: self.tag,
            reason: NoWrite::NoInverse,
        })?;
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
///
/// `docs/rpf-format.md`, Resource page flags. Saturating rather than fallible:
/// a length no `usize` holds is a payload no machine read, and the conversion
/// it is handed to bounds every access by the payload it was given.
fn system_len(flags: ResourceFlags) -> usize {
    usize::try_from(size_from_flags(flags.system)).unwrap_or(usize::MAX)
}

/// A resource payload a caller already holds, taken apart at the boundary its
/// stream begins at.
///
/// [`crate::archive::Unframed`] over a payload rather than over an archive, and
/// the two agree by construction: both carry the bytes in front of the stream,
/// because both feed [`exported`], which puts them back.
struct InHand<'a> {
    /// The opaque bytes in front of the stream.
    prefix: &'a [u8],
    /// What the stream inflates to.
    contents: Vec<u8>,
    /// Whether the stream was found under the archive's own transform, which
    /// is how what is written back goes back the way it came. DR-051, DR-060.
    sealed: bool,
}

/// The inflated contents of a resource payload a caller already holds, or
/// `None` when these bytes are not one.
///
/// **The boundary is found rather than declared** — DR-045's rule, applied to a
/// payload with no archive behind it. A Rockstar resource's payload carries no
/// header (Q7), so what is in front of its stream is 16 or 24 opaque bytes
/// ([`RESOURCE_HEADER_LENS`]) and the entry's own flag words are what judge a
/// candidate: the stream has to inflate to exactly the length they declare.
///
/// **The transform is tried as well as the boundary**, in the clear first and
/// under the archive's own second, which is `Archive::resource_stream`'s own
/// order over an entry rather than over a payload. It is here because a
/// converted write leaves a payload in the form the entry sits in on disk, and
/// for a keyed resource that is ciphertext: a seam that could not take it apart
/// answered "no view" for the daemon's own buffer, and `auto` then wrote the
/// document into the archive in its place (DR-061). A [`Resource`] with no
/// cipher tries the clear boundary alone, which is what a caller holding only
/// flag words can honestly answer.
///
/// **A payload that does carry an `RSC7` header is judged by it.** Its words at
/// offsets 8 and 12 are the same two facts the row carries, and
/// `build::store_resource` takes the payload's over the row's when it has them
/// — so a header that contradicts the row describes a different entry, and
/// unframing it against the row's boundary would answer a document read at
/// addresses that are not its own. Two elements over one address have to agree
/// (DR-059); where they do not, there is no view rather than a guess.
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
/// **The prefix is carried across rather than replaced with a header of this
/// build's own**, and that is DR-060 rather than a shortcut. `docs/rpf-format.md`
/// records that no Rockstar resource payload begins with `RSC7` and that
/// nothing decrypts those 16 or 24 bytes into one — nobody knows what they are
/// — and `docs/approach.md` commits that what this build cannot interpret still
/// round-trips byte for byte. Writing a header instead moved the stream by 8
/// bytes for the 22 of 7,072 resources whose stream begins at 24 and discarded
/// the original bytes for all of them.
///
/// What the row declares is unaffected: `build::store_resource` reads flag words
/// out of an `RSC7` header when the payload carries one and takes the entry's
/// `declared` words when it does not (DR-046), and a payload keeping a
/// Rockstar prefix is the second case — which is the case every resource in the
/// corpus is in already.
///
/// # Errors
///
/// [`Error::Io`] from the encoder, which for a payload in memory is
/// unreachable.
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

/// Whether these offered bytes announce themselves as an XML document, which is
/// the whole of what [`View::Auto`] converts.
fn announces_xml(offered: &[u8]) -> bool {
    Encoding::of(offered.get(..Encoding::HEAD_LEN).unwrap_or(offered)) == Some(Encoding::Xml)
}

/// What the entry at `index` holds, refusing a directory.
///
/// A resource's answer carries the archive's transform, which a
/// [`View::Raw`] read never uses — and it is derived anyway rather than
/// deferred, because deferring it costs more than it saves. An archive that is
/// not encrypted derives nothing at all ([`Archive::resource_transform`] over
/// no scheme is two `None`s), and an archive that is encrypted pays one key
/// derivation per **call**: both callers, [`read`] and [`apply`], are one entry
/// each and neither frontend loops over a table here. A lazily-held transform
/// would put an `Archive` borrow, or a cell, inside a [`Held`] that is cloned
/// and handed across the daemon's session — which is a great deal of shape for
/// a cost the archive's own opening already paid.
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
/// The length matters because the NG key index is a function of the payload's
/// length on disk (DR-051), and a payload a caller holds is not always the one
/// the entry carries: what a converted write buffers is deflated again and is
/// its own length. The AES key is the tag's and takes neither, so for the one
/// transform this build writes forwards the two agree by construction.
fn resource_at(archive: &Archive, index: u32, in_hand: Option<u64>) -> Result<Held> {
    let EntryKind::Resource {
        system_flags,
        graphics_flags,
        ..
    } = archive.entry(index)?.kind
    else {
        // `Classification::Resource` comes from this same row, so the two
        // cannot disagree; an entry that is not a resource holds no flags and
        // has no resource view.
        return Ok(Held::Nothing);
    };
    let (cipher, seal) = archive.resource_transform(index, in_hand)?;
    Ok(Held::Resource(Resource {
        flags: ResourceFlags {
            system: system_flags,
            graphics: graphics_flags,
        },
        cipher,
        seal,
        tag: archive.encryption_tag(),
    }))
}

/// What the entry at `index` holds, for a payload the caller has **in hand**
/// rather than the one the archive carries.
///
/// [`of`] and [`applied`] over a buffered write, which is the daemon's whole
/// read-back path. It differs from what a read of the entry answers in exactly
/// two ways, and both are about the buffer rather than about the entry:
///
/// - **An encoding is the buffer's**, because a client may have written bytes
///   of another one over the entry, and what is converted is what is there.
/// - **A resource's transform is keyed for the buffer's own length**, which is
///   what `resource_at` documents.
///
/// What does *not* differ is the rule that decides whether there is a view at
/// all: a resource is what its row says it is, and its payload is never
/// sniffed for an encoding (Q7, DR-044). A directory holds nothing rather than
/// refusing, because a payload buffered over one is a refusal its caller has
/// already made.
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
///
/// [`Archive::classify`]'s rule, applied one layer up: a payload that cannot be
/// read is not an error here but an entry with no view. A resource whose
/// deflate stream does not inflate is a resource all the same — `verify` is
/// where that is reported, one problem per path — and `--as auto` over an
/// archive holding one must still hand back the bytes rather than fail.
fn contents_at<R: Read + Seek>(src: &mut R, archive: &Archive, index: u32) -> Option<Vec<u8>> {
    archive.read(src, index).ok()
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
/// [`Archive::classify`], so what a resource's bytes look like never makes it
/// something else — Q7's trap, and DR-044's answer to it. What a resource's
/// *contents* carry is a second question, asked only of an entry the row
/// already called a resource, and its answer is a `Meta` or nothing (R5.8).
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
    let held = held_by(src, archive, index, path)?;
    // A resource is read in the framing its view lives in. `Archive::extract`
    // is the file outside the archive — framed and deflated — and a `Meta` is
    // what that inflates to, so the converted read asks `Archive::read` for the
    // contents and only falls back to the payload when there is no view. R5.8.
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
/// `held` is what the entry holds, and [`Held::Nothing`] is "nothing
/// recognised", "not read" and "there is no entry yet" alike. An
/// `Option<Encoding>` converts into it, so a caller with no resource to
/// describe writes what it always wrote. A caller with no entry to ask — a
/// payload on its own — puts the payload's own [`Encoding::of`] here, which is
/// what the conversion would have derived anyway.
///
/// **A resource in hand is the exported form or it is nothing** — an `RSC7`
/// header and a stream that inflates to the length its flag words declare —
/// because the boundary a Rockstar payload's stream begins at is recovered by
/// reading the archive. A caller holding one should ask [`read`], which unframes
/// through it.
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
    // A resource's payload is never *sniffed* — what it holds came from its
    // row, and the bytes decide only what is inside the framing that row
    // describes.
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
/// document and applies it to the payload the entry holds — DR-049, for `PSO`
/// — and refuses an entry with no view. [`View::Auto`] does that only when the
/// offered bytes announce themselves as XML **and** the entry has a view, and
/// hands them back untouched otherwise: an editor hands back what it was given,
/// and a payload that is not a document is not one.
///
/// **A resource entry is the one entry that does not take a document**,
/// whichever view asked. `auto`'s fallback is "these bytes are not a document
/// for this entry", and for a resource that answer wrote the XML document into
/// the archive as the resource's payload — silently, because a resource carries
/// no encoding for `edit::check_encoding` to see a change in. A resource takes
/// a document only by converting it, and where it cannot convert one it refuses.
/// DR-061. Bytes that are genuinely a resource's own still go in as they always
/// did, under [`View::Raw`] and under `auto` for anything that is not a
/// document.
///
/// `held` is what the **entry** holds, on the same terms as [`of`]'s: it is the
/// caller's [`Archive::classify`] answer, and [`Held::Nothing`] is "nothing
/// recognised" or "there is no entry yet". It is the whole of whether there is
/// a view, and `payload` is never consulted to decide that — the write side of
/// **a resource is never sniffed** (Q7, DR-044). Without it a resource whose
/// payload happens to begin `RBF0` would be handed to the tokeniser and a
/// tokenised payload written into a resource entry, which is the one thing
/// [`Classification::Resource`] carries no encoding to prevent. A resource
/// carrying `Meta` is not that case reversed: it has a view because its **row**
/// says it is a resource and its inflated contents carry the `Meta` magic, and
/// never because a payload looked like one.
///
/// What comes back is a payload of the entry's own encoding, which is why a
/// converted write needs no `allow_encoding_change`: there is no encoding
/// change in it. DR-050's rule judges the result, unchanged and unweakened.
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
                // The entry has no view and is not a resource, so the document
                // is bytes like any other and `auto` hands back what it was
                // given. A binary entry written full of XML is an encoding
                // change, which `edit::check_encoding` sees and DR-050 judges.
                Applied::NoView => Ok(offered),
                // The entry is a resource and the document did not become its
                // payload, so handing it back would write the document into the
                // entry as the payload — with nothing to see it, because a
                // resource carries no encoding. DR-061.
                Applied::Resource => Err(no_view()),
            }
        }
    }
}

/// What a document became against what the entry holds.
///
/// Three answers rather than an `Option`, because the two ways of not becoming
/// a payload are not one: a **binary** entry with no view holds bytes a
/// document is no worse than, and DR-050 judges the write that lands them; a
/// **resource** entry holds a payload whose framing, flag words and transform a
/// document is not, and there is nothing there for `edit::check_encoding` to
/// judge it by. [`View::Auto`] hands the document back for the first and
/// refuses for the second, which is DR-061; an `Option` collapsed them, and the
/// collapse wrote XML documents into resource entries as their payloads.
enum Applied {
    /// The payload the document becomes.
    Payload(Vec<u8>),
    /// The entry is not a resource and has no XML view.
    NoView,
    /// The entry is a **resource** and the document did not become a payload
    /// for it — its own payload would not come apart, or what came apart is not
    /// something a document describes.
    ///
    /// Both are refusals and neither is a fallback: a resource entry does not
    /// take a document.
    Resource,
}

/// The payload a document becomes against what the entry holds, or `None` when
/// the entry has no view.
///
/// The whole of the write-side dispatch, in one place so that [`applied`]'s two
/// converting arms cannot come to disagree. An entry with no view has nothing
/// for a document to be applied to, and that is the **entry's** answer rather
/// than the payload's: `payload` is not reached at all in that case, so it
/// cannot overturn it (Q7, DR-044).
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
                // Framed back up with the prefix it was unframed at and put
                // back under the transform it was found under, so a payload in
                // hand goes back the shape it arrived in (DR-060, DR-061).
                Some(edited) => {
                    let mut payload = exported(held.prefix, &edited)?;
                    resource.seal_from(&mut payload, held.prefix.len(), held.sealed)?;
                    Applied::Payload(payload)
                }
                // The payload came apart and is not a `Meta`: this resource has
                // no view, and a resource with no view still does not take a
                // document. DR-061.
                None => Applied::Resource,
            }
        }
    })
}

/// The same, reading the payload the entry holds now out of the archive.
///
/// The read is the whole of what makes a `PSO` write possible: DR-049 makes it
/// an **edit** of the file the document came from, so the file has to be to
/// hand. It is read here, in the call that converts, from the handle the caller
/// is already holding open — never asked about first and read later, which is
/// the shape that once corrupted an 80 MB archive.
///
/// **A resource is never sniffed**, exactly as in [`read`]: the entry's kind
/// decides first, so a resource has no view whatever its bytes look like and
/// its payload is not fetched at all. Q7, DR-044.
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
        // read nor sniffed. The empty slice is what a path with no entry at all
        // offers, and it is the same answer for the same reason.
        Held::Nothing => applied(&[], held, path, wanted, offered),
        Held::Encoded(_) => {
            let payload = archive.extract(src, index)?;
            applied(&payload, held, path, wanted, offered)
        }
        // A resource is unframed by the archive rather than by [`contents_of`],
        // which is the whole reason this pair exists: the boundary its stream
        // begins at is recovered by reading, and a payload under the archive's
        // own transform is decrypted on the way. What comes back is framed
        // again by [`exported`] and **put back under the transform it was read
        // under** — [`Resource::seal_from`] seals it, because `build::is_sealed`
        // answers `false` for every resource and is right to (DR-054 §3,
        // DR-060).
        Held::Resource(ref resource) => {
            // `auto` over bytes that are not a document converts nothing, so a
            // resource that is not being edited as XML is not inflated at all.
            if wanted.view == View::Auto && !announces_xml(&offered) {
                return Ok(offered);
            }
            // A payload that will not come apart is a refusal in **both**
            // forms. `auto`'s fallback is "these bytes are not a document for
            // this entry", and for an entry whose payload nothing here can
            // interpret that answer wrote the document into the archive as the
            // resource's payload, with nothing refused and nothing reported:
            // `edit::check_encoding` sees no encoding change because a resource
            // carries no encoding. DR-061.
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
                // The payload came apart and is not a `Meta`: this resource has
                // no view, and `auto` refuses here exactly as it does for one
                // that would not come apart at all. Handing the document back
                // wrote it into the entry as the resource's payload, and this
                // is the branch that covers 694,470 of the corpus's 696,578
                // resources. DR-061.
                //
                // `View::Raw` never reaches this: it hands the offered bytes
                // back at the top of the call, which is how genuine resource
                // bytes still go in.
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
        // Every caller before R5.8 hands over an `Option<Encoding>`, and the
        // conversion has to be the identity on both of its answers or a binary
        // entry's view would move.
        assert!(matches!(Held::from(None), Held::Nothing));
        assert!(matches!(
            Held::from(Some(Encoding::Rbf)),
            Held::Encoded(Encoding::Rbf)
        ));
        assert_eq!(Held::Nothing.encoding(), None);
        assert_eq!(Held::Encoded(Encoding::Pso).encoding(), Some(Encoding::Pso));
        // And a resource holds no encoding, which is what a listing row says
        // about one and what `read` answers for one. Q7, DR-044.
        assert_eq!(Held::from(FLAGS).encoding(), None);
    }

    #[test]
    fn a_resource_payload_in_hand_is_unframed_by_its_own_boundary_or_has_no_view() {
        // What the daemon holds after a converted write is framed by
        // `exported`, and unframing it again is what lets a buffered read
        // answer the document. The prefix crosses both ways: `exported` keeps
        // the one it was given (DR-060) and `contents_of` finds it again by the
        // boundary the stream begins at, which is DR-045's rule with no archive
        // behind it.
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
        // The write side refuses the document in **both** views, rather than
        // handing it back for the commit to write into the entry as the
        // resource's payload: a resource entry does not take a document, and
        // this payload — framed, deflating to the length the row declares, and
        // not a `Meta` — is the shape 694,470 of the corpus's 696,578 resources
        // are in. DR-061.
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
        // `auto_hands_back_bytes_that_are_not_a_document_untouched` covers the
        // `!has_view` arm and offers bytes `auto` cannot read as XML either
        // way, so neither tells the two `View::Auto` arms apart. An entry with
        // a view, offered a document its encoding actually reads, is the one
        // input only the real conversion answers right.
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
        // The write side of Q7. An entry that carries no encoding — a resource,
        // whose kind `Archive::classify` short-circuits on before any read —
        // has no view whatever its payload begins with, and `RBF0` is what a
        // high-entropy resource has a 2^-32 chance of beginning with. Sniffing
        // `held` instead would take the `rbf` arm and write a tokenised payload
        // into a resource entry. DR-044.
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
    /// the bytes that land on disk.
    ///
    /// `keys::Material::over_zeros` and the AES tag are what let this run on a
    /// machine with no game installed and no corpus, exactly as
    /// [`crate::build`]'s own tests do (DR-006): the transform is real and the
    /// key is thirty-two zero bytes, so nothing here is or came from a key.
    mod converted {
        use std::{io::Cursor, sync::Arc};

        use super::*;
        use crate::{
            archive::Archive,
            build::{FileKind, FileSpec, Under, build_under},
            edit::{Bytes, Change, Changes},
            format::{
                Version,
                crypto::{Cipher, Seal},
                rpf7,
            },
            keys::{Material, Unlock},
            scratch::InMemory,
            watch::Unwatched,
        };

        /// The path the one entry sits at.
        const AT: &str = "data/thing.ymt";

        /// The opaque bytes in front of the fixture's deflate stream: sixteen
        /// of them, none of which is an `RSC7` header, which is what all
        /// 696,578 of Rockstar's resource payloads look like (Q7, DR-046).
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

        /// The smallest `Meta` that reaches a value: one structure of one
        /// `UINT`, one data block holding it, in exactly one 512-byte system
        /// page — which is what [`FLAGS`] declares.
        ///
        /// Built by hand from `docs/metadata-encodings.md`, so that a payload
        /// built by the reader's own model cannot share the reader's bugs. The
        /// same fixture as `crates/rpf/tests/common`'s, which is where both
        /// frontends meet it.
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

        /// `contents` deflated, which is what a resource payload holds past its
        /// opaque prefix.
        fn deflated(contents: &[u8]) -> Vec<u8> {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(contents).expect("the page deflates");
            encoder.finish().expect("the encoder finishes")
        }

        /// The zero-key AES seal, and the [`Unlock`] that opens what it wrote.
        fn zeroed(named: &str) -> (Seal, Unlock) {
            let material = Arc::new(Material::over_zeros());
            let scheme = Version::Rpf7.scheme(rpf7::ENCRYPTION_AES).expect("AES");
            let seal = Seal::new(scheme, &material).expect("AES seals");
            (seal, Unlock::held(material, named))
        }

        /// An AES-sealed archive holding one resource whose payload is under
        /// the archive's own transform, and that payload as it sits on disk.
        ///
        /// The 3,022-of-696,578 case DR-051 measured, assembled: the whole
        /// payload is sealed from its own start, so the stream is found only
        /// under the key and the sixteen opaque bytes in front of it are
        /// ciphertext too.
        fn sealed_archive() -> (Vec<u8>, Unlock, Vec<u8>) {
            sealed_archive_behind(&PREFIX, 0)
        }

        /// The same behind a prefix of any length, sealed from `from` onwards.
        ///
        /// The two parameters are one fact each and they are not the same fact.
        /// A **16**-byte prefix cannot tell them apart: sealing from 0 and from
        /// 16 leave byte-identical streams, because 16 is the cipher's own
        /// block. A **24**-byte one can, and it is the only fixture that can:
        /// the reader decrypts a resource from its *stream's* start, so a
        /// 24-byte payload sealed from 0 does not read back at all and one
        /// sealed from 24 does. DR-060 §2, and what
        /// `RESOURCE_HEADER_LENS`'s 22-in-7,072 case costs.
        fn sealed_archive_behind(prefix: &[u8], from: usize) -> (Vec<u8>, Unlock, Vec<u8>) {
            let (seal, unlock) = zeroed("meta.rpf");
            let mut payload = prefix.to_vec();
            payload.extend_from_slice(&deflated(&meta_page()));
            seal.apply(payload.get_mut(from..).expect("the stream is there"));
            let held = payload.clone();
            let mut out = Cursor::new(Vec::new());
            build_under(
                &mut out,
                Under::sealed(Version::Rpf7, rpf7::ENCRYPTION_AES, &seal),
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

        /// What `stream` inflates to, or nothing at all.
        fn inflated(stream: &[u8]) -> Vec<u8> {
            let mut contents = Vec::new();
            flate2::read::DeflateDecoder::new(stream)
                .take(4096)
                .read_to_end(&mut contents)
                .ok();
            contents
        }

        /// The one entry's payload as it sits on disk, out of a written
        /// archive.
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
            // The severe one. A resource under the archive's own transform is
            // read **decrypted and inflated** — `Archive::resource_stream`
            // recovers the transform, DR-051 — so what a converted write frames
            // back up is contents, and `build::is_sealed` answers `false` for
            // every resource because it is handed payloads as they sit on disk.
            // Written through unsealed, the plaintext lands inside an encrypted
            // archive, and `verify` cannot see it: the read side tries the
            // clear boundary first and finds it. DR-054 §3 is the rule this
            // asserts — an archive is written back under the transform it was
            // read under.
            let (bytes, unlock, on_disk) = sealed_archive();

            // The fixture is the case it claims to be: the payload reads back
            // only under the key.
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

            // The assertion is over the bytes on disk and not over what the
            // reader makes of them, because the reader is what hid this: it
            // tries the clear boundary first and would find plaintext there.
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
            // And the row is the row it was: a converted write moves the
            // payload and nothing else about the entry.
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

        /// The 24-byte prefix, which is the only fixture that can see where a
        /// converted write starts sealing.
        const WIDE_PREFIX: [u8; 24] = [0xFF; 24];

        #[test]
        fn a_converted_write_behind_a_wide_prefix_seals_from_the_streams_own_start() {
            // `a_converted_write_into_a_sealed_archive_lands_as_ciphertext`
            // cannot see this and never could: its prefix is 16 bytes, which is
            // the cipher's own block, so sealing from the payload's start and
            // from the stream's produce byte-identical bytes. The 22 of 7,072
            // resources whose stream begins at 24 are the case where the two
            // differ, and there the reader is the authority: `Decrypting`
            // counts its blocks from the stream's first byte
            // (`archive::resource_stream`), so a payload sealed anywhere else
            // does not read back at all. DR-060 §2.
            let (bytes, unlock, on_disk) = sealed_archive_behind(&WIDE_PREFIX, WIDE_PREFIX.len());
            let mut src = Cursor::new(bytes);
            let archive = Archive::open(&mut src, &unlock).expect("opens");
            let index = archive.find(AT).expect("the entry is there");
            // The fixture is the case it claims to be: keyed, and found at 24.
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

            // Over the raw bytes, and both directions of the one fact. Sealed
            // from the stream: what is at 24 onwards decrypts and inflates.
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
            // And not from the payload's: decrypting the whole and then taking
            // the stream is what a write sealed from 0 would answer, and it is
            // a different arrangement of the same 16-byte blocks.
            let mut from_payload = payload.clone();
            Cipher::over_zeros().apply(&mut from_payload);
            assert_ne!(
                inflated(from_payload.get(WIDE_PREFIX.len()..).unwrap_or_default()).len(),
                512,
                "the written payload was sealed from the payload's start"
            );

            // And it reads back through the archive as the document that was
            // written, which is the whole round trip the two above bound.
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
            // The daemon's own buffer, without the daemon. What `apply`
            // produces for a keyed resource is the payload as it will sit on
            // disk — ciphertext — and the two seams that read a payload in hand
            // have no archive to decrypt it with, so until they were given the
            // entry's own transform this answered `NoXmlView` for a read of the
            // buffer and, worse, let `auto` write the **document** into the
            // entry in place of the payload. DR-061.
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

                // Read back: the buffer answers the document that made it.
                let viewed = of(buffered.clone(), held.clone(), AT, wanted(View::Xml))
                    .expect("a keyed buffer has a view");
                assert!(viewed.xml);
                assert_eq!(String::from_utf8_lossy(&viewed.bytes), EDITED);

                // Written over again, as `auto` — the flow that wrote the
                // document into the archive. What comes back is a payload and
                // not the 133 bytes of the document.
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
                // Sealed as it was found: the stream decrypts from where the
                // entry's own does, and reads back as what was written.
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
            // DR-060. The bytes in front of a resource's deflate stream are
            // nobody's — no Rockstar payload begins with `RSC7` and nothing
            // decrypts those bytes into one (`docs/rpf-format.md`) — so a
            // converted write carries them across rather than replacing them
            // with a header of this build's own devising.
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
            // Two elements over one address have to agree (DR-059). An `RSC7`
            // header's words at offsets 8 and 12 are the same two facts the row
            // carries, and `build::store_resource` takes the payload's when it
            // has them — so a payload in hand whose header declares the
            // boundary somewhere else is not this entry's, and unframing it
            // against the row's flags would answer a document read at an
            // address that is not its own.
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
            // And the write side answers the same, rather than re-framing what
            // the client wrote with the row's flags and losing it.
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

        /// The same 512 bytes with the boundary declared in the wrong place:
        /// no system pages and one graphics page.
        const ELSEWHERE: ResourceFlags = ResourceFlags {
            system: 0x2000_0000,
            graphics: 0xA800_0000,
        };

        #[test]
        fn a_resource_payload_in_hand_is_unframed_at_the_boundary_it_begins_at() {
            // The daemon's case: a client buffers a resource's own bytes over
            // its entry and asks for XML. The boundary is *found* rather than
            // declared (DR-045) — the stream inflates to exactly the length the
            // row's flag words give, at 16 or at 24 — and a payload that
            // answers at neither has no view rather than a guessed one.
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
