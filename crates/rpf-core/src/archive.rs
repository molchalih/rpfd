//! The parsed table of contents of one archive, and reads against it.
//!
//! [`Archive`] holds the table of contents and never the source, so a nested
//! archive is another one parsed at a different base over the same source.

use std::{
    collections::HashMap,
    io::{self, BufReader, Read, Seek, SeekFrom},
    sync::Arc,
};

use crate::{
    entry::{Entry, EntryKind},
    error::{Category, Error, NoWrite, Result},
    format::{
        Header, MAX_HEADER_LEN, Names, Version,
        crypto::{CIPHER_BLOCK_LEN, Cipher, Scheme, Sealer},
        folded,
        resource::{MAGIC_RSC7, RESOURCE_HEADER_LEN, RESOURCE_HEADER_LENS, resource_len},
        same_name,
    },
    keys::{Material, Unlock},
    metadata::Encoding,
};

/// How deep anything in this container is walked before it is refused: policy
/// rather than a format limit, bounding the directory tree and nesting alike.
pub const MAX_DEPTH: u32 = 32;

/// Seeks and fills `buf`, reporting where it was when it failed.
fn read_exact_at<R: Read + Seek>(src: &mut R, offset: u64, buf: &mut [u8]) -> Result<()> {
    src.seek(SeekFrom::Start(offset))
        .map_err(|source| Error::Io { offset, source })?;
    src.read_exact(buf)
        .map_err(|source| Error::Io { offset, source })
}

/// Reads `len` bytes at `offset` into a fresh buffer; the caller must have
/// bounds-checked `len` first, since here it becomes an allocation.
fn read_vec_at<R: Read + Seek>(src: &mut R, offset: u64, len: u64) -> Result<Vec<u8>> {
    let len = usize::try_from(len).map_err(|_| Error::OutOfBounds {
        region: "payload",
        offset,
        len,
        archive_len: u64::MAX,
    })?;
    let mut buf = vec![0u8; len];
    read_exact_at(src, offset, &mut buf)?;
    Ok(buf)
}

/// Where a resource's deflate stream was found, and what inflating it from
/// there produced: the whole of what [`Archive::resource_stream`] settles.
struct Boundary {
    /// Offset of the stream's first byte, inside the archive.
    at: u64,
    /// Length of the stream: the payload's extent less the header in front of
    /// it.
    len: u64,
    /// The transform the stream is under, which the probe recovered along with
    /// the boundary.
    cipher: Option<Cipher>,
    /// What the entry's flag words declare the contents to be, and what the
    /// probe confirmed the stream inflates to.
    expected: u64,
    /// What the probe's own inflate found, for a caller checking the entry
    /// rather than reading it.
    payload: Payload,
}

/// A resource entry taken apart, as [`Archive::resource_unframed`] answers it:
/// the three facts a converted write needs, none of them askable alone.
pub(crate) struct Unframed {
    /// The opaque bytes in front of the deflate stream, as they sit on disk —
    /// sixteen or twenty-four of them ([`RESOURCE_HEADER_LENS`]).
    pub(crate) prefix: Vec<u8>,
    /// What the stream inflates to: the length the entry's flag words declare.
    pub(crate) contents: Vec<u8>,
    /// Whether the stream was found under the archive's own transform.
    pub(crate) sealed: bool,
}

/// What a read of one entry found out about the payload it came out of;
/// `declared` and `used` are both the payload's, and differ without anything
/// having failed, since a deflate stream carries its own end.
pub(crate) struct Payload {
    entry: u32,
    len: u64,
    declared: u64,
    used: u64,
}

impl Payload {
    /// How many bytes the entry holds.
    pub(crate) const fn len(&self) -> u64 {
        self.len
    }

    /// Whether the stream reached the end of the payload it was given.
    ///
    /// # Errors
    ///
    /// [`Error::TrailingBytes`], with both lengths.
    pub(crate) fn checked(&self) -> Result<()> {
        if self.used < self.declared {
            return Err(Error::TrailingBytes {
                entry: self.entry,
                declared: self.declared,
                used: self.used,
            });
        }
        Ok(())
    }
}

/// A seek target from a base and a signed offset.
fn shift(base: u64, delta: i64) -> io::Result<u64> {
    let target = if delta < 0 {
        base.checked_sub(delta.unsigned_abs())
    } else {
        base.checked_add(delta.unsigned_abs())
    };
    target.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek out of range"))
}

/// A failure of the source, on its way out through a [`Read`].
fn source_failed(at: u64, source: io::Error) -> io::Error {
    Error::Io { offset: at, source }.into_io()
}

/// A window on the source: `len` bytes from `at`, addressed from its own start.
/// Every read is clamped to it, so an overrunning stream cannot read past the
/// entry it belongs to.
#[derive(Debug)]
struct Region<S> {
    src: S,
    at: u64,
    len: u64,
    pos: u64,
    /// Whether `src` is where the next read wants it.
    positioned: bool,
}

impl<S> Region<S> {
    const fn new(src: S, at: u64, len: u64) -> Self {
        Self {
            src,
            at,
            len,
            pos: 0,
            positioned: false,
        }
    }
}

impl<S: Read + Seek> Read for Region<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.len.saturating_sub(self.pos);
        if left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let at = self.at;
        if !self.positioned {
            self.src
                .seek(SeekFrom::Start(at.saturating_add(self.pos)))
                .map_err(|source| source_failed(at, source))?;
            self.positioned = true;
        }
        let want = usize::try_from(left).unwrap_or(usize::MAX).min(buf.len());
        let window = buf.get_mut(..want).unwrap_or_default();
        let read = self
            .src
            .read(window)
            .map_err(|source| source_failed(at, source))?;
        if read == 0 {
            // The window is inside the archive's declared extent, so these
            // bytes exist unless the file is shorter than the archive says.
            return Err(source_failed(at, io::ErrorKind::UnexpectedEof.into()));
        }
        self.pos = self.pos.saturating_add(u64::try_from(read).unwrap_or(0));
        Ok(read)
    }
}

impl<S: Read + Seek> Seek for Region<S> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(at) => at,
            SeekFrom::End(delta) => shift(self.len, delta)?,
            SeekFrom::Current(delta) => shift(self.pos, delta)?,
        };
        self.pos = target;
        self.positioned = false;
        Ok(target)
    }
}

/// A region read through a block transform. No chaining, so a block is
/// decrypted where it is read and only one is held; `len` is kept because the
/// sub-block tail is left untransformed.
#[derive(Debug)]
struct Decrypting<R> {
    src: R,
    cipher: Cipher,
    /// How long the transformed region is, so the tail is known in advance.
    len: u64,
    /// How much of the region has been pulled out of `src`.
    consumed: u64,
    /// The block being handed out.
    block: [u8; CIPHER_BLOCK_LEN],
    /// How much of `block` holds bytes.
    filled: usize,
    /// How much of `block` has been handed out.
    taken: usize,
}

impl<R: Read + Seek> Decrypting<R> {
    /// A region of `len` bytes, decrypted as it is read.
    const fn new(src: R, cipher: Cipher, len: u64) -> Self {
        Self {
            src,
            cipher,
            len,
            consumed: 0,
            block: [0_u8; CIPHER_BLOCK_LEN],
            filled: 0,
            taken: 0,
        }
    }

    /// Where the next byte handed out comes from, in the region's own terms.
    fn position(&self) -> u64 {
        let held = u64::try_from(self.filled.saturating_sub(self.taken)).unwrap_or(0);
        self.consumed.saturating_sub(held)
    }

    /// Reads the next block, decrypting it unless it is the sub-block tail;
    /// `filled` is left at zero at the end of the region.
    fn fill(&mut self) -> io::Result<()> {
        self.filled = 0;
        self.taken = 0;
        let left = self.len.saturating_sub(self.consumed);
        if left == 0 {
            return Ok(());
        }
        let want = usize::try_from(left)
            .unwrap_or(CIPHER_BLOCK_LEN)
            .min(CIPHER_BLOCK_LEN);
        let mut got = 0_usize;
        while got < want {
            let window = self.block.get_mut(got..want).unwrap_or_default();
            let read = self.src.read(window)?;
            if read == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            got = got.saturating_add(read);
        }
        self.consumed = self
            .consumed
            .saturating_add(u64::try_from(got).unwrap_or(0));
        if got == CIPHER_BLOCK_LEN {
            self.cipher.block(&mut self.block);
        }
        self.filled = got;
        Ok(())
    }
}

impl<R: Read + Seek> Read for Decrypting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.taken >= self.filled {
            self.fill()?;
            if self.filled == 0 {
                return Ok(0);
            }
        }
        let ready = self.block.get(self.taken..self.filled).unwrap_or_default();
        let want = ready.len().min(buf.len());
        let (Some(target), Some(source)) = (buf.get_mut(..want), ready.get(..want)) else {
            return Ok(0);
        };
        target.copy_from_slice(source);
        self.taken = self.taken.saturating_add(want);
        Ok(want)
    }
}

impl<R: Read + Seek> Seek for Decrypting<R> {
    /// Seeks within the transformed region, landing inside the block that holds
    /// the target.
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(at) => at,
            SeekFrom::End(delta) => shift(self.len, delta)?,
            SeekFrom::Current(delta) => shift(self.position(), delta)?,
        };
        let block = u64::try_from(CIPHER_BLOCK_LEN).unwrap_or(1);
        let start = target.checked_div(block).unwrap_or(0).saturating_mul(block);
        self.src.seek(SeekFrom::Start(start))?;
        self.consumed = start;
        self.filled = 0;
        self.taken = 0;
        let into = usize::try_from(target.saturating_sub(start)).unwrap_or(0);
        if into > 0 {
            self.fill()?;
            self.taken = into.min(self.filled);
        }
        Ok(target)
    }
}

/// A payload's bytes, past whatever transform the archive is under.
#[derive(Debug)]
enum Plain<S> {
    /// Stored in the clear.
    Clear(Region<S>),
    /// Decrypted a block at a time as it is read.
    Keyed(Decrypting<Region<S>>),
}

impl<S: Read + Seek> Plain<S> {
    /// A window on the source, through `cipher` when there is one.
    fn new(src: S, at: u64, len: u64, cipher: Option<Cipher>) -> Self {
        let region = Region::new(src, at, len);
        match cipher {
            None => Self::Clear(region),
            Some(cipher) => Self::Keyed(Decrypting::new(region, cipher, len)),
        }
    }

    /// How many bytes of the window have been read.
    fn pos(&self) -> u64 {
        match *self {
            Self::Clear(ref region) => region.pos,
            Self::Keyed(ref keyed) => keyed.position(),
        }
    }
}

impl<S: Read + Seek> Read for Plain<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            Self::Clear(ref mut region) => region.read(buf),
            Self::Keyed(ref mut keyed) => keyed.read(buf),
        }
    }
}

impl<S: Read + Seek> Seek for Plain<S> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        match *self {
            Self::Clear(ref mut region) => region.seek(to),
            Self::Keyed(ref mut keyed) => keyed.seek(to),
        }
    }
}

/// No transform: the **file** form of a resource, and the first candidate the
/// **contents** form tries.
///
/// Passthrough hands the payload back as it sits on disk, transformed or not.
/// It says nothing about the contents: some resources are under the archive's
/// own transform, so the clear is where the contents form starts, not ends.
const RESOURCE_IS_IN_THE_CLEAR: Option<Cipher> = None;

/// Which of the two forms an entry is read in. They differ for a resource and
/// only for a resource: its file is the `RSC7` header and body as they sit on
/// disk, its contents what that body inflates to.
#[derive(Debug, Clone, Copy)]
enum Form {
    /// The file it is outside the archive. [`Archive::extracted`].
    File,
    /// What the file means, with no container framing left on it.
    /// [`Archive::read`].
    Contents,
}

/// How an entry's bytes come out of its payload.
#[derive(Debug)]
enum Stream<S> {
    /// As they sit on disk, past the archive's transform.
    Stored(Plain<S>),
    /// Inflated as they are read, with the transform under the decompressor:
    /// the archive deflated and then encrypted, so this reverses that order.
    Deflated(flate2::bufread::DeflateDecoder<BufReader<Plain<S>>>),
}

/// One entry as a stream of the bytes it is made of, in either framing.
///
/// A length that does not match the entry's is [`Error::LengthMismatch`] at the
/// end of the read, and every failure carries the [`Error`] it really was
/// ([`Error::carried`]).
#[derive(Debug)]
pub struct Extracted<S> {
    entry: u32,
    /// Where the bytes this yields begin in the source.
    at: u64,
    /// How many bytes the entry says this yields in full.
    len: u64,
    /// How many it has yielded.
    pos: u64,
    /// How many have actually come out of the decompressor: behind
    /// [`Extracted::pos`] by whatever a forward seek passed over. Zero for a
    /// stored stream, whose source seeks.
    inflated: u64,
    /// How many bytes on disk the entry gives the stream.
    declared: u64,
    stream: Stream<S>,
}

impl<S: Read + Seek> Extracted<S> {
    /// A payload read as it sits on disk, through `cipher` if there is one.
    fn stored(entry: u32, src: S, at: u64, len: u64, cipher: Option<Cipher>) -> Self {
        Self {
            entry,
            at,
            len,
            pos: 0,
            inflated: 0,
            declared: len,
            stream: Stream::Stored(Plain::new(src, at, len, cipher)),
        }
    }

    /// A deflated payload, inflated to the `expected` length the entry claims.
    fn deflated(
        entry: u32,
        src: S,
        at: u64,
        on_disk: u64,
        expected: u64,
        cipher: Option<Cipher>,
    ) -> Self {
        Self {
            entry,
            at,
            len: expected,
            pos: 0,
            inflated: 0,
            declared: on_disk,
            stream: Stream::Deflated(flate2::bufread::DeflateDecoder::new(BufReader::new(
                Plain::new(src, at, on_disk, cipher),
            ))),
        }
    }

    /// How many bytes this yields in full, as the entry declares them.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Whether the entry holds nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// How many bytes on disk the entry gives the stream, and how many the
    /// stream occupied — meaningful once it has been read to the end.
    fn extent(&self) -> (u64, u64) {
        let used = match self.stream {
            Stream::Stored(ref plain) => plain.pos(),
            // What the decompressor took, not what it was handed: that is where
            // the stream ends.
            Stream::Deflated(ref decoder) => decoder.total_in(),
        };
        (self.declared, used)
    }

    /// How much to reserve for [`Extracted::whole`]: a stored payload's length
    /// is bounds-checked and sizes an allocation, a deflated payload's is only
    /// what the entry claims and caps the read instead.
    fn reserve(&self) -> usize {
        match self.stream {
            Stream::Stored(_) => usize::try_from(self.len).unwrap_or_default(),
            Stream::Deflated(_) => 0,
        }
    }

    /// The whole of it, in memory.
    ///
    /// # Errors
    ///
    /// Whatever the stream fails with, as the [`Error`] it really was.
    fn whole(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.reserve());
        let at = self.at;
        self.read_to_end(&mut out)
            .map_err(|source| Error::recovered(at, source))?;
        Ok(out)
    }

    /// All of it, kept nowhere, and how many bytes that was.
    ///
    /// # Errors
    ///
    /// Whatever the stream fails with, as the [`Error`] it really was.
    fn drained(&mut self) -> Result<u64> {
        let at = self.at;
        io::copy(self, &mut io::sink()).map_err(|source| Error::recovered(at, source))
    }

    /// Puts a deflated stream back at its start, which means inflating it
    /// again from there.
    fn restart(&mut self) -> io::Result<()> {
        if let Stream::Deflated(ref mut decoder) = self.stream {
            decoder.reset_data();
            decoder.get_mut().seek(SeekFrom::Start(0))?;
        }
        self.pos = 0;
        self.inflated = 0;
        Ok(())
    }

    /// Inflates into `buf`, one byte past what the entry promises at most, so
    /// an over-long payload is caught rather than truncated. The bound is over
    /// [`Extracted::inflated`], which a forward seek does not move.
    fn inflate(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (entry, expected) = (self.entry, self.len);
        let limit = expected.checked_add(1).ok_or_else(|| {
            Error::LengthMismatch {
                entry,
                expected,
                actual: u64::MAX,
            }
            .into_io()
        })?;
        let room = limit.saturating_sub(self.inflated);
        let want = usize::try_from(room).unwrap_or(usize::MAX).min(buf.len());
        let window = buf.get_mut(..want).unwrap_or_default();
        if window.is_empty() {
            return Ok(0);
        }
        let Stream::Deflated(ref mut decoder) = self.stream else {
            return Ok(0);
        };
        let read = decoder
            .read(window)
            .map_err(|source| inflating(entry, source))?;
        self.inflated = self
            .inflated
            .saturating_add(u64::try_from(read).unwrap_or(0));
        Ok(read)
    }

    /// Inflates and discards whatever a forward seek passed over, bounded by
    /// the entry's length; a short stream leaves the position where it stopped.
    fn catch_up(&mut self) -> io::Result<()> {
        let target = self.pos.min(self.len);
        let mut discarded = [0_u8; 8 * 1024];
        while self.inflated < target {
            let want = usize::try_from(target.saturating_sub(self.inflated))
                .unwrap_or(usize::MAX)
                .min(discarded.len());
            let read = self.inflate(discarded.get_mut(..want).unwrap_or_default())?;
            if read == 0 {
                self.pos = self.inflated;
                break;
            }
        }
        Ok(())
    }
}

/// A failure out of the decompressor, unless it is the source's own coming
/// back through it.
fn inflating(entry: u32, source: io::Error) -> io::Error {
    match Error::carried(source) {
        Ok(carried) => carried.into_io(),
        Err(source) => Error::Inflate { entry, source }.into_io(),
    }
}

impl<S: Read + Seek> Read for Extracted<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let (entry, expected) = (self.entry, self.len);
        let read = match self.stream {
            Stream::Stored(ref mut plain) => plain.read(buf)?,
            Stream::Deflated(_) => {
                // Whatever a forward seek passed over is inflated here, at the
                // read that needs it.
                self.catch_up()?;
                self.inflate(buf)?
            }
        };

        // Both checks are the deflated stream's: a stored payload ends where
        // its window does.
        if read == 0 {
            if self.pos < expected {
                return Err(Error::LengthMismatch {
                    entry,
                    expected,
                    actual: self.pos,
                }
                .into_io());
            }
            return Ok(0);
        }
        self.pos = self.pos.saturating_add(u64::try_from(read).unwrap_or(0));
        if self.pos > expected {
            return Err(Error::LengthMismatch {
                entry,
                expected,
                actual: self.pos,
            }
            .into_io());
        }
        Ok(read)
    }
}

impl<S: Read + Seek> Seek for Extracted<S> {
    /// Seeks within the entry, whose length is known without reading it. A
    /// deflated stream has no position but the one it has inflated to, so
    /// backwards restarts it and forwards only moves the position — which keeps
    /// a measuring seek to the end from inflating anything.
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(at) => at,
            SeekFrom::End(delta) => shift(self.len, delta)?,
            SeekFrom::Current(delta) => shift(self.pos, delta)?,
        };
        if let Stream::Stored(ref mut plain) = self.stream {
            plain.seek(SeekFrom::Start(target))?;
            self.pos = target;
            return Ok(target);
        }

        if target < self.pos {
            self.restart()?;
        }
        // Forward costs nothing: the position moves, the decompressor stays,
        // and `catch_up` inflates the gap at the read that needs it.
        self.pos = target;
        Ok(target)
    }
}

/// The table of contents of one archive.
#[derive(Debug, Clone)]
pub struct Archive {
    base: u64,
    len: u64,
    version: Version,
    encryption: u32,
    /// How many archives this one sits inside, counted against [`MAX_DEPTH`].
    depth: u32,
    /// What opened this archive and what opens the archives nested in it,
    /// normalised at parse so a cache is consulted once rather than per read.
    unlock: Unlock,
    /// The transform this archive's own payloads are under, or `None` when it
    /// is not encrypted; `Some` implies the material for it is in `unlock`.
    scheme: Option<Scheme>,
    entries: Vec<Entry>,
    names: Names,
    parents: Vec<Option<u32>>,
}

impl Archive {
    /// Parses the archive that begins at `base` and runs for `len` bytes.
    ///
    /// `len` is the archive's own extent — for a nested archive the size of the
    /// entry that holds it — and every offset inside is checked against it.
    ///
    /// # Errors
    ///
    /// [`Error::NotAnArchive`], [`Error::UnsupportedVersion`],
    /// [`Error::NeedsKey`], [`Error::WrongKey`], and the bounds variants for a
    /// header describing regions that do not fit.
    pub fn parse<R: Read + Seek>(
        src: &mut R,
        base: u64,
        len: u64,
        unlock: &Unlock,
    ) -> Result<Self> {
        // Parsed by name rather than through a holder: nested inside nothing.
        Self::parse_nested(src, base, len, 0, unlock)
    }

    /// [`Archive::parse`], told how many archives it already sits inside, which
    /// is the caller's to supply because it is not in the bytes.
    fn parse_nested<R: Read + Seek>(
        src: &mut R,
        base: u64,
        len: u64,
        depth: u32,
        unlock: &Unlock,
    ) -> Result<Self> {
        if depth > MAX_DEPTH {
            return Err(Error::TooDeep {
                what: "archive nesting",
                depth,
                limit: MAX_DEPTH,
            });
        }

        let Header {
            version,
            entry_count,
            names_len,
            encryption,
        } = read_header(src, base)?;

        // Decided before any of the layout below is believed, so an archive
        // nobody can open says so rather than being called malformed.
        let opening = opening_for(version, encryption, unlock)?;

        let table_at = version.header_len();

        let table_len = u64::from(entry_count)
            .checked_mul(version.row_len())
            .ok_or(Error::OutOfBounds {
                region: "entry table",
                offset: table_at,
                len: u64::MAX,
                archive_len: len,
            })?;
        let names_at = table_at.checked_add(table_len).ok_or(Error::OutOfBounds {
            region: "entry table",
            offset: table_at,
            len: table_len,
            archive_len: len,
        })?;
        // Checked first, so a header claiming more entries than the file can
        // hold names the entry table rather than the blob.
        if names_at > len {
            return Err(Error::OutOfBounds {
                region: "entry table",
                offset: table_at,
                len: table_len,
                archive_len: len,
            });
        }
        let names_end = names_at
            .checked_add(u64::from(names_len))
            .ok_or(Error::OutOfBounds {
                region: "names blob",
                offset: names_at,
                len: u64::from(names_len),
                archive_len: len,
            })?;
        if names_end > len {
            return Err(Error::OutOfBounds {
                region: "names blob",
                offset: names_at,
                len: u64::from(names_len),
                archive_len: len,
            });
        }

        let mut table = read_vec_at(src, base.checked_add(table_at).unwrap_or(base), table_len)?;
        let mut names_blob = read_vec_at(
            src,
            base.checked_add(names_at).unwrap_or(base),
            u64::from(names_len),
        )?;

        // Decrypted before a single row is decoded. The key is chosen by this
        // archive's own name and length, both of which the caller supplied.
        let (unlock, scheme) = match opening {
            None => (unlock.clone(), None),
            Some(opening) => decrypt_table_of_contents(
                version,
                len,
                unlock,
                opening,
                &mut table,
                &mut names_blob,
            )?,
        };

        let entries = parse_entries(version, &table, entry_count)?;

        // Located once, here, so that `name` has nothing left to find.
        let names = Names::parse(version, names_blob, &entries)?;

        let parents = parse_parents(&entries)?;

        Ok(Self {
            base,
            len,
            version,
            encryption,
            depth,
            unlock,
            scheme,
            entries,
            names,
            parents,
        })
    }

    /// Parses the archive occupying the whole of `src`.
    ///
    /// # Errors
    ///
    /// As [`Archive::parse`], plus [`Error::Io`] if the length cannot be found.
    pub fn open<R: Read + Seek>(src: &mut R, unlock: &Unlock) -> Result<Self> {
        let len = src
            .seek(SeekFrom::End(0))
            .map_err(|source| Error::Io { offset: 0, source })?;
        Self::parse(src, 0, len, unlock)
    }

    /// Where this archive begins in the source.
    #[must_use]
    pub const fn base(&self) -> u64 {
        self.base
    }

    /// How long this archive is.
    #[must_use]
    pub const fn len_bytes(&self) -> u64 {
        self.len
    }

    /// The container version this archive is.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    /// The archive's encryption tag, exactly as the header carries it.
    #[must_use]
    pub const fn encryption(&self) -> u32 {
        self.encryption
    }

    /// Which transform this archive's bytes were under, or `None` when it is
    /// not encrypted. A name, never a key.
    #[must_use]
    pub fn scheme(&self) -> Option<&'static str> {
        self.scheme.map(Scheme::named)
    }

    /// Whether this archive can be written back at all: an unencrypted one can,
    /// and so can one whose transform this build can run forwards over the
    /// material it was opened with ([`Scheme::seals`]).
    ///
    /// # Errors
    ///
    /// [`Error::CannotWriteEncrypted`] with [`NoWrite::NoInverse`] for a
    /// transform this build cannot run forwards, which no flag overrides.
    pub fn writable(&self) -> Result<()> {
        match self.scheme {
            None => Ok(()),
            Some(scheme) if scheme.seals(self.unlock.held_material().map(AsRef::as_ref)) => Ok(()),
            Some(_) => Err(Error::CannotWriteEncrypted {
                tag: self.encryption,
                reason: NoWrite::NoInverse,
            }),
        }
    }

    /// What re-encrypts this archive's own bytes, or `None` when it is not
    /// encrypted.
    ///
    /// A [`Sealer`] rather than a finished seal because an NG key is chosen by
    /// the region's own name and length. Entry rows are resealed one at a time,
    /// so a version whose row is not one aligned cipher block is refused.
    ///
    /// # Errors
    ///
    /// As [`Archive::writable`], and [`Error::WrongKey`] for an encrypted
    /// archive with no material in hand.
    pub fn seal(&self) -> Result<Option<Sealer>> {
        self.writable()?;
        let Some(scheme) = self.scheme else {
            return Ok(None);
        };
        if !self.version.row_is_a_cipher_block() {
            return Err(Error::CannotWriteEncrypted {
                tag: self.encryption,
                reason: NoWrite::NoInverse,
            });
        }
        let wrong = || Error::WrongKey {
            tag: self.encryption,
            scheme: scheme.named(),
            tried: 1,
        };
        let material = self.unlock.held_material().ok_or_else(wrong)?;
        Sealer::new(scheme, material)
            .map(Some)
            .ok_or_else(|| match scheme {
                Scheme::Ng => Error::CannotWriteEncrypted {
                    tag: self.encryption,
                    reason: NoWrite::NoInverse,
                },
                Scheme::Aes(_) => wrong(),
            })
    }

    /// The archive's own name, which is half of what its table of contents and
    /// names blob are keyed by: the name it was opened under, and the one a
    /// rebuild renames back over rather than the scratch file's.
    pub(crate) fn keyed_name(&self) -> &str {
        self.unlock.name()
    }

    /// Every entry, in table order. Entry 0 is the root directory.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The names blob exactly as it appears on disk.
    #[must_use]
    pub fn names_blob(&self) -> &[u8] {
        self.names.blob()
    }

    /// One entry by index.
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchEntry`] if the index is past the end.
    pub fn entry(&self, index: u32) -> Result<&Entry> {
        let at = usize::try_from(index)
            .ok()
            .and_then(|i| self.entries.get(i));
        at.ok_or(Error::NoSuchEntry {
            index,
            entry_count: count_of(&self.entries),
        })
    }

    /// One entry's own name, without its parents.
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchEntry`] past the end, [`Error::BadName`] for a name that
    /// is not UTF-8.
    pub fn name(&self, index: u32) -> Result<&str> {
        self.names.at(index)
    }

    /// The full path of an entry from the archive root, the root itself being
    /// the empty string. The walk up the parent map needs no guard: every child
    /// index is greater than its parent's, so each step decreases.
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchEntry`] if the index, or any ancestor, is past the end.
    pub fn path(&self, index: u32) -> Result<String> {
        let mut parts = Vec::new();
        let mut at = index;
        loop {
            let parent = usize::try_from(at)
                .ok()
                .and_then(|i| self.parents.get(i))
                .copied()
                .ok_or(Error::NoSuchEntry {
                    index: at,
                    entry_count: count_of(&self.entries),
                })?;
            let Some(parent) = parent else { break };
            parts.push(self.name(at)?);
            at = parent;
        }
        parts.reverse();
        Ok(parts.join("/"))
    }

    /// Refuses an archive in which two children of one directory fold to one
    /// name, leaving the second unreachable by any spelling of its path. Such
    /// an archive is legal in the format, so what is refused is turning it into
    /// a tree rather than parsing it.
    ///
    /// # Errors
    ///
    /// As `Archive::one_name_twice` and [`Archive::path`].
    pub fn check_names(&self) -> Result<()> {
        let mut seen: HashMap<(u32, String), u32> = HashMap::new();
        for index in 0..count_of(&self.entries) {
            let parent = usize::try_from(index)
                .ok()
                .and_then(|i| self.parents.get(i))
                .copied()
                .ok_or(Error::NoSuchEntry {
                    index,
                    entry_count: count_of(&self.entries),
                })?;
            // The root is nobody's child, so it has no sibling to collide with.
            let Some(parent) = parent else { continue };
            if let Some(first) = seen.insert((parent, folded(self.name(index)?)), index) {
                return Err(self.one_name_twice(first, index)?);
            }
        }
        Ok(())
    }

    /// The refusal for two children of one directory that are one name here,
    /// returned rather than raised so its two callers spell it one way.
    ///
    /// # Errors
    ///
    /// [`Error::NameCollision`] for two spellings of one name,
    /// [`Error::BadPath`] for one name carried by two entries, and as
    /// [`Archive::path`].
    fn one_name_twice(&self, first: u32, second: u32) -> Result<Error> {
        let path = self.path(second)?;
        if self.name(first)? != self.name(second)? {
            return Ok(Error::NameCollision {
                path,
                other: self.path(first)?,
            });
        }
        let reason = if self.entry(first)?.is_directory() == self.entry(second)?.is_directory() {
            "is named twice in one directory"
        } else {
            "a file and a directory share one name"
        };
        Ok(Error::BadPath { path, reason })
    }

    /// How an entry is named in a failure: its path from this archive's root,
    /// or `entry N` when the tree does not resolve far enough to give it one.
    fn named(&self, index: u32) -> String {
        self.path(index)
            .unwrap_or_else(|_| format!("entry {index}"))
    }

    /// The indices of a directory's children.
    ///
    /// # Errors
    ///
    /// [`Error::WrongKind`] if the entry is not a directory.
    pub fn children(&self, index: u32) -> Result<std::ops::Range<u32>> {
        let entry = self.entry(index)?;
        match entry.kind {
            EntryKind::Directory {
                first_child,
                child_count,
            } => {
                let end = first_child
                    .checked_add(child_count)
                    .ok_or(Error::BadChildRange {
                        entry: index,
                        first: first_child,
                        count: child_count,
                        entry_count: count_of(&self.entries),
                    })?;
                Ok(first_child..end)
            }
            other => Err(Error::WrongKind {
                path: self.named(index),
                found: other.noun(),
                wanted: "directory",
            }),
        }
    }

    /// Where an entry's payload begins, and how long its row says it is, with
    /// nothing checked — read literally, so that placing a saturated entry's
    /// neighbours cannot ask [`Archive::payload_span`] back.
    fn declared_span(&self, index: u32) -> Result<(u64, u64)> {
        let entry = self.entry(index)?;
        let (block, on_disk) = match entry.kind {
            EntryKind::Directory { .. } => {
                return Err(Error::WrongKind {
                    path: self.named(index),
                    found: "directory",
                    wanted: "file",
                });
            }
            EntryKind::Binary {
                block,
                compressed_len,
                uncompressed_len,
                ..
            } => {
                // Compressed size zero means stored, and then the other field
                // carries the real length.
                let len = if compressed_len == 0 {
                    uncompressed_len
                } else {
                    compressed_len
                };
                (block, u64::from(len))
            }
            // No stored sentinel: a resource's two trailing words are both
            // page flags, so one declaring zero has no length to recover and is
            // refused for being smaller than its own `RSC7` header.
            EntryKind::Resource {
                block,
                compressed_len,
                ..
            } => (block, u64::from(compressed_len)),
        };

        let relative = u64::from(block)
            .checked_mul(self.version.block_len())
            .ok_or(Error::OutOfBounds {
                region: "payload",
                offset: 0,
                len: on_disk,
                archive_len: self.len,
            })?;
        Ok((relative, on_disk))
    }

    /// Whether this entry's compressed-size field has run out of room to
    /// describe its own payload: the field is 24 bits and saturates to a
    /// sentinel, so believing it hands the inflater a truncated stream. Only a
    /// resource is asked; a binary entry says it with the zero sentinel instead.
    fn size_field_saturated(&self, index: u32) -> Result<bool> {
        Ok(matches!(
            self.entry(index)?.kind,
            EntryKind::Resource { compressed_len, .. }
                if self.version.size_field_saturates(u64::from(compressed_len))
        ))
    }

    /// How many bytes a payload beginning at `relative` has before the next one
    /// begins, over what the rows declare rather than what they mean.
    fn room_from(&self, index: u32, relative: u64) -> u64 {
        let count = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        let mut end = self.len;
        for other in 0..count {
            if other == index {
                continue;
            }
            let Ok((at, _)) = self.declared_span(other) else {
                continue;
            };
            if at > relative && at < end {
                end = at;
            }
        }
        end.saturating_sub(relative)
    }

    /// Where an entry's payload begins in the source, and how long it is,
    /// bounds-checked against this archive's own extent. The length is the
    /// row's, except where the row could not hold it: a resource whose size
    /// field has saturated takes the room its neighbours leave it.
    fn payload_span(&self, index: u32) -> Result<(u64, u64)> {
        let (relative, declared) = self.declared_span(index)?;
        // A payload lies after the names blob. Without this floor an entry at
        // block 0 reads the table of contents back as file contents.
        let floor = self.version.payload_floor(
            u64::try_from(self.entries.len()).unwrap_or(u64::MAX),
            u64::try_from(self.names.blob().len()).unwrap_or(u64::MAX),
        );
        if relative < floor {
            return Err(Error::PayloadUnderflow {
                entry: index,
                offset: relative,
                floor,
            });
        }

        let on_disk = if self.size_field_saturated(index)? {
            self.room_from(index, relative)
        } else {
            declared
        };
        let end = relative.checked_add(on_disk).ok_or(Error::OutOfBounds {
            region: "payload",
            offset: relative,
            len: on_disk,
            archive_len: self.len,
        })?;
        if end > self.len {
            return Err(Error::OutOfBounds {
                region: "payload",
                offset: relative,
                len: on_disk,
                archive_len: self.len,
            });
        }

        let absolute = self.base.checked_add(relative).ok_or(Error::OutOfBounds {
            region: "payload",
            offset: relative,
            len: on_disk,
            archive_len: self.len,
        })?;
        Ok((absolute, on_disk))
    }

    /// The payload extent of every file entry, relative to this archive's base.
    ///
    /// # Errors
    ///
    /// As [`Archive::entry`], and the bounds variants.
    pub fn payload_extents(&self) -> Result<Vec<(u32, u64, u64)>> {
        let count = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        let mut out = Vec::new();
        for index in 0..count {
            if self.entry(index)?.is_directory() {
                continue;
            }
            let (absolute, len) = self.payload_span(index)?;
            out.push((index, absolute.saturating_sub(self.base), len));
        }
        Ok(out)
    }

    /// How many bytes an entry's payload may occupy without moving.
    ///
    /// Room a caller may write into, so it stops at the first byte any other
    /// payload claims from this one's start onwards, not at the next to begin
    /// strictly later: an entry sharing or straddling this start makes the
    /// answer zero, which [`crate::patch::plan`] rests on.
    ///
    /// # Errors
    ///
    /// As [`Archive::payload_extents`], plus [`Error::NoSuchEntry`] or
    /// [`Error::WrongKind`] for an index that is not a file here.
    pub fn allocation(&self, index: u32) -> Result<u64> {
        // Resolved before the extents are searched, so an index that is not an
        // entry at all says so rather than looking like the wrong kind.
        let (absolute, _) = self.payload_span(index)?;
        let start = absolute.saturating_sub(self.base);

        let end = self
            .payload_extents()?
            .iter()
            .filter(|(at, _, _)| *at != index)
            .filter_map(|(_, other, len)| {
                let other_end = other.saturating_add(*len);
                (other_end > start).then_some((*other).max(start))
            })
            .min()
            .unwrap_or(self.len);
        Ok(end.saturating_sub(start))
    }

    /// Where an entry's payload begins, absolutely, and how long it is now.
    ///
    /// # Errors
    ///
    /// As [`Archive::payload_extents`].
    pub fn payload_at(&self, index: u32) -> Result<(u64, u64)> {
        self.payload_span(index)
    }

    /// Where this entry's row begins in the source.
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchEntry`] if the index is past the end.
    pub fn row_at(&self, index: u32) -> Result<u64> {
        let _ = self.entry(index)?;
        let offset = self
            .version
            .row_at(index)
            .and_then(|at| self.base.checked_add(at))
            .ok_or(Error::OutOfBounds {
                region: "entry table",
                offset: self.version.header_len(),
                len: self.version.row_len(),
                archive_len: self.len,
            })?;
        Ok(offset)
    }

    /// Reads an entry's **contents**: what the file means, with no container
    /// framing left on it.
    ///
    /// A binary entry inflates to its declared length; a resource has its
    /// 16-byte `RSC7` header removed and the remainder inflated. A payload
    /// whose stream ends early still reads back, and [`crate::Verified`]
    /// reports the bytes after it as trailing.
    ///
    /// # Errors
    ///
    /// [`Error::WrongKind`] for a directory, the bounds variants, and
    /// [`Error::Inflate`] or [`Error::LengthMismatch`] for a payload that does
    /// not decompress as promised.
    pub fn read<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Vec<u8>> {
        self.opened(src, index, Form::Contents)?.whole()
    }

    /// One **resource** taken apart the way a converted write has to put it
    /// back together: the opaque bytes in front of its stream, what the stream
    /// inflates to, and whether the payload sits under the archive's transform.
    ///
    /// All three come from one probe, so a caller cannot read the contents
    /// under a key and write them back without one. The prefix is never
    /// decrypted and crosses verbatim.
    ///
    /// # Errors
    ///
    /// [`Error::WrongKind`] for an entry that is not a resource, and as
    /// [`Archive::read`].
    pub(crate) fn resource_unframed<R: Read + Seek>(
        &self,
        src: &mut R,
        index: u32,
    ) -> Result<Unframed> {
        let (offset, _) = self.payload_span(index)?;
        let found = self.resource_stream(src, index)?;
        let header = usize::try_from(found.at.saturating_sub(offset)).unwrap_or(0);
        let mut prefix = vec![0_u8; header];
        src.seek(SeekFrom::Start(offset))
            .and_then(|_| src.read_exact(&mut prefix))
            .map_err(|source| Error::Io { offset, source })?;
        let sealed = found.cipher.is_some();
        let contents = Extracted::deflated(
            index,
            &mut *src,
            found.at,
            found.len,
            found.expected,
            found.cipher,
        )
        .whole()?;
        Ok(Unframed {
            prefix,
            contents,
            sealed,
        })
    }

    /// The archive's own transform as a payload of the **resource** entry at
    /// `index` needs it, in both directions: one seam takes a payload apart and
    /// the other puts what it produced back under the same transform.
    ///
    /// `in_hand` is the length of a payload the caller holds, `None` the
    /// entry's own; it keys the cipher, because the NG key index is a function
    /// of the payload's length on disk. The sealer is `None` only for a
    /// transform this build cannot run forwards, which the write refuses.
    ///
    /// # Errors
    ///
    /// As [`Archive::name`], and whatever [`Archive::seal`] refuses with other
    /// than the write's own missing inverse.
    pub(crate) fn resource_transform(
        &self,
        index: u32,
        in_hand: Option<u64>,
    ) -> Result<(Option<Cipher>, Option<Arc<Sealer>>)> {
        let len = match in_hand {
            Some(len) => len,
            None => self.payload_span(index)?.1,
        };
        let sealer = match self.seal() {
            Ok(sealer) => sealer,
            Err(Error::CannotWriteEncrypted { .. }) => None,
            Err(other) => return Err(other),
        };
        Ok((self.resource_cipher(index, len)?, sealer.map(Arc::new)))
    }

    /// The archive's own encryption tag, which a refusal to write one names.
    #[must_use]
    pub(crate) const fn encryption_tag(&self) -> u32 {
        self.encryption
    }

    /// [`Archive::read`] for a caller checking an entry rather than using it:
    /// only what the read learned about the payload comes back.
    ///
    /// # Errors
    ///
    /// As [`Archive::read`].
    pub(crate) fn read_back<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Payload> {
        // The probe that recovers a resource's boundary already answers
        // everything this reports; going through `opened` would inflate twice.
        if let EntryKind::Resource { .. } = self.entry(index)?.kind {
            return self.resource_stream(src, index).map(|found| found.payload);
        }
        let mut stream = self.opened(src, index, Form::Contents)?;
        let len = stream.drained()?;
        let (declared, used) = stream.extent();
        Ok(Payload {
            entry: index,
            len,
            declared,
            used,
        })
    }

    /// Where a resource's deflate stream begins inside its payload, and what
    /// inflating it from there found.
    ///
    /// The header length is neither declared nor derivable — offsets 8 and 12
    /// are both flag words, and entries with identical flags begin at 16 and at
    /// 24 ([`RESOURCE_HEADER_LENS`]) — so a candidate is accepted when the
    /// stream there inflates to exactly the length the flag words give. The
    /// transform is recovered the same way, every boundary in the clear first.
    ///
    /// # Errors
    ///
    /// [`Error::ResourceTooSmall`] for a payload no candidate fits inside, and
    /// otherwise whatever the **first** candidate failed with.
    fn resource_stream<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Boundary> {
        let (offset, on_disk) = self.payload_span(index)?;
        let EntryKind::Resource {
            compressed_len,
            system_flags,
            graphics_flags,
            ..
        } = self.entry(index)?.kind
        else {
            return Err(Error::WrongKind {
                path: self.named(index),
                found: self.entry(index)?.kind.noun(),
                wanted: "resource file",
            });
        };
        let expected = resource_len(system_flags, graphics_flags);
        let too_small = Error::ResourceTooSmall {
            entry: index,
            compressed_len,
        };
        // A saturated size field bounds nothing, so there is no shortfall to
        // report against it: the payload's end is then the stream's own.
        let saturated = self.size_field_saturated(index)?;
        let mut first: Option<Error> = None;

        for keyed in [false, true] {
            let cipher = if keyed {
                match self.resource_cipher(index, on_disk)? {
                    Some(cipher) => Some(cipher),
                    None => break,
                }
            } else {
                RESOURCE_IS_IN_THE_CLEAR
            };
            for header in RESOURCE_HEADER_LENS {
                let (Some(stream_len), Some(at)) =
                    (on_disk.checked_sub(header), offset.checked_add(header))
                else {
                    continue;
                };
                let mut stream =
                    Extracted::deflated(index, &mut *src, at, stream_len, expected, cipher.clone());
                match stream.drained() {
                    Ok(len) => {
                        let (declared, used) = stream.extent();
                        return Ok(Boundary {
                            at,
                            len: stream_len,
                            cipher,
                            expected,
                            payload: Payload {
                                entry: index,
                                len,
                                declared: if saturated { used } else { declared },
                                used,
                            },
                        });
                    }
                    Err(error) => first.get_or_insert(error),
                };
            }
        }
        Err(first.unwrap_or(too_small))
    }

    /// The archive's own transform, keyed for this **resource** payload, or
    /// `None` where this build holds nothing to key it with.
    ///
    /// The key is chosen by the payload's length on disk, the opposite of the
    /// binary-entry rule, as [`Version::resource_key_len`] gives it.
    fn resource_cipher(&self, index: u32, on_disk: u64) -> Result<Option<Cipher>> {
        let Some(scheme) = self.scheme else {
            return Ok(None);
        };
        let Some(material) = self.unlock.held_material() else {
            return Ok(None);
        };
        let len = self.version.resource_key_len(on_disk);
        Ok(Cipher::new(scheme, material, self.name(index)?, len))
    }

    /// One entry as a stream of the file it is **outside the archive**: the
    /// streaming form of [`Archive::extract`], which never holds the entry.
    /// `src` is taken by value, so nothing else may read it until the stream
    /// is dropped.
    ///
    /// # Errors
    ///
    /// [`Error::WrongKind`] for a directory, [`Error::ResourceTooSmall`] for a
    /// resource that cannot hold its own header, and the bounds variants.
    pub fn extracted<S: Read + Seek>(&self, src: S, index: u32) -> Result<Extracted<S>> {
        self.opened(src, index, Form::File)
    }

    /// The transform one entry's payload is under, if it is under one.
    ///
    /// A binary entry is under the archive's transform exactly when its own
    /// per-entry encryption field says so. A resource has no such field and is
    /// not asked here; [`Archive::resource_cipher`] reads instead.
    fn payload_cipher(&self, index: u32, contents_len: u32) -> Result<Cipher> {
        let scheme = self.scheme.ok_or(Error::NeedsKey {
            tag: self.encryption,
        })?;
        let wrong = || Error::WrongKey {
            tag: self.encryption,
            scheme: scheme.named(),
            tried: 1,
        };
        let material = self.unlock.held_material().ok_or_else(wrong)?;
        let name = self.name(index)?;
        Cipher::new(scheme, material, name, u64::from(contents_len)).ok_or_else(wrong)
    }

    /// The one place a payload becomes a stream, in either framing (§3).
    fn opened<S: Read + Seek>(&self, src: S, index: u32, form: Form) -> Result<Extracted<S>> {
        let (offset, on_disk) = self.payload_span(index)?;
        let entry = self.entry(index)?;

        match entry.kind {
            EntryKind::Directory { .. } => Err(Error::WrongKind {
                path: self.named(index),
                found: "directory",
                wanted: "file",
            }),

            // Compression decides a binary entry, and one answer serves both
            // framings: outside the archive it is what it means.
            EntryKind::Binary {
                compressed_len,
                uncompressed_len,
                encryption,
                ..
            } => {
                let cipher = if self.scheme.is_some() && !self.version.entry_is_open(encryption) {
                    Some(self.payload_cipher(index, uncompressed_len)?)
                } else {
                    None
                };
                Ok(if compressed_len == 0 {
                    Extracted::stored(index, src, offset, on_disk, cipher)
                } else {
                    Extracted::deflated(
                        index,
                        src,
                        offset,
                        on_disk,
                        u64::from(uncompressed_len),
                        cipher,
                    )
                })
            }

            EntryKind::Resource { compressed_len, .. } => match form {
                Form::File => {
                    if u64::from(compressed_len) < RESOURCE_HEADER_LEN {
                        return Err(Error::ResourceTooSmall {
                            entry: index,
                            compressed_len,
                        });
                    }
                    Ok(Extracted::stored(
                        index,
                        src,
                        offset,
                        on_disk,
                        RESOURCE_IS_IN_THE_CLEAR,
                    ))
                }
                // The probe already settled the start, length, transform and
                // expected extent, so nothing here recomputes them.
                Form::Contents => {
                    let mut src = src;
                    let found = self.resource_stream(&mut src, index)?;
                    Ok(Extracted::deflated(
                        index,
                        src,
                        found.at,
                        found.len,
                        found.expected,
                        found.cipher,
                    ))
                }
            },
        }
    }

    /// Reads an entry as the **file it is outside the archive**.
    ///
    /// The difference from [`Archive::read`] is resources: this keeps the
    /// 16-byte `RSC7` header and leaves the body deflated, so an entry we
    /// cannot interpret round-trips byte for byte.
    ///
    /// # Errors
    ///
    /// As [`Archive::read`].
    pub fn extract<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Vec<u8>> {
        self.extracted(src, index)?.whole()
    }

    /// What an entry is, and what its payload announces itself to be.
    ///
    /// A resource is read off the entry's resource bit and its payload never
    /// touched, since a Rockstar resource payload does not begin with `RSC7`.
    /// Everything else is decided by the first [`Encoding::HEAD_LEN`] bytes of
    /// the contents, inflated, and a payload that cannot be read at all is
    /// [`Classification::Binary`].
    ///
    /// # Errors
    ///
    /// As [`Archive::entry`].
    pub fn classify<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Classification> {
        match self.entry(index)?.kind {
            EntryKind::Directory { .. } => Ok(Classification::Directory),
            EntryKind::Resource { .. } => Ok(Classification::Resource),
            EntryKind::Binary { .. } => {
                let (head, len) = self.head(src, index);
                Ok(match Encoding::of(head.get(..len).unwrap_or_default()) {
                    Some(encoding) => Classification::Encoded(encoding),
                    None => Classification::Binary,
                })
            }
        }
    }

    /// The first [`Encoding::HEAD_LEN`] bytes of an entry's contents, and how
    /// many of them there were — without the count a caller reads the zero
    /// filler as content. Short by any means is short rather than an error.
    fn head<R: Read + Seek>(&self, src: &mut R, index: u32) -> ([u8; Encoding::HEAD_LEN], usize) {
        let mut head = [0_u8; Encoding::HEAD_LEN];
        let Ok(mut contents) = self.extracted(&mut *src, index) else {
            return (head, 0);
        };
        let mut got = 0_usize;
        while let Some(rest) = head.get_mut(got..) {
            match contents.read(rest) {
                Ok(0) | Err(_) => break,
                Ok(read) => got = got.saturating_add(read),
            }
            if got >= Encoding::HEAD_LEN {
                break;
            }
        }
        (head, got)
    }

    /// Whether an entry's payload begins with the `RSC7` magic. Not a
    /// classifier: in a Rockstar archive this answers `false` on every resource
    /// there is, and the entry's resource bit is the only truth.
    ///
    /// # Errors
    ///
    /// As [`Archive::read`] for the bounds cases.
    pub fn payload_is_resource<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<bool> {
        let (offset, on_disk) = self.payload_span(index)?;
        if on_disk < 4 {
            return Ok(false);
        }
        let mut magic = [0u8; 4];
        read_exact_at(src, offset, &mut magic)?;
        Ok(magic == MAGIC_RSC7)
    }

    /// Finds an entry by path **within this archive**, not descending into any
    /// archive nested in it. Matching is [`same_name`] and the empty path is
    /// the root directory.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] naming the component that failed, a mid-path
    /// component that is not a directory included.
    pub fn find(&self, path: &str) -> Result<u32> {
        let mut current = 0_u32;
        for segment in path.split('/').filter(|s| !s.is_empty()) {
            current = self
                .child_named(current, segment)?
                .ok_or_else(|| Error::NotFound {
                    path: path.to_owned(),
                    segment: segment.to_owned(),
                })?;
        }
        Ok(current)
    }

    /// The child of `parent` with this name, or `None` if `parent` is not a
    /// directory or has no such child.
    ///
    /// Ambiguity is refused rather than resolved: folding case, two children
    /// can answer to one spelling, and this is the only resolution the
    /// patch-in-place path goes through.
    ///
    /// # Errors
    ///
    /// As [`Archive::one_name_twice`] when more than one child answers.
    pub(crate) fn child_named(&self, parent: u32, name: &str) -> Result<Option<u32>> {
        let Ok(children) = self.children(parent) else {
            return Ok(None);
        };
        let mut found: Option<u32> = None;
        for index in children {
            if !self.name(index).is_ok_and(|held| same_name(held, name)) {
                continue;
            }
            if let Some(first) = found {
                return Err(self.one_name_twice(first, index)?);
            }
            found = Some(index);
        }
        Ok(found)
    }

    /// Finds an entry by a path that may address **through** nested archives,
    /// returning the archive that holds it and the index within it.
    ///
    /// The descent is driven by position, not extension: a component resolving
    /// to a file with components still to come is opened as an archive.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] for a component that does not resolve, and as
    /// [`Archive::parse`] for a nested archive that does not open.
    pub fn locate<R: Read + Seek>(&self, src: &mut R, path: &str) -> Result<(Self, u32)> {
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut archive = self.clone();
        let mut current = 0_u32;

        for (position, segment) in segments.iter().enumerate() {
            let index = archive
                .child_named(current, segment)?
                .ok_or_else(|| Error::NotFound {
                    path: path.to_owned(),
                    segment: (*segment).to_owned(),
                })?;

            let is_last = position.saturating_add(1) == segments.len();
            let entry = archive.entry(index)?;

            if is_last || entry.is_directory() {
                current = index;
                continue;
            }

            // A file with components still to come is an archive to descend.
            archive = archive.open_nested(src, index)?;
            current = 0;
        }

        Ok((archive, current))
    }

    /// Parses an archive nested inside this one: the payload is another archive
    /// whose offsets are relative to its own base. The only way nesting depth
    /// grows, and bounded by [`MAX_DEPTH`].
    ///
    /// # Errors
    ///
    /// As [`Archive::parse`], plus [`Error::WrongKind`] for a directory and
    /// [`Error::TooDeep`] past [`MAX_DEPTH`] levels of nesting.
    pub fn open_nested<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Self> {
        let (offset, on_disk) = self.payload_span(index)?;
        let depth = self.depth.checked_add(1).ok_or(Error::TooDeep {
            what: "archive nesting",
            depth: u32::MAX,
            limit: MAX_DEPTH,
        })?;
        // A nested archive's key is chosen by its own name and length, so the
        // material carries over and the name does not.
        let unlock = self.unlock.renamed(self.name(index)?);
        Self::parse_nested(src, offset, on_disk, depth, &unlock)
    }

    /// The transform of an archive nested in this entry's payload, decided from
    /// the header alone so that an archive nobody here can open is still
    /// answered. `None` for a payload that is not an archive, or is one of a
    /// version this build does not read.
    pub(crate) fn nested_transform<R: Read + Seek>(
        &self,
        src: &mut R,
        index: u32,
    ) -> Option<NestedTransform> {
        let (offset, _) = self.payload_span(index).ok()?;
        let header = read_header(src, offset).ok()?;
        let tag = header.encryption;
        Some(match header.version.scheme(tag) {
            Some(scheme) => NestedTransform::Known { tag, scheme },
            None if header.version.is_open(tag) => NestedTransform::Open,
            None => NestedTransform::Unknown { tag },
        })
    }

    /// The archive nested in an entry's payload, or `None` when the payload is
    /// not one — an unreadable version included, which [`Archive::locate`]
    /// names instead. Depth is the exception: swallowing it would report a
    /// truncated listing as a complete one.
    ///
    /// # Errors
    ///
    /// [`Error::TooDeep`] past [`MAX_DEPTH`] levels of nesting, and nothing
    /// else.
    pub fn nested_at<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Nested> {
        match self.open_nested(src, index) {
            Ok(nested) => Ok(Nested::Open(Box::new(nested))),
            Err(error @ Error::TooDeep { .. }) => Err(error),
            // The archive is there and this build cannot open it; answering
            // "not an archive" would depend on what a key cache holds.
            Err(error) if error.category() == Category::NeedsKey => Ok(Nested::Locked(error)),
            Err(_) => Ok(Nested::None),
        }
    }
}

/// What the archive nested in an entry's payload is under, as a caller that
/// must not move it needs it: three answers, because "nothing here to protect"
/// and "under something nobody here has identified" are opposite facts and a
/// rename that confuses them moves an archive out from under its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NestedTransform {
    /// The nested archive is not encrypted, so nothing in it is keyed by
    /// anything.
    Open,
    /// It is under a transform this build names.
    Known {
        /// Its own encryption tag.
        tag: u32,
        /// What that tag names.
        scheme: Scheme,
    },
    /// It carries a tag this build does not define, so what keys it is unknown
    /// and its name is treated as part of it.
    Unknown {
        /// The tag as it stands, which a refusal names.
        tag: u32,
    },
}

/// What one entry is, and which of the two sources said so:
/// [`Classification::Resource`] comes from the entry table and every other
/// variant from the payload's leading bytes, and no value can mix the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Classification {
    /// A directory. It has no payload to classify.
    Directory,
    /// A resource, from the entry's resource bit; its payload is not read.
    Resource,
    /// A binary entry whose leading bytes announce an encoding.
    Encoded(Encoding),
    /// A binary entry whose leading bytes announce nothing.
    Binary,
}

impl Classification {
    /// The encoding the payload announced, or `None` for a directory, a
    /// resource, and a binary entry nothing recognised.
    #[must_use]
    pub const fn encoding(self) -> Option<Encoding> {
        match self {
            Self::Encoded(encoding) => Some(encoding),
            Self::Directory | Self::Resource | Self::Binary => None,
        }
    }
}

/// What sniffing an entry's payload for a nested archive found: "no archive
/// here" and "one this build could not open" are different facts a walk reports
/// differently. [`Nested::None`] still covers a version this build has no codec
/// for, since raising that would fail on a file that merely begins `RPF3`.
#[derive(Debug)]
pub enum Nested {
    /// The payload is not an archive, or is one of a version this build does
    /// not read.
    None,
    /// An archive, open. Boxed because it is much the larger arm.
    Open(Box<Archive>),
    /// An archive whose header this build read and whose table of contents it
    /// could not decrypt, carrying the reason so a report can name it.
    Locked(Error),
}

/// Reads the header at `base`, or says why those bytes are not one; leaves the
/// source wherever the read ended, since every read after it seeks for itself.
fn read_header<R: Read + Seek>(src: &mut R, base: u64) -> Result<Header> {
    // A file too short to hold the longest header is not an archive rather
    // than an i/o failure.
    src.seek(SeekFrom::Start(base))
        .map_err(|source| Error::Io {
            offset: base,
            source,
        })?;
    let mut bytes = [0u8; MAX_HEADER_LEN];
    let mut filled = 0_usize;
    while filled < bytes.len() {
        let rest = bytes.get_mut(filled..).unwrap_or_default();
        let read = src.read(rest).map_err(|source| Error::Io {
            offset: base,
            source,
        })?;
        if read == 0 {
            break;
        }
        filled = filled.saturating_add(read);
    }

    // The tag is read here and acted on in `decrypt_table_of_contents`, the
    // only place holding the material for it.
    Header::read(bytes.get(0..filled).unwrap_or_default(), base)
}

/// Whether these bytes begin with a root directory row: the one check that says
/// a table of contents was decrypted with the right key, since entry 0 is always
/// the root and its marker is a word no file entry can produce.
fn is_root_directory(version: Version, table: &[u8]) -> bool {
    version
        .decode_row(table)
        .is_some_and(|entry| entry.is_directory())
}

/// What is going to decrypt an archive's table of contents, decided from the
/// header alone. An unencrypted archive touches no key material at all.
struct Opening {
    /// The tag it was decided from, which a failure has to name.
    tag: u32,
    /// The transform that tag names.
    scheme: Scheme,
    /// Every material that could run that transform, in the order to try them.
    candidates: Vec<Arc<Material>>,
}

/// Which material is going to be tried, before a byte of layout is believed:
/// an archive nobody here can open must say so rather than be reported as
/// malformed because its entry table does not fit.
///
/// # Errors
///
/// [`Error::NeedsKey`] when the archive is encrypted and no material is
/// available, a tag no transform is named for included.
fn opening_for(version: Version, tag: u32, unlock: &Unlock) -> Result<Option<Opening>> {
    if version.is_open(tag) {
        return Ok(None);
    }
    // A tag this build has no transform for is `NeedsKey` whatever is in the
    // cache: the material that would open it is not material anyone has.
    let Some(scheme) = version.scheme(tag) else {
        return Err(Error::NeedsKey { tag });
    };
    let candidates = unlock.candidates(scheme)?;
    if candidates.is_empty() {
        return Err(Error::NeedsKey { tag });
    }
    Ok(Some(Opening {
        tag,
        scheme,
        candidates,
    }))
}

/// Decrypts an archive's table of contents and names blob in place, answering
/// the [`Unlock`] the archive keeps and the transform its payloads are under.
///
/// # Errors
///
/// [`Error::WrongKey`] when none of the material decrypts the table of contents
/// into one.
fn decrypt_table_of_contents(
    version: Version,
    len: u64,
    unlock: &Unlock,
    opening: Opening,
    table: &mut [u8],
    names_blob: &mut [u8],
) -> Result<(Unlock, Option<Scheme>)> {
    let Opening {
        tag,
        scheme,
        candidates,
    } = opening;
    let tried = u32::try_from(candidates.len()).unwrap_or(u32::MAX);

    // The row a key is judged by, read once. `None` is a header claiming no
    // entries, and then there is nothing for a key to be right about.
    let root_row: Option<[u8; CIPHER_BLOCK_LEN]> = table.get(..CIPHER_BLOCK_LEN).map(|first| {
        let mut probe = [0_u8; CIPHER_BLOCK_LEN];
        probe.copy_from_slice(first);
        probe
    });

    for material in candidates {
        let Some(cipher) = Cipher::new(scheme, &material, unlock.name(), len) else {
            continue;
        };
        // One block decides it; the answer is in the table's first row.
        if let Some(mut probe) = root_row {
            cipher.block(&mut probe);
            if !is_root_directory(version, &probe) {
                continue;
            }
        }
        cipher.apply(table);
        cipher.apply(names_blob);
        return Ok((unlock.resolved(&material), Some(scheme)));
    }

    Err(Error::WrongKey {
        tag,
        scheme: scheme.named(),
        tried,
    })
}

/// How many entries, saturating rather than truncating.
fn count_of(entries: &[Entry]) -> u32 {
    u32::try_from(entries.len()).unwrap_or(u32::MAX)
}

/// Splits the entry table into rows, at the stride its version gives them.
fn parse_entries(version: Version, table: &[u8], entry_count: u32) -> Result<Vec<Entry>> {
    let row_len = version.row_len();
    let stride = usize::try_from(row_len).unwrap_or(usize::MAX);
    let overrun = || Error::OutOfBounds {
        region: "entry table",
        offset: version.header_len(),
        len: u64::from(entry_count).saturating_mul(row_len),
        archive_len: 0,
    };
    let mut entries = Vec::new();
    for index in 0..entry_count {
        let start = usize::try_from(index)
            .ok()
            .and_then(|i| i.checked_mul(stride))
            .ok_or_else(overrun)?;
        let end = start.checked_add(stride).ok_or_else(overrun)?;
        let row = table.get(start..end).ok_or_else(overrun)?;
        let entry = version.decode_row(row).ok_or_else(overrun)?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Builds the child-to-parent map, and with it establishes that the entries are
/// a forest at all.
///
/// Three checks, each a crash downstream if missing: the child range fits the
/// table; every child comes after the directory claiming it, which makes the
/// parent map well founded for `Archive::path`'s unguarded walk; and no entry
/// is claimed twice, or the children relation becomes a lattice while the
/// single-valued parent map still looks ordinary.
fn parse_parents(entries: &[Entry]) -> Result<Vec<Option<u32>>> {
    let total = count_of(entries);
    let mut parents = vec![None; entries.len()];

    for (index, entry) in entries.iter().enumerate() {
        let EntryKind::Directory {
            first_child,
            child_count,
        } = entry.kind
        else {
            continue;
        };
        let index = u32::try_from(index).unwrap_or(u32::MAX);
        let bad_range = || Error::BadChildRange {
            entry: index,
            first: first_child,
            count: child_count,
            entry_count: total,
        };
        let end = first_child.checked_add(child_count).ok_or_else(bad_range)?;
        if end > total {
            return Err(bad_range());
        }

        for child in first_child..end {
            if child <= index {
                return Err(Error::CyclicTree {
                    entry: index,
                    child,
                });
            }
            let Some(slot) = usize::try_from(child).ok().and_then(|c| parents.get_mut(c)) else {
                return Err(bad_range());
            };
            if let Some(first) = *slot {
                return Err(Error::ClaimedTwice {
                    child,
                    first,
                    second: index,
                });
            }
            *slot = Some(index);
        }
    }

    check_depth(&parents)?;
    Ok(parents)
}

/// Refuses a tree deeper than [`MAX_DEPTH`], in one forward pass — cheap only
/// because every entry's parent has a smaller index and is already measured.
fn check_depth(parents: &[Option<u32>]) -> Result<()> {
    let mut depth: Vec<u32> = Vec::with_capacity(parents.len());
    for parent in parents {
        let here = match *parent {
            None => 0,
            Some(parent) => usize::try_from(parent)
                .ok()
                .and_then(|p| depth.get(p))
                .copied()
                .unwrap_or(MAX_DEPTH)
                .saturating_add(1),
        };
        if here > MAX_DEPTH {
            return Err(Error::TooDeep {
                what: "directory tree",
                depth: here,
                limit: MAX_DEPTH,
            });
        }
        depth.push(here);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The streaming transform, over a key of zeros.
    //!
    //! Nothing here checks a cipher value: only that the streaming and buffered
    //! forms answer the same bytes at every read size and from every offset.

    use std::io::Cursor;

    use super::*;
    use crate::format::{crypto::AesKey, rpf7};

    /// Bytes no block arithmetic could accidentally agree with.
    fn bytes(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| u8::try_from(index.wrapping_mul(7).wrapping_add(3) & 0xFF).unwrap_or(0))
            .collect()
    }

    /// The buffered answer: what `Cipher::apply` makes of the same bytes.
    fn buffered(source: &[u8]) -> Vec<u8> {
        let mut expected = source.to_vec();
        Cipher::over_zeros().apply(&mut expected);
        expected
    }

    /// A stream over `source`, decrypting the whole of it.
    fn streaming(source: &[u8]) -> Decrypting<Region<Cursor<Vec<u8>>>> {
        let len = u64::try_from(source.len()).unwrap_or(0);
        Decrypting::new(
            Region::new(Cursor::new(source.to_vec()), 0, len),
            Cipher::over_zeros(),
            len,
        )
    }

    /// Empty, under a block, a block exactly, a block and a tail, and more.
    const LENGTHS: [usize; 11] = [0, 1, 15, 16, 17, 31, 32, 33, 100, 511, 512];

    #[test]
    fn a_stream_answers_what_the_buffered_form_answers() {
        use std::io::Read as _;

        for len in LENGTHS {
            let source = bytes(len);
            let mut whole = Vec::new();
            streaming(&source)
                .read_to_end(&mut whole)
                .expect("reads to the end");
            assert_eq!(whole, buffered(&source), "length {len}");
        }
    }

    #[test]
    fn a_short_read_hands_out_the_same_bytes_as_a_long_one() {
        use std::io::Read as _;

        // A caller asking for one byte at a time crosses every block boundary.
        for len in LENGTHS {
            let source = bytes(len);
            let expected = buffered(&source);
            for cap in 1..=17_usize {
                let mut stream = streaming(&source);
                let mut got = Vec::new();
                let mut window = vec![0_u8; cap];
                loop {
                    let read = stream.read(&mut window).expect("reads");
                    if read == 0 {
                        break;
                    }
                    got.extend_from_slice(window.get(..read).unwrap_or_default());
                }
                assert_eq!(got, expected, "length {len} in {cap}-byte reads");
            }
        }
    }

    #[test]
    fn a_seek_lands_on_the_byte_it_names_from_any_offset() {
        use std::io::{Read as _, Seek as _, SeekFrom};

        // The block holding the target is read and the remainder handed out
        // from inside it; an off-by-one there reads an entry from a block away.
        for len in LENGTHS {
            let source = bytes(len);
            let expected = buffered(&source);
            for at in 0..=len {
                let mut stream = streaming(&source);
                let landed = stream
                    .seek(SeekFrom::Start(u64::try_from(at).unwrap_or(0)))
                    .expect("seeks");
                assert_eq!(landed, u64::try_from(at).unwrap_or(0));
                let mut tail = Vec::new();
                stream.read_to_end(&mut tail).expect("reads the tail");
                assert_eq!(
                    tail.as_slice(),
                    expected.get(at..).unwrap_or_default(),
                    "length {len} seeked to {at}"
                );
            }
        }
    }

    #[test]
    fn a_seek_back_and_forth_stays_on_the_same_bytes() {
        use std::io::{Read as _, Seek as _, SeekFrom};

        // `SeekFrom::Current` is computed from the position a partly-drained
        // block reports, not from what was pulled out of the source.
        let source = bytes(200);
        let expected = buffered(&source);
        let mut stream = streaming(&source);
        let mut first = [0_u8; 5];
        stream.read_exact(&mut first).expect("reads five");
        assert_eq!(first.as_slice(), expected.get(..5).unwrap_or_default());

        assert_eq!(stream.stream_position().expect("asks"), 5);
        assert_eq!(stream.seek(SeekFrom::Current(20)).expect("seeks"), 25);
        assert_eq!(stream.seek(SeekFrom::Current(-20)).expect("seeks"), 5);
        assert_eq!(
            stream.seek(SeekFrom::End(-8)).expect("seeks"),
            u64::try_from(source.len().saturating_sub(8)).unwrap_or(0)
        );
        let mut tail = Vec::new();
        stream.read_to_end(&mut tail).expect("reads");
        assert_eq!(
            tail.as_slice(),
            expected
                .get(source.len().saturating_sub(8)..)
                .unwrap_or_default()
        );
    }

    #[test]
    fn the_tail_a_stream_hands_out_is_the_tail_the_archive_wrote() {
        use std::io::Read as _;

        // A sub-block tail is handed out exactly as it sits.
        let source = bytes(CIPHER_BLOCK_LEN.saturating_add(5));
        let mut whole = Vec::new();
        streaming(&source)
            .read_to_end(&mut whole)
            .expect("reads to the end");
        assert_eq!(
            whole.get(CIPHER_BLOCK_LEN..),
            source.get(CIPHER_BLOCK_LEN..),
            "the sub-block tail was transformed"
        );
        assert_ne!(
            whole.get(..CIPHER_BLOCK_LEN),
            source.get(..CIPHER_BLOCK_LEN),
            "the whole block in front of it was not"
        );
    }

    /// An archive over `entries`, every name resolving to the empty string.
    fn unnamed_archive(
        entries: Vec<Entry>,
        len: u64,
        scheme: Option<Scheme>,
        unlock: Unlock,
    ) -> Archive {
        let names = Names::parse(Version::Rpf7, vec![0], &entries).expect("the root name resolves");
        let parents = vec![None; entries.len()];
        Archive {
            base: 0,
            len,
            version: Version::Rpf7,
            encryption: rpf7::ENCRYPTION_OPEN,
            depth: 0,
            unlock,
            scheme,
            entries,
            names,
            parents,
        }
    }

    /// A stored binary entry with a sixteen-byte payload at `block`.
    fn binary_at(block: u32) -> Entry {
        Entry {
            name_offset: 0,
            kind: EntryKind::Binary {
                block,
                compressed_len: 16,
                uncompressed_len: 16,
                encryption: rpf7::ENTRY_OPEN,
            },
        }
    }

    /// An empty directory, for a slot `room_from` is asked to skip over.
    fn empty_directory() -> Entry {
        Entry {
            name_offset: 0,
            kind: EntryKind::Directory {
                first_child: 0,
                child_count: 0,
            },
        }
    }

    #[test]
    fn payload_len_answers_what_it_was_built_with() {
        let payload = Payload {
            entry: 0,
            len: 42,
            declared: 42,
            used: 42,
        };
        assert_eq!(payload.len(), 42);
    }

    #[test]
    fn a_payload_used_exactly_to_its_declared_length_is_not_trailing() {
        let payload = Payload {
            entry: 0,
            len: 10,
            declared: 10,
            used: 10,
        };
        assert!(payload.checked().is_ok());
    }

    #[test]
    fn a_payload_used_short_of_its_declared_length_is_trailing() {
        let payload = Payload {
            entry: 0,
            len: 10,
            declared: 10,
            used: 9,
        };
        assert!(payload.checked().is_err());
    }

    #[test]
    fn reserve_matches_a_stored_payloads_own_length() {
        let extracted = Extracted::stored(0, Cursor::new(vec![0_u8; 100]), 0, 100, None);
        assert_eq!(extracted.reserve(), 100);
    }

    #[test]
    fn an_entry_of_zero_bytes_is_empty() {
        let extracted = Extracted::stored(0, Cursor::new(Vec::new()), 0, 0, None);
        assert!(extracted.is_empty());
    }

    #[test]
    fn a_seek_to_a_filled_block_boundary_does_not_read_past_it() {
        use std::io::{Seek as _, SeekFrom};

        // A seek to the boundary must land without needing the block after it.
        let source = bytes(CIPHER_BLOCK_LEN);
        let full = u64::try_from(CIPHER_BLOCK_LEN.saturating_mul(2)).unwrap_or(0);
        let region = Region::new(Cursor::new(source), 0, full);
        let mut stream = Decrypting::new(region, Cipher::over_zeros(), full);
        let at = u64::try_from(CIPHER_BLOCK_LEN).unwrap_or(0);
        let landed = stream
            .seek(SeekFrom::Start(at))
            .expect("lands on the boundary without reading past it");
        assert_eq!(landed, at);
    }

    #[test]
    fn a_deflated_streams_seek_sequence_lands_on_the_bytes_it_names() {
        use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

        let plain = bytes(500);
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&plain).expect("deflates");
        let compressed = encoder.finish().expect("finishes");

        let len = u64::try_from(plain.len()).unwrap_or(0);
        let on_disk = u64::try_from(compressed.len()).unwrap_or(0);
        let mut stream = Extracted::deflated(0, Cursor::new(compressed), 0, on_disk, len, None);

        let mut window = vec![0_u8; 10];
        stream.read_exact(&mut window).expect("reads");
        assert_eq!(window, plain.get(..10).unwrap_or_default());

        assert_eq!(stream.seek(SeekFrom::Start(10)).expect("seeks"), 10);
        stream.read_exact(&mut window).expect("reads");
        assert_eq!(window, plain.get(10..20).unwrap_or_default());

        assert_eq!(stream.seek(SeekFrom::Start(5)).expect("seeks"), 5);
        let mut fifteen = vec![0_u8; 15];
        stream.read_exact(&mut fifteen).expect("reads");
        assert_eq!(fifteen, plain.get(5..20).unwrap_or_default());

        assert_eq!(stream.seek(SeekFrom::Start(300)).expect("seeks"), 300);
        let mut fifty = vec![0_u8; 50];
        stream.read_exact(&mut fifty).expect("reads");
        assert_eq!(fifty, plain.get(300..350).unwrap_or_default());

        assert_eq!(stream.seek(SeekFrom::End(0)).expect("seeks"), len);
        let mut tail = Vec::new();
        stream.read_to_end(&mut tail).expect("reads");
        assert!(tail.is_empty());
    }

    /// A source that counts the bytes handed out of it.
    struct Counted<S> {
        inner: S,
        read: std::rc::Rc<std::cell::Cell<u64>>,
    }

    impl<S: Read> Read for Counted<S> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let read = self.inner.read(buf)?;
            self.read.set(
                self.read
                    .get()
                    .saturating_add(u64::try_from(read).unwrap_or(0)),
            );
            Ok(read)
        }
    }

    impl<S: Seek> Seek for Counted<S> {
        fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
            self.inner.seek(to)
        }
    }

    #[test]
    fn a_deflated_entry_answers_its_length_without_inflating_it() {
        use std::io::{Read as _, Seek as _, Write as _};

        // `build::store` measures the payload with `seek(SeekFrom::End(0))` and
        // rewinds, so a forward seek must inflate nothing: the length is what
        // the entry declares, not what the bytes say.
        let plain = bytes(64 * 1024);
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&plain).expect("deflates");
        let compressed = encoder.finish().expect("finishes");
        let read = std::rc::Rc::new(std::cell::Cell::new(0_u64));
        let source = Counted {
            inner: Cursor::new(compressed.clone()),
            read: std::rc::Rc::clone(&read),
        };
        let len = u64::try_from(plain.len()).unwrap_or(0);
        let on_disk = u64::try_from(compressed.len()).unwrap_or(0);
        let mut stream = Extracted::deflated(0, source, 0, on_disk, len, None);

        assert_eq!(stream.seek(SeekFrom::End(0)).expect("seeks"), len);
        assert_eq!(
            read.get(),
            0,
            "measuring the entry read {} bytes of it",
            read.get()
        );

        stream.rewind().expect("rewinds");
        let mut whole = Vec::new();
        stream.read_to_end(&mut whole).expect("reads");
        assert_eq!(whole, plain);
        assert!(
            read.get() <= on_disk,
            "the payload was read {} times over its {on_disk} bytes",
            read.get()
        );
    }

    #[test]
    fn a_writable_check_is_decided_by_whether_the_scheme_can_run_forwards() {
        let sealing = unnamed_archive(
            vec![],
            64,
            Some(Scheme::Aes(AesKey::Rage)),
            Unlock::unkeyed(),
        );
        assert!(sealing.writable().is_ok());

        let not_sealing = unnamed_archive(vec![], 64, Some(Scheme::Ng), Unlock::unkeyed());
        assert!(not_sealing.writable().is_err());
    }

    #[test]
    fn seal_produces_a_forward_transform_for_a_scheme_that_has_one() {
        let unlock = Unlock::held(Arc::new(Material::over_zeros()), "test.rpf");
        let archive = unnamed_archive(vec![], 64, Some(Scheme::Aes(AesKey::Rage)), unlock);
        assert!(archive.seal().expect("seals").is_some());
    }

    #[test]
    fn resource_cipher_answers_a_transform_when_material_is_in_hand() {
        let unlock = Unlock::held(Arc::new(Material::over_zeros()), "test.rpf");
        let entries = vec![Entry {
            name_offset: 0,
            kind: EntryKind::Resource {
                block: 1,
                compressed_len: 100,
                system_flags: 0,
                graphics_flags: 0,
            },
        }];
        let archive = unnamed_archive(entries, 1024, Some(Scheme::Aes(AesKey::Rage)), unlock);
        let cipher = archive.resource_cipher(0, 100).expect("no error");
        assert!(cipher.is_some());
    }

    #[test]
    fn an_entry_marked_open_is_not_put_through_the_archives_own_transform() {
        use std::io::Read as _;

        let unlock = Unlock::held(Arc::new(Material::over_zeros()), "test.rpf");
        let plain = bytes(16);
        let mut source = vec![0_u8; 512];
        source.extend_from_slice(&plain);
        let entries = vec![Entry {
            name_offset: 0,
            kind: EntryKind::Binary {
                block: 1,
                compressed_len: 0,
                uncompressed_len: u32::try_from(plain.len()).unwrap_or(0),
                encryption: rpf7::ENTRY_OPEN,
            },
        }];
        let len = u64::try_from(source.len()).unwrap_or(0);
        let archive = unnamed_archive(entries, len, Some(Scheme::Aes(AesKey::Rage)), unlock);
        let mut src = Cursor::new(source);
        let mut extracted = archive.extracted(&mut src, 0).expect("opens");
        let mut got = Vec::new();
        extracted.read_to_end(&mut got).expect("reads");
        assert_eq!(got, plain);
    }

    #[test]
    fn an_entry_sharing_this_ones_start_claims_none_of_the_room() {
        let entries = vec![empty_directory(), binary_at(2)];
        let archive = unnamed_archive(entries, 5000, None, Unlock::unkeyed());
        assert_eq!(archive.room_from(0, 1024), 5000_u64.saturating_sub(1024));
    }

    #[test]
    fn an_entry_before_the_one_asking_does_not_shrink_its_room() {
        let entries = vec![empty_directory(), binary_at(0)];
        let archive = unnamed_archive(entries, 5000, None, Unlock::unkeyed());
        assert_eq!(archive.room_from(0, 1024), 5000_u64.saturating_sub(1024));
    }

    #[test]
    fn the_nearest_entry_after_this_one_bounds_its_room() {
        let entries = vec![empty_directory(), binary_at(3)];
        let archive = unnamed_archive(entries, 5000, None, Unlock::unkeyed());
        assert_eq!(archive.room_from(0, 1024), 1536_u64.saturating_sub(1024));
    }

    #[test]
    fn named_answers_the_entrys_own_path() {
        let entries = vec![
            Entry {
                name_offset: 0,
                kind: EntryKind::Directory {
                    first_child: 1,
                    child_count: 1,
                },
            },
            Entry {
                name_offset: 1,
                kind: EntryKind::Binary {
                    block: 1,
                    compressed_len: 0,
                    uncompressed_len: 0,
                    encryption: rpf7::ENTRY_OPEN,
                },
            },
        ];
        let blob = b"\0hello\0".to_vec();
        let parents = parse_parents(&entries).expect("a valid tree");
        let names = Names::parse(Version::Rpf7, blob, &entries).expect("names resolve");
        let archive = Archive {
            base: 0,
            len: 1024,
            version: Version::Rpf7,
            encryption: rpf7::ENCRYPTION_OPEN,
            depth: 0,
            unlock: Unlock::unkeyed(),
            scheme: None,
            entries,
            names,
            parents,
        };
        assert_eq!(archive.named(1), "hello");
    }

    /// A reader that hands out at most `step` bytes per call.
    struct Throttled<R> {
        inner: R,
        step: usize,
    }

    impl<R: Read> Read for Throttled<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let want = buf.len().min(self.step);
            self.inner.read(buf.get_mut(..want).unwrap_or_default())
        }
    }

    impl<R: Seek> Seek for Throttled<R> {
        fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
            self.inner.seek(to)
        }
    }

    #[test]
    fn head_keeps_reading_until_it_has_the_whole_of_what_it_asked_for() {
        let plain = bytes(Encoding::HEAD_LEN.saturating_add(4));
        let mut source = vec![0_u8; 512];
        source.extend_from_slice(&plain);
        let entries = vec![Entry {
            name_offset: 0,
            kind: EntryKind::Binary {
                block: 1,
                compressed_len: 0,
                uncompressed_len: u32::try_from(plain.len()).unwrap_or(0),
                encryption: rpf7::ENTRY_OPEN,
            },
        }];
        let len = u64::try_from(source.len()).unwrap_or(0);
        let archive = unnamed_archive(entries, len, None, Unlock::unkeyed());
        let mut throttled = Throttled {
            inner: Cursor::new(source),
            step: 1,
        };
        let (head, got) = archive.head(&mut throttled, 0);
        assert_eq!(got, Encoding::HEAD_LEN);
        assert_eq!(
            head.get(..got).unwrap_or_default(),
            plain.get(..got).unwrap_or_default()
        );
    }
}
