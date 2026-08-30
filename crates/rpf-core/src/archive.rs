//! The parsed table of contents of one archive, and reads against it.
//!
//! [`Archive`] holds only the table of contents — entries, names, and the shape
//! of the tree. It does **not** hold the source. Reads take `&mut R` where
//! `R: Read + Seek`, which is what §7 requires and what makes a nested archive
//! ordinary: it is another [`Archive`] parsed at a different base over the same
//! source.
//!
//! Nothing here loads an archive. A 2.7 GB file costs its table of contents to
//! open, and one entry to read. R3.9.

use std::{
    collections::HashMap,
    io::{self, BufReader, Read, Seek, SeekFrom},
    sync::Arc,
};

use crate::{
    entry::{Entry, EntryKind},
    error::{Category, Error, Result},
    format::{
        Header, MAX_HEADER_LEN, Names, Version,
        crypto::{CIPHER_BLOCK_LEN, Cipher, Scheme},
        folded,
        resource::{MAGIC_RSC7, RESOURCE_HEADER_LEN, resource_len},
        same_name,
    },
    keys::{Material, Unlock},
    metadata::Encoding,
};

/// How deep anything in this container is walked before it is refused.
///
/// **Policy, not a measured fact.** The format sets no limit and nothing about
/// a deep archive is self-contradictory; this is the depth we choose to follow
/// to, and DR-011 holds the reasoning and the measurements behind the number.
/// It is deliberately absent from `docs/rpf-format.md`, which holds facts an
/// archive told us.
///
/// It bounds two structures, because it is one fact about one thing: every
/// recursive walk over an archive — `child_named` down a path, `ls -R`,
/// `verify`, the daemon's recursive list — descends a directory tree, an
/// archive nested inside an archive, or both, and both depths are chosen by
/// the bytes rather than by us. The bound belongs here and not at each walker
/// (§5): a walker that carried its own counter would be one walker away from a
/// walker that forgot, and the symptom of forgetting is a stack overflow rather
/// than a wrong answer.
pub const MAX_DEPTH: u32 = 32;

/// Seeks and fills `buf`, reporting where it was when it failed.
fn read_exact_at<R: Read + Seek>(src: &mut R, offset: u64, buf: &mut [u8]) -> Result<()> {
    src.seek(SeekFrom::Start(offset))
        .map_err(|source| Error::Io { offset, source })?;
    src.read_exact(buf)
        .map_err(|source| Error::Io { offset, source })
}

/// Reads `len` bytes at `offset` into a fresh buffer.
///
/// The caller must have bounds-checked `len` against the archive first; this is
/// where an unchecked length would become an allocation.
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

/// What a read of one entry found out about the payload it came out of.
///
/// It holds no contents, only their length: a read that keeps them is
/// [`Archive::read`], and this is what the read that does not keep them can
/// still say. The two other lengths are the **payload's**, not the contents':
/// `declared` is how many bytes on disk the entry table gives the stream, and
/// `used` is how many of them the stream turned out to occupy. They can differ
/// without anything failing to inflate, because a deflate stream carries its
/// own end and whatever follows it is never looked at — which is the whole of
/// R6.10 and what [`Payload::checked`] is for.
pub(crate) struct Payload {
    entry: u32,
    len: u64,
    declared: u64,
    used: u64,
}

impl Payload {
    /// How many bytes the entry holds, for a caller counting progress rather
    /// than reading.
    pub(crate) const fn len(&self) -> u64 {
        self.len
    }

    /// Whether the stream reached the end of the payload it was given.
    ///
    /// The one place that fact is decided. `docs/rpf-format.md`, Resource page
    /// flags, `verified`: every resource in the sample ends its stream exactly
    /// at its payload, 0 bytes over, 20 of 20.
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
///
/// Every read is clamped to it, so a payload whose deflate stream does not end
/// where the entry says cannot read past the entry it belongs to (§6). The
/// source is seeked to before the first read and after every seek of the
/// window, and nothing else may touch it in between — which is what taking it
/// by value is for.
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
            // The window is inside the archive's own declared extent, so these
            // bytes exist unless the file is shorter than the archive says.
            // `read_exact` reported that as `Error::Io` at the window's start,
            // and so does this.
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

/// A region read through a block transform.
///
/// The transform has no chaining, so a block is decrypted where it is read and
/// nothing before it is needed. The whole of what this holds is **one block**,
/// which is what keeps a payload's cost its buffer rather than its length (§7,
/// R3.9) — a 1.5 GB encrypted entry streams through sixteen bytes.
///
/// The tail rule is [`Cipher::apply`]'s, which is why `len` is held here: a
/// stream has to know the tail is coming before it reaches it.
#[derive(Debug)]
struct Decrypting<R> {
    src: R,
    cipher: Cipher,
    /// How long the transformed region is, so the sub-block tail is known
    /// without reading to it.
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

    /// Reads the next block, decrypting it unless it is the sub-block tail.
    ///
    /// Leaves `filled` at zero at the end of the region, which is what a read
    /// answers `Ok(0)` on.
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
    /// Seeks within the transformed region.
    ///
    /// The block containing the target is the one that has to be read, so a
    /// seek lands on a block boundary and the remainder is handed out from
    /// there. No chaining is what makes that possible at all.
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
///
/// An enum rather than a generic: the two arms are the same window on the same
/// source, and a generic would push the choice into every signature that
/// carries a stream.
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

/// What decrypts a **resource** payload: nothing, in either framing.
///
/// A resource is never under the archive's transform, whatever the archive's
/// tag says. Its deflate stream sits in the clear sixteen bytes into the
/// payload and inflates to exactly the length its two flag words give, and it
/// has no per-entry encryption field to consult in the first place — offsets 8
/// and 12 are those flag words (§5). `docs/rpf-format.md`, Encryption,
/// `verified`: checked on every resource of the AES archive and of an NG one.
///
/// Named once rather than written as a bare `None` in each of the two framings,
/// because two spellings of one format fact drift silently and this one decides
/// whether bytes are transformed (§3).
const RESOURCE_IS_IN_THE_CLEAR: Option<Cipher> = None;

/// Which of the two forms an entry is read in.
///
/// They differ for a **resource** and only for a resource: the file it is
/// outside the archive is its `RSC7` header and its body as they sit on disk,
/// and its contents are what that body inflates to. Passthrough is why the
/// first exists — `docs/approach.md` — and DR-023 digests it.
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
    /// Inflated as they are read.
    ///
    /// Buffered because the decompressor asks for input a little at a time and
    /// the window under it seeks the source. The buffer is the decoder's own,
    /// which is what makes it discardable on a restart: seeking it throws away
    /// what it read ahead, which a fresh decompressor has to see again.
    ///
    /// The transform goes **under** the decompressor, because that is the order
    /// the archive wrote them in: a payload is deflated and then encrypted, so
    /// it is decrypted and then inflated.
    Deflated(flate2::bufread::DeflateDecoder<BufReader<Plain<S>>>),
}

/// One entry as a stream of the bytes it is made of.
///
/// The one place a payload becomes bytes, in either of the two framings the
/// container has (§3): [`Archive::extracted`] gives the file as it is outside
/// the archive, and [`Archive::read`] gives the contents. They differ for a
/// **resource** and only for a resource — the first keeps its `RSC7` header and
/// leaves the body deflated, the second inflates that body.
///
/// Nothing larger than the caller's own buffer is held, which is what lets one
/// entry out of a multi-gigabyte archive cost its buffer rather than its
/// length. R3.9.
///
/// **What a stream reports, it reports where it ends.** A payload that inflates
/// to more or fewer bytes than the entry promises is [`Error::LengthMismatch`]
/// at the end of the read, as it was when this read into a buffer; a caller
/// that stops early has not asked. Every failure comes out as an
/// [`std::io::Error`] carrying the [`Error`] it really was — [`Error::carried`]
/// is where it comes back out.
#[derive(Debug)]
pub struct Extracted<S> {
    entry: u32,
    /// Where the bytes this yields begin in the source, for a failure to name.
    at: u64,
    /// How many bytes the entry says this yields in full.
    len: u64,
    /// How many it has yielded.
    pos: u64,
    /// How many bytes on disk the entry gives the stream.
    declared: u64,
    stream: Stream<S>,
}

impl<S: Read + Seek> Extracted<S> {
    /// A payload read as it sits on disk, through `cipher` where the archive
    /// put one over it.
    fn stored(entry: u32, src: S, at: u64, len: u64, cipher: Option<Cipher>) -> Self {
        Self {
            entry,
            at,
            len,
            pos: 0,
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
            declared: on_disk,
            stream: Stream::Deflated(flate2::bufread::DeflateDecoder::new(BufReader::new(
                Plain::new(src, at, on_disk, cipher),
            ))),
        }
    }

    /// How many bytes this yields in full.
    ///
    /// Known before anything is read: it is what the entry declares, and a
    /// stream that does not match it is a failure rather than a shorter answer.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Whether the entry holds nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// How many bytes on disk the entry gives the stream, and how many of them
    /// the stream turned out to occupy. Meaningful once it has been read to the
    /// end; before that, `used` is how far it has got.
    fn extent(&self) -> (u64, u64) {
        let used = match self.stream {
            Stream::Stored(ref plain) => plain.pos(),
            // What the decompressor took, rather than what it was handed: that
            // is where the stream ends, and the bytes after it belong to
            // nothing.
            Stream::Deflated(ref decoder) => decoder.total_in(),
        };
        (self.declared, used)
    }

    /// How much to reserve for [`Extracted::whole`].
    ///
    /// A stored payload's length is the entry's own extent, already
    /// bounds-checked against the archive, so reserving it is one allocation.
    /// A deflated payload's is what the entry *claims* it inflates to, which is
    /// attacker-controlled, so it caps the read rather than sizing an
    /// allocation up front.
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
    /// The read that checks an entry rather than using it: every byte goes
    /// through the decompressor and none of them is held, so reading a whole
    /// archive back costs a buffer rather than its largest entry. R3.9.
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
            Stream::Deflated(ref mut decoder) => {
                // One byte past what the entry promises, so a payload that
                // inflates to more than that is caught rather than truncated
                // to it.
                let limit = expected.checked_add(1).ok_or_else(|| {
                    Error::LengthMismatch {
                        entry,
                        expected,
                        actual: u64::MAX,
                    }
                    .into_io()
                })?;
                let room = limit.saturating_sub(self.pos);
                let want = usize::try_from(room).unwrap_or(usize::MAX).min(buf.len());
                let window = buf.get_mut(..want).unwrap_or_default();
                if window.is_empty() {
                    return Ok(0);
                }
                decoder
                    .read(window)
                    .map_err(|source| inflating(entry, source))?
            }
        };

        // Both checks are the deflated stream's: a stored payload ends where
        // its window does, and a window that ends early has already failed.
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
    /// Seeks within the entry, whose length is known without reading it.
    ///
    /// A stored payload seeks its source and costs nothing. **A deflated one
    /// has no position but the one it has inflated to**: seeking backwards
    /// starts the stream again and seeking forwards inflates what it passes
    /// over and throws it away. [`crate::Payload`] asks for [`Seek`] because
    /// [`crate::build()`] reads a payload twice in one case, and that case is a
    /// rewind.
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
        // Forward by inflating and discarding, bounded by the entry's own
        // length: past that there is nothing to inflate, and a read answers
        // empty exactly as it does past the end of a file.
        let mut left = self.len.min(target).saturating_sub(self.pos);
        let mut discarded = [0_u8; 8 * 1024];
        while left > 0 {
            let want = usize::try_from(left)
                .unwrap_or(usize::MAX)
                .min(discarded.len());
            let read = self.read(discarded.get_mut(..want).unwrap_or_default())?;
            if read == 0 {
                break;
            }
            left = left.saturating_sub(u64::try_from(read).unwrap_or(0));
        }
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
    /// How many archives this one sits inside. Zero for a file opened on its
    /// own, and one more than its holder's for every nested archive, which is
    /// what [`MAX_DEPTH`] is counted against.
    depth: u32,
    /// What opened this archive, and what opens the archives nested in it.
    ///
    /// Normalised at parse: an archive that consulted a cache holds the
    /// material it found rather than the cache, so reading an entry is not a
    /// second pass over a configuration directory. DR-041.
    unlock: Unlock,
    /// The transform this archive's own payloads are under, or `None` when it
    /// is not encrypted.
    ///
    /// `Some` implies the material that runs it is in `unlock`: the two are set
    /// together at parse and there is no way to reach one without the other
    /// (§5).
    scheme: Option<Scheme>,
    entries: Vec<Entry>,
    names: Names,
    parents: Vec<Option<u32>>,
}

impl Archive {
    /// Parses the archive that begins at `base` and runs for `len` bytes.
    ///
    /// `len` is the archive's own extent, which for a nested archive is the
    /// size of the entry that holds it, not the size of the file. Every offset
    /// inside is checked against it.
    ///
    /// `unlock` is what opens it if it turns out to be encrypted, and what
    /// opens every archive nested inside it. [`crate::Unlock::unkeyed`] is the
    /// whole of what an unencrypted archive needs, and is what a caller with no
    /// key material passes — the parameter is not optional, because an archive
    /// that can now be opened with a key must not be silently refused by a call
    /// site that forgot to say it had one (§4, DR-041).
    ///
    /// # Errors
    ///
    /// [`Error::NotAnArchive`] if the magic is nothing this format uses,
    /// [`Error::UnsupportedVersion`] if it names a version this build does not
    /// read, [`Error::NeedsKey`] if it is encrypted and no material is
    /// available, [`Error::WrongKey`] if material is available and none of it
    /// opens the archive, and the bounds variants if the header describes
    /// regions that do not fit.
    pub fn parse<R: Read + Seek>(
        src: &mut R,
        base: u64,
        len: u64,
        unlock: &Unlock,
    ) -> Result<Self> {
        // An archive parsed by name rather than through a holder is the
        // outermost one there is, so it is nested inside nothing.
        Self::parse_nested(src, base, len, 0, unlock)
    }

    /// [`Archive::parse`], told how many archives it already sits inside.
    ///
    /// The depth is the caller's to supply because it is not in the bytes: an
    /// archive cannot tell where it is being read from. [`Archive::open_nested`]
    /// is the only caller that supplies anything but zero, which is what keeps
    /// the count honest.
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

        // Decided from the header, before any of the layout below is believed:
        // an archive nobody can open says so rather than being reported as
        // malformed for a region that does not fit.
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
        // Checked before the names blob, so that a header claiming more
        // entries than the file can hold names the entry table rather than the
        // blob that never got a chance to start (§10).
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

        // Decrypted before a single row is decoded: an encrypted table of
        // contents parses into nonsense otherwise, and nonsense is what the
        // rest of this function is written to refuse. The key is chosen by this
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

        // Names are located once, here, so that `name` has nothing left to
        // find (§5). How they are encoded is the version's, which is why the
        // seam is asked rather than the blob read here.
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
    /// not encrypted.
    ///
    /// A name, never a key and never a key index: DR-020.
    #[must_use]
    pub fn scheme(&self) -> Option<&'static str> {
        self.scheme.map(Scheme::named)
    }

    /// Whether this archive can be written back at all.
    ///
    /// Reading an encrypted archive and writing one are separate capabilities,
    /// and this build has only the first: the transform has no inverse here
    /// (R4.7, `docs/ng-scheme.md`). Every write path asks this before it
    /// computes a byte, so the one answer serves patching, rebuilding and the
    /// resolution a buffered change is accepted by — which is what keeps three
    /// call sites from growing three answers (§3).
    ///
    /// # Errors
    ///
    /// [`Error::CannotWriteEncrypted`], naming the tag, when the archive is
    /// under a transform. It is not overridable: a capability that is absent is
    /// not a safety interlock, and no flag supplies it. DR-041.
    pub const fn writable(&self) -> Result<()> {
        match self.scheme {
            None => Ok(()),
            Some(_) => Err(Error::CannotWriteEncrypted {
                tag: self.encryption,
            }),
        }
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
    /// [`Error::NoSuchEntry`] if the index is past the end, and
    /// [`Error::BadName`] if the bytes at the entry's name offset are not
    /// UTF-8. Every name in the sample is ASCII; refusing the rest is §6's
    /// answer for third-party bytes, and it is a name the caller can be shown
    /// rather than a repair it cannot check.
    pub fn name(&self, index: u32) -> Result<&str> {
        self.names.at(index)
    }

    /// The full path of an entry, addressed from the archive root.
    ///
    /// The root itself is the empty string; everything else is
    /// slash-separated with no leading slash.
    ///
    /// The walk up the parent map is unguarded because it does not need a
    /// guard: `parse_parents` refuses any archive in which a child's index is
    /// not greater than its parent's, so every step of this loop moves to a
    /// smaller index and it ends (§5).
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

    /// Refuses an archive in which two children of one directory are one name
    /// here.
    ///
    /// [`same_name`] folds case, so `A.txt` and `a.txt` under one parent are
    /// one name and the second is unreachable by any spelling of its own path.
    /// `build` has always refused to write such an archive; this is the reading
    /// of the same rule, so an archive that cannot be packed cannot be
    /// extracted either. R10.4.
    ///
    /// **Not done at parse**, deliberately, and this is the reason rather than
    /// an omission: an archive like this is legal in the format, no corpus here
    /// is wide enough to say the game never ships one, and refusing it at
    /// `Archive::parse` would leave `ls` unable to show what is wrong with it.
    /// What is refused is turning it into a tree — which is `specs_of` and
    /// `directories_of`, and therefore `extract`, `pack` and every rebuild.
    ///
    /// # Errors
    ///
    /// As `Archive::one_name_twice`, and as [`Archive::path`] for an entry
    /// whose ancestry does not resolve.
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

    /// The refusal for two children of one directory that are one name here.
    ///
    /// **Three conditions, and the reader answers each of them as the writer
    /// does.** `build` refuses a tree for two spellings of one folded name
    /// ([`Error::NameCollision`]), for one path given twice, and for a file and
    /// a directory of one name; reading an archive can meet all three, and
    /// answering them all as a case collision told a caller `"aa.txt" and
    /// "aa.txt" are one name here`, which names one string twice and says
    /// nothing. All three are `Category::Refused` and exit 6 either way, so the
    /// symmetry is in what is reported rather than in what a machine branches
    /// on.
    ///
    /// # Errors
    ///
    /// [`Error::NameCollision`] for two spellings of one name, [`Error::BadPath`]
    /// for one name carried by two entries, and as [`Archive::path`] for an
    /// entry whose ancestry does not resolve. It returns the refusal rather
    /// than raising it, so the two callers spell the refusal one way.
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
    ///
    /// The fallback is not a guess — it names the entry exactly, by the only
    /// thing that is still true of it — and it is reached only from an archive
    /// whose parent map is already broken, which is a failure of its own.
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

    /// Where an entry's payload begins in the source, bounds-checked against
    /// this archive's own extent.
    fn payload_span(&self, index: u32) -> Result<(u64, u64)> {
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
                // carries the real length. docs/rpf-format.md, Compression.
                let len = if compressed_len == 0 {
                    uncompressed_len
                } else {
                    compressed_len
                };
                (block, u64::from(len))
            }
            // No stored sentinel here, and the asymmetry with the arm above is
            // the format's rather than an oversight: a binary entry that
            // declares zero has its real length at offset 8, and a resource
            // does not — both of its trailing words are page flags.
            // `docs/rpf-format.md` records no measurement of a stored
            // resource, so nothing here invents a rule for recovering one; a
            // resource declaring zero is refused by `read` and `extract` for
            // being smaller than its own `RSC7` header.
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
        // A payload lies after the names blob — `docs/rpf-format.md`, Layout.
        // The upper bound alone leaves the archive's own header, entry table
        // and names blob addressable as file contents: an entry at block 0
        // reads back the table of contents, which is a plausible-but-wrong
        // value rather than a failure, and `allocation` then offers those same
        // bytes to a patch as room to write into.
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
    /// As [`Archive::entry`], and the bounds variants for a payload that does
    /// not fit.
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
    /// This is room a caller may **write into**, so it stops at the first byte
    /// any other payload claims from this one's start onwards — not at the
    /// next payload to begin strictly later. Two entries sharing a block, and
    /// an entry whose payload runs through this one's start, are both invisible
    /// to the second reading, and both mean these bytes are already spoken
    /// for: the answer is then zero, not the distance to whatever comes next.
    ///
    /// [`crate::patch::plan`] rests on that. It treats an allocation as the
    /// bytes an edit claims and refuses two edits that overlap, which only
    /// tells it what it needs if an allocation really does end where the next
    /// payload begins.
    ///
    /// Real archives leave a great deal of room here — 82.7% of the sample is
    /// unreferenced — which is what makes patching in place worth doing at all.
    ///
    /// # Errors
    ///
    /// As [`Archive::payload_extents`], and [`Error::NoSuchEntry`] or
    /// [`Error::WrongKind`] for an index that is not a file in this archive.
    pub fn allocation(&self, index: u32) -> Result<u64> {
        // Resolved before the extents are searched: an index that is not an
        // entry at all must say so, rather than being reported as the wrong
        // kind of entry because the search for it came up empty (§10).
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
    /// A binary entry inflates to its declared length. A resource entry has its
    /// 16-byte `RSC7` header removed and the remainder inflated. Compare
    /// [`Archive::extract`], which keeps the header.
    ///
    /// A payload whose deflate stream ends before the payload does still reads
    /// back, because it reads back correctly: the contents are what the archive
    /// promises, and only the bytes after the stream are unaccounted for.
    /// [`crate::Verified`] reports those as [`Error::TrailingBytes`]; refusing
    /// them here would reject an archive on one producer's evidence. R6.10.
    ///
    /// # Errors
    ///
    /// [`Error::WrongKind`] for a directory, the bounds variants for a payload
    /// that does not fit, and [`Error::Inflate`] or [`Error::LengthMismatch`]
    /// when the payload does not decompress as promised.
    pub fn read<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Vec<u8>> {
        self.opened(src, index, Form::Contents)?.whole()
    }

    /// [`Archive::read`] for a caller checking an entry rather than using it:
    /// the contents go past and only what the read learned about the payload
    /// comes back.
    ///
    /// The same machine as [`Archive::read`] and the same two lengths, so
    /// [`Error::TrailingBytes`] rests on one accounting rather than two (§3).
    /// Nothing is held, so [`crate::Verified`] costs a buffer per entry rather
    /// than the archive's largest one. R3.9.
    ///
    /// # Errors
    ///
    /// As [`Archive::read`].
    pub(crate) fn read_back<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Payload> {
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

    /// One entry as a stream of the file it is **outside the archive**.
    ///
    /// The streaming form of [`Archive::extract`], and the one the bytes come
    /// out of: a caller writing an entry into a sink, digesting it, or handing
    /// it to [`crate::build()`] as a payload never holds it. One entry out of a
    /// multi-gigabyte archive costs its own buffer. R3.9.
    ///
    /// `src` is taken by value and read from wherever the stream needs it, so
    /// nothing else may read it until the stream is dropped — a `&mut R` is
    /// what a caller normally hands over.
    ///
    /// # Errors
    ///
    /// [`Error::WrongKind`] for a directory, [`Error::ResourceTooSmall`] for a
    /// resource that cannot hold its own header, and the bounds variants for a
    /// payload that does not fit. What the *stream* fails with is
    /// [`Extracted`]'s.
    pub fn extracted<S: Read + Seek>(&self, src: S, index: u32) -> Result<Extracted<S>> {
        self.opened(src, index, Form::File)
    }

    /// The transform one entry's payload is under, if it is under one.
    ///
    /// Three measured facts decide it, and none of them is a guess.
    ///
    /// - The **archive's** tag chooses the transform, and an archive that is
    ///   not encrypted puts none of its entries under one.
    /// - A **binary** entry is transformed exactly when its own per-entry
    ///   encryption field says so. Across both GTA V installs that field takes
    ///   two values and no others — 27,276 entries carry 0 and 64,300 carry 1 —
    ///   and 1 is the one whose payload only reads back after the transform.
    ///   `docs/rpf-format.md`, Entry table; `docs/backlog.md` Q10.
    /// - A **resource** entry never is. Its deflate stream sits in the clear
    ///   sixteen bytes into the payload and inflates to exactly the length its
    ///   flag words give, in every archive measured; the sixteen bytes in front
    ///   of it are not a readable `RSC7` header and no key here recovers one.
    ///   A resource also has no per-entry encryption field to consult — offsets
    ///   8 and 12 are its two flag words (§5) — so there would be nothing to
    ///   ask even if it did.
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

            // Compression is what decides a binary entry, and the same answer
            // serves both framings: what a binary file is outside the archive
            // is what it means.
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

            EntryKind::Resource {
                compressed_len,
                system_flags,
                graphics_flags,
                ..
            } => match form {
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
                Form::Contents => {
                    let stream_len = u64::from(compressed_len)
                        .checked_sub(RESOURCE_HEADER_LEN)
                        .ok_or(Error::ResourceTooSmall {
                            entry: index,
                            compressed_len,
                        })?;
                    let at =
                        offset
                            .checked_add(RESOURCE_HEADER_LEN)
                            .ok_or(Error::ResourceTooSmall {
                                entry: index,
                                compressed_len,
                            })?;
                    Ok(Extracted::deflated(
                        index,
                        src,
                        at,
                        stream_len,
                        resource_len(system_flags, graphics_flags),
                        RESOURCE_IS_IN_THE_CLEAR,
                    ))
                }
            },
        }
    }

    /// Reads an entry as the **file it is outside the archive**.
    ///
    /// The difference from [`Archive::read`] is resources: this keeps the
    /// 16-byte `RSC7` header and leaves the body deflated, because that is what
    /// a `.yft` on disk is. Passthrough is a commitment — an entry we cannot
    /// interpret still round-trips byte for byte. `docs/approach.md`.
    ///
    /// [`Archive::extracted`] is the same read as a stream, and this is the
    /// convenience over it for a caller that wants the bytes — a checksum, a
    /// 200-byte `.meta`, a `cat` into a pipe. It holds the whole entry, which
    /// for a multi-gigabyte one is the caller's choice to make rather than the
    /// signature's (§7).
    ///
    /// # Errors
    ///
    /// As [`Archive::read`].
    pub fn extract<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Vec<u8>> {
        self.extracted(src, index)?.whole()
    }

    /// What an entry is, and what its payload announces itself to be.
    ///
    /// Two sources, and the type keeps them apart. A **resource** is read off
    /// the entry's resource bit and its payload is never touched, because
    /// `docs/backlog.md` Q7 measured 694,470 of 694,470 Rockstar resource
    /// entries whose payload does not begin with `RSC7`: the bit is the only
    /// truth there is. Everything else is decided by the first
    /// [`Encoding::HEAD_LEN`] bytes of the entry's **contents** — inflated, so
    /// a deflated payload is classified by what it is rather than by what its
    /// first deflate block happens to look like.
    ///
    /// A payload that cannot be read is [`Classification::Binary`]. That is
    /// [`Archive::nested_at`]'s rule for the same reason: every walk over an
    /// archive asks this of every entry, and a listing that stopped at the
    /// first unreadable payload would be useless. `verify` is where a payload
    /// that does not read back is reported, one problem per path.
    ///
    /// # Errors
    ///
    /// As [`Archive::entry`] for an index the entry table does not hold or an
    /// entry it contradicts itself about.
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
    /// many of them there were.
    ///
    /// **The count is the answer's other half**, and a caller classifying the
    /// buffer without it reads the filler as content: an eleven-byte text
    /// payload followed by five zero bytes is not text, and reported itself as
    /// unknown binary until the count came back with it.
    ///
    /// Short by any means — a short payload, a payload that does not open, a
    /// deflate stream that fails part-way — is short rather than an error, for
    /// the reason [`Archive::classify`] states.
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

    /// Whether an entry's payload begins with the `RSC7` magic.
    ///
    /// **Not a classifier, and it cannot be made into one.** `docs/backlog.md`
    /// Q7 is closed: in a Rockstar archive this answers `false` on every
    /// resource there is, 694,470 of 694,470, and the entry's resource bit is
    /// the only truth. What it is for is comparing the two — the sample's
    /// third-party packer agrees on 20 of 20, Rockstar's agrees on none — and
    /// [`Archive::classify`] is what a caller asking what an entry is should
    /// ask.
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
    /// archive nested in it.
    ///
    /// Matching is [`same_name`], which is how the runtime addresses these
    /// paths. Every name in the sample is lower-case, so this repository cannot
    /// yet tell case-folded order from byte order — `docs/backlog.md` Q1.
    ///
    /// The empty path is the root directory.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] naming the component that failed, including when a
    /// component in the middle of the path turns out not to be a directory.
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
    /// Ambiguity is refused rather than resolved. [`same_name`] folds case, so
    /// two children of one directory can both answer to one spelling, and
    /// taking the first of them addresses one entry by another's name: measured,
    /// `rpf put … ax.txt` against an archive holding `AX.txt` beside `ax.txt`
    /// reported `patched 8 bytes in place`, exit 0, and `AX.txt` is what
    /// changed. This is the only resolution the patch-in-place path goes
    /// through, so it is where the refusal has to be — [`Archive::check_names`]
    /// is reached only by whoever turns the archive into a tree.
    ///
    /// # Errors
    ///
    /// As [`Archive::one_name_twice`] when more than one child answers to
    /// `name`.
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
    /// in one string.
    ///
    /// `x64/vehicles.rpf/meringls63amg24.yft` resolves in a single call. The
    /// descent is driven by position, not by extension: when a component
    /// resolves to a file and components remain, that file is opened as an
    /// archive. A file that is not one fails with [`Error::NotAnArchive`],
    /// which says more than "not found" would.
    ///
    /// Returns the archive that holds the entry — which is `self` when the path
    /// never left it — and the index within it.
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

    /// Parses an archive nested inside this one.
    ///
    /// Nesting is not a special case: the payload is another archive, and its
    /// offsets are relative to its own base. `docs/rpf-format.md`.
    ///
    /// This is the only way an archive's nesting depth grows, and it is
    /// bounded: a payload whose own payload is another archive, repeated, is
    /// recursion an archive chooses for its readers. [`MAX_DEPTH`].
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
        // A nested archive's own key is chosen by *its* name and length, not by
        // its holder's, so the material carries over and the name does not.
        // `docs/rpf-format.md`, Encryption.
        let unlock = self.unlock.renamed(self.name(index)?);
        Self::parse_nested(src, offset, on_disk, depth, &unlock)
    }

    /// The archive nested in an entry's payload, or `None` when the payload is
    /// not one.
    ///
    /// Every walk over an archive sniffs each payload for a nested one, so
    /// "this is not an archive" is the ordinary answer and cannot be a failure
    /// — a listing that stopped at the first `.txt` would be useless. A refusal
    /// on depth is not ordinary: it says the walk stopped short of what the
    /// archive describes, and swallowing it would report a truncated listing as
    /// a complete one, which is the plausible-but-wrong value §6 rules out
    /// alongside the panic it replaced.
    ///
    /// **An archive of a version this build does not read is `None` here**, and
    /// that is the limit of DR-010's amendment rather than a case it covers.
    /// `Error::UnsupportedVersion` carries the offset so that a nested archive
    /// of another version names where it is, which it does through
    /// [`Archive::locate`]; the sniff cannot fail on it without failing on
    /// every `.txt`, so `info` reports `nested 0` and `verify` passes clean on
    /// an archive holding a nested `RPF2`. Recorded rather than changed, and
    /// pinned by a test.
    ///
    /// # Errors
    ///
    /// [`Error::TooDeep`] past [`MAX_DEPTH`] levels of nesting, and nothing
    /// else: every other reason a payload is not an archive is an answer rather
    /// than a failure.
    pub fn nested_at<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Nested> {
        match self.open_nested(src, index) {
            Ok(nested) => Ok(Nested::Open(Box::new(nested))),
            Err(error @ Error::TooDeep { .. }) => Err(error),
            // The archive is there and this build cannot open it. Answering
            // "not an archive" made the count depend on what a key cache
            // happens to hold and let `verify` report clean over an archive it
            // never descended into. DR-041.
            Err(error) if error.category() == Category::NeedsKey => Ok(Nested::Locked(error)),
            Err(_) => Ok(Nested::None),
        }
    }
}

/// What one entry is: R3.7's six classes, and the two sources they come from.
///
/// [`Classification::Resource`] comes from the entry table and every other
/// variant from the payload's leading bytes, and **no value of this type can
/// mix the two**: there is no resource variant carrying an [`Encoding`] and no
/// [`Encoding`] naming a resource. That is the whole shape of the type, and it
/// is deliberate. Q7 measured that a payload sniff for `RSC7` answers `false`
/// on all 694,470 Rockstar resources, so the obvious implementation — read the
/// magic, believe it — is wrong on every archive the product exists to open,
/// and a type that cannot express it is worth more than a comment saying not
/// to. DR-044.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Classification {
    /// A directory. It has no payload to classify.
    Directory,
    /// A resource, **from the entry's resource bit**. Its payload is not read.
    ///
    /// What kind of resource — a `Meta`, a model, a texture — is not decided
    /// here: it is inside the paged payload, and reading it is R5.8.
    Resource,
    /// A binary entry whose leading bytes announce an encoding.
    Encoded(Encoding),
    /// A binary entry whose leading bytes announce nothing: R3.7's unknown
    /// binary, and by far the commonest answer in a real archive.
    Binary,
}

impl Classification {
    /// The encoding the payload announced, for a caller that has already
    /// decided what to do about the other three answers.
    ///
    /// `None` for a directory and for a resource — neither had its payload
    /// read — as well as for a binary entry nothing recognised.
    #[must_use]
    pub const fn encoding(self) -> Option<Encoding> {
        match self {
            Self::Encoded(encoding) => Some(encoding),
            Self::Directory | Self::Resource | Self::Binary => None,
        }
    }
}

/// What sniffing an entry's payload for a nested archive found.
///
/// Three answers rather than two, because "there is no archive here" and "there
/// is an archive here that this build could not open" are different facts and
/// a walk reports them differently. The distinction only became visible on
/// 2026-08-30: before key material could be present, every encrypted nested
/// archive was uniformly invisible, and afterwards the same walk answered
/// differently depending on what a cache held.
///
/// [`Nested::None`] still covers a version this build has no codec for, which
/// is DR-010's correction recorded rather than changed: raising that from the
/// sniff would fail `info` on an archive holding an ordinary file whose first
/// four bytes read `RPF3`. A key failure cannot happen to a `.txt` — the magic
/// and the version have already been read — so it is safe to name where an
/// unsupported version is not.
#[derive(Debug)]
pub enum Nested {
    /// The payload is not an archive, or is one of a version this build does
    /// not read.
    None,
    /// An archive, open.
    ///
    /// Boxed because an [`Archive`] is much the larger of the two arms and this
    /// is returned by value from every sniff of every walk.
    Open(Box<Archive>),
    /// An archive whose header this build read and whose table of contents it
    /// could not decrypt: [`Error::NeedsKey`] or [`Error::WrongKey`], carried
    /// so that whoever reports it can say which and can name the tag.
    Locked(Error),
}

/// Reads the header at `base`, or says why those bytes are not one.
///
/// The bytes are fetched here and decoded behind the seam: which fields a
/// header has, and how many bytes it occupies, are the version's.
/// [`Header::read`].
///
/// Leaves the source positioned wherever the read ended; every read after this
/// one seeks for itself.
fn read_header<R: Read + Seek>(src: &mut R, base: u64) -> Result<Header> {
    // Read as much of the longest header any version has as there is. A file
    // too short to hold one is not an archive, which is a better answer than
    // "i/o failure" — nothing failed, the bytes simply are not there.
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

    // The encryption tag is read here and acted on in `decrypt_table_of_contents`, which is
    // the only place that has the material to act on it with. R6.3 is still
    // what shapes the answer: "cannot open this" stays a distinct variant from
    // "this is broken".
    Header::read(bytes.get(0..filled).unwrap_or_default(), base)
}

/// Whether these bytes begin with a root directory row.
///
/// The one check that says a table of contents was decrypted with the right
/// key. Entry 0 is always the root directory (`docs/rpf-format.md`, Layout,
/// `verified`), and the marker that says so is a whole word no file entry can
/// produce — so a wrong key answers `false` with the odds of a 32-bit
/// coincidence, and a right one cannot answer anything else. DR-041.
fn is_root_directory(version: Version, table: &[u8]) -> bool {
    version
        .decode_row(table)
        .is_some_and(|entry| entry.is_directory())
}

/// What is going to decrypt an archive's table of contents, decided from the
/// header alone.
///
/// `None` for an archive that is not encrypted, which is the ordinary case and
/// touches no key material and no cache at all (R2.6).
struct Opening {
    /// The tag it was decided from, which a failure has to name.
    tag: u32,
    /// The transform that tag names.
    scheme: Scheme,
    /// Every material that could run that transform, in the order to try them.
    candidates: Vec<Arc<Material>>,
}

/// Which material is going to be tried, before a byte of layout is believed.
///
/// **Asked before the bounds checks on purpose.** An archive nobody here can
/// open must say so rather than be reported as malformed because its entry
/// table does not fit — the refusal is about the tag, and the tag is in the
/// sixteen bytes already read. That ordering is what
/// `crates/rpf-core/tests/no_keys.rs` pins.
///
/// # Errors
///
/// [`Error::NeedsKey`] when the archive is encrypted and no material is
/// available — which includes a tag no transform here is named for, because no
/// key anyone has opens one of those either.
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

/// Decrypts an archive's table of contents and names blob in place, and says
/// what opened them.
///
/// Answers the [`Unlock`] the archive keeps — the same source, with whatever it
/// resolved to already in hand — and the transform its payloads are under.
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

    // The row a key is judged by, read once: it is the same bytes for every
    // candidate, and only the transform over it differs.
    //
    // `None` is an archive whose header claims **no entries**, and then there
    // is no root directory row and nothing for a key to be right or wrong
    // about. That is not a key failure: it is an archive with no entries, and
    // asking for entry 0 is what answers — the same answer this header gives
    // under tag `OPEN`. It used to leave the loop into `WrongKey`, reporting
    // "1 source(s) tried" with no candidate having run, which tells an
    // automation to go and extract a key for ever.
    let root_row: Option<[u8; CIPHER_BLOCK_LEN]> = table.get(..CIPHER_BLOCK_LEN).map(|first| {
        let mut probe = [0_u8; CIPHER_BLOCK_LEN];
        probe.copy_from_slice(first);
        probe
    });

    for material in candidates {
        let Some(cipher) = Cipher::new(scheme, &material, unlock.name(), len) else {
            continue;
        };
        // One block decides it. Decrypting the whole table to find out costs
        // the table per candidate, and the answer is in its first row.
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
/// A child range inside the entry table is not enough. Three things are checked
/// here, and each of them is a crash somewhere downstream if it is not:
///
/// - the range fits the entry table, or an index in it names no entry;
/// - **every child comes after the directory that claims it.** The entry table
///   is laid out breadth-first, each directory's children in one run after it
///   (`docs/rpf-format.md`, Table order), so this holds of any archive a packer
///   wrote — and it is what makes the parent map well founded, since a walk up
///   it then strictly decreases and must end. `Archive::path` walks it in an
///   unguarded loop;
/// - **no entry is claimed twice.** Otherwise the children relation is a
///   lattice rather than a forest while the parent map, which holds one parent
///   per entry, looks perfectly ordinary — and it is the children relation that
///   `ls -R` recurses over.
///
/// The last two are what a single-valued, last-writer-wins parent map cannot
/// see. A directory whose range includes itself stays in the children relation
/// while being erased from the parent map the moment a later entry re-claims
/// the same child, and a check over the parent map alone then passes: measured,
/// three directory rows in 512 bytes left `info`, `cat` and `verify` all
/// reporting success and `ls -R` aborting with a stack overflow.
///
/// Refused here rather than guarded against at each walk (§5): a caller cannot
/// act on a value it never gets back.
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

/// Refuses a tree deeper than [`MAX_DEPTH`].
///
/// One forward pass, and it is only that cheap because of the rule above: every
/// entry's parent has a smaller index, so by the time an entry is reached its
/// parent's depth is already known. An entry no directory claims is a root of
/// its own and counts as depth zero, which is what entry 0 is.
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
    //! `Decrypting`'s read loop and its block arithmetic had no coverage that
    //! runs without a game installation: every gated test needs key material,
    //! and none of the five fuzz targets can reach this code at all because a
    //! target has no way to build a `Material` — the values are found by their
    //! own SHA-1 digests, so no synthetic source produces one (DR-006, DR-017).
    //! `Cipher::over_zeros` is what makes the framing testable without any.
    //!
    //! Nothing here checks a cipher value. What it checks is that the streaming
    //! form and the buffered form answer the same bytes, at every read size and
    //! from every offset — which is the claim `Cipher::block` being the one
    //! implementation is supposed to buy (§3).

    use std::io::Cursor;

    use super::{Decrypting, Region};
    use crate::format::crypto::{CIPHER_BLOCK_LEN, Cipher};

    /// Bytes that are not a pattern the block arithmetic could accidentally
    /// agree with.
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

    /// The lengths that matter: empty, under a block, a block exactly, a block
    /// and a tail, and several blocks with and without one.
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

        // The read loop fills one block and hands out what a caller asked for,
        // so a caller asking for one byte at a time crosses every boundary
        // there is. R7 clients do exactly this.
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

        // No chaining is what makes this possible: the block holding the target
        // is read and the remainder handed out from inside it. An off-by-one in
        // that arithmetic reads a whole entry from sixteen bytes away and
        // inflates to nonsense rather than failing.
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
        // block reports, not from what has been pulled out of the source, and
        // the two differ by whatever is still in hand.
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

        // The one place the streaming form could disagree with the buffered
        // one: a region whose last bytes are fewer than a block. They are
        // handed out exactly as they sit, which is `Cipher::apply`'s rule
        // reached from the other side.
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
}
