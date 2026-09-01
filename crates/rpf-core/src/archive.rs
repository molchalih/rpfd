//! The parsed table of contents of one archive; nested archives parse again at a different base.

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

/// How deep anything in this container may be walked before it is refused.
pub const MAX_DEPTH: u32 = 32;

fn read_exact_at<R: Read + Seek>(src: &mut R, offset: u64, buf: &mut [u8]) -> Result<()> {
    src.seek(SeekFrom::Start(offset))
        .map_err(|source| Error::Io { offset, source })?;
    src.read_exact(buf)
        .map_err(|source| Error::Io { offset, source })
}

/// Reads `len` bytes at `offset` into a fresh buffer; the caller must bounds-check `len` first.
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

struct Boundary {
    at: u64,
    len: u64,
    cipher: Option<Cipher>,
    expected: u64,
    payload: Payload,
}

pub(crate) struct Unframed {
    /// The opaque bytes before the deflate stream: sixteen or twenty-four (`RESOURCE_HEADER_LENS`).
    pub(crate) prefix: Vec<u8>,
    pub(crate) contents: Vec<u8>,
    pub(crate) sealed: bool,
}

/// What one entry's read found about its payload; `declared` and `used` can differ without failing.
pub(crate) struct Payload {
    entry: u32,
    len: u64,
    declared: u64,
    used: u64,
}

impl Payload {
    pub(crate) const fn len(&self) -> u64 {
        self.len
    }

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

fn shift(base: u64, delta: i64) -> io::Result<u64> {
    let target = if delta < 0 {
        base.checked_sub(delta.unsigned_abs())
    } else {
        base.checked_add(delta.unsigned_abs())
    };
    target.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek out of range"))
}

fn source_failed(at: u64, source: io::Error) -> io::Error {
    Error::Io { offset: at, source }.into_io()
}

#[derive(Debug)]
struct Region<S> {
    src: S,
    at: u64,
    len: u64,
    pos: u64,
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
            // UnexpectedEof here means the file is shorter than the archive declares.
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

/// A region decrypted one block at a time through a transform; the sub-block tail stays plain.
#[derive(Debug)]
struct Decrypting<R> {
    src: R,
    cipher: Cipher,
    len: u64,
    consumed: u64,
    block: [u8; CIPHER_BLOCK_LEN],
    filled: usize,
    taken: usize,
}

impl<R: Read + Seek> Decrypting<R> {
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

    fn position(&self) -> u64 {
        let held = u64::try_from(self.filled.saturating_sub(self.taken)).unwrap_or(0);
        self.consumed.saturating_sub(held)
    }

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

#[derive(Debug)]
enum Plain<S> {
    Clear(Region<S>),
    Keyed(Decrypting<Region<S>>),
}

impl<S: Read + Seek> Plain<S> {
    fn new(src: S, at: u64, len: u64, cipher: Option<Cipher>) -> Self {
        let region = Region::new(src, at, len);
        match cipher {
            None => Self::Clear(region),
            Some(cipher) => Self::Keyed(Decrypting::new(region, cipher, len)),
        }
    }

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

const RESOURCE_IS_IN_THE_CLEAR: Option<Cipher> = None;

#[derive(Debug, Clone, Copy)]
enum Form {
    File,
    Contents,
}

#[derive(Debug)]
enum Stream<S> {
    Stored(Plain<S>),
    Deflated(flate2::bufread::DeflateDecoder<BufReader<Plain<S>>>),
}

/// One entry as a stream of the bytes it is made of, in either framing.
#[derive(Debug)]
pub struct Extracted<S> {
    entry: u32,
    at: u64,
    len: u64,
    pos: u64,
    /// Bytes out of the decompressor, behind `Extracted::pos` by any forward seek.
    inflated: u64,
    /// How many bytes on disk the entry gives the stream.
    declared: u64,
    stream: Stream<S>,
}

impl<S: Read + Seek> Extracted<S> {
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

    /// Bytes on disk given to the stream, and how many it used; meaningful once read to the end.
    fn extent(&self) -> (u64, u64) {
        let used = match self.stream {
            Stream::Stored(ref plain) => plain.pos(),
            // What the decompressor took, not what it was handed, is where the stream ends.
            Stream::Deflated(ref decoder) => decoder.total_in(),
        };
        (self.declared, used)
    }

    fn reserve(&self) -> usize {
        match self.stream {
            Stream::Stored(_) => usize::try_from(self.len).unwrap_or_default(),
            Stream::Deflated(_) => 0,
        }
    }

    fn whole(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.reserve());
        let at = self.at;
        self.read_to_end(&mut out)
            .map_err(|source| Error::recovered(at, source))?;
        Ok(out)
    }

    fn drained(&mut self) -> Result<u64> {
        let at = self.at;
        io::copy(self, &mut io::sink()).map_err(|source| Error::recovered(at, source))
    }

    fn restart(&mut self) -> io::Result<()> {
        if let Stream::Deflated(ref mut decoder) = self.stream {
            decoder.reset_data();
            decoder.get_mut().seek(SeekFrom::Start(0))?;
        }
        self.pos = 0;
        self.inflated = 0;
        Ok(())
    }

    /// Inflates into `buf`, capped one byte past the declared length to catch an over-long payload.
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
                // Whatever a forward seek passed over is inflated here, at the read that needs it.
                self.catch_up()?;
                self.inflate(buf)?
            }
        };

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
    /// Seeks within the entry; a deflated stream restarts backward, moves forward for free.
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
    depth: u32,
    unlock: Unlock,
    scheme: Option<Scheme>,
    entries: Vec<Entry>,
    names: Names,
    parents: Vec<Option<u32>>,
}

impl Archive {
    /// Parses the archive that begins at `base` and runs for `len` bytes.
    /// # Errors
    /// Fails if the header is unrecognised, the key is wrong or missing, or a region does not fit.
    pub fn parse<R: Read + Seek>(
        src: &mut R,
        base: u64,
        len: u64,
        unlock: &Unlock,
    ) -> Result<Self> {
        Self::parse_nested(src, base, len, 0, unlock)
    }

    /// `Archive::parse`, told how deep it already sits, since that is not in the bytes.
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

        // Decided before the layout is believed, so an unopenable archive says so rather than
        // looking malformed.
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
        // Checked first, so too many entries names the entry table, not the names blob.
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

        // Decrypted before a row is decoded; keyed by this archive's own name and length.
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
    /// # Errors
    /// As `Archive::parse`, plus `Error::Io` if the length cannot be found.
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

    /// Which transform this archive's bytes were under, or `None` when it is not encrypted.
    #[must_use]
    pub fn scheme(&self) -> Option<&'static str> {
        self.scheme.map(Scheme::named)
    }

    /// Whether this archive can be written back at all.
    /// # Errors
    /// Fails for a transform this build cannot run forwards; no flag overrides that.
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

    /// What re-encrypts this archive's own bytes, or `None` when it is not encrypted.
    /// # Errors
    /// As `Archive::writable`, and `Error::WrongKey` with no material in hand.
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
    /// # Errors
    /// `Error::NoSuchEntry` if the index is past the end.
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
    /// # Errors
    /// `Error::NoSuchEntry` past the end, `Error::BadName` for non-UTF-8.
    pub fn name(&self, index: u32) -> Result<&str> {
        self.names.at(index)
    }

    /// The full path of an entry from the archive root; the root itself is the empty string.
    /// # Errors
    /// `Error::NoSuchEntry` if the index, or any ancestor, is past the end.
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

    /// Refuses an archive in which two children of one directory fold to one name.
    /// # Errors
    /// As `Archive::one_name_twice` and `Archive::path`.
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
            let Some(parent) = parent else { continue };
            if let Some(first) = seen.insert((parent, folded(self.name(index)?)), index) {
                return Err(self.one_name_twice(first, index)?);
            }
        }
        Ok(())
    }

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

    fn named(&self, index: u32) -> String {
        self.path(index)
            .unwrap_or_else(|_| format!("entry {index}"))
    }

    /// The indices of a directory's children.
    /// # Errors
    /// `Error::WrongKind` if the entry is not a directory.
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

    /// Where a payload begins and how long its row declares it, read literally, nothing checked.
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
                // Compressed size zero means stored; the other field then carries the real length.
                let len = if compressed_len == 0 {
                    uncompressed_len
                } else {
                    compressed_len
                };
                (block, u64::from(len))
            }
            // A resource has no such sentinel: both trailing words are flags, so zero is just
            // too small for its own `RSC7` header.
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

    /// Whether this entry's 24-bit compressed-size field saturated; its extent isn't in the row.
    fn size_field_saturated(&self, index: u32) -> Result<bool> {
        Ok(matches!(
            self.entry(index)?.kind,
            EntryKind::Resource { compressed_len, .. }
                if self.version.size_field_saturates(u64::from(compressed_len))
        ))
    }

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

    /// A saturated resource's length is the gap to its neighbour: table order, a monotonic cursor.
    fn payload_span(&self, index: u32) -> Result<(u64, u64)> {
        let (relative, declared) = self.declared_span(index)?;
        // Without this floor, an entry at block 0 reads the table of contents as file contents.
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
    /// # Errors
    /// As `Archive::entry`, and the bounds variants.
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

    /// Bytes an entry's payload may occupy without moving; straddling this start gives zero.
    /// # Errors
    /// As `Archive::payload_extents`, plus `Error::NoSuchEntry` or `Error::WrongKind`.
    pub fn allocation(&self, index: u32) -> Result<u64> {
        // Resolved first, so a bad index says so rather than looking like the wrong kind.
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
    /// # Errors
    /// As `Archive::payload_extents`.
    pub fn payload_at(&self, index: u32) -> Result<(u64, u64)> {
        self.payload_span(index)
    }

    /// Where this entry's row begins in the source.
    /// # Errors
    /// `Error::NoSuchEntry` if the index is past the end.
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

    /// Reads an entry's **contents**: what the file means, with no container framing left on it.
    /// # Errors
    /// `Error::WrongKind` for a directory, `Error::Inflate` or `Error::LengthMismatch` otherwise.
    pub fn read<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Vec<u8>> {
        self.opened(src, index, Form::Contents)?.whole()
    }

    /// A resource split into the three facts a converted write needs; the prefix crosses verbatim.
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

    /// The archive's transform for this resource; `in_hand` is its length, needed by the NG key.
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

    #[must_use]
    pub(crate) const fn encryption_tag(&self) -> u32 {
        self.encryption
    }

    /// `Archive::read` for a caller checking, not using, an entry; only what it learned comes back.
    pub(crate) fn read_back<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Payload> {
        // The boundary probe already answers this; going through `opened` would inflate twice.
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

    /// Where a resource's stream begins: 16 or 24 bytes, whichever inflates to the flags' length.
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
        // Saturated bounds nothing to report a shortfall against; the payload ends with the stream.
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

    /// `Archive::extract`'s streaming form, never held in memory.
    /// # Errors
    /// `Error::WrongKind` for a directory, `Error::ResourceTooSmall` if it can't hold its header.
    pub fn extracted<S: Read + Seek>(&self, src: S, index: u32) -> Result<Extracted<S>> {
        self.opened(src, index, Form::File)
    }

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

    fn opened<S: Read + Seek>(&self, src: S, index: u32, form: Form) -> Result<Extracted<S>> {
        let (offset, on_disk) = self.payload_span(index)?;
        let entry = self.entry(index)?;

        match entry.kind {
            EntryKind::Directory { .. } => Err(Error::WrongKind {
                path: self.named(index),
                found: "directory",
                wanted: "file",
            }),

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
                // The probe already settled start, length, transform, and extent.
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

    /// Reads an entry as the file outside the archive; unlike `read`, a resource stays deflated.
    /// # Errors
    /// As `Archive::read`.
    pub fn extract<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Vec<u8>> {
        self.extracted(src, index)?.whole()
    }

    /// What an entry is; a resource is read off the entry's resource bit, its payload untouched.
    /// # Errors
    /// As `Archive::entry`.
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

    /// Whether an entry's payload begins with the `RSC7` magic; a real resource payload never does.
    /// # Errors
    /// As `Archive::read` for the bounds cases.
    pub fn payload_is_resource<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<bool> {
        let (offset, on_disk) = self.payload_span(index)?;
        if on_disk < 4 {
            return Ok(false);
        }
        let mut magic = [0u8; 4];
        read_exact_at(src, offset, &mut magic)?;
        Ok(magic == MAGIC_RSC7)
    }

    /// Finds an entry by path within this archive, not descending into any nested archive.
    /// # Errors
    /// `Error::NotFound` naming the component that failed.
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

    /// Finds an entry by a path that may cross nested archives; returns the archive and index.
    /// # Errors
    /// `Error::NotFound` for a component that does not resolve, and as `Archive::parse`.
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

    /// Parses an archive nested inside this one's payload; the only way nesting depth grows.
    /// # Errors
    /// As `Archive::parse`, plus `Error::WrongKind` for a directory and `Error::TooDeep`.
    pub fn open_nested<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Self> {
        let (offset, on_disk) = self.payload_span(index)?;
        let depth = self.depth.checked_add(1).ok_or(Error::TooDeep {
            what: "archive nesting",
            depth: u32::MAX,
            limit: MAX_DEPTH,
        })?;
        // A nested archive's key is its own name; material carries over, the name does not.
        let unlock = self.unlock.renamed(self.name(index)?);
        Self::parse_nested(src, offset, on_disk, depth, &unlock)
    }

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

    /// The archive nested in an entry's payload, or `Nested::None` when it is not one.
    /// # Errors
    /// `Error::TooDeep` past `MAX_DEPTH` levels of nesting, and nothing else.
    pub fn nested_at<R: Read + Seek>(&self, src: &mut R, index: u32) -> Result<Nested> {
        match self.open_nested(src, index) {
            Ok(nested) => Ok(Nested::Open(Box::new(nested))),
            Err(error @ Error::TooDeep { .. }) => Err(error),
            // "Not an archive" here would depend on what a key cache holds.
            Err(error) if error.category() == Category::NeedsKey => Ok(Nested::Locked(error)),
            Err(_) => Ok(Nested::None),
        }
    }
}

/// What an archive nested in a payload is under, for a caller that must not move it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NestedTransform {
    Open,
    Known {
        /// Its own encryption tag.
        tag: u32,
        scheme: Scheme,
    },
    Unknown {
        /// The tag as it stands, which a refusal names.
        tag: u32,
    },
}

/// What one entry is: `Classification::Resource` comes from the entry table, others from its bytes.
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
    /// The encoding announced, or `None` for a directory, resource, or unrecognised binary entry.
    #[must_use]
    pub const fn encoding(self) -> Option<Encoding> {
        match self {
            Self::Encoded(encoding) => Some(encoding),
            Self::Directory | Self::Resource | Self::Binary => None,
        }
    }
}

/// What sniffing an entry's payload for a nested archive found.
#[derive(Debug)]
pub enum Nested {
    /// The payload is not an archive, or is a version this build does not read.
    None,
    /// An archive, open. Boxed because it is much the larger arm.
    Open(Box<Archive>),
    /// An archive this build could read the header of but not decrypt, carrying the reason.
    Locked(Error),
}

fn read_header<R: Read + Seek>(src: &mut R, base: u64) -> Result<Header> {
    // A file too short to hold the longest header is not an archive, not an i/o failure.
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

    Header::read(bytes.get(0..filled).unwrap_or_default(), base)
}

/// Whether these bytes begin with a root directory row: the check that the right key decrypts them.
fn is_root_directory(version: Version, table: &[u8]) -> bool {
    version
        .decode_row(table)
        .is_some_and(|entry| entry.is_directory())
}

struct Opening {
    /// The tag it was decided from, which a failure has to name.
    tag: u32,
    scheme: Scheme,
    /// Every material that could run that transform, in the order to try them.
    candidates: Vec<Arc<Material>>,
}

fn opening_for(version: Version, tag: u32, unlock: &Unlock) -> Result<Option<Opening>> {
    if version.is_open(tag) {
        return Ok(None);
    }
    // A tag this build has no transform for is `NeedsKey` whatever is in the cache.
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

    // `None` is a header claiming no entries, so there is nothing for a key to be right about.
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

fn count_of(entries: &[Entry]) -> u32 {
    u32::try_from(entries.len()).unwrap_or(u32::MAX)
}

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

/// Builds the child-to-parent map, verifying a well-founded forest with no entry claimed twice.
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

    use std::io::Cursor;

    use super::*;
    use crate::format::{crypto::AesKey, rpf7};

    fn bytes(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| u8::try_from(index.wrapping_mul(7).wrapping_add(3) & 0xFF).unwrap_or(0))
            .collect()
    }

    fn buffered(source: &[u8]) -> Vec<u8> {
        let mut expected = source.to_vec();
        Cipher::over_zeros().apply(&mut expected);
        expected
    }

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

        // `SeekFrom::Current` uses the position a partly-drained block reports, not bytes pulled.
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

        // `build::store` measures via `seek(SeekFrom::End(0))` then rewinds, so a forward seek
        // must inflate nothing.
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
