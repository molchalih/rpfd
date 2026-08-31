//! The container error type.
//!
//! Variants are structured, not stringly (§10): exit codes are derived from
//! them (R6.3), which makes the variant set part of the public contract. Each
//! carries what a caller needs to act on or report, never a pre-rendered
//! sentence.

use std::io;

use crate::{
    format::{Version, unsupported_version},
    manifest::Checksum,
};

/// Why an encrypted archive cannot be written, in the two ways it cannot.
///
/// A typed reason rather than a rendered sentence (§10), because the two name
/// different things for a caller to do: one is a wall, and the other is a
/// different command. DR-054.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NoWrite {
    /// The transform has no inverse in this build.
    ///
    /// The NG scheme is a white-box construction and this repository holds only
    /// its decrypt tables; inverting it is Gaussian elimination over GF(2) for
    /// rounds 0, 1 and 16 and a 2^32 sweep per column for the rest.
    /// `docs/ng-scheme.md`. Nothing a caller can supply changes it.
    #[error(
        "the NG transform has no inverse in this build, so an NG archive is \
         read and never written"
    )]
    NoInverse,

    /// The bytes are not being written **through the archive they came from**,
    /// so nothing here holds the key its tag chose.
    ///
    /// `pack` builds an archive out of a tree and a manifest and opens no
    /// archive at all, so it has no key material and no name to derive one
    /// from. Editing through the archive — `put`, `rm`, `mv`, `mkdir` — does,
    /// and **that remedy is the frontend's to spell**: `rpf`'s `advice` module
    /// names the commands, because a command name is a frontend's vocabulary
    /// and §10 keeps a rendered sentence out of a variant. DR-050's pattern.
    #[error(
        "pack builds from a tree and opens no archive, so it holds no key for \
         this tag"
    )]
    NotThroughTheArchive,
}

/// Anything that can go wrong reading a container.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The underlying source failed. `offset` is where we were reading.
    #[error("i/o failure at offset {offset}")]
    Io {
        /// Absolute offset in the source that was being read.
        offset: u64,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },

    /// A source of contents the caller supplied could not be read.
    ///
    /// [`crate::Contents`] is answered by the frontend, so this crate cannot
    /// say what the source was — the implementation names it, and this carries
    /// that name back out unchanged. Distinct from [`Error::Io`], which is
    /// about the archive and names an offset in it; a donor file has no offset
    /// in the archive, and what the caller needs is which file. DR-036.
    #[error("{name}: {source}")]
    Contents {
        /// The source, as the frontend that supplied it names it.
        name: String,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },

    /// The bytes at the archive's base are not an RPF7 header.
    ///
    /// **Its category is decided by `found`.** The four bytes are the only
    /// thing in the format that ever claims an archive is here — no entry row
    /// marks a payload as one, which is why every walk sniffs — so bytes that
    /// name a container version and then fail to hold a whole header are a
    /// malformed archive, and bytes that name nothing are a request that
    /// called an ordinary file an archive. DR-019.
    #[error("not an RPF7 archive at offset {base}: magic reads {found:02x?}")]
    NotAnArchive {
        /// Where the archive was expected to begin.
        base: u64,
        /// The four bytes actually found there. Also what decides whether this
        /// is [`Category::Corrupt`] or [`Category::Refused`].
        found: [u8; 4],
    },

    /// The bytes at the archive's base are an RPF header of a version this
    /// build does not read.
    ///
    /// Distinct from [`Error::NotAnArchive`], which is what the version used to
    /// be reported as: nothing here is malformed. The version is in the first
    /// four bytes and throwing it away told a caller the archive was broken.
    /// DR-012, and DR-010's amendment for the category.
    #[error(
        "RPF{version} archive at offset {base}: magic reads {found:02x?}, \
         and this build reads only RPF7 in its 7FPR spelling"
    )]
    UnsupportedVersion {
        /// Where the archive was expected to begin.
        base: u64,
        /// The version number the magic names.
        version: u8,
        /// The four bytes actually found there, which say which of the two
        /// byte orders the archive was written in.
        found: [u8; 4],
    },

    /// The archive is encrypted and no key material is available.
    ///
    /// Distinct from [`Category::Corrupt`] on purpose: the archive is fine, we
    /// simply cannot open it here. R2 and R6.3.
    #[error("archive is encrypted (tag {tag:#010x}); no key material available")]
    NeedsKey {
        /// The encryption tag from the header.
        tag: u32,
    },

    /// The archive is encrypted, key material **is** available, and none of it
    /// opens the archive.
    ///
    /// Distinct from [`Error::NeedsKey`] because the two name different things
    /// to do (DR-010): the first is answered by extracting key material, and
    /// this one cannot be — the material in hand is the wrong material, or the
    /// archive was renamed after it was packed, which changes the key it is
    /// under (`docs/rpf-format.md`, Encryption). Both are
    /// [`Category::NeedsKey`], because the person holding the archive is the
    /// one who acts either way.
    ///
    /// It is decided by the archive's own root directory row, not by a guess:
    /// a table of contents that decrypts to something whose entry 0 is not the
    /// root directory was decrypted with the wrong key. DR-041.
    #[error(
        "the {scheme} key material available does not open this archive \
         (tag {tag:#010x}, {tried} source(s) tried)"
    )]
    WrongKey {
        /// The encryption tag from the header.
        tag: u32,
        /// Which transform the tag names, for a caller deciding what material
        /// to go and get. Never a key, and never a key index: DR-020.
        scheme: &'static str,
        /// How many sources' material was tried before this was answered.
        tried: u32,
    },

    /// The archive is encrypted and this write cannot produce one.
    ///
    /// Two situations, and `reason` tells them apart because they are two
    /// different things to do about it — [`NoWrite`]. An AES-tagged archive is
    /// written back through the archive it was read from; an NG-tagged one is
    /// written back by nobody outside Rockstar.
    ///
    /// Every write path answers this before it touches a byte, so an archive
    /// refused here is exactly as it was.
    ///
    /// [`Category::Unsupported`] rather than [`Category::NeedsKey`]: no
    /// material closes either gap, because the missing part is here and not
    /// there. Not [`Category::Refused`] either — the request was reasonable and
    /// the container simply cannot. DR-010's amendment, DR-041, DR-054.
    #[error("archive is encrypted (tag {tag:#010x}); {reason}")]
    CannotWriteEncrypted {
        /// The encryption tag from the header.
        tag: u32,
        /// Which of the two gaps this is.
        reason: NoWrite,
    },

    /// A game executable does not carry the key material this build knows how
    /// to find.
    ///
    /// Extraction anchors each value on the SHA-1 of its own bytes rather than
    /// on an offset, so a match is its own proof and a miss means the value is
    /// not present in that exact form — a different build of the game, a
    /// patched executable, or the wrong file entirely. It carries the counts
    /// because "1 of 2" and "0 of 2" are different situations to be in, and it
    /// names the values it did not find because "1 of 2" does not say which.
    ///
    /// [`Category::Unsupported`] for the reason [`Error::UnsupportedVersion`]
    /// is: the file is intact and the part that is missing is here.
    #[error(
        "{what}: {found} of {wanted} values are in this executable; missing {}",
        .missing.join(" and ")
    )]
    UnrecognisedExecutable {
        /// Which material was looked for.
        what: &'static str,
        /// The values that were not found, by name, and never empty — a search
        /// that found everything is not this failure.
        ///
        /// A kind rather than each value: the NG survey looks for 373 of them
        /// and 373 names are not something a caller acts on, while `found` and
        /// `wanted` already say how many. Names only, so nothing here can carry
        /// a byte of what was looked for (DR-006).
        missing: &'static [&'static str],
        /// How many of its values were found.
        found: u32,
        /// How many there are to find.
        wanted: u32,
    },

    /// A region the header describes does not fit inside the archive.
    #[error("{region} runs from {offset} for {len} bytes, past the archive's {archive_len}")]
    OutOfBounds {
        /// Which region: `"entry table"`, `"names blob"`, `"payload"`.
        region: &'static str,
        /// Where the region claims to start, relative to the archive's base.
        offset: u64,
        /// How long it claims to be.
        len: u64,
        /// The archive's own declared length.
        archive_len: u64,
    },

    /// An entry's name offset does not point at a terminated string inside the
    /// names blob.
    ///
    /// Reading past `namesLength` is how stale names from a previous pack get
    /// mistaken for live ones. `docs/rpf-format.md`, Slack.
    #[error(
        "entry {entry}: name offset {name_offset} is not a terminated string in {names_len} bytes"
    )]
    BadName {
        /// Index of the offending entry.
        entry: u32,
        /// The name offset it carried.
        name_offset: u32,
        /// Length of the names blob.
        names_len: u32,
    },

    /// A directory entry's child range is not inside the entry table.
    #[error("entry {entry}: children {first}..+{count} are outside the {entry_count} entries")]
    BadChildRange {
        /// Index of the offending directory.
        entry: u32,
        /// First child index it claimed.
        first: u32,
        /// How many children it claimed.
        count: u32,
        /// How many entries the archive actually has.
        entry_count: u32,
    },

    /// A directory claims a child that does not come after it in the entry
    /// table — itself, or an entry above it — so the entries do not form a
    /// tree.
    ///
    /// The entry table is laid out breadth-first, each directory's children in
    /// one run after it (`docs/rpf-format.md`, Table order), so a child index
    /// greater than its parent's is what makes the parent map well founded: a
    /// walk up it strictly decreases and therefore ends. A claim that goes the
    /// other way is what a cycle is made of.
    ///
    /// Distinct from [`Error::BadChildRange`], and worse: every index involved
    /// is inside the entry table, so walking the parent map does not run off
    /// the end — it runs for ever. Refused at parse, because a caller cannot
    /// act on a value it never gets back.
    #[error("entry {entry}: child {child} does not come after it in the entry table")]
    CyclicTree {
        /// Index of the directory that claimed the child.
        entry: u32,
        /// The child it claimed.
        child: u32,
    },

    /// Two directories claim the same entry as a child, so the entries are not
    /// a forest.
    ///
    /// Nothing here is out of range and nothing is a cycle, which is why it
    /// needs saying separately: the children relation can still be a lattice,
    /// and the number of root-to-leaf paths through one doubles per row. A
    /// 512-byte archive of 26 such rows made `ls -R` produce 33,554,431 rows.
    #[error("entry {child} is claimed as a child by both entry {first} and entry {second}")]
    ClaimedTwice {
        /// The entry claimed more than once.
        child: u32,
        /// The first directory to claim it.
        first: u32,
        /// The second.
        second: u32,
    },

    /// A recursive structure is deeper than this container will walk.
    ///
    /// Both directory trees and archives nested inside archives are walked
    /// recursively, by this crate and by everything built on it, and both
    /// depths are the archive's to choose. Nothing about a deep one is
    /// self-contradictory — which is exactly why it is refused at a stated
    /// depth rather than discovered as a stack overflow (§6).
    #[error("{what} is {depth} deep, over the limit of {limit}")]
    TooDeep {
        /// Which structure: `"directory tree"` or `"archive nesting"`.
        what: &'static str,
        /// The depth reached.
        depth: u32,
        /// The deepest that is accepted.
        limit: u32,
    },

    /// An entry's payload begins inside the archive's own header, entry table
    /// or names blob rather than after them.
    ///
    /// Distinct from [`Error::OutOfBounds`]: the region fits inside the
    /// archive, and that is what makes it dangerous. Reading it hands back the
    /// archive's own structure as file contents, and the room reported for
    /// patching it in place covers the header.
    #[error("entry {entry}: payload begins at {offset}, before the first payload offset {floor}")]
    PayloadUnderflow {
        /// Index of the offending entry.
        entry: u32,
        /// Where the payload claims to begin, relative to the archive's base.
        offset: u64,
        /// The lowest offset a payload may occupy in this archive.
        floor: u64,
    },

    /// A resource entry's compressed size cannot hold its own `RSC7` header.
    #[error("entry {entry}: resource of {compressed_len} bytes is smaller than its 16-byte header")]
    ResourceTooSmall {
        /// Index of the offending entry.
        entry: u32,
        /// The compressed size it declared.
        compressed_len: u32,
    },

    /// The payload did not inflate.
    ///
    /// A fact about the archive's bytes, not about the source they came from:
    /// every byte asked for arrived, and then did not decode. DR-010.
    #[error("entry {entry}: payload did not inflate")]
    Inflate {
        /// Index of the offending entry.
        entry: u32,
        /// The underlying decompression failure.
        #[source]
        source: io::Error,
    },

    /// The payload inflated, but not to the length the archive promised.
    ///
    /// Worth its own variant: it means the archive is internally inconsistent
    /// rather than unreadable, and that is a different thing to report.
    #[error("entry {entry}: inflated to {actual} bytes, archive declares {expected}")]
    LengthMismatch {
        /// Index of the offending entry.
        entry: u32,
        /// The length the archive declared.
        expected: u64,
        /// The length actually produced.
        actual: u64,
    },

    /// The payload's deflate stream ended before the payload did, so the entry
    /// declares bytes that are not part of anything it holds.
    ///
    /// A deflate stream carries its own end, so the bytes after it inflate to
    /// nothing and are silently ignored: the contents come back exactly as the
    /// archive promises them while the payload is longer than what produced
    /// them. That is the archive contradicting itself, which is why it is
    /// `Corrupt` and not a refusal — but it is reported by `verify` rather
    /// than refused by a read, because one producer's archives are not enough
    /// evidence to reject another's. `docs/backlog.md`, R6.10.
    ///
    /// Carries both lengths because both are what a caller acts on: where the
    /// stream ends, and how much the entry claims after it.
    #[error(
        "entry {entry}: the deflate stream ends after {used} bytes, \
         but the payload declares {declared}"
    )]
    TrailingBytes {
        /// Index of the offending entry.
        entry: u32,
        /// How many bytes of payload the entry table declares. For a resource
        /// this is its compressed size with the 16-byte `RSC7` header taken
        /// off, which is the extent of the stream itself.
        declared: u64,
        /// How many of them the deflate stream consumed.
        used: u64,
    },

    /// An entry's contents are not the contents recorded for it.
    ///
    /// The one failure here that the archive cannot state on its own. A
    /// deflated entry declares its inflated length and its stream carries its
    /// own end, so bytes changed inside one surface as [`Error::Inflate`],
    /// [`Error::LengthMismatch`] or [`Error::TrailingBytes`]; a **stored**
    /// entry declares neither, so a byte changed inside it reads back
    /// perfectly and is the wrong byte. Only a checksum recorded elsewhere —
    /// the sidecar manifest's, DR-004's territory, since nothing in an RPF
    /// archive carries one — can see it. DR-023.
    ///
    /// [`Category::Corrupt`], not [`Category::Refused`]: the caller asked a
    /// reasonable question and the answer is that the archive's bytes are not
    /// the bytes they were. DR-010.
    ///
    /// Identifies the entry by index, as every failure about the archive's own
    /// bytes does. The path is `crate::Problem`'s to carry, and repeating it
    /// here would be the same string twice in one sentence.
    /// [`Error::WrongKind`] names a path instead, and the reason it differs is
    /// stated there: it is a fact about the request rather than about the
    /// bytes.
    #[error("entry {entry}: contents digest {found}, not the recorded {recorded}")]
    ChecksumMismatch {
        /// Index of the offending entry.
        entry: u32,
        /// The digest recorded for it.
        recorded: Checksum,
        /// The digest its contents actually have.
        found: Checksum,
    },

    /// An entry index does not exist in this archive.
    #[error("no entry with index {index}; the archive has {entry_count}")]
    NoSuchEntry {
        /// The index asked for.
        index: u32,
        /// How many entries exist.
        entry_count: u32,
    },

    /// No entry at the given path.
    ///
    /// `segment` is the component that failed, which is more useful than the
    /// whole path when addressing through several nested archives.
    #[error("no entry at {path:?}: {segment:?} not found")]
    NotFound {
        /// The path that was asked for.
        path: String,
        /// The component of it that did not resolve.
        segment: String,
    },

    /// A value does not fit the field the format stores it in.
    ///
    /// The container's fields are narrow — a compressed size is 24 bits, a
    /// block offset 23, a file's name offset 16 — and exceeding one is a limit
    /// of the format, not a bug in the caller's input.
    #[error("{path:?}: {what} is {len}, over the format's limit of {limit}")]
    FieldOverflow {
        /// The entry being written.
        path: String,
        /// Which field overflowed.
        what: &'static str,
        /// The value that did not fit.
        len: u64,
        /// The largest value that would have.
        limit: u64,
    },

    /// The layout ran past the largest payload offset the version can address.
    ///
    /// A version stores a payload's offset in a narrow field, so it has a size
    /// ceiling: RPF7 counts 512-byte blocks in 23 bits, which is 4,294,966,784
    /// bytes. `docs/rpf-format.md`, Entry table.
    ///
    /// Not a [`Error::FieldOverflow`], although it is noticed in the same
    /// place. Every other narrow field is a fact about the entry that
    /// overflowed it and is fixed by changing that entry; this is a fact about
    /// the **archive**, and the entry named is only where the layout first ran
    /// past the end — which is not the entry the caller added, and is nothing
    /// the caller chose.
    #[error(
        "the archive is too large: this version addresses {limit} bytes \
         and the layout reached {reached} (at {path:?})"
    )]
    ArchiveTooLarge {
        /// The entry the layout was placing when it ran past the limit.
        path: String,
        /// The offset it reached, in bytes.
        reached: u64,
        /// The largest offset this version addresses, in bytes.
        limit: u64,
    },

    /// A payload cannot be written into a resource entry.
    ///
    /// **Never because it does not begin with `RSC7`.** `docs/backlog.md` Q7
    /// measured that no Rockstar resource payload does, so that test refused
    /// the archives it was meant to serve; what is refused now is a write whose
    /// row could not be filled in. DR-046.
    #[error("{path:?}: cannot be written into a resource entry: {reason}")]
    NotAResource {
        /// The entry being written.
        path: String,
        /// What is missing, for a caller that has to change what it asked for.
        reason: &'static str,
    },

    /// A payload cannot be written into an entry that holds a tokenised
    /// metadata encoding.
    ///
    /// Both encodings are carried rather than a sentence, so a caller acts on
    /// the pair rather than on English (§10). DR-050.
    #[error(
        "{path:?}: an entry holding {} cannot take a payload of {}",
        held.name(),
        offered.name()
    )]
    WrongEncoding {
        /// The entry being written, by path from the archive that holds it.
        path: String,
        /// What its payload announces itself to be now.
        held: crate::metadata::Encoding,
        /// What the offered payload announces itself to be.
        offered: crate::metadata::Encoding,
    },

    /// An entry was asked for as XML and has no XML view.
    ///
    /// What it holds is carried rather than a sentence (§10), and `None` is
    /// both "its payload announces nothing" and "it is a resource, whose
    /// payload is not read" — `docs/backlog.md` Q7. An entry that gains a view
    /// later stops answering this, which is what makes it the right refusal to
    /// leave R5.8 room in. DR-053.
    #[error(
        "{path:?}: an entry holding {} has no XML view",
        held.map_or("no encoding this tool converts", crate::metadata::Encoding::name)
    )]
    NoXmlView {
        /// The entry, by path from the archive that holds it.
        path: String,
        /// What its payload announces itself to be, if anything.
        held: Option<crate::metadata::Encoding>,
    },

    /// Two children of one directory are one name here, so one of them cannot
    /// be addressed by any spelling of its own path.
    ///
    /// Path components resolve case-insensitively in this container
    /// ([`crate::format::same_name`]), so `A.txt` and `a.txt` in one directory
    /// are one name and the second is unreachable. Reported by the writer,
    /// which will not produce such an archive, and by the reader, which will
    /// not turn one into a tree, rather than "2 files" now and a failure one
    /// command later. R10.4.
    ///
    /// **Two names one reader cannot tell apart is three conditions, not one,
    /// and this variant is the first of them.** The other two are
    /// [`Error::BadPath`]: `"is named twice in one directory"` for one name
    /// carried twice, and `"a file and a directory share one name"` for a
    /// clash of kinds. The writer has always answered all three separately;
    /// the reader answered every one of them with this variant, which rendered
    /// `"aa.txt" and "aa.txt" are one name here` for an exact duplicate — one
    /// string named twice, telling a caller nothing. Both variants are
    /// [`Category::Refused`] and exit 6, so nothing branching on the number
    /// moves; what changes is that the sentence is now the same one either
    /// way.
    ///
    /// **Both are paths from the archive's root, and they are the two names
    /// that collide** — not the request that ran into the collision. For a
    /// directory component that is not the same thing: adding
    /// `X64/alpha.txt` to a tree that already holds `x64` used to render
    /// `"X64/alpha.txt" and its sibling "x64" are one name here`, which is
    /// untrue twice over — those two are neither siblings nor one name. What
    /// the caller has to act on is the pair of directories, and §10 says a
    /// variant carries that rather than what was being attempted when it
    /// surfaced.
    #[error("{path:?} and {other:?} are one name here, so one of them cannot be addressed")]
    NameCollision {
        /// One of the two, by path from the archive's root.
        path: String,
        /// The other, likewise. The two sit in one directory.
        other: String,
    },

    /// A path a change would create is already in the archive.
    ///
    /// The counterpart of [`Error::NotFound`], and a refusal rather than a
    /// corruption: nothing about the archive is wrong, and what the caller has
    /// to do is pick another name or remove what is there. It exists as its own
    /// variant because a client mapping this onto an editor's filesystem has a
    /// distinct answer for it, which "invalid path" would not reach.
    ///
    /// A rename onto an occupied path and a directory created twice are the two
    /// that raise it. A **write** does not: replacing what is at a path is what
    /// a write has always meant here, and DR-026 keeps it that way.
    #[error("{path:?} is already in the archive")]
    AlreadyExists {
        /// The path that is taken, from the archive's root.
        path: String,
    },

    /// A change set already holds a change at this path, and the one offered
    /// would replace it rather than join it.
    ///
    /// A set holds one change per path ([`crate::Change`]), so a second change
    /// at a path silently drops the first. Measured over the wire on
    /// 2026-08-29: a buffered rename followed by a write of the same entry was
    /// answered `pending: 1`, and the commit renamed nothing. Two **writes** are
    /// not this — saving one file twice is what an editor does, and the later
    /// contents are what it means — and neither is the same change offered
    /// again.
    ///
    /// A refusal rather than a corruption: what the caller has to do is take
    /// the change it no longer wants back out of the set. DR-032.
    #[error("{path:?} already has {held} in this change set, which holds one change per path")]
    Claimed {
        /// The path both changes are at.
        path: String,
        /// What the change already there is: `"a write"`, `"a removal"`,
        /// `"a rename"` or `"a new directory"`.
        held: &'static str,
    },

    /// A path cannot be turned into entries.
    #[error("invalid path {path:?}: {reason}")]
    BadPath {
        /// The offending path.
        path: String,
        /// Why it cannot be used.
        reason: &'static str,
    },

    /// Two edits in one plan claim the same bytes.
    ///
    /// A nested archive and a file inside it, or two spellings of one path.
    /// Nothing about the archive is wrong, so this is a refusal rather than a
    /// corrupt archive: the caller has to drop one of the two or rebuild.
    #[error("{path:?} and {other:?} cannot be patched together: they claim the same bytes")]
    Overlapping {
        /// The edit that collided.
        path: String,
        /// The edit already planned over those bytes.
        other: String,
    },

    /// A watcher stopped the write. DR-008.
    ///
    /// Not a failure of the archive or of the caller's input — the caller asked
    /// for this — which is why it carries how far it got rather than a reason.
    #[error("cancelled after {done} of {total} entries")]
    Cancelled {
        /// How many entries had been written when it stopped.
        done: u32,
        /// How many there would have been.
        total: u32,
    },

    /// Entries are not as they are recorded.
    ///
    /// What a failing `verify` returns. It is one failure about a set of
    /// entries rather than about any one of them, so it carries the two counts
    /// a caller acts on — how many were read, and how many of those were not
    /// as recorded — and leaves the per-entry detail to the report beside it.
    /// R6.9. Borrowing [`Error::LengthMismatch`] for this rendered
    /// "entry 0: inflated to 25 bytes, archive declares 26", a sentence about
    /// inflation with nothing to do with what happened.
    ///
    /// "as they are recorded" rather than "as the archive describes them",
    /// which was true until a manifest could be given: a checksum mismatch is
    /// an entry that read back *perfectly* and disagrees with what the sidecar
    /// recorded for it, so the archive is not the only thing doing the
    /// describing any more. DR-023, DR-025.
    #[error("{failed} of {checked} entries are not as they are recorded")]
    VerifyFailed {
        /// How many file entries were read, the failing ones included.
        checked: u32,
        /// How many of them did not come back as the archive promised.
        failed: u32,
    },

    /// The entry exists but is not the kind the operation needs.
    ///
    /// **Named by path, not by index**, unlike the per-entry failures above it.
    /// Those are all facts about the archive's own bytes, which a caller reads
    /// alongside an entry table; this one is a fact about the *request* — the
    /// caller named something, and it was the wrong kind of thing — and what it
    /// named was a path. `rpf info a.rpf data` reported `entry 1 is a
    /// directory, expected a file`, which says nothing a caller can act on
    /// without first working out what entry 1 is.
    ///
    /// The path is spelled as the caller spelled it wherever there is a caller
    /// to ask: [`crate::Summary::of`] refills it with the path it was given, so
    /// an entry inside a nested archive names the whole path rather than its
    /// path within that archive. Where there is no caller — a walk that reached
    /// the entry on its own — it is `Archive::path`, falling back to the
    /// index when the tree does not resolve, which is the one case where
    /// nothing better exists.
    #[error("{path:?} is a {found}, expected a {wanted}")]
    WrongKind {
        /// The entry, by path from the archive that holds it.
        path: String,
        /// What it actually is.
        found: &'static str,
        /// What the operation needed.
        wanted: &'static str,
    },

    /// An `RBF` payload's token stream is not well formed.
    ///
    /// The metadata layer's failures are variants of this enum rather than of
    /// one of their own, because §10 counts **crate** boundaries and there is
    /// one of those. What is not flattened is the cause: it is the metadata
    /// layer's own typed enum, so that the layer keeps its vocabulary and this
    /// enum does not grow a variant per token.
    #[error("malformed RBF at offset {offset}")]
    BadRbf {
        /// Where in the payload the stream stopped making sense.
        offset: u64,
        /// What was wrong with it.
        cause: crate::metadata::rbf::Malformed,
    },

    /// An `RBF` payload is well formed and says something XML cannot carry.
    ///
    /// Distinct from [`Error::BadRbf`] because the caller's position is
    /// different: those bytes are wrong, these are right and this build has no
    /// way to render them. Every one of them is measured never to occur in a
    /// shipped file — `docs/metadata-encodings.md` gives the count for each.
    #[error("the RBF payload cannot be written as XML")]
    UnrepresentableRbf {
        /// Which thing it says.
        cause: crate::metadata::rbf::Unrepresentable,
    },

    /// A `PSO` payload contradicts itself.
    ///
    /// The same shape as [`Error::BadRbf`] and for the same reason: §10 counts
    /// **crate** boundaries and there is one, so the metadata layer keeps its
    /// own vocabulary inside `cause` rather than this enum growing a variant
    /// per section.
    #[error("malformed PSO at offset {offset}")]
    BadPso {
        /// Where in the payload the file stopped making sense.
        offset: u64,
        /// What was wrong with it.
        cause: crate::metadata::pso::Malformed,
    },

    /// A resource `Meta` payload contradicts itself.
    ///
    /// The same shape as [`Error::BadPso`] and for the same reason: §10 counts
    /// **crate** boundaries and there is one, so the metadata layer keeps its
    /// own vocabulary inside `cause` rather than this enum growing a variant
    /// per table.
    #[error("malformed Meta at offset {offset}")]
    BadMeta {
        /// Where in the payload the file stopped making sense.
        offset: u64,
        /// What was wrong with it.
        cause: crate::metadata::meta::Malformed,
    },

    /// A `PSO` payload is well formed and carries something this build does not
    /// decode.
    ///
    /// `docs/metadata-encodings.md` measured 37 `(type, subtype)` pairs over
    /// 580,044 members, and a decoder that handles those handles every metadata
    /// file both games ship — so reaching this means a file neither shipped
    /// build contains.
    #[error("the PSO payload carries something this build does not decode")]
    UnsupportedPso {
        /// Which thing.
        cause: crate::metadata::pso::Unsupported,
    },

    /// The XML handed to the metadata layer does not describe an `RBF`
    /// document.
    #[error("the XML at position {position} does not describe an RBF document")]
    NotRbfXml {
        /// Where in the XML the reader was. What a caller acts on: it is what
        /// puts an editor's cursor on the line that has to change.
        position: u64,
        /// What was wrong with it.
        cause: crate::metadata::rbf::NotRbf,
    },

    /// The XML handed to the metadata layer does not describe the `PSO`
    /// payload it was given beside.
    ///
    /// The `PSO` write direction is an edit of the file the document came from
    /// — DR-049 — so this says the two disagree rather than that either is
    /// malformed on its own.
    #[error("the XML at position {position} does not describe this PSO payload")]
    NotPsoXml {
        /// Where in the XML the reader was, so an editor can put the cursor on
        /// the line that has to change.
        position: u64,
        /// What was wrong with it.
        cause: crate::metadata::pso::NotPsoXml,
    },
}

/// The class of a failure, which is what an exit code is derived from.
///
/// R6.3 wants exit codes that distinguish these, so the mapping lives here
/// rather than in the binary: the variant set is the public contract (§10), and
/// a new variant that forgets to classify itself would otherwise become an
/// exit code silently.
/// A category names what the caller has to do about the failure rather than
/// what the code was doing when it noticed. DR-010.
/// Deliberately **not** `#[non_exhaustive]`, unlike [`Error`]: a new category
/// must break every mapping of it at compile time, which is the whole point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// The thing asked for is not in the archive.
    NotFound,
    /// The archive contradicts itself, or does not decompress as it promises.
    Corrupt,
    /// The archive is intact but needs key material we do not have.
    NeedsKey,
    /// The archive is intact and this build cannot read it. Nobody who is
    /// holding it can act: the missing part is here. DR-010's amendment.
    Unsupported,
    /// The container declines to carry out the request. Either it is not well
    /// formed, or it is and the container will not do it. DR-010.
    Refused,
    /// The caller stopped it part-way.
    Cancelled,
    /// The source or sink failed. Nobody's input is in question: this is the
    /// disk, the pipe or the handle. DR-010.
    Io,
}

/// Whether four bytes at an archive's base claim to be a container at all.
///
/// Composed from the two things `format` already names, rather than spelling
/// the magic again (§3): the version this build reads, and the versions it
/// only recognises. Either claim is enough — what matters is that something
/// asserted an archive was there.
fn claims_a_container(magic: [u8; 4]) -> bool {
    magic == Version::Rpf7.magic() || unsupported_version(magic).is_some()
}

impl Error {
    /// What kind of failure this is.
    ///
    /// Not `const`, because [`Error::NotAnArchive`] is classified from the
    /// bytes it carries and that reads a `format` function. DR-019.
    #[must_use]
    pub fn category(&self) -> Category {
        match *self {
            Self::Io { .. } | Self::Contents { .. } => Category::Io,
            Self::NeedsKey { .. } | Self::WrongKey { .. } => Category::NeedsKey,
            Self::UnsupportedVersion { .. }
            | Self::UnrecognisedExecutable { .. }
            | Self::CannotWriteEncrypted { .. }
            | Self::UnrepresentableRbf { .. }
            | Self::UnsupportedPso { .. } => Category::Unsupported,
            Self::NotFound { .. } | Self::NoSuchEntry { .. } => Category::NotFound,
            Self::Overlapping { .. }
            | Self::FieldOverflow { .. }
            | Self::ArchiveTooLarge { .. }
            | Self::NotAResource { .. }
            | Self::WrongEncoding { .. }
            | Self::NoXmlView { .. }
            | Self::BadPath { .. }
            | Self::AlreadyExists { .. }
            | Self::Claimed { .. }
            | Self::NameCollision { .. }
            | Self::WrongKind { .. }
            | Self::NotRbfXml { .. }
            | Self::NotPsoXml { .. } => Category::Refused,
            Self::Cancelled { .. } => Category::Cancelled,
            // DR-019: the bytes decide. A payload that never claimed to be an
            // archive was named one by the caller's own path.
            Self::NotAnArchive { found, .. } => {
                if claims_a_container(found) {
                    Category::Corrupt
                } else {
                    Category::Refused
                }
            }
            Self::OutOfBounds { .. }
            | Self::BadName { .. }
            | Self::BadChildRange { .. }
            | Self::CyclicTree { .. }
            | Self::ClaimedTwice { .. }
            | Self::TooDeep { .. }
            | Self::PayloadUnderflow { .. }
            | Self::ResourceTooSmall { .. }
            | Self::Inflate { .. }
            | Self::LengthMismatch { .. }
            | Self::TrailingBytes { .. }
            | Self::ChecksumMismatch { .. }
            | Self::VerifyFailed { .. }
            | Self::BadRbf { .. }
            | Self::BadPso { .. }
            | Self::BadMeta { .. } => Category::Corrupt,
        }
    }

    /// This variant's own name, as a stable symbol.
    ///
    /// The category ([`Error::category`]) says who has to act and is what the
    /// exit code is derived from; this says **which** failure it was, for a
    /// caller that has a distinct answer for one of them. An editor's
    /// filesystem has `FileExists` for [`Error::AlreadyExists`] and nothing for
    /// the rest of [`Category::Refused`], and picking it out by reading the
    /// rendered sentence is what §10 forbids — so the name goes on the wire
    /// beside the number rather than the client parsing English. DR-030 asked
    /// for it; DR-032 is where it was decided and where what it commits to is
    /// written down.
    ///
    /// **These names are part of the contract.** Renaming a variant changes
    /// them, so it is a breaking change to the daemon's wire in the same way
    /// remapping an exit code is. Adding a variant is not: a caller that does
    /// not know a name has the number, which is what it had before.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match *self {
            Self::Io { .. } => "Io",
            Self::Contents { .. } => "Contents",
            Self::NotAnArchive { .. } => "NotAnArchive",
            Self::UnsupportedVersion { .. } => "UnsupportedVersion",
            Self::UnrecognisedExecutable { .. } => "UnrecognisedExecutable",
            Self::NeedsKey { .. } => "NeedsKey",
            Self::WrongKey { .. } => "WrongKey",
            Self::CannotWriteEncrypted { .. } => "CannotWriteEncrypted",
            Self::OutOfBounds { .. } => "OutOfBounds",
            Self::BadName { .. } => "BadName",
            Self::BadChildRange { .. } => "BadChildRange",
            Self::CyclicTree { .. } => "CyclicTree",
            Self::ClaimedTwice { .. } => "ClaimedTwice",
            Self::TooDeep { .. } => "TooDeep",
            Self::PayloadUnderflow { .. } => "PayloadUnderflow",
            Self::ResourceTooSmall { .. } => "ResourceTooSmall",
            Self::Inflate { .. } => "Inflate",
            Self::LengthMismatch { .. } => "LengthMismatch",
            Self::TrailingBytes { .. } => "TrailingBytes",
            Self::ChecksumMismatch { .. } => "ChecksumMismatch",
            Self::VerifyFailed { .. } => "VerifyFailed",
            Self::NoSuchEntry { .. } => "NoSuchEntry",
            Self::NotFound { .. } => "NotFound",
            Self::FieldOverflow { .. } => "FieldOverflow",
            Self::ArchiveTooLarge { .. } => "ArchiveTooLarge",
            Self::NotAResource { .. } => "NotAResource",
            Self::WrongEncoding { .. } => "WrongEncoding",
            Self::NoXmlView { .. } => "NoXmlView",
            Self::NameCollision { .. } => "NameCollision",
            Self::AlreadyExists { .. } => "AlreadyExists",
            Self::Claimed { .. } => "Claimed",
            Self::BadPath { .. } => "BadPath",
            Self::Overlapping { .. } => "Overlapping",
            Self::Cancelled { .. } => "Cancelled",
            Self::BadRbf { .. } => "BadRbf",
            Self::BadPso { .. } => "BadPso",
            Self::BadMeta { .. } => "BadMeta",
            Self::UnsupportedPso { .. } => "UnsupportedPso",
            Self::UnrepresentableRbf { .. } => "UnrepresentableRbf",
            Self::NotRbfXml { .. } => "NotRbfXml",
            Self::NotPsoXml { .. } => "NotPsoXml",
            Self::WrongKind { .. } => "WrongKind",
        }
    }

    /// The container failure an [`io::Error`] is carrying, if it is one.
    ///
    /// A streaming read can only fail as an [`io::Error`] — that is what
    /// [`std::io::Read`] returns — so [`crate::archive::Extracted`] packs the
    /// failure it really had inside one, and this is where it comes back out.
    ///
    /// # Errors
    ///
    /// The [`io::Error`] itself, unchanged, when it is not carrying one. A
    /// caller copying an entry into a sink of its own gets a container failure
    /// back for a failure of the **read** and its own error for a failure of
    /// the **write**, which is what lets it name the file it could not write.
    pub fn carried(source: io::Error) -> std::result::Result<Self, io::Error> {
        source.downcast::<Self>()
    }

    /// This failure as the [`io::Error`] a [`std::io::Read`] can return.
    pub(crate) fn into_io(self) -> io::Error {
        io::Error::other(self)
    }

    /// [`Error::carried`], for a caller whose sink cannot fail on its own: a
    /// failure carrying nothing is the source's, at `offset`.
    pub(crate) fn recovered(offset: u64, source: io::Error) -> Self {
        Self::carried(source).unwrap_or_else(|source| Self::Io { offset, source })
    }
}

/// Result of a container operation.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{Category, Error, NoWrite};

    /// How many variants [`Error`] has, which is what [`Error::name`] counts.
    ///
    /// That match is exhaustive, so a variant added later stops the crate
    /// compiling until it is named there — and then this number and the tables
    /// below have to be brought up to date, which is the point.
    const VARIANTS: usize = 42;

    /// The variant's own name, for a test that has to say which one it means.
    ///
    /// [`Error::name`] itself, so that what the tables below enumerate is the
    /// contract rather than a copy of it.
    fn name(error: &Error) -> &'static str {
        error.name()
    }

    /// A stand-in for whatever the source or the decompressor reported.
    fn io() -> std::io::Error {
        std::io::Error::other("something below us failed")
    }

    /// Every failure that means the archive's own bytes are wrong.
    ///
    /// `Inflate` belongs here and was `Io`: every byte asked for arrived and
    /// then failed to decode. DR-010.
    fn corrupt() -> Vec<Error> {
        vec![
            // The bytes name a container and then do not hold one. The other
            // spelling of this variant is in `refused()`.
            Error::NotAnArchive {
                base: 0,
                found: crate::format::Version::Rpf7.magic(),
            },
            Error::OutOfBounds {
                region: "payload",
                offset: 0,
                len: 1,
                archive_len: 0,
            },
            Error::BadName {
                entry: 0,
                name_offset: 0,
                names_len: 0,
            },
            Error::BadChildRange {
                entry: 0,
                first: 0,
                count: 0,
                entry_count: 0,
            },
            Error::CyclicTree { entry: 0, child: 0 },
            Error::ClaimedTwice {
                child: 2,
                first: 0,
                second: 1,
            },
            Error::TooDeep {
                what: "directory tree",
                depth: 33,
                limit: 32,
            },
            Error::PayloadUnderflow {
                entry: 0,
                offset: 0,
                floor: 16,
            },
            Error::ResourceTooSmall {
                entry: 0,
                compressed_len: 4,
            },
            Error::Inflate {
                entry: 0,
                source: io(),
            },
            Error::LengthMismatch {
                entry: 0,
                expected: 26,
                actual: 25,
            },
            Error::TrailingBytes {
                entry: 0,
                declared: 200_044,
                used: 44,
            },
            // The archive's bytes are not the bytes recorded for them, which is
            // a fact about the archive and not about the request. DR-023.
            Error::ChecksumMismatch {
                entry: 0,
                recorded: crate::manifest::Checksum::of(b"as extracted"),
                found: crate::manifest::Checksum::of(b"as it is now"),
            },
            Error::VerifyFailed {
                checked: 27,
                failed: 1,
            },
            // A metadata payload's own bytes are wrong, which is the same
            // fact one layer up: the container handed over exactly what it
            // held and the tokens in it do not parse.
            Error::BadRbf {
                offset: 7,
                cause: crate::metadata::rbf::Malformed::Truncated,
            },
            // The same fact for the other binary encoding. Added when
            // `the_variant_count_is_the_one_the_enum_declares` caught the enum
            // growing past the tables — which is what it is for.
            Error::BadPso {
                offset: 7,
                cause: crate::metadata::pso::Malformed::NotPso,
            },
            // And for the third encoding, whose bytes are a resource's paged
            // payload rather than a file with a magic at the front.
            Error::BadMeta {
                offset: 0x10,
                cause: crate::metadata::meta::Malformed::NotMeta,
            },
        ]
    }

    /// Every failure that means the request, or the input it carried, was
    /// wrong. All but `Overlapping` were `Corrupt`, and so blamed the archive
    /// for what the caller passed. DR-010.
    fn refused() -> Vec<Error> {
        vec![
            // Bytes that never claimed to be a container. Nothing about them
            // is malformed; the request that called them an archive was wrong.
            // DR-019.
            Error::NotAnArchive {
                base: 512,
                found: *b"hell",
            },
            Error::FieldOverflow {
                path: "big.bin".to_owned(),
                what: "compressed size",
                len: 1 << 24,
                limit: (1 << 24) - 1,
            },
            Error::ArchiveTooLarge {
                path: "data/vehicles.meta".to_owned(),
                reached: 4_294_967_296,
                limit: 4_294_966_784,
            },
            Error::NotAResource {
                path: "x.ytd".to_owned(),
                reason: "the payload is shorter than a resource header",
            },
            Error::WrongEncoding {
                path: "data/vehicles.ymt".to_owned(),
                held: crate::metadata::Encoding::Rbf,
                offered: crate::metadata::Encoding::Xml,
            },
            Error::NoXmlView {
                path: "data/vehicles.ymt".to_owned(),
                held: Some(crate::metadata::Encoding::Text),
            },
            Error::BadPath {
                path: "../escape".to_owned(),
                reason: "leaves the archive",
            },
            // A path a change would create and something is already at. The
            // archive is intact; what the caller asked for cannot be done.
            // DR-026.
            Error::AlreadyExists {
                path: "data/notes.txt".to_owned(),
            },
            // A second change at one path of a set that holds one per path.
            // DR-032.
            Error::Claimed {
                path: "data/notes.txt".to_owned(),
                held: "a rename",
            },
            Error::NameCollision {
                path: "data/NOTES.TXT".to_owned(),
                other: "data/notes.txt".to_owned(),
            },
            Error::Overlapping {
                path: "a".to_owned(),
                other: "b".to_owned(),
            },
            Error::WrongKind {
                path: "data".to_owned(),
                found: "directory",
                wanted: "file",
            },
            // The XML is the caller's, so the caller is who acts on it.
            Error::NotRbfXml {
                position: 12,
                cause: crate::metadata::rbf::NotRbf::Empty,
            },
            // And the `PSO` document is the caller's twice over: it says the
            // payload it was given beside is not the one it describes.
            Error::NotPsoXml {
                position: 12,
                cause: crate::metadata::pso::NotPsoXml::Empty,
            },
        ]
    }

    /// One failure for each of the categories with no group of their own.
    fn the_rest() -> Vec<(Error, Category)> {
        vec![
            (
                Error::Io {
                    offset: 0,
                    source: io(),
                },
                Category::Io,
            ),
            (
                Error::Contents {
                    name: "donor.bin".to_owned(),
                    source: io(),
                },
                Category::Io,
            ),
            (Error::NeedsKey { tag: 0x0FFF_FFF9 }, Category::NeedsKey),
            (
                Error::WrongKey {
                    tag: 0x0FEF_FFFF,
                    scheme: "NG",
                    tried: 1,
                },
                Category::NeedsKey,
            ),
            (
                Error::CannotWriteEncrypted {
                    tag: 0x0FEF_FFFF,
                    reason: NoWrite::NoInverse,
                },
                Category::Unsupported,
            ),
            (
                Error::UnsupportedVersion {
                    base: 0,
                    version: 2,
                    found: *b"RPF2",
                },
                Category::Unsupported,
            ),
            (
                Error::UnrecognisedExecutable {
                    what: "AES key and hash lookup table",
                    missing: &["the hash lookup table"],
                    found: 1,
                    wanted: 2,
                },
                Category::Unsupported,
            ),
            (
                Error::NoSuchEntry {
                    index: 9,
                    entry_count: 4,
                },
                Category::NotFound,
            ),
            (
                Error::NotFound {
                    path: "x64/nope".to_owned(),
                    segment: "nope".to_owned(),
                },
                Category::NotFound,
            ),
            (Error::Cancelled { done: 1, total: 24 }, Category::Cancelled),
            // Nothing is wrong with the payload; this build has no way to
            // render it. The same shape as `UnsupportedVersion`: whoever holds
            // it cannot act, because the missing part is here.
            (
                Error::UnrepresentableRbf {
                    cause: crate::metadata::rbf::Unrepresentable::EmptyBlob,
                },
                Category::Unsupported,
            ),
            // A `(type, subtype)` pair outside the 37 the corpus carries: the
            // payload is fine and this build cannot render it, which is
            // `UnsupportedVersion`'s shape once more.
            (
                Error::UnsupportedPso {
                    cause: crate::metadata::pso::Unsupported::DataType {
                        code: 0xFF,
                        subtype: 0xFF,
                    },
                },
                Category::Unsupported,
            ),
        ]
    }

    /// A failure of each variant, with the category it is contracted to carry.
    fn taxonomy() -> Vec<(Error, Category)> {
        corrupt()
            .into_iter()
            .map(|error| (error, Category::Corrupt))
            .chain(
                refused()
                    .into_iter()
                    .map(|error| (error, Category::Refused)),
            )
            .chain(the_rest())
            .collect()
    }

    #[test]
    fn every_variant_carries_the_category_it_is_contracted_to() {
        // §10 makes the variant set the public contract and R6.3 derives the
        // exit code from it, so a category that moves is a contract that moved.
        for (error, expected) in taxonomy() {
            assert_eq!(
                error.category(),
                expected,
                "{} is classified {:?}",
                name(&error),
                error.category()
            );
        }
    }

    #[test]
    fn what_the_bytes_claim_decides_who_has_to_act_on_them() {
        // DR-019. The four bytes are the only thing that ever says an archive
        // is here — nothing in an entry row marks a payload as one, which is
        // why every walk sniffs. So bytes that name a container and then fail
        // to hold one are a malformed archive, and bytes that name nothing are
        // a request that called an ordinary file an archive.
        for (found, expected) in [
            (crate::format::Version::Rpf7.magic(), Category::Corrupt),
            (*b"RPF2", Category::Corrupt),
            (*b"hell", Category::Refused),
            ([0; 4], Category::Refused),
            (*b"PK\x03\x04", Category::Refused),
        ] {
            let error = Error::NotAnArchive { base: 0, found };
            assert_eq!(error.category(), expected, "{found:02x?}");
        }
    }

    #[test]
    fn the_taxonomy_covers_every_variant() {
        // `NotAnArchive` is listed twice, once per category, because its
        // category is decided by the bytes it carries. DR-019.
        let named: BTreeSet<&str> = taxonomy().iter().map(|(error, _)| name(error)).collect();
        assert_eq!(
            named.len(),
            VARIANTS,
            "the tables name {} of {VARIANTS} variants",
            named.len()
        );
    }

    /// Every variant [`Error`] declares, read off this file.
    ///
    /// The enum is `rustfmt`-formatted, so a variant is a line of exactly four
    /// spaces, an upper-case letter, and an opening brace; a field is
    /// lower-case, a doc comment begins `///` and an attribute `#[`. Nothing
    /// else sits at that indentation.
    fn declared_variants() -> Vec<String> {
        let source = include_str!("error.rs");
        let mut found = Vec::new();
        let mut inside = false;
        for line in source.lines() {
            if line == "pub enum Error {" {
                inside = true;
                continue;
            }
            if !inside {
                continue;
            }
            if line == "}" {
                break;
            }
            let Some(rest) = line.strip_prefix("    ") else {
                continue;
            };
            if !rest.starts_with(|first: char| first.is_ascii_uppercase()) {
                continue;
            }
            found.push(rest.trim_end_matches(" {").to_owned());
        }
        found
    }

    #[test]
    fn the_variant_count_is_the_one_the_enum_declares() {
        // The test above compares two things that are both written by hand:
        // the taxonomy tables and `VARIANTS`. **Neither is the enum.** Adding a
        // variant makes `Error::name` fail to compile until it is named there,
        // and then nothing at all requires the tables or the count to follow —
        // so both stay as they were, `named.len()` stays equal to `VARIANTS`,
        // and the taxonomy test passes while covering one variant fewer than
        // there are. That has now happened twice: `VARIANTS` sat at 29 against
        // 30 arms, and again at 31 when `WrongKey` arrived against 32.
        //
        // This is the third party. It reads the declaration itself, so a new
        // variant makes the count wrong here whatever anybody remembered to
        // update — and the only way to make it right again is to add the
        // variant to the tables, which is what was wanted in the first place.
        let declared = declared_variants();
        assert!(
            declared.len() > 20,
            "the enum was not found in this file: {declared:?}"
        );
        assert_eq!(
            declared.len(),
            VARIANTS,
            "`Error` declares {} variants and `VARIANTS` says {VARIANTS}: {declared:?}",
            declared.len()
        );

        // And the tables name those variants and no others, so a count that
        // matches by coincidence — one variant dropped and another added — is
        // not enough either.
        let named: BTreeSet<&str> = taxonomy().iter().map(|(error, _)| name(error)).collect();
        let declared: BTreeSet<&str> = declared.iter().map(String::as_str).collect();
        assert_eq!(
            named, declared,
            "the tables and the enum do not name the same variants"
        );
    }
}
