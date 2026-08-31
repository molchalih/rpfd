//! Where extracted key material is kept between runs, and what invalidates it.
//!
//! R2.4. Scanning a 47 MB executable is seconds of work that would otherwise be
//! repeated on every command, and the cache is keyed by the **SHA-256 of the
//! executable it came from** so that a game update does not silently reuse the
//! previous install's material: a new executable is a new digest, which is a
//! file the cache has never written.
//!
//! Nothing here goes near the repository. DR-006 puts extracted material in the
//! user's own configuration directory, and [`Cache::platform`] is what finds it.

use std::{
    ffi::{OsStr, OsString},
    fs,
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use super::{
    AES_KEY_LEN, HASH_LUT_LEN, Keys, LauncherKey, Material, NG_DECRYPT_TABLE_COUNT,
    NG_DECRYPT_TABLE_LEN, NG_EXPANDED_KEY_COUNT, NG_EXPANDED_KEY_LEN, NgKeys,
};
use crate::error::{Error, Result};

/// Length of the digest an executable is identified by, in bytes.
pub const SOURCE_DIGEST_LEN: usize = 32;

/// This application's directory, below the platform's configuration root.
const APPLICATION: &str = "rpf";

/// The cache's own directory, below [`APPLICATION`].
///
/// Cache entries were kept directly in the application directory until
/// 2026-08-28, which made the cache directory *be* the configuration directory:
/// a configuration file put there later would have been inside the thing
/// `keys invalidate` empties. DR-024.
const KEYS: &str = "keys";

/// What a cache file is called, after its source's digest.
const SUFFIX: &str = ".keys";

/// What a store that has not finished calls the file it is writing.
///
/// It carries the same payload the entry will, so it is one of ours for the
/// purpose of clearing the cache even though it is not an entry.
const TEMPORARY: &str = ".tmp";

/// The first bytes of a cache file, so that a file of some other kind under the
/// same name is not read as one.
const MAGIC: [u8; 8] = *b"RPFKEYS\0";

/// The layout version of a cache file. A file of another schema is a miss, not
/// a failure: a cache is disposable and re-extraction is the correct answer.
///
/// Raised to 2 on 2026-08-30, when an entry gained the NG material it may now
/// carry. An entry this build cannot read is a miss and the next extraction
/// overwrites it, so nothing migrates. DR-040.
///
/// **Not raised again** when an entry gained the launcher key later the same
/// day, and that is a decision rather than an omission: the new half is
/// appended in a shape the length already tells apart, so an entry written
/// before it reads back as exactly what it holds — material with no launcher
/// key, which is the truth about every source but one. Raising it would have
/// discarded every entry on every machine, including a memory image that costs
/// a minute to scan, to add a value only `Launcher.exe` has ever carried and
/// which no existing entry could hold. DR-042.
const SCHEMA: u32 = 2;

/// Offset of the payload within a cache file.
const PAYLOAD_AT: usize = 48;

/// Length of the payload of an entry holding only what every source carries:
/// the two values and the two offsets they were at.
const BASE_LEN: usize = AES_KEY_LEN.saturating_add(HASH_LUT_LEN).saturating_add(16);

/// How much longer an entry is when it also holds the NG material: the expanded
/// keys, the decrypt tables, and the two offsets they were at.
const NG_LEN: usize = NG_EXPANDED_KEY_COUNT
    .saturating_mul(NG_EXPANDED_KEY_LEN)
    .saturating_add(NG_DECRYPT_TABLE_COUNT.saturating_mul(NG_DECRYPT_TABLE_LEN))
    .saturating_add(16);

/// How much longer an entry is when it also holds the launcher's own AES key:
/// the key, and the offset it was at.
const LAUNCHER_LEN: usize = AES_KEY_LEN.saturating_add(8);

/// The payload length of an entry that holds the launcher key and no NG
/// material, which is what `Launcher.exe` produces.
const WITH_LAUNCHER_LEN: usize = BASE_LEN.saturating_add(LAUNCHER_LEN);

/// The payload length of an entry that also holds the NG material.
///
/// The **length is the discriminator**: an entry is one of exactly four shapes
/// — the two halves are each present or not — and a declared length that is
/// none of them is not an entry this build wrote. That is one fact deciding one
/// thing, rather than a flag byte that could disagree with the bytes after it
/// (`docs/conventions.md` §5). The four are distinct because the two optional
/// halves are 40 and 306,016 bytes.
const WITH_NG_LEN: usize = BASE_LEN.saturating_add(NG_LEN);

/// The payload length of an entry holding both optional halves.
const WITH_BOTH_LEN: usize = WITH_NG_LEN.saturating_add(LAUNCHER_LEN);

/// Which optional halves an entry of this declared payload length carries, or
/// `None` when no entry this build writes is that long.
///
/// One reader of the four lengths, so `encode` and `decode` cannot come to
/// disagree about what a shape is (`docs/conventions.md` §3).
const fn shape(len: usize) -> Option<(bool, bool)> {
    match len {
        BASE_LEN => Some((false, false)),
        WITH_LAUNCHER_LEN => Some((true, false)),
        WITH_NG_LEN => Some((false, true)),
        WITH_BOTH_LEN => Some((true, true)),
        _ => None,
    }
}

/// The SHA-256 of a game executable, which is what a cache entry is keyed by.
///
/// A digest, never key material: this identifies the file the material came
/// from and says nothing about the material.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SourceDigest([u8; SOURCE_DIGEST_LEN]);

impl SourceDigest {
    /// Digests a source whole, from its start.
    ///
    /// It rewinds first, and that is the whole reason it asks for [`Seek`]. A
    /// scan leaves the source wherever its last read ended, so the obvious
    /// sequence — extract from a file, then digest the same file — used to
    /// hash zero bytes and hand back the digest of nothing. Every source would
    /// then share one cache key, and the next game build would read the
    /// previous install's material out of the cache: exactly the failure the
    /// digest exists to prevent, arrived at silently.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the source cannot be rewound or read, naming how far it
    /// got.
    pub fn of<S: Read + Seek>(source: &mut S) -> Result<Self> {
        source.rewind().map_err(io)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 1 << 16];
        let mut read_so_far = 0_u64;
        loop {
            match source.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    let Some(chunk) = buffer.get(..read) else {
                        break;
                    };
                    hasher.update(chunk);
                    read_so_far =
                        read_so_far.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => {
                    return Err(Error::Io {
                        offset: read_so_far,
                        source: error,
                    });
                }
            }
        }
        Ok(Self(hasher.finalize().into()))
    }

    /// The digest a lower-case hexadecimal name spells, if it spells one.
    ///
    /// The inverse of [`SourceDigest::hex`], and the reason a cache entry can
    /// be enumerated rather than only addressed: a name is where the digest of
    /// the source it came from is recorded.
    fn from_hex(text: &str) -> Option<Self> {
        if text.len() != SOURCE_DIGEST_LEN.checked_mul(2)? {
            return None;
        }
        if !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return None;
        }
        let mut out = [0_u8; SOURCE_DIGEST_LEN];
        let (pairs, _) = text.as_bytes().as_chunks::<2>();
        for (byte, pair) in out.iter_mut().zip(pairs) {
            *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        Some(Self(out))
    }

    /// The digest as lower-case hexadecimal, which is what names its cache file.
    #[must_use]
    pub fn hex(&self) -> String {
        use std::fmt::Write as _;

        let mut out = String::with_capacity(SOURCE_DIGEST_LEN.saturating_mul(2));
        for byte in self.0 {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

/// A directory holding extracted key material, one file per source executable.
#[derive(Clone, Debug)]
pub struct Cache {
    /// Where the files are.
    directory: PathBuf,
    /// A directory this cache kept its entries in before, and still clears.
    ///
    /// `Some` only for [`Cache::platform`]: a directory the caller named has
    /// never moved, and clearing it must not reach outside what it was given.
    superseded: Option<PathBuf>,
}

impl Cache {
    /// The cache in a directory of the caller's choosing.
    ///
    /// It reads, writes and clears that directory and nothing else.
    #[must_use]
    pub fn at(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            superseded: None,
        }
    }

    /// The cache in this platform's configuration directory, if there is one.
    ///
    /// `<config>/rpf/keys`. `None` where the environment does not say where the
    /// configuration root is — no `HOME` on a Unix, no `APPDATA` on Windows —
    /// which is a complete answer rather than a failure: the caller can still
    /// name a directory itself.
    #[must_use]
    pub fn platform() -> Option<Self> {
        root(HOST, &Environment::of_this_process()).map(Self::below)
    }

    /// The cache below an application configuration directory.
    ///
    /// Entries go in a `keys` subdirectory so that the cache directory is not
    /// the configuration directory, and so a later configuration file is not
    /// inside the thing `keys invalidate` empties.
    ///
    /// [`Cache::clear`] also sweeps the configuration directory itself, because
    /// that is where entries lived until 2026-08-28. Material there is **not**
    /// migrated — re-extraction is about a second and a cache is disposable,
    /// which is DR-017's own answer to an entry it cannot use — but it is still
    /// removed, because "take the key material off this machine" cannot have an
    /// exception the size of an old location. DR-024.
    fn below(application: PathBuf) -> Self {
        Self {
            directory: application.join(KEYS),
            superseded: Some(application),
        }
    }

    /// Where this cache keeps its files.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// The material extracted from the executable with this digest, if it is
    /// cached.
    ///
    /// A file that is absent, of another schema, truncated, or whose payload
    /// does not match its own checksum is a **miss** rather than a failure: a
    /// cache is disposable, and the answer to a bad entry is to extract again
    /// and overwrite it.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the directory exists and the file cannot be read.
    pub fn load(&self, source: &SourceDigest) -> Result<Option<Material>> {
        let path = self.path_for(source);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(Error::Io {
                    offset: 0,
                    source: error,
                });
            }
        };
        Ok(decode(&bytes))
    }

    /// Writes material to the cache under its source's digest, replacing
    /// whatever was there.
    ///
    /// The file is written beside its destination and renamed onto it, so a
    /// cache entry is never half-written (`docs/conventions.md` §8). On a Unix
    /// it is created readable by its owner alone, because it holds a key.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the directory cannot be created or the file written.
    pub fn store(&self, source: &SourceDigest, material: &Material) -> Result<()> {
        fs::create_dir_all(&self.directory).map_err(io)?;

        let destination = self.path_for(source);
        let mut temporary = destination.clone();
        temporary
            .as_mut_os_string()
            .push(format!(".{}{TEMPORARY}", std::process::id()));

        let mut file = create_private(&temporary)?;
        file.write_all(&encode(material)).map_err(io)?;
        file.flush().map_err(io)?;
        drop(file);

        fs::rename(&temporary, &destination).map_err(io)
    }

    /// The sources this cache holds material for.
    ///
    /// One digest per entry, in whatever order the directory reads back. A file
    /// this cache did not write — a configuration file beside them, a
    /// subdirectory, a temporary from a store that did not finish — is not an
    /// entry and is not reported. That rule is here rather than in a caller
    /// because it is the same rule [`Cache::store`] names a file by (§3).
    ///
    /// A directory that is not there yet holds no entries, which is not a
    /// failure: a machine that has never needed a key has no cache, and asking
    /// about it must not make one (R2.6).
    ///
    /// An entry is recognised by its name and not read, so one that would fail
    /// its own checksum is still listed. That is deliberate and it is DR-017's
    /// rule seen from the other side: whether an entry is usable is decided by
    /// [`Cache::load`], and a bad one is a miss that the next extraction
    /// overwrites.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the directory exists and cannot be read.
    pub fn entries(&self) -> Result<Vec<SourceDigest>> {
        let mut entries = Vec::new();
        for (_, held) in ours_in(&self.directory)? {
            if let Held::Entry(source) = held {
                entries.push(source);
            }
        }
        Ok(entries)
    }

    /// Every material this cache holds, in a stable order.
    ///
    /// Entries are read in **digest order** rather than in whatever order the
    /// directory hands back, so which one opens an archive is the same answer
    /// on two runs of the same command. An entry that fails its own checksum is
    /// a miss and is simply not here, which is [`Cache::load`]'s rule and
    /// DR-017's.
    ///
    /// A cache that is not there yet holds nothing, which is not a failure and
    /// does not create it: a machine that has never needed a key has no cache
    /// (R2.6).
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the directory exists and an entry cannot be read.
    pub fn materials(&self) -> Result<Vec<Material>> {
        let mut sources = self.entries()?;
        sources.sort_unstable_by_key(SourceDigest::hex);
        let mut held = Vec::with_capacity(sources.len());
        for source in &sources {
            if let Some(material) = self.load(source)? {
                held.push(material);
            }
        }
        Ok(held)
    }

    /// Removes everything this cache wrote, and says how many files that was.
    ///
    /// Whole rather than one entry at a time, and DR-020 says why: extraction
    /// already replaces the entry for a given executable, so the only thing a
    /// per-entry removal adds is leaving every *other* install's material where
    /// it was — which for "take the key material off this machine" is not a
    /// partial answer but a wrong one.
    ///
    /// It removes entries and any temporary a store left behind, and leaves
    /// every other file and every subdirectory alone. It is idempotent: a cache
    /// that is empty or absent is `0`.
    ///
    /// The platform cache also sweeps the directory it superseded, so the count
    /// can exceed what [`Cache::entries`] reported — an entry at the old
    /// location is material this build cannot read but can still remove. See
    /// `Cache::below`.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if a directory cannot be read or a file cannot be removed.
    pub fn clear(&self) -> Result<usize> {
        let mut removed = 0_usize;
        for directory in std::iter::once(&self.directory).chain(self.superseded.as_ref()) {
            for (path, _) in ours_in(directory)? {
                fs::remove_file(&path).map_err(io)?;
                removed = removed.saturating_add(1);
            }
        }
        Ok(removed)
    }

    /// The file the material from this source is kept in.
    fn path_for(&self, source: &SourceDigest) -> PathBuf {
        self.directory.join(format!("{}{SUFFIX}", source.hex()))
    }
}

/// What a file under a cache directory is, when it is one of the cache's own.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Held {
    /// A cache entry, keyed by the digest its name spells.
    Entry(SourceDigest),
    /// A temporary left by a store that did not finish.
    Temporary,
}

/// What a file name means to this cache, or `None` if it means nothing.
fn held(name: &str) -> Option<Held> {
    let (digest, rest) = name.split_once(SUFFIX)?;
    let source = SourceDigest::from_hex(digest)?;
    if rest.is_empty() {
        Some(Held::Entry(source))
    } else if rest.ends_with(TEMPORARY) {
        Some(Held::Temporary)
    } else {
        None
    }
}

/// This cache's own files in a directory, each with what it is.
///
/// A directory that is not there holds none, which is why neither
/// [`Cache::entries`] nor [`Cache::clear`] creates one.
fn ours_in(directory: &Path) -> Result<Vec<(PathBuf, Held)>> {
    let reading = match fs::read_dir(directory) {
        Ok(reading) => reading,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io(error)),
    };
    let mut found = Vec::new();
    for entry in reading {
        let entry = entry.map_err(io)?;
        if !entry.file_type().map_err(io)?.is_file() {
            continue;
        }
        let Some(what) = entry.file_name().to_str().and_then(held) else {
            continue;
        };
        found.push((entry.path(), what));
    }
    Ok(found)
}

/// Wraps a filesystem failure, which has no offset to report.
fn io(source: std::io::Error) -> Error {
    Error::Io { offset: 0, source }
}

/// Creates a cache file readable by its owner alone, **at creation**.
///
/// The mode goes on the `open` call rather than on a `set_permissions` after
/// it, and the difference is the whole point: a Unix permission check happens
/// at `open`, so a file created `0644` and narrowed a moment later is readable
/// by anyone who opens it inside that window, and a descriptor they obtained
/// there stays readable after the narrowing. The key bytes are written after,
/// so the window was a window on this project's one piece of secret material.
/// DR-006.
///
/// A stale temporary from a crashed process of the same id is removed rather
/// than reopened, because reopening one would inherit its mode.
///
/// Unix only, and stated rather than assumed: Windows has no mode bits, and a
/// file created inside the user's own `%APPDATA%` inherits that directory's
/// access control instead. DR-012 asks for a test on both sides of a `#[cfg]`;
/// the Unix side is asserted in this module's tests, and the other side has no
/// behaviour to assert.
#[cfg(unix)]
fn create_private(path: &Path) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    drop(fs::remove_file(path));
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(io)
}

/// Creates the file off Unix, where there is no mode to set. See the Unix arm.
#[cfg(not(unix))]
fn create_private(path: &Path) -> Result<fs::File> {
    fs::File::create(path).map_err(io)
}

/// The bytes of a cache file holding this material.
fn encode(material: &Material) -> Vec<u8> {
    let keys = material.keys();
    let mut payload = Vec::with_capacity(WITH_BOTH_LEN);
    payload.extend_from_slice(keys.aes_key());
    payload.extend_from_slice(keys.hash_lut());
    payload.extend_from_slice(&keys.aes_key_offset().to_le_bytes());
    payload.extend_from_slice(&keys.hash_lut_offset().to_le_bytes());
    if let Some(launcher) = material.launcher() {
        payload.extend_from_slice(launcher.key());
        payload.extend_from_slice(&launcher.offset().to_le_bytes());
    }
    if let Some(ng) = material.ng() {
        payload.extend_from_slice(ng.expanded_bytes());
        payload.extend_from_slice(ng.table_bytes());
        payload.extend_from_slice(&ng.expanded_keys_offset().to_le_bytes());
        payload.extend_from_slice(&ng.decrypt_tables_offset().to_le_bytes());
    }

    let checksum: [u8; SOURCE_DIGEST_LEN] = Sha256::digest(&payload).into();
    let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);

    let mut out = Vec::with_capacity(PAYLOAD_AT.saturating_add(payload.len()));
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&SCHEMA.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&checksum);
    out.extend_from_slice(&payload);
    out
}

/// The material in a cache file, or `None` if it is not one this build wrote.
///
/// The declared payload length says which of the four shapes the entry is, and
/// any other length is not one of ours. See [`shape`].
fn decode(bytes: &[u8]) -> Option<Material> {
    if bytes.get(..MAGIC.len())? != MAGIC {
        return None;
    }
    if u32::from_le_bytes(word(bytes, 8)?) != SCHEMA {
        return None;
    }
    let len = usize::try_from(u32::from_le_bytes(word(bytes, 12)?)).ok()?;
    let (has_launcher, has_ng) = shape(len)?;
    let checksum = bytes.get(16..PAYLOAD_AT)?;
    let payload = bytes.get(PAYLOAD_AT..PAYLOAD_AT.checked_add(len)?)?;
    if Sha256::digest(payload).as_slice() != checksum {
        return None;
    }

    let aes: [u8; AES_KEY_LEN] = payload.get(..AES_KEY_LEN)?.try_into().ok()?;
    let lut_end = AES_KEY_LEN.checked_add(HASH_LUT_LEN)?;
    let lut: [u8; HASH_LUT_LEN] = payload.get(AES_KEY_LEN..lut_end)?.try_into().ok()?;
    let aes_at = u64::from_le_bytes(long(payload, lut_end)?);
    let lut_at = u64::from_le_bytes(long(payload, lut_end.checked_add(8)?)?);

    let keys = Keys {
        aes,
        aes_at,
        lut,
        lut_at,
    };
    // In the order the payload lays them out, so each bound is read against the
    // one before it.
    let launcher = if has_launcher {
        Some(decode_launcher(payload)?)
    } else {
        None
    };
    let ng_at = if has_launcher {
        BASE_LEN.checked_add(LAUNCHER_LEN)?
    } else {
        BASE_LEN
    };
    let ng = if has_ng {
        Some(decode_ng(payload, ng_at)?)
    } else {
        None
    };
    Some(Material::restored(keys, ng, launcher))
}

/// The launcher key of a payload that declared itself long enough to hold one.
fn decode_launcher(payload: &[u8]) -> Option<LauncherKey> {
    let key_end = BASE_LEN.checked_add(AES_KEY_LEN)?;
    let key: [u8; AES_KEY_LEN] = payload.get(BASE_LEN..key_end)?.try_into().ok()?;
    Some(LauncherKey::restored(
        key,
        u64::from_le_bytes(long(payload, key_end)?),
    ))
}

/// The NG half of a payload that declared itself long enough to hold one,
/// beginning at `starts_at` — which is past the launcher key where the entry
/// carries one.
///
/// The three bounds are declared in the order the payload lays them out —
/// expanded keys, decrypt tables, then the two offsets — so that a reader can
/// check each against the one before it.
fn decode_ng(payload: &[u8], starts_at: usize) -> Option<NgKeys> {
    let tables_start =
        starts_at.checked_add(NG_EXPANDED_KEY_COUNT.checked_mul(NG_EXPANDED_KEY_LEN)?)?;
    let offsets_start =
        tables_start.checked_add(NG_DECRYPT_TABLE_COUNT.checked_mul(NG_DECRYPT_TABLE_LEN)?)?;

    let expanded = payload.get(starts_at..tables_start)?.to_vec();
    let tables = payload.get(tables_start..offsets_start)?.to_vec();
    let expanded_at = u64::from_le_bytes(long(payload, offsets_start)?);
    let tables_at = u64::from_le_bytes(long(payload, offsets_start.checked_add(8)?)?);

    NgKeys::restored(expanded, tables, expanded_at, tables_at)
}

/// Four bytes at `at`, if they are there.
fn word(bytes: &[u8], at: usize) -> Option<[u8; 4]> {
    bytes.get(at..at.checked_add(4)?)?.try_into().ok()
}

/// Eight bytes at `at`, if they are there.
fn long(bytes: &[u8], at: usize) -> Option<[u8; 8]> {
    bytes.get(at..at.checked_add(8)?)?.try_into().ok()
}

/// The three shapes a configuration directory takes.
///
/// Named rather than `#[cfg]`-ed at each use so that all three are live code on
/// every platform, and so [`root`] can be tested for all three from any of
/// them. DR-012: a behaviour that differs by platform gets a test on both
/// sides, which is impossible when only one side compiles.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Platform {
    /// `$XDG_CONFIG_HOME`, or `$HOME/.config`.
    Xdg,
    /// `$HOME/Library/Application Support`.
    Apple,
    /// `%APPDATA%`.
    Windows,
}

/// The platform this build runs on.
const HOST: Platform = if cfg!(windows) {
    Platform::Windows
} else if cfg!(target_os = "macos") {
    Platform::Apple
} else {
    Platform::Xdg
};

/// The environment variables a configuration directory is derived from.
#[derive(Clone, Default, Debug)]
struct Environment {
    /// `$HOME`.
    home: Option<OsString>,
    /// `$XDG_CONFIG_HOME`.
    xdg_config_home: Option<OsString>,
    /// `%APPDATA%`.
    appdata: Option<OsString>,
}

impl Environment {
    /// This process's own environment.
    fn of_this_process() -> Self {
        Self {
            home: std::env::var_os("HOME"),
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME"),
            appdata: std::env::var_os("APPDATA"),
        }
    }
}

/// Whether `$XDG_CONFIG_HOME` names an absolute path **by the specification's
/// rule**, which is a leading `/`.
///
/// Not `Path::is_absolute`, which answers the question the platform this was
/// compiled for asks: on Windows `/elsewhere/config` is relative, so the
/// `Platform::Xdg` arm — a Unix convention, and live code on every platform by
/// `docs/conventions.md` §14 — silently fell through to `$HOME/.config` there.
/// Found by the suite's first run on Windows.
fn xdg_absolute(configured: &OsStr) -> bool {
    configured.as_encoded_bytes().first() == Some(&b'/')
}

/// The cache directory for a platform and an environment, if that environment
/// says where it is.
fn root(platform: Platform, environment: &Environment) -> Option<PathBuf> {
    let base = match platform {
        Platform::Xdg => match environment.xdg_config_home.as_ref() {
            Some(configured) if xdg_absolute(configured) => PathBuf::from(configured),
            _ => PathBuf::from(environment.home.as_ref()?).join(".config"),
        },
        Platform::Apple => PathBuf::from(environment.home.as_ref()?)
            .join("Library")
            .join("Application Support"),
        Platform::Windows => PathBuf::from(environment.appdata.as_ref()?),
    };
    Some(base.join(APPLICATION))
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Cursor};

    use crate::Error;

    use super::{
        APPLICATION, BASE_LEN, Cache, Environment, KEYS, MAGIC, PAYLOAD_AT, Platform, SUFFIX,
        SourceDigest, TEMPORARY, WITH_BOTH_LEN, WITH_LAUNCHER_LEN, WITH_NG_LEN, decode, encode,
        root, xdg_absolute,
    };
    use crate::keys::{
        AES_KEY_LEN, HASH_LUT_LEN, Keys, LauncherKey, Material, NG_DECRYPT_TABLE_COUNT,
        NG_DECRYPT_TABLE_LEN, NG_EXPANDED_KEY_COUNT, NG_EXPANDED_KEY_LEN, NgKeys,
    };

    /// Material that is not key material: fixed byte patterns and offsets,
    /// which is all the file format has to carry.
    fn keys_at(aes_at: u64) -> Keys {
        Keys {
            aes: [0x11; AES_KEY_LEN],
            aes_at,
            lut: [0x22; HASH_LUT_LEN],
            lut_at: 0x00AB_CDEF,
        }
    }

    /// An entry of the shape every source produces: no NG material and no
    /// launcher key.
    fn material() -> Material {
        Material::restored(keys_at(0x1234_5678), None, None)
    }

    /// The shape only the launcher's own executable produces.
    ///
    /// A byte pattern rather than anything extracted, for the reason
    /// [`material_with_ng`] gives.
    fn material_with_launcher() -> Material {
        Material::restored(
            keys_at(0x1234_5678),
            None,
            Some(LauncherKey::restored([0x55; AES_KEY_LEN], 0x005E_E3F0)),
        )
    }

    /// An entry of the other shape, which only a memory image produces.
    ///
    /// The bytes are a pattern rather than anything extracted: DR-006 keeps key
    /// material out of this repository, and what the file format has to carry
    /// correctly is a length and a position, not a value.
    fn material_with_ng() -> Material {
        let expanded = vec![0x33; NG_EXPANDED_KEY_COUNT * NG_EXPANDED_KEY_LEN];
        let tables = vec![0x44; NG_DECRYPT_TABLE_COUNT * NG_DECRYPT_TABLE_LEN];
        let ng = NgKeys::restored(expanded, tables, 0x01E3_3120, 0x01E8_6CE0)
            .expect("the lengths are the ones the type promises");
        Material::restored(keys_at(0x1234_5678), Some(ng), None)
    }

    /// The shape a source carrying both halves would produce.
    ///
    /// No source measured here carries both — the NG material is in a memory
    /// image of a game and the launcher key is in `Launcher.exe` — but the file
    /// format has to hold either half without the other, and a shape that is
    /// only reachable by writing it is exactly the one that rots.
    fn material_with_both() -> Material {
        let expanded = vec![0x33; NG_EXPANDED_KEY_COUNT * NG_EXPANDED_KEY_LEN];
        let tables = vec![0x44; NG_DECRYPT_TABLE_COUNT * NG_DECRYPT_TABLE_LEN];
        let ng = NgKeys::restored(expanded, tables, 0x01E3_3120, 0x01E8_6CE0)
            .expect("the lengths are the ones the type promises");
        Material::restored(
            keys_at(0x1234_5678),
            Some(ng),
            Some(LauncherKey::restored([0x55; AES_KEY_LEN], 0x005E_E3F0)),
        )
    }

    fn digest_of(bytes: &[u8]) -> SourceDigest {
        SourceDigest::of(&mut Cursor::new(bytes.to_vec())).unwrap()
    }

    #[test]
    fn the_source_digest_is_sha256_of_the_whole_source() {
        // The empty string's SHA-256, which is the one value everybody can
        // check against something else.
        assert_eq!(
            digest_of(b"").hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn two_executables_have_two_digests_and_therefore_two_cache_files() {
        // R2.4's whole mechanism: an update is a different file, a different
        // digest, and a cache entry that has never been written.
        assert_ne!(digest_of(b"one build"), digest_of(b"another build"));
    }

    #[test]
    fn material_survives_the_file_format_unchanged() {
        let written = encode(&material());
        let read = decode(&written).expect("a file this build wrote reads back");
        let expected = material();
        assert_eq!(read.keys().aes_key(), expected.keys().aes_key());
        assert_eq!(read.keys().hash_lut(), expected.keys().hash_lut());
        assert_eq!(
            read.keys().aes_key_offset(),
            expected.keys().aes_key_offset()
        );
        assert_eq!(
            read.keys().hash_lut_offset(),
            expected.keys().hash_lut_offset()
        );
        assert!(read.ng().is_none(), "NG material appeared from nowhere");
        assert!(
            read.launcher().is_none(),
            "a launcher key appeared from nowhere"
        );
    }

    #[test]
    fn the_launcher_key_survives_the_file_format_and_keeps_its_position() {
        // The half the cache gained on 2026-08-30 beside the NG one, and the
        // one an entry written before either still reads back without: the
        // shapes are told apart by length, so nothing migrates and nothing
        // silently acquires a key it never had. DR-042.
        let written = encode(&material_with_launcher());
        let read = decode(&written).expect("a file this build wrote reads back");
        let source = material_with_launcher();
        let (read_key, source_key) = (
            read.launcher().expect("the entry carried a launcher key"),
            source.launcher().expect("as written"),
        );
        assert_eq!(read_key.key(), source_key.key());
        assert_eq!(read_key.offset(), source_key.offset());
        assert_eq!(read.keys().aes_key(), source.keys().aes_key());
        assert!(read.ng().is_none(), "NG material appeared from nowhere");
    }

    #[test]
    fn an_entry_holding_both_halves_reads_both_back_in_order() {
        // The launcher key sits between the base and the NG material, so
        // reading the second is only right if the first was measured rather
        // than assumed absent.
        let written = encode(&material_with_both());
        let read = decode(&written).expect("a file this build wrote reads back");
        let source = material_with_both();
        assert_eq!(
            read.launcher().expect("carried").offset(),
            source.launcher().expect("as written").offset()
        );
        let read_ng = read.ng().expect("the entry carried NG material");
        let source_ng = source.ng().expect("as written");
        assert_eq!(
            read_ng.expanded_keys_offset(),
            source_ng.expanded_keys_offset()
        );
        assert_eq!(read_ng.expanded_key(0), source_ng.expanded_key(0));
        assert_eq!(
            read_ng.decrypt_table(NG_ROUNDS_LAST, 0),
            source_ng.decrypt_table(NG_ROUNDS_LAST, 0)
        );
    }

    /// The last round the NG material is indexed by, so the test above reaches
    /// the far end of the payload rather than only its start.
    const NG_ROUNDS_LAST: usize = crate::keys::NG_ROUNDS - 1;

    #[test]
    fn the_ng_material_survives_the_file_format_and_keeps_its_positions() {
        // The half the cache gained on 2026-08-30. An entry that carries the NG
        // material has to read back with every one of its 373 values in the
        // order they were written, because the index into them *is* how a key
        // is chosen (`docs/ng-scheme.md`), and a rotation would decrypt nothing
        // while looking well-formed.
        let written = encode(&material_with_ng());
        let read = decode(&written).expect("a file this build wrote reads back");
        let source = material_with_ng();
        let (read_ng, source_ng) = (
            read.ng().expect("the entry carried NG material"),
            source.ng().expect("as written"),
        );

        assert_eq!(read.keys().aes_key(), source.keys().aes_key());
        assert_eq!(
            read_ng.expanded_keys_offset(),
            source_ng.expanded_keys_offset()
        );
        assert_eq!(
            read_ng.decrypt_tables_offset(),
            source_ng.decrypt_tables_offset()
        );
        for index in 0..NG_EXPANDED_KEY_COUNT {
            assert_eq!(
                read_ng.expanded_key(index),
                source_ng.expanded_key(index),
                "expanded key {index}"
            );
        }
        for round in 0..crate::keys::NG_ROUNDS {
            for column in 0..crate::keys::NG_COLUMNS {
                assert_eq!(
                    read_ng.decrypt_table(round, column),
                    source_ng.decrypt_table(round, column),
                    "decrypt table {round}/{column}"
                );
            }
        }
    }

    #[test]
    fn the_four_shapes_of_an_entry_are_told_apart_by_their_declared_length() {
        // §5: the length is the discriminator, so there is no flag that could
        // disagree with the bytes after it. A length that is no shape at all is
        // not an entry this build wrote, and a payload that claims a longer
        // shape without carrying it is a miss rather than a short read.
        assert_eq!(encode(&material()).len(), PAYLOAD_AT + BASE_LEN);
        assert_eq!(encode(&material_with_ng()).len(), PAYLOAD_AT + WITH_NG_LEN);
        assert_eq!(
            encode(&material_with_launcher()).len(),
            PAYLOAD_AT + WITH_LAUNCHER_LEN
        );
        assert_eq!(
            encode(&material_with_both()).len(),
            PAYLOAD_AT + WITH_BOTH_LEN
        );
        let lengths = [BASE_LEN, WITH_LAUNCHER_LEN, WITH_NG_LEN, WITH_BOTH_LEN];
        for (index, len) in lengths.iter().enumerate() {
            for other in lengths.iter().skip(index + 1) {
                assert_ne!(len, other, "two shapes share a length");
            }
        }

        let mut lying = encode(&material());
        lying[12..16].copy_from_slice(
            &u32::try_from(WITH_NG_LEN)
                .expect("the payload length fits a word")
                .to_le_bytes(),
        );
        assert!(
            decode(&lying).is_none(),
            "a short entry claiming to carry NG material was read as one"
        );
    }

    #[test]
    fn a_file_that_is_not_one_of_ours_is_a_miss() {
        let mut wrong = encode(&material());
        wrong[0] = b'X';
        assert!(decode(&wrong).is_none(), "any file under the name was read");
        assert!(decode(b"").is_none());
        assert!(
            decode(&MAGIC).is_none(),
            "a header with no payload was read"
        );
    }

    #[test]
    fn a_file_of_another_schema_is_a_miss_rather_than_a_misreading() {
        let mut future = encode(&material());
        future[MAGIC.len()] = 0xFF;
        assert!(decode(&future).is_none());
    }

    #[test]
    fn a_truncated_or_altered_payload_is_a_miss() {
        let written = encode(&material());

        let short = &written[..written.len() - 1];
        assert!(decode(short).is_none(), "a truncated payload was accepted");

        let mut altered = written.clone();
        altered[PAYLOAD_AT] ^= 0x01;
        assert!(
            decode(&altered).is_none(),
            "a payload that fails its own checksum was accepted"
        );
    }

    #[test]
    fn a_miss_and_a_hit_are_told_apart_by_the_source_digest() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::at(directory.path());
        let source = digest_of(b"an executable");
        let updated = digest_of(b"the same executable, patched");

        assert!(cache.load(&source).unwrap().is_none(), "a fresh cache hit");
        cache.store(&source, &material()).unwrap();
        assert!(cache.load(&source).unwrap().is_some(), "what was stored");
        assert!(
            cache.load(&updated).unwrap().is_none(),
            "an updated executable read the previous install's material"
        );
    }

    #[test]
    fn storing_twice_leaves_one_file_and_the_later_material() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::at(directory.path());
        let source = digest_of(b"an executable");

        cache.store(&source, &material()).unwrap();
        let moved = Material::restored(keys_at(0x9999), None, None);
        cache.store(&source, &moved).unwrap();

        let files: Vec<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            files.len(),
            1,
            "a temporary file was left behind: {files:?}"
        );
        assert_eq!(
            cache
                .load(&source)
                .unwrap()
                .unwrap()
                .keys()
                .aes_key_offset(),
            0x9999
        );
    }

    #[test]
    fn a_cache_file_is_named_after_its_source() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::at(directory.path());
        let source = digest_of(b"an executable");
        cache.store(&source, &material()).unwrap();

        let expected = format!("{}{SUFFIX}", source.hex());
        assert!(directory.path().join(&expected).is_file(), "{expected}");
    }

    #[test]
    fn every_material_a_cache_holds_is_a_candidate_it_offers() {
        // `Cache::materials` is what `Unlock::cached` asks, and an empty answer
        // is `Error::NeedsKey`: a cache holding the material that opens the
        // archive, reported as holding nothing, tells an automation to go and
        // extract a key it already has. Nothing called it in a test at all —
        // replacing it with an empty vector left the whole suite green.
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::at(directory.path());

        assert!(
            cache.materials().unwrap().is_empty(),
            "an empty cache offered a candidate"
        );

        // Two sources, and the shapes an entry can be: one plain, one with the
        // NG half. Both come back, so `materials` is not answering from the
        // first entry alone either.
        cache.store(&digest_of(b"one"), &material()).unwrap();
        cache
            .store(&digest_of(b"two"), &material_with_ng())
            .unwrap();

        let held = cache.materials().unwrap();
        assert_eq!(
            held.len(),
            2,
            "the cache holds two and offered {}",
            held.len()
        );
        assert_eq!(
            held.iter()
                .filter(|material| material.ng().is_some())
                .count(),
            1,
            "the NG half did not survive the round trip through the cache"
        );
    }

    #[test]
    fn a_cache_in_a_directory_that_does_not_exist_yet_creates_it() {
        let directory = tempfile::tempdir().unwrap();
        let nested = directory.path().join("one").join("two");
        let cache = Cache::at(&nested);
        cache.store(&digest_of(b"x"), &material()).unwrap();
        assert!(nested.is_dir());
    }

    #[test]
    #[cfg(unix)]
    fn a_cache_file_is_private_from_the_moment_it_exists() {
        // The test above asserts the mode a cache file ends up with, which the
        // create-then-narrow it replaced also satisfied. This one asserts the
        // mode it is *created* with, and that is the property that matters: a
        // Unix permission check happens at `open`, so a file created `0644` and
        // narrowed afterwards is readable by anyone who opens it in between,
        // and the key bytes are written after the narrowing. Nothing is written
        // here — the point is the file's mode before anything has been.
        //
        // It reads `0600` under a `0077` umask either way, so this pins the
        // behaviour rather than reproducing the old failure on every machine.
        use std::os::unix::fs::PermissionsExt as _;

        use super::create_private;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fresh.tmp");
        let file = create_private(&path).expect("creates");
        drop(file);

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode is {:o}", mode & 0o777);
    }

    #[test]
    #[cfg(unix)]
    fn a_stale_temporary_does_not_lend_its_mode_to_the_next_one() {
        // Reopening a leftover file would inherit whatever mode it had, which
        // is how the window would come back for a process whose id repeats.
        use std::os::unix::fs::PermissionsExt as _;

        use super::create_private;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("stale.tmp");
        std::fs::write(&path, b"left behind").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

        drop(create_private(&path).expect("creates over the stale one"));

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode is {:o}", mode & 0o777);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"",
            "the stale bytes are gone"
        );
    }

    #[test]
    fn a_source_is_digested_whole_however_it_was_left() {
        // A scan leaves the source wherever its last read ended. Digesting from
        // there hashed nothing and handed back the digest of an empty input, so
        // every executable shared one cache key and a game update would have
        // read the previous install's material back out. The digest rewinds.
        use std::io::Read as _;

        let bytes = b"an executable, or near enough".to_vec();

        let mut fresh = Cursor::new(bytes.clone());
        let whole = SourceDigest::of(&mut fresh).expect("digests");

        let mut read_to_end = Cursor::new(bytes.clone());
        let mut sink = Vec::new();
        read_to_end.read_to_end(&mut sink).expect("reads");
        let after = SourceDigest::of(&mut read_to_end).expect("digests");

        assert_eq!(after, whole, "a consumed source still digests whole");
        assert_ne!(
            whole,
            SourceDigest::of(&mut Cursor::new(Vec::new())).expect("digests"),
            "and it is not the digest of nothing"
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_cache_file_is_readable_by_its_owner_alone() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::at(directory.path());
        let source = digest_of(b"an executable");
        cache.store(&source, &material()).unwrap();

        let mode = std::fs::metadata(directory.path().join(format!("{}{SUFFIX}", source.hex())))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "mode is {:o}", mode & 0o777);
    }

    #[test]
    fn the_platform_cache_keeps_its_entries_below_the_configuration_directory() {
        // The cache directory used to *be* the application's configuration
        // directory, so any configuration file put there later would have been
        // inside the thing `keys invalidate` empties. DR-024.
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::below(directory.path().to_path_buf());
        assert_eq!(cache.directory(), directory.path().join(KEYS));
    }

    #[test]
    fn clearing_the_platform_cache_reaches_the_place_entries_used_to_live() {
        // A path change users already have on disk. Material is not migrated —
        // re-extraction is a second of work and a cache is disposable, DR-017 —
        // but it is still removed, because "take the key material off this
        // machine" cannot have an exception the size of an old location.
        let application = tempfile::tempdir().unwrap();
        let cache = Cache::below(application.path().to_path_buf());
        let old = digest_of(b"a build cached before the move");
        let new = digest_of(b"a build cached after it");

        std::fs::write(
            application.path().join(format!("{}{SUFFIX}", old.hex())),
            encode(&material()),
        )
        .unwrap();
        cache.store(&new, &material()).unwrap();
        let settings = application.path().join("settings.json");
        std::fs::write(&settings, b"{}").unwrap();

        assert_eq!(
            cache.entries().unwrap().len(),
            1,
            "an entry at the old location was reported as one this cache can read"
        );
        assert_eq!(cache.clear().unwrap(), 2);
        assert!(cache.entries().unwrap().is_empty());
        assert!(
            !application
                .path()
                .join(format!("{}{SUFFIX}", old.hex()))
                .exists(),
            "material at the old location survived an invalidation"
        );
        assert!(settings.is_file(), "a configuration file was removed");
    }

    #[test]
    fn a_cache_in_a_named_directory_supersedes_nothing_and_touches_no_parent() {
        // Only the platform cache moved, so only the platform cache sweeps. A
        // `--cache-dir` pointed inside somebody's tree must not reach outside
        // the directory it was given.
        let parent = tempfile::tempdir().unwrap();
        let source = digest_of(b"one build");
        let above = parent.path().join(format!("{}{SUFFIX}", source.hex()));
        std::fs::write(&above, encode(&material())).unwrap();

        let cache = Cache::at(parent.path().join("named"));
        cache.store(&source, &material()).unwrap();
        assert_eq!(cache.clear().unwrap(), 1);
        assert!(
            above.is_file(),
            "clearing reached outside its own directory"
        );
    }

    #[test]
    fn the_entries_a_cache_holds_are_its_own_files_and_nothing_else() {
        // §3: what a cache entry is, is the cache's own rule. A frontend
        // counting regular files decides it a second time, and decides it
        // differently — anything else under the directory used to be one.
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::at(directory.path());
        let one = digest_of(b"one build");
        let two = digest_of(b"another build");

        assert!(
            cache.entries().unwrap().is_empty(),
            "a fresh cache holds an entry"
        );
        cache.store(&one, &material()).unwrap();
        cache.store(&two, &material()).unwrap();
        std::fs::write(directory.path().join("settings.json"), b"{}").unwrap();
        std::fs::write(directory.path().join("notes"), b"").unwrap();
        std::fs::create_dir(directory.path().join("held")).unwrap();

        let mut held: Vec<String> = cache
            .entries()
            .unwrap()
            .iter()
            .map(SourceDigest::hex)
            .collect();
        held.sort();
        let mut expected = vec![one.hex(), two.hex()];
        expected.sort();
        assert_eq!(held, expected, "a file that is not an entry was counted");
    }

    #[test]
    fn clearing_removes_the_cache_s_own_files_and_leaves_everything_else() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::at(directory.path());
        cache.store(&digest_of(b"one build"), &material()).unwrap();
        cache
            .store(&digest_of(b"another build"), &material())
            .unwrap();
        let beside = directory.path().join("settings.json");
        std::fs::write(&beside, b"{}").unwrap();
        std::fs::create_dir(directory.path().join("held")).unwrap();

        assert_eq!(cache.clear().unwrap(), 2);
        assert!(cache.entries().unwrap().is_empty());
        assert!(beside.is_file(), "a file that is not ours was removed");
        assert!(directory.path().join("held").is_dir());
    }

    #[test]
    fn clearing_a_cache_that_was_never_written_is_zero_and_creates_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let absent = directory.path().join("never-written");
        let cache = Cache::at(&absent);
        assert_eq!(cache.clear().unwrap(), 0);
        assert!(cache.entries().unwrap().is_empty());
        assert!(!absent.exists(), "asking emptied a cache into existence");
    }

    #[test]
    fn a_temporary_from_a_store_that_did_not_finish_is_cleared_too() {
        // It holds the same payload an entry does, mode and all. Leaving it
        // would make "take the key material off this machine" untrue by the
        // width of one crash.
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::at(directory.path());
        let source = digest_of(b"one build");
        std::fs::create_dir_all(directory.path()).unwrap();
        let stale = directory
            .path()
            .join(format!("{}{SUFFIX}.4321{TEMPORARY}", source.hex()));
        std::fs::write(&stale, encode(&material())).unwrap();

        assert!(
            cache.entries().unwrap().is_empty(),
            "a half-written store was reported as an entry"
        );
        assert_eq!(cache.clear().unwrap(), 1);
        assert!(!stale.exists());
    }

    #[test]
    fn a_name_that_is_not_a_digest_is_not_an_entry() {
        // The naming rule is the whole of what makes an entry addressable, so
        // it is pinned rather than left to `store` and a reader agreeing.
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::at(directory.path());
        std::fs::create_dir_all(directory.path()).unwrap();
        let source = digest_of(b"one build");
        for name in [
            format!("{}{SUFFIX}", &source.hex()[1..]),
            format!("{}{SUFFIX}", source.hex().to_uppercase()),
            format!("{}.key", source.hex()),
            source.hex(),
            format!("{}{SUFFIX}.notatemporary", source.hex()),
        ] {
            std::fs::write(directory.path().join(&name), b"x").unwrap();
            assert!(
                cache.entries().unwrap().is_empty(),
                "{name} was read as an entry"
            );
            assert_eq!(cache.clear().unwrap(), 0, "{name} was removed");
            std::fs::remove_file(directory.path().join(&name)).unwrap();
        }
    }

    fn environment(home: &str, xdg: Option<&str>, appdata: Option<&str>) -> Environment {
        Environment {
            home: Some(home.into()),
            xdg_config_home: xdg.map(Into::into),
            appdata: appdata.map(Into::into),
        }
    }

    #[test]
    fn xdg_prefers_its_own_variable_and_falls_back_to_the_home_directory() {
        let with = environment("/home/p", Some("/elsewhere/config"), None);
        assert_eq!(
            root(Platform::Xdg, &with).unwrap(),
            std::path::Path::new("/elsewhere/config").join(APPLICATION)
        );

        let without = environment("/home/p", None, None);
        assert_eq!(
            root(Platform::Xdg, &without).unwrap(),
            std::path::Path::new("/home/p/.config").join(APPLICATION)
        );
    }

    #[test]
    fn a_relative_xdg_variable_is_ignored_rather_than_joined() {
        // The specification says a relative value is invalid and must be
        // ignored. Joining it would put the cache below the working directory,
        // which is wherever the caller happened to be.
        let relative = environment("/home/p", Some("config"), None);
        assert_eq!(
            root(Platform::Xdg, &relative).unwrap(),
            std::path::Path::new("/home/p/.config").join(APPLICATION)
        );
    }

    #[test]
    fn the_xdg_rule_is_a_leading_slash_and_not_the_host_s_idea_of_absolute() {
        // Asserted against the rule rather than through `root`, because through
        // `root` it is only ever wrong on one platform: `Path::is_absolute`
        // agrees with this on Unix and disagrees on Windows, where it called
        // `/elsewhere/config` relative and sent the cache to `$HOME/.config`.
        // `docs/conventions.md` §14 claims all three arms are live everywhere,
        // and this is what makes that testable from anywhere.
        assert!(xdg_absolute(std::ffi::OsStr::new("/elsewhere/config")));
        assert!(!xdg_absolute(std::ffi::OsStr::new("C:\\config")));
        assert!(!xdg_absolute(std::ffi::OsStr::new("config")));
        assert!(!xdg_absolute(std::ffi::OsStr::new("")));
    }

    #[test]
    fn apple_uses_the_application_support_directory() {
        let environment = environment("/Users/p", Some("/ignored"), None);
        assert_eq!(
            root(Platform::Apple, &environment).unwrap(),
            std::path::Path::new("/Users/p/Library/Application Support").join(APPLICATION)
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_unix_that_says_where_home_is_finds_a_platform_cache() {
        // `Cache::platform` is `root(HOST, Environment::of_this_process())`.
        // Both halves are tested exhaustively against a written-down
        // environment; **the fetch is what nothing tested**, and replacing
        // either of them with an empty answer left the whole suite green.
        //
        // It stayed green for a specific and instructive reason.
        // `tests/keys.rs`'s `the_platform_cache_is_an_absolute_directory_of_
        // this_tool_s_own` opens with `let Some(cache) = Cache::platform()
        // else { skip; return }`, and nothing checks that the skip was earned
        // — so a `platform` that answers `None` everywhere makes the one test
        // of the platform cache skip on every machine and report `ok`. That is
        // §12's silent pass, one level in: the gate is the function under test.
        //
        // This is the check that skip needs. On a Unix both configuration
        // roots are reached through `$HOME` — `$HOME/.config` under the XDG
        // rule and `$HOME/Library/Application Support` under Apple's — so a
        // `$HOME` that is set is an environment that says where the directory
        // is, and `None` is then the wrong answer. `expect` rather than a skip,
        // because a Unix running `cargo test` without `$HOME` is a broken
        // environment and should say so rather than pass quietly.
        let home =
            std::env::var_os("HOME").expect("a Unix that can run cargo test says where $HOME is");
        assert!(!home.is_empty(), "$HOME is set to nothing");

        let cache = Cache::platform()
            .expect("$HOME is set, so this environment says where its configuration root is");
        assert!(cache.directory().is_absolute());
        assert!(
            cache
                .directory()
                .ends_with(std::path::Path::new(APPLICATION).join(KEYS)),
            "{} is not this tool's own directory",
            cache.directory().display()
        );
    }

    #[test]
    fn windows_uses_appdata_and_nothing_else() {
        let with = environment("C:\\Users\\p", None, Some("C:\\Users\\p\\AppData\\Roaming"));
        assert_eq!(
            root(Platform::Windows, &with).unwrap(),
            std::path::Path::new("C:\\Users\\p\\AppData\\Roaming").join(APPLICATION)
        );

        let without = environment("C:\\Users\\p", None, None);
        assert!(
            root(Platform::Windows, &without).is_none(),
            "a home directory is not a substitute for APPDATA"
        );
    }

    #[test]
    fn an_environment_that_says_nothing_yields_no_directory() {
        let nothing = Environment::default();
        for platform in [Platform::Xdg, Platform::Apple, Platform::Windows] {
            assert!(
                root(platform, &nothing).is_none(),
                "{platform:?} guessed a directory from an empty environment"
            );
        }
    }

    /// A source that answers `EINTR` before each of its first `left` reads and
    /// its own bytes after that.
    ///
    /// The digest is what decides whether a cache entry belongs to the
    /// executable in hand, so a read that stopped at an interruption would
    /// digest a prefix and hand the previous install's material back under it.
    /// Nothing in the repository provoked one.
    struct Interrupting {
        inner: Cursor<Vec<u8>>,
        left: usize,
    }

    impl std::io::Read for Interrupting {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.left > 0 {
                self.left = self.left.saturating_sub(1);
                return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
            }
            self.inner.read(buf)
        }
    }

    impl std::io::Seek for Interrupting {
        fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(to)
        }
    }

    /// A source that hands over `head` and then fails once, permanently.
    ///
    /// Not an `Interrupted` failure, so it is the one the guard must let
    /// through. It ends rather than failing again, so a digest that swallowed
    /// it answers a digest instead of spinning, and the assertion below is what
    /// tells the two apart.
    struct Failing {
        head: Vec<u8>,
        at: usize,
        failed: bool,
    }

    impl std::io::Read for Failing {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if let Some(rest) = self.head.get(self.at..)
                && !rest.is_empty()
            {
                let want = rest.len().min(buf.len());
                buf[..want].copy_from_slice(&rest[..want]);
                self.at = self.at.saturating_add(want);
                return Ok(want);
            }
            if self.failed {
                return Ok(0);
            }
            self.failed = true;
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        }
    }

    impl std::io::Seek for Failing {
        fn seek(&mut self, _to: std::io::SeekFrom) -> std::io::Result<u64> {
            self.at = 0;
            self.failed = false;
            Ok(0)
        }
    }

    #[test]
    fn a_digest_of_an_interrupted_source_is_the_digest_of_the_whole_source() {
        let bytes: Vec<u8> = (0..40_000_u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let mut source = Interrupting {
            inner: Cursor::new(bytes.clone()),
            left: 3,
        };
        assert_eq!(
            SourceDigest::of(&mut source).unwrap(),
            digest_of(&bytes),
            "an interruption changed which source this is"
        );
    }

    #[test]
    fn a_digest_of_a_source_that_fails_says_how_far_it_got() {
        // The other half of the guard, and the reason the offset is carried:
        // a truncated read must not become a digest of a prefix, which would
        // be a cache key for a file nobody has.
        let head: Vec<u8> = (0..1_000_u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let mut source = Failing {
            head,
            at: 0,
            failed: false,
        };
        match SourceDigest::of(&mut source) {
            Err(crate::Error::Io { offset, source }) => {
                assert_eq!(offset, 1_000);
                assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
            }
            other => panic!("expected the read failure to be reported, got {other:?}"),
        }
    }

    #[test]
    fn an_entry_that_cannot_be_read_is_a_failure_and_not_a_miss() {
        // A cache is disposable, so an entry that is **absent** is a miss and
        // the answer is to extract again. An entry that is there and cannot be
        // read is not that: it is a directory the tool cannot use, or a file
        // somebody else owns, and reporting it as a miss re-scans a 47 MB
        // executable on every command for ever while saying nothing.
        //
        // Only the absence is a miss, and nothing said so — every test of this
        // path used a cache directory that was simply not there, which is the
        // one case both readings agree on.
        let parent = tempfile::tempdir().unwrap();
        let scratch = parent.path().join("cache");
        let cache = Cache::at(&scratch);
        let digest = digest_of(b"an executable");

        // Absent: a miss, and the directory is not created by asking.
        assert!(cache.load(&digest).expect("absent is a miss").is_none());

        // Present and unreadable: a directory where the entry file goes. Every
        // platform refuses to read one as a file, and none of them calls it
        // `NotFound`.
        let path = cache.path_for(&digest);
        fs::create_dir_all(&path).expect("a directory where the entry goes");
        match cache.load(&digest) {
            Err(Error::Io { source, .. }) => {
                assert_ne!(
                    source.kind(),
                    std::io::ErrorKind::NotFound,
                    "an entry that is there was reported absent"
                );
            }
            other => panic!("expected the unreadable entry to be reported, got {other:?}"),
        }
    }

    #[test]
    fn a_cache_directory_that_is_a_file_is_a_failure_and_not_an_empty_cache() {
        // The same rule one level up, for the enumeration `entries` and `clear`
        // are built on: a directory that is **not there** holds nothing, which
        // is why neither creates one. Anything else that stops it being read is
        // a failure — and a `clear` that reported success over a cache it never
        // managed to open would leave key material on disk while saying it had
        // removed it.
        let parent = tempfile::tempdir().unwrap();
        let scratch = parent.path().join("cache");

        // Absent: no entries, and asking did not create it.
        let cache = Cache::at(&scratch);
        assert!(cache.entries().expect("absent holds nothing").is_empty());
        assert!(!scratch.exists(), "asking created the cache directory");

        // A plain file where the directory goes: every platform refuses to
        // enumerate it, and none of them calls it `NotFound`.
        fs::write(&scratch, b"not a directory").expect("a file where the directory goes");
        match cache.entries() {
            Err(Error::Io { source, .. }) => {
                assert_ne!(
                    source.kind(),
                    std::io::ErrorKind::NotFound,
                    "a cache that is there was reported absent"
                );
            }
            other => panic!("expected the unreadable cache to be reported, got {other:?}"),
        }
    }
}
