//! Where extracted key material is kept between runs, and what invalidates it.

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

const APPLICATION: &str = "rpf";

const KEYS: &str = "keys";

const SUFFIX: &str = ".keys";

const TEMPORARY: &str = ".tmp";

const MAGIC: [u8; 8] = *b"RPFKEYS\0";

const SCHEMA: u32 = 2;

const PAYLOAD_AT: usize = 48;

/// Length of the payload every source carries: the two values and their offsets.
const BASE_LEN: usize = AES_KEY_LEN.saturating_add(HASH_LUT_LEN).saturating_add(16);

/// How much longer an entry is when it also holds the NG material.
const NG_LEN: usize = NG_EXPANDED_KEY_COUNT
    .saturating_mul(NG_EXPANDED_KEY_LEN)
    .saturating_add(NG_DECRYPT_TABLE_COUNT.saturating_mul(NG_DECRYPT_TABLE_LEN))
    .saturating_add(16);

const LAUNCHER_LEN: usize = AES_KEY_LEN.saturating_add(8);

const WITH_LAUNCHER_LEN: usize = BASE_LEN.saturating_add(LAUNCHER_LEN);

const WITH_NG_LEN: usize = BASE_LEN.saturating_add(NG_LEN);

const WITH_BOTH_LEN: usize = WITH_NG_LEN.saturating_add(LAUNCHER_LEN);

const fn shape(len: usize) -> Option<(bool, bool)> {
    match len {
        BASE_LEN => Some((false, false)),
        WITH_LAUNCHER_LEN => Some((true, false)),
        WITH_NG_LEN => Some((false, true)),
        WITH_BOTH_LEN => Some((true, true)),
        _ => None,
    }
}

/// The SHA-256 of a game executable, which is what a cache entry is keyed by; never a key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SourceDigest([u8; SOURCE_DIGEST_LEN]);

impl SourceDigest {
    /// Digests a source whole, rewinding first so a partly-read source hashes the same.
    /// # Errors
    /// An I/O error if the source cannot be rewound or read.
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
    directory: PathBuf,
    superseded: Option<PathBuf>,
}

impl Cache {
    /// The cache in a directory of the caller's choosing.
    #[must_use]
    pub fn at(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            superseded: None,
        }
    }

    /// The cache in this platform's configuration directory, if there is one.
    #[must_use]
    pub fn platform() -> Option<Self> {
        root(HOST, &Environment::of_this_process()).map(Self::below)
    }

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

    /// The material extracted from the executable with this digest, if cached.
    /// # Errors
    /// An I/O error if the directory exists and the file cannot be read.
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

    /// Writes material to the cache, renamed atomically into place; owner-only on Unix.
    /// # Errors
    /// An I/O error if the directory cannot be created or the file written.
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

    /// The sources this cache holds material for, one digest per entry.
    /// # Errors
    /// An I/O error if the directory exists and cannot be read.
    pub fn entries(&self) -> Result<Vec<SourceDigest>> {
        let mut entries = Vec::new();
        for (_, held) in ours_in(&self.directory)? {
            if let Held::Entry(source) = held {
                entries.push(source);
            }
        }
        Ok(entries)
    }

    /// Every material this cache holds, in digest order for a stable result.
    /// # Errors
    /// An I/O error if the directory exists and an entry cannot be read.
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

    /// Removes everything this cache wrote; the platform cache also sweeps its predecessor.
    /// # Errors
    /// An I/O error if a directory cannot be read or a file cannot be removed.
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

    fn path_for(&self, source: &SourceDigest) -> PathBuf {
        self.directory.join(format!("{}{SUFFIX}", source.hex()))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Held {
    Entry(SourceDigest),
    Temporary,
}

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

fn io(source: std::io::Error) -> Error {
    Error::Io { offset: 0, source }
}

/// Readable by its owner alone: the mode is set at `open`, before any key bytes are written.
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

#[cfg(not(unix))]
fn create_private(path: &Path) -> Result<fs::File> {
    fs::File::create(path).map_err(io)
}

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
    // In the order the payload lays them out, so each bound reads against the last.
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

fn decode_launcher(payload: &[u8]) -> Option<LauncherKey> {
    let key_end = BASE_LEN.checked_add(AES_KEY_LEN)?;
    let key: [u8; AES_KEY_LEN] = payload.get(BASE_LEN..key_end)?.try_into().ok()?;
    Some(LauncherKey::restored(
        key,
        u64::from_le_bytes(long(payload, key_end)?),
    ))
}

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

fn word(bytes: &[u8], at: usize) -> Option<[u8; 4]> {
    bytes.get(at..at.checked_add(4)?)?.try_into().ok()
}

fn long(bytes: &[u8], at: usize) -> Option<[u8; 8]> {
    bytes.get(at..at.checked_add(8)?)?.try_into().ok()
}

/// The three shapes a config directory takes; not `#[cfg]`-ed, so `root` tests all three.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Platform {
    Xdg,
    Apple,
    Windows,
}

const HOST: Platform = if cfg!(windows) {
    Platform::Windows
} else if cfg!(target_os = "macos") {
    Platform::Apple
} else {
    Platform::Xdg
};

#[derive(Clone, Default, Debug)]
struct Environment {
    home: Option<OsString>,
    xdg_config_home: Option<OsString>,
    appdata: Option<OsString>,
}

impl Environment {
    fn of_this_process() -> Self {
        Self {
            home: std::env::var_os("HOME"),
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME"),
            appdata: std::env::var_os("APPDATA"),
        }
    }
}

/// Absolute by the spec's rule (a leading `/`), not `Path::is_absolute`'s host rule.
fn xdg_absolute(configured: &OsStr) -> bool {
    configured.as_encoded_bytes().first() == Some(&b'/')
}

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

    fn keys_at(aes_at: u64) -> Keys {
        Keys {
            aes: [0x11; AES_KEY_LEN],
            aes_at,
            lut: [0x22; HASH_LUT_LEN],
            lut_at: 0x00AB_CDEF,
        }
    }

    fn material() -> Material {
        Material::restored(keys_at(0x1234_5678), None, None)
    }

    fn material_with_launcher() -> Material {
        Material::restored(
            keys_at(0x1234_5678),
            None,
            Some(LauncherKey::restored([0x55; AES_KEY_LEN], 0x005E_E3F0)),
        )
    }

    fn material_with_ng() -> Material {
        let expanded = vec![0x33; NG_EXPANDED_KEY_COUNT * NG_EXPANDED_KEY_LEN];
        let tables = vec![0x44; NG_DECRYPT_TABLE_COUNT * NG_DECRYPT_TABLE_LEN];
        let ng = NgKeys::restored(expanded, tables, 0x01E3_3120, 0x01E8_6CE0)
            .expect("the lengths are the ones the type promises");
        Material::restored(keys_at(0x1234_5678), Some(ng), None)
    }

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
        assert_eq!(
            digest_of(b"").hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn two_executables_have_two_digests_and_therefore_two_cache_files() {
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

    const NG_ROUNDS_LAST: usize = crate::keys::NG_ROUNDS - 1;

    #[test]
    fn the_ng_material_survives_the_file_format_and_keeps_its_positions() {
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
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::at(directory.path());

        assert!(
            cache.materials().unwrap().is_empty(),
            "an empty cache offered a candidate"
        );

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
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::below(directory.path().to_path_buf());
        assert_eq!(cache.directory(), directory.path().join(KEYS));
    }

    #[test]
    fn clearing_the_platform_cache_reaches_the_place_entries_used_to_live() {
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
        let relative = environment("/home/p", Some("config"), None);
        assert_eq!(
            root(Platform::Xdg, &relative).unwrap(),
            std::path::Path::new("/home/p/.config").join(APPLICATION)
        );
    }

    #[test]
    fn the_xdg_rule_is_a_leading_slash_and_not_the_host_s_idea_of_absolute() {
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
        let parent = tempfile::tempdir().unwrap();
        let scratch = parent.path().join("cache");
        let cache = Cache::at(&scratch);
        let digest = digest_of(b"an executable");

        assert!(cache.load(&digest).expect("absent is a miss").is_none());

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
        let parent = tempfile::tempdir().unwrap();
        let scratch = parent.path().join("cache");

        let cache = Cache::at(&scratch);
        assert!(cache.entries().expect("absent holds nothing").is_empty());
        assert!(!scratch.exists(), "asking created the cache directory");

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
