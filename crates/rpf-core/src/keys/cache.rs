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
    ffi::OsString,
    fs,
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use super::{AES_KEY_LEN, HASH_LUT_LEN, Keys};
use crate::error::{Error, Result};

/// Length of the digest an executable is identified by, in bytes.
pub const SOURCE_DIGEST_LEN: usize = 32;

/// The directory the cache lives in, below the platform's configuration root.
const APPLICATION: &str = "rpf";

/// What a cache file is called, after its source's digest.
const SUFFIX: &str = ".keys";

/// The first bytes of a cache file, so that a file of some other kind under the
/// same name is not read as one.
const MAGIC: [u8; 8] = *b"RPFKEYS\0";

/// The layout version of a cache file. A file of another schema is a miss, not
/// a failure: a cache is disposable and re-extraction is the correct answer.
const SCHEMA: u32 = 1;

/// Offset of the payload within a cache file.
const PAYLOAD_AT: usize = 48;

/// Length of the payload: the two values and the two offsets they were at.
const PAYLOAD_LEN: usize = AES_KEY_LEN.saturating_add(HASH_LUT_LEN).saturating_add(16);

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
}

impl Cache {
    /// The cache in a directory of the caller's choosing.
    #[must_use]
    pub fn at(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    /// The cache in this platform's configuration directory, if there is one.
    ///
    /// `None` where the environment does not say where that is — no `HOME` on a
    /// Unix, no `APPDATA` on Windows — which is a complete answer rather than a
    /// failure: the caller can still name a directory itself.
    #[must_use]
    pub fn platform() -> Option<Self> {
        root(HOST, &Environment::of_this_process()).map(Self::at)
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
    pub fn load(&self, source: &SourceDigest) -> Result<Option<Keys>> {
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
    pub fn store(&self, source: &SourceDigest, keys: &Keys) -> Result<()> {
        fs::create_dir_all(&self.directory).map_err(io)?;

        let destination = self.path_for(source);
        let mut temporary = destination.clone();
        temporary
            .as_mut_os_string()
            .push(format!(".{}.tmp", std::process::id()));

        let mut file = create_private(&temporary)?;
        file.write_all(&encode(keys)).map_err(io)?;
        file.flush().map_err(io)?;
        drop(file);

        fs::rename(&temporary, &destination).map_err(io)
    }

    /// The file the material from this source is kept in.
    fn path_for(&self, source: &SourceDigest) -> PathBuf {
        self.directory.join(format!("{}{SUFFIX}", source.hex()))
    }
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
fn encode(keys: &Keys) -> Vec<u8> {
    let mut payload = Vec::with_capacity(PAYLOAD_LEN);
    payload.extend_from_slice(keys.aes_key());
    payload.extend_from_slice(keys.hash_lut());
    payload.extend_from_slice(&keys.aes_key_offset().to_le_bytes());
    payload.extend_from_slice(&keys.hash_lut_offset().to_le_bytes());

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
fn decode(bytes: &[u8]) -> Option<Keys> {
    if bytes.get(..MAGIC.len())? != MAGIC {
        return None;
    }
    if u32::from_le_bytes(word(bytes, 8)?) != SCHEMA {
        return None;
    }
    let len = usize::try_from(u32::from_le_bytes(word(bytes, 12)?)).ok()?;
    if len != PAYLOAD_LEN {
        return None;
    }
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

    Some(Keys {
        aes,
        aes_at,
        lut,
        lut_at,
    })
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

/// The cache directory for a platform and an environment, if that environment
/// says where it is.
fn root(platform: Platform, environment: &Environment) -> Option<PathBuf> {
    let base = match platform {
        Platform::Xdg => match environment.xdg_config_home.as_ref() {
            Some(configured) if Path::new(configured).is_absolute() => PathBuf::from(configured),
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
    use std::io::Cursor;

    use super::{
        APPLICATION, Cache, Environment, MAGIC, PAYLOAD_AT, Platform, SUFFIX, SourceDigest, decode,
        encode, root,
    };
    use crate::keys::{AES_KEY_LEN, HASH_LUT_LEN, Keys};

    /// Material that is not key material: two fixed byte patterns and two
    /// offsets, which is all the file format has to carry.
    fn material() -> Keys {
        Keys {
            aes: [0x11; AES_KEY_LEN],
            aes_at: 0x1234_5678,
            lut: [0x22; HASH_LUT_LEN],
            lut_at: 0x00AB_CDEF,
        }
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
        assert_eq!(read.aes_key(), material().aes_key());
        assert_eq!(read.hash_lut(), material().hash_lut());
        assert_eq!(read.aes_key_offset(), material().aes_key_offset());
        assert_eq!(read.hash_lut_offset(), material().hash_lut_offset());
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
        let mut moved = material();
        moved.aes_at = 0x9999;
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
            cache.load(&source).unwrap().unwrap().aes_key_offset(),
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
    fn apple_uses_the_application_support_directory() {
        let environment = environment("/Users/p", Some("/ignored"), None);
        assert_eq!(
            root(Platform::Apple, &environment).unwrap(),
            std::path::Path::new("/Users/p/Library/Application Support").join(APPLICATION)
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
}
