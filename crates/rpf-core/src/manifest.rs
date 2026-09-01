//! The sidecar manifest: what an extracted tree cannot say for itself.

use std::{
    collections::BTreeMap,
    fmt,
    io::{Read, Seek, Write},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest as _, Sha256};

use crate::{
    archive::Archive,
    build::{
        Fetch, FileKind, FileSpec, Report, ResourceFlags, Storage, Under, build_under,
        directories_of, specs_of,
    },
    entry::EntryKind,
    error::{Error, NoWrite, Result},
    format::{
        Codec, Version,
        crypto::{Scheme, Sealer},
    },
    keys::Unlock,
    name,
    watch::{Flow, Step, Watch},
};

/// What the manifest is called inside an extracted tree.
pub const MANIFEST_NAME: &str = ".rpf-manifest.json";

/// The schema version this build writes, bumped only when a field's meaning changes.
pub const SCHEMA_VERSION: u32 = 4;

/// The oldest schema this build reads; missing fields are inferred, not refused.
pub const OLDEST_SCHEMA: u32 = 1;

fn schema_1_version() -> Version {
    Version::Rpf7
}

fn schema_1_codec() -> Codec {
    Codec::Deflate
}

fn schema_2_checksum() -> Option<Checksum> {
    None
}

/// The page flags an entry without them has: none recorded, not zeros and not derived.
fn schema_3_flags() -> Option<ResourceFlags> {
    None
}

/// Bytes in a `Checksum`, which is the digest length of SHA-256.
pub const CHECKSUM_LEN: usize = 32;

/// The SHA-256 of one entry's contents, as extracted, never of the payload on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Checksum([u8; CHECKSUM_LEN]);

impl Checksum {
    /// Digests one entry's contents.
    #[must_use]
    pub fn of(contents: &[u8]) -> Self {
        Self(Sha256::digest(contents).into())
    }

    /// `Checksum::of`, over contents that stream past.
    /// # Errors
    /// Returns whatever error the stream itself failed with.
    pub fn of_stream<S: Read>(contents: &mut S) -> Result<Self> {
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            let read = contents
                .read(&mut buffer)
                .map_err(|source| Error::recovered(0, source))?;
            if read == 0 {
                return Ok(Self(digest.finalize().into()));
            }
            digest.update(buffer.get(..read).unwrap_or_default());
        }
    }
}

impl fmt::Display for Checksum {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(out, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for Checksum {
    fn serialize<S: Serializer>(&self, out: S) -> std::result::Result<S::Ok, S::Error> {
        out.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Checksum {
    fn deserialize<D: Deserializer<'de>>(text: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(text)?;
        let mut bytes = [0_u8; CHECKSUM_LEN];
        if text.len() != CHECKSUM_LEN.saturating_mul(2) {
            return Err(D::Error::custom("a checksum is 64 hexadecimal digits"));
        }
        let (pairs, _) = text.as_bytes().as_chunks::<2>();
        for (byte, digits) in bytes.iter_mut().zip(pairs) {
            let digits = str::from_utf8(digits)
                .map_err(|_| D::Error::custom("a checksum is hexadecimal"))?;
            *byte = u8::from_str_radix(digits, 16)
                .map_err(|_| D::Error::custom("a checksum is hexadecimal"))?;
        }
        Ok(Self(bytes))
    }
}

/// How an entry's payload was stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageKind {
    /// Written as-is.
    Stored,
    /// Deflated.
    Deflate,
}

/// What kind of entry this was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryClass {
    /// Plain bytes.
    Binary,
    /// An `RSC7` resource.
    Resource,
}

/// One entry's record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Path within the archive.
    pub path: String,
    /// Binary or resource.
    pub class: EntryClass,
    /// The two page-flag words the entry's row declared, kept verbatim (many-to-one mapping).
    #[serde(default = "schema_3_flags", skip_serializing_if = "Option::is_none")]
    pub flags: Option<ResourceFlags>,
    /// Stored or deflated; recorded even for a resource, which is always stored.
    pub storage: StorageKind,
    /// The per-entry encryption word.
    #[serde(default)]
    pub encryption: u32,
    /// The digest of the entry's contents; `None` means none was recorded.
    #[serde(default = "schema_2_checksum", skip_serializing_if = "Option::is_none")]
    pub checksum: Option<Checksum>,
}

/// Everything about an archive that its extracted tree does not carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Schema version of this file.
    pub schema: u32,
    /// The container version the tree was extracted from and packs back to.
    #[serde(default = "schema_1_version")]
    pub version: Version,
    /// The compressor payloads are written with, since one version can mean two codecs.
    #[serde(default = "schema_1_codec")]
    pub codec: Codec,
    /// The archive's encryption tag.
    pub encryption: u32,
    /// Every directory, root excluded. Present so an empty one survives.
    pub directories: Vec<String>,
    /// Every file, in entry-table order.
    pub entries: Vec<ManifestEntry>,
}

impl Manifest {
    /// Derives everything an archive's entry table says that a tree cannot; no checksum.
    /// # Errors
    /// `Error::BadPath` for a name that could not be one file on a host.
    pub fn of(archive: &Archive) -> Result<Self> {
        Self::derive(archive, &BTreeMap::new())
    }

    /// `Manifest::of`, with each entry's contents digested in, one `Watch` step per entry.
    /// # Errors
    /// As `Manifest::of`, plus a payload that fails to read back or a watcher that stops it.
    pub fn of_contents<R: Read + Seek>(
        src: &mut R,
        archive: &Archive,
        watch: &mut impl Watch,
    ) -> Result<Self> {
        let specs = specs_of(archive)?;
        let total = u32::try_from(specs.len()).unwrap_or(u32::MAX);
        let mut recorded = BTreeMap::new();
        let mut done = 0_u32;
        let mut bytes = 0_u64;
        for (spec, index) in &specs {
            // Streamed, not held: the largest entry isn't a size the caller chose.
            let mut contents = archive.extracted(&mut *src, *index)?;
            let len = contents.len();
            recorded.insert(spec.path.clone(), Checksum::of_stream(&mut contents)?);

            done = done.saturating_add(1);
            bytes = bytes.saturating_add(len);
            if watch.step(Step {
                path: &spec.path,
                done,
                total,
                bytes,
            }) == Flow::Stop
            {
                return Err(Error::Cancelled { done, total });
            }
        }
        Self::derive(archive, &recorded)
    }

    fn derive(archive: &Archive, recorded: &BTreeMap<String, Checksum>) -> Result<Self> {
        let mut entries = Vec::new();
        for (spec, index) in specs_of(archive)? {
            let class = match archive.entry(index)?.kind {
                EntryKind::Resource { .. } => EntryClass::Resource,
                _ => EntryClass::Binary,
            };
            let storage = match spec.kind {
                FileKind::Binary {
                    storage: Storage::Deflate,
                    ..
                } => StorageKind::Deflate,
                FileKind::Binary {
                    storage: Storage::Stored,
                    ..
                }
                | FileKind::Resource { .. } => StorageKind::Stored,
            };
            let encryption = match spec.kind {
                FileKind::Binary { encryption, .. } => encryption,
                FileKind::Resource { .. } => 0,
            };
            // Not from the entry a second time: `build::kind_of` reads a row's flags once.
            let flags = match spec.kind {
                FileKind::Resource { declared } => declared,
                FileKind::Binary { .. } => None,
            };
            entries.push(ManifestEntry {
                checksum: recorded.get(&spec.path).copied(),
                path: spec.path,
                class,
                flags,
                storage,
                encryption,
            });
        }

        let manifest = Self {
            schema: SCHEMA_VERSION,
            version: archive.version(),
            codec: archive.version().codec(),
            encryption: archive.encryption(),
            directories: directories_of(archive)?,
            entries,
        };
        manifest.check_host_names()?;
        Ok(manifest)
    }

    /// The checksum recorded for each path; an entry with none is absent, not zero.
    #[must_use]
    pub fn checksums(&self) -> BTreeMap<&str, Checksum> {
        self.entries
            .iter()
            .filter_map(|entry| Some((entry.path.as_str(), entry.checksum?)))
            .collect()
    }

    fn check_host_names(&self) -> Result<()> {
        for directory in &self.directories {
            name::check_host(directory)?;
        }
        for entry in &self.entries {
            name::check_host(&entry.path)?;
        }
        Ok(())
    }

    fn check_flags(&self) -> Result<()> {
        for entry in &self.entries {
            if entry.class == EntryClass::Binary && entry.flags.is_some() {
                return Err(Error::BadPath {
                    path: entry.path.clone(),
                    reason: "is a binary entry and declares resource page flags",
                });
            }
        }
        Ok(())
    }

    /// The build specification this manifest describes.
    #[must_use]
    pub fn specs(&self) -> Vec<FileSpec> {
        self.entries
            .iter()
            .map(|entry| FileSpec {
                path: entry.path.clone(),
                kind: match entry.class {
                    EntryClass::Resource => FileKind::Resource {
                        declared: entry.flags,
                    },
                    EntryClass::Binary => FileKind::Binary {
                        storage: match entry.storage {
                            StorageKind::Stored => Storage::Stored,
                            StorageKind::Deflate => Storage::Deflate,
                        },
                        encryption: entry.encryption,
                    },
                },
            })
            .collect()
    }

    fn sealing(&self) -> Result<Option<Scheme>> {
        if self.version.is_open(self.encryption) {
            return Ok(None);
        }
        match self.version.scheme(self.encryption) {
            Some(scheme) if self.version.row_is_a_cipher_block() => Ok(Some(scheme)),
            Some(_) | None => Err(Error::CannotWriteEncrypted {
                tag: self.encryption,
                reason: NoWrite::NoInverse,
            }),
        }
    }

    fn sealer(&self, scheme: Scheme, unlock: &Unlock) -> Result<Sealer> {
        unlock
            .candidates(scheme)?
            .iter()
            .find_map(|material| Sealer::new(scheme, material))
            .ok_or(match scheme {
                // A memory image is missing here, not a key; `NeedsKey` would mislead.
                Scheme::Ng => Error::CannotWriteEncrypted {
                    tag: self.encryption,
                    reason: NoWrite::NoInverse,
                },
                // Every source carries the AES key, so a caller with none extracts one.
                Scheme::Aes(_) => Error::NeedsKey {
                    tag: self.encryption,
                },
            })
    }

    /// Writes the archive this manifest describes, fetching each file's contents as written.
    /// # Errors
    /// An unwritable transform, or no material to run it, checked before anything is written.
    pub fn pack_into<W, F>(
        &self,
        out: &mut W,
        unlock: &Unlock,
        fetch: F,
        watch: &mut impl Watch,
    ) -> Result<Report>
    where
        W: Write + Seek,
        F: Fetch,
    {
        let sealer = match self.sealing()? {
            None => None,
            Some(scheme) => Some(self.sealer(scheme, unlock)?),
        };
        let under = sealer.as_ref().map_or_else(
            || Under::open(self.version),
            |sealer| Under::sealed(self.version, self.encryption, sealer, unlock.name()),
        );
        build_under(out, under, &self.specs(), &self.directories, fetch, watch)
    }

    /// Renders the manifest.
    /// # Errors
    /// Never in practice; the shape is fixed and every field is serialisable.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|error| Error::BadPath {
            path: MANIFEST_NAME.to_owned(),
            reason: if error.is_io() {
                "could not be written"
            } else {
                "could not be rendered"
            },
        })
    }

    /// Reads a manifest of schema `OLDEST_SCHEMA` through `SCHEMA_VERSION`.
    /// # Errors
    /// Not a manifest, an unreadable schema or path, binary flags, or an unwritable tag.
    pub fn from_json(text: &str) -> Result<Self> {
        let manifest: Self = serde_json::from_str(text).map_err(|_| Error::BadPath {
            path: MANIFEST_NAME.to_owned(),
            reason: "is not a manifest this version understands",
        })?;
        if manifest.schema < OLDEST_SCHEMA || manifest.schema > SCHEMA_VERSION {
            return Err(Error::BadPath {
                path: MANIFEST_NAME.to_owned(),
                reason: "was written by a schema version this build does not read",
            });
        }
        // Refused now, before a byte of the tree is read or any key material is wanted.
        manifest.sealing()?;
        // Before `pack` opens anything, so no read is attempted from a bad name.
        manifest.check_host_names()?;
        manifest.check_flags()?;
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, sync::Arc};

    use super::*;
    use crate::{keys::Material, watch::Unwatched};

    fn contents() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("short.bin", vec![b'a'; 7]),
            (
                "deep/words.txt",
                b"the same words over and over ".repeat(40),
            ),
        ]
    }

    fn packable(tag: u32) -> Manifest {
        let sealed = !Version::Rpf7.is_open(tag);
        Manifest {
            schema: SCHEMA_VERSION,
            version: Version::Rpf7,
            codec: Codec::Deflate,
            encryption: tag,
            directories: vec!["deep".to_owned()],
            entries: contents()
                .iter()
                .map(|(path, _)| ManifestEntry {
                    path: (*path).to_owned(),
                    class: EntryClass::Binary,
                    flags: None,
                    storage: if path.contains(".txt") {
                        StorageKind::Deflate
                    } else {
                        StorageKind::Stored
                    },
                    encryption: u32::from(sealed),
                    checksum: None,
                })
                .collect(),
        }
    }

    fn fetching() -> impl Fetch {
        move |wanted: &str| {
            let found = contents()
                .iter()
                .find(|(path, _)| *path == wanted)
                .map(|(_, bytes)| bytes.clone())
                .unwrap_or_default();
            Ok(Cursor::new(found))
        }
    }

    fn keyed(named: &str) -> Unlock {
        Unlock::held(Arc::new(Material::over_zeros()), named)
    }

    #[test]
    fn a_manifest_round_trips_through_its_own_json() {
        let manifest = Manifest {
            schema: SCHEMA_VERSION,
            version: Version::Rpf7,
            codec: Codec::Deflate,
            encryption: Version::Rpf7.open(),
            directories: vec!["data".to_owned(), "x64/empty".to_owned()],
            entries: vec![
                ManifestEntry {
                    path: "data/vehicles.meta".to_owned(),
                    class: EntryClass::Binary,
                    flags: None,
                    storage: StorageKind::Deflate,
                    encryption: 0,
                    checksum: Some(Checksum::of(b"hello there")),
                },
                ManifestEntry {
                    path: "x64/a.yft".to_owned(),
                    class: EntryClass::Resource,
                    flags: None,
                    storage: StorageKind::Stored,
                    encryption: 0,
                    checksum: None,
                },
            ],
        };
        let text = manifest.to_json().expect("renders");
        assert!(text.contains("\"version\": \"rpf7\""), "{text}");
        assert!(text.contains("\"codec\": \"deflate\""), "{text}");
        assert!(
            text.contains(
                "\"checksum\": \"12998c017066eb0d2a70b94e6ed31929\
                 85855ce390f321bbdb832022888bd251\""
            ),
            "{text}"
        );
        assert_eq!(
            text.matches("\"checksum\"").count(),
            1,
            "an entry that recorded none says nothing rather than null: {text}"
        );
        assert_eq!(Manifest::from_json(&text).expect("parses"), manifest);
    }

    #[test]
    fn a_manifest_that_records_no_checksum_reads_as_having_recorded_none() {
        let text = r#"{"schema":2,"version":"rpf7","codec":"deflate",
                       "encryption":1313165391,"directories":[],
                       "entries":[{"path":"a.txt","class":"binary",
                                   "storage":"stored","encryption":0}]}"#;
        let manifest = Manifest::from_json(text).expect("schema 2 still reads");
        assert_eq!(manifest.schema, 2);
        assert_eq!(manifest.entries.first().and_then(|e| e.checksum), None);
        assert!(
            manifest.checksums().is_empty(),
            "an entry that recorded none is absent, not present and empty",
        );
    }

    #[test]
    fn a_checksum_that_is_not_a_digest_is_refused_rather_than_padded() {
        for bad in [
            "",
            "beef",
            "zz17e88bebe5bfb1a29a52a8b1d0b31e70e0b1b34a3e0a0c6ac1a1c0b9b57f4c",
        ] {
            let text = format!(
                r#"{{"schema":3,"version":"rpf7","codec":"deflate",
                     "encryption":1313165391,"directories":[],
                     "entries":[{{"path":"a.txt","class":"binary","storage":"stored",
                                  "encryption":0,"checksum":"{bad}"}}]}}"#
            );
            assert!(
                matches!(Manifest::from_json(&text), Err(Error::BadPath { .. })),
                "{bad:?} is not a checksum"
            );
        }
    }

    #[test]
    fn a_schema_1_manifest_is_read_as_the_only_container_it_could_have_meant() {
        let text = r#"{"schema":1,"encryption":1313165391,"directories":[],
                       "entries":[{"path":"a.txt","class":"binary",
                                   "storage":"stored","encryption":0}]}"#;
        let manifest = Manifest::from_json(text).expect("schema 1 still reads");
        assert_eq!(manifest.schema, 1);
        assert_eq!(manifest.version, Version::Rpf7);
        assert_eq!(manifest.codec, Codec::Deflate);
        assert_eq!(manifest.specs().len(), 1);
    }

    #[test]
    fn a_manifest_naming_a_container_this_build_cannot_write_is_refused() {
        let text = r#"{"schema":2,"version":"rpf2","codec":"deflate",
                       "encryption":1313165391,"directories":[],"entries":[]}"#;
        assert!(matches!(
            Manifest::from_json(text),
            Err(Error::BadPath { .. })
        ));
    }

    #[test]
    fn an_ng_manifest_refuses_the_pack_when_nothing_derives_the_transform() {
        let tag = 267_386_879_u32;
        let mut out = Cursor::new(Vec::new());
        let error = packable(tag)
            .pack_into(&mut out, &keyed("packed.rpf"), fetching(), &mut Unwatched)
            .expect_err("an NG manifest does not pack without the material");
        assert!(
            matches!(
                error,
                Error::CannotWriteEncrypted {
                    tag: found,
                    reason: NoWrite::NoInverse,
                } if found == tag
            ),
            "{error:?}"
        );
        assert_eq!(error.category(), crate::error::Category::Unsupported);
        assert!(out.into_inner().is_empty(), "a refused pack wrote bytes");
    }

    #[test]
    fn an_ng_manifest_is_read_back_rather_than_refused_at_parse_time() {
        let tag = 267_386_879_u32;
        let text = format!(r#"{{"schema":1,"encryption":{tag},"directories":[],"entries":[]}}"#);
        let manifest = Manifest::from_json(&text).expect("an NG manifest reads back");
        assert_eq!(manifest.encryption, tag);

        let unknown = 0x0FAB_CDEF_u32;
        assert!(Version::Rpf7.scheme(unknown).is_none());
        let text =
            format!(r#"{{"schema":1,"encryption":{unknown},"directories":[],"entries":[]}}"#);
        let error = Manifest::from_json(&text).expect_err("an unknown encrypted tag is refused");
        assert!(
            matches!(
                error,
                Error::CannotWriteEncrypted {
                    tag: found,
                    reason: NoWrite::NoInverse,
                } if found == unknown
            ),
            "{error:?}"
        );
    }

    #[test]
    fn an_ng_manifest_packs_back_under_its_own_transform_and_opens_again() {
        let tag = crate::format::rpf7::ENCRYPTION_NG;
        let manifest = packable(tag);
        let unlock = Unlock::held(
            Arc::new(crate::format::crypto::synthetic::ng_material(0x4A17_0000)),
            "packed.rpf",
        );
        let mut out = Cursor::new(Vec::new());
        manifest
            .pack_into(&mut out, &unlock, fetching(), &mut Unwatched)
            .expect("an NG tree packs");
        let mut source = Cursor::new(out.into_inner());
        let archive = crate::Archive::open(&mut source, &unlock).expect("it opens again");
        assert_eq!(archive.encryption(), tag);
        for (path, expected) in contents() {
            let index = archive
                .find(path)
                .unwrap_or_else(|error| panic!("{path} does not resolve: {error}"));
            let read = archive
                .read(&mut source, index)
                .unwrap_or_else(|error| panic!("{path} does not read back: {error}"));
            assert_eq!(read, expected, "{path} came back different");
        }
    }

    #[test]
    fn an_aes_manifest_packs_back_under_its_own_transform_and_opens_again() {
        let manifest = packable(crate::format::rpf7::ENCRYPTION_AES);
        let text = manifest.to_json().expect("renders");
        assert_eq!(
            Manifest::from_json(&text).expect("an AES manifest is read"),
            manifest,
            "an AES manifest is no longer refused at parse time"
        );

        let mut out = Cursor::new(Vec::new());
        manifest
            .pack_into(&mut out, &keyed("packed.rpf"), fetching(), &mut Unwatched)
            .expect("the tree packs back");

        let mut source = Cursor::new(out.into_inner());
        let archive =
            Archive::open(&mut source, &keyed("packed.rpf")).expect("the packed archive opens");
        assert_eq!(archive.encryption(), crate::format::rpf7::ENCRYPTION_AES);
        for (path, expected) in contents() {
            let index = archive.find(path).expect("the entry resolves");
            let read = archive.read(&mut source, index).expect("the entry reads");
            assert_eq!(read, expected, "{path} came back different");
        }

        let error = Archive::open(&mut source, &Unlock::unkeyed())
            .expect_err("a sealed archive opens for no one unkeyed");
        assert!(matches!(error, Error::NeedsKey { .. }), "{error:?}");
    }

    #[test]
    fn a_pack_with_no_key_material_refuses_rather_than_writing_in_the_clear() {
        let tag = crate::format::rpf7::ENCRYPTION_AES;
        let mut out = Cursor::new(Vec::new());
        let error = packable(tag)
            .pack_into(&mut out, &Unlock::unkeyed(), fetching(), &mut Unwatched)
            .expect_err("a pack with no material does not write an archive");
        assert!(
            matches!(error, Error::NeedsKey { tag: found } if found == tag),
            "{error:?}"
        );
        assert_eq!(error.category(), crate::error::Category::NeedsKey);
        assert!(out.into_inner().is_empty(), "a refused pack wrote bytes");
    }

    #[test]
    fn a_manifest_naming_no_transform_packs_in_the_clear_and_reaches_no_cache() {
        let manifest = packable(Version::Rpf7.open());
        let mut out = Cursor::new(Vec::new());
        manifest
            .pack_into(&mut out, &Unlock::unkeyed(), fetching(), &mut Unwatched)
            .expect("an unencrypted tree packs with no material");

        let mut source = Cursor::new(out.into_inner());
        let archive = Archive::open(&mut source, &Unlock::unkeyed()).expect("it opens");
        assert!(Version::Rpf7.is_open(archive.encryption()));
        for (path, expected) in contents() {
            let index = archive.find(path).expect("the entry resolves");
            assert_eq!(archive.read(&mut source, index).expect("reads"), expected);
        }
    }

    #[test]
    fn a_resources_flag_words_survive_the_manifests_own_json() {
        let manifest = Manifest {
            schema: SCHEMA_VERSION,
            version: Version::Rpf7,
            codec: Codec::Deflate,
            encryption: Version::Rpf7.open(),
            directories: vec![],
            entries: vec![ManifestEntry {
                path: "des_canister.ytyp".to_owned(),
                class: EntryClass::Resource,
                flags: Some(ResourceFlags {
                    system: 0x0002_0000,
                    graphics: 0xd000_0000,
                }),
                storage: StorageKind::Stored,
                encryption: 0,
                checksum: None,
            }],
        };
        let text = manifest.to_json().expect("renders");
        assert!(text.contains("\"system\": \"0x00020000\""), "{text}");
        assert!(text.contains("\"graphics\": \"0xd0000000\""), "{text}");
        assert_eq!(Manifest::from_json(&text).expect("parses"), manifest);

        assert_eq!(
            manifest.specs().first().map(|spec| spec.kind),
            Some(FileKind::Resource {
                declared: Some(ResourceFlags {
                    system: 0x0002_0000,
                    graphics: 0xd000_0000,
                }),
            })
        );
    }

    #[test]
    fn a_flag_word_that_is_not_eight_hex_digits_is_refused_rather_than_padded() {
        for bad in [
            "",
            "0x2000",
            "131072",
            "0xzzzzzzzz",
            "0X00020000",
            "0x0002000A",
        ] {
            let text = format!(
                r#"{{"schema":4,"version":"rpf7","codec":"deflate",
                     "encryption":1313165391,"directories":[],
                     "entries":[{{"path":"a.ydr","class":"resource",
                                  "flags":{{"system":"{bad}","graphics":"0xd0000000"}},
                                  "storage":"stored","encryption":0}}]}}"#
            );
            assert!(
                matches!(Manifest::from_json(&text), Err(Error::BadPath { .. })),
                "{bad:?} is not a flag word"
            );
        }
    }

    #[test]
    fn a_schema_3_manifest_reads_and_records_no_flag_words() {
        let text = r#"{"schema":3,"version":"rpf7","codec":"deflate",
                       "encryption":1313165391,"directories":[],
                       "entries":[{"path":"a.ydr","class":"resource",
                                   "storage":"stored","encryption":0}]}"#;
        let manifest = Manifest::from_json(text).expect("schema 3 still reads");
        assert_eq!(manifest.schema, 3);
        assert_eq!(manifest.entries.first().and_then(|entry| entry.flags), None);
        assert_eq!(
            manifest.specs().first().map(|spec| spec.kind),
            Some(FileKind::Resource { declared: None }),
            "a manifest that recorded none says exactly that, at both ends",
        );
    }

    #[test]
    fn a_binary_entry_that_carries_flag_words_is_refused() {
        let text = r#"{"schema":4,"version":"rpf7","codec":"deflate",
                       "encryption":1313165391,"directories":[],
                       "entries":[{"path":"a.txt","class":"binary",
                                   "flags":{"system":"0x00020000",
                                            "graphics":"0xd0000000"},
                                   "storage":"stored","encryption":0}]}"#;
        let error = Manifest::from_json(text).expect_err("a binary entry declares no page flags");
        assert!(
            matches!(error, Error::BadPath { ref path, .. } if path == "a.txt"),
            "{error:?}"
        );
    }

    #[test]
    fn a_schema_outside_the_range_this_build_reads_is_refused() {
        for schema in [0, SCHEMA_VERSION.saturating_add(1), 99] {
            let text = format!(
                r#"{{"schema":{schema},"encryption":1313165391,"directories":[],"entries":[]}}"#
            );
            assert!(
                matches!(Manifest::from_json(&text), Err(Error::BadPath { .. })),
                "schema {schema}"
            );
        }
    }
}
