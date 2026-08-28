//! The sidecar manifest: what an extracted tree cannot say for itself.
//!
//! DR-004. An extracted file carries its own contents, and a resource carries
//! its flags and version inside its `RSC7` header, so the manifest is not the
//! route for those. What it is the only route for:
//!
//! - whether an entry was **stored or deflated**, which the contents cannot say;
//! - the per-entry **encryption** word;
//! - the **resource bit** for an entry whose payload is not `RSC7`, which is
//!   `docs/backlog.md` Q7 and has no observed instance yet;
//! - **empty directories**, which a tree of files loses;
//! - the **container version** and the **codec** the tree came out of, which
//!   nothing on disk carries and which a tree extracted from one version must
//!   not be packed as another without. R11.3, DR-012;
//! - a **checksum of each entry's contents**, which no archive carries and
//!   which is the only thing that can say a *stored* entry's bytes changed.
//!   DR-023.
//!
//! It is JSON so that it can be read in a diff and edited by hand, and its
//! field names are stable.

use std::{
    collections::BTreeMap,
    fmt,
    io::{Read, Seek},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest as _, Sha256};

use crate::{
    archive::Archive,
    build::{FileKind, FileSpec, Storage, directories_of, specs_of},
    entry::EntryKind,
    error::{Error, Result},
    format::{Codec, Version},
    name,
    watch::{Flow, Step, Watch},
};

/// What the manifest is called inside an extracted tree.
pub const MANIFEST_NAME: &str = ".rpf-manifest.json";

/// The schema version this build writes.
///
/// Bumped when a field changes meaning, never for an addition a reader can
/// ignore — and [`Manifest::version`] is not one a reader may ignore, because a
/// reader that does packs a tree as a version nobody said it was. R11.3.
/// [`ManifestEntry::checksum`] took it to 3 for the reason DR-023 gives: a
/// reader that ignores it verifies less than it says it did.
pub const SCHEMA_VERSION: u32 = 3;

/// The oldest schema this build reads.
///
/// Schema 1 carried no version and no codec. It did not need to: `RPF7` was the
/// only container this tool had ever read or written, so a schema-1 manifest
/// describes an `RPF7` tree with deflated payloads and nothing else it could
/// describe. It is therefore **read as that** rather than refused —
/// [`schema_1_version`] and [`schema_1_codec`] are where that reading is
/// written down, and DR-018 is why. Refusing it instead would have made a
/// schema bump break every tree already extracted, for no fact recovered.
///
/// Schema 2 carried no checksum, and 1 is still the oldest read: a manifest
/// without one is a manifest that recorded none, which is a thing a reader can
/// act on rather than a thing it has to guess. [`schema_2_checksum`], DR-023.
pub const OLDEST_SCHEMA: u32 = 1;

/// The container version a manifest that does not name one was written from.
fn schema_1_version() -> Version {
    Version::Rpf7
}

/// The codec a manifest that does not name one was written with.
fn schema_1_codec() -> Codec {
    Codec::Deflate
}

/// The checksum an entry that does not carry one has: **none was recorded**.
///
/// Not "the contents matched", and not "the contents are empty" — an entry with
/// no checksum is one nothing can be checked against, and a walk counts it as
/// unchecked rather than as passed. Written as a named function rather than as
/// a bare `#[serde(default)]` for DR-018's reason: what a missing field means is
/// a stated migration rule with a record attached, never the `Default` impl of
/// an unrelated type. DR-023.
fn schema_2_checksum() -> Option<Checksum> {
    None
}

/// Bytes in a [`Checksum`], which is the digest length of SHA-256.
pub const CHECKSUM_LEN: usize = 32;

/// The SHA-256 of one entry as the file it is outside the archive.
///
/// **Of the contents, never of the payload on disk.** The two differ for a
/// deflated entry, and a rebuild is expected to change the payload — our
/// deflate is not the producer's — while leaving the contents byte for byte
/// the same. A digest over the payload would therefore fail on every archive
/// this tool writes correctly, which is the opposite of what it is for.
/// DR-023.
///
/// Contents means exactly what [`Archive::extract`] returns: the bytes the
/// extracted file holds. For a binary entry that is what it inflates to; for a
/// resource it is the `RSC7` file, header and deflated body, because that is
/// what a `.yft` on disk is and passthrough keeps it identical across a
/// rebuild. So `sha256sum` over an extracted tree reproduces these values.
///
/// SHA-256 because `docs/conventions.md` §14's checksums row already names
/// `sha2` for exactly this — "per-entry checksums" — so nothing new is
/// depended on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Checksum([u8; CHECKSUM_LEN]);

impl Checksum {
    /// Digests one entry's contents.
    #[must_use]
    pub fn of(contents: &[u8]) -> Self {
        Self(Sha256::digest(contents).into())
    }
}

impl fmt::Display for Checksum {
    /// Lower-case hexadecimal, which is what the manifest holds and what
    /// `sha256sum` prints.
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
    /// Stored or deflated. A resource is always stored as it is; the field is
    /// recorded anyway so the row reads the same for both kinds.
    pub storage: StorageKind,
    /// The per-entry encryption word. Zero on everything measured so far.
    #[serde(default)]
    pub encryption: u32,
    /// The digest of the entry's contents, when one was recorded.
    ///
    /// `None` means **no checksum was recorded**, which is what every schema-1
    /// and schema-2 manifest says and what [`Manifest::of`] writes: it is not a
    /// claim that the contents are empty and not a claim that they were
    /// checked. [`schema_2_checksum`], DR-023.
    #[serde(default = "schema_2_checksum", skip_serializing_if = "Option::is_none")]
    pub checksum: Option<Checksum>,
}

/// Everything about an archive that its extracted tree does not carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Schema version of this file.
    pub schema: u32,
    /// The container version the tree was extracted from, and the one it packs
    /// back to.
    ///
    /// Absent in schema 1, which meant [`Version::Rpf7`] because that was the
    /// only container there was.
    #[serde(default = "schema_1_version")]
    pub version: Version,
    /// The compressor its payloads are written with.
    ///
    /// Beside the version rather than derived from it: `docs/rpf-format.md`
    /// reads one version number as two codecs on two platforms, `secondary`.
    /// Absent in schema 1, which meant [`Codec::Deflate`].
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
    /// Derives everything an archive's entry table says that a tree cannot.
    ///
    /// This is where an archive becomes a tree on a filesystem, so it is where
    /// [`name::check_host`] is asked. `extract` derives the manifest before it
    /// creates the target directory, so a refused extraction leaves nothing
    /// behind. DR-013's second amendment.
    ///
    /// It records **no checksum**, because it is not given the payloads to
    /// digest — nothing about an entry's contents is in the entry table.
    /// [`Manifest::of_contents`] is the form that reads them, and a manifest
    /// from here is exactly the schema-3 manifest DR-023's migration rule
    /// describes: one that recorded none.
    ///
    /// # Errors
    ///
    /// As [`Archive::path`], for an entry whose ancestry does not resolve, and
    /// [`Error::BadPath`] for a name that could not be one file on a host.
    pub fn of(archive: &Archive) -> Result<Self> {
        Self::derive(archive, &BTreeMap::new())
    }

    /// [`Manifest::of`], with each entry's contents digested into it.
    ///
    /// Reading every payload is unbounded work in the same way a rebuild or a
    /// `verify` is, so it takes the same [`Watch`] seam, reports one step per
    /// entry and stops when the watcher says to. DR-008.
    ///
    /// What is digested is [`Archive::extract`]'s answer — the entry as the
    /// file it is outside the archive — which is what makes the value survive a
    /// rebuild and match `sha256sum` over the extracted tree. [`Checksum`].
    ///
    /// # Errors
    ///
    /// As [`Manifest::of`], as [`Archive::extract`] for a payload that does not
    /// read back, and [`Error::Cancelled`] when the watcher stops it.
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
            let contents = archive.extract(src, *index)?;
            recorded.insert(spec.path.clone(), Checksum::of(&contents));

            done = done.saturating_add(1);
            bytes = bytes.saturating_add(u64::try_from(contents.len()).unwrap_or(u64::MAX));
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

    /// One derivation, with whatever checksums were recorded for its paths.
    ///
    /// Joined by path rather than by position, because path is what a manifest
    /// keys an entry by everywhere else — [`Manifest::checksums`] and
    /// [`Manifest::specs`] both — and two orders that happen to agree are a
    /// fact nothing checks.
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
                | FileKind::Resource => StorageKind::Stored,
            };
            let encryption = match spec.kind {
                FileKind::Binary { encryption, .. } => encryption,
                FileKind::Resource => 0,
            };
            entries.push(ManifestEntry {
                checksum: recorded.get(&spec.path).copied(),
                path: spec.path,
                class,
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

    /// The checksum recorded for each path, for a caller checking many entries.
    ///
    /// One place decides what a recorded checksum is keyed by (§3), and an
    /// entry that records none is simply absent — which is what makes "not
    /// recorded" and "did not match" two different answers at the other end.
    #[must_use]
    pub fn checksums(&self) -> BTreeMap<&str, Checksum> {
        self.entries
            .iter()
            .filter_map(|entry| Some((entry.path.as_str(), entry.checksum?)))
            .collect()
    }

    /// Refuses any path in the manifest that could not be one file below a
    /// directory on a host filesystem.
    ///
    /// One place rather than two, because the manifest is what `extract` writes
    /// a tree from and what `pack` reads one back through, and the rule is the
    /// same in both directions.
    fn check_host_names(&self) -> Result<()> {
        for directory in &self.directories {
            name::check_host(directory)?;
        }
        for entry in &self.entries {
            name::check_host(&entry.path)?;
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
                    EntryClass::Resource => FileKind::Resource,
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

    /// Renders the manifest.
    ///
    /// # Errors
    ///
    /// Never, in practice; the shape is fixed and every field is serialisable.
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

    /// Reads a manifest.
    ///
    /// A manifest of schema [`OLDEST_SCHEMA`] through [`SCHEMA_VERSION`] is
    /// read; anything else is refused by its schema rather than by whichever
    /// field first failed to parse. A schema-1 manifest names no container
    /// version, and is read as the one it can only have meant — see
    /// [`OLDEST_SCHEMA`].
    ///
    /// A `version` this build has no codec for is refused here too: [`Version`]
    /// is closed over the versions that have one, so naming another is a
    /// manifest this build does not understand rather than one it half-reads.
    ///
    /// A schema-1 or schema-2 manifest records no checksum for any entry, and a
    /// schema-3 one may record none for some of them. Both read, and both mean
    /// the same thing — [`ManifestEntry::checksum`].
    ///
    /// # Errors
    ///
    /// [`Error::BadPath`] when the text is not a manifest, names a schema this
    /// build does not read, or names a path that could not be one file on a
    /// host, and [`Error::NeedsKey`] when it describes an encrypted archive,
    /// which nothing here can rebuild yet.
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
        if !manifest.version.is_open(manifest.encryption) {
            return Err(Error::NeedsKey {
                tag: manifest.encryption,
            });
        }
        // Before `pack` opens anything: `build` plans the tree before it
        // fetches a payload, and this is earlier still, so a read from a name
        // no host should hold does not happen at all.
        manifest.check_host_names()?;
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                    storage: StorageKind::Deflate,
                    encryption: 0,
                    checksum: Some(Checksum::of(b"hello there")),
                },
                ManifestEntry {
                    path: "x64/a.yft".to_owned(),
                    class: EntryClass::Resource,
                    storage: StorageKind::Stored,
                    encryption: 0,
                    checksum: None,
                },
            ],
        };
        let text = manifest.to_json().expect("renders");
        assert!(text.contains("\"version\": \"rpf7\""), "{text}");
        assert!(text.contains("\"codec\": \"deflate\""), "{text}");
        // Lower-case hexadecimal, which is what `sha256sum` prints, so the
        // value in a diff is one a reader can reproduce from the file itself.
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
        // Schema 2's every entry, and any schema-3 entry written by
        // `Manifest::of`. The missing field is a stated migration rule, not the
        // `Default` of an unrelated type: DR-023, following DR-018.
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
        // Schema 1 named no version, because `RPF7` was the only one there was.
        // Refusing it would break every tree already on disk and recover no
        // fact. DR-018.
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
        // `Version` is closed over the versions that have a codec, so a tree
        // from another one cannot be packed as this one by accident. DR-012.
        let text = r#"{"schema":2,"version":"rpf2","codec":"deflate",
                       "encryption":1313165391,"directories":[],"entries":[]}"#;
        assert!(matches!(
            Manifest::from_json(text),
            Err(Error::BadPath { .. })
        ));
    }

    #[test]
    fn an_encrypted_manifest_is_refused_rather_than_half_understood() {
        let text = r#"{"schema":1,"encryption":268435449,"directories":[],"entries":[]}"#;
        assert!(matches!(
            Manifest::from_json(text),
            Err(Error::NeedsKey { tag: 268_435_449 })
        ));
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
