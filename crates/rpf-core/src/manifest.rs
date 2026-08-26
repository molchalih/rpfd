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
//! - **empty directories**, which a tree of files loses.
//!
//! It is JSON so that it can be read in a diff and edited by hand, and its
//! field names are stable.

use serde::{Deserialize, Serialize};

use crate::{
    archive::Archive,
    build::{FileKind, FileSpec, Storage, directories_of, specs_of},
    entry::EntryKind,
    error::{Error, Result},
    format::ENCRYPTION_OPEN,
};

/// What the manifest is called inside an extracted tree.
pub const MANIFEST_NAME: &str = ".rpf-manifest.json";

/// The schema version. Bumped when a field changes meaning, never for an
/// addition a reader can ignore.
pub const SCHEMA_VERSION: u32 = 1;

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
}

/// Everything about an archive that its extracted tree does not carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Schema version of this file.
    pub schema: u32,
    /// The archive's encryption tag.
    pub encryption: u32,
    /// Every directory, root excluded. Present so an empty one survives.
    pub directories: Vec<String>,
    /// Every file, in entry-table order.
    pub entries: Vec<ManifestEntry>,
}

impl Manifest {
    /// Derives the manifest of an archive as it stands.
    ///
    /// # Errors
    ///
    /// As [`Archive::path`], for an entry whose ancestry does not resolve.
    pub fn of(archive: &Archive) -> Result<Self> {
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
                path: spec.path,
                class,
                storage,
                encryption,
            });
        }

        Ok(Self {
            schema: SCHEMA_VERSION,
            encryption: archive.encryption(),
            directories: directories_of(archive)?,
            entries,
        })
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
    /// # Errors
    ///
    /// [`Error::BadPath`] when the text is not a manifest, and
    /// [`Error::NeedsKey`] when it describes an encrypted archive, which
    /// nothing here can rebuild yet.
    pub fn from_json(text: &str) -> Result<Self> {
        let manifest: Self = serde_json::from_str(text).map_err(|_| Error::BadPath {
            path: MANIFEST_NAME.to_owned(),
            reason: "is not a manifest this version understands",
        })?;
        if manifest.schema != SCHEMA_VERSION {
            return Err(Error::BadPath {
                path: MANIFEST_NAME.to_owned(),
                reason: "was written by a different schema version",
            });
        }
        if manifest.encryption != ENCRYPTION_OPEN {
            return Err(Error::NeedsKey {
                tag: manifest.encryption,
            });
        }
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
            encryption: ENCRYPTION_OPEN,
            directories: vec!["data".to_owned(), "x64/empty".to_owned()],
            entries: vec![
                ManifestEntry {
                    path: "data/vehicles.meta".to_owned(),
                    class: EntryClass::Binary,
                    storage: StorageKind::Deflate,
                    encryption: 0,
                },
                ManifestEntry {
                    path: "x64/a.yft".to_owned(),
                    class: EntryClass::Resource,
                    storage: StorageKind::Stored,
                    encryption: 0,
                },
            ],
        };
        let text = manifest.to_json().expect("renders");
        assert_eq!(Manifest::from_json(&text).expect("parses"), manifest);
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
    fn a_future_schema_is_refused() {
        let text = r#"{"schema":99,"encryption":1313165391,"directories":[],"entries":[]}"#;
        assert!(matches!(
            Manifest::from_json(text),
            Err(Error::BadPath { .. })
        ));
    }
}
