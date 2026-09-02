//! The committed oracle fixtures: rebuilt and compared, never trusted.
//!
//! `tools/oracle` links the reference implementation, is excluded from this
//! workspace and is never built here (DR-007). What is checked is its output.
//! Two legs: one needs no corpus and rebuilds each fixture from its own
//! content, so continuous integration runs it; one needs `RPF_CORPUS` and
//! rebuilds each fixture from the archive it describes.
//!
//! Unencrypted archives only. The oracle wants a pre-dumped key blob and
//! DR-006 refuses to hold one, so an encrypted archive gets no fixture and the
//! corpus-gated leg says which ones and why.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; a panic is the reporting mechanism. docs/conventions.md §15"
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::{Read, Seek},
    path::{Path, PathBuf},
};

use rpf_core::{Archive, EntryKind, Unlock, format::Version};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const FIXTURE_DIR: &str = "../../fixtures";
const TOOL: &str = "tools/oracle";

/// One oracle fixture, in the field order its generator emits.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Fixture {
    generator: Generator,
    source: Source,
    archives: Vec<ArchiveDump>,
    files: Vec<FileDump>,
}

/// Provenance rather than an observation of the archive: carried across a
/// rebuild verbatim, because nothing in the corpus can produce it.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Generator {
    tool: String,
    reference_implementation: String,
    extraction_semantics: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Source {
    name: String,
    /// Where the archive sits under `RPF_CORPUS`, `/`-separated.
    path: String,
    len: u64,
    sha256: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ArchiveDump {
    path: String,
    version: String,
    encryption: String,
    entry_count: usize,
    entries: Vec<EntryDump>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
struct EntryDump {
    name: String,
    kind: String,
    #[serde(flatten)]
    fields: BTreeMap<String, u64>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FileDump {
    path: String,
    len: u64,
    sha256: String,
}

/// The exact bytes a fixture file holds for this document.
fn rendered(fixture: &Fixture) -> String {
    let mut text = serde_json::to_string_pretty(fixture).expect("a fixture serialises");
    text.push('\n');
    text
}

/// Where two renderings first part company. A fixture runs to thousands of
/// lines, and an assertion over the whole document prints all of them. The
/// split keeps the line terminator, so a stray `\r` or a missing final newline
/// is a difference rather than something the comparison discards.
fn first_difference(ours: &str, theirs: &str) -> Option<String> {
    let (mine, yours) = (ours.split_inclusive('\n'), theirs.split_inclusive('\n'));
    for (number, (ours, theirs)) in mine.zip(yours).enumerate() {
        if ours != theirs {
            return Some(format!(
                "line {}: the fixture has {}, this reading has {}",
                number + 1,
                theirs.escape_debug(),
                ours.escape_debug(),
            ));
        }
    }
    let ours = ours.split_inclusive('\n').count();
    let theirs = theirs.split_inclusive('\n').count();
    (ours != theirs).then(|| format!("the fixture is {theirs} lines, this reading {ours}"))
}

fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    hex::encode(digest.finalize())
}

/// An archive's length and checksum, drained rather than held: the largest one
/// here is 505 MB.
fn measured(path: &Path) -> (u64, String) {
    let mut file = fs::File::open(path).expect("archive opens");
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 16];
    let mut len = 0_u64;
    loop {
        let read = file.read(&mut buffer).expect("archive reads");
        if read == 0 {
            return (len, hex::encode(digest.finalize()));
        }
        digest.update(buffer.get(..read).expect("read fits the buffer"));
        len += u64::try_from(read).expect("length fits");
    }
}

/// Every tracked oracle fixture: its file name, the bytes on disk, the document.
fn committed() -> Vec<(String, String, Fixture)> {
    let mut out = Vec::new();
    let mut names: Vec<PathBuf> = fs::read_dir(FIXTURE_DIR)
        .expect("fixtures/ is tracked")
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    names.sort();

    for path in names {
        let raw = fs::read_to_string(&path).expect("fixture readable");
        let value: Value = serde_json::from_str(&raw).expect("fixture parses");
        let tool = value
            .get("generator")
            .and_then(|generator| generator.get("tool"))
            .and_then(Value::as_str);
        if tool != Some(TOOL) {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("fixture has a name")
            .to_owned();
        let fixture: Fixture = serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("{name} is not the document the oracle emits: {e}"));
        out.push((name, raw, fixture));
    }
    out
}

/// Reports a skip; `RPF_REQUIRE_CORPUS` turns a skip into a failure.
fn skip(test: &str, reason: &str) {
    assert!(
        env::var_os("RPF_REQUIRE_CORPUS").is_none(),
        "RPF_REQUIRE_CORPUS is set, but {test} would have skipped: {reason}",
    );
    println!("SKIP {test}: {reason}");
}

fn corpus_root(test: &str) -> Option<PathBuf> {
    let Some(root) = env::var_os("RPF_CORPUS") else {
        skip(test, "RPF_CORPUS is not set, so no archive can be located");
        return None;
    };
    Some(PathBuf::from(root))
}

/// Whether a name is a nested archive; `name` is already lower-cased.
#[allow(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "name is lower-cased"
)]
fn is_nested_archive(name: &str) -> bool {
    name.ends_with(".rpf")
}

fn version_name(version: Version) -> String {
    match version {
        Version::Rpf7 => "V7".to_owned(),
    }
}

/// R0.3 covers unencrypted archives only, so this is the only tag a rebuild
/// can meet.
fn encryption_name(version: Version, tag: u32) -> String {
    assert!(
        version.is_open(tag),
        "an oracle fixture describes an encrypted archive (tag {tag:#010x})",
    );
    "Open".to_owned()
}

fn entry_dump(archive: &Archive, index: u32) -> EntryDump {
    let entry = archive.entry(index).expect("index came from this archive");
    let mut fields = BTreeMap::new();
    let kind = match entry.kind {
        EntryKind::Directory {
            first_child,
            child_count,
        } => {
            fields.insert("entries_index".to_owned(), u64::from(first_child));
            fields.insert("entries_count".to_owned(), u64::from(child_count));
            "directory"
        }
        EntryKind::Binary {
            block,
            compressed_len,
            uncompressed_len,
            encryption,
        } => {
            fields.insert("file_offset".to_owned(), u64::from(block));
            fields.insert("file_size".to_owned(), u64::from(compressed_len));
            fields.insert("uncompressed_size".to_owned(), u64::from(uncompressed_len));
            fields.insert("is_encrypted".to_owned(), u64::from(encryption != 0));
            "binary"
        }
        EntryKind::Resource {
            block,
            compressed_len,
            system_flags,
            graphics_flags,
        } => {
            fields.insert("file_offset".to_owned(), u64::from(block));
            fields.insert("file_size".to_owned(), u64::from(compressed_len));
            fields.insert("system_flags".to_owned(), u64::from(system_flags));
            fields.insert("graphics_flags".to_owned(), u64::from(graphics_flags));
            // `EntryKind::Resource` does not model the encryption field the
            // generator reads, so a corpus resource carrying 1 differs here.
            fields.insert("is_encrypted".to_owned(), 0);
            "resource"
        }
    };
    EntryDump {
        name: archive
            .name(index)
            .expect("name resolved at parse")
            .to_owned(),
        kind: kind.to_owned(),
        fields,
    }
}

/// Walks this archive and every archive nested in it, in the order the oracle
/// emits them. `prefix` carries the nested-archive chain only: the oracle skips
/// directory records rather than descending them, so a leaf path has no
/// directory component.
fn dump<R: Read + Seek>(
    src: &mut R,
    archive: &Archive,
    archive_path: &str,
    prefix: &str,
    archives: &mut Vec<ArchiveDump>,
    files: &mut Vec<FileDump>,
) {
    let count = u32::try_from(archive.entries().len()).expect("entry count fits");
    archives.push(ArchiveDump {
        path: archive_path.to_owned(),
        version: version_name(archive.version()),
        encryption: encryption_name(archive.version(), archive.encryption()),
        entry_count: archive.entries().len(),
        entries: (0..count).map(|i| entry_dump(archive, i)).collect(),
    });

    for index in 0..count {
        let entry = archive.entry(index).expect("index in range");
        if entry.is_directory() {
            continue;
        }
        let name = archive
            .name(index)
            .expect("name resolved at parse")
            .to_lowercase();
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };

        if is_nested_archive(&name) {
            let nested = archive
                .open_nested(src, index)
                .expect("nested archive parses");
            let nested_path = format!("{archive_path}/{name}");
            dump(src, &nested, &nested_path, &path, archives, files);
        } else {
            let bytes = archive.extract(src, index).expect("entry extracts");
            files.push(FileDump {
                path,
                len: u64::try_from(bytes.len()).expect("length fits"),
                sha256: sha256(&bytes),
            });
        }
    }
}

/// The fixture this archive would produce now, with the generator block carried
/// over: it records which implementation was read, which is provenance and not
/// something the archive can be asked for.
fn rebuild(path: &Path, name: &str, relative: &str, generator: Generator) -> Fixture {
    let (len, sha256) = measured(path);
    let mut file = fs::File::open(path).expect("archive opens");
    let archive = Archive::open(&mut file, &Unlock::unkeyed()).expect("archive parses");

    let mut archives = Vec::new();
    let mut files = Vec::new();
    dump(&mut file, &archive, name, "", &mut archives, &mut files);
    files.sort_by(|a, b| a.path.cmp(&b.path));

    Fixture {
        generator,
        source: Source {
            name: name.to_owned(),
            path: relative.to_owned(),
            len,
            sha256,
        },
        archives,
        files,
    }
}

/// Every `.rpf` under a directory, as `/`-separated paths relative to it. The
/// extension is matched case-insensitively, as `is_nested_archive` does: a
/// `DLC.RPF` skipped here escapes the completeness check silently.
fn archives_under(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, prefix: &str, seen: &mut BTreeSet<PathBuf>, out: &mut Vec<String>) {
        // `is_dir` follows symlinks, so a cycle in the corpus would recurse
        // without bound; a directory is descended once, by its real path.
        if !seen.insert(fs::canonicalize(dir).unwrap_or_else(|_| dir.to_owned())) {
            return;
        }
        let mut entries: Vec<PathBuf> = fs::read_dir(dir)
            .expect("corpus directory readable")
            .map(|entry| entry.expect("directory entry").path())
            .collect();
        entries.sort();
        for path in entries {
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let relative = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            if path.is_dir() {
                walk(&path, &relative, seen, out);
            } else if path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("rpf"))
            {
                out.push(relative);
            }
        }
    }

    let mut out = Vec::new();
    walk(root, "", &mut BTreeSet::new(), &mut out);
    out
}

/// The ungated leg, and the one continuous integration runs: every committed
/// fixture is exactly the document its own content re-emits. A hand edit, a
/// field the generator no longer writes, or an ordering that is not the
/// generator's fails here without an archive in reach.
#[test]
fn every_oracle_fixture_is_the_document_its_generator_emits() {
    let fixtures = committed();
    assert!(!fixtures.is_empty(), "no oracle fixture is committed");

    for (name, raw, fixture) in &fixtures {
        if let Some(where_it_differs) = first_difference(&rendered(fixture), raw) {
            panic!("{name} is not the document its generator emits: {where_it_differs}");
        }
        assert_eq!(fixture.generator.tool, TOOL, "{name}: generator");

        let source = &fixture.source;
        assert!(!source.path.is_empty(), "{name}: no archive path");
        assert!(
            !source.path.starts_with('/') && !source.path.contains('\\'),
            "{name}: {} is not a corpus-relative path",
            source.path,
        );
        assert!(
            source.path.ends_with(&format!("/{}", source.name)) || source.path == source.name,
            "{name}: {} does not end in {}",
            source.path,
            source.name,
        );
        assert_eq!(source.sha256.len(), 64, "{name}: source checksum");

        let mut paths: Vec<&str> = Vec::new();
        for archive in &fixture.archives {
            assert_eq!(
                archive.entry_count,
                archive.entries.len(),
                "{name}: {} declares {} entries",
                archive.path,
                archive.entry_count,
            );
            assert_eq!(archive.encryption, "Open", "{name}: {}", archive.path);
            for entry in &archive.entries {
                // Load-bearing: `EntryDump` cannot carry `deny_unknown_fields`
                // beside `#[serde(flatten)]`, so a stray field lands in
                // `fields` and this is the only thing that sees it.
                let expected: &[&str] = match entry.kind.as_str() {
                    "directory" => &["entries_count", "entries_index"],
                    "binary" => &[
                        "file_offset",
                        "file_size",
                        "is_encrypted",
                        "uncompressed_size",
                    ],
                    "resource" => &[
                        "file_offset",
                        "file_size",
                        "graphics_flags",
                        "is_encrypted",
                        "system_flags",
                    ],
                    other => panic!("{name}: unknown entry kind {other}"),
                };
                let held: Vec<&str> = entry.fields.keys().map(String::as_str).collect();
                assert_eq!(held, expected, "{name}: {} fields", entry.name);
            }
            paths.push(&archive.path);
        }
        assert_eq!(
            paths.first().copied(),
            Some(source.name.as_str()),
            "{name}: the first archive is the source",
        );
        let mut sorted = paths.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), paths.len(), "{name}: an archive path repeats");

        let mut previous: Option<&str> = None;
        for file in &fixture.files {
            assert_eq!(file.sha256.len(), 64, "{name}: {} checksum", file.path);
            assert!(
                previous < Some(file.path.as_str()),
                "{name}: {} is out of order",
                file.path,
            );
            previous = Some(&file.path);
        }
    }
}

/// The corpus-gated leg: every fixture is rebuilt from the archive it names and
/// compared byte for byte. This is what makes a fixture a description of an
/// archive rather than a file that once was one.
#[test]
#[cfg_attr(
    no_corpus,
    ignore = "no RPF_CORPUS: the archives a fixture describes are not tracked"
)]
fn every_oracle_fixture_rebuilds_from_the_archive_it_describes() {
    const TEST: &str = "every_oracle_fixture_rebuilds_from_the_archive_it_describes";
    let Some(root) = corpus_root(TEST) else {
        return;
    };

    let mut rebuilt = 0_u32;
    for (name, raw, fixture) in &committed() {
        let path = root.join(&fixture.source.path);
        if !path.is_file() {
            skip(TEST, &format!("{name}: {} is not a file", path.display()));
            continue;
        }
        let now = rebuild(
            &path,
            &fixture.source.name,
            &fixture.source.path,
            fixture.generator.clone(),
        );
        assert_eq!(
            (now.source.len, now.source.sha256.as_str()),
            (fixture.source.len, fixture.source.sha256.as_str()),
            "{} is not the archive {name} describes",
            path.display(),
        );
        if let Some(where_it_differs) = first_difference(&rendered(&now), raw) {
            panic!("{name} no longer describes its archive: {where_it_differs}");
        }
        rebuilt += 1;
    }
    assert!(
        rebuilt > 0,
        "{TEST}: {} names no archive any fixture describes, \
         so every fixture skipped and nothing was compared",
        root.display(),
    );
    println!("{TEST}: {rebuilt} fixture(s) rebuilt and compared");
}

/// The refusal, stated rather than implied: an archive the oracle cannot cover
/// is one no key material can be committed for (DR-006), and every other one
/// has a fixture.
#[test]
#[cfg_attr(
    no_corpus,
    ignore = "no RPF_CORPUS: the archives a fixture describes are not tracked"
)]
fn every_unencrypted_corpus_archive_has_an_oracle_fixture() {
    const TEST: &str = "every_unencrypted_corpus_archive_has_an_oracle_fixture";
    let Some(root) = corpus_root(TEST) else {
        return;
    };

    let described: Vec<String> = committed()
        .into_iter()
        .map(|(_, _, fixture)| fixture.source.path)
        .collect();

    let (mut examined, mut refused) = (0_u32, 0_u32);
    for relative in archives_under(&root) {
        examined += 1;
        let path = root.join(&relative);
        let mut file = fs::File::open(&path).expect("archive opens");
        let has_fixture = described.contains(&relative);
        match Archive::open(&mut file, &Unlock::unkeyed()) {
            Ok(_) => assert!(
                has_fixture,
                "{relative} is unencrypted and has no oracle fixture",
            ),
            Err(rpf_core::Error::NeedsKey { tag }) => {
                assert!(
                    !has_fixture,
                    "{relative} is encrypted (tag {tag:#010x}) and cannot have been dumped",
                );
                println!(
                    "NO ORACLE {relative}: encrypted (tag {tag:#010x}); \
                     the generator wants a pre-dumped key blob and DR-006 refuses to hold one",
                );
                refused += 1;
            }
            Err(other) => panic!("{relative}: {other}"),
        }
    }
    assert!(
        examined > 0,
        "{TEST}: no archive at all under {}, so nothing was checked for a fixture",
        root.display(),
    );
    println!(
        "{TEST}: {examined} archive(s) examined, \
         {refused} of them encrypted and deliberately without a fixture",
    );
}
