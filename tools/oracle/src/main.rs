//! Oracle generator. Runs the reference implementation over an archive and
//! writes down what it saw, so that our own reader can be checked against
//! something that is not us.
//!
//! This crate is deliberately outside the workspace and is never built by
//! continuous integration. DR-007: the reference implementation is an oracle,
//! not a dependency. What gets committed is this program's output.
//!
//! Usage: `cargo run --release -- <archive.rpf> > ../../fixtures/<name>.json`

use std::{collections::BTreeMap, env, fs, path::Path};

use anyhow::{Context, Result, bail};
use rpf_archive::{RpfArchive, RpfEntry, RpfEntryKind, RpfFile};
use serde::Serialize;
use sha2::{Digest, Sha256};

fn sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

#[derive(Serialize)]
struct Fixture {
    generator: Generator,
    source: Source,
    /// Entry table of the archive and of every archive nested inside it.
    archives: Vec<ArchiveDump>,
    /// Every leaf file, addressed through the nesting, with the checksum of the
    /// bytes the reference implementation extracts for it.
    files: Vec<FileDump>,
}

#[derive(Serialize)]
struct Generator {
    tool: &'static str,
    reference_implementation: &'static str,
    /// What `files[].sha256` is taken over, since it is not the same rule for
    /// both entry kinds and our reader has to match it exactly.
    extraction_semantics: &'static str,
}

#[derive(Serialize)]
struct Source {
    name: String,
    len: u64,
    sha256: String,
}

#[derive(Serialize)]
struct ArchiveDump {
    path: String,
    version: String,
    encryption: String,
    entry_count: usize,
    entries: Vec<EntryDump>,
}

#[derive(Serialize)]
struct EntryDump {
    name: String,
    kind: &'static str,
    #[serde(flatten)]
    fields: BTreeMap<&'static str, u64>,
}

#[derive(Serialize)]
struct FileDump {
    path: String,
    len: usize,
    sha256: String,
}

fn dump_entry(entry: &RpfEntry) -> EntryDump {
    let mut fields = BTreeMap::new();
    let kind = match &entry.kind {
        RpfEntryKind::Directory { entries_index, entries_count } => {
            fields.insert("entries_index", u64::from(*entries_index));
            fields.insert("entries_count", u64::from(*entries_count));
            "directory"
        }
        RpfEntryKind::BinaryFile {
            file_offset, file_size, uncompressed_size, is_encrypted,
        } => {
            fields.insert("file_offset", u64::from(*file_offset));
            fields.insert("file_size", u64::from(*file_size));
            fields.insert("uncompressed_size", u64::from(*uncompressed_size));
            fields.insert("is_encrypted", u64::from(*is_encrypted));
            "binary"
        }
        RpfEntryKind::ResourceFile {
            file_offset, file_size, system_flags, graphics_flags, is_encrypted,
        } => {
            fields.insert("file_offset", u64::from(*file_offset));
            fields.insert("file_size", u64::from(*file_size));
            fields.insert("system_flags", u64::from(*system_flags));
            fields.insert("graphics_flags", u64::from(*graphics_flags));
            fields.insert("is_encrypted", u64::from(*is_encrypted));
            "resource"
        }
    };
    EntryDump { name: entry.name.clone(), kind, fields }
}

/// Record this archive's entry table, then descend into any nested archive and
/// record that too. Paths address through the nesting in one string, which is
/// the shape R6.4 wants.
fn dump_archives(
    archive: &RpfArchive,
    data: &[u8],
    path: &str,
    out: &mut Vec<ArchiveDump>,
) -> Result<()> {
    out.push(ArchiveDump {
        path: path.to_owned(),
        version: format!("{:?}", archive.version),
        encryption: format!("{:?}", archive.encryption),
        entry_count: archive.entries.len(),
        entries: archive.entries.iter().map(dump_entry).collect(),
    });

    for entry in &archive.entries {
        if !entry.is_file() || !entry.name_lower.ends_with(".rpf") {
            continue;
        }
        let nested_bytes = archive.extract_entry(data, entry, None)?;
        let nested = RpfArchive::parse(&nested_bytes, &entry.name_lower, None)?;
        let nested_path = format!("{path}/{}", entry.name_lower);
        dump_archives(&nested, &nested_bytes, &nested_path, out)?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let Some(arg) = env::args().nth(1) else {
        bail!("usage: oracle <archive.rpf>");
    };
    let path = Path::new(&arg);

    let raw = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .context("archive path has no file name")?
        .to_owned();

    // No keys. DR-006 keeps key material out of this repository, and the
    // reference implementation wants a pre-dumped blob we decline to hold. The
    // oracle therefore covers unencrypted archives only, which DR-007 records.
    let file = RpfFile::open(path, None)?;

    let mut archives = Vec::new();
    dump_archives(&file.archive, file.raw_data(), &name, &mut archives)?;

    let mut files = Vec::new();
    file.walk(None, &mut |p, bytes| {
        files.push(FileDump { path: p.to_owned(), len: bytes.len(), sha256: sha256(&bytes) });
    })?;
    files.sort_by(|a, b| a.path.cmp(&b.path));

    let fixture = Fixture {
        generator: Generator {
            tool: "tools/oracle",
            reference_implementation: concat!("rpf-archive ", "0.7.1"),
            extraction_semantics: "binary entries: inflated contents. \
                resource entries: 16-byte RSC7 header followed by the still-deflated body, \
                which is the file as it exists outside the archive. \
                Nested archives are descended into, not emitted.",
        },
        source: Source { name, len: raw.len() as u64, sha256: sha256(&raw) },
        archives,
        files,
    };

    println!("{}", serde_json::to_string_pretty(&fixture)?);
    Ok(())
}
