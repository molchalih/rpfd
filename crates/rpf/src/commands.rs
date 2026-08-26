//! The commands themselves.
//!
//! Every one of them is a thin call into `rpf-core`. Nothing here knows the
//! byte layout of an archive; if it did, the editor client could not do the
//! same thing. `docs/conventions.md` §1.

use std::{
    fs,
    io::{Read, Seek, Write},
    path::Path,
};

use rpf_core::{Archive, EntryKind};
use serde_json::{Value, json};

use crate::{
    exit::{Failure, Result},
    install,
};

/// Opens an archive file and parses its table of contents.
pub fn open(path: &Path) -> Result<(fs::File, Archive)> {
    let mut file = fs::File::open(path).map_err(|source| Failure::Io {
        path: path.display().to_string(),
        source,
    })?;
    let archive = Archive::open(&mut file)?;
    Ok((file, archive))
}

/// `info` — the header, and what the entries add up to.
pub fn info(path: &Path, json_out: bool) -> Result<()> {
    let (mut file, archive) = open(path)?;
    let len = archive.len_bytes();

    let mut directories = 0_u32;
    let mut binaries = 0_u32;
    let mut resources = 0_u32;
    let mut referenced = rpf_core::format::HEADER_LEN;
    for index in 0..count(&archive) {
        match archive.entry(index)?.kind {
            EntryKind::Directory { .. } => directories = directories.saturating_add(1),
            EntryKind::Binary {
                compressed_len,
                uncompressed_len,
                ..
            } => {
                binaries = binaries.saturating_add(1);
                referenced = referenced.saturating_add(u64::from(if compressed_len == 0 {
                    uncompressed_len
                } else {
                    compressed_len
                }));
            }
            EntryKind::Resource { compressed_len, .. } => {
                resources = resources.saturating_add(1);
                referenced = referenced.saturating_add(u64::from(compressed_len));
            }
        }
    }
    let nested = count_nested(&mut file, &archive)?;
    let slack = len.saturating_sub(referenced);

    if json_out {
        emit(&json!({
            "path": path.display().to_string(),
            "len": len,
            "encryption": encryption_name(archive.encryption()),
            "entries": count(&archive),
            "directories": directories,
            "binary_files": binaries,
            "resource_files": resources,
            "nested_archives": nested,
            "unreferenced_bytes": slack,
        }));
        Ok(())
    } else {
        println!("path         {}", path.display());
        println!("length       {len}");
        println!("encryption   {}", encryption_name(archive.encryption()));
        println!("entries      {}", count(&archive));
        println!("  directories {directories}");
        println!("  binary      {binaries}");
        println!("  resource    {resources}");
        println!("nested       {nested}");
        println!("unreferenced {slack}");
        Ok(())
    }
}

/// `ls` — what is at a path.
pub fn ls(path: &Path, inside: &str, recursive: bool, json_out: bool) -> Result<()> {
    let (mut file, archive) = open(path)?;
    let (holder, at) = archive.locate(&mut file, inside)?;

    let mut rows = Vec::new();
    list_into(&mut file, &holder, at, inside, recursive, &mut rows)?;

    if json_out {
        emit(&Value::Array(rows));
        Ok(())
    } else {
        for row in &rows {
            let kind = row["kind"].as_str().unwrap_or("?");
            let len = row["len"].as_u64().unwrap_or_default();
            let name = row["path"].as_str().unwrap_or("?");
            println!("{kind:<9} {len:>12}  {name}");
        }
        Ok(())
    }
}

/// `cat` — one entry's contents on standard output.
pub fn cat(path: &Path, inside: &str) -> Result<()> {
    let (mut file, archive) = open(path)?;
    let (holder, index) = archive.locate(&mut file, inside)?;
    if holder.entry(index)?.is_directory() {
        return Err(Failure::Refused {
            reason: format!("{inside} is a directory"),
        });
    }
    // `extract`, not `read`: this has to be the same form `put` accepts, or
    // `rpf cat … > f && rpf put … f` would fail on every resource. For a binary
    // entry the two are identical; for a resource `extract` keeps the RSC7
    // header, which is what the file is outside the archive.
    let bytes = holder.extract(&mut file, index)?;
    std::io::stdout()
        .write_all(&bytes)
        .map_err(|source| Failure::Io {
            path: "<stdout>".to_owned(),
            source,
        })
}

/// `put` — replace one entry and rebuild, cascading through nesting.
///
/// Writes to a temporary file beside the archive and renames it into place, so
/// an interrupted rebuild cannot leave a corrupt archive where a good one was.
/// R4.2.
pub fn put(path: &Path, inside: &str, from: &Path, force: bool) -> Result<()> {
    refuse_game_install(path, force)?;

    let contents = fs::read(from).map_err(|source| Failure::Io {
        path: from.display().to_string(),
        source,
    })?;

    let (mut file, archive) = open(path)?;
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let mut scratch = tempfile::NamedTempFile::new_in(directory).map_err(|source| Failure::Io {
        path: directory.display().to_string(),
        source,
    })?;

    rpf_core::replace_at(&mut file, &archive, inside, contents, scratch.as_file_mut())?;
    persist(scratch, path)
}

/// `extract` — write every entry to a tree, with the manifest beside it.
///
/// Nested archives come out as the `.rpf` files they are, byte for byte, rather
/// than being unpacked in place. Packing puts them back untouched, which is
/// what passthrough means. Editing inside one is `put`'s job, and it cascades.
pub fn extract(path: &Path, into: &Path, json_out: bool) -> Result<()> {
    let (mut file, archive) = open(path)?;
    let manifest = rpf_core::Manifest::of(&archive)?;

    create_dir(into)?;
    for directory in &manifest.directories {
        create_dir(&into.join(directory))?;
    }

    let specs = rpf_core::specs_of(&archive)?;
    for (spec, index) in &specs {
        let target = into.join(&spec.path);
        if let Some(parent) = target.parent() {
            create_dir(parent)?;
        }
        let bytes = archive.extract(&mut file, *index)?;
        write_file(&target, &bytes)?;
    }

    let manifest_path = into.join(rpf_core::MANIFEST_NAME);
    write_file(&manifest_path, manifest.to_json()?.as_bytes())?;

    if json_out {
        emit(&json!({
            "archive": path.display().to_string(),
            "into": into.display().to_string(),
            "files": specs.len(),
            "directories": manifest.directories.len(),
            "manifest": manifest_path.display().to_string(),
        }));
    } else {
        println!(
            "{} files and {} directories into {}",
            specs.len(),
            manifest.directories.len(),
            into.display(),
        );
    }
    Ok(())
}

/// `pack` — build an archive from a tree and its manifest.
pub fn pack(from: &Path, archive_path: &Path, force: bool, json_out: bool) -> Result<()> {
    refuse_game_install(archive_path, force)?;

    let manifest_path = from.join(rpf_core::MANIFEST_NAME);
    let text = fs::read_to_string(&manifest_path).map_err(|source| Failure::Io {
        path: manifest_path.display().to_string(),
        source,
    })?;
    let manifest = rpf_core::Manifest::from_json(&text)?;
    let specs = manifest.specs();

    let directory = archive_path.parent().unwrap_or_else(|| Path::new("."));
    let mut scratch = tempfile::NamedTempFile::new_in(directory).map_err(|source| Failure::Io {
        path: directory.display().to_string(),
        source,
    })?;

    // A missing file is reported as itself rather than as a build failure: the
    // tree is the caller's, and naming the path is the actionable part.
    let mut missing = None;
    let report = rpf_core::build(
        scratch.as_file_mut(),
        &specs,
        &manifest.directories,
        |wanted| {
            let source_path = from.join(wanted);
            match fs::read(&source_path) {
                Ok(bytes) => Ok(bytes),
                Err(error) => {
                    missing = Some((source_path, error));
                    Err(rpf_core::Error::BadPath {
                        path: wanted.to_owned(),
                        reason: "is in the manifest but not in the tree",
                    })
                }
            }
        },
    );
    if let Some((path, source)) = missing {
        return Err(Failure::Io {
            path: path.display().to_string(),
            source,
        });
    }
    let report = report?;

    persist(scratch, archive_path)?;

    if json_out {
        emit(&json!({
            "archive": archive_path.display().to_string(),
            "entries": report.entry_count,
            "len": report.len,
        }));
    } else {
        println!("{} entries, {} bytes", report.entry_count, report.len);
    }
    Ok(())
}

/// Creates a directory and everything above it.
fn create_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|source| Failure::Io {
        path: path.display().to_string(),
        source,
    })
}

/// Writes a file, reporting the path rather than the syscall.
fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).map_err(|source| Failure::Io {
        path: path.display().to_string(),
        source,
    })
}

/// Refuses to write into a detected game installation.
fn refuse_game_install(path: &Path, force: bool) -> Result<()> {
    if !force && let Some(root) = install::detect(path) {
        return Err(Failure::GameInstall { root });
    }
    Ok(())
}

/// Moves a freshly written archive into place, keeping any permissions the
/// file it replaces already had.
pub fn persist(scratch: tempfile::NamedTempFile, path: &Path) -> Result<()> {
    let mut scratch = scratch;
    scratch
        .as_file_mut()
        .flush()
        .map_err(|source| Failure::Io {
            path: "<temporary file>".to_owned(),
            source,
        })?;

    // A temporary file is created 0600. Silently tightening a file we replaced
    // would be a surprise the caller never asked for.
    if let Ok(existing) = fs::metadata(path) {
        fs::set_permissions(scratch.path(), existing.permissions()).map_err(|source| {
            Failure::Io {
                path: scratch.path().display().to_string(),
                source,
            }
        })?;
    }

    scratch.persist(path).map_err(|error| Failure::Io {
        path: path.display().to_string(),
        source: error.error,
    })?;
    Ok(())
}

/// `verify` — read every entry back and check it against what the archive says.
pub fn verify(path: &Path, json_out: bool) -> Result<()> {
    let (mut file, archive) = open(path)?;
    let mut checked = 0_u32;
    let mut problems = Vec::new();
    verify_into(&mut file, &archive, "", &mut checked, &mut problems)?;

    if json_out {
        emit(&json!({
            "path": path.display().to_string(),
            "entries_checked": checked,
            "problems": problems,
        }));
    } else if problems.is_empty() {
        println!("{checked} entries verified");
    } else {
        for problem in &problems {
            println!("{problem}");
        }
        println!("{} of {checked} entries failed", problems.len());
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(Failure::Container(rpf_core::Error::LengthMismatch {
            entry: 0,
            expected: u64::from(checked),
            actual: u64::from(checked)
                .saturating_sub(u64::try_from(problems.len()).unwrap_or(u64::MAX)),
        }))
    }
}

/// Entries in an archive, as a `u32`.
fn count(archive: &Archive) -> u32 {
    u32::try_from(archive.entries().len()).unwrap_or(u32::MAX)
}

/// A readable name for an encryption tag.
fn encryption_name(tag: u32) -> String {
    if tag == rpf_core::format::ENCRYPTION_OPEN {
        "OPEN".to_owned()
    } else {
        format!("{tag:#010x}")
    }
}

/// Writes a value as one line of JSON.
fn emit(value: &Value) {
    let text = serde_json::to_string_pretty(value).unwrap_or_default();
    println!("{text}");
}

/// Counts archives nested directly inside this one.
fn count_nested<R: Read + Seek>(src: &mut R, archive: &Archive) -> Result<u32> {
    let mut nested = 0_u32;
    for index in 0..count(archive) {
        if archive.entry(index)?.is_directory() {
            continue;
        }
        if archive.open_nested(src, index).is_ok() {
            nested = nested.saturating_add(1);
        }
    }
    Ok(nested)
}

/// Collects the rows `ls` prints.
pub fn list_into<R: Read + Seek>(
    src: &mut R,
    archive: &Archive,
    at: u32,
    prefix: &str,
    recursive: bool,
    rows: &mut Vec<Value>,
) -> Result<()> {
    // Not a directory? If it is an archive, listing it means listing what is
    // inside it — a nested archive is a directory as far as a path is
    // concerned. Anything else is a single entry.
    let Ok(children) = archive.children(at) else {
        if let Ok(nested) = archive.open_nested(src, at) {
            return list_into(src, &nested, 0, prefix, recursive, rows);
        }
        rows.push(describe(archive, at, prefix)?);
        return Ok(());
    };

    for index in children {
        let name = archive.name(index)?;
        let path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        rows.push(describe(archive, index, &path)?);

        if !recursive {
            continue;
        }
        if archive.entry(index)?.is_directory() {
            list_into(src, archive, index, &path, true, rows)?;
        } else if let Ok(nested) = archive.open_nested(src, index) {
            list_into(src, &nested, 0, &path, true, rows)?;
        }
    }
    Ok(())
}

/// One `ls` row.
fn describe(archive: &Archive, index: u32, path: &str) -> Result<Value> {
    let entry = archive.entry(index)?;
    let (kind, len) = match entry.kind {
        EntryKind::Directory { child_count, .. } => ("directory", u64::from(child_count)),
        // Either way the content is `uncompressed_len` bytes: the storage
        // choice changes what sits on disk, not what the file is.
        EntryKind::Binary {
            uncompressed_len, ..
        } => ("binary", u64::from(uncompressed_len)),
        EntryKind::Resource {
            system_flags,
            graphics_flags,
            ..
        } => (
            "resource",
            rpf_core::format::resource_len(system_flags, graphics_flags),
        ),
    };
    Ok(json!({ "path": path, "kind": kind, "len": len }))
}

/// Reads every entry, recording the ones that do not come back as promised.
fn verify_into<R: Read + Seek>(
    src: &mut R,
    archive: &Archive,
    prefix: &str,
    checked: &mut u32,
    problems: &mut Vec<String>,
) -> Result<()> {
    for index in 0..count(archive) {
        let entry = archive.entry(index)?;
        if entry.is_directory() {
            continue;
        }
        let name = archive.name(index)?;
        let path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };

        match archive.read(src, index) {
            Ok(_) => *checked = checked.saturating_add(1),
            Err(error) => {
                problems.push(format!("{path}: {error}"));
                continue;
            }
        }
        if let Ok(nested) = archive.open_nested(src, index) {
            verify_into(src, &nested, &path, checked, problems)?;
        }
    }
    Ok(())
}
