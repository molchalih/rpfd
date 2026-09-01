//! An arbitrary set of changes resolved against an arbitrary archive, and the
//! archive that committing it produces.
//!
//! Three things are asserted past "no panic": that the set is the data
//! structure it says it is; that [`allows`] and the commit through [`rewrite`]
//! agree, since a client told its edit is fine and then failed at commit is the
//! failure that pair exists to prevent; and that every path the commit was
//! asked to create is findable in the archive it wrote, a name the writer
//! transforms and the reader cannot address being silent corruption.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rpf_core::{
    Archive, Bytes, Change, Changes, EntryKind, Error, InMemory, Unwatched, allows, rewrite,
};
use rpf_fuzz::{MAX_INPUT, bounded, watched};
use std::io::Cursor;
use std::sync::Arc;

/// A [`Change`] the fuzzer can name.
///
/// `Change` itself carries an `Arc<dyn Contents>`, which is a trait object
/// rather than something `Arbitrary` can produce.
#[derive(Debug, Arbitrary)]
enum Wanted {
    Write {
        contents: Vec<u8>,
        create: bool,
        allow_encoding_change: bool,
    },
    Remove { recursive: bool },
    RenameTo(String),
    MakeDirectory,
}

impl Wanted {
    /// The bytes of input this change carries.
    fn weight(&self) -> usize {
        match *self {
            Self::Write { ref contents, .. } => contents.len(),
            Self::RenameTo(ref to) => to.len(),
            _ => 0,
        }
    }
}

/// A set of changes to buffer, and the archive to buffer them against.
#[derive(Debug, Arbitrary)]
struct Input<'a> {
    edits: Vec<(String, Wanted)>,
    data: &'a [u8],
}

/// The most changes one input may buffer.
///
/// Each one costs a resolution against the archive, and the fuzzer finds a
/// refusal in the first handful or in none of them.
const EDIT_LIMIT: usize = 16;

/// The most entries an archive may have before this target stops committing
/// it.
const ENTRY_LIMIT: usize = 128;

/// The most payload one archive may hold before this target stops committing
/// it.
///
/// The entry count is the wrong axis on its own: a commit re-encodes every
/// payload and deflate expands, so a two-entry archive well inside
/// [`ENTRY_LIMIT`] can cost the whole input's time in `flate2`.
const PAYLOAD_LIMIT: u64 = 1024 * 1024;

/// The [`Change`] a [`Wanted`] names.
fn change_of(wanted: Wanted) -> Change {
    match wanted {
        Wanted::Write {
            contents,
            create,
            allow_encoding_change,
        } => Change::Write {
            contents: Arc::new(Bytes::new(contents)),
            create,
            allow_encoding_change,
        },
        Wanted::Remove { recursive } => Change::Remove { recursive },
        Wanted::RenameTo(to) => Change::RenameTo(to),
        Wanted::MakeDirectory => Change::MakeDirectory,
    }
}

fuzz_target!(|input: Input| {
    let Some(data) = bounded(input.data) else {
        return;
    };
    // The edits are input too, and all of them reach the archive being written,
    // so the allocation bound is sized against all of it.
    let edits: Vec<(String, Wanted)> = input.edits.into_iter().take(EDIT_LIMIT).collect();
    let carried: usize = edits
        .iter()
        .map(|(path, wanted)| path.len().saturating_add(wanted.weight()))
        .sum();
    if carried > MAX_INPUT {
        return;
    }

    watched(|| {
        let mut src = Cursor::new(data);
        // An archive that does not open is still an input that builds a set;
        // only `allows` needs the archive.
        let archive = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).ok();

        let mut buffered = Changes::new();
        let mut all_allowed = true;
        for (path, wanted) in edits {
            let change = change_of(wanted);

            // What a client does before it buffers an edit: ask whether the
            // set it already holds admits this one.
            if let Some(ref archive) = archive {
                all_allowed &= allows(&mut src, archive, &buffered, &path, &change).is_ok();
            }

            // A plain write is the one change `bears_on` does not count: it
            // replaces an entry that is there, so it moves nothing.
            let restructures = !matches!(change, Change::Write { create: false, .. });

            let before = buffered.len();
            let replaced = buffered.set(&path, change);
            assert_eq!(
                buffered.len(),
                before + usize::from(replaced.is_none()),
                "setting a change at {path:?} left the set the wrong length"
            );
            assert!(
                buffered.at(&path).is_some(),
                "a change set at {path:?} is not in the set that took it"
            );
            assert!(
                !restructures || buffered.bears_on(&path),
                "a restructuring change at {path:?} does not bear on its own path"
            );
        }

        assert_eq!(
            buffered.len(),
            buffered.paths().count(),
            "the set's length and its paths disagree"
        );

        if let Some(ref archive) = archive
            && affordable(archive)
        {
            let created = created_here(archive, &buffered);
            committed(&mut src, archive, &buffered, &created, all_allowed);
        }

        // Taking a change back out is the one operation on the set that is not
        // a read: what went in comes out, and the set is empty after.
        let taken: Vec<String> = buffered.paths().map(str::to_owned).collect();
        for path in &taken {
            assert!(
                buffered.forget(path).is_some(),
                "the set will not give back the change it holds at {path:?}"
            );
        }
        assert!(
            buffered.is_empty(),
            "a set emptied path by path is not empty"
        );
    });
});

/// Whether committing this archive is worth an input's time.
///
/// [`ENTRY_LIMIT`] and [`PAYLOAD_LIMIT`], which are two different costs: the
/// table is walked per entry and the payloads are re-encoded per byte.
fn affordable(archive: &Archive) -> bool {
    if archive.entries().len() > ENTRY_LIMIT {
        return false;
    }
    let mut payload = 0_u64;
    for entry in archive.entries() {
        payload = payload.saturating_add(match entry.kind {
            EntryKind::Directory { .. } => 0,
            // What the commit re-encodes is what the payload inflates to,
            // which for a stored entry is the length it already has.
            EntryKind::Binary {
                compressed_len,
                uncompressed_len,
                ..
            } => u64::from(uncompressed_len.max(compressed_len)),
            EntryKind::Resource { compressed_len, .. } => u64::from(compressed_len),
        });
        if payload > PAYLOAD_LIMIT {
            return false;
        }
    }
    true
}

/// Every path the commit is being asked to bring into existence **in this
/// archive itself**.
///
/// `tree_of` applies removals, then renames, then writes, then new
/// directories, so a creation is the last word on its own path. A `Write` onto
/// an existing path is left out: it attaches to an entry an earlier rename may
/// already have moved.
///
/// A creation inside a nested archive is left out too, since a payload
/// descended into on the way in is deflated again on the way out and the reader
/// cannot descend it, though nothing went wrong.
fn created_here(archive: &Archive, buffered: &Changes) -> Vec<String> {
    buffered
        .iter()
        .filter(|(path, change)| match **change {
            Change::MakeDirectory => true,
            Change::Write { create: true, .. } => archive.find(path).is_err(),
            _ => false,
        })
        .map(|(path, _)| path)
        .filter(|path| lands_here(archive, path))
        .map(str::to_owned)
        .collect()
}

/// Whether `path` names something in `archive` itself rather than inside a
/// nested one.
///
/// A component that resolves to a file with components still after it is an
/// archive the commit descends into. Deliberately conservative: anything it
/// cannot decide counts as nested, so the assertion is skipped rather than made
/// about a path the commit routed somewhere this cannot see.
fn lands_here(archive: &Archive, path: &str) -> bool {
    let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    for taken in 1..segments.len() {
        match archive.find(&segments[..taken].join("/")) {
            // A directory to keep walking through.
            Ok(index) if archive.entry(index).is_ok_and(|entry| entry.is_directory()) => {}
            // A file, with components still to come.
            Ok(_) => return false,
            // Nothing resolves here, so the rest is made in this archive.
            Err(Error::NotFound { .. }) => return true,
            Err(_) => return false,
        }
    }
    true
}

/// Commits `buffered` against `archive`, and checks what came out.
fn committed(
    src: &mut Cursor<&[u8]>,
    archive: &Archive,
    buffered: &Changes,
    created: &[String],
    all_allowed: bool,
) {
    let mut out = Cursor::new(Vec::new());
    let report = match rewrite(
        src,
        archive,
        buffered,
        &mut out,
        &mut InMemory,
        &mut Unwatched,
    ) {
        Ok(report) => report,
        Err(failure) => {
            // `allows` promises that a change it accepts is one the commit
            // will not refuse for the same reason. Only `AlreadyExists` can be
            // asserted on: `build` raises the other kinds of its own, so a
            // refusal carrying one cannot be attributed to the resolution.
            assert!(
                !all_allowed || !matches!(failure, Error::AlreadyExists { .. }),
                "every change was allowed, and the commit refused: {failure:?}"
            );
            return;
        }
    };

    let written = out.into_inner();
    assert_eq!(
        u64::try_from(written.len()).unwrap_or(u64::MAX),
        report.len,
        "the commit reported a length it did not write"
    );
    let reopened = match Archive::open(
        &mut Cursor::new(written.as_slice()),
        &rpf_core::Unlock::unkeyed(),
    ) {
        Ok(reopened) => reopened,
        Err(failure) => panic!("an archive this build committed does not open: {failure:?}"),
    };
    assert_eq!(
        u32::try_from(reopened.entries().len()).unwrap_or(u32::MAX),
        report.entry_count,
        "the commit reported an entry count the archive does not have"
    );
    assert!(
        reopened.check_names().is_ok(),
        "an archive this build committed has names it will not read"
    );

    // The claim `check_names` is blind to: a commit that accepted a path wrote
    // it, and the reader can address it by the name it was given.
    for path in created {
        assert!(
            reopened.find(path).is_ok(),
            "the commit accepted {path:?} and the archive it wrote has nothing there"
        );
    }
}
