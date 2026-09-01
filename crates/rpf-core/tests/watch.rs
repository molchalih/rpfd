//! Watching a long write or a long read: what it reports, and stopping one
//! part-way.
//!
//! Corpus-free: each test builds the archive it needs.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code; a panic is the reporting mechanism"
)]

use std::io::Cursor;

use rpf_core::{FileKind, FileSpec, Flow, Step, Storage, Unwatched, Watch};

struct Recorder {
    seen: Vec<(String, u32, u32, u64)>,
    stop_after: Option<u32>,
}

impl Recorder {
    fn watching() -> Self {
        Self {
            seen: Vec::new(),
            stop_after: None,
        }
    }

    fn stopping_after(entries: u32) -> Self {
        Self {
            seen: Vec::new(),
            stop_after: Some(entries),
        }
    }
}

impl Watch for Recorder {
    fn step(&mut self, step: Step<'_>) -> Flow {
        self.seen
            .push((step.path.to_owned(), step.done, step.total, step.bytes));
        match self.stop_after {
            Some(limit) if step.done >= limit => Flow::Stop,
            _ => Flow::Continue,
        }
    }
}

/// Three files, so a build has something to report between.
fn specs() -> Vec<FileSpec> {
    ["a.txt", "b.txt", "c.txt"]
        .into_iter()
        .map(|path| FileSpec {
            path: path.to_owned(),
            kind: FileKind::Binary {
                storage: Storage::Stored,
                encryption: 0,
            },
        })
        .collect()
}

#[test]
fn a_build_reports_every_entry_it_writes() {
    let mut watch = Recorder::watching();
    let mut out = Cursor::new(Vec::new());
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &specs(),
        &[],
        |wanted: &str| Ok(Cursor::new(vec![b'x'; wanted.len()])),
        &mut watch,
    )
    .expect("builds");

    let paths: Vec<&str> = watch.seen.iter().map(|(p, ..)| p.as_str()).collect();
    assert_eq!(paths, vec!["a.txt", "b.txt", "c.txt"]);

    for (index, &(_, done, total, _)) in watch.seen.iter().enumerate() {
        assert_eq!(
            done,
            u32::try_from(index).expect("small") + 1,
            "counted wrong"
        );
        assert_eq!(total, 3, "the total should be known up front");
    }

    let written: Vec<u64> = watch.seen.iter().map(|&(.., bytes)| bytes).collect();
    assert!(
        written.windows(2).all(|pair| pair[0] < pair[1]),
        "bytes written did not grow: {written:?}"
    );
}

#[test]
fn stopping_a_build_stops_it_and_says_so() {
    let mut watch = Recorder::stopping_after(2);
    let mut out = Cursor::new(Vec::new());
    let stopped = rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &specs(),
        &[],
        |wanted: &str| Ok(Cursor::new(vec![b'x'; wanted.len()])),
        &mut watch,
    );

    assert!(
        matches!(stopped, Err(rpf_core::Error::Cancelled { .. })),
        "got {stopped:?}",
    );
    assert_eq!(watch.seen.len(), 2, "it kept going after being stopped");
}

#[test]
fn a_cancellation_is_its_own_category() {
    // A cancel is the caller's own doing, so it is neither a refusal nor a
    // corrupt archive.
    let mut watch = Recorder::stopping_after(1);
    let mut out = Cursor::new(Vec::new());
    let stopped = rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &specs(),
        &[],
        |wanted: &str| Ok(Cursor::new(vec![b'x'; wanted.len()])),
        &mut watch,
    )
    .expect_err("stops");
    assert_eq!(stopped.category(), rpf_core::Category::Cancelled);
}

#[test]
fn a_caller_that_does_not_care_says_so() {
    let mut out = Cursor::new(Vec::new());
    let report = rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &specs(),
        &[],
        |wanted: &str| Ok(Cursor::new(vec![b'x'; wanted.len()])),
        &mut Unwatched,
    )
    .expect("builds");
    assert_eq!(report.entry_count, 4, "three files and a root");
}

#[test]
fn a_cascading_rebuild_reports_the_nested_archive_it_is_rebuilding() {
    // Each ancestor is rebuilt in turn, so the report is one sequence per
    // archive, innermost first.
    let mut inner = Cursor::new(Vec::new());
    rpf_core::build(
        &mut inner,
        rpf_core::Version::Rpf7,
        &specs(),
        &[],
        |wanted: &str| Ok(Cursor::new(vec![b'x'; wanted.len()])),
        &mut Unwatched,
    )
    .expect("inner builds");
    let inner = inner.into_inner();

    let outer_specs = vec![FileSpec {
        path: "x64/inner.rpf".to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Stored,
            encryption: 0,
        },
    }];
    let mut outer = Cursor::new(Vec::new());
    rpf_core::build(
        &mut outer,
        rpf_core::Version::Rpf7,
        &outer_specs,
        &[],
        |_: &str| Ok(Cursor::new(inner.clone())),
        &mut Unwatched,
    )
    .expect("outer builds");

    let mut src = Cursor::new(outer.into_inner());
    let archive = rpf_core::Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
    let edits = std::collections::BTreeMap::from([(
        "x64/inner.rpf/b.txt".to_owned(),
        b"replaced".to_vec(),
    )]);

    let mut watch = Recorder::watching();
    let mut out = Cursor::new(Vec::new());
    rpf_core::rewrite(
        &mut src,
        &archive,
        &rpf_core::Changes::writing(edits),
        &mut out,
        &mut rpf_core::InMemory,
        &mut watch,
    )
    .expect("rebuilds");

    let paths: Vec<&str> = watch.seen.iter().map(|(p, ..)| p.as_str()).collect();
    assert_eq!(
        paths,
        vec!["a.txt", "b.txt", "c.txt", "x64/inner.rpf"],
        "the inner archive should be reported before the ancestor holding it"
    );
}

#[test]
fn a_verify_reports_every_entry_it_reads_and_stops_when_told_to() {
    let mut out = Cursor::new(Vec::new());
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &specs(),
        &[],
        |wanted: &str| Ok(Cursor::new(vec![b'x'; wanted.len()])),
        &mut Unwatched,
    )
    .expect("builds");
    let archive = rpf_core::Archive::open(&mut out, &rpf_core::Unlock::unkeyed()).expect("parses");

    let mut watch = Recorder::watching();
    let verified = rpf_core::Verified::of(&mut out, &archive, &mut watch).expect("reads back");
    assert_eq!(verified.checked, 3);
    assert!(verified.problems.is_empty(), "{:?}", verified.problems);
    let steps: Vec<(&str, u32, u32)> = watch
        .seen
        .iter()
        .map(|(path, done, total, _)| (path.as_str(), *done, *total))
        .collect();
    assert_eq!(
        steps,
        vec![("a.txt", 1, 3), ("b.txt", 2, 3), ("c.txt", 3, 3)],
    );

    let mut watch = Recorder::stopping_after(2);
    let stopped = rpf_core::Verified::of(&mut out, &archive, &mut watch);
    assert!(
        matches!(
            stopped,
            Err(rpf_core::Error::Cancelled { done: 2, total: 3 })
        ),
        "got {stopped:?}",
    );
    assert_eq!(watch.seen.len(), 2, "it kept reading after being stopped");
}
