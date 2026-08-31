//! What an entry holding one metadata encoding will take as a replacement.
//!
//! `RBF` and `PSO` are tokenised, and the runtime reads an entry as whatever
//! the entry was — so XML or plain text written into one produces an archive
//! that parses and does not load, which `docs/backlog.md` names as the standing
//! top risk. R6.6 refuses that write, `--allow-encoding-change` is the way
//! through, and DR-050 is why the way through is a switch of its own.
//!
//! **Every write path is asked, every time.** A patch, a rebuild and the
//! cascading `rewrite` both frontends actually commit through reach one rule in
//! `crate::edit`, and a caller that falls back from one to the other must not
//! get a different answer (§3), so every case here is run through all three.
//!
//! Corpus-free. Every archive here is built by this crate's own writer, so the
//! facts are pinned on a machine with no game installed.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "an integration test is its own crate with no cfg(test), so the \
              exception docs/conventions.md §15 grants test code is spelled \
              here. A panic is the reporting mechanism, and these run on \
              64-bit hosts against buffers the test itself created"
)]

use std::{
    collections::BTreeMap,
    io::{Cursor, Read as _, Seek as _},
    sync::Arc,
};

use rpf_core::{
    Archive, Bytes, Change, Changes, Encoding, Error, FileKind, FileSpec, Manifest, Storage,
    Unlock, Unwatched, Verified,
};

/// The path every archive here holds its one metadata entry at.
const AT: &str = "data/thing.ymt";

/// A payload announcing each encoding, and one announcing none.
///
/// The magics are `docs/rpf-format.md`'s, Metadata encodings, `verified`. The
/// unknown one is a byte that is neither text nor a signature.
fn payload(named: Option<Encoding>) -> Vec<u8> {
    match named {
        Some(Encoding::Rbf) => b"RBF0\x01\x02\x03\x04tokens here".to_vec(),
        Some(Encoding::Pso) => b"PSIN\x01\x02\x03\x04sections here".to_vec(),
        Some(Encoding::Xml) => b"<CVehicleModelInfo />".to_vec(),
        Some(Encoding::Text) => b"a plain line of text\n".to_vec(),
        None => vec![0x00_u8; 32],
    }
}

/// An archive holding one stored entry at [`AT`], with `contents` in it.
///
/// Stored rather than deflated so the entry's allocation is what its length
/// says, which is what keeps every patch below a patch rather than a rebuild.
fn archive_holding(contents: &[u8]) -> Vec<u8> {
    let owned = contents.to_vec();
    let mut out = Cursor::new(Vec::new());
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &[FileSpec {
            path: AT.to_owned(),
            kind: FileKind::Binary {
                storage: Storage::Stored,
                encryption: 0,
            },
        }],
        &[],
        |_: &str| Ok(Cursor::new(owned.clone())),
        &mut Unwatched,
    )
    .expect("builds");
    out.into_inner()
}

/// The change one write is.
fn writing(contents: &[u8], allow_encoding_change: bool) -> Changes {
    Changes::one(
        AT,
        Change::Write {
            contents: Arc::new(Bytes::new(contents.to_vec())),
            create: false,
            allow_encoding_change,
        },
    )
}

/// Which write path a case is run through.
#[derive(Debug, Clone, Copy)]
enum Path {
    /// `rpf_core::plan` — the entry is rewritten where it sits.
    Patch,
    /// `rpf_core::rebuild` — the whole archive is written again.
    Rebuild,
    /// `rpf_core::rewrite` — the same, cascading through nesting. **This is
    /// the one that ships**: both frontends commit through it, and `rebuild`
    /// answers a different question for every path that addresses through a
    /// nested archive. `docs/backlog.md` records a fuzz target that tested the
    /// function beside the one clients call.
    Rewrite,
}

/// All of them, so a case that names none is run through each.
const ALL: [Path; 3] = [Path::Patch, Path::Rebuild, Path::Rewrite];

/// Writes `contents` into an archive holding `held`, by `path`, and answers
/// the archive that came out.
///
/// A patch and a rebuild produce the same archive from the same change, which
/// is what lets one assertion cover both.
fn written(
    held: &[u8],
    contents: &[u8],
    allow_encoding_change: bool,
    path: Path,
) -> rpf_core::Result<Vec<u8>> {
    let mut file = Cursor::new(archive_holding(held));
    let archive = Archive::open(&mut file, &Unlock::unkeyed()).expect("parses");
    let changes = writing(contents, allow_encoding_change);
    match path {
        Path::Patch => {
            let plan = rpf_core::plan(&mut file, &archive, &changes)?;
            let rpf_core::Plan::Fits(patches) = plan else {
                panic!("expected a patch to fit, got {plan:?}")
            };
            patches.apply(&mut file)?;
            Ok(file.into_inner())
        }
        Path::Rebuild => {
            let mut out = Cursor::new(Vec::new());
            rpf_core::rebuild(
                &mut file,
                &archive,
                &changes,
                &mut out,
                BTreeMap::new(),
                &mut Unwatched,
            )?;
            Ok(out.into_inner())
        }
        Path::Rewrite => {
            let mut out = Cursor::new(Vec::new());
            rpf_core::rewrite(
                &mut file,
                &archive,
                &changes,
                &mut out,
                &mut rpf_core::InMemory,
                &mut Unwatched,
            )?;
            Ok(out.into_inner())
        }
    }
}

/// The contents of [`AT`] in an archive.
fn contents_of(bytes: &[u8]) -> Vec<u8> {
    let mut file = Cursor::new(bytes.to_vec());
    let archive = Archive::open(&mut file, &Unlock::unkeyed()).expect("re-parses");
    let index = archive.find(AT).expect("holds the entry");
    archive.extract(&mut file, index).expect("reads back")
}

/// The four pairs R6.6 names, on every write path: an entry holding a
/// tokenised encoding refuses a textual payload.
///
/// Two targets and two payloads, because a rule written for one of them is a
/// rule that lets the other through — which is how a guard covering `RBF` and
/// not `PSO` would pass a suite that only ever asked about `RBF`.
#[test]
fn a_tokenised_entry_refuses_a_textual_payload() {
    for held in [Encoding::Rbf, Encoding::Pso] {
        for offered in [Encoding::Xml, Encoding::Text] {
            for path in ALL {
                let outcome = written(&payload(Some(held)), &payload(Some(offered)), false, path);
                match outcome {
                    Err(Error::WrongEncoding {
                        path: ref at,
                        held: reported,
                        offered: refused,
                    }) => {
                        assert_eq!(at, AT, "the refusal names the entry it is about");
                        assert_eq!(reported, held);
                        assert_eq!(refused, offered);
                    }
                    other => panic!(
                        "expected {held:?} to refuse {offered:?} on {path:?}, got \
                         {other:?}"
                    ),
                }
            }
        }
    }
}

/// The refusal is [`rpf_core::Category::Refused`], which is exit 6 — the
/// number DR-010 already gives "the caller asked for something the entry
/// cannot take".
#[test]
fn the_refusal_is_a_refusal_rather_than_a_claim_about_the_archive() {
    let error = written(
        &payload(Some(Encoding::Rbf)),
        &payload(Some(Encoding::Xml)),
        false,
        Path::Patch,
    )
    .expect_err("is refused");
    assert_eq!(error.category(), rpf_core::Category::Refused);
    assert_eq!(error.name(), "WrongEncoding");
}

/// The escape hatch: with it, the write is taken and the payload is what came
/// out.
///
/// Both paths, because an override honoured by one of them and not the other
/// is the same layering bug as a refusal honoured by one of them.
#[test]
fn an_allowed_encoding_change_writes_the_payload() {
    for held in [Encoding::Rbf, Encoding::Pso] {
        for offered in [Encoding::Xml, Encoding::Text] {
            for path in ALL {
                let after = written(&payload(Some(held)), &payload(Some(offered)), true, path)
                    .expect("the override takes the write");
                assert_eq!(
                    contents_of(&after),
                    payload(Some(offered)),
                    "{held:?} took {offered:?} on {path:?} and kept it byte for byte"
                );
            }
        }
    }
}

/// The negative, and the reason the rule is four cells rather than a mood:
/// every write that was allowed before is allowed still.
///
/// A guard that refused more than R6.6 asks for would pass every test above.
/// This is what fails when it does — including the two cases a careless rule
/// would catch by symmetry: a tokenised payload into a textual entry, and a
/// tokenised payload into a tokenised entry of the other kind.
#[test]
fn every_other_pair_is_taken() {
    let all = [
        Some(Encoding::Xml),
        Some(Encoding::Text),
        Some(Encoding::Rbf),
        Some(Encoding::Pso),
        None,
    ];
    for held in all {
        for offered in all {
            let refused = matches!(held, Some(Encoding::Rbf | Encoding::Pso))
                && matches!(offered, Some(Encoding::Xml | Encoding::Text));
            if refused {
                continue;
            }
            for path in ALL {
                let after = written(&payload(held), &payload(offered), false, path).unwrap_or_else(
                    |error| {
                        panic!(
                            "an entry holding {held:?} must take {offered:?} on \
                             {path:?}, and answered {error:?}"
                        )
                    },
                );
                assert_eq!(contents_of(&after), payload(offered));
            }
        }
    }
}

/// The loosening, pinned as a loosening: an overridden write is taken, reads
/// back, and a bare `verify` has **nothing to say about it**.
///
/// This is the half of DR-050 that is worth a test rather than a sentence. A
/// resource entry keeps its own flag words when a payload is written into it,
/// so DR-046's loosening is caught by a later `verify`; a metadata entry keeps
/// no record of what it used to hold, so once the write is taken the archive
/// is a perfectly sound archive holding XML. Anything claiming otherwise is
/// claiming a safety net that is not there, and this is what fails when it
/// does.
#[test]
fn an_overridden_write_is_sound_afterwards_and_verify_cannot_see_it() {
    let after = written(
        &payload(Some(Encoding::Rbf)),
        &payload(Some(Encoding::Xml)),
        true,
        Path::Patch,
    )
    .expect("the override takes the write");

    let mut file = Cursor::new(after);
    let archive = Archive::open(&mut file, &Unlock::unkeyed()).expect("re-parses");
    let walked = Verified::of(&mut file, &archive, &mut Unwatched).expect("walks");
    assert_eq!(walked.checked, 1, "the entry was read back");
    assert!(
        walked.problems.is_empty(),
        "a bare verify has no record of what the entry held, so it reports \
         nothing: {:?}",
        walked.problems
    );
    assert!(walked.outcome().is_ok());
}

/// What `verify` **can** say about it, which is the whole of what R6.6's
/// override is checked by afterwards: the per-entry contents checksum a
/// manifest records. DR-023.
///
/// The manifest is written from the archive as it was, so the entry's `RBF`
/// contents are what its checksum is over; the overridden write replaces them,
/// and `verify --against` names that entry and no other.
#[test]
fn a_recorded_checksum_is_what_catches_an_overridden_write() {
    let before = archive_holding(&payload(Some(Encoding::Rbf)));
    let mut file = Cursor::new(before);
    let archive = Archive::open(&mut file, &Unlock::unkeyed()).expect("parses");
    let manifest =
        Manifest::of_contents(&mut file, &archive, &mut Unwatched).expect("describes the archive");

    let after = written(
        &payload(Some(Encoding::Rbf)),
        &payload(Some(Encoding::Xml)),
        true,
        Path::Patch,
    )
    .expect("the override takes the write");
    let mut file = Cursor::new(after);
    let archive = Archive::open(&mut file, &Unlock::unkeyed()).expect("re-parses");
    let walked = Verified::against(&mut file, &archive, &manifest, &mut Unwatched).expect("walks");
    assert_eq!(walked.contents_checked, 1, "the checksum was consulted");
    match walked.problems.as_slice() {
        [problem] => {
            assert_eq!(problem.path, AT);
            assert!(
                matches!(problem.error, Error::ChecksumMismatch { .. }),
                "expected the recorded checksum to catch it, got {:?}",
                problem.error
            );
        }
        other => panic!("expected exactly this entry to be reported, got {other:?}"),
    }
}

/// A payload that announces nothing is taken, whatever the entry holds.
///
/// `Encoding::of` answers `None` for it, and `None` contradicts no entry. A
/// rule that refused everything it did not recognise would refuse the commonest
/// payload in a real archive.
#[test]
fn a_payload_announcing_nothing_is_taken() {
    for held in [Encoding::Rbf, Encoding::Pso] {
        let after = written(&payload(Some(held)), &payload(None), false, Path::Rebuild)
            .expect("an unannounced payload is taken");
        assert_eq!(contents_of(&after), payload(None));
    }
}

/// A path the archive does not hold has no entry to contradict, so the rule
/// has nothing to say and a created entry takes whatever it is given.
#[test]
fn a_created_entry_is_not_judged_against_an_entry_that_is_not_there() {
    let mut file = Cursor::new(archive_holding(&payload(Some(Encoding::Rbf))));
    let archive = Archive::open(&mut file, &Unlock::unkeyed()).expect("parses");
    let changes = Changes::one(
        "data/added.ymt",
        Change::Write {
            contents: Arc::new(Bytes::new(payload(Some(Encoding::Xml)))),
            create: true,
            allow_encoding_change: false,
        },
    );
    let mut out = Cursor::new(Vec::new());
    rpf_core::rebuild(
        &mut file,
        &archive,
        &changes,
        &mut out,
        BTreeMap::new(),
        &mut Unwatched,
    )
    .expect("a created entry is not judged against one that is not there");

    let mut after = Cursor::new(out.into_inner());
    let archive = Archive::open(&mut after, &Unlock::unkeyed()).expect("re-parses");
    let index = archive.find("data/added.ymt").expect("holds it");
    let mut bytes = Vec::new();
    archive
        .extracted(&mut after, index)
        .expect("opens")
        .read_to_end(&mut bytes)
        .expect("reads");
    assert_eq!(bytes, payload(Some(Encoding::Xml)));
}

/// The daemon's early check runs the same rule: `allows` refuses what a commit
/// would refuse.
///
/// `allows` is what a client is told at the moment it can still act (R7.1), and
/// it is the resolution a commit performs run early and thrown away. A rule the
/// commit applies and `allows` does not is a refusal arriving at the save
/// rather than at the edit.
#[test]
fn allows_refuses_what_a_commit_would_refuse() {
    let mut file = Cursor::new(archive_holding(&payload(Some(Encoding::Pso))));
    let archive = Archive::open(&mut file, &Unlock::unkeyed()).expect("parses");
    let change = Change::Write {
        contents: Arc::new(Bytes::new(payload(Some(Encoding::Xml)))),
        create: false,
        allow_encoding_change: false,
    };
    let error = rpf_core::allows(&mut file, &archive, &Changes::new(), AT, &change)
        .expect_err("is refused before it is buffered");
    assert!(
        matches!(
            error,
            Error::WrongEncoding {
                held: Encoding::Pso,
                offered: Encoding::Xml,
                ..
            }
        ),
        "got {error:?}"
    );

    file.rewind().expect("rewinds");
    let allowed = Change::Write {
        contents: Arc::new(Bytes::new(payload(Some(Encoding::Xml)))),
        create: false,
        allow_encoding_change: true,
    };
    rpf_core::allows(&mut file, &archive, &Changes::new(), AT, &allowed)
        .expect("and taken when the caller says it meant it");
}

/// An archive holding one deflated entry at [`AT`], with `contents` in it.
fn deflated_holding(contents: &[u8]) -> Vec<u8> {
    let owned = contents.to_vec();
    let mut out = Cursor::new(Vec::new());
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &[FileSpec {
            path: AT.to_owned(),
            kind: FileKind::Binary {
                storage: Storage::Deflate,
                encryption: 0,
            },
        }],
        &[],
        |_: &str| Ok(Cursor::new(owned.clone())),
        &mut Unwatched,
    )
    .expect("builds");
    out.into_inner()
}

/// The entry is judged by what it holds, not by what is stored in it.
///
/// A deflated `RBF` payload begins with a deflate stream and not with `RBF0`,
/// so a rule reading the stored bytes would find no encoding and take every
/// write. Every fixture above is `Storage::Stored`, which is exactly the shape
/// that cannot notice.
#[test]
fn a_deflated_entry_is_judged_by_what_it_inflates_to() {
    let mut file = Cursor::new(deflated_holding(&payload(Some(Encoding::Rbf))));
    let archive = Archive::open(&mut file, &Unlock::unkeyed()).expect("parses");
    let changes = writing(&payload(Some(Encoding::Xml)), false);

    let mut out = Cursor::new(Vec::new());
    let refused = rpf_core::rewrite(
        &mut file,
        &archive,
        &changes,
        &mut out,
        &mut rpf_core::InMemory,
        &mut Unwatched,
    )
    .expect_err("a deflated RBF entry does not take XML");
    assert!(
        matches!(
            refused,
            Error::WrongEncoding {
                held: Encoding::Rbf,
                offered: Encoding::Xml,
                ..
            }
        ),
        "got {refused:?}"
    );

    file.rewind().expect("rewinds");
    let refused = rpf_core::plan(&mut file, &archive, &changes)
        .expect_err("and the patch path says the same");
    assert!(
        matches!(refused, Error::WrongEncoding { .. }),
        "got {refused:?}"
    );
}

/// An archive holding `inner.rpf`, which holds [`AT`] with `contents` in it.
fn nesting(contents: &[u8]) -> Vec<u8> {
    let inner = archive_holding(contents);
    let mut out = Cursor::new(Vec::new());
    rpf_core::build(
        &mut out,
        rpf_core::Version::Rpf7,
        &[FileSpec {
            path: "inner.rpf".to_owned(),
            kind: FileKind::Binary {
                storage: Storage::Stored,
                encryption: 0,
            },
        }],
        &[],
        |_: &str| Ok(Cursor::new(inner.clone())),
        &mut Unwatched,
    )
    .expect("builds");
    out.into_inner()
}

/// The path a nested archive's entry is addressed by, from the outside.
const THROUGH: &str = "inner.rpf/data/thing.ymt";

/// The rule reaches an entry inside a nested archive, and the refusal names the
/// path the caller used.
///
/// `rewrite` is where a cascade happens and `plan` is the path a caller falls
/// back from, so the two are asked the same question here. They answered
/// **different paths** until 2026-08-31: `split` re-keys a nested change to the
/// path within the archive it lands in, and the rebuild path reported that,
/// which does not resolve in the archive the caller named. DR-050 §2.
#[test]
fn a_nested_entry_is_refused_under_the_path_the_caller_spelled() {
    for allowed in [false, true] {
        let mut file = Cursor::new(nesting(&payload(Some(Encoding::Rbf))));
        let archive = Archive::open(&mut file, &Unlock::unkeyed()).expect("parses");
        let changes = Changes::one(
            THROUGH,
            Change::Write {
                contents: Arc::new(Bytes::new(payload(Some(Encoding::Xml)))),
                create: false,
                allow_encoding_change: allowed,
            },
        );

        let mut out = Cursor::new(Vec::new());
        let outcome = rpf_core::rewrite(
            &mut file,
            &archive,
            &changes,
            &mut out,
            &mut rpf_core::InMemory,
            &mut Unwatched,
        );
        if allowed {
            outcome.expect("the override reaches through the nesting too");
            continue;
        }
        match outcome.expect_err("a nested RBF entry does not take XML") {
            Error::WrongEncoding { path, .. } => assert_eq!(
                path, THROUGH,
                "the refusal must name the path the caller can use"
            ),
            other => panic!("got {other:?}"),
        }

        // And the patch path, which is what a frontend tries first: the same
        // refusal, under the same path.
        file.rewind().expect("rewinds");
        match rpf_core::plan(&mut file, &archive, &changes).expect_err("refused there too") {
            Error::WrongEncoding { path, .. } => assert_eq!(path, THROUGH),
            other => panic!("got {other:?}"),
        }

        // The early check a client gets is the same answer under the same path.
        file.rewind().expect("rewinds");
        let change = changes.at(THROUGH).expect("holds it").clone();
        match rpf_core::allows(&mut file, &archive, &Changes::new(), THROUGH, &change)
            .expect_err("refused before it is buffered")
        {
            Error::WrongEncoding { path, .. } => assert_eq!(path, THROUGH),
            other => panic!("got {other:?}"),
        }
    }
}
