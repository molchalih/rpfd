//! Decides, at build time, whether the corpus-gated tests can reach anything.
//!
//! `cargo test` prints `ok` for a passing test and swallows its output, so a
//! test that returns early because there is no corpus is indistinguishable in
//! the log from one that ran — the outcome `docs/conventions.md` §12 calls the
//! most expensive one available. `#[ignore]` is the one outcome the harness
//! reports by name without `--nocapture`, so the gate is a `cfg` and the tests
//! carry `#[cfg_attr(no_corpus, ignore = …)]`.
//!
//! `RPF_REQUIRE_CORPUS` deliberately suppresses the gate: a caller that says
//! the corpus must be there wants the tests to run and fail, not to be skipped
//! quietly at a level `--include-ignored` is needed to see past.
//!
//! `RPF_GAME_EXE` gates the same way and is a separate variable because it
//! names a separate thing: `docs/corpus.md` records that the game executables
//! are not corpus — none of them is an archive — and key extraction reads them
//! while nothing else does. R2.
//!
//! `RPF_GAME_IMAGE` is a third, for the same reason again. It names one file: a
//! memory image of a running game, which is the only source the NG material has
//! ever been found in the clear in. It is separate from `RPF_GAME_EXE` because
//! the two answer opposite questions — an executable carries none of that
//! material and an image carries all of it — and a machine can easily have one
//! and not the other. DR-040.

fn main() {
    gate("RPF_CORPUS", "RPF_REQUIRE_CORPUS", "no_corpus");
    gate("RPF_GAME_EXE", "RPF_REQUIRE_GAME_EXE", "no_executables");
    gate("RPF_GAME_IMAGE", "RPF_REQUIRE_GAME_IMAGE", "no_game_image");
}

/// Sets `flag` unless `located` is set, or `required` says it must be there.
fn gate(located: &str, required: &str, flag: &str) {
    println!("cargo::rerun-if-env-changed={located}");
    println!("cargo::rerun-if-env-changed={required}");
    println!("cargo::rustc-check-cfg=cfg({flag})");

    if std::env::var_os(located).is_none() && std::env::var_os(required).is_none() {
        println!("cargo::rustc-cfg={flag}");
    }
}
