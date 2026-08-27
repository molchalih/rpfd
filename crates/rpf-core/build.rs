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

fn main() {
    println!("cargo::rerun-if-env-changed=RPF_CORPUS");
    println!("cargo::rerun-if-env-changed=RPF_REQUIRE_CORPUS");
    println!("cargo::rustc-check-cfg=cfg(no_corpus)");

    let located = std::env::var_os("RPF_CORPUS").is_some();
    let required = std::env::var_os("RPF_REQUIRE_CORPUS").is_some();
    if !located && !required {
        println!("cargo::rustc-cfg=no_corpus");
    }
}
