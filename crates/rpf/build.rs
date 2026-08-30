//! Decides, at build time, whether the gated tests here can reach anything.
//!
//! The same gate `crates/rpf-core/build.rs` carries, and for the same reason:
//! `cargo test` prints `ok` for a passing test and swallows its output, so a
//! test that returns early because there is nothing to read is
//! indistinguishable in the log from one that ran. `#[ignore]` is the one
//! outcome the harness reports by name without `--nocapture`.
//!
//! It is duplicated rather than shared because a build script belongs to one
//! package and there is nowhere else for it to put a shared one. Two gates,
//! because two things are named: `RPF_GAME_EXE` is where the key material comes
//! from and `RPF_CORPUS` is where the encrypted archives are. Almost every test
//! in this crate builds its own archive and needs neither.

fn main() {
    gate("RPF_CORPUS", "RPF_REQUIRE_CORPUS", "no_corpus");
    gate("RPF_GAME_EXE", "RPF_REQUIRE_GAME_EXE", "no_executables");
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
