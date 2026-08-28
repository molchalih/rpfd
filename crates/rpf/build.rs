//! Decides, at build time, whether the executable-gated tests can reach
//! anything.
//!
//! The same gate `crates/rpf-core/build.rs` carries, and for the same reason:
//! `cargo test` prints `ok` for a passing test and swallows its output, so a
//! test that returns early because there is no executable is indistinguishable
//! in the log from one that ran. `#[ignore]` is the one outcome the harness
//! reports by name without `--nocapture`.
//!
//! It is duplicated rather than shared because a build script belongs to one
//! package and there is nowhere else for it to put a shared one. Only the
//! executable gate is here: the tests in this crate build their own archives
//! and need no corpus.

fn main() {
    println!("cargo::rerun-if-env-changed=RPF_GAME_EXE");
    println!("cargo::rerun-if-env-changed=RPF_REQUIRE_GAME_EXE");
    println!("cargo::rustc-check-cfg=cfg(no_executables)");

    if std::env::var_os("RPF_GAME_EXE").is_none()
        && std::env::var_os("RPF_REQUIRE_GAME_EXE").is_none()
    {
        println!("cargo::rustc-cfg=no_executables");
    }
}
