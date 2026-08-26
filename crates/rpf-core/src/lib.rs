//! Reading, editing and rebuilding RAGE Package File (`.rpf`) archives.
//!
//! This crate is the product; the `rpf` binary and the editor client are both
//! clients of it and hold no archive knowledge of their own. See
//! `docs/conventions.md` §1.
//!
//! Every constant and decode in [`format`] cites the row of `docs/rpf-format.md`
//! it comes from. A fact is encoded here exactly once (§3), so that changing it
//! is one edit rather than a search.

pub mod format;
