//! The tree and host name rules over arbitrary strings.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rpf_core::name;
use rpf_fuzz::{bounded, watched};

fuzz_target!(|path: &str| {
    let Some(path) = bounded(path.as_bytes()).map(|_| path) else {
        return;
    };

    watched(|| {
        let _ = name::check_tree(path);
        let _ = name::check_host(path);
    });
});
