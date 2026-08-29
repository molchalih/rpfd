//! The sidecar manifest parser over arbitrary text, and what it answers.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rpf_core::Manifest;
use rpf_fuzz::{bounded, watched};

fuzz_target!(|text: &str| {
    let Some(text) = bounded(text.as_bytes()).map(|_| text) else {
        return;
    };

    watched(|| {
        let Ok(manifest) = Manifest::from_json(text) else {
            return;
        };

        let _ = manifest.checksums();
        let _ = manifest.specs();

        let Ok(written) = manifest.to_json() else {
            return;
        };
        assert!(
            Manifest::from_json(&written).is_ok(),
            "a manifest this build wrote does not read back"
        );
    });
});
