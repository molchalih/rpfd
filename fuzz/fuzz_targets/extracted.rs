//! Every entry's payload drained through the streaming read.
//!
//! `Extracted` reports failure as an `std::io::Error`, and its contract is
//! that the error carries the typed one it really was — the source here is a
//! `Cursor`, which cannot fail on its own, so a bare i/o error is a defect.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rpf_core::{Archive, Error};
use rpf_fuzz::{DRAIN_LIMIT, bounded, watched};
use std::io::{Cursor, Read, copy, sink};

fuzz_target!(|data: &[u8]| {
    let Some(data) = bounded(data) else { return };

    watched(|| {
        let mut src = Cursor::new(data);
        let Ok(archive) = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()) else {
            return;
        };

        let count = u32::try_from(archive.entries().len()).unwrap_or(u32::MAX);
        for index in 0..count {
            let Ok(stream) = archive.extracted(Cursor::new(data), index) else {
                continue;
            };
            if let Err(failure) = copy(&mut stream.take(DRAIN_LIMIT), &mut sink()) {
                let reported = failure.to_string();
                assert!(
                    Error::carried(failure).is_ok(),
                    "the stream failed with a bare i/o error over a Cursor: {reported}"
                );
            }
        }
    });
});
