//! `Archive::open` over arbitrary bytes, and every accessor the parsed archive
//! offers, at every index it claims to have.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rpf_core::Archive;
use rpf_fuzz::{bounded, watched};
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let Some(data) = bounded(data) else { return };

    watched(|| {
        let mut src = Cursor::new(data);
        let Ok(archive) = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()) else {
            return;
        };

        let _ = archive.check_names();
        let _ = archive.payload_extents();

        let count = u32::try_from(archive.entries().len()).unwrap_or(u32::MAX);
        for index in 0..count {
            let _ = archive.entry(index);
            let _ = archive.name(index);
            let _ = archive.path(index);
            let _ = archive.children(index);
            let _ = archive.allocation(index);
            let _ = archive.payload_at(index);
            let _ = archive.row_at(index);
        }
    });
});
