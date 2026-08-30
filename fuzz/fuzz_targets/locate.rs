//! An arbitrary path resolved through an arbitrary archive, including down
//! into whatever the walk decides is a nested archive.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rpf_core::Archive;
use rpf_fuzz::{bounded, watched};
use std::io::Cursor;

#[derive(Debug, Arbitrary)]
struct Input<'a> {
    path: &'a str,
    data: &'a [u8],
}

fuzz_target!(|input: Input| {
    let Some(data) = bounded(input.data) else {
        return;
    };
    let Some(path) = bounded(input.path.as_bytes()).map(|_| input.path) else {
        return;
    };

    watched(|| {
        let mut src = Cursor::new(data);
        let Ok(archive) = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()) else {
            return;
        };

        let _ = archive.find(path);
        let _ = archive.locate(&mut src, path);

        let count = u32::try_from(archive.entries().len()).unwrap_or(u32::MAX);
        for index in 0..count {
            let _ = archive.payload_is_resource(&mut src, index);
            if let Ok(rpf_core::archive::Nested::Open(nested)) = archive.nested_at(&mut src, index) {
                let _ = nested.check_names();
                let _ = nested.find(path);
                let _ = nested.locate(&mut src, path);
            }
        }
    });
});
