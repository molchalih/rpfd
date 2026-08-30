//! R3.9: one entry out of an archive, without holding it.
//!
//! `Archive::extract` answers the bytes and `Archive::extracted` answers the
//! same read as a stream. What these pin is that they are the **same read**:
//! the same bytes in the same order for each of the three forms a payload
//! takes, the same failures at the same places, and a rewind that gives the
//! stream back from its start — which is what `build` needs of a payload it
//! offers to the compressor twice.
//!
//! What they do not measure is memory. That is `memory.rs`, which counts.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test code; a panic is the reporting mechanism. \
              clippy.toml's allow-panic-in-tests reaches #[test] functions and \
              not the plain ones they call, which is what the crate-level allow \
              is for. docs/conventions.md §15"
)]

use std::io::{Cursor, Read, Seek, SeekFrom, Write};

use rpf_core::{
    Archive, Checksum, EntryKind, Error, FileKind, FileSpec, Storage, Unwatched, Version,
};

/// Bytes deflate cannot make smaller, so that the resource below is longer
/// than the reads these tests do into it.
fn incompressible(len: usize) -> Vec<u8> {
    let mut state = 0x2545_F491_4F6C_DD1D_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

/// A resource payload: an `RSC7` header for one 512-byte system page, then a
/// deflate stream of exactly that much.
///
/// `docs/rpf-format.md`, Resource page flags, `verified`: the top nibble of
/// each flag word is the header's version field and the rest decodes to the
/// length.
fn resource() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"RSC7");
    bytes.extend_from_slice(&162_u32.to_le_bytes());
    bytes.extend_from_slice(&0x0800_0000_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&incompressible(512)).expect("deflates");
    bytes.extend_from_slice(&encoder.finish().expect("finishes"));
    bytes
}

/// What each of the three entries of [`archive`] holds outside the archive.
fn contents(path: &str) -> Vec<u8> {
    match path {
        "stored.bin" => (0..8_192_u32).map(|byte| byte as u8).collect(),
        "deflated.bin" => vec![b'x'; 8_192],
        _ => resource(),
    }
}

/// An archive holding one stored entry, one deflated entry and one resource —
/// the three forms a payload takes.
fn archive() -> Vec<u8> {
    let files = vec![
        FileSpec {
            path: "stored.bin".to_owned(),
            kind: FileKind::Binary {
                storage: Storage::Stored,
                encryption: 0,
            },
        },
        FileSpec {
            path: "deflated.bin".to_owned(),
            kind: FileKind::Binary {
                storage: Storage::Deflate,
                encryption: 0,
            },
        },
        FileSpec {
            path: "art.yft".to_owned(),
            kind: FileKind::Resource,
        },
    ];
    let mut out = Vec::new();
    rpf_core::build(
        &mut Cursor::new(&mut out),
        Version::Rpf7,
        &files,
        &[],
        |wanted: &str| Ok(Cursor::new(contents(wanted))),
        &mut Unwatched,
    )
    .expect("builds");
    out
}

/// The whole of one entry, read through the stream a byte at a time.
///
/// A byte at a time on purpose: a stream that only answered correctly when
/// asked for everything at once would pass a `read_to_end` and fail the
/// `io::copy` every caller actually does.
fn streamed(bytes: &[u8], archive: &Archive, index: u32) -> Vec<u8> {
    let mut src = Cursor::new(bytes);
    let mut stream = archive.extracted(&mut src, index).expect("opens");
    let mut out = Vec::new();
    let mut one = [0_u8; 1];
    loop {
        match stream.read(&mut one).expect("reads") {
            0 => break,
            _ => out.extend_from_slice(&one),
        }
    }
    out
}

#[test]
fn a_streamed_entry_is_the_bytes_extract_answers() {
    let bytes = archive();
    let mut src = Cursor::new(bytes.clone());
    let parsed = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");

    for (index, path) in [(1_u32, "art.yft"), (2, "deflated.bin"), (3, "stored.bin")] {
        assert_eq!(
            parsed.name(index).expect("named"),
            path,
            "the entries are in name order",
        );

        let held = parsed.extract(&mut src, index).expect("extracts");
        assert_eq!(held, contents(path), "{path} came back as it went in");
        assert_eq!(
            streamed(&bytes, &parsed, index),
            held,
            "{path} streams the bytes `extract` answers",
        );

        // The length is the entry's own, known before anything is read: a
        // caller sizing a buffer or reporting progress does not have to read
        // the entry to find out how long it is.
        let mut src = Cursor::new(bytes.clone());
        let stream = parsed.extracted(&mut src, index).expect("opens");
        assert_eq!(
            stream.len(),
            held.len() as u64,
            "{path} declares its length"
        );
        assert!(!stream.is_empty());
    }
}

#[test]
fn a_digest_of_a_stream_is_the_digest_of_the_bytes() {
    // DR-023 defines the manifest's checksum as being of what `extract`
    // answers, and a resource is the case that would move if anything about
    // the framing changed: what is digested is its `RSC7` file, header and
    // deflated body, not what that body inflates to. Nothing that streams the
    // entry may change that value — a manifest already written would become
    // wrong, and silently.
    let bytes = archive();
    let mut src = Cursor::new(bytes.clone());
    let parsed = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");

    for (index, path) in [(1_u32, "art.yft"), (2, "deflated.bin"), (3, "stored.bin")] {
        let held = parsed.extract(&mut src, index).expect("extracts");
        let mut streaming = Cursor::new(bytes.clone());
        let mut stream = parsed.extracted(&mut streaming, index).expect("opens");
        assert_eq!(
            Checksum::of_stream(&mut stream).expect("digests"),
            Checksum::of(&held),
            "{path} digests to something else when it is streamed",
        );
    }
}

#[test]
fn a_stream_read_again_from_its_start_is_the_same_stream() {
    // What `build` does to a payload whose deflate does not pay for itself: it
    // reads it, finds the deflated form no smaller, rewinds and writes the
    // plain bytes over the top. A stream that could not do that would make a
    // rebuild silently write the tail of an entry.
    let bytes = archive();
    let mut src = Cursor::new(bytes.clone());
    let parsed = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");

    for (index, path) in [(1_u32, "art.yft"), (2, "deflated.bin"), (3, "stored.bin")] {
        let mut src = Cursor::new(bytes.clone());
        let mut stream = parsed.extracted(&mut src, index).expect("opens");

        let mut first = Vec::new();
        stream.read_to_end(&mut first).expect("reads");
        stream.rewind().expect("rewinds");
        let mut again = Vec::new();
        stream.read_to_end(&mut again).expect("reads again");
        assert_eq!(first, contents(path), "{path}");
        assert_eq!(again, first, "{path} reads the same twice");

        // And from the middle, which is the general case of the same thing.
        stream.rewind().expect("rewinds");
        let mut head = vec![0_u8; 100];
        stream.read_exact(&mut head).expect("reads a hundred");
        stream.seek(SeekFrom::Start(50)).expect("seeks back");
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).expect("reads the rest");
        assert_eq!(rest, first[50..], "{path} resumes from where it was sent");
    }
}

#[test]
fn a_stream_knows_where_its_end_is_without_reading_to_it() {
    let bytes = archive();
    let mut src = Cursor::new(bytes.clone());
    let parsed = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");

    for index in 1..=3_u32 {
        let mut src = Cursor::new(bytes.clone());
        let mut stream = parsed.extracted(&mut src, index).expect("opens");
        let len = stream.len();

        assert_eq!(stream.seek(SeekFrom::End(0)).expect("seeks"), len);
        let mut nothing = Vec::new();
        stream.read_to_end(&mut nothing).expect("reads");
        assert!(nothing.is_empty(), "there is nothing past the end");

        assert_eq!(stream.seek(SeekFrom::End(-16)).expect("seeks"), len - 16);
        let mut tail = Vec::new();
        stream.read_to_end(&mut tail).expect("reads");
        assert_eq!(tail.len(), 16, "the last sixteen bytes");
        assert_eq!(stream.stream_position().expect("tells"), len);
    }
}

/// A forward seek in a deflated entry lands on the bytes it claims to.
///
/// Seeking forward has no shortcut: the stream inflates what it passes over
/// and throws it away, in pieces, and then records the destination as its
/// position. Stopping that walk early still records the destination, so the
/// stream's real position and its reported one disagree and **every later read
/// answers from the wrong place** — with no error anywhere, which is what
/// makes it worth a test rather than a comment.
///
/// Nothing compared what a forward seek landed on. The test above seeks to the
/// last sixteen bytes and asserts that they are sixteen bytes, never that they
/// are the last sixteen; the one test that does compare bytes seeks
/// *backwards*, which restarts the stream and takes the other branch.
///
/// The payload is deliberately longer than one piece of the walk, so that
/// reaching the destination takes several: an entry small enough to be passed
/// over in one go cannot tell a loop that runs once from a loop that runs
/// until it is done.
#[test]
fn a_forward_seek_in_a_deflated_entry_lands_on_the_right_bytes() {
    // Compressible, so `build` really does deflate it, and periodic with a
    // period that is not a power of two, so no two offsets in the archive hold
    // the same window of bytes by accident.
    let plain: Vec<u8> = (0..96_000_u32).map(|byte| (byte % 251) as u8).collect();
    let files = vec![FileSpec {
        path: "long.bin".to_owned(),
        kind: FileKind::Binary {
            storage: Storage::Deflate,
            encryption: 0,
        },
    }];
    let mut out = Vec::new();
    rpf_core::build(
        &mut Cursor::new(&mut out),
        Version::Rpf7,
        &files,
        &[],
        |_: &str| Ok(Cursor::new(plain.clone())),
        &mut Unwatched,
    )
    .expect("builds");

    let mut src = Cursor::new(out.clone());
    let parsed = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");
    let index = parsed.find("long.bin").expect("resolves");
    match parsed.entry(index).expect("in range").kind {
        EntryKind::Binary { compressed_len, .. } => assert!(
            compressed_len > 0,
            "the entry is meant to be deflated, not stored"
        ),
        other => panic!("expected a binary entry, got {other:?}"),
    }

    let mut src = Cursor::new(out);
    let mut stream = parsed.extracted(&mut src, index).expect("opens");
    for at in [40_000_usize, 60_000, 95_900] {
        assert_eq!(
            stream.seek(SeekFrom::Start(at as u64)).expect("seeks"),
            at as u64
        );
        let mut got = vec![0_u8; 100.min(plain.len() - at)];
        stream.read_exact(&mut got).expect("reads");
        assert_eq!(got, plain[at..at + got.len()], "read after a seek to {at}");
    }
}

#[test]
fn a_stream_carries_the_failure_it_really_had() {
    // A `Read` can only fail with an `io::Error`, so the container failure
    // travels inside one. A caller that could not get it back out would report
    // a corrupt archive as a disk failure — a different exit code, blaming the
    // wrong party. DR-010.
    let mut bytes = archive();
    let parsed = Archive::open(
        &mut Cursor::new(bytes.clone()),
        &rpf_core::Unlock::unkeyed(),
    )
    .expect("parses");
    let (at, _) = parsed.payload_at(2).expect("the deflated entry");

    // One byte inside the deflate stream, past its header.
    bytes[at as usize + 6] ^= 0xFF;
    let parsed = Archive::open(
        &mut Cursor::new(bytes.clone()),
        &rpf_core::Unlock::unkeyed(),
    )
    .expect("still parses");
    let mut src = Cursor::new(bytes);
    let mut stream = parsed.extracted(&mut src, 2).expect("opens");
    let mut out = Vec::new();
    let failure = stream.read_to_end(&mut out).expect_err("does not inflate");

    match Error::carried(failure) {
        Ok(Error::Inflate { entry, .. } | Error::LengthMismatch { entry, .. }) => {
            assert_eq!(entry, 2, "the failure names the entry it happened in");
        }
        Ok(other) => panic!("expected the stream to fail, got {other:?}"),
        Err(source) => panic!("the io failure carried nothing: {source:?}"),
    }
}

#[test]
fn a_stream_of_something_that_is_not_a_file_is_refused_before_any_of_it() {
    let bytes = archive();
    let mut src = Cursor::new(bytes.clone());
    let parsed = Archive::open(&mut src, &rpf_core::Unlock::unkeyed()).expect("parses");

    // Entry 0 is the root directory, which has no payload to stream.
    let refused = parsed.extracted(&mut src, 0).expect_err("refused");
    assert!(
        matches!(
            refused,
            Error::WrongKind {
                found: "directory",
                ..
            }
        ),
        "expected a directory to be refused, got {refused:?}",
    );

    let refused = parsed.extracted(&mut src, 99).expect_err("refused");
    assert!(
        matches!(refused, Error::NoSuchEntry { .. }),
        "expected an index past the end to be refused, got {refused:?}",
    );
}
