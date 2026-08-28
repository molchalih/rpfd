//! Archives that are wrong on purpose.
//!
//! §12 asks for these deliberately, because they are the inputs that turn into
//! panics and they do not occur in the corpus: a truncated archive, an entry
//! offset past the end, a names blob overrun, a deflate stream that lies about
//! its length. §6 sets the bar they are held to — every one of them is a
//! *named error*, never a panic, a hang, or a plausible-but-wrong value.
//!
//! Every archive here is assembled byte by byte from the constants in
//! `rpf_core::format`, so a test says what the bytes are rather than what some
//! builder thought they should be. Corpus-free by construction.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "test code; a panic is the reporting mechanism, and these run on \
              64-bit hosts against buffers the test itself created"
)]

use std::io::{Cursor, Write as _};

use rpf_core::{
    Archive, Error, MAX_DEPTH, Unwatched, Verified,
    format::{
        BLOCK_LEN, DIRECTORY_MARKER, ENCRYPTION_OPEN, ENTRY_LEN, HEADER_LEN, MAGIC_RPF7,
        MAGIC_RSC7, RESOURCE_FLAG, RESOURCE_HEADER_LEN,
    },
};

/// One directory row: name offset, the marker, first child, child count.
fn directory_row(name_offset: u32, first_child: u32, child_count: u32) -> [u8; 16] {
    let mut row = [0u8; 16];
    row[0..4].copy_from_slice(&name_offset.to_le_bytes());
    row[4..8].copy_from_slice(&DIRECTORY_MARKER.to_le_bytes());
    row[8..12].copy_from_slice(&first_child.to_le_bytes());
    row[12..16].copy_from_slice(&child_count.to_le_bytes());
    row
}

/// One file row: a 16-bit name offset, a 24-bit compressed size, a 24-bit
/// block offset carrying the resource bit, and the two words whose meaning
/// depends on that bit.
fn file_row(
    name_offset: u16,
    compressed_len: u32,
    block: u32,
    word8: u32,
    word12: u32,
) -> [u8; 16] {
    let mut row = [0u8; 16];
    row[0..2].copy_from_slice(&name_offset.to_le_bytes());
    row[2..5].copy_from_slice(&compressed_len.to_le_bytes()[..3]);
    row[5..8].copy_from_slice(&block.to_le_bytes()[..3]);
    row[8..12].copy_from_slice(&word8.to_le_bytes());
    row[12..16].copy_from_slice(&word12.to_le_bytes());
    row
}

/// Header, entry table, names blob, then zeroes out to `len`.
fn archive_bytes(rows: &[[u8; 16]], names: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&MAGIC_RPF7);
    out.extend_from_slice(&(rows.len() as u32).to_le_bytes());
    out.extend_from_slice(&(names.len() as u32).to_le_bytes());
    out.extend_from_slice(&ENCRYPTION_OPEN.to_le_bytes());
    for row in rows {
        out.extend_from_slice(row);
    }
    out.extend_from_slice(names);
    if out.len() < len {
        out.resize(len, 0);
    }
    out
}

/// Raw deflate of `plain`, which is what a binary payload is.
fn deflate(plain: &[u8]) -> Vec<u8> {
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(plain).expect("deflates");
    encoder.finish().expect("finishes")
}

/// A root directory over `count` stored files, named `a`, `b`, … in one blob,
/// each holding sixteen bytes a block apart from block 8 on.
///
/// Well formed as it stands; the tests that are about layout replace the rows
/// they care about.
fn named_root(count: u32) -> (Vec<[u8; 16]>, Vec<u8>) {
    let mut names = vec![0u8];
    let mut rows = vec![directory_row(0, 1, count)];
    for index in 0..count {
        let at = names.len() as u16;
        names.push(b'a' + index as u8);
        names.push(0);
        rows.push(file_row(at, 0, 8 + index, 16, 0));
    }
    (rows, names)
}

// ----- a tree that is not a tree ------------------------------------------

#[test]
fn a_directory_that_is_its_own_child_is_refused_at_parse() {
    // 512 bytes, two directories, the second of which claims itself. Before
    // this was refused, `Archive::path(1)` walked the parent map for ever and
    // `ls -R` died of a stack overflow — a reachable panic from an input this
    // small, which is exactly what §6 rules out.
    let rows = [directory_row(0, 1, 1), directory_row(0, 1, 1)];
    let bytes = archive_bytes(&rows, &[0, 0, 0], 512);

    let error = Archive::open(&mut Cursor::new(bytes)).expect_err("a cycle is not a tree");
    assert!(
        matches!(error, Error::CyclicTree { entry: 1, child: 1 }),
        "expected the self-referential directory to be named, got {error:?}"
    );
}

#[test]
fn two_directories_that_claim_each_other_are_refused_at_parse() {
    // The same failure one link longer: 0 holds 1, 1 holds 0. Nothing here is
    // out of range, which is what makes it worse than a bad child range —
    // walking it does not run off the end, it runs for ever.
    let rows = [directory_row(0, 1, 1), directory_row(0, 0, 1)];
    let bytes = archive_bytes(&rows, &[0, 0, 0], 512);

    let error = Archive::open(&mut Cursor::new(bytes)).expect_err("a cycle is not a tree");
    assert!(
        matches!(error, Error::CyclicTree { .. }),
        "expected a cycle, got {error:?}"
    );
}

#[test]
fn a_self_claiming_directory_is_refused_even_when_a_later_entry_reclaims_its_child() {
    // Three rows, 512 bytes. Entry 1 claims itself, and entry 2 claims entry 1
    // as well. The parent map is single-valued, so entry 2's claim overwrote
    // entry 1's: `parents[1]` read 2, the chain 1 → 2 → 0 → None ended, and a
    // walk of the *parent* map found nothing wrong. The **children** relation
    // still had entry 1 inside its own child range, which is what `ls -R`
    // recurses over. `info`, `cat` and `verify` all succeeded on this file and
    // `ls -R` aborted with "has overflowed its stack", exit 134 — and so did
    // the daemon's recursive list, taking the editor session with it.
    //
    // The two tests above pass for a narrower reason than their names imply:
    // with only two rows nothing ever reclaims the child, so the parent map
    // keeps the cycle. This is the case that separates the two relations.
    let rows = [
        directory_row(0, 1, 2),
        directory_row(0, 1, 1),
        directory_row(0, 1, 1),
    ];
    let bytes = archive_bytes(&rows, &[0, 0, 0], 512);

    let error = Archive::open(&mut Cursor::new(bytes)).expect_err("a cycle is not a tree");
    assert!(
        matches!(error, Error::CyclicTree { entry: 1, child: 1 }),
        "expected the self-referential directory to be named, got {error:?}"
    );
}

#[test]
fn two_directories_claiming_one_child_are_refused() {
    // Every entry claims every entry after it. Nothing here is a cycle and
    // nothing is out of range — the children still come after their parents —
    // but the relation is a lattice rather than a forest, and the number of
    // root-to-leaf paths through it doubles per row. Measured on this exact
    // file at 26 rows, all 512 bytes of it: `rpf ls -R` printed 33,554,431 rows
    // in 63 seconds, having accumulated every one of them in memory first. Two
    // more rows is four times that, and the file does not get any bigger.
    const ROWS: u32 = 26;
    let rows: Vec<[u8; 16]> = (0..ROWS)
        .map(|index| directory_row(0, index + 1, ROWS - 1 - index))
        .collect();
    let bytes = archive_bytes(&rows, &[0], 512);

    let error = Archive::open(&mut Cursor::new(bytes)).expect_err("a lattice is not a forest");
    assert!(
        matches!(
            error,
            Error::ClaimedTwice {
                child: 2,
                first: 0,
                second: 1
            }
        ),
        "expected the doubly-claimed child and both claimants, got {error:?}"
    );
}

#[test]
fn a_directory_tree_deeper_than_the_limit_is_refused() {
    // A chain of directories, each holding the next. Every child comes after
    // its parent, so this is a tree — just an arbitrarily deep one, and
    // `commands::list_into` recurses once per level. Measured before the limit:
    // 5,000 rows, a file of 80,384 bytes, and `rpf ls -R` aborted with a stack
    // overflow, exit 134. The bound belongs at parse, so that no walker has to
    // carry a counter of its own (§5).
    let deep = MAX_DEPTH + 1;
    let rows: Vec<[u8; 16]> = (0..=deep)
        .map(|index| {
            if index == deep {
                directory_row(0, 0, 0)
            } else {
                directory_row(0, index + 1, 1)
            }
        })
        .collect();
    let len = (HEADER_LEN as usize + rows.len() * ENTRY_LEN as usize + 1)
        .next_multiple_of(BLOCK_LEN as usize);
    let bytes = archive_bytes(&rows, &[0], len);

    let error = Archive::open(&mut Cursor::new(bytes)).expect_err("one level too deep");
    assert!(
        matches!(
            error,
            Error::TooDeep {
                what: "directory tree",
                depth: at,
                limit: MAX_DEPTH
            } if at == deep
        ),
        "expected the depth and the limit, got {error:?}"
    );
}

#[test]
fn a_directory_tree_exactly_at_the_limit_still_opens() {
    // The other side of it: the limit is the deepest tree that works, not the
    // shallowest that fails. Without this, a limit set one too low would look
    // just as green as a correct one.
    let rows: Vec<[u8; 16]> = (0..=MAX_DEPTH)
        .map(|index| {
            if index == MAX_DEPTH {
                directory_row(0, 0, 0)
            } else {
                directory_row(0, index + 1, 1)
            }
        })
        .collect();
    let len = (HEADER_LEN as usize + rows.len() * ENTRY_LEN as usize + 1)
        .next_multiple_of(BLOCK_LEN as usize);
    let bytes = archive_bytes(&rows, &[0], len);

    let archive = Archive::open(&mut Cursor::new(bytes)).expect("exactly at the limit");
    assert_eq!(archive.entries().len() as u32, MAX_DEPTH + 1);
}

#[test]
fn a_child_range_past_the_entry_table_is_still_refused() {
    // The check that was already here, kept honest alongside the new one.
    let rows = [directory_row(0, 1, 9)];
    let bytes = archive_bytes(&rows, &[0], 512);

    let error = Archive::open(&mut Cursor::new(bytes)).expect_err("9 children of 1 entry");
    assert!(
        matches!(
            error,
            Error::BadChildRange {
                entry: 0,
                first: 1,
                count: 9,
                entry_count: 1
            }
        ),
        "expected the range to be named, got {error:?}"
    );
}

#[test]
fn archives_nested_deeper_than_the_limit_are_refused() {
    // A stack of archives, one per block, each holding the whole remaining tail
    // as its only file. `open_nested` had no bound and both recursive walkers
    // descend through it, so the depth of the recursion was the caller's to
    // choose. Measured before the limit: 16,000 stacked headers — 8,192,000
    // bytes — aborted `rpf ls -R`, `rpf verify` and the daemon's recursive list
    // with a stack overflow, exit 134, with the threshold between 7 MB and
    // 8 MB. §6 rules out a reachable panic from hostile bytes; the answer is a
    // named error at a named depth.
    let levels = MAX_DEPTH + 2;
    let bytes = stacked_archives(levels);

    let mut src = Cursor::new(bytes);
    let mut archive = Archive::open(&mut src).expect("the outermost parses");
    for level in 1..=MAX_DEPTH {
        archive = archive
            .open_nested(&mut src, 1)
            .unwrap_or_else(|error| panic!("level {level} should open: {error:?}"));
    }

    let error = archive
        .open_nested(&mut src, 1)
        .expect_err("one archive too deep");
    assert!(
        matches!(
            error,
            Error::TooDeep {
                what: "archive nesting",
                depth: at,
                limit: MAX_DEPTH
            } if at == MAX_DEPTH + 1
        ),
        "expected the depth and the limit, got {error:?}"
    );
}

/// `levels` archives stacked one per block, each one's single file entry
/// covering the whole of the tail after it.
fn stacked_archives(levels: u32) -> Vec<u8> {
    let block = BLOCK_LEN as usize;
    let total = levels as usize * block;
    let mut out = Vec::with_capacity(total);
    for level in 0..levels as usize {
        let tail = total - (level + 1) * block;
        let rows = [directory_row(0, 1, 1), file_row(1, 0, 1, tail as u32, 0)];
        out.extend_from_slice(&archive_bytes(&rows, b"\0a\0", block));
    }
    out
}

// ----- what opening an archive is allowed to cost --------------------------

#[test]
fn a_names_blob_every_entry_shares_does_not_cost_one_copy_each() {
    // 40,000 entries, all pointing at offset 0 of a 40,000-byte blob holding
    // one unterminated-until-the-end name. The file is 680,016 bytes and every
    // byte of it is legitimate: the entry table and the blob both fit, and the
    // format says nothing against two entries having the same name.
    //
    // Materialising each name separately made opening it cost entry_count ×
    // names_len: measured at 1,980,317,696 bytes of resident memory over 4.2
    // seconds, and ~7 MB of input would have asked for ~200 GB. It fires in
    // `Archive::open`, so on every command and every daemon session.
    //
    // The assertion is the structure rather than the clock. Every entry here
    // points at offset 0, so a reader that resolves spans hands every one of
    // them the *same* bytes of the one blob, at one address; a reader that
    // materialises names gives each its own copy, which is the amplification
    // itself rather than a symptom of it. A stopwatch could not see this: the
    // bound that stood here was two seconds, and under `--release` the
    // amplifying reader finished this archive in 0.83 of one.
    const ENTRIES: u32 = 40_000;
    const NAMES_LEN: usize = 40_000;

    let rows = vec![file_row(0, 0, 0, 0, 0); ENTRIES as usize];
    let mut names = vec![b'A'; NAMES_LEN];
    names[NAMES_LEN - 1] = 0;
    let len = HEADER_LEN as usize + ENTRIES as usize * ENTRY_LEN as usize + NAMES_LEN;
    let bytes = archive_bytes(&rows, &names, len);
    assert_eq!(bytes.len(), 680_016);

    let archive = Archive::open(&mut Cursor::new(bytes)).expect("every region fits");
    let blob = archive.names_blob();
    assert_eq!(blob.len(), NAMES_LEN, "the blob is held once, whole");

    for index in [0, 1, ENTRIES / 2, ENTRIES - 1] {
        let name = archive.name(index).expect("every entry has a name");
        assert_eq!(name.len(), NAMES_LEN - 1, "entry {index}: name length");
        assert!(
            std::ptr::eq(name.as_ptr(), blob.as_ptr()),
            "entry {index} carries a copy of the names blob rather than a view of it",
        );
    }
}

// ----- allocation: the room a patch may write into -------------------------

#[test]
fn an_allocation_stops_where_a_payload_sharing_its_block_begins() {
    // a.bin and b.bin both start at block 1; c.bin is at block 8. Filtering
    // the next payload by "starts strictly later" made b.bin invisible, so
    // a.bin's allocation read 3,584 — through the whole of b.bin — and `put`
    // reported "room for 3584" and destroyed b.bin's payload in place.
    let (mut rows, names) = named_root(3);
    rows[1] = file_row(1, 0, 1, 16, 0);
    rows[2] = file_row(3, 0, 1, 2_000, 0);
    rows[3] = file_row(5, 0, 8, 16, 0);
    let bytes = archive_bytes(&rows, &names, 8_192);

    let archive = Archive::open(&mut Cursor::new(bytes)).expect("well formed");
    assert_eq!(
        archive.allocation(1).expect("a.bin has an allocation"),
        0,
        "a.bin shares its block with b.bin, so it has no room at all"
    );
    assert_eq!(
        archive.allocation(3).expect("c.bin has an allocation"),
        8_192 - 8 * BLOCK_LEN,
        "c.bin is last, so its allocation runs to the end of the archive"
    );
}

#[test]
fn an_allocation_never_spans_a_payload_that_began_before_it() {
    // b.bin sits at block 2, inside a.bin's 2,000 bytes at block 1. Nothing
    // starts after b.bin, so "to the end of the archive" would hand a patch
    // the bytes a.bin is still using.
    let (mut rows, names) = named_root(2);
    rows[1] = file_row(1, 0, 1, 2_000, 0);
    rows[2] = file_row(3, 0, 2, 16, 0);
    let bytes = archive_bytes(&rows, &names, 8_192);

    let archive = Archive::open(&mut Cursor::new(bytes)).expect("well formed");
    assert_eq!(
        archive.allocation(2).expect("b.bin has an allocation"),
        0,
        "a.bin's payload runs through b.bin's start, so b.bin has no room"
    );
}

#[test]
fn an_allocation_of_an_index_that_does_not_exist_says_so() {
    // §10: the caller can act on "there is no entry 99". It cannot act on
    // "entry 99 is a directory", which is what searching the extents first
    // reported.
    let (rows, names) = named_root(3);
    let bytes = archive_bytes(&rows, &names, 8_192);

    let archive = Archive::open(&mut Cursor::new(bytes)).expect("well formed");
    let error = archive.allocation(99).expect_err("there is no entry 99");
    assert!(
        matches!(
            error,
            Error::NoSuchEntry {
                index: 99,
                entry_count: 4
            }
        ),
        "expected the index to be reported as missing, got {error:?}"
    );
}

#[test]
fn an_allocation_of_a_directory_is_a_wrong_kind() {
    let (rows, names) = named_root(3);
    let bytes = archive_bytes(&rows, &names, 8_192);

    let archive = Archive::open(&mut Cursor::new(bytes)).expect("well formed");
    let error = archive
        .allocation(0)
        .expect_err("entry 0 is the root directory");
    assert!(
        matches!(
            error,
            Error::WrongKind {
                entry: 0,
                found: "directory",
                wanted: "file"
            }
        ),
        "expected a wrong kind, got {error:?}"
    );
}

// ----- payloads, and where one may begin -----------------------------------

#[test]
fn a_payload_that_begins_inside_the_table_of_contents_is_refused() {
    // Block 0 is the archive's own header. Checking only the upper bound made
    // `cat` return the header and the entry table as file contents — a
    // plausible-but-wrong value rather than an error — and made `allocation`
    // report the whole archive as room, so `put` overwrote the magic.
    let rows = [directory_row(0, 1, 1), file_row(1, 0, 0, 64, 0)];
    let bytes = archive_bytes(&rows, b"\0a\0", 2_048);
    let floor = HEADER_LEN + 2 * ENTRY_LEN + 3;

    let archive = Archive::open(&mut Cursor::new(bytes.clone())).expect("the header is fine");
    let error = archive
        .read(&mut Cursor::new(bytes), 1)
        .expect_err("no payload may begin at block 0");
    assert!(
        matches!(
            error,
            Error::PayloadUnderflow {
                entry: 1,
                offset: 0,
                floor: at
            } if at == floor
        ),
        "expected the floor to be named, got {error:?}"
    );

    let error = archive
        .allocation(1)
        .expect_err("and no patch may be offered that room");
    assert!(
        matches!(error, Error::PayloadUnderflow { entry: 1, .. }),
        "expected the same refusal from allocation, got {error:?}"
    );
}

#[test]
fn an_entry_offset_past_the_end_is_refused() {
    // §12's second case. Block 100 of a 2,048-byte archive.
    let rows = [directory_row(0, 1, 1), file_row(1, 0, 100, 64, 0)];
    let bytes = archive_bytes(&rows, b"\0a\0", 2_048);

    let archive = Archive::open(&mut Cursor::new(bytes.clone())).expect("the header is fine");
    let error = archive
        .read(&mut Cursor::new(bytes), 1)
        .expect_err("block 100 is past the end");
    assert!(
        matches!(
            error,
            Error::OutOfBounds {
                region: "payload",
                archive_len: 2_048,
                ..
            }
        ),
        "expected an out-of-bounds payload, got {error:?}"
    );
}

// ----- truncation ----------------------------------------------------------

#[test]
fn a_file_too_short_to_hold_a_header_is_not_an_archive() {
    // §12's first case. Nothing failed — the bytes are simply not there — so
    // this is not an i/o error.
    let error = Archive::open(&mut Cursor::new(b"7FPR\x02".to_vec()))
        .expect_err("five bytes is not an archive");
    assert!(
        matches!(error, Error::NotAnArchive { base: 0, .. }),
        "expected a refusal to call it an archive, got {error:?}"
    );
}

#[test]
fn an_entry_table_that_does_not_fit_the_archive_is_refused() {
    // A header claiming 100 entries in a 64-byte file. The entry table is what
    // does not fit, and saying so is what tells the caller where to look.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MAGIC_RPF7);
    bytes.extend_from_slice(&100_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&ENCRYPTION_OPEN.to_le_bytes());
    bytes.resize(64, 0);

    let error = Archive::open(&mut Cursor::new(bytes)).expect_err("100 entries do not fit");
    assert!(
        matches!(
            error,
            Error::OutOfBounds {
                region: "entry table",
                archive_len: 64,
                ..
            }
        ),
        "expected the entry table to be named, got {error:?}"
    );
}

#[test]
fn a_names_blob_that_does_not_fit_the_archive_is_refused() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MAGIC_RPF7);
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&4_096_u32.to_le_bytes());
    bytes.extend_from_slice(&ENCRYPTION_OPEN.to_le_bytes());
    bytes.resize(512, 0);

    let error = Archive::open(&mut Cursor::new(bytes)).expect_err("4 KB of names do not fit");
    assert!(
        matches!(
            error,
            Error::OutOfBounds {
                region: "names blob",
                archive_len: 512,
                ..
            }
        ),
        "expected the names blob to be named, got {error:?}"
    );
}

// ----- names ---------------------------------------------------------------

#[test]
fn a_name_that_runs_past_the_names_blob_is_refused() {
    // §12's third case. The blob's last byte is not a terminator, and the
    // bytes after it can be stale names from a previous pack — reading on is
    // how those get mistaken for live ones.
    let rows = [directory_row(0, 1, 0)];
    let bytes = archive_bytes(&rows, b"abcd", 512);

    let error = Archive::open(&mut Cursor::new(bytes)).expect_err("no terminator in the blob");
    assert!(
        matches!(
            error,
            Error::BadName {
                entry: 0,
                name_offset: 0,
                names_len: 4
            }
        ),
        "expected the entry and its offset, got {error:?}"
    );
}

#[test]
fn a_name_offset_past_the_names_blob_is_refused() {
    let rows = [directory_row(9, 1, 0)];
    let bytes = archive_bytes(&rows, b"root\0", 512);

    let error = Archive::open(&mut Cursor::new(bytes)).expect_err("offset 9 is outside 5 bytes");
    assert!(
        matches!(
            error,
            Error::BadName {
                entry: 0,
                name_offset: 9,
                names_len: 5
            }
        ),
        "expected the entry and its offset, got {error:?}"
    );
}

#[test]
fn names_are_still_resolved_where_they_overlap() {
    // Two entries pointing into one string: the second name is the tail of the
    // first. Legal, and the thing a bound on total name bytes would have
    // wrongly refused.
    let rows = [
        directory_row(0, 1, 1),
        file_row(1, 0, 8, 4, 0),
        file_row(3, 0, 9, 4, 0),
    ];
    let bytes = archive_bytes(&rows, b"\0abc\0", 8_192);

    let archive = Archive::open(&mut Cursor::new(bytes)).expect("well formed");
    assert_eq!(archive.name(0).expect("root"), "");
    assert_eq!(archive.name(1).expect("first"), "abc");
    assert_eq!(archive.name(2).expect("second"), "c");
}

#[test]
fn a_name_that_is_not_utf_8_is_refused_rather_than_repaired() {
    // The names blob is bytes, and nothing in the format says which encoding.
    // Every name in the sample is ASCII, so the answer for the rest is §6's:
    // refuse, and say which entry — a lossy repair would hand the caller a name
    // that does not address the entry it came from, and `find` would then miss
    // a file that is plainly in the listing.
    //
    // The archive is otherwise well formed, so this fires on the name and on
    // nothing else: 0xFF and 0xFE are the two bytes that begin no UTF-8
    // sequence at all.
    let rows = [directory_row(0, 1, 1), file_row(1, 0, 8, 16, 0)];
    let bytes = archive_bytes(&rows, b"\0\xFF\xFE\0", 8_192);

    let archive = Archive::open(&mut Cursor::new(bytes)).expect("every region fits");
    assert_eq!(archive.name(0).expect("the root is empty and valid"), "");

    let error = archive.name(1).expect_err("0xFF 0xFE is not UTF-8");
    assert!(
        matches!(
            error,
            Error::BadName {
                entry: 1,
                name_offset: 1,
                names_len: 4
            }
        ),
        "expected the entry and its offset, got {error:?}"
    );
    // And the same through the path walk, which is what a listing calls.
    assert!(
        matches!(archive.path(1), Err(Error::BadName { entry: 1, .. })),
        "a path built out of bytes that are not a name",
    );
}

// ----- compression ---------------------------------------------------------

#[test]
fn a_deflate_stream_that_lies_about_its_length_is_refused() {
    // §12's fourth case. The payload inflates perfectly well; it simply is not
    // the length the entry table promised, which is an archive contradicting
    // itself rather than an unreadable one.
    let payload = deflate(&[b'x'; 64]);
    let rows = [
        directory_row(0, 1, 1),
        file_row(1, payload.len() as u32, 1, 4_096, 0),
    ];
    let mut bytes = archive_bytes(&rows, b"\0a\0", 2_048);
    bytes[BLOCK_LEN as usize..BLOCK_LEN as usize + payload.len()].copy_from_slice(&payload);

    let archive = Archive::open(&mut Cursor::new(bytes.clone())).expect("well formed");
    let error = archive
        .read(&mut Cursor::new(bytes), 1)
        .expect_err("64 bytes is not 4,096");
    assert!(
        matches!(
            error,
            Error::LengthMismatch {
                entry: 1,
                expected: 4_096,
                actual: 64
            }
        ),
        "expected the two lengths, got {error:?}"
    );
}

/// System page flags naming exactly one page of the base 512 bytes, which is
/// the smallest resource there is. `docs/rpf-format.md`, Resource page flags,
/// `verified`.
const ONE_SYSTEM_PAGE: u32 = 0x0800_0000;

/// What [`ONE_SYSTEM_PAGE`] with no graphics pages inflates to.
const ONE_SYSTEM_PAGE_LEN: usize = 512;

/// A resource payload: an `RSC7` header for one system page, then a deflate
/// stream of exactly that much.
///
/// The header's version is the top nibble of each flag word, so flags naming
/// no version make it zero. `docs/rpf-format.md`, Resource page flags.
fn resource_payload() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC_RSC7);
    out.extend_from_slice(&0_u32.to_le_bytes());
    out.extend_from_slice(&ONE_SYSTEM_PAGE.to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes());
    out.extend_from_slice(&deflate(&[0xAA_u8; ONE_SYSTEM_PAGE_LEN]));
    out
}

/// A 2,048-byte archive holding one file, its payload written at block 1 and
/// its entry declaring `declared` bytes of it.
///
/// Declaring more than `payload` is long is how a payload grows a tail: the
/// bytes after it are the zeroes the archive is padded with, which is the
/// sample's case in miniature — 200,000 zeroes appended to a resource.
fn one_file_archive(payload: &[u8], declared: u32, block_flag: u32, word8: u32) -> Vec<u8> {
    let rows = [
        directory_row(0, 1, 1),
        file_row(1, declared, 1 | block_flag, word8, 0),
    ];
    let mut bytes = archive_bytes(&rows, b"\0a\0", 2_048);
    bytes[BLOCK_LEN as usize..BLOCK_LEN as usize + payload.len()].copy_from_slice(payload);
    bytes
}

/// Every problem `verify` reports about an archive, by path and failure.
fn problems(bytes: &[u8]) -> Vec<(String, Error)> {
    let archive = Archive::open(&mut Cursor::new(bytes.to_vec())).expect("well formed");
    Verified::of(&mut Cursor::new(bytes.to_vec()), &archive, &mut Unwatched)
        .expect("the walk itself does not fail")
        .problems
        .into_iter()
        .map(|problem| (problem.path, problem.error))
        .collect()
}

#[test]
fn a_resource_that_ends_exactly_at_its_payload_verifies_clean() {
    // The direction that keeps the check honest. All 20 resources of the
    // sample end their stream exactly here — `docs/rpf-format.md`, Resource
    // page flags, `verified` — so a check that fired on this one would fire on
    // every archive there is.
    let payload = resource_payload();
    let declared = payload.len() as u32;
    let bytes = one_file_archive(&payload, declared, RESOURCE_FLAG, ONE_SYSTEM_PAGE);

    assert!(
        problems(&bytes).is_empty(),
        "a resource that ends where it says it does is not a problem"
    );
}

#[test]
fn a_resource_whose_stream_ends_before_its_payload_is_reported_by_verify() {
    // R6.10. The stream is self-terminating, so 200 bytes after it inflate to
    // nothing and the contents come back exactly as promised: this is the
    // archive contradicting itself, and nothing in a read has to notice it.
    let payload = resource_payload();
    let tail = 200_u32;
    let declared = payload.len() as u32 + tail;
    let bytes = one_file_archive(&payload, declared, RESOURCE_FLAG, ONE_SYSTEM_PAGE);

    let archive = Archive::open(&mut Cursor::new(bytes.clone())).expect("well formed");
    assert_eq!(
        archive
            .read(&mut Cursor::new(bytes.clone()), 1)
            .expect("reads back")
            .len(),
        ONE_SYSTEM_PAGE_LEN,
        "a read is deliberately not where this is refused: `cat`, `extract` \
         and `put` go on working on such an archive",
    );

    // The stream's own extent, which is the payload without the `RSC7` header
    // and without the tail.
    let used = (payload.len() as u64) - RESOURCE_HEADER_LEN;
    match problems(&bytes).as_slice() {
        [
            (
                path,
                error @ Error::TrailingBytes {
                    entry,
                    declared,
                    used: got,
                },
            ),
        ] => {
            assert_eq!(path, "a", "the problem names the entry's path");
            assert_eq!(
                (*entry, *declared, *got),
                (1, used + u64::from(tail), used),
                "expected the two payload lengths, got {error}"
            );
        }
        other => panic!("expected one trailing-bytes problem, got {other:?}"),
    }
}

#[test]
fn a_resource_corrupted_inside_its_stream_is_still_caught() {
    // The other direction of the same table: bytes changed *within* the stream
    // were caught before R6.10 and must go on being caught, as a failure of
    // the stream rather than as a tail. Measured on the sample as
    // `inflated to 3153921 bytes, archive declares 3153920`.
    let mut payload = resource_payload();
    let at = payload.len() - 4;
    for byte in &mut payload[at - 3..at] {
        *byte ^= 0xFF;
    }
    let declared = payload.len() as u32;
    let bytes = one_file_archive(&payload, declared, RESOURCE_FLAG, ONE_SYSTEM_PAGE);

    match problems(&bytes).as_slice() {
        [
            (
                path,
                error @ (Error::Inflate { entry: 1, .. } | Error::LengthMismatch { entry: 1, .. }),
            ),
        ] => {
            assert_eq!(path, "a", "the problem names the entry's path");
            assert!(
                !matches!(error, Error::TrailingBytes { .. }),
                "a stream that does not decode is not a tail",
            );
        }
        other => panic!("expected the corrupted stream to be caught, got {other:?}"),
    }
}

#[test]
fn a_binary_entry_whose_stream_ends_before_its_payload_is_reported_by_verify() {
    // The read path is shared, so the hole was too: measured 2026-08-28, a
    // deflated binary entry declaring 200 bytes more than its stream occupies
    // verified clean and exit 0, exactly as the resource did.
    let stream = deflate(&[b'x'; ONE_SYSTEM_PAGE_LEN]);
    let tail = 200_u32;
    let declared = stream.len() as u32 + tail;
    let bytes = one_file_archive(&stream, declared, 0, ONE_SYSTEM_PAGE_LEN as u32);

    let used = stream.len() as u64;
    match problems(&bytes).as_slice() {
        [
            (
                path,
                error @ Error::TrailingBytes {
                    entry,
                    declared,
                    used: got,
                },
            ),
        ] => {
            assert_eq!(path, "a", "the problem names the entry's path");
            assert_eq!(
                (*entry, *declared, *got),
                (1, used + u64::from(tail), used),
                "expected the two payload lengths, got {error}"
            );
        }
        other => panic!("expected one trailing-bytes problem, got {other:?}"),
    }
}

#[test]
fn a_payload_that_is_not_deflate_at_all_is_refused() {
    let rows = [directory_row(0, 1, 1), file_row(1, 64, 1, 64, 0)];
    let bytes = archive_bytes(&rows, b"\0a\0", 2_048);

    let archive = Archive::open(&mut Cursor::new(bytes.clone())).expect("well formed");
    let error = archive
        .read(&mut Cursor::new(bytes), 1)
        .expect_err("zeroes are not a deflate stream");
    assert!(
        matches!(error, Error::Inflate { entry: 1, .. }),
        "expected an inflate failure, got {error:?}"
    );
}

#[test]
fn a_resource_declaring_no_compressed_size_is_refused_rather_than_guessed() {
    // The "compressed size 0 means stored" sentinel is a binary entry's, and
    // it works there because offset 8 still holds the real length. A resource
    // has no such field: offsets 8 and 12 are both page flags, so an entry
    // like this one says nothing about how many bytes are on disk.
    // `docs/rpf-format.md` records no measurement of a stored resource, so the
    // container refuses it instead of inventing a rule for recovering it.
    let rows = [
        directory_row(0, 1, 1),
        file_row(1, 0, 1 | RESOURCE_FLAG, 0x8000_0010, 0),
    ];
    let bytes = archive_bytes(&rows, b"\0a\0", 2_048);

    let archive = Archive::open(&mut Cursor::new(bytes.clone())).expect("well formed");
    let error = archive
        .read(&mut Cursor::new(bytes), 1)
        .expect_err("nothing carries this resource's length");
    assert!(
        matches!(
            error,
            Error::ResourceTooSmall {
                entry: 1,
                compressed_len: 0
            }
        ),
        "expected the resource to be refused by size, got {error:?}"
    );
}

// ----- names that do not mean one file below a directory --------------------

#[test]
fn a_name_that_climbs_out_of_the_archive_is_refused_on_read() {
    // The read half of R10.3, pinned at the library boundary rather than at
    // the command line: an archive is third-party data, and the name is what
    // becomes a filesystem path. `specs_of` is the one route from entries to a
    // tree specification, so both `extract` and a rebuild come through here.
    let rows = [directory_row(0, 1, 1), file_row(1, 0, 4, 16, 0)];
    let bytes = archive_bytes(&rows, b"\0../escaped.txt\0", 4_096);

    let archive =
        Archive::open(&mut Cursor::new(bytes)).expect("the archive itself is well formed");
    assert_eq!(
        archive.path(1).expect("the name reads back"),
        "../escaped.txt",
        "the name is readable; it is turning it into a file that is refused"
    );

    let error = rpf_core::specs_of(&archive).expect_err("a name that leaves the tree");
    assert!(
        matches!(
            error,
            Error::BadPath {
                ref path,
                reason: "navigates with . or .. rather than naming a file",
            } if path == "../escaped.txt"
        ),
        "expected the name to be refused as itself, got {error:?}"
    );
    assert!(
        matches!(rpf_core::Manifest::of(&archive), Err(Error::BadPath { .. })),
        "the manifest is derived from the same specification and must agree"
    );
}

#[test]
fn a_directory_whose_name_climbs_out_of_the_archive_is_refused_on_read() {
    // A directory is created before any file is written into it, so it reaches
    // the filesystem first and has to be refused on its own account.
    let rows = [
        directory_row(0, 1, 1),
        directory_row(1, 2, 1),
        file_row(4, 0, 4, 16, 0),
    ];
    let bytes = archive_bytes(&rows, b"\0..\0a\0", 4_096);

    let archive =
        Archive::open(&mut Cursor::new(bytes)).expect("the archive itself is well formed");
    let error = rpf_core::directories_of(&archive).expect_err("a directory that leaves the tree");
    assert!(
        matches!(
            error,
            Error::BadPath {
                ref path,
                reason: "navigates with . or .. rather than naming a file",
            } if path == ".."
        ),
        "expected the directory to be refused as itself, got {error:?}"
    );
}

#[test]
fn a_name_no_host_can_hold_is_still_one_node_of_a_tree() {
    // The tree rules and the host rules are two questions, and only the first
    // is `rebuild`'s. `aux.ytd` is a name Windows opens as a device and a
    // perfectly ordinary node of an archive's own tree, so refusing it at
    // `specs_of` made an archive holding one unrepairable — and the refusal
    // arrived after `put` had already printed `rebuilding`. DR-013's second
    // amendment.
    let rows = [directory_row(0, 1, 1), file_row(1, 0, 4, 16, 0)];
    let bytes = archive_bytes(&rows, b"\0aux.ytd\0", 4_096);
    let mut source = Cursor::new(bytes);
    let archive = Archive::open(&mut source).expect("the archive is well formed");

    let specs = rpf_core::specs_of(&archive).expect("a device name is one node of a tree");
    assert_eq!(specs.len(), 1);
    let mut out = Cursor::new(Vec::new());
    rpf_core::rebuild(
        &mut source,
        &archive,
        &mut out,
        &std::collections::BTreeMap::new(),
        &mut rpf_core::Unwatched,
    )
    .expect("an archive this build can read is an archive it can repair");

    // What is refused is turning it into a tree on a filesystem, which is the
    // manifest in both directions.
    let error = rpf_core::Manifest::of(&archive).expect_err("no host holds AUX");
    assert!(
        matches!(
            error,
            Error::BadPath {
                ref path,
                reason: "has a component that names a Windows device",
            } if path == "aux.ytd"
        ),
        "expected the name to be refused as itself, got {error:?}"
    );
}

#[test]
fn a_name_windows_would_trim_is_still_one_node_of_a_tree() {
    // R10.12, in both of its spellings. Windows drops a trailing dot or space
    // before it opens a name, so `a.txt.` and `a.txt ` are the file `a.txt`
    // there and two more entries here: one archive, two trees. The refusal is
    // a host rule, so the archive stays readable and repairable and only
    // becoming a tree on a filesystem is refused. DR-015.
    for name in [b"a.txt.", b"a.txt "] {
        let mut names = vec![0u8];
        names.extend_from_slice(name);
        names.push(0);
        let rows = [directory_row(0, 1, 1), file_row(1, 0, 4, 16, 0)];
        let bytes = archive_bytes(&rows, &names, 4_096);
        let mut source = Cursor::new(bytes);
        let archive = Archive::open(&mut source).expect("the archive is well formed");

        let spelling = std::str::from_utf8(name).expect("ascii");
        assert_eq!(
            archive.path(1).expect("the name reads back"),
            spelling,
            "the name is readable; it is turning it into a file that is refused"
        );
        assert_eq!(
            rpf_core::specs_of(&archive)
                .expect("a name a host trims is one node of a tree")
                .len(),
            1,
        );
        rpf_core::rebuild(
            &mut source,
            &archive,
            &mut Cursor::new(Vec::new()),
            &std::collections::BTreeMap::new(),
            &mut rpf_core::Unwatched,
        )
        .expect("an archive this build can read is an archive it can repair");

        let error = rpf_core::Manifest::of(&archive).expect_err("Windows trims this name");
        assert!(
            matches!(
                error,
                Error::BadPath {
                    ref path,
                    reason: "has a component ending in a dot or a space, which Windows trims",
                } if path == spelling
            ),
            "expected {spelling:?} to be refused as itself, got {error:?}"
        );
    }
}

// ----- container versions this build does not read --------------------------

/// A sixteen-byte header of `version`, with the fields RPF7 would put there.
///
/// Nothing beyond the magic is read, which is the point: the version is
/// answered from the first four bytes, before any layout is believed.
fn header_of(magic: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&magic);
    out.extend_from_slice(&1_u32.to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes());
    out.extend_from_slice(&ENCRYPTION_OPEN.to_le_bytes());
    out
}

#[test]
fn an_archive_of_another_version_is_refused_by_its_own_name() {
    // All three used to report `not an RPF7 archive` and exit 4, the code for a
    // malformed archive, while the encryption tag four words later already got
    // an honest `NeedsKey`. Nothing about these is malformed. DR-012, R11.1.
    for (magic, version) in [
        (*b"RPF0", 0_u8),
        (*b"RPF2", 2),
        (*b"RPF6", 6),
        (*b"RPF7", 7),
        (*b"8FPR", 8),
    ] {
        let error = Archive::open(&mut Cursor::new(header_of(magic)))
            .expect_err("this build reads RPF7 in its 7FPR spelling only");
        assert!(
            matches!(
                error,
                Error::UnsupportedVersion {
                    base: 0,
                    version: found,
                    ..
                } if found == version
            ),
            "expected RPF{version} to be named, got {error:?}",
        );
        assert!(
            error.to_string().contains(&format!("RPF{version}")),
            "the message must name the version: {error}",
        );
    }
}

#[test]
fn a_version_this_build_cannot_read_is_its_own_category() {
    // Not `Corrupt` — nothing is malformed — and not `Refused`, because the
    // caller's request was fine. It is `NeedsKey`'s shape with a different
    // answer to "who has to act": no key opens it, and the missing part is
    // here. DR-010's amendment.
    let error = Archive::open(&mut Cursor::new(header_of(*b"RPF2"))).expect_err("not RPF7");
    assert_eq!(error.category(), rpf_core::Category::Unsupported);
}

#[test]
fn a_nested_archive_of_another_version_is_named_by_locate_and_invisible_to_info() {
    // DR-010's amendment says `UnsupportedVersion` carries the offset "so a
    // nested archive of another version names where it is". That holds through
    // `locate` and not through `nested_at`, which maps every failure but
    // `TooDeep` to `None` — deliberately, because the sniff must not fail a
    // listing at the first `.txt`. The cost is recorded here rather than
    // changed: `info` reports `nested 0` and `verify` passes clean on this.
    let rows = [directory_row(0, 1, 1), file_row(1, 0, 2, 16, 0)];
    let mut bytes = archive_bytes(&rows, b"\0inner.rpf\0", 4_096);
    let mut header = Vec::new();
    header.extend_from_slice(b"RPF2");
    header.extend_from_slice(&1_u32.to_le_bytes());
    header.extend_from_slice(&2_u32.to_le_bytes());
    header.extend_from_slice(&ENCRYPTION_OPEN.to_le_bytes());
    bytes[1_024..1_024 + header.len()].copy_from_slice(&header);

    let mut source = Cursor::new(bytes);
    let archive = Archive::open(&mut source).expect("the outer archive parses");

    // Through `locate`, the refusal names the version and where it begins.
    let error = archive
        .locate(&mut source, "inner.rpf/anything")
        .expect_err("this build reads no RPF2");
    assert!(
        matches!(
            error,
            Error::UnsupportedVersion {
                base: 1_024,
                version: 2,
                ..
            }
        ),
        "expected the version and its offset, got {error:?}"
    );

    // Through the sniff, it is not there at all. This is the limit, pinned so
    // that changing it is a decision rather than a surprise.
    let summary = rpf_core::Summary::of(&mut source, &archive, "").expect("info summarises");
    assert_eq!(summary.nested_archives, 0, "the sniff swallows the version");
    let verified =
        rpf_core::Verified::of(&mut source, &archive, &mut rpf_core::Unwatched).expect("verify");
    assert!(verified.outcome().is_ok(), "verify reports nothing wrong");
}

#[test]
fn bytes_that_are_not_an_rpf_header_at_all_are_still_not_an_archive() {
    // The version arm must not swallow the case it was carved out of: a file
    // that is not an archive is still `NotAnArchive`, and a file too short to
    // hold a header is too, whatever its first four bytes say.
    let error = Archive::open(&mut Cursor::new(header_of(*b"PK\x03\x04")))
        .expect_err("a zip is not an archive");
    assert!(
        matches!(error, Error::NotAnArchive { base: 0, .. }),
        "expected NotAnArchive, got {error:?}"
    );

    let error = Archive::open(&mut Cursor::new(b"RPF2".to_vec()))
        .expect_err("four bytes cannot hold a header");
    assert!(
        matches!(error, Error::NotAnArchive { base: 0, .. }),
        "expected a truncated file to be refused as not an archive, got {error:?}"
    );
}

#[test]
fn two_children_of_one_directory_that_are_one_name_are_refused_on_read() {
    // `child_named` folds case, so the second of these is unreachable by any
    // spelling of its own path — including its own. `build` has always refused
    // to write such an archive; this is the same rule read back, so an archive
    // that cannot be packed cannot be extracted either. R10.4.
    let rows = [
        directory_row(0, 1, 2),
        file_row(1, 0, 4, 16, 0),
        file_row(7, 0, 5, 16, 0),
    ];
    let bytes = archive_bytes(&rows, b"\0A.txt\0a.txt\0", 4_096);

    let archive = Archive::open(&mut Cursor::new(bytes)).expect("the archive itself parses");
    // Listing still works: refusing at parse would leave a caller unable to see
    // what is wrong with the archive.
    assert_eq!(archive.name(1).expect("name"), "A.txt");
    assert_eq!(archive.name(2).expect("name"), "a.txt");

    let error = rpf_core::specs_of(&archive).expect_err("one name for two entries");
    assert!(
        matches!(
            error,
            Error::NameCollision {
                ref path,
                ref other,
            } if path == "a.txt" && other == "A.txt"
        ),
        "expected both names to be reported, got {error:?}"
    );
}

#[test]
fn a_collision_between_two_directories_is_refused_on_read() {
    // A directory pair collides in exactly the way a file pair does, and it is
    // `directories_of` rather than `specs_of` that would have carried it into a
    // tree — an empty directory survives a round trip through that list alone.
    let rows = [
        directory_row(0, 1, 2),
        directory_row(1, 3, 0),
        directory_row(5, 3, 0),
    ];
    let bytes = archive_bytes(&rows, b"\0X64\0x64\0", 4_096);

    let archive = Archive::open(&mut Cursor::new(bytes)).expect("the archive itself parses");
    let error = rpf_core::directories_of(&archive).expect_err("one name for two directories");
    assert!(
        matches!(
            error,
            Error::NameCollision {
                ref path,
                ref other,
            } if path == "x64" && other == "X64"
        ),
        "expected both names to be reported, got {error:?}"
    );
}

#[test]
fn one_name_carried_by_two_entries_is_not_reported_as_a_case_collision() {
    // The reader used to answer every kind of one-name-twice with
    // `NameCollision`, which for an exact duplicate rendered `"aa.txt" and
    // "aa.txt" are one name here` — one string named twice. The writer has
    // always had three answers for this; the reader now gives the same three.
    let rows = [
        directory_row(0, 1, 2),
        file_row(1, 0, 4, 16, 0),
        file_row(1, 0, 5, 16, 0),
    ];
    let bytes = archive_bytes(&rows, b"\0aa.txt\0", 4_096);
    let archive = Archive::open(&mut Cursor::new(bytes)).expect("parses");
    let error = rpf_core::specs_of(&archive).expect_err("one name for two entries");
    assert!(
        matches!(
            error,
            Error::BadPath {
                ref path,
                reason: "is named twice in one directory",
            } if path == "aa.txt"
        ),
        "expected an exact duplicate to say so, got {error:?}"
    );

    // And a file beside a directory of the same name is the third answer, the
    // one `build` gives as "a file and a directory share one name".
    let rows = [
        directory_row(0, 1, 2),
        file_row(1, 0, 4, 16, 0),
        directory_row(1, 3, 0),
    ];
    let bytes = archive_bytes(&rows, b"\0aa.txt\0", 4_096);
    let archive = Archive::open(&mut Cursor::new(bytes)).expect("parses");
    let error = rpf_core::specs_of(&archive).expect_err("a file and a directory");
    assert!(
        matches!(
            error,
            Error::BadPath {
                ref path,
                reason: "a file and a directory share one name",
            } if path == "aa.txt"
        ),
        "expected the clash of kinds to say so, got {error:?}"
    );
}

#[test]
fn one_name_in_two_directories_is_not_a_collision() {
    // The check is per parent, not per archive. Refusing `a/x.txt` beside
    // `b/x.txt` would reject almost every real archive there is.
    let rows = [
        directory_row(0, 1, 2),
        directory_row(1, 3, 1),
        directory_row(3, 4, 1),
        file_row(5, 0, 8, 16, 0),
        file_row(5, 0, 9, 16, 0),
    ];
    let bytes = archive_bytes(&rows, b"\0a\0b\0x.txt\0", 8_192);

    let archive = Archive::open(&mut Cursor::new(bytes)).expect("parses");
    let specs = rpf_core::specs_of(&archive).expect("two directories, one name each");
    let paths: Vec<String> = specs.into_iter().map(|(spec, _)| spec.path).collect();
    assert_eq!(paths, ["a/x.txt", "b/x.txt"]);
}

#[test]
fn a_name_two_siblings_answer_to_is_refused_rather_than_resolved_to_the_first() {
    // The patch-in-place path never reaches `check_names`: `plan` resolves
    // through `locate`, which folds case and used to take the first match. So
    // `put … a.txt` against this archive patched `A.txt` and reported success.
    // Ambiguity is a property of one resolution, so it is answered where the
    // resolution happens.
    let rows = [
        directory_row(0, 1, 2),
        file_row(1, 0, 4, 16, 0),
        file_row(7, 0, 5, 16, 0),
    ];
    let bytes = archive_bytes(&rows, b"\0A.txt\0a.txt\0", 4_096);
    let archive = Archive::open(&mut Cursor::new(bytes)).expect("the archive itself parses");

    for spelling in ["a.txt", "A.txt", "a.TXT"] {
        let error = archive
            .find(spelling)
            .expect_err("two entries answer to it");
        assert!(
            matches!(
                error,
                Error::NameCollision {
                    ref path,
                    ref other,
                } if path == "a.txt" && other == "A.txt"
            ),
            "{spelling}: expected both names to be reported, got {error:?}",
        );
    }

    // And listing still works, which is why the refusal is not at parse: a
    // caller has to be able to see what is wrong with such an archive.
    assert_eq!(archive.name(1).expect("name"), "A.txt");
    assert_eq!(archive.name(2).expect("name"), "a.txt");
    assert_eq!(archive.children(0).expect("children"), 1..3);
}

#[test]
fn one_name_in_two_directories_still_resolves() {
    // The refusal is per parent. `a/x.txt` and `b/x.txt` are two names, and a
    // lookup of either has exactly one answer.
    let rows = [
        directory_row(0, 1, 2),
        directory_row(1, 3, 1),
        directory_row(3, 4, 1),
        file_row(5, 0, 8, 16, 0),
        file_row(5, 0, 9, 16, 0),
    ];
    let bytes = archive_bytes(&rows, b"\0a\0b\0x.txt\0", 8_192);
    let archive = Archive::open(&mut Cursor::new(bytes)).expect("parses");
    assert_eq!(archive.find("a/x.txt").expect("resolves"), 3);
    assert_eq!(archive.find("b/x.txt").expect("resolves"), 4);
}
