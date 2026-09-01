//! Real `RBF`, `PSO` and `Meta` payloads, and the documents they convert to.
//! Shared by both frontends' tests; each payload is built here, from no game data.
#![allow(
    dead_code,
    reason = "each including test crate gets its own copy of this module and \
              uses the part of it that its frontend needs"
)]
#![allow(
    clippy::expect_used,
    reason = "test scaffolding; a panic is the reporting mechanism. \
              docs/conventions.md §15"
)]
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "the `Meta` builder writes at offsets the fixture itself states, \
              and an offset outside the buffer it just allocated is a bug in \
              the fixture that must fail the test loudly. docs/conventions.md \
              §15"
)]

use std::path::Path;

/// The document [`rbf_payload`] is built from, and converts back to: one string
/// attribute and one value record, whose types no spelling distinguishes.
pub const RBF_DOCUMENT: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                                <Root name=\"hello\">\n  \
                                <count rbf:uint=\"7\"/>\n\
                                </Root>\n";

/// The same document with its one value changed, which is what an edit is.
pub const RBF_EDITED: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                              <Root name=\"hello\">\n  \
                              <count rbf:uint=\"9\"/>\n\
                              </Root>\n";

/// The document [`minimal_pso`] converts to, with the empty dictionary that is
/// the only one this repository ships.
pub const PSO_DOCUMENT: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                                <hash_D98BB561 pso:struct=\"hash_D98BB561\">\n  \
                                <hash_12345678 pso:uint=\"7\"/>\n\
                                </hash_D98BB561>\n";

/// The same, with the one value edited.
pub const PSO_EDITED: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                              <hash_D98BB561 pso:struct=\"hash_D98BB561\">\n  \
                              <hash_12345678 pso:uint=\"9\"/>\n\
                              </hash_D98BB561>\n";

/// A real `RBF` payload, written by the crate's own serialiser from `document`.
pub fn rbf_payload(document: &str) -> Vec<u8> {
    rpf_core::metadata::rbf::from_xml(document.as_bytes()).expect("the fixture is an RBF document")
}

/// The name hash of the one structure [`minimal_pso`] defines.
const ROOT_NAME: u32 = 0xD98B_B561;

/// The name hash of its one member.
const MEMBER_NAME: u32 = 0x1234_5678;

/// A minimal valid `PSO`: one block, one structure, one `UINT` member. Built by
/// hand, because a payload built by the reader's own model shares its bugs.
pub fn minimal_pso() -> Vec<u8> {
    let mut psin = Vec::new();
    psin.extend_from_slice(&rpf_core::metadata::pso::MAGIC);
    psin.extend_from_slice(&20u32.to_be_bytes());
    psin.extend_from_slice(b"pppppppp"); // docs/metadata-encodings.md: not zero
    psin.extend_from_slice(&7u32.to_be_bytes()); // the member's value

    let mut pmap = Vec::new();
    pmap.extend_from_slice(b"PMAP");
    pmap.extend_from_slice(&32u32.to_be_bytes());
    pmap.extend_from_slice(&1i32.to_be_bytes()); // rootId, 1-based
    pmap.extend_from_slice(&1i16.to_be_bytes()); // entriesCount
    pmap.extend_from_slice(&0x7070u16.to_be_bytes()); // unknown_Eh
    pmap.extend_from_slice(&ROOT_NAME.to_be_bytes());
    pmap.extend_from_slice(&16i32.to_be_bytes()); // offset, from the PSIN header
    pmap.extend_from_slice(&0i32.to_be_bytes()); // unknown_8h
    pmap.extend_from_slice(&4i32.to_be_bytes()); // length

    let mut psch = Vec::new();
    psch.extend_from_slice(b"PSCH");
    psch.extend_from_slice(&44u32.to_be_bytes());
    psch.extend_from_slice(&1u32.to_be_bytes()); // count
    psch.extend_from_slice(&ROOT_NAME.to_be_bytes());
    psch.extend_from_slice(&20i32.to_be_bytes()); // where the entry is
    psch.extend_from_slice(&1u32.to_be_bytes()); // packed: structure, 1 member
    psch.extend_from_slice(&4i32.to_be_bytes()); // structureLength
    psch.extend_from_slice(&0u32.to_be_bytes()); // unk_Ch
    psch.extend_from_slice(&MEMBER_NAME.to_be_bytes());
    psch.extend_from_slice(&[0x06, 0x00]); // UINT, subtype 0
    psch.extend_from_slice(&0u16.to_be_bytes()); // dataOffset
    psch.extend_from_slice(&0u32.to_be_bytes()); // referenceKey

    let mut payload = psin;
    payload.extend_from_slice(&pmap);
    payload.extend_from_slice(&psch);
    payload
}

/// Every encoding a frontend has to show reading and writing as XML, as
/// (payload, document, edited document, the encoding's name on the wire).
pub fn tokenised() -> Vec<(Vec<u8>, &'static str, &'static str, &'static str)> {
    vec![
        (rbf_payload(RBF_DOCUMENT), RBF_DOCUMENT, RBF_EDITED, "rbf"),
        (minimal_pso(), PSO_DOCUMENT, PSO_EDITED, "pso"),
    ]
}

// ---------------------------------------------------------------------------
// Resource-embedded `Meta`: the encoding that is not a payload with a magic.
// ---------------------------------------------------------------------------

/// The flag words the `Meta` fixture's entry declares: one 512-byte system page
/// and no graphics pages. The top nibbles are the resource version.
pub const META_FLAGS: rpf_core::ResourceFlags = rpf_core::ResourceFlags {
    system: 0xA800_0000,
    graphics: 0x2000_0000,
};

/// The same 512 bytes with the boundary declared in the wrong place: only the
/// sum is checked, and every pointer is resolved against the system half.
pub const META_ELSEWHERE: rpf_core::ResourceFlags = rpf_core::ResourceFlags {
    system: 0x2000_0000,
    graphics: 0xA800_0000,
};

/// The document [`minimal_meta`] converts to, with the empty dictionary.
pub const META_DOCUMENT: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                                 <hash_D98BB561 meta:struct=\"hash_D98BB561\">\n  \
                                 <hash_12345678 meta:uint=\"7\"/>\n\
                                 </hash_D98BB561>\n";

/// The same, with the one value edited.
pub const META_EDITED: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                               <hash_D98BB561 meta:struct=\"hash_D98BB561\">\n  \
                               <hash_12345678 meta:uint=\"9\"/>\n\
                               </hash_D98BB561>\n";

/// A `Meta` payload under construction, stating the bytes it means.
struct MetaBytes(Vec<u8>);

impl MetaBytes {
    fn put(&mut self, at: usize, bytes: &[u8]) -> &mut Self {
        self.0[at..at + bytes.len()].copy_from_slice(bytes);
        self
    }

    fn u16(&mut self, at: usize, value: u16) -> &mut Self {
        self.put(at, &value.to_le_bytes())
    }

    fn u32(&mut self, at: usize, value: u32) -> &mut Self {
        self.put(at, &value.to_le_bytes())
    }

    fn u64(&mut self, at: usize, value: u64) -> &mut Self {
        self.put(at, &value.to_le_bytes())
    }
}

/// A system-space resource pointer at `offset`.
fn meta_system(offset: u32) -> u64 {
    (5_u64 << 28) | u64::from(offset)
}

/// The smallest `Meta` that reaches a value: one structure of one `UINT`, one
/// data block holding it, in exactly one 512-byte system page.
pub fn minimal_meta() -> Vec<u8> {
    let mut payload = MetaBytes(vec![0_u8; 512]);
    payload
        // The header: the `Meta` magic at 0x10 and version two at 0x14.
        .u32(0x00, 0xDEAD_BEEF)
        .u32(0x04, 1)
        .u32(0x10, rpf_core::metadata::meta::MAGIC)
        .u32(0x14, rpf_core::metadata::meta::VERSION_TWO)
        .u32(0x1C, 1)
        .u64(0x20, meta_system(0x50))
        .u64(0x30, meta_system(0xA0))
        .u16(0x48, 1)
        .u16(0x4C, 1)
        // The structure: name, name2, kind, membersPtr, length, count.
        .u32(0x50, 0xD98B_B561)
        .u32(0x54, 0xD98B_B561)
        .u32(0x58, 0x300)
        .u64(0x60, meta_system(0x70))
        .u32(0x68, 4)
        .u16(0x6E, 1)
        // Its one member: a `UINT` at offset 0.
        .u32(0x70, 0x1234_5678)
        .u32(0x74, 0)
        .put(0x78, &[0x15, 0x00])
        // The block table, and the block.
        .u32(0xA0, 0xD98B_B561)
        .u32(0xA4, 4)
        .u64(0xA8, meta_system(0xB0))
        .u32(0xB0, 7);
    payload.0
}

/// [`minimal_meta`] as the **file outside the archive**: no `RSC7` header, 24
/// bytes that are not a deflate stream either, then the contents deflated.
pub fn meta_resource() -> Vec<u8> {
    use std::io::Write as _;
    let mut payload = vec![0xFF_u8; 24];
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(&minimal_meta())
        .expect("the page deflates");
    payload.extend_from_slice(&encoder.finish().expect("the encoder finishes"));
    payload
}

// ---------------------------------------------------------------------------
// An AES-tagged archive holding a **keyed** resource: what is planted below is
// thirty-two zero bytes and a table of zeros — not a key, and derived from none.
// ---------------------------------------------------------------------------

/// The bytes of a hexadecimal digest.
fn from_hex(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16).expect("hexadecimal")
        })
        .collect()
}

/// Plants material whose every value is zero in `at`, and answers the cache it
/// planted it in — written by hand, since nothing outside `rpf-core` builds one.
pub fn zeroed_cache(at: &Path) -> rpf_core::keys::Cache {
    let payload = vec![
        0_u8;
        rpf_core::keys::AES_KEY_LEN
            .saturating_add(rpf_core::keys::HASH_LUT_LEN)
            .saturating_add(16)
    ];
    let digest = rpf_core::keys::SourceDigest::of(&mut std::io::Cursor::new(&payload))
        .expect("the payload digests");
    let mut file = b"RPFKEYS\0".to_vec();
    file.extend_from_slice(&2_u32.to_le_bytes());
    file.extend_from_slice(&u32::try_from(payload.len()).expect("fits").to_le_bytes());
    file.extend_from_slice(&from_hex(&digest.hex()));
    file.extend_from_slice(&payload);
    std::fs::create_dir_all(at).expect("the cache directory is creatable");
    std::fs::write(at.join(format!("{}.keys", "a".repeat(64))), file).expect("writable");
    rpf_core::keys::Cache::at(at)
}

/// The forward transform an archive tagged AES is written under, from whatever
/// `cache` holds.
pub fn zeroed_seal(cache: &rpf_core::keys::Cache) -> rpf_core::format::crypto::Seal {
    let material = cache
        .materials()
        .expect("the cache reads back")
        .into_iter()
        .next()
        .expect("the cache holds the material that was planted in it");
    let scheme = rpf_core::Version::Rpf7
        .scheme(rpf_core::format::rpf7::ENCRYPTION_AES)
        .expect("the AES tag has a scheme");
    // The AES key is the tag's and nothing else, so the name and length a seal
    // is keyed by are ignored on this arm.
    rpf_core::format::crypto::Seal::new(scheme, &material, "", 0).expect("AES seals")
}

/// [`meta_resource`] behind `prefix` opaque bytes, with its **stream** under
/// `seal` — sealed from the stream's own start, where the reader counts from.
pub fn keyed_meta_resource(seal: &rpf_core::format::crypto::Seal, prefix: usize) -> Vec<u8> {
    use std::io::Write as _;
    let mut payload = vec![0xFF_u8; prefix];
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(&minimal_meta())
        .expect("the page deflates");
    payload.extend_from_slice(&encoder.finish().expect("the encoder finishes"));
    seal.apply(payload.get_mut(prefix..).expect("the stream is there"));
    payload
}

/// An AES-tagged archive at `at` holding one resource, `data/thing.ymt`, whose
/// payload is under the archive's own transform behind `prefix` opaque bytes.
pub fn make_keyed_meta_archive(at: &Path, cache: &Path, prefix: usize) {
    let cache = zeroed_cache(cache);
    let payload = keyed_meta_resource(&zeroed_seal(&cache), prefix);
    let specs = [rpf_core::FileSpec {
        path: "data/thing.ymt".to_owned(),
        kind: rpf_core::FileKind::Resource {
            declared: Some(META_FLAGS),
        },
    }];
    let fetch = |_: &str| Ok(std::io::Cursor::new(payload.clone()));

    let mut plain = std::io::Cursor::new(Vec::new());
    rpf_core::build(
        &mut plain,
        rpf_core::Version::Rpf7,
        &specs,
        &[],
        fetch,
        &mut rpf_core::Unwatched,
    )
    .expect("the plain archive builds");
    let mut plain = std::io::Cursor::new(plain.into_inner());
    let archive = rpf_core::Archive::open(&mut plain, &rpf_core::Unlock::unkeyed())
        .expect("the plain archive opens");
    let mut manifest = rpf_core::Manifest::of(&archive).expect("the manifest derives");
    manifest.encryption = rpf_core::format::rpf7::ENCRYPTION_AES;

    let name = at
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut out = std::fs::File::create(at).expect("creatable");
    manifest
        .pack_into(
            &mut out,
            &rpf_core::Unlock::cached(cache, name),
            fetch,
            &mut rpf_core::Unwatched,
        )
        .expect("the sealed archive packs");
}
