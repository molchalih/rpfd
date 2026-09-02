# oracle

Runs the reference implementation over an archive and writes down what it saw,
so that our reader can be checked against something that is not us.

## Why it is outside the workspace

DR-007: the reference implementation is an oracle, never a dependency. This
crate links it, so it is excluded from the workspace and never built by
continuous integration. What gets committed is its **output**, under
`fixtures/`, and what continuous integration builds is that output rather than
this crate: `crates/rpf-core/tests/oracle.rs` re-emits every fixture from its
own content and, where a corpus is in reach, rebuilds it from the archive it
names and compares byte for byte. Once a fixture exists the crate is not needed
again until the corpus changes.

It is worth knowing what linking it costs, since that cost is the argument:
`rpf-archive` pulls in 114 transitive crates, among them `image`, `gltf`,
`texture2ddecoder` and `wasm-bindgen`. That is the typed-asset surface DR-003
excludes, and it is why this stays in `tools/`.

## Running it

Both arguments are required: the corpus root, and the archive's path under it.
The second is what the fixture records, so a fixture always says which archive
it describes and can be rebuilt from it.

```
cd tools/oracle
cargo run --release -- /path/to/corpus <dir>/<archive>.rpf > ../../fixtures/<name>.json
```

## What the output means

- `source.path` — where the archive sits under `RPF_CORPUS`. What
  `crates/rpf-core/tests/oracle.rs` locates the archive by.
- `archives[]` — the entry table of the archive and of every archive nested
  inside it, with each entry's raw fields. This is what R3.1–R3.5 check against.
- `files[]` — every leaf file with a checksum of its extracted bytes.
  `generator.extraction_semantics` states exactly what those bytes are, because
  the rule is not the same for both entry kinds and our reader has to match it.

**`files[].path` omits directories.** The reference implementation walks entries
linearly and skips directory entries rather than descending them, so
`data/carvariations.meta` is emitted as `carvariations.meta`. Path construction
(R3.2) is therefore checked against `archives[].entries`, which does carry the
directory records, and not against these paths.

## Limits

No key material, so unencrypted archives only. `GtaKeys::load` wants a
pre-dumped blob, which is the artifact DR-006 declines to hold. Encrypted
archives get an oracle once R2 can supply material extracted from the user's own
install, and not before.
