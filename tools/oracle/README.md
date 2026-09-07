---
foreign-paths:
  - "data/*.meta"  # a path inside a game archive, not in this tree
---

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
`rpf-archive` pulls in **61 transitive crates**, among them `image v0.25.10`,
`gltf v1.4.1`, `texture2ddecoder v0.1.2` and `wasm-bindgen v0.2.127`. That is
the typed-asset surface DR-003 excludes, and it is why this stays in `tools/`.

Verified 2026-09-07 against `Cargo.lock` beside this file, unchanged since it
was generated:

```
$ cargo tree --offline --target all --edges normal,build -p rpf-archive \
    --prefix none | sed '/^$/d; s/ (\*)$//' | sort -u | wc -l
      62
```

62 distinct `name version` lines, less `rpf-archive` itself, is 61. The 114
this corrects was two counting errors at once: a tree rooted at the whole crate
rather than at `rpf-archive`, counted by occurrence rather than by distinct
crate, since `cargo tree` prints a crate once under every parent that depends
on it.

```
$ cargo tree --offline --target all --edges normal,build --prefix none \
    | sed '/^$/d' | wc -l
     114
```

Rooted at `rpf-archive` — the same command with `-p rpf-archive` — that
occurrence count is 98, so neither error alone reaches 114. DR-007's amendment
of 2026-09-07 carries the correction. The whole lockfile is 71 `[[package]]`
entries: those 62, plus `oracle` and the eight crates `anyhow`, `serde`,
`serde_json`, `sha2` and `hex` bring that `rpf-archive` does not.

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
  inside it, with each entry's raw fields. This is what the corpus-gated leg of
  `crates/rpf-core/tests/oracle.rs` checks our reader against.
- `files[]` — every leaf file with a checksum of its extracted bytes.
  `generator.extraction_semantics` states exactly what those bytes are, because
  the rule is not the same for both entry kinds and our reader has to match it.

**`files[].path` omits directories.** The reference implementation walks entries
linearly and skips directory entries rather than descending them, so
`data/carvariations.meta` is emitted as `carvariations.meta`. Path construction
is therefore checked against `archives[].entries`, which does carry the
directory records, and not against these paths.

## Limits

No key material, so unencrypted archives only. `GtaKeys::load` wants a
pre-dumped blob, which is the artifact DR-006 declines to hold. That `rpf`
itself takes its keys from the user's own install at run time does not settle
it: nothing routes that material into this crate, so an encrypted archive has no
oracle and gets one only when something does.
