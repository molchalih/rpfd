# metadata-dump

Writes the dump `RPF_METADATA` names: every `PSO`, `RBF` and resource `Meta`
payload in a corpus, out of its archives and onto disk.

Run by hand, once per corpus, like `tools/oracle`. Unlike the oracle it links
nothing but `rpf-core`, so it is a workspace member and the lint set, the
formatter and `clippy --all-targets` reach it.

## Running it

```
cargo run --release -p metadata-dump -- [--kinds pso,rbf,meta] [--cache-dir DIR] <corpus> <out>
```

`<corpus>` is walked recursively for `*.rpf`, and every archive nested inside
one is descended into. `<out>` is created if absent. With no `--kinds` all
three are written; `--kinds meta` is the 2.85 GB arm on its own.

An encrypted archive needs the key material `rpf` caches — `--cache-dir` names
a cache, and without it the platform's own is consulted. An archive that will
not open, an entry that will not read back and a nested archive whose key is
not held are each reported by path and stepped over; the summary counts them.

## What the names mean

```
00002_sys8192_gtav_dlc.rpf_x64_data_des_canister.ytyp
^^^^^ ^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
index system   where it came from, with `/` flattened to `_`
      pages
```

A dumped file's **contents are exactly the payload** — inflated, with no
container framing and nothing prepended — because everything that reads this
dump reads payload bytes: the fuzz targets seed their corpora straight out of
it and `rpf_core::metadata::meta::parse` takes a payload.

The `sys` field is on resource `Meta` payloads and on nothing else. It is
there because a `Meta` is *paged* — system pages, then graphics pages — and
every resource pointer in the file resolves against the boundary between the
two. That boundary is the entry's, from
`rpf_core::format::resource::size_from_flags` of its system flags, and it
appears **nowhere in the payload**: without it a dumped `Meta` cannot be parsed
at all. `src/lib.rs` says why it is carried in the name rather than in a
sidecar or a header, and is the one place either half of the convention is
written — `crates/rpf-core/tests/metadata.rs` reads it back through
`metadata_dump::system_len_of`.

The index makes a name unique and is otherwise not meaningful. It is assigned
in walk order, so **names are not stable across runs**: what a test keys on is
the payload's `sha256`, which is what `fixtures/*-metadata.json` records.
