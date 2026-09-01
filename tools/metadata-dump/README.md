# metadata-dump

Writes the metadata dump the `RPF_METADATA` test variable names: every `PSO`,
`RBF` and resource `Meta` payload in a corpus of archives, out of its archive
and onto disk. Run it once per corpus; the test suite and the fuzz targets read
what it leaves behind.

## Running it

```
cargo run --release -p metadata-dump -- [--kinds pso,rbf,meta] [--cache-dir DIR] <corpus> <out>
```

`<corpus>` is walked recursively for `*.rpf`, and every archive nested inside
one is descended into. `<out>` is created if it does not exist. With no
`--kinds` all three are written; `meta` alone is by far the largest of the
three.

It prints a count per kind and a summary:

```
$ cargo run --release -p metadata-dump -- corpus/ dump/
1 meta
2 pso
3 payloads, 10412 bytes, 0 refused, 0 locked
```

An encrypted archive needs the key material `rpf` caches. `--cache-dir` names a
cache; without it the platform's own is used. An archive that will not open, an
entry that will not read back and a nested archive whose key is not held are
each reported by path and stepped over, and counted in the summary.

## What the names mean

```
00002_sys8192_des_canister.rpf_des_canister.ytyp
^^^^^ ^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
index system   where it came from, with `/` flattened to `_`
      pages
```

A dumped file's contents are exactly the payload — inflated, with no container
framing and nothing prepended — because everything that reads this dump reads
payload bytes.

The `sys` field appears on resource `Meta` payloads and on nothing else. A
`Meta` is paged, system pages first and then graphics pages, and every resource
pointer in the file resolves against the boundary between the two. That
boundary belongs to the archive entry and appears nowhere in the payload, so
without it a dumped `Meta` cannot be parsed at all. Carrying it in the file name
keeps the dump one file per payload, with no sidecar to lose.

The index makes a name unique and means nothing else. It is assigned in walk
order, so **names are not stable between runs**: what a test keys on is the
payload's SHA-256, which is what `fixtures/*-metadata.json` records.
