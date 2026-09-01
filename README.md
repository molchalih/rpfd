<img src=".github/banner.svg" alt="rpf" width="820">

# rpf

A dependency-light Rust toolchain for reading, editing and rebuilding RPF7
archives — the `dlc.rpf` files RAGE Multiplayer servers hand to their clients,
and the archives Grand Theft Auto V ships.

`rpf` is a command-line binary with no runtime prerequisite. The same code runs
as a JSON-RPC daemon, and a VS Code extension uses it to open files inside an
archive as ordinary files.

## What it does

- Lists, reads, writes, adds, removes and renames entries, addressing through
  archives nested inside archives with a single path.
- Opens and writes back encrypted archives, both the AES and the NG transform.
- Converts the three binary metadata encodings — `RBF`, `PSO` and the
  resource-embedded `Meta` — to XML, and reads the XML back into the entry.
- Patches an edit in place when the new payload fits where the entry sits, and
  rebuilds the archive when it does not. It says which of the two it did.
- Extracts an archive to a directory tree, packs a tree back into an archive,
  and verifies an archive against the checksums the extraction recorded.
- Reports as JSON on every command, and answers the same objects over
  JSON-RPC.

## Installing

There is no published release yet, so build from source. The Rust toolchain is
pinned in `rust-toolchain.toml`; nothing else is needed.

```
git clone <this repository> && cd rpf
cargo build --release          # target/release/rpf
```

Put `target/release/rpf` somewhere on your `PATH`.

## Usage

List an archive, descending into the archives inside it:

```
$ rpf ls -R dlc.rpf
binary    xml          2199  content.xml
directory -               3  data
binary    xml          1445  data/carvariations.meta
binary    xml           191  data/dlctext.meta
binary    xml          5100  data/vehicles.meta
binary    xml           559  setup2.xml
directory -               2  x64
directory -               1  x64/vehiclemods
binary    -         2544128  x64/vehiclemods/meringls63amg24_mods.rpf
resource  -          262144  x64/vehiclemods/meringls63amg24_mods.rpf/meringls63amg24_brabus_diffuser_1.yft
...
```

Read a binary metadata entry as XML. The second column of a listing says what
an entry holds; `pso`, `rbf` and `meta` entries have an XML view:

```
$ rpf cat --as xml des_hosp_ceil2.rpf des_hosp_ceil2.ytyp
<?xml version="1.0" encoding="UTF-8"?>
<hash_D98BB561 pso:struct="hash_D98BB561">
  <hash_F17E7F28 pso:array="atarray"/>
  <hash_018A3B1B pso:array="atarray">
    <pso:item pso:struct="hash_82D6FC83">
      <hash_BF74DFA7 pso:float="100.0"/>
      <hash_67D26872 pso:uint="0"/>
      <hash_6C1523E4 pso:uint="0"/>
      <hash_D9EF8236 pso:float3="-2.80584, -2.95097, 0.0"/>
      <hash_E78AA618 pso:float3="2.80584, 2.95097, 3.0961"/>
      <hash_E6E17F14 pso:string.counted="DES_Hosp_Ceil2"/>
      <hash_75D215A1 pso:string.counted="DES_Hosp_Ceil2_txd"/>
...
```

`rpf put --as xml` takes an edited document and writes it back in the entry's
own encoding. Ask first what a write would cost, then make it:

```
$ rpf put dlc.rpf data/vehicles.meta edited.meta --dry-run
would patch 1637 bytes in place at 2048 (room for 2048)

$ rpf put dlc.rpf data/vehicles.meta edited.meta
patched 1637 bytes in place at 2048 (room for 2048)
```

Adding, removing or renaming an entry moves every offset after the header, so
those always rebuild — `put --create`, `rm`, `mv` and `mkdir` say so before
they start. A rebuild is atomic: it writes a scratch file beside the archive
and replaces the original in one step.

Take an archive apart, build it back, and check the result against what the
extraction recorded:

```
$ rpf extract dlc.rpf tree/
7 files and 3 directories into tree/

$ rpf pack tree/ rebuilt.rpf
11 entries, 65160704 bytes

$ rpf verify rebuilt.rpf --against tree/
27 entries read back; 7 of 7 recorded checksums checked against tree/
20 entries carry no recorded checksum: an entry inside a nested archive is covered by the checksum of the entry that holds it
```

Every reporting command also takes `--json`.

## Encrypted archives

An AES-encrypted archive needs the RAGE AES-256 key and the NG hash lookup
table. An NG-encrypted archive needs 373 values beyond those. **No key material
is bundled here, and none ever will be.** It is found in your own game
installation, identified by the hash of each value's own bytes, and cached
under the hash of the file it came from:

```
$ rpf keys extract /path/to/GTA5.exe
source      /path/to/GTA5.exe
sha256      677e4e355cfbdb13273b1d992407e3c261b3a108dc4dd5c8a0c4c1da651802e5
found in    this source
aes key     32 bytes at 0x1e34c98
hash lut    256 bytes at 0x1b7bcc0
ng material not in this source (an executable never carries it; it is in the clear only in a memory image of a running game)
cache       /Users/you/Library/Application Support/rpf/keys
```

No command prints a key: what is reported is offsets, lengths, counts and
paths. Once material is cached, every command that opens an archive finds it —
there is no flag to pass. `--cache-dir` names a different cache, which is how
several installations are kept apart.

The AES material is in the game executable. The NG material is not: on disk it
is transformed, and it is in the clear only in the loaded image of a running
game, so extracting it means pointing `rpf keys extract` at a memory image or a
process dump rather than at the executable. An executable that carries no NG
material is not an error, and everything outside the NG archives opens without
it.

## The daemon

`rpf serve --stdio` speaks JSON-RPC over standard input and output, one object
per line. It answers everything the binary does, holds edits in a buffer until
`commit`, reports the progress of a long rebuild as notifications, and can be
cancelled mid-rebuild.

```
$ echo '{"jsonrpc":"2.0","id":1,"method":"open","params":{"path":"/tmp/dlc.rpf"}}' | rpf serve --stdio
{"id":1,"jsonrpc":"2.0","result":{"entries":11,"handle":1,"len":144504832,"path":"/tmp/dlc.rpf"}}
```

## The editor extension

`clients/vscode` mounts an archive as a workspace folder. Files below it open,
edit and save like any other file, an archive nested inside one is a folder
inside a folder, and the archive itself is written by one explicit act — with a
preview of whether that act would patch or rebuild. It holds no format
knowledge of its own; everything it does it asks the daemon for.
`clients/vscode/README.md` has the details.

## Exit codes

Stable, so a caller can classify a failure without reading the message. The
daemon reports the same numbers as a JSON-RPC `error.code`, alongside a
symbolic `error.data.reason`.

| Code | Meaning |
|---|---|
| 0 | Everything worked |
| 1 | A failure with no better classification |
| 2 | The arguments were wrong |
| 3 | The path is not in the archive |
| 4 | The archive is malformed or does not decompress as it promises |
| 5 | The archive needs key material that is not available |
| 6 | The request or its input was wrong, and the tool declined to act |
| 7 | Reading or writing failed |
| 8 | The caller stopped the operation part-way |
| 9 | This build cannot do it |

## Building and testing

```
cargo build --release
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

The test suite needs no game data and passes without it, skipping what it
cannot reach. Four environment variables point it at real data, and each has a
companion that turns its own skips into failures:

| Variable | Names |
|---|---|
| `RPF_CORPUS` | a directory of `.rpf` archives |
| `RPF_GAME_EXE` | a directory of game executables, for key extraction |
| `RPF_GAME_IMAGE` | one memory image of a running game, the only source NG material is found in |
| `RPF_METADATA` | a directory of metadata payloads already out of their archives, written by `tools/metadata-dump` |

```
RPF_CORPUS=/path/to/corpus RPF_REQUIRE_CORPUS=1 cargo test --all
```

## Licence

`MIT OR Apache-2.0`, at your option. See `LICENSE-MIT` and `LICENSE-APACHE`.
