<img src=".github/banner.svg" alt="rpf" width="800">

A dependency-light Rust toolchain for reading, editing and rebuilding RPF7
archives — the `dlc.rpf` files RAGE Multiplayer and FiveM servers hand to their
clients, and the archives Grand Theft Auto V ships. One command-line binary with
no runtime prerequisite; the same code serves JSON-RPC, which a VS Code
extension uses to open entries as ordinary files.

## Formats

| Version | Variant | Used by | Support |
|---|---|---|---|
| RPF7 | `OPEN`, unencrypted | RAGE MP and FiveM server packs | Read, write |
| RPF7 | AES-256, `0x0FFFFFF9` | GTA V, nested archives such as `des_*` and `script_*` | Read, write — key from the game executable |
| RPF7 | AES-256, `0x0FFFFFF7` | Rockstar Games Launcher | Read, write — key from `Launcher.exe` |
| RPF7 | NG, `0x0FEFFFFF` | GTA V Legacy and Enhanced, every top-level archive: 179 of 179 each | Read, write — both need a memory image |
| RPF8 | — | Red Dead Redemption 2 | Not supported; its codec is Oodle |
| RPF6 | — | Red Dead Redemption, 2010 and 2023 | Not supported |
| RPF4 | — | Max Payne 3 | Not supported |
| RPF3 | — | GTA IV audio, Midnight Club: LA | Not supported |
| RPF2 | — | GTA IV, main archives | Not supported |
| RPF0 | — | Table Tennis | Not supported |

Pre-RPF7 attributions are read from other implementations, not measured here;
`docs/rpf-format.md` records them and where those implementations disagree.
Every non-RPF7 version is recognised by its magic word and refused by number.

Encryption is per entry as well as per archive: the tag covers the table of
contents and the names blob, and each entry's row says whether its own payload
is under the transform.

## Installing

Prebuilt binaries for macOS, Windows and Linux are attached to each release. To
build from source instead — the toolchain is pinned in `rust-toolchain.toml`:

```
git clone <this repository> && cd rpf
cargo build --release          # target/release/rpf
```

Encrypted archives need key material, which is extracted from your own
installation:

```
$ rpf keys extract GTA5.exe         # the AES key and the hash lookup table
$ rpf keys extract Launcher.exe     # the second AES key, carried by no game executable
$ rpf keys extract <memory image>   # the NG expanded keys and decrypt tables
```

No key material is bundled here, and none ever will be. Each source is cached
under the hash of its own bytes in `./keys`, which every command that opens an
archive consults without a flag; `--cache-dir` selects another cache, and is the
one way to keep several installations apart. `rpf keys invalidate` empties a
cache. No command prints a key — only offsets, lengths, counts and paths. NG
material stands in the clear only in a memory image of a running game, which is
therefore the sole route to an NG archive; obtaining such an image is out of
scope here. An archive whose material is absent fails rather than guessing.

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

The second column says what an entry holds; `pso`, `rbf` and `meta` entries have
an XML view:

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
...
```

`rpf put --as xml` takes an edited document and writes it back in the entry's
own encoding. Ask what a write would cost, then make it:

```
$ rpf put dlc.rpf data/vehicles.meta edited.meta --dry-run
would patch 1632 bytes in place at 2048 (room for 2048)

$ rpf put dlc.rpf data/vehicles.meta edited.meta
patched 1632 bytes in place at 2048 (room for 2048)
```

`put --create`, `rm`, `mv` and `mkdir` move every offset after the header, so
they always rebuild and say so first. A rebuild is atomic: a scratch file beside
the archive replaces the original in one step.

Take an archive apart, build it back, check the result:

```
$ rpf extract dlc.rpf tree/
7 files and 3 directories into tree/

$ rpf pack tree/ rebuilt.rpf
11 entries, 65160704 bytes

$ rpf verify rebuilt.rpf --against tree/
27 entries read back; 7 of 7 recorded checksums checked against tree/
20 entries carry no recorded checksum: an entry inside a nested archive is covered by the checksum of the entry that holds it
```

Every reporting command takes `--json`. `rpf --help` lists the rest, and
`clients/agent/README.md` is the page for driving the tool from a program: the
JSON shapes, what each exit code means for a caller, the failure object `--json`
answers with, and `cat --out` for a payload nobody is going to read.

## The daemon

`rpf serve --stdio` speaks JSON-RPC over standard input and output, one object
per line. It answers everything the binary does, holds edits until `commit`, and
reports a long rebuild's progress as cancellable notifications.

```
$ echo '{"jsonrpc":"2.0","id":1,"method":"open","params":{"path":"/tmp/dlc.rpf"}}' | rpf serve --stdio
{"id":1,"jsonrpc":"2.0","result":{"entries":11,"handle":1,"len":144504832,"path":"/private/tmp/dlc.rpf"}}
```

## The editor extension

`clients/vscode` mounts an archive as a workspace folder: files below it open,
edit and save like any other, a nested archive is a folder inside a folder, and
the archive itself is written by one explicit act, previewed as patch or
rebuild. See `clients/vscode/README.md`.

## Exit codes

Stable, so a caller can classify a failure without reading the message. The
daemon reports the same numbers as a JSON-RPC `error.code`, alongside a symbolic
`error.data.reason`.

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

The suite needs no game data and passes without it, skipping what it cannot
reach. Four variables point it at real data: `RPF_CORPUS` at a directory of
archives, `RPF_GAME_EXE` at a directory of game executables, `RPF_GAME_IMAGE` at
one memory image of a running game, and `RPF_METADATA` at metadata payloads
already out of their archives, as `tools/metadata-dump` writes them. Each has a
companion — `RPF_REQUIRE_CORPUS` and its three siblings — that turns its own
skips into failures.

## Licence

`MIT OR Apache-2.0`, at your option. See `LICENSE-MIT` and `LICENSE-APACHE`.
