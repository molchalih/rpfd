<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/banner-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset=".github/banner-light.svg">
  <img src=".github/banner-light.svg" alt="rpfd" width="800">
</picture>

[![release](https://img.shields.io/github/v/release/molchalih/rpfd?style=for-the-badge&logo=github&logoColor=white)](https://github.com/molchalih/rpfd/releases/latest)
[![rust 1.98+](https://img.shields.io/badge/rust-1.98%2B-000000?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org)
[![VS Code](https://vsmarketplacebadges.dev/version-short/molchalih.rpfd.svg?style=for-the-badge&label=VS%20Code&color=0098FF)](https://marketplace.visualstudio.com/items?itemName=molchalih.rpfd)
[![Open VSX](https://img.shields.io/open-vsx/v/molchalih/rpfd?style=for-the-badge&label=Open%20VSX&logo=eclipseide&logoColor=white)](https://open-vsx.org/extension/molchalih/rpfd)

</div>

A dependency-light Rust toolchain for reading, editing and rebuilding RPF7
archives — the `dlc.rpf` files RAGE Multiplayer and FiveM servers hand to their
clients, and the archives Grand Theft Auto V ships. One command-line binary with
no runtime prerequisite, and the same code behind a JSON-RPC daemon and a VS
Code extension.

**The editor extension installs from the store**, so updates arrive by
themselves: `molchalih.rpfd` on the
[VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=molchalih.rpfd)
and on [Open VSX](https://open-vsx.org/extension/molchalih/rpfd), or
`code --install-extension molchalih.rpfd`.

**Asked to install this?** An agent follows
[the procedure in `INSTALL.md`](INSTALL.md#installing-everything-as-an-agent):
the binary on `PATH` first, then `rpf` registered with every client the machine
has.

## Formats

| Version | Variant | Used by | Support |
|---|---|---|---|
| RPF7 | `OPEN`, unencrypted | RAGE MP and FiveM server packs | Read, write |
| RPF7 | AES-256, `0x0FFFFFF9` | GTA V, nested archives such as `des_*` and `script_*` | Read, write — key from the game executable |
| RPF7 | AES-256, `0x0FFFFFF7` | Rockstar Games Launcher | Read, write — key from `Launcher.exe` |
| RPF7 | NG, `0x0FEFFFFF` | GTA V Legacy and Enhanced, every top-level archive | Read, write — both need a memory image |
| RPF8 | — | Red Dead Redemption 2 | Not supported |
| RPF6 | — | Red Dead Redemption, 2010 and 2023 | Not supported |
| RPF4 | — | Max Payne 3 | Not supported |
| RPF3 | — | GTA IV audio, Midnight Club: LA | Not supported |
| RPF2 | — | GTA IV, main archives | Not supported |
| RPF0 | — | Table Tennis | Not supported |

Pre-RPF7 attributions are read from other implementations, not measured here,
and are recorded with their disagreements in the format notes. Every non-RPF7
version is recognised by its magic word and refused by number.

Encryption is per entry as well as per archive: the tag covers the table of
contents and the names blob, and each entry's row says whether its payload is
under the transform.

## Installing

`INSTALL.md` is the page for this, and it answers three separate questions: how
to install the editor extension — from the VS Code Marketplace or Open VSX, with
a `.vsix` as the fallback — how to register the MCP server with an editor or an
agent, and where to put the binary if that is all you want.
It ends with the procedure an agent follows to do all three on one machine.
Prebuilt binaries for macOS, Windows and Linux are attached to each release.

To build from source instead — the toolchain is pinned in `rust-toolchain.toml`.
Clone the repository, then build from the root of the clone, wherever you put
it:

```
git clone https://github.com/molchalih/rpfd.git
cargo build --release          # target/release/rpf
```

Encrypted archives need key material, extracted from your own installation:

```
rpf keys extract GTA5.exe         # the AES key and the hash lookup table
rpf keys extract Launcher.exe     # the second AES key, carried by no game executable
rpf keys extract <memory image>   # the NG expanded keys and decrypt tables
```

No key material is bundled here, and none ever will be. Each source is cached
under the hash of its own bytes, under `keys` inside an `rpf` directory of the
platform's own configuration directory — `$XDG_CONFIG_HOME` or `~/.config` on
Linux, `~/Library/Application Support` on macOS, `%APPDATA%` on Windows. Every
command consults it without a flag, and `rpf keys cache` is what says where it
landed and how much is in it:

```
$ rpf keys cache
cache   /Users/you/Library/Application Support/rpf/keys
entries 2
```

`--cache-dir` selects another cache, the one way to keep several installations
apart, and `rpf keys invalidate` empties one. No command prints a key — only
offsets, lengths, counts and paths. NG material stands in the clear only in a
memory image of a running game, so that is the sole route to an NG archive;
obtaining one is out of scope here. An archive whose material is absent fails
rather than guessing.

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
... 20 more rows: the rest of the mods archive, and x64/vehicles.rpf
```

The second column says what an entry holds; `pso`, `rbf` and `meta` have an XML
view:

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
      <hash_D61872FF pso:float3="0.0, 0.0, 1.54805"/>
      <hash_82E8C5DE pso:float="4.356308"/>
      <hash_AD5D5B4C pso:float="5.0"/>
      <hash_E6E17F14 pso:string.counted="DES_Hosp_Ceil2"/>
      <hash_75D215A1 pso:string.counted="DES_Hosp_Ceil2_txd"/>
      <hash_19471791 pso:null="string.counted"/>
      <hash_FC1FB6FB pso:null="string.counted"/>
      <hash_D3C717FC pso:hashstring="hash_00000000"/>
      <hash_F17E7F28 pso:array="atarray"/>
    </pso:item>
  </hash_018A3B1B>
  <hash_E6E17F14 pso:hashstring="hash_334D5CB2"/>
  <hash_3C6F8844 pso:array="atarray"/>
  <hash_069ADF93 pso:array="atarray"/>
  <hash_65E9D4EB pso:array="atarray"/>
</hash_D98BB561>
```

`rpf put --as xml` writes an edited document back in the entry's own encoding.
Ask what a write costs, then make it — the byte count is your `edited.meta`'s,
not a constant, and `--dry-run` is how you learn it before anything is written:

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

Every reporting command takes `--json`; `rpf --help` lists the rest.
`clients/agent/README.md` is the page for driving the tool from a program: the
JSON shapes, the failure object, and `cat --out` for a payload nobody is going
to read.

## The daemon

`rpf serve --stdio` speaks JSON-RPC, one object per line. It answers everything
the binary does, holds edits until `commit`, and reports a long rebuild's
progress as cancellable notifications.

```
$ echo '{"jsonrpc":"2.0","id":1,"method":"open","params":{"path":"/tmp/dlc.rpf"}}' | rpf serve --stdio
{"id":1,"jsonrpc":"2.0","result":{"entries":11,"handle":1,"len":144504832,"path":"/private/tmp/dlc.rpf"}}
```

## The editor extension

`clients/vscode` mounts an archive as a workspace folder: files open, edit and
save like any other, and a nested archive is a folder inside a folder. The
archive is written by one explicit act, previewed as patch or rebuild. See
`clients/vscode/README.md`.

## Exit codes

Stable, so a caller can classify a failure without reading the message: `0` is
success, and every non-zero code names one class of failure. The daemon reports
the same numbers as a JSON-RPC `error.code`, with a symbolic
`error.data.reason`.

The table is in `clients/agent/README.md`, which owns it, along with what each
code tells a caller to do next.

## Building and testing

```
cargo build --release
```

Continuous integration runs these, on macOS, Linux and Windows for the first
three; passing them locally is what makes a green run likely:

```
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo test -p rpf-core --test oracle -- --nocapture
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --workspace
cargo deny check
./tools/docgate/docgate.sh
```

It also checks every commit message; `git config core.hooksPath .githooks`
runs the same check locally.

The suite needs no game data: what needs it is skipped. `RPF_CORPUS`,
`RPF_GAME_EXE`, `RPF_GAME_IMAGE` and `RPF_METADATA` point it at archives, game
executables, a memory image of the running game, and extracted metadata
payloads; the matching `RPF_REQUIRE_*` turns a skip into a failure.

## Licence

`MIT OR Apache-2.0`, at your option. See `LICENSE-MIT` and `LICENSE-APACHE`.
