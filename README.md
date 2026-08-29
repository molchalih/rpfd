# rpf

A minimal, dependency-light toolchain for reading, editing and rebuilding
RAGE Package File (`.rpf`) archives from the terminal, from an editor, or from
an automated agent — without installing a GUI modding suite.

Status: **the container works.** An archive can be listed, read, edited and
rebuilt from the command line, including through nested archives. Metadata
conversion, encryption and the editor client are not built yet; see the backlog.

```
rpf info    dlc.rpf x64/vehicles.rpf   # or the archive alone
rpf ls -R   dlc.rpf x64
rpf cat     dlc.rpf data/vehicles.meta
rpf put     dlc.rpf x64/vehicles.rpf/meringls63amg24.ytd new.ytd   # patches in place
rpf put     dlc.rpf data/new.meta new.meta --create   # add an entry
rpf rm      dlc.rpf data/old.meta            # and -r for a directory
rpf mv      dlc.rpf data/old.meta data/new.meta
rpf mkdir   dlc.rpf data/empty
rpf extract dlc.rpf tree/ && rpf pack tree/ dlc.rpf   # --overwrite to reuse a tree
rpf put     dlc.rpf data/vehicles.meta new.meta --dry-run   # decide, write nothing
rpf verify  dlc.rpf --against tree/   # and against what the tree recorded
rpf keys extract GTA5.exe   # find the key material in your own install
rpf serve --stdio        # JSON-RPC, one object per line, edits held until commit
```

A path addresses through nesting in one string. Every reporting command takes
`--json`, and what it prints is the same object the daemon answers with, under
the same field names.

> **`--json verify` changed shape on 2026-08-28.** `problems` was an array of
> `"path: reason"` sentences and is now an array of `{"path": …, "reason": …}`
> objects, which is what the daemon has always answered. A reason carries colons
> of its own — `entry 0: payload did not inflate` — so the sentence could not be
> split back apart, and a consumer looking for the path got everything up to the
> first colon. Nothing else about `--json` moved. DR-027.

## Installing

R8.2. `rpf` is one statically linked file with no runtime prerequisite —
DR-001, and the reason `docs/conventions.md` §14 rules out C dependencies — so
installing it is putting that file somewhere on your `PATH`. **No Rust, no
Node, no package manager.** Every step below uses a tool the platform already
ships.

> **Read this first.** *No release has ever been produced.* There is no git
> remote, no tag has ever been pushed, and `.github/workflows/release.yml` has
> never been executed — nor has `ci.yml`. Each target has been compiled locally;
> the musl link, the Windows link, the packaging step and the upload have run
> nowhere. So the steps below describe **what to do with an asset that workflow
> would produce**, named as that workflow names it. They are not a download
> instruction, because there is nothing yet to download, and this section will
> assert a URL when a release exists and not before. The workflow also publishes
> no checksums, so there is nothing to check a download against.

A tagged release publishes one archive per target, named
`rpf-<tag>-<target>.tar.gz` — `.zip` on Windows — each holding a directory of
the same name with the binary, this file, and both licence files.

| Target | For |
|---|---|
| `aarch64-apple-darwin` | Apple silicon Macs. `uname -m` says `arm64` |
| `x86_64-apple-darwin` | Intel Macs. `uname -m` says `x86_64` |
| `x86_64-unknown-linux-musl` | Linux on `x86_64`, any distribution |
| `x86_64-pc-windows-msvc` | Windows on `x86_64` |

There is no build for Linux or Windows on ARM. Build from source there.

### macOS

```
tar -xzf rpf-<tag>-aarch64-apple-darwin.tar.gz
sudo install -m 755 rpf-<tag>-aarch64-apple-darwin/rpf /usr/local/bin/rpf
rpf --version
```

The binary is **not signed and not notarised**, so a copy a browser downloaded
carries the `com.apple.quarantine` attribute and Gatekeeper refuses to run it —
"cannot be opened because the developer cannot be verified". Clear it once:

```
xattr -d com.apple.quarantine /usr/local/bin/rpf
```

A copy fetched with `curl` in a terminal never gets the attribute, so this step
is only for the browser route.

### Linux

```
mkdir -p ~/.local/bin
tar -xzf rpf-<tag>-x86_64-unknown-linux-musl.tar.gz
install -m 755 rpf-<tag>-x86_64-unknown-linux-musl/rpf ~/.local/bin/rpf
rpf --version
```

`~/.local/bin` needs no root and is on `PATH` by default on most distributions;
`/usr/local/bin` with `sudo` is the system-wide alternative. The binary is
linked against musl and carries its own libc, so it has no glibc version
requirement and runs on a distribution older than the one that built it —
`ldd ~/.local/bin/rpf` answers "not a dynamic executable".

### Windows

In PowerShell:

```
Unblock-File .\rpf-<tag>-x86_64-pc-windows-msvc.zip
Expand-Archive .\rpf-<tag>-x86_64-pc-windows-msvc.zip -DestinationPath $env:LOCALAPPDATA\Programs
[Environment]::SetEnvironmentVariable(
  'Path',
  "$env:Path;$env:LOCALAPPDATA\Programs\rpf-<tag>-x86_64-pc-windows-msvc",
  'User')
```

Open a new terminal, then `rpf --version`. `Unblock-File` before extracting is
what stops SmartScreen refusing the extracted `rpf.exe`; without it the first
run shows "Windows protected your PC", and **More info → Run anyway** is the
other way past it. The executable is unsigned, which is why either is needed.
It is built with `-C target-feature=+crt-static`, so the Visual C++
redistributable is **not** a prerequisite.

### From source

The fallback, and the only route that assumes a language runtime. It needs the
Rust toolchain `rust-toolchain.toml` pins:

```
git clone <this repository> && cd rpf
cargo build --release          # target/release/rpf
```

## Exit codes

Stable, and part of the contract: a caller classifies a failure without parsing
a message. What a code names is what the caller has to do about the failure,
not what the tool was doing when it noticed. DR-010.

| Code | Meaning |
|---|---|
| 0 | Everything worked |
| 1 | A failure with no better classification |
| 2 | The arguments were wrong |
| 3 | The path is not in the archive |
| 4 | The archive is malformed, contradicts itself, or does not decompress as it promises |
| 5 | The archive needs key material that is not available |
| 6 | The request or its input was wrong, and the tool declined to act |
| 7 | Reading or writing failed — the source or the sink, and nobody's input |
| 8 | The caller stopped the operation part-way |
| 9 | The archive is an RPF version this build does not read |

The daemon reports the same numbers as a JSON-RPC `error.code`. A negative code
there is JSON-RPC's own — `-32601` for an unknown method, `-32602` for a bad
parameter — so the two schemes read apart on sight.

Beside the number, every error the daemon writes carries
`error.data.reason`: the failure's own name, as a stable symbol —
`AlreadyExists`, `NotFound`, `NeedsKey`, `MethodNotFound`. The number says who
has to act and is shared by everything in its class; the name says which
failure it was, for a client that has a distinct answer for one of them and
would otherwise have to read the sentence. The number is unchanged and is still
the contract.

An edit that fits where its entry already sits is written in place: `put` does
it for one file and `commit` for a whole set of buffered ones, deciding for the
set before writing any of it. Two small edits to a 145 MB archive cost 92 bytes
of writes rather than 145 MB. A set that does not all fit is rebuilt instead,
and the report says which of the two ran — they are not equivalent in
durability, since a rebuild is atomic and a patch is not.

"Atomic" here means the archive is never left half-written under its own name:
the rebuild goes to a scratch file in the same directory and replaces the
original in one step. It is not a claim about surviving power loss — the replace
is not followed by a sync — and it is measured on macOS and Linux, not yet on
Windows.

Adding, removing and renaming an entry always rebuild, and the tool says so
before it starts: each of them changes the entry count or the names blob, so
every offset after the header moves and there is nothing to patch in place.
`put --create`, `rm`, `mv` and `mkdir` are the command line's; `write` with
`"create": true`, `delete`, `rename` and `mkdir` are the daemon's, all buffered
until `commit` like any other edit. A rename onto a path the archive already
holds is refused rather than replacing it — remove that path in the same set,
which says the same thing out loud — and a directory that holds anything needs
`-r`, or `"recursive": true`, before it takes its children with it.

Each change the daemon buffers is judged against the archive **and against the
changes already buffered over it**, so the set a session is building is one the
commit will accept: a rename onto a path a buffered removal frees is allowed,
and a rename onto a path another buffered rename claims is refused at the
request that asks for it rather than at the save. A set holds one change per
path, so a second change of another kind at one path is refused too, rather
than the second quietly replacing the first — `forget` takes one change back
out of the buffer and answers what is left, and `discard` takes all of them.

**One thing about that is unverified, and it is the important one.** A rebuilt
archive with a different entry count parses, verifies and reads back here, and
whether the *game* accepts one has never been tested: it needs a machine running
a RAGE title and there is not one. `docs/backlog.md` Q8, and DR-026.

`--dry-run` on `put`, and `"dry_run": true` on the daemon's `commit`, take that
same decision and stop before acting on it — reporting where each edit would be
written and how much room its entry has, or which edits will not fit and force
the rebuild. It needs no write permission, and a refusal is reported as a
refusal, so what it says is what the real call would do.

`extract` refuses a directory that already holds something, and `--overwrite`
— `"overwrite": true` on the daemon — is the way through. An extracted tree
claims to *be* the archive: `pack` reads it back and `verify --against` checks
each entry against the manifest beside it, and a tree that also holds files no
entry names is not that. A target that does not exist is created, and an empty
one is written into, so a first extraction is unaffected. `--overwrite` writes
into the directory as it is, replacing what an entry names and leaving the rest
— it never deletes what it did not write. DR-029.

`verify` reads every entry back and checks it against what the archive says
about itself, which for a **stored** entry is nothing at all: it declares no
inflated length and carries no deflate stream that ends, so a byte changed
inside one reads back perfectly. `--against TREE` closes that, by checking each
entry against the SHA-256 an `extract` of the same archive recorded for it —
`rpf verify dlc.rpf --against tree/`. The report says how far it reached in two
numbers, because they are not the same: 27 entries read back on the sample and 7
of them checked against a recorded checksum, the other twenty being inside
nested archives, each covered by the checksum of the entry that holds it. A tree
extracted from a *different* archive names none of this one's entries, so it is
refused — exit 6 — rather than reported as nothing checked. DR-023, DR-025.

Each entry that failed is one object in `problems`, with its in-archive `path`
and the `reason` apart — the same on both frontends. DR-027.

The daemon answers everything the binary does. `info` and `verify` are methods
on an open handle — `verify` taking the same tree as `against` — and `extract`
and `pack` are too, with a tree named by a path on the daemon's own filesystem —
the same thing `open`'s path already is, and DR-014 says why. An editor client,
which reaches the container only through the daemon, is not limited to a subset
of what the command line can do.

A rebuild reports progress as it goes: on the command line to standard error
when there is a terminal to read it, and over the daemon as JSON-RPC
notifications — objects with a `method` and no `id`, so a client reads past them
looking for the response it is waiting for. Reading an archive back is unbounded
work in the same way, so `verify` reports and cancels the same way a rebuild
does. A `cancel` sent to the daemon during either stops it: standard input is
read on its own thread, so it arrives while there is still something to cancel. Nothing is left behind, because a
rebuild only replaces the archive once it has finished.

## Key material

An encrypted archive needs the RAGE AES-256 key and the NG hash lookup table,
and both live inside the game executable. Nothing is bundled here: the material
is found in **your own installation**, by the SHA-1 of each value's own bytes
rather than by an offset, and cached under the SHA-256 of the file it came
from. DR-006, DR-017.

```
rpf keys extract /path/to/GTA5.exe   # find it, and cache what was found
rpf keys cache                       # where the cache is, and how much is in it
rpf keys invalidate                  # remove every cached entry
```

`--cache-dir DIR` puts the cache somewhere other than this platform's
configuration directory, which is `$XDG_CONFIG_HOME/rpf` or `$HOME/.config/rpf`
on Linux, `~/Library/Application Support/rpf` on macOS and `%APPDATA%\rpf` on
Windows. The daemon answers `keys.extract`, `keys.cache` and `keys.invalidate`,
taking `executable` and `cache` as paths on its own filesystem and returning
the same objects `--json` prints.

**No output path prints a key.** What is reported is offsets, lengths, the
executable's SHA-256 and the cache path — `--json` is written to be piped into
automation and pasted into a bug report. Extraction is whole or it is a
failure: an executable carrying neither value exits 9, one that is not there
exits 7, and a cache that cannot be written exits 7 naming the directory.

Extracting a key does not yet let `rpf` open an encrypted archive — R3.6, which
is deliberately unwritten while there is no encrypted archive to check a cipher
against.

## Building and testing

What a tagged release would publish, and what to do with it, is **Installing**
above — including what has and has not ever been run.

```
cargo build --release          # target/release/rpf
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo deny check
cargo test --all
```

The test suite needs no game data and passes without it, skipping what it
cannot reach. To run the parts that need real archives, point `RPF_CORPUS` at a
directory holding them and set `RPF_REQUIRE_CORPUS` so a skip becomes a failure
— otherwise "green" and "it ran" are different claims:

```
RPF_CORPUS=/path/to/corpus RPF_REQUIRE_CORPUS=1 cargo test --all
```

Key extraction is gated the same way, on its own variable, because a game
executable is not an archive and no archive here is encrypted: `RPF_GAME_EXE`
names a directory holding them, and `RPF_REQUIRE_GAME_EXE` turns its skips into
failures.

```
RPF_GAME_EXE=/path/to/executables RPF_REQUIRE_GAME_EXE=1 cargo test --release --all
```

`fixtures/` records what each corpus archive looked like to an implementation
that is not ours; `fixtures/README.md` explains how those are made and what
they are worth.

| Where to look | For |
|---|---|
| `AGENTS.md` | routing, authority order, repository policy |
| `docs/approach.md` | goal, scope boundary, stack, architecture |
| `docs/conventions.md` | how code is written; read before changing source |
| `docs/rpf-format.md` | format facts, each marked verified or not |
| `docs/backlog.md` | research and delivery backlog |
| `docs/corpus.md` | what archives exist to test against, and what they do not cover |
| `docs/decisions/` | decision records |

## Licence

`MIT OR Apache-2.0`, at your option: `LICENSE-MIT` and `LICENSE-APACHE` at the
repository root. DR-007 permits reading the reference implementations as
specification and porting from them with attribution, which assumes an outbound
licence compatible with theirs; `deny.toml` already admits only permissive
inbound ones, and this is the other half of that.

**`docs/` is deliberately untracked.** It lives in the working tree and not in
the repository, so the table above resolves for anyone working here and not in
a fresh clone. Source comments cite its rows the same way.
