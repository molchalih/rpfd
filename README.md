# rpf

A minimal, dependency-light toolchain for reading, editing and rebuilding
RAGE Package File (`.rpf`) archives from the terminal, from an editor, or from
an automated agent — without installing a GUI modding suite.

Status: **the container works.** An archive can be listed, read, edited and
rebuilt from the command line, including through nested archives. Metadata
conversion, encryption and the editor client are not built yet; see the backlog.

```
rpf info    dlc.rpf
rpf ls -R   dlc.rpf x64
rpf cat     dlc.rpf data/vehicles.meta
rpf put     dlc.rpf x64/vehicles.rpf/meringls63amg24.ytd new.ytd   # patches in place
rpf extract dlc.rpf tree/ && rpf pack tree/ dlc.rpf
rpf put     dlc.rpf data/vehicles.meta new.meta --dry-run   # decide, write nothing
rpf verify  dlc.rpf
rpf serve --stdio        # JSON-RPC, one object per line, edits held until commit
```

A path addresses through nesting in one string. Every reporting command takes
`--json`.

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

`--dry-run` on `put`, and `"dry_run": true` on the daemon's `commit`, take that
same decision and stop before acting on it — reporting where each edit would be
written and how much room its entry has, or which edits will not fit and force
the rebuild. It needs no write permission, and a refusal is reported as a
refusal, so what it says is what the real call would do.

The daemon answers every question the binary does: `info` and `verify` are
methods on an open handle, so an editor client — which reaches the container
only through the daemon — is not limited to a subset of what the command line
can do.

A rebuild reports progress as it goes: on the command line to standard error
when there is a terminal to read it, and over the daemon as JSON-RPC
notifications — objects with a `method` and no `id`, so a client reads past them
looking for the response it is waiting for. Reading an archive back is unbounded
work in the same way, so `verify` reports and cancels the same way a rebuild
does. A `cancel` sent to the daemon during either stops it: standard input is
read on its own thread, so it arrives while there is still something to cancel. Nothing is left behind, because a
rebuild only replaces the archive once it has finished.

## Building and testing

A tagged release publishes a static binary per platform — macOS on both
architectures, Linux `x86_64` against musl, and Windows `x86_64` — with both
licence files beside it. Nothing has to be installed first.

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
