# RPF Archives — the editor client

Edit files inside RAGE `.rpf` archives as ordinary files. The archive mounts as
a folder, files open and save the way any other file does, and the archive
itself is written by one explicit act.

It holds no archive knowledge of its own. Everything it does it asks the `rpf`
binary for, over `rpf serve --stdio` — one long-lived process per window, with
the entry table parsed once and kept warm.

## What it does

| | |
|---|---|
| Mount an archive as a workspace folder | `RPF: Mount Archive as Folder`. Files below it are `rpf:` URIs |
| Read and edit entries, through nesting | An archive inside an archive is a folder inside a folder; the path addresses through it in one string |
| Hold edits until you say so | Saving a document buffers the edit. `RPF: Save Archive` writes the archive |
| See what a save would cost first | `RPF: Preview Archive Save` reports whether it would patch in place or rebuild, and which edits do not fit |
| Stop a long save | The progress notification is cancellable. A rebuild stops between entries and leaves the original untouched; a patch in place cannot be stopped, and says so |
| Check an archive | `RPF: Verify Archive` reads every entry back and lists what did not |
| Hand an asset to another tool | `RPF: Edit With Another Tool` writes a `.ytd`, `.yft` or the like to disk, watches it, and buffers whatever is written back |
| Say what to do when something fails | Every failure names who has to act on it — you, the archive, or this extension |

## What it does not do

- **It cannot add, remove or rename an entry.** The daemon has no method that
  changes the entry table; extract the archive, change the tree, and pack it
  again.
- **A nested archive is a folder, not a file.** You can descend into it; you
  cannot read its raw bytes through the folder view.
- **It does not convert metadata.** Presenting `.ymt`/`.meta` as XML is R7.4,
  and it waits on the metadata layer existing at all.
- **It does not decrypt.** An encrypted archive is refused, and says so.

## Getting the binary

Looked for in this order, and each candidate is proved by running
`rpf --version`:

1. The `rpf.binaryPath` setting.
2. `bin/<platform>-<arch>/rpf` inside the extension, if one was bundled.
3. The first `rpf` on `PATH`.

With none of them, the first mount fails with a message naming every place it
looked and what to do about it. `rpf` is one static binary with no runtime
prerequisite: put it on `PATH`, or build it with `cargo build --release` and
point the setting at `target/release/rpf`.

## One writer per archive

An archive is open in one session at a time — the daemon refuses the second
`open`, because every offset a session holds is true only of the bytes it
parsed. Two names for one file are one archive: a hard link, a symlink and a
second spelling are all refused. Mount an archive once per window.

Nothing stops another *process* writing an archive this window holds. That is
out of scope and stated rather than half-guarded.

## Developing

```
npm install
npm run check     # type-check only
npm test          # build, then run the suite
```

The suite spawns a real `rpf serve --stdio` and drives it. It looks for the
binary at `RPF_BIN`, then `target/release/rpf`, then `target/debug/rpf`
relative to the repository root. **With no binary the live tests skip and say
so** — they never pass silently.

The line between what is tested and what is not is the same line as the one in
the source:

| | |
|---|---|
| `src/core/` | No editor is imported. Framing, request correlation, progress, cancellation, error mapping, the `rpf:` URI, the archive tree, the buffered-edit state machine, binary discovery, hand-off. All of it is exercised against a live daemon |
| `src/vscode/`, `src/extension.ts` | The editor's own API. Nothing here can be exercised without a running VS Code, so as little as possible is here |

## Packaging

```
npm run package -- --publisher <your-publisher-id>
```

That writes `rpf-<version>.vsix` beside this file. Install it with:

```
code --install-extension rpf-<version>.vsix
```

To ship a binary inside the package, put it at
`bin/<platform>-<arch>/rpf` (`rpf.exe` on Windows) before packaging; whatever
is under `bin/` is included.

**A publisher id is not supplied here and will not be invented.** It is an
identity on a marketplace and belongs to whoever publishes. Packaging is what
this repository does; publishing is a separate act it does not do.

What goes into the package is the list in `scripts/vsix.ts` and nothing else —
there is no ignore file saying the same thing in the negative.
