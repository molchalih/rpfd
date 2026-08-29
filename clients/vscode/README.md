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
| Mount an archive as a workspace folder | `RPF: Mount Archive as Folder`, or the same item on a `.rpf` in the explorer, which mounts the one you clicked. Files below it are `rpf:` URIs |
| Read and edit entries, through nesting | An archive inside an archive is a folder inside a folder; the path addresses through it in one string |
| Add, delete and rename entries | New File, New Folder, Delete and Rename in the explorer. Each buffers like an edit, and the archive is written by the same one act |
| Hold changes until you say so | Saving a document buffers the edit. `RPF: Save Archive` writes the archive |
| See what a save would cost first | `RPF: Preview Archive Save` reports whether it would patch in place or rebuild, which edits do not fit, and which changes alter what the archive holds |
| Stop a long save | The progress notification is cancellable. A rebuild stops between entries and leaves the original untouched; a patch in place cannot be stopped, and says so |
| Check an archive | `RPF: Verify Archive` reads every entry back and lists what did not |
| Hand an asset to another tool | `RPF: Edit With Another Tool` writes a `.ytd`, `.yft` or the like to disk, watches it, and buffers whatever is written back. The watch is backed by a stat, because on macOS a watch armed while others are armed can miss the first change outright |
| Say what to do when something fails | Every failure names who has to act on it — you, the archive, or this extension |

## What it does not do

- **A rename does not replace a folder that holds anything.** Renaming onto an
  entry replaces it — the target is removed in the same change set, which is
  how the library says "I meant to replace that", and the entry keeps its
  storage class because it is still a rename. A directory with entries under it
  is not: delete it deliberately first.
- **One change per entry until you save.** An entry with a rename buffered
  against it cannot also be edited, nor an edited one renamed, and a directory
  being renamed cannot hold another rename. Save the archive, then make the
  second change.
- **A nested archive is a folder, not a file.** You can descend into it; you
  cannot read its raw bytes through the folder view.
- **It does not convert metadata.** Presenting `.ymt`/`.meta` as XML is R7.4,
  and it waits on the metadata layer existing at all.
- **It does not decrypt.** An encrypted archive is refused, and says so.

## Getting the binary

Looked for in this order, and each candidate is proved by running
`rpf --version`:

1. The `rpf.binaryPath` setting. It is **machine-scoped**: a workspace cannot
   set it, because a repository that could name the executable this extension
   runs would be a repository that runs anything it likes.
2. `bin/<platform>-<arch>/rpf` inside the extension, if one was bundled.
3. The first `rpf` on `PATH`.

With none of them, the first mount fails with a message naming every place it
looked and what to do about it. `rpf` is one static binary with no runtime
prerequisite: put it on `PATH`, or build it with `cargo build --release` and
point the setting at `target/release/rpf`.

## What the explorer shows before a save

A listing from the daemon is the archive **on disk**: a created entry is not in
it, a deleted one still is, and a renamed one is under its old name, until the
commit. So this extension keeps the buffered change set itself and shows you the
archive a save would produce — applying the changes in the order the rebuild
applies them, which is removals, then renames, then writes, then directories.
Everything below that line is what you asked for; nothing on disk has moved.

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
npm run check       # type-check only
npm test            # build, then run the suite against a live daemon
npm run test:editor # build, then run the same client inside a real VS Code
```

The suite spawns a real `rpf serve --stdio` and drives it. It looks for the
binary at `RPF_BIN`, then `target/release/rpf`, then `target/debug/rpf`
relative to the repository root. **With no binary the live tests skip and say
so** — they never pass silently.

Every test has a **60-second limit**. Node's own default is no limit at all, and
a test that waits on something that never arrives then hangs for as long as
anyone lets it — measured here at over fifteen minutes, twice, in a suite whose
whole run is under a second. A limit turns that into a failure, which is the
difference that matters in continuous integration.

`npm run test:editor` downloads a VS Code into `.vscode-test/` (about 300 MB,
once) and launches it with this directory as an extension under development. It
mounts an archive through the command a person runs, walks the explorer into a
nested archive, edits a file and saves it, and creates, renames and deletes
entries — and then checks every result with `rpf ls`, `rpf cat` and `rpf verify`
**from outside the editor**, so a pass means the bytes landed rather than that
the client believes they did. It runs on an archive it packs itself; set
`RPF_CORPUS` and it runs the same workflow on the sample archive as well, after
confirming the `sha256` the fixture records. Without it that half **skips and
says so**, and `RPF_REQUIRE_CORPUS=1` turns the skip into a failure.

Two lines in the source are the two suites:

| | |
|---|---|
| `src/core/` | No editor is imported. Framing, request correlation, progress, cancellation, error mapping, the `rpf:` URI, the archive tree, the buffered-edit state machine, binary discovery, hand-off. All of it is exercised against a live daemon, by `npm test` |
| `src/vscode/`, `src/extension.ts` | The editor's own API, and as little as possible is here. It cannot be exercised without a running VS Code, so `npm run test:editor` runs one |

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
