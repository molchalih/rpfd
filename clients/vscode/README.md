# RPF Archives

Edit files inside RAGE `.rpf` archives as ordinary files. The archive mounts as
a folder in the explorer, entries open and save the way any other file does,
and the archive itself is written by one explicit act.

The extension holds no format knowledge of its own. Everything it does it asks
the `rpf` binary for, over `rpf serve --stdio` — one long-lived process per
window, with the entry table parsed once and kept warm.

## What it does

- **Mounts an archive as a workspace folder.** Run `RPF: Mount Archive as
  Folder`, or use the same item on a `.rpf` in the explorer. An archive nested
  inside another is a folder inside a folder.
- **Presents metadata as XML.** An entry holding `RBF`, `PSO` or a
  resource-embedded `Meta` opens as an XML document and is converted back on
  save. Everything else opens as its own bytes.
- **Opens encrypted archives.** AES and NG archives mount and are written back,
  given key material. No keys are bundled: `rpf keys extract` reads them from
  your own game installation and caches them, and the extension finds them
  there.
- **Holds changes until you say so.** Saving a document buffers the edit;
  `RPF: Save Archive` writes the archive. Creating, deleting and renaming
  entries in the explorer buffer the same way.
- **Says what a save would cost.** `RPF: Preview Archive Save` reports whether
  it would patch the archive in place or rebuild it, and which edits do not fit
  where they are.
- **Can be stopped.** The save progress notification is cancellable. A
  cancelled rebuild leaves the original archive untouched.
- **Checks an archive.** `RPF: Verify Archive` reads every entry back and lists
  what did not come back as recorded.
- **Hands an asset to another tool.** `RPF: Edit With Another Tool` writes a
  `.ytd`, `.yft` or the like to disk, watches it, and buffers whatever the
  other tool writes back.

## Requirements

The `rpf` binary. The extension looks for it in this order, and proves each
candidate by running `rpf --version`:

1. The `rpf.binaryPath` setting. It is machine-scoped, so a workspace cannot
   choose which executable the extension runs.
2. A binary bundled inside the extension, if the package carries one.
3. The first `rpf` on `PATH`.

With none of them, the first mount fails with a message naming every place it
looked. `rpf` is one static binary with no runtime prerequisite: put it on
`PATH`, or build it and point the setting at the result.

## Settings

| Setting | What it does |
|---|---|
| `rpf.binaryPath` | Absolute path to the `rpf` binary. Empty means the bundled one, else the first on `PATH` |
| `rpf.handOff.extensions` | Entry extensions the editor will not try to open itself. Opening one offers the hand-off instead |
| `rpf.handOff.directory` | Where handed-off files are written. Empty means a directory under the system temporary directory |

## What the explorer shows before a save

A listing from the daemon is the archive as it is on disk: a created entry is
not in it, a deleted one still is, and a renamed one is under its old name,
until the save. So the extension keeps the buffered changes itself and shows
you the archive a save would produce. Nothing on disk has moved until you save.

## Limits

- **One session per archive.** An archive is open in one window at a time, and
  two names for one file — a hard link, a symlink, a second spelling — count as
  one archive. Nothing stops another program writing an archive a window holds.
- **One buffered change per entry.** An entry with a rename waiting against it
  cannot also be edited, nor an edited one renamed. Save, then make the second
  change.
- **A nested archive is a folder.** You can descend into it; you cannot read
  its raw bytes through the folder view.
- **Renaming onto a folder that holds something is refused.** Renaming onto a
  file replaces it. Delete a non-empty folder deliberately first.

## Building it

```
npm install
npm run check        # type-check
npm test             # unit and daemon tests
npm run test:editor  # the same client inside a real VS Code
```

The tests drive a real `rpf serve --stdio`. They look for the binary at
`RPF_BIN`, then `target/release/rpf`, then `target/debug/rpf` relative to the
repository root, and skip aloud rather than passing silently when there is
none. `npm run test:editor` downloads a VS Code on first use, mounts an archive
through the command a person runs, edits and saves through the editor, and then
checks the result with `rpf ls`, `rpf cat` and `rpf verify` from outside the
editor.

Package it with:

```
npm run package -- --publisher <your-publisher-id>
```

That writes `rpf-<version>.vsix` beside this file; install it with `code
--install-extension rpf-<version>.vsix`. To ship a binary inside the package,
put it at `bin/<platform>-<arch>/rpf` (`rpf.exe` on Windows) before packaging.

## Licence

`MIT OR Apache-2.0`, at your option.
