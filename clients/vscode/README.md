# RPF Archives

Open a RAGE `.rpf` archive as a folder in the editor. Entries are files: they
open in a tab, edit, and save the way any other file does, and the archive on
disk is patched in place whenever the edit still fits where its entry sits,
while anything that would mean writing the whole archive out again waits for you
to ask. A nested archive is a folder inside a folder, and `.meta`, `.ymt` and
their kind open as XML and are written back in the entry's own binary encoding.

**It needs the `rpf` binary, and the package you install probably carries one.**
Each per-platform release package — `rpf-vX.Y.Z-darwin-arm64.vsix` and its three
siblings — ships the static binary for that platform inside it, so a first
install has everything it needs and there is nothing to put on `PATH`. The
suffix-less `rpf-vX.Y.Z.vsix` carries none, for a platform this project does not
build for, and falls back to `rpf` on `PATH`. `INSTALL.md` at the repository
root is how to install either, and the server without the editor.

The extension holds no format knowledge of its own and parses nothing. Every
answer it gives comes from the binary, over `rpf serve --stdio` — one long-lived
process per window, with the entry table parsed once and kept warm.

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
- **Writes your edits for you, when it can do it in place.** Saving a document
  buffers the edit, and a moment later the archive is patched with it.
  Creating, deleting and renaming entries in the explorer buffer the same way.
- **Shows what is waiting, where it is waiting.** An entry with a buffered
  change is badged in the explorer with the letter git uses — `M` modified, `A`
  added, `D` deleted, `R` renamed — and every folder above it carries the badge
  too. The colours are the theme's: this extension contributes four colour ids
  that default to git's own, so a theme that recolours git recolours these.
- **Never rebuilds an archive behind your back.** An edit that does not fit
  where its entry sits, and any change to what the archive holds, would have
  the whole archive written out again. The edits stay buffered instead, the
  status bar says so, and `RPF: Rebuild Archive` is what writes them.
- **Can be stopped.** The rebuild progress notification is cancellable. A
  cancelled rebuild leaves the original archive untouched.
- **Checks an archive.** `RPF: Verify Archive` reads every entry back and lists
  what did not come back as recorded.
- **Hands an asset to another tool.** `RPF: Edit With Another Tool` writes a
  `.ytd`, `.yft` or the like to disk, watches it, and buffers whatever the
  other tool writes back.
- **Gives the editor's agents an MCP server.** A mounted archive is a folder
  only inside this editor, so nothing outside its file service — an agent
  included — can read one. The extension registers `rpf serve --mcp` instead,
  built from the same binary it found for itself, and there is nothing to
  configure. `clients/mcp/README.md` describes the six tools it offers. With no
  binary, no server is offered rather than one that cannot start.

## Requirements

VS Code 1.101 or later, for the MCP server registration, and the `rpf` binary.
The extension looks for the binary in this order, and proves each candidate by
running `rpf --version`:

1. The `rpf.binaryPath` setting. It is machine-scoped, so a workspace cannot
   choose which executable the extension runs.
2. A binary bundled inside the extension, if the package carries one.
3. The first `rpf` on `PATH`.

With none of them, the first mount fails with a message naming every place it
looked, and no MCP server is offered. `rpf` is one static binary with no runtime
prerequisite: install a per-platform package and row 2 answers, or put one on
`PATH`, or build it and point the setting at the result. `INSTALL.md` covers the
first two.

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
you the archive a save would produce, badged with what is waiting against each
entry. Nothing on disk has moved until the archive is written.

## When you have to ask for the rebuild

An archive is patched in place when every buffered edit fits in the room its
entry already has. Anything else — an edit that grew, a created, deleted or
renamed entry — means writing the whole archive out again, which is slow and
replaces the file. That is not done for you: the edits stay buffered, the
status bar turns amber with how many are waiting, and hovering it says why.
Run `RPF: Rebuild Archive`, or press the status bar item, to write them. The
archive on disk is untouched until you do.

Writing into a detected game installation is refused as well. The rebuild
command offers to do it anyway; nothing writes there without being told to
twice.

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
