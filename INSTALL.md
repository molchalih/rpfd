# Installing

Three things ship from one release, and they install differently: the **editor
extension**, the **MCP server**, and the **binary on its own**. Pick the section
that matches what you want; nothing here depends on the others being installed.

Every artefact is attached to a
[release](https://github.com/molchalih/rpfd/releases/latest). `vX.Y.Z` below is
whichever tag you are taking. There is nothing to install underneath any of it:
`rpf` is one static binary with no runtime prerequisite — no Node, no Python, no
Visual C++ redistributable.

## The editor extension

**There is no one-click install for a `.vsix`.** A `vscode://` link that
installs an extension resolves against the Marketplace, where this extension is
not listed, so the file is what you have. Three ways to install it, all
equivalent:

```sh
code --install-extension rpf-vX.Y.Z-darwin-arm64.vsix
```

- Run `Extensions: Install from VSIX…` from the command palette and pick the
  file.
- Drag the `.vsix` onto the Extensions panel.

Take the package that matches the machine. Each carries the `rpf` binary for
that platform inside it, so a first install has everything it needs:

| You are on | Take |
|---|---|
| macOS, Apple silicon | `rpf-vX.Y.Z-darwin-arm64.vsix` |
| macOS, Intel | `rpf-vX.Y.Z-darwin-x64.vsix` |
| Linux, x86-64 | `rpf-vX.Y.Z-linux-x64.vsix` |
| Windows, x86-64 | `rpf-vX.Y.Z-win32-x64.vsix` |

`rpf-vX.Y.Z.vsix`, with no platform suffix, is the fifth package and carries no
binary at all. It is for a platform this project does not build for — Linux
arm64, Windows arm64 — and it expects `rpf` on `PATH`, which the last section of
this page is about.

**An extension installed from a file does not update itself.** Updates come from
the Marketplace, and a `.vsix` is outside it: to move to a new release, download
the next one and install it over this one.

`clients/vscode/README.md` is the extension's own page — what it does in the
editor, what it refuses to do behind your back, and how it finds the binary.

## The MCP server, in VS Code

Installing the extension is enough: it registers `rpf serve --mcp` for the
editor's agents, built from the binary it already found, and there is nothing to
configure. The rest of this section is for registering the server **without** the
extension.

VS Code documents a URL handler for exactly this, and unlike the extension case
it is a real one-click link: `vscode:mcp/install?{json-configuration}`, where the
configuration is a JSON object carrying `name`, `type`, `command` and `args`,
JSON-stringified and URL-encoded. For this server that is

```
{"name":"rpf","type":"stdio","command":"rpf","args":["serve","--mcp"]}
```

encoded, which assumes `rpf` is on `PATH`:

```
vscode:mcp/install?%7B%22name%22%3A%22rpf%22%2C%22type%22%3A%22stdio%22%2C%22command%22%3A%22rpf%22%2C%22args%22%3A%5B%22serve%22%2C%22--mcp%22%5D%7D
```

As a button, on a page that keeps the scheme:

```markdown
[![add rpf to VS Code](https://img.shields.io/badge/VS_Code-add_rpf-0098FF?style=for-the-badge&logo=visualstudiocode&logoColor=white)](vscode:mcp/install?%7B%22name%22%3A%22rpf%22%2C%22type%22%3A%22stdio%22%2C%22command%22%3A%22rpf%22%2C%22args%22%3A%5B%22serve%22%2C%22--mcp%22%5D%7D)
```

The button is shown as source rather than rendered because **GitHub strips it**:
its markdown sanitiser drops every URL scheme it does not know, `vscode:` is one
of them, and the same line rendered here would be an image with no link behind
it. Measured against GitHub's own renderer through `gh api /markdown`, which
returned the link text with no `<a>` around it. The
`https://insiders.vscode.dev/redirect?url=…` wrapper that would survive the
sanitiser is documented for VS Code Insiders, so it is not offered here as the
stable path. The link itself works from a browser's address bar, and the docs
name `xdg-open $LINK` for handing it to the desktop from a shell.

Or skip the link. The command line takes the same object and writes it to the
user profile, which is the form that needs no handler and no dialog:

```sh
code --add-mcp '{"name":"rpf","type":"stdio","command":"/path/to/rpf","args":["serve","--mcp"]}'
```

And the same registration as a file, which is the form you can check into a
repository — `.vscode/mcp.json`, with the binary named by its full path:

```json
{
  "servers": {
    "rpf": {
      "type": "stdio",
      "command": "/path/to/rpf",
      "args": ["serve", "--mcp"]
    }
  }
}
```

**The key is `servers`, not `mcpServers`.** `clients/mcp/README.md` has the file
and the key for every other client, and what the six tools promise.

## The MCP server, in Claude Code

One command, and the JSON is the same object every client takes:

```sh
claude mcp add-json rpf '{"type":"stdio","command":"/path/to/rpf","args":["serve","--mcp"]}'
```

`claude mcp add` does the same thing interactively, and `claude mcp list` shows
what is registered. No settings file is named on this page deliberately: the
command is the documented interface and where it writes is its own business, so
a path written down here would be a second answer waiting to go stale.

Every other client takes the same command and arguments; what differs is the
file and, in one case, the key inside it. `clients/mcp/README.md` has the table.
The exception is `rpf-vX.Y.Z.mcpb`, the bundle Claude Desktop installs by being
opened: it carries all three platforms' binaries, so there is no path to name
and no JSON to write.

## Just the binary, and the server with no editor at all

This is the whole tool. The extension and the bundle are two ways of delivering
it; the archive on the release is the thing itself.

| You are on | Take |
|---|---|
| macOS, Apple silicon | `rpf-vX.Y.Z-aarch64-apple-darwin.tar.gz` |
| macOS, Intel | `rpf-vX.Y.Z-x86_64-apple-darwin.tar.gz` |
| Linux, x86-64 | `rpf-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz` |
| Windows, x86-64 | `rpf-vX.Y.Z-x86_64-pc-windows-msvc.zip` |

Nothing checks the match for you — a hand-downloaded file installs whatever it
is, on whatever it is. Each archive holds the binary, the README and both licences.

```sh
tar -xzf rpf-vX.Y.Z-aarch64-apple-darwin.tar.gz
install -m 755 rpf-vX.Y.Z-aarch64-apple-darwin/rpf ~/.local/bin/rpf   # or /usr/local/bin
rpf --version
```

On Windows, unzip it and put `rpf.exe` in a directory on `PATH`. Nothing in this
project is code-signed or notarised, so macOS will quarantine a binary a browser
downloaded: clear it with `xattr -d com.apple.quarantine rpf`, or approve it
once under System Settings → Privacy & Security.

Then the server is the binary:

```sh
rpf serve --mcp
```

It speaks the Model Context Protocol on stdin and stdout, one JSON object per
line, and nothing else ever goes to stdout. It is not a thing you leave running
— a client starts it. `clients/mcp/README.md` is the page for registering it and
reading a transcript of it afterwards.

If what you have is a program rather than a model, none of the above applies and
the command line is the simpler surface by some distance: a call is a process,
there is no protocol to speak, every reporting command takes `--json`, and
`clients/agent/README.md` is the contract — the shape of each report, what each
exit code means, and the failure object.

## Can an agent do this for me?

Nearly all of it, and it is worth knowing where the line falls.

| An agent can | And then |
|---|---|
| Run `code --install-extension <file>.vsix` | the extension is installed |
| Run `code --add-mcp '{…}'` | the server is in your user profile |
| Write `.vscode/mcp.json` | the server is in the repository, for everyone who opens it |
| Run `claude mcp add-json rpf '{…}'` | the server is registered with Claude Code |
| Download and unpack a release archive and put the binary on `PATH` | `rpf --version` answers |

What it cannot do is **click** the `vscode:mcp/install?…` link. A protocol
handler is dispatched by your desktop to your editor, which then asks you to
confirm; an agent sharing your desktop session can hand the link over with
`open` or `xdg-open`, but the dialog on the other side is yours to answer, and
an agent running anywhere else cannot reach the handler at all.

Which is why the link is a convenience rather than the path: `code --add-mcp`
and `.vscode/mcp.json` register the same server with no handler in the way, and
both are things an agent can simply do.
