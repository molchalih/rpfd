# Installing

Three things ship from one release, and they install differently: the **editor
extension**, the **MCP server**, and the **binary on its own**. Pick the section
that matches what you want; nothing here depends on the others being installed.
An agent asked to install this repository follows
[the procedure at the end](#installing-everything-as-an-agent), which does all
three in order.

Every artefact is attached to a
[release](https://github.com/molchalih/rpfd/releases/latest). `vX.Y.Z` below is
whichever tag you are taking. There is nothing to install underneath any of it:
`rpf` is one static binary with no runtime prerequisite — no Node, no Python, no
Visual C++ redistributable.

## The editor extension

**In Cursor, VSCodium and Windsurf, install it from the editor.** It is listed
on [Open VSX](https://open-vsx.org/extension/molchalih/rpf), the registry those
editors install from, as `molchalih.rpf`: search the Extensions view for it, and
the editor takes the package for its platform and updates it with each release.
Listed from `v0.3.0`, published by `release.yml`. VS Code installs from the
Marketplace instead, where it is not listed yet, so in VS Code it is the file.

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
the registry an extension was installed from, and a `.vsix` is outside every
one: to move to a new release, download the next one and install it over this
one.

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

## The MCP server, in Claude Code and Codex

One command each, and the JSON is the same object every client takes:

```sh
claude mcp add-json rpf '{"type":"stdio","command":"/path/to/rpf","args":["serve","--mcp"]}'
codex mcp add rpf -- /path/to/rpf serve --mcp
```

`claude mcp add` takes the second form too, and `claude mcp list` and
`codex mcp list` show what is registered. No settings file is named on this
page deliberately: the command is the documented interface and where it writes
is its own business, so a path written down here would be a second answer
waiting to go stale.

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

## Installing everything, as an agent

A user who points an agent at this repository and says "install this" means:
the binary on `PATH`, then `rpf` registered with every client the machine has.
This is that procedure, in order. Three rules hold throughout it.

- **Never replace an `rpf` that is already there** — one on `PATH`, or a file
  or link at the destination below. Stop and ask.
- **Never write into a game installation.** Nothing here goes into a game's
  directory, and nothing it runs carries `--force`: `rpf` refuses to write into
  a detected install unless forced, because it is driven by automation that does
  exactly what it is told.
- **Report exactly what changed** — every file written, every line added to a
  profile, every registration made — each with the command that undoes it.

**Ask a clean shell whether `rpf` is on `PATH`, never the current one.** A
terminal inside VS Code has the extension's bundled copy prepended to `PATH`
when nothing else provides `rpf`, so `command -v rpf` there finds a binary that
no other program on the machine can see. The clean question is

```sh
env -i HOME="$HOME" USER="$USER" SHELL="$SHELL" "$SHELL" -lic 'command -v rpf'
```

and an answer from the `bin` directory of the extension's own folder, inside
an editor's `extensions` directory, is that private copy, not a machine install,
and does not count.

### 1. The binary, on `PATH`

The destination is `~/.local/bin/rpf`, or `%LOCALAPPDATA%\Programs\rpf\rpf.exe`
on Windows. These are the paths the editor extension's **RPF: Install 'rpf'
Command in PATH** writes. That command stops when `rpf` is already on `PATH` and
never overwrites a binary it did not install, so after this procedure it does
nothing. That is intended: one binary on `PATH`, whichever of the two put it
there.

The archive is the one the table under
[Just the binary](#just-the-binary-and-the-server-with-no-editor-at-all) names
for the platform. The release carries no checksum file of its own; GitHub
records a SHA-256 `digest` for every release asset, and the download is checked
against it. Run it as one script, with `sh`:

```sh
set -eu
found=$(env -i HOME="$HOME" USER="${USER-}" SHELL="$SHELL" "$SHELL" -lic 'command -v rpf' 2>/dev/null | tail -n 1)
case "$found" in
  ''|*/extensions/*rpf*/bin/*) ;;
  *) echo "rpf is already on PATH: $found" >&2; exit 1 ;;
esac
[ -e ~/.local/bin/rpf ] || [ -L ~/.local/bin/rpf ] && exit 1
repo=molchalih/rpfd
case "$(uname -s)/$(uname -m)" in
  Darwin/*)     [ "$(sysctl -n hw.optional.arm64 2>/dev/null)" = 1 ] \
                  && target=aarch64-apple-darwin || target=x86_64-apple-darwin ;;
  Linux/x86_64) target=x86_64-unknown-linux-musl ;;
  *)            echo "no release build for this platform" >&2; exit 1 ;;
esac
cd "$(mktemp -d)"
tag=$(gh release view --repo "$repo" --json tagName -q .tagName)
asset="rpf-$tag-$target.tar.gz"
gh release download "$tag" --repo "$repo" --pattern "$asset"
want=$(gh release view "$tag" --repo "$repo" --json assets \
         -q ".assets[] | select(.name == \"$asset\") | .digest")
got="sha256:$( (sha256sum "$asset" 2>/dev/null || shasum -a 256 "$asset") | cut -d' ' -f1)"
[ "$want" = "$got" ] || { echo "digest mismatch" >&2; exit 1; }
tar -xzf "$asset"
mkdir -p ~/.local/bin
install -m 755 "rpf-$tag-$target/rpf" ~/.local/bin/rpf
xattr -d com.apple.quarantine ~/.local/bin/rpf 2>/dev/null || true
~/.local/bin/rpf --version
```

`sysctl`, not `uname -m`, decides the Mac: under Rosetta a shell reports
`x86_64` on Apple silicon. `gh` answers nothing until it is logged in
(`gh auth status`); without it, the tag is the last segment of the URL
`https://github.com/molchalih/rpfd/releases/latest` redirects to, the asset is
under `releases/download/$tag/`, and the digest is its `digest` field in
`https://api.github.com/repos/molchalih/rpfd/releases/tags/$tag`. Neither `gh`
nor `curl` quarantines what it downloads, so the `xattr` line only matters for a
file that came through a browser.

Then `PATH`. If the clean question above does not now answer
`~/.local/bin/rpf`, the shell is given one line, in the file and in the words
the extension's command uses — so that each recognises the other's line and
neither adds a second. Tell the user it was added.

```sh
line='export PATH="$HOME/.local/bin:$PATH"  # added by RPF Archives'
case "$(basename "$SHELL")" in
  zsh)  profile="${ZDOTDIR:-$HOME}/.zshrc" ;;
  bash) if [ "$(uname -s)" != Darwin ]; then profile="$HOME/.bashrc"
        elif [ ! -e "$HOME/.bash_profile" ] && [ -e "$HOME/.profile" ]; then profile="$HOME/.profile"
        else profile="$HOME/.bash_profile"; fi ;;
  fish) profile="${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d/rpf.fish"
        line='fish_add_path --path "$HOME/.local/bin"  # added by RPF Archives' ;;
  *)    echo "no profile known for $SHELL: tell the user" >&2; exit 1 ;;
esac
if ! grep -qxF "$line" "$profile" 2>/dev/null; then
  mkdir -p "$(dirname "$profile")"
  [ -s "$profile" ] && [ -n "$(tail -c 1 "$profile")" ] && echo >> "$profile"
  printf '%s\n' "$line" >> "$profile"
fi
```

Ask the clean question again; it now answers the binary's path. Undo is
deleting the binary and the line.

Both blocks were executed as written on 2026-10-09, macOS arm64, against
`v0.2.2`, with `HOME` pointed at a scratch directory. The first printed
`rpf 0.2.2`; a second run, and one with a dangling link where the binary goes,
stopped before downloading; the `curl` route produced the same digest. The
second added the line to `.zshrc` and, with `SHELL=/bin/bash`, to
`.bash_profile` — or to `.profile` where only that existed — once each over two
runs, after which the clean question answered the scratch binary and the first
block stopped with `rpf is already on PATH`. A copy prepended to `PATH` from a directory shaped
like the extension's was found by `command -v rpf` and not by the clean
question.

On Windows, in PowerShell. Written, not executed here — this machine has no
Windows. The user `Path` is read and written through the registry with its own
value kind, as the extension does, because `SetEnvironmentVariable` writes
`REG_SZ` and would stop `%USERPROFILE%`-style entries expanding; an entry is
compared after expansion, which matches it written either way.

```powershell
$ErrorActionPreference = 'Stop'
$dir = "$env:LOCALAPPDATA\Programs\rpf"
$hit = Get-Command rpf -ErrorAction SilentlyContinue
if ($hit -and $hit.Source -notlike '*\extensions\*rpf*\bin\*') { throw "rpf is already on PATH: $($hit.Source)" }
if (Test-Path "$dir\rpf.exe") { throw "$dir\rpf.exe already exists" }
$rel = Invoke-RestMethod 'https://api.github.com/repos/molchalih/rpfd/releases/latest'
$name = "rpf-$($rel.tag_name)-x86_64-pc-windows-msvc"
$a = $rel.assets | Where-Object name -eq "$name.zip"
$tmp = New-Item -ItemType Directory (Join-Path $env:TEMP ([guid]::NewGuid()))
Invoke-WebRequest $a.browser_download_url -OutFile "$tmp\$name.zip"
$got = 'sha256:' + (Get-FileHash "$tmp\$name.zip" -Algorithm SHA256).Hash.ToLower()
if ($got -ne $a.digest) { throw 'digest mismatch' }
Expand-Archive "$tmp\$name.zip" $tmp
New-Item -ItemType Directory -Force $dir | Out-Null
Copy-Item "$tmp\$name\rpf.exe" $dir
$key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
$raw = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
$kind = if ($key.GetValueNames() -contains 'Path') { $key.GetValueKind('Path') } else { [Microsoft.Win32.RegistryValueKind]::ExpandString }
$parts = @($raw -split ';' | Where-Object { $_ -ne '' })
$there = $parts | Where-Object {
  [Environment]::ExpandEnvironmentVariables($_.Trim('"')).TrimEnd('\') -ieq $dir.TrimEnd('\')
}
if (-not $there) {
  $key.SetValue('Path', (($parts + $dir) -join ';'), $kind)
  [Environment]::SetEnvironmentVariable('RPF_PATH_CHANGED', '1', 'User')
  [Environment]::SetEnvironmentVariable('RPF_PATH_CHANGED', $null, 'User')
}
& "$dir\rpf.exe" --version
```

The two `RPF_PATH_CHANGED` lines exist for their side effect: setting a user
variable broadcasts the change, so programs started afterwards see the new
`Path`. The shell that ran this does not. Undo is deleting the binary and the
`Path` entry, if this added it.

### 2. Each client that is present

**Every registration names the binary by its absolute path** —
`$HOME/.local/bin/rpf` expanded, or `%LOCALAPPDATA%\Programs\rpf\rpf.exe`.
These files are read by whatever starts the client, which is often a desktop app
or an editor rather than a terminal, and on macOS an app started from the Dock
or Finder starts with launchd's `/usr/bin:/bin:/usr/sbin:/sbin` and no shell
profile. The editor extension and the Claude Desktop bundle each carry their
own binary and need no path at all.

The release assets below come down and are checked exactly as the archive was
in step 1, with `--pattern` naming the asset.

**VS Code** — present if `code` is on `PATH` or, on macOS,
`/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code` exists,
or the same under `~/Applications`, which is then the command line to use. Look
first for a user-level registration an earlier `code --add-mcp` made: an `rpf`
under `servers` in `~/Library/Application Support/Code/User/mcp.json` on macOS,
`~/.config/Code/User/mcp.json` on Linux, `%APPDATA%\Code\User\mcp.json` on
Windows. If there is one, ask the user to let it go, because
the extension registers the server itself and the two would stand side by side.
For the same reason, **never run `code --add-mcp` here**. Then install the
platform's `.vsix` from [the table](#the-editor-extension):

```sh
code --install-extension rpf-vX.Y.Z-darwin-arm64.vsix
```

`code --list-extensions` then lists `molchalih.rpf`, and
`code --uninstall-extension molchalih.rpf` undoes it.

**Cursor** — present if `~/.cursor/` exists or, on macOS,
`/Applications/Cursor.app` does. A `cursor` on `PATH` is not proof: Cursor's
terminal agent installs a `cursor` shim into `~/.local/bin` that runs without
the editor. Register in `~/.cursor/mcp.json`, which the editor and the terminal
agent both read — merge an `rpf` entry into `mcpServers` and keep every entry
already there:

```json
{
  "mcpServers": {
    "rpf": {
      "command": "/Users/you/.local/bin/rpf",
      "args": ["serve", "--mcp"]
    }
  }
}
```

Undo is removing the `rpf` key. Measured from a scratch `HOME`, with the
terminal agent and not the editor: `cursor-agent mcp list-tools rpf` started the
server and listed the six tools, while `cursor-agent mcp list` went on reporting
`rpf: not loaded (needs approval)` — and `cursor-agent mcp enable rpf`, which
adds a server to that agent's approved list, answered that it already was. What
the editor asks the user before it starts the server was not checked. Nor is the
`.vsix` installed into Cursor: the extension registers its server through VS
Code's MCP provider API, and that Cursor honours it has not been checked.
`cursor --add-mcp` exists and is not used, for the same reason — where it
writes has not been checked either.

**Claude Code** — present if `claude` is on `PATH`. User scope, because this is
a machine install; `--scope project` would write one repository's `.mcp.json`:

```sh
claude mcp add --scope user rpf -- "$HOME/.local/bin/rpf" serve --mcp
```

Then read the `Status:` line of `claude mcp get rpf`, not its exit code: it
exits 0 for `✘ Failed to connect` as well as for `✔ Connected`. An existing
`rpf` makes the `add` fail with `MCP server rpf already exists in user config`,
which is a stop-and-ask. Undo with `claude mcp remove --scope user rpf`.

**Codex** — present if `codex` is on `PATH`. Check first, because
`codex mcp add` replaces an entry of the same name without asking:

```sh
codex mcp get rpf      # exit 1, "No MCP server named 'rpf' found.": go on
codex mcp add rpf -- "$HOME/.local/bin/rpf" serve --mcp
```

`codex mcp list` then shows `rpf` as `enabled` — without starting it, so it
confirms the registration and not the binary. Undo with `codex mcp remove rpf`.

**Claude Desktop** — detected here on macOS only, by `/Applications/Claude.app`;
elsewhere, tell the user the bundle exists and leave it to them. Download
`rpf-vX.Y.Z.mcpb` and hand it to the app with `open -a Claude rpf-vX.Y.Z.mcpb`.
The app shows an install dialog, and **the user answers it, not the agent**; say
so, and wait. Once accepted, `rpf` is listed under the app's extension settings,
and that is where it is removed.

The Codex commands were run against a scratch `CODEX_HOME`, the Claude Code ones
against a scratch `CLAUDE_CONFIG_DIR` and `HOME` — including a registration of a
missing binary, to see `claude mcp get` exit 0 on it — and `code --add-mcp`
against a scratch `--user-data-dir`, to see where it writes; all on 2026-10-09.
`code --install-extension` and the Claude Desktop step were checked against
`code --help` and the app's declared file types, not run.

### 3. The report

End by telling the user, in one list: the binary's path and `rpf --version`, any
profile line or `Path` entry added and the file it went into, each client
registered and the command that undoes it, and each client found and skipped,
with why — already registered, or waiting on a dialog only the user can answer.
The `vscode:mcp/install?…` link above ends in a dialog the same way, which is
why this procedure registers through the command line instead.
