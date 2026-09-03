# Driving rpf from an MCP client

The Model Context Protocol client. There is nothing here to install — the server
is the `rpf` binary itself, run as `rpf serve --mcp`, and this page is what a
person needs to register it and read a transcript of it afterwards.

`clients/agent/README.md` is the same page for the command line. Read that one
first if what you have is a program rather than a model: a call is a process,
there is no protocol to speak, and it is the simpler surface by some distance.

## Registering it

The transport is stdio: one JSON object per line on standard input and standard
output, and nothing else on standard output ever. Most clients take a command
and its arguments:

```json
{
  "mcpServers": {
    "rpf": {
      "command": "/path/to/rpf",
      "args": ["serve", "--mcp"]
    }
  }
}
```

Add `"--cache-dir", "/path/to/keys"` to `args` if you keep extracted key
material somewhere other than the platform's configuration directory. **The
cache directory is a command-line argument and nothing else.** No tool takes
one, because a cache directory reachable from a tool argument is a path a model
chooses for key material.

## The two eras

The server speaks both eras of the protocol and picks one per connection, from
how the client opens.

A client that carries the revision in each request's `_meta` gets `2026-07-28`:
stateless, `server/discover` first, `resultType`, `ttlMs` and `cacheScope` on
the results that may be cached. That is the only revision reachable that way; a
request declaring any other in `_meta` is answered `-32022`.

A client that opens with `initialize` gets a handshake revision instead —
`2025-11-25`, `2025-06-18`, `2025-03-26` or `2024-11-05`. It is answered the one
it asked for where this server has it, and `2025-11-25` where it did not, which
leaves the client the decision. After that there is no `_meta` to send, no
`server/discover` to call, and the results carry none of the caching fields. A
revision older than `2025-06-18` is not sent `structuredContent`, a tool `title`
or a `resource_link` — the file `rpf_read` wrote is named in a text block
instead — and one older than `2025-03-26` is not sent tool annotations, because
those revisions do not have them.

`ping` is answered with an empty result in either era, which every revision
requires of both ends.

The six tools, their schemas, their bounds and the way a failure comes back are
the same either way. Only the envelope differs.

## Which file to download

`INSTALL.md` names the asset each platform takes, for every artefact this
project ships. It owns that table; repeating it here is how the two drift when
`release.yml` gains a target.

`rpf-vX.Y.Z.mcpb` is the one that needs no matching: it carries macOS as a
universal binary, Linux x86-64 and Windows x86-64, and Claude Desktop picks the
right one.

Linux arm64 and Windows arm64 are not built. Build from source.

## Per client

The transport and the argument list are the same everywhere; what differs is
the file, and in one case the key inside it.

<details>
<summary><b>Claude Code</b></summary>

`.mcp.json` at the repository root, which is the scope the whole team shares:

```json
{
  "mcpServers": {
    "rpf": {
      "command": "/path/to/rpf",
      "args": ["serve", "--mcp"]
    }
  }
}
```

Or let the CLI write it. Everything after `--` is passed to the server
untouched, which is why the two `rpf` arguments need no escaping:

```sh
claude mcp add --scope project rpf -- /path/to/rpf serve --mcp
```

</details>

<details>
<summary><b>Claude Desktop</b></summary>

Download `rpf-vX.Y.Z.mcpb` from the release and open it. Claude Desktop shows
an install dialog; there is no JSON to write and no path to name, because the
bundle carries the binary and the manifest names the command.

The bundle installs with the default cache directory. If you keep key material
somewhere else, register the binary by hand with `--cache-dir` instead, as
above.

</details>

<details>
<summary><b>VS Code</b></summary>

Installing the extension is enough — it hands the editor the binary it ships
with, and `clients/vscode/README.md` is that story.

To register the binary directly instead, `.vscode/mcp.json`. **The key is
`servers`, not `mcpServers`**, and it is the one place in this page where that
is true:

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

VS Code can sandbox a stdio server on macOS and Linux — `"sandboxEnabled":
true` beside the fields above, off unless you ask for it. Switch it on and an
archive outside the workspace stops being reachable, which is most of them.

</details>

<details>
<summary><b>Cursor</b></summary>

`.cursor/mcp.json`, back to `mcpServers`:

```json
{
  "mcpServers": {
    "rpf": {
      "command": "/path/to/rpf",
      "args": ["serve", "--mcp"]
    }
  }
}
```

</details>

## Where the bundle comes from, and the registry

`tools/mcpb/` holds the manifest and the assembler; the `bundle` job in
`.github/workflows/release.yml` runs it over the binaries the release already
carries and attaches `rpf-vX.Y.Z.mcpb`. The same job renders
`tools/mcpb/server.json` — the MCP registry entry for `io.github.molchalih/rpfd`
— with the tag's version, the asset's URL and its SHA-256, and attaches that
too.

Attaching it is as far as automation goes. Publishing needs a device-code login
that is a credential, so it is two commands run by hand, from a directory
holding the `server.json` the release attached:

```sh
mcp-publisher login github
mcp-publisher publish server.json
```

Registry versions are immutable and there is no unpublish.

An `mcpb` package carries its full download URL in `identifier` and must not
carry `registryBaseUrl`. The published schema permits the field, so nothing in
this tree catches it; the registry refuses the publish, which is how v0.2.0's
entry was found wrong after the release had already built it.

## The six tools

| Tool | What it does | Annotated |
|---|---|---|
| `rpf_info` | Summarise an archive, or one nested inside it | read-only |
| `rpf_list` | List what is at a path, filtered and paged | read-only |
| `rpf_read` | Read one entry, as its bytes or as its XML view | **destructive**, because `out` replaces a file |
| `rpf_plan` | Report what a change set would do, and write nothing | read-only |
| `rpf_apply` | Apply a change set: writes, removals, renames, directories | **destructive** |
| `rpf_verify` | Read every entry back and check it against what the archive says | read-only |

`rpf_plan` and `rpf_apply` take the same arguments but for `allow_game_install`,
which only `rpf_apply` has. That is deliberate and it is the reason there are two
tools rather than one with a `dry_run` argument: a client that puts the
destructive tool behind a confirmation prompt would otherwise put the free dry
run behind the same prompt, at exactly the moment the dry run is worth having.

### What is not here, and why

- **No `extract` and no `pack`.** An agent that needs a whole tree can run the
  binary; the guardrails those two carry (`extract` refuses a non-empty
  directory, `pack` refuses a game installation) are therefore not reachable
  from here at all rather than reachable and weakened.
- **No `keys` anything.** DR-006 and DR-020 keep key material at arm's length
  from a tool a model can call speculatively. Run `rpf keys extract` yourself.
- **No entry bytes inline, in either direction.** `rpf_read` writes to a file
  you name and answers a link; `rpf_apply` reads from a file you name. Nothing
  on this wire is ever base64.
- **No progress notifications.** A long `rpf_verify` reports nothing until it
  finishes. Cancelling it is the only feedback there is, and a cancelled request
  is answered with silence, because the protocol forbids any further message
  about it.

## How a failure looks

A tool that ran and did not succeed answers a **result**, not a JSON-RPC error:
`isError: true`, and a `structuredContent` of `{code, message, data: {reason}}`
— the same object `rpf --json` writes to standard error and the same one
`serve --stdio` puts in its `error` member. `code` is the exit code the command
line would use; `data.reason` is the failure's own symbol. Match on `code`
first.

JSON-RPC errors are reserved for the request itself: `-32700` for a line that is
not JSON, `-32600` for one that is not a request, `-32601` for an unknown
method, `-32602` for a missing parameter or an unknown tool, and `-32022` for a
revision no request may declare. There are six and no more.

Argument validation is this server's own, so a bad argument comes back as a
result with `code: 2` and `reason: "InvalidArguments"` — where the command line
would exit 2 out of the argument parser with no JSON at all.

## Two things a transcript will look wrong about

**`--force` in a message that has no `--force`.** `Failure::GameInstall`'s
sentence says "Pass --force to override", because one function renders a failure
for every frontend and rewording it per frontend would be a second spelling of
one fact. On this wire the argument is `allow_game_install`. What carries the
truth is `data.reason`, which is `GameInstall` or `UncertainInstall`, and the
`rpf_apply` description, which names the argument. The two translations:

| The message says | This wire calls it |
|---|---|
| `--force` | `allow_game_install` |
| `--allow-encoding-change` | `allow_encoding_change` |

**`as` defaults to `auto` here.** Everywhere else in this project it defaults to
`raw`, because a wire addition must not change what an existing request meant.
This surface had no existing requests when it was written, and a model asking
for a `.meta` almost always wants the document.

## Bounds

| What | Bound |
|---|---|
| Contents `rpf_read` will send inline | 32 KiB, and text only. Anything else needs `out` |
| A whole result line | 96 KiB |
| Rows `rpf_list` returns | 200 by default, 1000 at most, and fewer if they will not fit |
| Problems `rpf_verify` carries | 100, with `problems_total` beside them |
| Changes one `rpf_apply` takes | 256 |

Nothing is ever truncated to fit: `rpf_read` refuses and names `out`, because a
truncated XML document is one a model will edit and hand back, and that is data
loss reported as a success. A listing is the exception, and it says so —
`truncated`, `total` and `returned` are how you tell "narrow this" from "ask for
the next page".
