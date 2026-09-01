# Driving rpf from a program

The agent client. There is nothing here to install — the client is the `rpf`
binary itself, and this page is its contract for a program that drives it: the
`--json` shape each command reports, what each exit code means for a caller, the
failure object `--json` answers with, `cat --out`, and four worked recipes.

`rpf` is the interface an automated caller wants: `--json` on every reporting
command, one exit code per class of failure, a free dry run before anything
destructive, and no session to open, hold or clean up. A call is a process. On
a 145 MB archive holding two nested archives, twenty full recursive listings —
twenty separate processes — measure 0.04 s in total, so the table of contents
is re-read per call and it costs nothing an agent can perceive.

Everything below was run against that archive and is copied from what came
back.

## The shape of a call

```
rpf [--json] [--cache-dir DIR] <command> <archive> [path] [options]
```

`--json` is global and goes before the command. A path inside an archive
addresses through nesting in one string, `/` on every platform:
`x64/vehiclemods/mods.rpf/part.yft`. The archive is a path on this machine; no
command moves bytes over a network.

## Reports

Every command below writes one JSON object — `ls` writes an array of them — to
standard output, pretty-printed.

| Command | Fields |
|---|---|
| `info` | `path`, `inside`, `len`, `encryption`, `entries`, `directories`, `binary_files`, `resource_files`, `nested_archives`, `unreferenced_bytes`, `locked_archives` |
| `ls` | rows of `path`, `kind`, `len`, `encoding` |
| `put` that fits where the entry is | `method: "patch"`, `path`, `at`, `len`, `allocation`, `dry_run` |
| `put --create`, `rm`, `mv`, `mkdir`, and a `put` that does not fit | `method: "rebuild"`, `path`, `entries`, `len` |
| any of those under `--dry-run` | `method: "rebuild"`, `path`, `structural`, `dry_run` |
| `extract` | `archive`, `into`, `files`, `directories`, `manifest` |
| `pack` | `archive`, `entries`, `len` |
| `verify` | `path`, `against`, `entries_checked`, `contents_checked`, `contents_recorded`, `problems` |
| `keys extract`, `keys cache`, `keys invalidate` | offsets, lengths, digests, counts and cache paths — never a key |

```
$ rpf --json info dlc.rpf
{
  "binary_files": 7,
  "directories": 4,
  "encryption": "OPEN",
  "entries": 11,
  "inside": "",
  "len": 144504832,
  "locked_archives": 0,
  "nested_archives": 2,
  "path": "dlc.rpf",
  "resource_files": 0,
  "unreferenced_bytes": 79345460
}
```

`kind` is `binary`, `resource` or `directory`. `encoding` is what the entry
holds — `xml`, `rbf`, `pso`, `meta` — or `null` where it is opaque bytes; it is
the field that says whether the entry has an XML view.

```
$ rpf --json ls dlc.rpf data
[
  {
    "encoding": "xml",
    "kind": "binary",
    "len": 1445,
    "path": "data/carvariations.meta"
  },
  ...
]
```

`ls -R` descends into directories and nested archives and has no filter: on this
archive it is 30 rows, and on a large one it is one row per entry. Ask for the
directory you want rather than the root where you can.

## Exit codes

| Code | Name | What it means for a caller |
|---|---|---|
| 0 | | It worked. The report on standard output is the answer |
| 1 | internal | A failure with no better classification. Report it |
| 2 | usage | The arguments were wrong. Fix the call. This one comes from the argument parser and is **not** JSON, whatever `--json` says |
| 3 | not found | Nothing at that path. Check the spelling with `ls`; `\` is not a separator |
| 4 | corrupt | The archive contradicts itself or does not decompress as it promises. Nothing to retry |
| 5 | needs key | The archive is encrypted and no key material is available. `keys extract` against a game source, then retry |
| 6 | refused | The request or its input was wrong, and the message says what would make it right. Some refusals name a switch that overrides them |
| 7 | io | The source or the sink failed. Nobody's input; retrying may work |
| 8 | cancelled | Stopped part-way by the caller |
| 9 | unsupported | Intact, and this build cannot read it — an archive version with no codec here |

## Failures

Under `--json` a failure is one JSON object on **standard error**, and the
exit code is the object's `code`:

```
$ rpf --json cat dlc.rpf data/absent.meta ; echo "exit=$?"
{
  "code": 3,
  "data": {
    "reason": "NotFound"
  },
  "message": "no entry at \"data/absent.meta\": \"absent.meta\" not found"
}
exit=3
```

Standard output carries what was asked for and nothing else, so a caller that
redirects only standard output never finds a failure mixed into an answer, and
one that captures neither still has the exit code.

`data.reason` is the failure's own symbol — a finer classification *within* a
code, never a replacement for one. Three refusals that share code 6 and nothing
else, as their `reason` and `message` came back:

| `reason` | `message` |
|---|---|
| `BadPath` | `invalid path "data": is a directory that is not empty` |
| `WrongEncoding` | `"des_hosp_ceil2.ytyp": an entry holding pso cannot take a payload of xml. Pass --allow-encoding-change to override, or convert the payload first` |
| `NoXmlView` | `"…_brabus_diffuser_1.yft": an entry holding no encoding this tool converts has no XML view` |

Match on `code` first and on `reason` only where two failures under one code
need different answers. The `message` is for a person to read; it is not a
contract. This is the same object the JSON-RPC daemon puts in its `error`
member, built by the same code, so the two cannot come to disagree.

Without `--json` a failure is the same sentence, prefixed `rpf: `, on standard
error.

## Payloads

`cat` writes one entry's contents. It is the one command whose answer is bytes
rather than a report.

**`--out FILE` writes the payload to a file** and reports the path and the
length instead of the bytes. This is the form to use from a program: an entry
can be tens of megabytes of compressed texture, and nothing is gained by moving
it through the caller.

```
$ rpf --json cat --out diffuser.yft dlc.rpf \
      x64/vehiclemods/meringls63amg24_mods.rpf/meringls63amg24_brabus_diffuser_1.yft
{
  "len": 144727,
  "path": "diffuser.yft"
}
```

**Bare `cat` refuses a payload that is not text** unless standard output is a
file. A terminal is ruined by binary and a pipe hands it to a caller with
nowhere to put it, so both are refused; a redirect to a file is not:

```
$ rpf cat dlc.rpf x64/…/meringls63amg24_brabus_diffuser_1.yft | wc -c ; echo ${PIPESTATUS[0]}
rpf: refusing: x64/…/meringls63amg24_brabus_diffuser_1.yft is not text and
standard output is a terminal or a pipe; pass --out FILE, or redirect standard
output to a file
       0
6

$ rpf cat dlc.rpf x64/…/meringls63amg24_brabus_diffuser_1.yft > diffuser.yft
$ echo $?
0
```

The refusal is on the destination and not on the command: a device that is not
a file — `/dev/null` among them — is refused the same way, and `--out` writes
wherever a file can be created.

`--as xml` converts an `rbf`, `pso` or `meta` entry to a document; `--as auto`
gives the document where there is one and the bytes where there is not. A
document is text, so it goes through a pipe unrefused — and it is still worth
`--out` if you are only going to edit it.

What `cat` writes raw is the form `put` takes back, which for a resource is its
stored payload: `--out` reported 144,727 bytes for a row whose `len` is 262,144.
The two numbers describe different things and neither is wrong.

## Four recipes

### Inspect an archive

```
$ rpf --json info dlc.rpf                 # counts, length, encryption
$ rpf --json ls dlc.rpf                   # the root
$ rpf --json ls dlc.rpf data              # one directory
$ rpf --json ls -R dlc.rpf                # everything, nested archives included
```

`unreferenced_bytes` from `info` is space no entry claims; `locked_archives` is
nested archives that need key material this run does not have.

### Read a metadata entry as XML

```
$ rpf --json cat --as xml --out ceil.xml des_hosp_ceil2.rpf des_hosp_ceil2.ytyp
{
  "len": 1108,
  "path": "ceil.xml"
}

$ head -3 ceil.xml
<?xml version="1.0" encoding="UTF-8"?>
<hash_D98BB561 pso:struct="hash_D98BB561">
  <hash_F17E7F28 pso:array="atarray"/>
```

The entry's `encoding` from `ls` says whether there is a view to ask for. An
entry with `"encoding": null` has none, and asking is refused — code 6, reason
`NoXmlView` — rather than answered with bytes.

### Make an edit and verify it

Take the document out, edit it, ask what writing it back would do, do it, read
it back, and check the archive:

```
$ rpf --json cat --as xml --out vehicles.xml dlc.rpf data/vehicles.meta
{
  "len": 5100,
  "path": "vehicles.xml"
}

… edit vehicles.xml …

$ rpf --json put dlc.rpf data/vehicles.meta vehicles.xml --as xml --dry-run
{
  "allocation": 2048,
  "at": 2048,
  "dry_run": true,
  "len": 1632,
  "method": "patch",
  "path": "data/vehicles.meta"
}

$ rpf --json put dlc.rpf data/vehicles.meta vehicles.xml --as xml
{
  "allocation": 2048,
  "at": 2048,
  "dry_run": false,
  "len": 1632,
  "method": "patch",
  "path": "data/vehicles.meta"
}

$ rpf cat --as xml dlc.rpf data/vehicles.meta | grep residentTxd
  <residentTxd>vehshare2</residentTxd>

$ rpf --json verify dlc.rpf
{
  "against": null,
  "contents_checked": 0,
  "contents_recorded": 0,
  "entries_checked": 27,
  "path": "dlc.rpf",
  "problems": []
}
```

`method` says which of the two things happened. A `patch` writes the payload in
the room the entry already has and moves nothing else. A `rebuild` writes the
whole archive to a scratch file beside it and replaces it in one step, so an
interrupted rebuild leaves the original untouched. Creating, removing, renaming
and adding a directory always rebuild, and a dry run says so and why:

```
$ rpf --json put dlc.rpf data/added.meta vehicles.xml --create --dry-run
{
  "dry_run": true,
  "method": "rebuild",
  "path": "data/added.meta",
  "structural": "adds an entry"
}
```

`verify` reads every entry back against what the archive says about it, and
reports what it found in `problems` rather than as a failure — the call did what
it was asked. `problems` is an array of `{path, reason}`. Checking an entry's
*contents* needs a record of what they should be, which only an extracted tree
carries: `verify` alone checked 27 entries and 0 contents above.

### Pack a tree

```
$ rpf --json extract dlc.rpf tree
{
  "archive": "dlc.rpf",
  "directories": 3,
  "files": 7,
  "into": "tree",
  "manifest": "tree/.rpf-manifest.json"
}

$ rpf --json pack tree rebuilt.rpf
{
  "archive": "rebuilt.rpf",
  "entries": 11,
  "len": 65160704
}

$ rpf --json verify rebuilt.rpf --against tree
{
  "against": "tree",
  "contents_checked": 7,
  "contents_recorded": 7,
  "entries_checked": 27,
  "path": "rebuilt.rpf",
  "problems": []
}
```

`extract` refuses a directory that already holds anything unless told
`--overwrite`; `pack` refuses to write into a detected game installation unless
told `--force`. The manifest beside the tree records each entry's storage,
flags and checksum, which is what makes `verify --against` able to check
contents at all.
