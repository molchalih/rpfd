# acceptance

Shows an archive `rpf` produced to the game itself. It stages the archive where
a RAGE Multiplayer server's own loader will pick it up, restarts the server,
starts the client, and reads the console until the client says whether the game
mounted the archive and decoded its metadata.

Run by hand, on a machine that has the server, the client and a game install.
It is a shell script rather than a workspace member because every one of its
inputs is a file or a process on that machine: the server's `dlcpacks`
directory, the server console, the client's logs and the client's package
cache.

**Nothing here reads a pixel.** Every value it prints comes from a log line, a
file length, a digest or process state.

This page cites two local documents below — `docs/acceptance.md`, the procedure
this script mechanises, and `docs/acceptance-runs.md`, the log of dated runs.
Both are working material a clone does not carry, as `README.md` explains, and
nothing here needs them read: what a run showed is quoted where it is cited.

## Running it

```
acceptance.sh install-instrument      # write the client and server JS halves
acceptance.sh restart                 # reload the instrument, keep the archive
acceptance.sh stage <archive>         # verify it, serve it, restart the server
acceptance.sh launch                  # start the client
acceptance.sh watch --expect 1        # read the console until it answers
acceptance.sh run <archive>           # stage, launch and watch in one call
acceptance.sh status                  # what is installed, staged and running
acceptance.sh cache                   # the client's package cache for this server
```

Those eight are every subcommand, not a sample. Anything else prints the
script's own header and leaves with 2. `stage` also takes
`--allow-unverified`; `watch` and `run` take `--timeout SEC` and `--expect N`.

Paths differ per machine and come from the environment: `RPF_ACCEPT_SERVER`,
`RPF_ACCEPT_DLC`, `RPF_ACCEPT_CLIENT`, `RPF_ACCEPT_ADDR`, `RPF_ACCEPT_STATE`
and `RPF_BIN`.

`node probe_test.js` checks the client instrument's control flow without a
game.

## Two rules for staging

**The archive must differ in length from the last one served.** A client does
not re-fetch a `dlc.rpf` of the same length as the one it already has, whatever
the contents, and the console line looks the same either way. If an edit does
not change the length, change it deliberately — an extra small entry does it. A
differing length is necessary but not sufficient; a reconnect has been seen to
decline a re-fetch across a 512-byte difference.

**The join must be a fresh start from the launcher, not a reconnect.** A DLC
pack is mounted at game start, so a client that downloads a newly staged
archive after it has already started is still running the previous one.

## The delivery gate

`acceptance.sh` decides whether a run is about the archive you staged, from
four timestamps: when it staged, the mtime of the archive in the client's
package cache, the `started at` line of the client log, and the `at=` of the
report line itself. The run is readable only if they are in that order:

```
staged <= cached <= client started <= reported
```

The fourth matters because the first three describe the machine as it is now,
not the transcript in the log: a report written before the current client
started came from the previous one. The script prints `delivery: fresh` or
`delivery: VOID …` with the reason.

**Read the `delivery:` line before the `result:` line.** Joins have printed a
passing-looking result for an archive the run was not about.

## What it answers

These are every code the script can leave with, not a sample of them. A wrapper
that treats an undocumented one as a crash gets the last two rows wrong.

| Result | Exit | Meaning |
|---|---|---|
| `in_cdimage=true class=1` | 0 | Pass. The container mounted and its metadata decoded. The class compared against is `--expect`, and `1` is its default |
| `in_cdimage=true class=7` | 3 | An archive mounted, but not this one. A delivery defect, not a result |
| `in_cdimage=false` | 4 | The archive did not mount. The failure this loop exists to catch |
| no line | 5 | The loop broke, not the archive. The line says whether the client joined first, and what it last announced |
| `unexpected — <line>` | 6 | A report line that is none of the four above — an `in_cdimage=true` with some other class. The harness is saying it does not know what this is, which is not the same as a crash and must not be wrapped as one |
| — | 2 | The harness refused to run at all: an unknown subcommand or option, a missing binary, an unreadable archive, no run log. It says nothing about any archive |

`watch` and `run` print `exit: N` on stdout as well as leaving with it, because
a caller that pipes the run through `tail` reads the pipe's status and not the
harness's.

## The probe

A native call can end the client process — a model-info lookup on this game
build has done it repeatedly — and a probe that speaks only at the end of a
sequence gets killed before it says anything. So the instrument announces every
risky call before making it, and makes it a beat later. Its whole vocabulary,
which is `client_index.js`'s `say()` calls and nothing else:

| Event | Said when |
|---|---|
| `rpf:joined model=… hash=…` | the client reached `playerReady` |
| `rpf:probe stage=pre_natives` | about to call `IS_MODEL_IN_CDIMAGE` |
| `rpf:probe stage=post_cdimage in_cdimage=…` | it returned, before the second native |
| `rpf:acceptance in_cdimage=… class=…` | the archive's identity — the line the exit codes above are read from |
| `rpf:probe stage=pre_request model=…` | about to call `REQUEST_MODEL`, naming which model |
| `rpf:probe stage=post_request` | it returned |
| `rpf:probe stage=pre_poll` | about to poll `HAS_MODEL_LOADED` |
| `rpf:streamed model=… model_loaded=… waited_ms=…` | that model resolved, or the 8 s ceiling expired |
| `rpf:error where=… message=…` | any throw, on any path |

The last line of a run that ends early therefore names what killed it. The four
`pre_request` … `streamed` events repeat once per model in the list below.

A real run of it — `docs/acceptance-runs.md` §26, executed 2026-09-01, as that
section records it less its `delivery:` line. `MODEL_NAME` was `volga5` that
day; it is `vesta` now:

```
rpf:acceptance in_cdimage=true class=3                            16:19:56.447Z
rpf:streamed   model=adder  model_loaded=true waited_ms=5         16:19:58.885Z
rpf:streamed   model=avarus model_loaded=true waited_ms=9         16:20:00.512Z
rpf:probe      stage=pre_request model=volga5                     16:20:00.908Z
rpf:probe      stage=post_request                                 16:20:01.324Z
   (no pre_poll — the client ended)
```

### The three models, and the two controls

`STREAM_MODEL_NAMES` in `client_index.js` is the list the streaming half walks,
in order, one `REQUEST_MODEL` and one poll each. It is
`["adder", DLC_CONTROL_NAME, MODEL_NAME]`, and the first two are controls:

| Model | What a `model_loaded=true` on it separates |
|---|---|
| `adder`, a base-game vehicle | a broken probe from a payload that did not load. It says requesting and polling work here at all |
| `avarus`, a **Rockstar DLC** vehicle from `mpbiker` — declared in that pack's own `vehicles.meta`, with `avarus.yft` (2,359,296 bytes) inside `mpbikervehicles.rpf`, a nested archive inside a `dlc.rpf` | the **harness** from the **archive**. It is structurally what the pack under test is, differing in exactly one thing: the game mounts `mpbiker` from its own install, and mounts ours because a server handed it over |
| `MODEL_NAME`, the pack's own model | nothing — it is the question. It is asked last, so a death on it is attributable, and both controls are already banked |

Each control differs from the subject in one thing, which is the whole of why
the sequence is readable. The order is not cosmetic: an answer that arrives
after the crash is not an answer.

**What this has shown about a large binary payload, precisely.** In §26 `avarus`
loaded in **9 ms**, in the same session, 400 ms before the served pack's model
ended the client. So **the loop is not the limit**: this harness can watch the
game read a multi-megabyte asset out of a nested archive inside a `dlc.rpf`.
What it has never watched is one come out of a **served** pack. §29 then
established why — three mods, three packs, two packer fingerprints, every
`REQUEST_MODEL` faulting at one module offset while `avarus` streamed beside
them — and the conclusion is a fact about delivery: a served pack's assets do
not reach the streaming index the way an installed pack's do. So a `streamed`
line for `adder` or `avarus` is evidence about the harness, and **no run here
is evidence about a large binary payload out of an archive this tool wrote**,
nor can one be until a different instrument mounts such an archive as an
installed pack. `docs/acceptance.md` §9 is the standing account of what a pass
proves; the container half is well evidenced and the streaming half is out of
reach.

Pointing `MODEL_NAME` at another pack does not change that, and neither does
adding a fourth name. The thing to change is the instrument, and §29 names the
one that would answer it.

`NATIVES_FIRST` is `true`, so the class line — the one that says which archive
the game read — is emitted before anything that has been seen to end the
process. Setting it `false` puts the streaming half first, and is only worth
doing when every model in the list is known not to fault.

**These names are `client_index.js`'s, not this page's.** A change to
`STREAM_MODEL_NAMES`, `MODEL_NAME`, `DLC_CONTROL_NAME`, `NATIVES_FIRST` or the
`say()` vocabulary updates this section in the same change. The last drift here
lasted from 2026-09-01 to 2026-09-07: one commit replaced a single
`STREAM_MODEL_NAME` constant with the array above and rewrote this paragraph
without carrying the rename into it, leaving a knob no reader could set.

Nothing spins. The clocks are `setTimeout` and the render tick, so the network
thread keeps servicing the connection; each frame makes at most one native
call, and the streaming ceiling is 8 s.

## The client's package cache

A joined server's `dlc.rpf` lands under `C:\RAGEMP\client_resources\<32 hex
digits>\`, one directory per server, with every file named by a hash rather
than by its path. `acceptance.sh cache` finds it by the length of the archive
that was staged, which is the only field that survives the renaming.

## Two things you have to do by hand

**The UAC prompt.** The client starts `updater.exe` on every launch, and that
binary requires administrator elevation, so every launch raises a prompt. A
client that is not elevated stops at a dialog reading `Please run updater.exe
as admin.` and never writes a line to its own log.

**The connect.** There is no direct-connect argument. The `rage://` handler is
registered, but a URI only opens the server browser; joining is the browser's
own `rageApi.launchGame(ip, port)`. The address the launcher last used is in
`HKCU\Software\RAGE-MP` (`launch.ip`, `launch.port`, `launch.type=connect`),
which is where to confirm which server a join was aimed at.

Everything on either side of those two acts — staging, verifying, restarting,
watching, classifying, finding the cache — the script does.
