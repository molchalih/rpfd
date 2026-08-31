# acceptance

The loop `docs/acceptance.md` describes, with the reading of the console line
mechanised: it stages an archive this tool produced where the game's own loader
will mount it, restarts the server that ships it, and answers with the log lines
that justify a classification rather than with a person's impression of them.

Run by hand on the acceptance machine, like `tools/oracle` and unlike
`tools/metadata-dump` it is a shell script rather than a workspace member,
because every one of its inputs is a file or a process on that machine: the
RAGE Multiplayer server's `dlcpacks` directory, the server console, the
client's own logs and the client's package cache.

**Nothing here reads a pixel.** Every value it prints comes from a log line, a
file length, a digest or process state.

## Running it

```
acceptance.sh install-instrument      # write the client and server JS halves
acceptance.sh stage <archive>         # verify it, serve it, restart the server
acceptance.sh launch                  # start the client (see below)
acceptance.sh watch --expect 1        # read the console until it answers
acceptance.sh status | cache          # what is installed, staged, cached
```

`run <archive>` is `stage`, `launch`, `watch` in one call.

Paths come from the environment where they differ per machine:
`RPF_ACCEPT_SERVER`, `RPF_ACCEPT_DLC`, `RPF_ACCEPT_CLIENT`, `RPF_ACCEPT_ADDR`,
`RPF_ACCEPT_STATE`, `RPF_BIN`.

## What it answers, and in whose vocabulary

`docs/acceptance.md` §5's, and it invents no class of its own:

| Result | Exit | Meaning |
|---|---|---|
| `in_cdimage=true class=1` | 0 | Pass. The container mounted and its metadata decoded — §13 for how narrow that is |
| `in_cdimage=true class=7` | 3 | An archive mounted, but not this one. A delivery defect, not a result |
| `in_cdimage=false` | 4 | The archive did not mount. The failure the loop exists to catch |
| no line | 5 | The loop broke, not the archive |

### The probe, and why it announces itself

A native call on this model can end the client process. Measured twice: on
2026-08-30 an access violation at module offset `0xf4cb31` about a second after
`IS_MODEL_IN_CDIMAGE` and `GET_VEHICLE_CLASS_FROM_NAME` (`docs/acceptance.md`
§13), and on 2026-09-01 the same offset with `REQUEST_MODEL` as the only native
the script had reached. So the danger is not two particular calls: it is any
model-info lookup on this model, and a probe that speaks only at the end of a
sequence gets killed before it says anything.

The probe therefore **announces every risky call before making it**, and makes
it a beat later so the announcement is on the wire first:

```
rpf:joined                       the client reached playerReady
rpf:probe stage=pre_natives      about to call IS_MODEL_IN_CDIMAGE
rpf:probe stage=post_cdimage in_cdimage=…
rpf:acceptance in_cdimage=… class=…      the archive's identity
rpf:probe stage=pre_request model=adder  about to call REQUEST_MODEL
rpf:probe stage=post_request     it returned
rpf:probe stage=pre_poll         about to poll HAS_MODEL_LOADED
rpf:streamed model=adder model_loaded=… waited_ms=…
rpf:error where=… message=…      any throw, on any path
```

The last line of a run that ends early therefore names what killed it.

### Why the streaming half asks about a stock model

Measured 2026-09-01, **on the control — the untouched sample**: `REQUEST_MODEL`
on `meringls63amg24` returned, `stage=post_request` reached the server, and the
client was dead before `stage=pre_poll` 400 ms later, at the same `0xf4cb31`.
Streaming this mod's vehicle ends this game build whatever archive it came out
of, so an observable built on it classifies nothing: it fails identically on a
good archive and a bad one.

So the streaming half asks about a **stock** model (`adder`). That measures the
probe rather than the payload — that requesting and polling works here at all —
which is what makes a `model_loaded=false` on a sample whose model does stream
mean "the payload did not load" rather than "the probe is broken". Point
`STREAM_MODEL_NAME` at a DLC model only when that model is known not to fault
this build. **Until such a sample exists, no run here is evidence about a large
binary payload**; `docs/acceptance.md` §13 stands.

`NATIVES_FIRST` is `true`: the class line — the one that says which archive the
game read — is emitted before anything that has been seen to end the process.
Setting it `false` puts the streaming half first, and is only worth doing when
the streamed model is known not to fault.

Nothing spins. The clocks are `setTimeout` and the render tick, which returns every frame, so the
network thread keeps servicing the connection; each frame makes at most one
native call, and the streaming ceiling is 8 s. `probe_test.js` checks all of
that without a game — `node tools/acceptance/probe_test.js`.

## The client's package cache

A joined server's `dlc.rpf` lands under
`C:\RAGEMP\client_resources\<32 hex digits>\`, one directory per server, with
every file named by a hash rather than by its path. `acceptance.sh cache` finds
it by the length of the archive that was staged, which is the only field that
survives the renaming.

## What a person still has to do, and why

Two acts, both at the machine, and neither is this script's to take.

**The UAC prompt.** The client starts `updater.exe` on every launch, and that
binary's manifest is `requestedExecutionLevel level='requireAdministrator'` —
so every launch raises an elevation prompt. A client that is not elevated stops
at a modal dialog reading `Please run updater.exe as admin.` and never writes a
line to its own log.

**The connect.** There is no direct-connect argument. The `rage://` handler is
registered — `HKCR\rage\shell\open\command` is `"C:\RAGEMP\ragemp_v.exe" "%1"` —
but a URI only opens the server browser; joining is the browser's own
`rageApi.launchGame(ip, port)`. The address the launcher last used is in
`HKCU\Software\RAGE-MP` (`launch.ip`, `launch.port`, `launch.type=connect`),
which is where to look to confirm which server a join was aimed at.

Everything on either side of those two acts — staging, verifying, restarting,
watching, classifying, finding the cache — is here.
