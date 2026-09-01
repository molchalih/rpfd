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

## Running it

```
acceptance.sh install-instrument      # write the client and server JS halves
acceptance.sh stage <archive>         # verify it, serve it, restart the server
acceptance.sh launch                  # start the client
acceptance.sh watch --expect 1        # read the console until it answers
acceptance.sh status | cache          # what is installed, staged, cached
```

`run <archive>` is `stage`, `launch`, `watch` in one call.

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

| Result | Exit | Meaning |
|---|---|---|
| `in_cdimage=true class=1` | 0 | Pass. The container mounted and its metadata decoded |
| `in_cdimage=true class=7` | 3 | An archive mounted, but not this one. A delivery defect, not a result |
| `in_cdimage=false` | 4 | The archive did not mount. The failure this loop exists to catch |
| no line | 5 | The loop broke, not the archive |

## The probe

A native call can end the client process — a model-info lookup on this game
build has done it repeatedly — and a probe that speaks only at the end of a
sequence gets killed before it says anything. So the instrument announces every
risky call before making it, and makes it a beat later:

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

The streaming half asks about a **stock** model (`adder`) rather than a modded
one, because streaming the sample's own vehicle ends this game build whatever
archive it came out of — an observable built on it fails identically on a good
archive and a bad one. Asking about a stock model measures the probe instead:
that requesting and polling works here at all. Point `STREAM_MODEL_NAME` at a
DLC model only when that model is known not to fault this build. Until then, no
run here is evidence about a large binary payload.

`NATIVES_FIRST` is `true`, so the class line — the one that says which archive
the game read — is emitted before anything that has been seen to end the
process. Setting it `false` puts the streaming half first, and is only worth
doing when the streamed model is known not to fault.

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
