#!/usr/bin/env bash
# The acceptance loop, driven from a shell. docs/acceptance.md is the procedure;
# this is that procedure with the reading of the console line mechanised, so a
# run answers with the log lines that justify it rather than with an impression.
#
# It runs ON the acceptance machine — the one holding the RAGE Multiplayer
# server, the client and the game — because every one of its inputs is a file
# or a process there. Nothing here reads a pixel: the evidence is the server
# console, the client's own logs, process state and file sizes.
#
#   acceptance.sh stage   <archive>        put an archive in front of the client
#   acceptance.sh watch   [--timeout SEC]  read the console until it answers
#   acceptance.sh run     <archive> [...]  stage, then watch
#   acceptance.sh launch                   start the client (see LAUNCHING)
#   acceptance.sh status                   what is installed, staged and running
#   acceptance.sh install-instrument       write the client/server JS halves
#   acceptance.sh restart                  reload the instrument, keep the archive
#   acceptance.sh cache                    the client's package cache for this server
#
# LAUNCHING, and the one thing this cannot do headlessly. The RAGE Multiplayer
# client starts `updater.exe` on every launch, and that binary's own manifest
# is `requestedExecutionLevel level='requireAdministrator'`, so a launch raises
# a UAC prompt that only a person at the machine may answer. A join is then
# initiated from the launcher's server browser, which calls `rageApi.launchGame`
# — there is no direct-connect argument and the `rage://` handler only opens the
# browser. `launch` therefore starts the client and stops; the prompt and the
# connect are the human's two acts, and everything before and after them is
# here.
set -euo pipefail

SERVER_ROOT=${RPF_ACCEPT_SERVER:-$HOME/ragemp-server/ragemp-srv}
DLC_NAME=${RPF_ACCEPT_DLC:-meringls63amg24}
DLC_DIR=$SERVER_ROOT/client_packages/game_resources/dlcpacks/$DLC_NAME
STATE_DIR=${RPF_ACCEPT_STATE:-$HOME/acceptance/harness}
CLIENT_ROOT=${RPF_ACCEPT_CLIENT:-/mnt/c/RAGEMP}
SERVER_ADDR=${RPF_ACCEPT_ADDR:-$(hostname -I | awk '{print $1}'):22005}
RPF=${RPF_BIN:-rpf}
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

log() { printf '%s\n' "$*" >&2; }
die() { log "acceptance: $*"; exit 2; }

run_log() { printf '%s/run.log' "$STATE_DIR"; }

# ---------------------------------------------------------------- instrument

install_instrument() {
    [ -d "$SERVER_ROOT" ] || die "no server at $SERVER_ROOT"
    mkdir -p "$STATE_DIR"
    local client=$SERVER_ROOT/client_packages/index.js
    local server=$SERVER_ROOT/packages/rpfloop/index.js
    for f in "$client" "$server"; do
        [ -f "$f" ] && [ ! -f "$STATE_DIR/$(basename "$(dirname "$f")").orig.js" ] &&
            cp "$f" "$STATE_DIR/$(basename "$(dirname "$f")").orig.js"
    done
    cp "$HERE/client_index.js" "$client"
    mkdir -p "$(dirname "$server")"
    cp "$HERE/server_index.js" "$server"
    log "instrument installed: $client, $server"
}

# ------------------------------------------------------------------- staging

server_stop() {
    local pid
    pid=$(pgrep -x ragemp-server || true)
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    for _ in $(seq 20); do pgrep -x ragemp-server >/dev/null || break; sleep 0.5; done
}

server_start() {
    mkdir -p "$STATE_DIR"
    : > "$(run_log)"
    ( cd "$SERVER_ROOT" && setsid nohup ./ragemp-server >>"$(run_log)" 2>&1 & )
    for _ in $(seq 60); do
        grep -aq "ready to accept connections" "$(run_log)" && return 0
        sleep 0.5
    done
    die "server did not report ready; see $(run_log)"
}

stage() {
    local archive=${1:?usage: stage <archive> [--allow-unverified]}
    local allow_unverified=${2:-}
    [ -f "$archive" ] || die "no such archive: $archive"
    [ -d "$DLC_DIR" ] || die "no dlcpack directory at $DLC_DIR"

    # The tool reads its own output back before the game is asked to. An archive
    # our own reader rejects would make the run a test of the harness.
    #
    # `--allow-unverified` is for the one case that is not that: a producer's
    # own archive, unmodified, that this reader is stricter than the game about.
    # It says so loudly, because the difference between "our reader is strict"
    # and "this file is damaged" is a judgement, and a run made on the wrong
    # side of it is worthless.
    if command -v "$RPF" >/dev/null 2>&1; then
        if ! "$RPF" verify "$archive" >&2; then
            if [ "$allow_unverified" = "--allow-unverified" ]; then
                log ""
                log "WARNING: staging an archive this reader does not accept."
                log "WARNING: the run measures the game, so state in the record why the"
                log "WARNING: refusal is this reader's strictness and not damage."
                log ""
            else
                die "$archive does not verify; not staging it (--allow-unverified overrides)"
            fi
        fi
    else
        log "warning: no $RPF on PATH, staging unverified"
    fi

    server_stop
    cp "$archive" "$DLC_DIR/dlc.rpf"
    mkdir -p "$STATE_DIR"
    printf '%s\n' "$archive" > "$STATE_DIR/staged.path"
    stat -c %s "$archive" > "$STATE_DIR/staged.size"
    sha256sum "$archive" | cut -d' ' -f1 > "$STATE_DIR/staged.sha256"
    date +%s > "$STATE_DIR/staged.at"

    log "staged : $(basename "$archive")"
    log "sha256 : $(cat "$STATE_DIR/staged.sha256")"
    log "bytes  : $(cat "$STATE_DIR/staged.size")"
    server_start
    log "weight : $(grep -a 'weight' "$(run_log)" | tail -1 | tr -d '\r')"
    log "address: $SERVER_ADDR"
}

# ----------------------------------------------------------- client packages

# Where a joined server's dlc.rpf lands on the client. RAGE Multiplayer keeps
# one directory per server under client_resources, named by a hash of the
# server, and every file in it is named by a hash rather than by its path — so
# the archive is found by its length, which is the length we staged.
cache_dir() {
    local want
    want=$(cat "$STATE_DIR/staged.size" 2>/dev/null || echo 0)
    [ "$want" -gt 0 ] || return 1
    local d hit
    for d in "$CLIENT_ROOT"/client_resources/*/; do
        [ -d "$d" ] || continue
        # A server's package directory holds a handful of files. The one other
        # directory here is a 26 GB production server's cache with tens of
        # thousands, and walking it costs minutes, so it is skipped by count
        # before anything is stat'ed.
        [ "$(ls -1 "$d" 2>/dev/null | head -64 | wc -l)" -lt 64 ] || continue
        hit=$(find "$d" -maxdepth 1 -type f -size "${want}c" -print -quit 2>/dev/null)
        [ -n "$hit" ] && { printf '%s\n' "$d" | tee "$STATE_DIR/cache.dir"; return 0; }
    done
    # Not found by length is itself informative — the client holds no copy of
    # what is staged — so fall back to the directory a previous run identified,
    # which is what lets the delivery gate say VOID rather than say nothing.
    if [ -s "$STATE_DIR/cache.dir" ]; then
        cat "$STATE_DIR/cache.dir"
        return 0
    fi
    return 1
}

# Whether what the client has MOUNTED is what is staged, decided from three
# timestamps and nothing else — no pixels, no memory, no game.
#
# Two ways a run is void, both measured here on 2026-09-01 and both invisible in
# the console line when two archives share a class value:
#
#   cache older than the staging  the client never fetched the staged archive.
#                                 RAGE Multiplayer did not re-fetch a dlc.rpf of
#                                 the SAME LENGTH and different content, so a
#                                 perturbation must change the archive's length.
#   cache newer than the client   it fetched it, but a pack is mounted at game
#                                 start, so the running client still holds the
#                                 previous archive. A reconnect does not remount.
#
# Deliverable is `staged <= cached <= started`.
delivery_note() {
    local log_file=${1:-}
    local main=$CLIENT_ROOT/clientdata/main_logs.txt
    local d big started_at cached_at staged_at reported_at ok=0
    d=$(cache_dir) || return 0
    big=$(ls -S "$d" 2>/dev/null | head -1)
    [ -n "$big" ] || return 0
    cached_at=$(stat -c %Y "$d$big")
    staged_at=$(cat "$STATE_DIR/staged.at" 2>/dev/null || echo 0)
    [ -f "$main" ] || return 0
    # `... started at 01-09-2026 02:56:37`, day first, local time.
    started_at=$(head -1 "$main" | sed -n 's/.*started at \([0-9]\{2\}\)-\([0-9]\{2\}\)-\([0-9]\{4\}\) \([0-9:]*\).*/\3-\2-\1 \4/p')
    [ -n "$started_at" ] || return 0
    started_at=$(date -d "$started_at" +%s 2>/dev/null) || return 0

    printf 'delivery: staged %s, cached %s, client started %s\n' \
        "$(date -d "@$staged_at" '+%F %T')" \
        "$(date -d "@$cached_at" '+%F %T')" \
        "$(date -d "@$started_at" '+%F %T')"

    if [ "$cached_at" -lt "$staged_at" ]; then
        printf '%s\n' 'delivery: VOID - the client never fetched the staged archive; its cached copy predates the staging.'
        printf '%s\n' 'delivery: a same-length archive is not re-fetched. Stage one whose LENGTH differs from the last.'
        ok=1
    elif [ "$cached_at" -gt "$started_at" ]; then
        printf '%s\n' 'delivery: VOID - the staged archive was downloaded AFTER this client started.'
        printf '%s\n' 'delivery: a pack is mounted at game start, so what it has mounted is the previous archive.'
        printf '%s\n' 'delivery: the client must be started again before this run means anything.'
        ok=1
    else
        printf '%s\n' 'delivery: fresh - the staged archive was fetched before this client started.'
    fi

    # The three timestamps above describe the machine as it is NOW. They do not
    # say that the transcript in the run log came from the client they describe:
    # a report written before the current client started is a report from the
    # previous one, and it will sit in the log looking like a result. So the
    # report's own time is the fourth timestamp, and the order that makes a run
    # readable is  staged <= cached <= started <= reported.
    if [ -n "$log_file" ] && [ -f "$log_file" ]; then
        reported_at=$(grep -a '^rpf:acceptance' "$log_file" | tail -1 |
            sed -n 's/.*at=\([0-9T:.-]*Z\).*/\1/p')
        if [ -n "$reported_at" ]; then
            reported_at=$(date -d "$reported_at" +%s 2>/dev/null) || reported_at=
        fi
        if [ -n "$reported_at" ]; then
            printf 'delivery: reported %s\n' "$(date -d "@$reported_at" '+%F %T')"
            if [ "$reported_at" -lt "$started_at" ]; then
                printf '%s\n' 'delivery: VOID - this transcript predates the running client.'
                printf '%s\n' 'delivery: it was reported by the client before this one, about the archive before this one.'
                ok=1
            fi
        fi
    fi
    return $ok
}

cache_report() {
    local d
    if d=$(cache_dir); then
        log "client package cache for this server: $d"
        ls -la "$d" | head -20 >&2
    else
        log "no client_resources directory holds a file of the staged length yet"
        log "(the client has not downloaded this archive; look under $CLIENT_ROOT/client_resources)"
    fi
}

# ------------------------------------------------------------------ watching

# The vocabulary is docs/acceptance.md §5 and §13's, and nothing here invents a
# class of its own.
classify() {
    local log_file=$1 expect=$2
    local line
    line=$(grep -a '^rpf:acceptance' "$log_file" | tail -1 || true)

    printf '\n%s\n' '--- evidence ------------------------------------------------'
    grep -aE '^rpf:(connect|joined|probe|streamed|acceptance|error|quit)|ready to accept|weight' "$log_file" || true
    printf '%s\n' '------------------------------------------------------------'

    local streamed breadcrumb failure
    streamed=$(grep -a '^rpf:streamed' "$log_file" | tail -1 || true)
    [ -n "$streamed" ] && printf 'streaming probe: %s\n' "$streamed"
    failure=$(grep -a '^rpf:error' "$log_file" | tail -1 || true)
    [ -n "$failure" ] && printf 'probe error: %s\n' "$failure"
    breadcrumb=$(grep -a '^rpf:probe' "$log_file" | tail -1 || true)
    delivery_note "$log_file" || true

    # The exit code is printed as well as returned, because a caller that pipes
    # this through `tail` reads the pipe's status and not the harness's.
    if [ -z "$line" ]; then
        if grep -aq '^rpf:joined' "$log_file"; then
            printf 'result: no line — the client joined and stopped after: %s\n' "${breadcrumb:-nothing}"
            printf 'exit: 5\n'
        else
            printf 'result: no line — the loop broke, not the archive (§5)\n'
            printf 'exit: 5\n'
        fi
        return 5
    fi

    case "$line" in
        *"in_cdimage=false"*)
            printf 'result: in_cdimage=false — the archive did not mount (§5, the failure this loop exists to catch)\nexit: 4\n'
            return 4 ;;
        *"class=$expect"*)
            printf 'result: in_cdimage=true class=%s — pass, read §13 for how narrow that is\nexit: 0\n' "$expect"
            return 0 ;;
        *"class=7"*)
            printf 'result: in_cdimage=true class=7 — an archive mounted, but not this one: a delivery defect, not a result (§5)\nexit: 3\n'
            return 3 ;;
        *)
            printf 'result: unexpected — %s\nexit: 6\n' "$line"
            return 6 ;;
    esac
}

watch_run() {
    local timeout=${1:-600} expect=${2:-1}
    local log_file waited=0
    log_file=$(run_log)
    [ -f "$log_file" ] || die "no run log at $log_file; stage something first"
    log "watching $log_file for up to ${timeout}s (expecting class=$expect)"
    while [ "$waited" -lt "$timeout" ]; do
        if grep -aq '^rpf:acceptance' "$log_file"; then break; fi
        sleep 2; waited=$((waited + 2))
    done
    classify "$log_file" "$expect"
}

# ------------------------------------------------------------------ the client

# Starts the client in the interactive Windows session. It does NOT elevate and
# must not: the UAC prompt updater.exe raises is the user's to grant, at the
# machine. After approving it the user connects from the server browser — see
# LAUNCHING at the top of this file.
launch_client() {
    local ps=/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe
    [ -x "$ps" ] || die "no Windows interop at $ps"
    local script=/mnt/c/Users/Public/rpf-acceptance-launch.ps1
    cat > "$script" <<'PS'
$name = "rpf-acceptance-launch"
$act  = New-ScheduledTaskAction -Execute "C:\RAGEMP\ragemp_v.exe" -WorkingDirectory "C:\RAGEMP"
$pri  = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $name -Action $act -Principal $pri -Force | Out-Null
Start-ScheduledTask -TaskName $name
Start-Sleep -Seconds 5
Unregister-ScheduledTask -TaskName $name -Confirm:$false
Get-Process ragemp_v -ErrorAction SilentlyContinue | Select-Object Id,SessionId | Format-Table | Out-String
PS
    ( cd /mnt/c && "$ps" -NoProfile -ExecutionPolicy Bypass -File 'C:\Users\Public\rpf-acceptance-launch.ps1' )
    log "the client is starting in the interactive session."
    log "a person at the machine has to (1) approve the updater's UAC prompt and"
    log "(2) connect to $SERVER_ADDR from the server browser. Then: $0 watch"
}

# ------------------------------------------------------------------- status

status() {
    printf 'server root   : %s\n' "$SERVER_ROOT"
    printf 'dlcpack       : %s\n' "$DLC_DIR/dlc.rpf"
    if [ -f "$DLC_DIR/dlc.rpf" ]; then
        printf 'served bytes  : %s\n' "$(stat -c %s "$DLC_DIR/dlc.rpf")"
        printf 'served sha256 : %s\n' "$(sha256sum "$DLC_DIR/dlc.rpf" | cut -d' ' -f1)"
    fi
    printf 'staged from   : %s\n' "$(cat "$STATE_DIR/staged.path" 2>/dev/null || echo none)"
    printf 'server process: %s\n' "$(pgrep -x ragemp-server || echo 'not running')"
    printf 'address       : %s\n' "$SERVER_ADDR"
    printf 'run log       : %s\n' "$(run_log)"
    local main=$CLIENT_ROOT/clientdata/main_logs.txt
    [ -f "$main" ] && printf 'client log    : %s (%s)\n' "$main" "$(head -1 "$main" | tr -d '\r')"
    cache_report
    delivery_note || true
}

case "${1:-}" in
    install-instrument) install_instrument ;;
    restart)
        # The server reads the instrument and hashes the client packages at
        # start, so an edited instrument needs this before the next join.
        server_stop; server_start
        log "weight : $(grep -a 'weight' "$(run_log)" | tail -1 | tr -d '\r')"
        log "serving: $(sha256sum "$DLC_DIR/dlc.rpf" | cut -d' ' -f1)" ;;
    stage)   shift; stage "$@" ;;
    watch)   shift
             timeout=600; expect=1
             while [ $# -gt 0 ]; do
                 case $1 in
                     --timeout) timeout=$2; shift 2 ;;
                     --expect)  expect=$2;  shift 2 ;;
                     *) die "unknown option $1" ;;
                 esac
             done
             watch_run "$timeout" "$expect" ;;
    run)     shift
             archive=$1; shift
             timeout=600; expect=1
             while [ $# -gt 0 ]; do
                 case $1 in
                     --timeout) timeout=$2; shift 2 ;;
                     --expect)  expect=$2;  shift 2 ;;
                     *) die "unknown option $1" ;;
                 esac
             done
             stage "$archive"; launch_client; watch_run "$timeout" "$expect" ;;
    launch)  launch_client ;;
    cache)   cache_report ;;
    status)  status ;;
    *) sed -n '2,32p' "$0" >&2; exit 2 ;;
esac
