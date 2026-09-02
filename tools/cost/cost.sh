#!/usr/bin/env bash
# What a patch and a rebuild cost, across the archive size range. R12.1.
# docs/cost.md reports a run of this and says how to read one.
#
#   cost.sh                measure every archive in archives.txt, then report
#   cost.sh report [DIR]   re-render the table from a previous run's samples.tsv
#
# Every measurement runs on a copy in a scratch directory. The archives named
# in the manifest are opened read-only and the run fails if their size or mtime
# moved while it ran.
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RPF=${RPF_BIN:-$HERE/../../target/release/rpf}
MANIFEST=${RPF_COST_ARCHIVES:-$HERE/archives.txt}
REPEATS=${RPF_COST_REPEATS:-7}
OUT=${RPF_COST_OUT:-${TMPDIR:-/tmp}/rpf-cost}
WORK=$OUT/work

log() { printf '%s\n' "$*" >&2; }
die() { log "cost: $*"; exit 2; }

samples() { printf '%s/samples.tsv' "$OUT"; }

# What the two platforms spell differently. Each is probed rather than inferred
# from `uname`, so a box with GNU coreutils on it is taken as it is found.
TIME_BIN=
TIME_FLAG=
RSS_SCALE=
STAT_FLAG=
STAT_SIZE=
STAT_STAMP=

# The whole report, in a variable. Through a pipe, a reader that stops at the
# first match kills `time` with SIGPIPE, which `pipefail` aborts on.
time_report() { { "$1" "$2" "$RPF" --version >/dev/null; } 2>&1; }

# `ru_maxrss` under -l is bytes on Darwin and kilobytes on the other BSDs, so
# the unit is measured: no real resident set reads under 64 KiB in bytes.
rss_scale_for_l() {
    local report reported
    report=$(time_report "$1" -l)
    reported=$(awk '/maximum resident set size/ { print $1; exit }' <<< "$report")
    case "$reported" in
        '' | *[!0-9]*) return 1 ;;
    esac
    if [ "$reported" -lt 65536 ]; then printf '1024\n'; else printf '1\n'; fi
}

# A -v that answers in some other wording would leave every resident set at
# zero and the sweep would finish and publish it, so the reading is required.
answers_rss_v() {
    local report
    report=$(time_report "$1" -v)
    grep -qE 'Maximum resident set size \(kbytes\):[[:space:]]*[0-9]+' <<< "$report"
}

probe_time() {
    local candidate scale
    for candidate in /usr/bin/time /usr/bin/gtime "$(command -v gtime || true)"; do
        [ -n "$candidate" ] && [ -x "$candidate" ] || continue
        if "$candidate" -l true >/dev/null 2>&1 && scale=$(rss_scale_for_l "$candidate"); then
            TIME_BIN=$candidate TIME_FLAG=-l RSS_SCALE=$scale
            return 0
        fi
        if "$candidate" -v true >/dev/null 2>&1 && answers_rss_v "$candidate"; then
            TIME_BIN=$candidate TIME_FLAG=-v RSS_SCALE=1024
            return 0
        fi
    done
    return 1
}

# A size back, not merely a zero exit: a `stat` that succeeds and prints
# something else corrupts the samples, and that surfaces after the whole sweep.
answers_size() { case "$("$@" 2>/dev/null)" in '' | *[!0-9]*) return 1 ;; esac; }

probe_stat() {
    if answers_size stat -f %z "$HERE/cost.sh"; then
        STAT_FLAG=-f STAT_SIZE=%z STAT_STAMP='%m %z %N'
        return 0
    fi
    if answers_size stat -c %s "$HERE/cost.sh"; then
        STAT_FLAG=-c STAT_SIZE=%s STAT_STAMP='%Y %s %n'
        return 0
    fi
    return 1
}

size_of() { stat "$STAT_FLAG" "$STAT_SIZE" "$1"; }
stamp_of() { stat "$STAT_FLAG" "$STAT_STAMP" "$1"; }

cpu_brand() {
    local brand=
    if command -v sysctl >/dev/null 2>&1; then
        brand=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || true)
    fi
    if [ -z "$brand" ] && [ -r /proc/cpuinfo ]; then
        # `awk` reads the file itself. Through a pipe, a reader that stops at the
        # first match kills the writer with SIGPIPE, which `pipefail` aborts on.
        brand=$(awk '/^model name/ { sub(/^[^:]*:[[:space:]]*/, ""); print; exit }' /proc/cpuinfo)
    fi
    printf '%s\n' "${brand:-$(uname -m)}"
}

cpu_count() {
    if command -v sysctl >/dev/null 2>&1 && sysctl -n hw.ncpu >/dev/null 2>&1; then
        sysctl -n hw.ncpu
    elif command -v nproc >/dev/null 2>&1; then
        nproc
    else
        printf 'unknown\n'
    fi
}

memory_bytes() {
    if command -v sysctl >/dev/null 2>&1 && sysctl -n hw.memsize >/dev/null 2>&1; then
        sysctl -n hw.memsize
    elif [ -r /proc/meminfo ]; then
        awk '/^MemTotal:/ { print $2 * 1024; exit }' /proc/meminfo
    else
        printf 'unknown\n'
    fi
}

system_name() {
    if command -v sw_vers >/dev/null 2>&1; then
        printf '%s %s\n' "$(sw_vers -productName)" "$(sw_vers -productVersion)"
    elif [ -r /etc/os-release ]; then
        # shellcheck source=/dev/null
        printf '%s %s\n' "$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-${NAME:-$(uname -s)}}")" "$(uname -r)"
    else
        printf '%s %s\n' "$(uname -s)" "$(uname -r)"
    fi
}

load_average() {
    if command -v sysctl >/dev/null 2>&1 && sysctl -n vm.loadavg >/dev/null 2>&1; then
        sysctl -n vm.loadavg
    elif [ -r /proc/loadavg ]; then
        cut -d' ' -f1-3 /proc/loadavg
    else
        printf 'unknown\n'
    fi
}

# One line of `real_seconds<TAB>max_rss_bytes<TAB>exit_code`. `time`'s own
# `real` is hundredths, which cannot resolve a patch at 7-9 ms, so the wall
# clock is taken around the spawn instead.
measure() {
    local out=$1 err=$2
    shift 2
    python3 - "$out" "$err" "$TIME_BIN" "$TIME_FLAG" "$RSS_SCALE" "$@" <<'PY'
import re, subprocess, sys, time

out, err, time_bin, time_flag, scale, *cmd = sys.argv[1:]
with open(out, 'wb') as o, open(err, 'wb') as e:
    start = time.monotonic()
    code = subprocess.call([time_bin, time_flag, *cmd], stdout=o, stderr=e)
    real = time.monotonic() - start
# BSD: "<n>  maximum resident set size", bytes. GNU: "Maximum resident set
# size (kbytes): <n>". The scale the probe chose converts the second to bytes.
patterns = (r'\s*(\d+)\s+maximum resident set size',
            r'\s*Maximum resident set size \(kbytes\):\s*(\d+)')
rss = 0
for line in open(err, errors='replace'):
    for pattern in patterns:
        m = re.match(pattern, line)
        if m:
            rss = int(m.group(1)) * int(scale)
print(f'{real:.6f}\t{rss}\t{code}')
PY
}

candidates() {
    "$RPF" ls --json -R "$1" | python3 -c '
import json, sys

files = [e for e in json.load(sys.stdin) if e["kind"] != "directory"]
by_len = lambda e: e["len"]
for e in sorted((e for e in files if ".rpf/" not in e["path"]), key=by_len)[:8]:
    print("outer", e["path"], sep="\t")
inner = [e for e in files if ".rpf/" in e["path"]]
# A binary entry first: cat of a resource answers its payload, which put --as
# raw does not put back byte for byte, so the failure measured is the harness.
for e in sorted(inner, key=lambda e: (e["kind"] != "binary", e["len"]))[:1]:
    print("inner", e["path"], sep="\t")
'
}

# An edit of the entry's own bytes that keeps their length, so the only reason a
# patch could be refused is the deflated size, which the dry run then settles.
payload_for() {
    "$RPF" cat "$1" "$2" > "$3"
    python3 -c '
import sys

b = bytearray(open(sys.argv[1], "rb").read())
if not b:
    sys.exit(3)
b[len(b) // 2] ^= 0x01
open(sys.argv[1], "wb").write(b)
' "$3"
}

verified() {
    "$RPF" verify "$1" 2>&1 | sed -n \
        -e 's/^\([0-9]*\) entries read back.*/\1 entries/p' \
        -e 's/^\([0-9]*\) of [0-9]* entries failed/\1 failed/p' | tr '\n' ' '
}

reported() { python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }

record() {
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$@" >> "$(samples)"
}

pick_patch_target() {
    local pristine=$1 subject=$2 payload=$3 path
    while IFS=$'\t' read -r where path; do
        [ "$where" = outer ] || continue
        payload_for "$pristine" "$path" "$payload" || continue
        cp "$pristine" "$subject"
        "$RPF" put --dry-run --json "$subject" "$path" "$payload" > "$WORK/dry.json" 2>/dev/null || continue
        [ "$(reported "$WORK/dry.json" method)" = patch ] || continue
        printf '%s\n' "$path"
        return 0
    done < "$WORK/candidates.tsv"
    return 1
}

run_op() {
    local label=$1 bytes=$2 op=$3 path=$4 payload=$5 expect=$6
    shift 6
    local pristine=$WORK/pristine.rpf subject=$WORK/subject.rpf
    local rep real rss code written method
    for rep in $(seq 1 "$REPEATS"); do
        cp "$pristine" "$subject"
        IFS=$'\t' read -r real rss code <<< "$(measure "$WORK/op.json" "$WORK/op.err" \
            "$RPF" put --json "$@" "$subject" "$path" "$payload")"
        [ "$code" = 0 ] || die "$label $op exited $code: $(cat "$WORK/op.err")"
        method=$(reported "$WORK/op.json" method)
        [ "$method" = "$expect" ] || die "$label $op took the $method path, not $expect"
        written=$(reported "$WORK/op.json" len)
        record "$label" "$bytes" "$op" "$rep" "$real" "$rss" "$written" "$(size_of "$subject")"
    done
    printf '%s\t%s\t%s\n' "$label" "$op" "$(verified "$subject")" >> "$OUT/verify.tsv"
}

sweep_archive() {
    local original=$1
    local label bytes outer inner
    label=$(basename "$(dirname "$original")")/$(basename "$original")
    bytes=$(size_of "$original")
    log "== $label ($bytes bytes)"

    cp "$original" "$WORK/pristine.rpf"
    printf '%s\t%s\t%s\n' "$label" pristine "$(verified "$WORK/pristine.rpf")" >> "$OUT/verify.tsv"

    candidates "$WORK/pristine.rpf" > "$WORK/candidates.tsv"
    outer=$(pick_patch_target "$WORK/pristine.rpf" "$WORK/subject.rpf" "$WORK/outer.bin") ||
        die "$label: no entry the dry run would patch in place"
    inner=$(awk -F'\t' '$1 == "inner" { print $2 }' "$WORK/candidates.tsv")
    log "   patch target : $outer"

    run_op "$label" "$bytes" patch "$outer" "$WORK/outer.bin" patch
    run_op "$label" "$bytes" rebuild "$outer" "$WORK/outer.bin" rebuild --rebuild
    if [ -n "$inner" ]; then
        log "   cascade target: $inner"
        payload_for "$WORK/pristine.rpf" "$inner" "$WORK/inner.bin"
        run_op "$label" "$bytes" cascade "$inner" "$WORK/inner.bin" rebuild --rebuild
    fi
}

floor() {
    local rep real rss code
    for rep in $(seq 1 "$REPEATS"); do
        IFS=$'\t' read -r real rss code <<< "$(measure "$WORK/op.json" "$WORK/op.err" "$RPF" --version)"
        record "(harness floor)" 0 floor "$rep" "$real" "$rss" 0 0
    done
}

# A leading ~ is the home directory; anything else relative resolves against the
# checkout, so a generated subject's path does not name one machine.
manifest_paths() {
    sed 's/#.*//' "$MANIFEST" | sed 's/[[:space:]]*$//' | grep -v '^$' |
        sed -e "s|^~|$HOME|" -e "s|^\([^/]\)|$HERE/../../\1|"
}

snapshot_originals() {
    manifest_paths | while IFS= read -r p; do stamp_of "$p"; done
}

report() {
    local dir=${1:-$OUT}
    [ -s "$dir/samples.tsv" ] || die "no samples in $dir"
    python3 - "$dir" <<'PY'
import statistics, sys
from collections import OrderedDict

d = sys.argv[1]
rows = OrderedDict()
for line in open(f'{d}/samples.tsv'):
    label, size, op, _rep, real, rss, written, result = line.rstrip('\n').split('\t')
    rows.setdefault((label, int(size), op), []).append(
        (float(real), int(rss), int(written), int(result)))


def mib(n):
    return f'{n / 1048576:.1f} MiB'


print(f'| Archive | Size | Operation | Runs | Median wall | Median peak RSS |'
      f' Bytes written | Result |')
print('|---|---|---|---|---|---|---|---|')
for (label, size, op), samples in rows.items():
    wall = statistics.median(s[0] for s in samples)
    rss = statistics.median(s[1] for s in samples)
    written = samples[-1][2]
    result = samples[-1][3]
    print(f'| `{label}` | {mib(size) if size else "-"} | {op} | {len(samples)} |'
          f' {wall * 1000:.1f} ms | {mib(rss)} |'
          f' {written:,} | {mib(result) if result else "-"} |')

print()
print('| Archive | State | `verify` says |')
print('|---|---|---|')
for line in open(f'{d}/verify.tsv'):
    label, state, said = line.rstrip('\n').split('\t')
    print(f'| `{label}` | {state} | {said} |')
PY
}

sweep() {
    [ -x "$RPF" ] || die "no binary at $RPF; cargo build --release"
    [ -f "$MANIFEST" ] || die "no manifest at $MANIFEST"
    command -v python3 >/dev/null || die "python3 is the timing and reporting helper"
    probe_time || die "no time(1) answering -l or -v; that is where the resident set comes from"
    probe_stat || die "no stat(1) answering -f %z or -c %s"

    rm -rf "$OUT"
    mkdir -p "$WORK"
    : > "$(samples)"
    : > "$OUT/verify.tsv"
    snapshot_originals > "$OUT/originals.before"

    {
        printf 'taken     : %s\n' "$(date '+%F %T %Z')"
        printf 'host      : %s\n' "$(cpu_brand)"
        printf 'cores     : %s\n' "$(cpu_count)"
        printf 'memory    : %s bytes\n' "$(memory_bytes)"
        printf 'system    : %s\n' "$(system_name)"
        printf 'binary    : %s\n' "$("$RPF" --version)"
        printf 'commit    : %s\n' "$(git -C "$HERE" rev-parse --short HEAD 2>/dev/null || echo unknown)"
        printf 'repeats   : %s\n' "$REPEATS"
        printf 'load start: %s\n' "$(load_average)"
    } > "$OUT/meta.txt"

    floor
    manifest_paths | while IFS= read -r p; do
        [ -f "$p" ] ||
            die "no archive at $p; the generated subject is written by tools/cost/make-deflate-subject.sh"
        sweep_archive "$p"
    done

    printf 'load end  : %s\n' "$(load_average)" >> "$OUT/meta.txt"
    snapshot_originals > "$OUT/originals.after"
    diff "$OUT/originals.before" "$OUT/originals.after" > "$OUT/originals.diff" ||
        die "an original archive changed while the run was in progress; results discarded"
    rm -rf "$WORK"

    cat "$OUT/meta.txt" >&2
    log ""
    log "originals unchanged; samples in $(samples)"
    log ""
    report "$OUT"
}

case "${1:-run}" in
    run)    sweep ;;
    report) shift; report "${1:-$OUT}" ;;
    *)      sed -n '2,8p' "$0" >&2; exit 2 ;;
esac
