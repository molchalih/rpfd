#!/usr/bin/env bash
# What the archives on this machine are made of, per file extension.
# docs/corpus.md reports a run of this and says what it cannot conclude.
#
#   census.sh                walk every archive under the roots, then report
#   census.sh report [DIR]   re-render the table from a previous run's samples
#
# Archives are opened read-only through the CLI. The run fails if the size or
# mtime of any of them moved while it ran.
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$HERE/../.." && pwd)
RPF=${RPF_BIN:-$ROOT/target/release/rpf}
MANIFEST=${RPF_CENSUS_ROOTS:-$HERE/roots.txt}
OUT=${RPF_CENSUS_OUT:-${TMPDIR:-/tmp}/rpf-census}

log() { printf '%s\n' "$*" >&2; }
die() { log "census: $*"; exit 2; }

roots() {
    { sed 's/#.*//' "$MANIFEST"; [ -n "${RPF_CORPUS:-}" ] && printf '%s\n' "$RPF_CORPUS"; } |
        sed 's/[[:space:]]*$//' | grep -v '^$' |
        sed -e "s|^~|$HOME|" -e "s|^\([^/]\)|$ROOT/\1|"
}

# Every .rpf under the roots, one per line, deduplicated by content: the same
# pack sits under more than one root here and counting it twice would weight
# the census by how often a directory was copied.
archives() {
    local root
    while IFS= read -r root; do
        [ -e "$root" ] || { log "   absent, skipped: $root"; continue; }
        find "$root" -type f -iname '*.rpf' -print0
    done < <(roots) | sort -z | while IFS= read -r -d '' path; do
        printf '%s\t%s\t%s\n' "$(shasum -a 256 "$path" | cut -d' ' -f1)" \
            "$(stat -f %z "$path")" "$path"
    done | sort -k1,1 -k3,3 | awk -F'\t' '!seen[$1]++'
}

# One row per (extension, class, placement) in one archive. A path carrying
# `.rpf/` is inside a nested archive; `len` is what the entry declares its
# contents to be, which is the only length `ls` reports.
tally() {
    python3 - "$1" "$2" <<'PY'
import json, sys
from collections import Counter

rows = Counter()
for e in json.load(open(sys.argv[2])):
    if e['kind'] == 'directory':
        continue
    name = e['path'].rsplit('/', 1)[-1]
    ext = ('.' + name.rsplit('.', 1)[1].lower()) if '.' in name[1:] else '(none)'
    place = 'nested' if '.rpf/' in e['path'] else 'top'
    rows[(ext, e['kind'], place)] += 1
    rows[(ext, e['kind'], place, 'bytes')] += e['len']
for (ext, kind, place) in {k[:3] for k in rows}:
    print(sys.argv[1], ext, kind, place, rows[(ext, kind, place)],
          rows[(ext, kind, place, 'bytes')], sep='\t')
PY
}

walk() {
    local sha bytes path label listing
    listing=$OUT/listing.json
    while IFS=$'\t' read -r sha bytes path; do
        label=$(basename "$(dirname "$path")")/$(basename "$path")
        if ! "$RPF" ls --json -R "$path" > "$listing" 2> "$OUT/err.txt"; then
            log "   refused: $label"
            printf '%s\t%s\t%s\trefused\t%s\n' "$sha" "$bytes" "$label" \
                "$(python3 -c '
import json, sys
for f in sys.argv[1:]:
    try:
        print(json.load(open(f))["message"]); break
    except Exception:
        pass
' "$listing" "$OUT/err.txt")" >> "$OUT/archives.tsv"
            continue
        fi
        log "   $label"
        printf '%s\t%s\t%s\tok\t-\n' "$sha" "$bytes" "$label" >> "$OUT/archives.tsv"
        tally "$sha" "$listing" >> "$OUT/samples.tsv"
    done
    rm -f "$listing" "$OUT/err.txt"
}

snapshot() { cut -f3 "$OUT/found.tsv" | while IFS= read -r p; do stat -f '%m %z %N' "$p"; done; }

report() {
    local dir=${1:-$OUT}
    [ -s "$dir/samples.tsv" ] || die "no samples in $dir"
    python3 - "$dir" <<'PY'
import sys
from collections import Counter

d = sys.argv[1]
count, size = Counter(), Counter()
by_class, by_place, by_archive = Counter(), Counter(), Counter()
for line in open(f'{d}/samples.tsv'):
    sha, ext, kind, place, n, b = line.rstrip('\n').split('\t')
    n, b = int(n), int(b)
    count[ext] += n
    size[ext] += b
    by_class[ext, kind] += n
    by_place[ext, place] += n
    if kind == 'resource':
        by_archive[sha, 'resource'] += n
        if ext == '.ytd':
            by_archive[sha, '.ytd'] += n

archives = [l.rstrip('\n').split('\t') for l in open(f'{d}/archives.tsv')]
ok = [a for a in archives if a[3] == 'ok']
entries = sum(count.values())
resources = sum(n for (_, kind), n in by_class.items() if kind == 'resource')

print(f'{len(archives)} archives found, {len(ok)} opened, '
      f'{sum(int(a[1]) for a in ok):,} bytes on disk')
print(f'{entries:,} entries — {resources:,} resource, {entries - resources:,} binary')
print()
print('| Extension | Entries | % of entries | Declared bytes | % of bytes |'
      ' Resource | Binary | Top-level | Nested |')
print('|---|---:|---:|---:|---:|---:|---:|---:|---:|')
total = sum(size.values())
for ext, n in count.most_common():
    print(f'| `{ext}` | {n:,} | {100 * n / entries:.2f}% | {size[ext]:,} |'
          f' {100 * size[ext] / total:.2f}% | {by_class[ext, "resource"]:,} |'
          f' {by_class[ext, "binary"]:,} | {by_place[ext, "top"]:,} |'
          f' {by_place[ext, "nested"]:,} |')
print(f'| **total** | **{entries:,}** | 100% | **{total:,}** | 100% |'
      f' **{resources:,}** | **{entries - resources:,}** |'
      f' **{sum(v for (_, p), v in by_place.items() if p == "top"):,}** |'
      f' **{sum(v for (_, p), v in by_place.items() if p == "nested"):,}** |')

print()
print('| Extension | Share of resource entries |')
print('|---|---:|')
res = Counter({e: n for (e, k), n in by_class.items() if k == 'resource' and n})
for ext, n in res.most_common():
    print(f'| `{ext}` | {100 * n / resources:.2f}% |')

print()
print('| Archive | Bytes | Resource entries | `.ytd` | `.ytd` share |')
print('|---|---:|---:|---:|---:|')
for a in sorted(ok, key=lambda a: -by_archive[a[0], 'resource']):
    res, ytd = by_archive[a[0], 'resource'], by_archive[a[0], '.ytd']
    share = f'{100 * ytd / res:.1f}%' if res else '-'
    print(f'| `{a[2]}` | {int(a[1]):,} | {res:,} | {ytd:,} | {share} |')

refused = [a for a in archives if a[3] != 'ok']
if refused:
    print()
    print('| Archive it would not open | Bytes | Why |')
    print('|---|---:|---|')
    for a in refused:
        print(f'| `{a[2]}` | {int(a[1]):,} | {a[4]} |')
PY
}

sweep() {
    [ -x "$RPF" ] || die "no binary at $RPF; cargo build --release"
    [ -f "$MANIFEST" ] || die "no manifest at $MANIFEST"
    command -v python3 >/dev/null || die "python3 is the tallying and reporting helper"

    rm -rf "$OUT"
    mkdir -p "$OUT"
    : > "$OUT/samples.tsv"
    : > "$OUT/archives.tsv"

    archives > "$OUT/found.tsv"
    [ -s "$OUT/found.tsv" ] || die "no archive under any root in $MANIFEST"
    snapshot > "$OUT/originals.before"

    {
        printf 'taken   : %s\n' "$(date '+%F %T %Z')"
        printf 'system  : %s %s\n' "$(sw_vers -productName)" "$(sw_vers -productVersion)"
        printf 'binary  : %s\n' "$("$RPF" --version)"
        printf 'commit  : %s\n' "$(git -C "$HERE" rev-parse --short HEAD 2>/dev/null || echo unknown)"
        printf 'roots   : %s\n' "$(roots | tr '\n' ' ')"
        printf 'corpus  : %s\n' "${RPF_CORPUS:-unset}"
        printf 'archives: %s distinct of %s found\n' \
            "$(wc -l < "$OUT/found.tsv" | tr -d ' ')" \
            "$(roots | while IFS= read -r r; do
                   [ -e "$r" ] && find "$r" -type f -iname '*.rpf'; done | wc -l | tr -d ' ')"
    } > "$OUT/meta.txt"

    walk < "$OUT/found.tsv"

    snapshot > "$OUT/originals.after"
    diff "$OUT/originals.before" "$OUT/originals.after" > "$OUT/originals.diff" ||
        die "an archive changed while the run was in progress; results discarded"

    cat "$OUT/meta.txt" >&2
    log ""
    log "archives unchanged; samples in $OUT/samples.tsv"
    log ""
    report "$OUT"
}

case "${1:-run}" in
    run)    sweep ;;
    report) shift; report "${1:-$OUT}" ;;
    *)      sed -n '2,8p' "$0" >&2; exit 2 ;;
esac
