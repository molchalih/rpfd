#!/usr/bin/env bash
# The documentation gate. Everything a clone receives as Markdown is checked
# here: that every path it names is a path, that every anchor it links to is a
# heading, that every `DR-NNN` any tracked file cites resolves wherever a clone
# holds anything for one to resolve to, that every fence it opens closes, that
# the extractor still finds claims to check, and that the surface is neither
# growing nor holding unspent budget.
#
#   docgate.sh            check the tracked Markdown surface
#   docgate.sh measure    print the yield and the byte total, then exit as check
#                         would — a wrapper must not get green from a red tree
#
# What the subject set is, what each failure means and why this is dependency-
# free: tools/docgate/README.md, which owns all of it. What follows is how,
# and each check carries the reason it is shaped the way it is.

set -euo pipefail

log() { printf '%s\n' "$*"; }
die() { printf 'docgate: %s\n' "$*" >&2; exit 2; }

ROOT=$(git rev-parse --show-toplevel)
# Beside the script rather than at a fixed path: this gate exists to catch a
# renamed directory, and one whose own budget file it could no longer find
# would die on the rename instead of reporting it.
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
SELF=$HERE/$(basename -- "$0")
cd -- "$ROOT"
BUDGET_FILE=${HERE#"$ROOT"/}/budget.txt
[ -f "$BUDGET_FILE" ] || die "no budget file at $BUDGET_FILE"

# An unknown argument is refused rather than run: `docgate.sh --help` used to
# fall through to a full check, so a caller asking a question got a gate. The
# usage it prints back is found by its own text rather than by line number: the
# range was `8,10p` until an edit to the header comment above pushed the block
# down one line, and the help then printed a bare `#` and dropped the line that
# says `measure` exits as check would.
MODE=${1:-check}
case $MODE in
    check|measure) ;;
    *) printf 'docgate: unknown argument %s\n' "$MODE" >&2
       sed -n '/^#   docgate\.sh /,/^#$/p' "$SELF" | grep -v '^#$' >&2
       exit 2 ;;
esac
[ $# -le 1 ] || die "unknown argument $2"

# The share of path claims that `git check-ignore` may withdraw before the whole
# withdrawal is refused. An excuse removes a claim from the check, so an
# uncapped excuse launders a broken corpus one ignored path at a time, however
# narrow each withdrawal looks on its own; capping the aggregate closes every
# such route at once without breaking the case the rule exists for. All or
# nothing, so that no `.gitignore` can be tuned to sit just under a partial cap.
MAX_EXCUSED_PERCENT=25

# The subject set, stated once. Tracked Markdown is the distributed surface:
# README.md, INSTALL.md, and the README under each client, tool and fixtures.
subjects() { git ls-files -- '*.md'; }

[ -n "$(subjects)" ] || die "no tracked Markdown found; run me inside the repository"

# The top-level entries a command line inside a fenced block may be rooted at,
# declared in budget.txt rather than derived from `git ls-files`. Derived was
# the hole this gate's own header describes: emit_fenced() read a token as a
# claim only when its first segment was a tracked top-level name, so renaming
# `tools/` did not flag the command lines still cd-ing into it — it stopped
# reading them as claims at all, and the gate went quiet on exactly the defect
# it was built for. A declared root cannot be satisfied by deleting what it
# names, and the check below fails when one stops naming a tracked directory.
ROOTS=$(awk '$1 == "roots" { $1 = ""; sub(/^[ \t]+/, ""); print }' "$BUDGET_FILE")
[ -n "$ROOTS" ] || die "$BUDGET_FILE has no 'roots' line; every fenced command line would go unread"

# Both numbers, read and checked before any work: a budget line that is missing
# or misspelt made `[` complain on stderr and the comparison it guards pass, so
# a corrupt budget file bought a PASS. A gate reads its own configuration
# strictly or it does not fail closed.
FLOOR=$(awk '$1 == "claims" { print $2 }' "$BUDGET_FILE")
BUDGET=$(awk '$1 == "bytes"  { print $2 }' "$BUDGET_FILE")
case $FLOOR in  ''|*[!0-9]*) die "$BUDGET_FILE has no whole number on its 'claims' line" ;; esac
case $BUDGET in ''|*[!0-9]*) die "$BUDGET_FILE has no whole number on its 'bytes' line" ;; esac

WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT

git ls-files > "$WORK/index"
subjects > "$WORK/subjects"

# The subject list as an array rather than an unquoted expansion: a Markdown
# file with a space in its name is not a reason for a gate to read the wrong
# files silently.
FILES=()
while IFS= read -r f; do FILES+=("$f"); done < "$WORK/subjects"

# ---------------------------------------------------------------------------
# One pass over every subject: fences, front matter, and path-shaped claims.
# Emits tab-separated records for the shell half to resolve and report.
# ---------------------------------------------------------------------------
awk -v indexfile="$WORK/index" -v rootlist="$ROOTS" '
function shape_ok(t) {
    if (t ~ /:\/\//) return 0                                   # a URL
    if (t ~ /^[A-Za-z][A-Za-z0-9+.-]*:/) return 0               # any other scheme
    if (t ~ /^#/) return 0                                      # an anchor
    # An elision is not a path. `docs/...` resolved to nothing, was then
    # withdrawn by `git check-ignore` as though it were a file this repository
    # declines to track, and so spent its life inflating the excuse it hid in.
    if (t ~ /\.\.\./) return 0
    if (t ~ /[ \t]/) return 0
    if (t ~ /^[A-Za-z0-9._@*?-]+(\/[A-Za-z0-9._@*?-]+)+\/?$/) return 1
    if (t ~ /^[A-Za-z0-9._-]+\.(md|rs|toml|json|sh|py|ts|js|mjs|cjs|yml|yaml|txt|lock|svg|png|jsonl)$/) return 1
    return 0
}
function glob_to_re(g,   r, i, c) {
    r = "^"
    for (i = 1; i <= length(g); i++) {
        c = substr(g, i, 1)
        if (c == "*") r = r ".*"
        else if (c == "?") r = r "."
        else if (index(".^$+()[]{}|\\/", c)) r = r "\\" c
        else r = r c
    }
    return r "$"
}
# The fence marker at the start of a line, after at most three spaces of
# indent, or "" for a line that opens or closes nothing. Written out by hand
# rather than as `/^ {0,3}(`{3,}|~{3,})/` because mawk — which is what `awk` is
# on the runner — does not read interval expressions, and a regex it silently
# reads as a literal is a gate that silently checks nothing.
function marker(s,   t, i, c, n) {
    t = s
    i = 0
    while (i < 3 && substr(t, 1, 1) == " ") { t = substr(t, 2); i++ }
    c = substr(t, 1, 1)
    rest_after = ""
    if (c != "`" && c != "~") return ""
    n = 0
    while (substr(t, n + 1, 1) == c) n++
    if (n < 3) return ""
    rest_after = substr(t, n + 1)
    return substr(t, 1, n)
}
function claim(file, line, kind, tok, anchor,   i) {
    if (!shape_ok(tok)) return
    # Withdrawn here, before yield++, so a foreign-paths claim is outside both
    # the numerator and the denominator of the excuse cap; BADGLOB and DEADGLOB
    # police this route instead of the cap.
    for (i = 1; i <= nfp; i++) {
        if (tok ~ fpre[i]) { fphit[i]++; foreign[file]++; return }
    }
    print "CLAIM\t" file "\t" line "\t" kind "\t" tok "\t" anchor
    yield++
}
function emit_prose(file, line, s,   t, p, q, tok, anchor, h) {
    # Backticked spans.
    t = s
    while (match(t, /`[^`]+`/)) {
        tok = substr(t, RSTART + 1, RLENGTH - 2)
        claim(file, line, "backtick", tok)
        t = substr(t, RSTART + RLENGTH)
    }
    # Markdown link and image targets. The anchor is carried rather than cut:
    # `README.md#gone` names a real file and lands the reader at the top of it
    # with no error, which is a dead link that resolves.
    t = s
    while (match(t, /\]\([^)]*\)/)) {
        tok = substr(t, RSTART + 2, RLENGTH - 3)
        sub(/[ \t].*$/, "", tok)            # drop a link title
        anchor = ""
        h = index(tok, "#")
        if (h > 0) { anchor = substr(tok, h + 1); tok = substr(tok, 1, h - 1) }
        if (tok != "") claim(file, line, "link", tok, anchor)
        else if (anchor != "") {
            # A link into the headings of this page.
            print "CLAIM\t" file "\t" line "\tanchor\t" file "\t" anchor
            yield++
        }
        t = substr(t, RSTART + RLENGTH)
    }
    # Raw HTML asset references; README.md carries its banner this way.
    t = s
    while (match(t, /(src|srcset)="[^"]*"/)) {
        tok = substr(t, RSTART, RLENGTH)
        sub(/^[a-z]+="/, "", tok); sub(/"$/, "", tok)
        sub(/[ \t].*$/, "", tok)
        if (tok != "") claim(file, line, "link", tok)
        t = substr(t, RSTART + RLENGTH)
    }
}
function emit_fenced(file, line, s,   n, i, a, tok, first) {
    # Inside a fence only tokens rooted at one of the declared roots are read as
    # claims about this repository. A command line that cd-s into a directory
    # renamed three commits ago is the defect this exists for; the rooting is
    # what keeps a JSON body, an archive-internal path or a shell variable out.
    # The roots are declared in budget.txt and checked against the tree, so a
    # rename fires here *and* there — rooting them in `git ls-files` instead
    # meant a renamed directory quietly stopped being a subject.
    n = split(s, a, /[ \t]+/)
    for (i = 1; i <= n; i++) {
        tok = a[i]
        gsub(/^[`"'"'"'(\[]+|[`"'"'"')\],;:.]+$/, "", tok)
        if (index(tok, "/") == 0) continue
        first = tok; sub(/\/.*$/, "", first)
        if (!(first in root)) continue
        claim(file, line, "command", tok)
    }
}
BEGIN {
    FS = "\n"
    n = split(rootlist, a, /[ \t]+/)
    for (i = 1; i <= n; i++) if (a[i] != "") root[a[i]] = 1
}
NR == FNR {
    tracked[$0] = 1
    p = $0
    while (sub(/\/[^\/]*$/, "", p)) tracked[p] = 1
    next
}
FNR == 1 {
    if (file != "") endfile()
    file = FILENAME
    fm = 0; fmkey = ""; nfp = 0; fence = ""; fenceline = 0; delete fpre; delete fphit
}
{
    line = FNR
    s = $0

    # --- front matter, and the foreign-paths declaration it may carry --------
    if (FNR == 1 && s == "---") { fm = 1; next }
    if (fm == 1) {
        if (s == "---" || s == "...") { fm = 2; next }
        if (s ~ /^foreign-paths:[ \t]*\[/) {
            t = s; sub(/^[^[]*\[/, "", t); sub(/\].*$/, "", t)
            n = split(t, a, /,/)
            for (i = 1; i <= n; i++) {
                g = a[i]; gsub(/^[ \t"'"'"']+|[ \t"'"'"']+$/, "", g)
                if (g != "") { nfp++; fpre[nfp] = glob_to_re(g); fpsrc[nfp] = g; fpline[nfp] = FNR }
            }
            fmkey = ""
            next
        }
        if (s ~ /^foreign-paths:[ \t]*$/) { fmkey = "foreign-paths"; next }
        if (s ~ /^[A-Za-z0-9_-]+:/) { fmkey = ""; next }
        if (fmkey == "foreign-paths" && s ~ /^[ \t]*-[ \t]*/) {
            g = s; sub(/^[ \t]*-[ \t]*/, "", g)
            sub(/[ \t]+#.*$/, "", g)
            gsub(/^["'"'"']|["'"'"']$/, "", g)
            gsub(/[ \t\r]+$/, "", g)
            if (g != "") {
                if (g ~ /^[*?\/]+$/) print "BADGLOB\t" file "\t" FNR "\t" g
                nfp++; fpre[nfp] = glob_to_re(g); fpsrc[nfp] = g; fpline[nfp] = FNR
            }
        }
        next
    }

    # --- fences -------------------------------------------------------------
    m = marker(s)
    if (fence == "") {
        if (m != "") { fence = m; fenceline = FNR; next }
        emit_prose(file, FNR, s)
        next
    } else {
        if (m != "" && substr(m, 1, 1) == substr(fence, 1, 1) && length(m) >= length(fence)) {
            if (rest_after ~ /^[ \t\r]*$/) { fence = ""; fenceline = 0; next }
            print "FENCETEXT\t" file "\t" FNR "\t" fenceline "\t" s
            fence = ""; fenceline = 0
            next
        }
        emit_fenced(file, FNR, s)
        next
    }
}
function endfile(   i) {
    if (fence != "") print "FENCEOPEN\t" file "\t" fenceline "\t" fence
    for (i = 1; i <= nfp; i++)
        if (!(i in fphit)) print "DEADGLOB\t" file "\t" fpline[i] "\t" fpsrc[i]
    if (file in foreign) print "FOREIGN\t" file "\t" foreign[file]
}
END { if (file != "") endfile(); print "YIELD\t" yield + 0 }
' "$WORK/index" "${FILES[@]}" > "$WORK/records"

# ---------------------------------------------------------------------------
# Resolution. A claim resolves against the index exactly, against the naming
# document's own directory, or as a `/`-boundary suffix of a tracked path — a
# document may name `src/main.rs` relative to a subtree. What is left is put to
# `git check-ignore`: a path this repository deliberately does not track is
# withdrawn and printed, never reported as rot. `.gitignore` says so in its own
# comments, and it is the checked-in, greppable place that decision lives.
# ---------------------------------------------------------------------------
awk -F'\t' -v indexfile="$WORK/index" '
BEGIN {
    while ((getline l < indexfile) > 0) {
        tracked[l] = 1
        p = l
        while (sub(/\/[^\/]*$/, "", p)) tracked[p] = 1
    }
    for (p in tracked) {
        s = p
        while (sub(/^[^\/]*\//, "", s)) suffix[s] = 1
    }
}
function glob_re(g,   r, i, c) {
    r = "^"
    for (i = 1; i <= length(g); i++) {
        c = substr(g, i, 1)
        if (c == "*") r = r ".*"
        else if (c == "?") r = r "."
        else if (index(".^$+()[]{}|\\/", c)) r = r "\\" c
        else r = r c
    }
    return r "$"
}
# A document may name a set rather than a file — `fixtures/*-metadata.json`.
# Expanded against the index literally, so it resolves when it names something
# and stays dead when it does not.
function glob_hits(g,   re, p) {
    re = glob_re(g)
    for (p in tracked) if (p ~ re) return 1
    for (p in suffix)  if (p ~ re) return 1
    return 0
}
# The GitHub heading slug: drop the marker and any link targets, lower-case,
# keep letters, digits, `-` and `_`, and turn each space into a hyphen.
function slugify(h,   s) {
    s = h
    sub(/^[ \t]*#+[ \t]*/, "", s)
    sub(/[ \t]+#+[ \t]*$/, "", s)
    gsub(/\]\([^)]*\)/, "", s)
    gsub(/\[/, "", s)
    s = tolower(s)
    gsub(/[^a-z0-9 _-]/, "", s)
    gsub(/ /, "-", s)
    return s
}
function load_anchors(target,   l, fence, v) {
    headed[target] = 1
    while ((getline l < target) > 0) {
        if (l ~ /^[ \t]*```/ || l ~ /^[ \t]*~~~/) { fence = 1 - fence; continue }
        if (fence) continue
        # An explicit anchor is as good as a heading, and a page that writes one
        # has usually written it because the generated slug was unusable.
        while (match(l, /(id|name)="[^"]*"/)) {
            v = substr(l, RSTART, RLENGTH)
            sub(/^[a-z]+="/, "", v); sub(/"$/, "", v)
            anchor_at[target SUBSEP v] = 1
            l = substr(l, RSTART + RLENGTH)
        }
        if (l ~ /^#/) anchor_at[target SUBSEP slugify(l)] = 1
    }
    close(target)
}
# A link may resolve and still be dead. `README.md#gone` names a real file, and
# a browser given an anchor it cannot find scrolls to the top of the page and
# reports nothing — so the reader lands somewhere plausible and never learns
# that the section moved.
function check_anchor(file, line, target, anchor) {
    if (target !~ /\.md$/) return
    if (!(target in headed)) load_anchors(target)
    if ((target SUBSEP anchor) in anchor_at) return
    print "ANCHOR\t" file "\t" line "\t" target "\t" anchor
}
$1 != "CLAIM" { print; next }
$4 == "anchor" { check_anchor($2, $3, $2, $6); next }
{
    file = $2; tok = $5
    sub(/^\.\//, "", tok)
    sub(/\/$/, "", tok)
    dir = file; if (!sub(/\/[^\/]*$/, "", dir)) dir = ""
    if (tok ~ /[*?]/) {
        if (glob_hits(tok)) next
        if (dir != "" && glob_hits(dir "/" tok)) next
        print "UNRESOLVED\t" $2 "\t" $3 "\t" $4 "\t" $5
        next
    }
    res = ""
    if (tok in tracked)                            res = tok
    else if (dir != "" && (dir "/" tok) in tracked) res = dir "/" tok
    if (res != "") {
        if ($6 != "") check_anchor($2, $3, res, $6)
        next
    }
    if ($4 != "link" && tok in suffix)        next
    print "UNRESOLVED\t" $2 "\t" $3 "\t" $4 "\t" $5
}
' "$WORK/records" > "$WORK/resolved"

grep '^UNRESOLVED' "$WORK/resolved" | cut -f5 | sed 's/\/$//' | sort -u > "$WORK/candidates" || true
: > "$WORK/bydesign"
if [ -s "$WORK/candidates" ]; then
    git check-ignore --stdin < "$WORK/candidates" > "$WORK/bydesign" || true
fi

# How much of the check the excuse is carrying. Counted in claims rather than in
# distinct tokens, because a token named on nine pages excuses nine claims.
excused=$(awk -F'\t' -v bd="$WORK/bydesign" '
    BEGIN { while ((getline l < bd) > 0) ok[l] = 1 }
    $1 == "UNRESOLVED" { t = $5; sub(/\/$/, "", t); if (t in ok) n++ }
    END { print n + 0 }' "$WORK/resolved")
excused_pages=$(grep -c '\.md$' "$WORK/bydesign" || true)

# ---------------------------------------------------------------------------
# Citations. `DR-NNN` is written throughout the code, the workflows and the
# manifests a clone receives, and nothing checked that any of them named
# something a cloner can reach. An identifier resolves to a tracked record file
# — `docs/decisions/DR-007-*.md` — or to an id-led row in a tracked page whose
# front matter declares which citations it resolves:
#
#   ---
#   resolves-citations: ["DR-*"]
#   ---
#
# The subject set here is every tracked text file, not just Markdown: a citation
# in `ci.yml` is read by the same cloner and rots the same way. It is also what
# settles whose declaration counts — a declaration in an untracked page is never
# read, because it would resolve nothing for the cloner it claims to resolve for.
# ---------------------------------------------------------------------------
CITEFILES=()
while IFS= read -r f; do CITEFILES+=("$f"); done < <(
    git ls-files -- ':!*.png' ':!*.jpg' ':!*.jpeg' ':!*.gif' ':!*.ico' \
                    ':!*.pdf' ':!*.zip' ':!*.gz' ':!*.vsix' ':!*.woff' ':!*.woff2')

awk -v indexfile="$WORK/index" '
function glob_re(g,   r, i, c) {
    r = "^"
    for (i = 1; i <= length(g); i++) {
        c = substr(g, i, 1)
        if (c == "*") r = r ".*"
        else if (c == "?") r = r "."
        else if (index(".^$+()[]{}|\\/", c)) r = r "\\" c
        else r = r c
    }
    return r "$"
}
# A declared namespace, policed as it is read. This declaration withdraws a
# citation from the check with no cap above it, so an opt-out here is wider than
# the all-wildcard shape BADGLOB refuses on the path side. The test is not a
# count of literal characters — every identifier is a tag, a `-` and a number,
# so `D*` names as little as `*` does while costing one character more. What a
# namespace has to do is name the tag: the run of literals before the first
# wildcard must reach the separator, which `DR-*` does at three characters and
# no pattern that resolves every identifier can do at any length.
function decl(g, ln,   lit, k) {
    ng[FILENAME]++
    k = ng[FILENAME]
    gre[FILENAME, k] = glob_re(g)
    gsrc[FILENAME, k] = g
    gline[FILENAME, k] = ln
    if (g ~ /^[*?]+$/) {
        print "BADCITE\t" FILENAME "\t" ln "\t" g "\tis all wildcard — an opt-out, not a namespace"
        return
    }
    lit = g
    sub(/[*?].*$/, "", lit)
    if (index(lit, "-") == 0)
        print "BADCITE\t" FILENAME "\t" ln "\t" g "\twildcards away the tag before the separator, so it resolves every identifier"
}
# The identifier at the head of a line, once a table pipe and any quoting is
# out of the way — and only when nothing runs on from it, so that a row for
# `DR-007` is a row and a link to `DR-007-own-container.md` is not.
function led_id(l,   r, id, after) {
    r = l
    sub(/^[ \t]*\|?[ \t]*/, "", r)
    sub(/^[`*_]+/, "", r)
    if (match(r, /^DR-[0-9][0-9]*/) == 0) return ""
    id = substr(r, 1, RLENGTH)
    after = substr(r, RLENGTH + 1, 1)
    if (after ~ /[0-9A-Za-z-]/) return ""
    return id
}
NR == FNR {
    b = $0; sub(/^.*\//, "", b)
    if (match(b, /^DR-[0-9][0-9]*-/) > 0) record[substr(b, 1, RLENGTH - 1)] = 1
    next
}
FNR == 1 { fm = (FILENAME ~ /\.md$/) ? 1 : 0; fmfirst = 1; fmkey = "" }
fm == 1 {
    if (fmfirst) { fmfirst = 0; if ($0 != "---") { fm = 0 } else next }
}
fm == 1 {
    if ($0 == "---" || $0 == "...") { fm = 0; next }
    if ($0 ~ /^resolves-citations:[ \t]*\[/) {
        t = $0; sub(/^[^[]*\[/, "", t); sub(/\].*$/, "", t)
        n = split(t, a, /,/)
        for (i = 1; i <= n; i++) {
            g = a[i]; gsub(/^[ \t"'"'"']+|[ \t"'"'"']+$/, "", g)
            if (g != "") decl(g, FNR)
        }
        fmkey = ""
        next
    }
    if ($0 ~ /^resolves-citations:[ \t]*$/) { fmkey = "resolves-citations"; next }
    if ($0 ~ /^[A-Za-z0-9_-]+:/) { fmkey = ""; next }
    if (fmkey == "resolves-citations" && $0 ~ /^[ \t]*-[ \t]*/) {
        g = $0; sub(/^[ \t]*-[ \t]*/, "", g)
        # The trailing comment goes the way the path side takes it. Left on, it
        # is part of the glob, and the declaration is then dead rather than wrong.
        sub(/[ \t]+#.*$/, "", g)
        gsub(/^["'"'"']|["'"'"']$/, "", g); gsub(/[ \t\r]+$/, "", g)
        if (g != "") decl(g, FNR)
    }
    next
}
{
    # Cheap first: the great majority of the tracked bytes are lines with no
    # identifier on them at all, and this pass reads every one of them.
    if (index($0, "DR-") == 0) next
    # A row resolves a citation only in a page that declared it would, and only
    # for an identifier its own declaration covers: a list of ids in a page that
    # claims nothing is a list, not an index.
    id = led_id($0)
    if (id != "")
        # Every matching declaration is credited, not just the first: a hit is
        # what makes a declaration live, and one shadowed by an overlapping
        # declaration above it is redundant rather than dead.
        for (k = 1; k <= ng[FILENAME]; k++)
            if (id ~ gre[FILENAME, k]) { rowok[id] = 1; ghit[FILENAME, k] = 1 }
    t = $0
    while (match(t, /DR-[0-9][0-9]*/)) {
        id = substr(t, RSTART, RLENGTH)
        if (!(id in cites)) { citefile[id] = FILENAME; citeline[id] = FNR }
        cites[id]++
        total++
        t = substr(t, RSTART + RLENGTH)
    }
}
END {
    for (id in cites) {
        distinct++
        if ((id in record) || (id in rowok)) continue
        print "CITE\t" citefile[id] "\t" citeline[id] "\t" id "\t" cites[id]
    }
    # A namespace that leads no row in the page declaring it resolves nothing
    # there. Credited above wherever a row matched, so a namespace whose ids also
    # have record files is live all the same: what is reported is a declaration
    # no row in its own page answers to.
    for (f in ng)
        for (k = 1; k <= ng[f]; k++)
            if (!((f, k) in ghit))
                print "DEADCITE\t" f "\t" gline[f, k] "\t" gsrc[f, k]
    # What there was to resolve *against*, so the shell half can tell a check
    # that found nothing wrong from one that had nothing to examine: the count
    # of declared namespaces and of tracked record files. Both zero and no
    # identifier in the tree could resolve however sound it is.
    for (f in ng) nsdecl += ng[f]
    for (r in record) nrec++
    print "CITENS\t" nsdecl + 0 "\t" nrec + 0
    print "CITETOTAL\t" total + 0 "\t" distinct + 0
}
' "$WORK/index" "${CITEFILES[@]}" | sort > "$WORK/citations"

# ---------------------------------------------------------------------------
# The report.
# ---------------------------------------------------------------------------
fail=0
yield=$(awk -F'\t' '$1 == "YIELD" { print $2 }' "$WORK/records")
bytes=$(git ls-files -z -- '*.md' | xargs -0 cat | wc -c | tr -d ' ')

log "docgate: $(wc -l < "$WORK/subjects" | tr -d ' ') tracked Markdown files, $yield path claims, $bytes bytes"

# Withdrawn, and printed rather than quiet: a withdrawal that nobody sees is a
# hole in the gate that nobody sees either. Above the cap the whole withdrawal
# is refused: an excuse that carries two fifths of the check is not a footnote
# about three ignored files, it is the check.
share=$(awk -v e="$excused" -v g="$yield" 'BEGIN { printf "%.1f", g ? 100 * e / g : 0 }')
excuse=honoured
if [ "$excused" -gt 0 ] && [ $((excused * 100)) -gt $((yield * MAX_EXCUSED_PERCENT)) ]; then
    excuse=refused
fi
if [ -s "$WORK/bydesign" ]; then
    log ""
    log "withdrawn — untracked by design (.gitignore), $(wc -l < "$WORK/bydesign" | tr -d ' ') distinct, $excused claims, $share% of $yield:"
    sed 's/^/  /' "$WORK/bydesign"
fi
awk -F'\t' '$1 == "FOREIGN" { printf "  %s: %s withdrawn by its foreign-paths declaration\n", \
                                     $2, ($3 == 1 ? "1 claim" : $3 " claims") }' \
    "$WORK/records" > "$WORK/fp"
if [ -s "$WORK/fp" ]; then
    log ""
    log "withdrawn — declared foreign:"
    cat "$WORK/fp"
fi

# 1. Roots. The other half of the declaration: a declared root that no longer
#    names a tracked directory means the directory was renamed, and every
#    command line still rooted at it is stale — including the ones this gate
#    would otherwise have gone quiet about.
: > "$WORK/staleroots"
for r in $ROOTS; do
    [ -n "$(git ls-files -- "$r/")" ] || printf '%s\n' "$r" >> "$WORK/staleroots"
done
if [ -s "$WORK/staleroots" ]; then
    log ""
    log "FAIL — declared roots that name no tracked directory:"
    sed 's/^/  /; s/$/: renamed or removed since it was declared/' "$WORK/staleroots"
    log "    every fenced command line rooted here still names the old directory,"
    log "    and a root derived from the tree would have gone quiet instead of"
    log "    saying so. Rename it on the 'roots' line in"
    log "      $BUDGET_FILE"
    log "    first, then in the pages, so the next run reports the pages."
    fail=1
fi

# 2. Fences. One unbalanced fence hid 86% of fixtures/README.md on GitHub, in a
#    file that had been read by eye more than once.
if awk -F'\t' '$1 == "FENCEOPEN" || $1 == "FENCETEXT"' "$WORK/records" | grep -q .; then
    log ""
    log "FAIL — fenced blocks:"
    awk -F'\t' '
        $1 == "FENCEOPEN" { printf "  %s:%s: fence `%s` is never closed\n", $2, $3, $4
                            printf "    close it, or the rest of the page renders as code\n" }
        $1 == "FENCETEXT" { printf "  %s:%s: closing fence carries trailing text: %s\n", $2, $3, $5
                            printf "    a closing fence must be the whole line, or everything below it\n"
                            printf "    renders as code; the block opened at %s:%s\n", $2, $4 }
    ' "$WORK/records"
    fail=1
fi

# 3. The excuse itself, before the claims it withdrew.
if [ "$excuse" = refused ]; then
    log ""
    log "FAIL — the untracked-by-design withdrawal is refused: it carries $excused of"
    log "       $yield claims ($share%), over the cap of $MAX_EXCUSED_PERCENT%."
    log "    A withdrawal removes a claim from the check, so an uncapped one is"
    log "    how a broken corpus passes — one ignored path at a time, each"
    log "    defensible on its own. $excused_pages of the withdrawn tokens are Markdown"
    log "    pages, and that is not a filing detail: a page every cloner receives"
    log "    points at a document no clone contains. Every claim below is now"
    log "    checked as though it had no excuse. Track what the shipped pages"
    log "    point at, or stop pointing at it."
    fail=1
fi

# 4. Paths.
if grep -q '^UNRESOLVED' "$WORK/resolved"; then
    awk -F'\t' -v bydesign="$WORK/bydesign" -v excuse="$excuse" '
        BEGIN { if (excuse == "honoured") while ((getline l < bydesign) > 0) ok[l] = 1 }
        $1 == "UNRESOLVED" { t = $5; sub(/\/$/, "", t); if (!(t in ok)) print }
    ' "$WORK/resolved" > "$WORK/dead" || true
    if [ -s "$WORK/dead" ]; then
        log ""
        log "FAIL — path claims that name nothing in this repository:"
        awk -F'\t' '{ printf "  %s:%s: `%s` (%s) resolves to no tracked path\n", $2, $3, $5, $4 }' "$WORK/dead"
        log "    fix the path, or — if it is not a path in this repository —"
        log "    declare its shape in that document's front matter:"
        log "      ---"
        log "      foreign-paths:"
        log "        - \"tools/*\"   # what these tokens really are"
        log "      ---"
        fail=1
    fi
fi

# 5. Declarations, of both kinds. One that excuses everything, or nothing, is
#    not a declaration. `resolves-citations` is policed here for the same reason
#    `foreign-paths` is and needs it more: it withdraws a citation from the check
#    with nothing like the 25% cap above it, so one line of front matter in any
#    tracked page could resolve every identifier in the tree and report PASS.
if awk -F'\t' '$1 == "BADGLOB" || $1 == "DEADGLOB"' "$WORK/records" | grep -q . ||
   awk -F'\t' '$1 == "BADCITE" || $1 == "DEADCITE"' "$WORK/citations" | grep -q .; then
    log ""
    log "FAIL — front-matter declarations:"
    awk -F'\t' '
        $1 == "BADGLOB"  { printf "  %s:%s: `%s` is all wildcard — an opt-out, not a shape\n", $2, $3, $4 }
        $1 == "DEADGLOB" { printf "  %s:%s: `%s` matches nothing in its own document; delete it\n", $2, $3, $4 }
    ' "$WORK/records"
    awk -F'\t' '
        $1 == "BADCITE"  { printf "  %s:%s: resolves-citations `%s` %s\n", $2, $3, $4, $5 }
        $1 == "DEADCITE" { printf "  %s:%s: resolves-citations `%s` leads no row in its own document; delete it\n", $2, $3, $4 }
    ' "$WORK/citations"
    fail=1
fi

# 6. Anchors. A link that resolves to the right file and the wrong place in it
#    is not reported by anything else a reader has: the browser scrolls to the
#    top of the page and says nothing.
if grep -q '^ANCHOR' "$WORK/resolved"; then
    log ""
    log "FAIL — links to headings that are not there:"
    awk -F'\t' '$1 == "ANCHOR" { printf "  %s:%s: `#%s` names no heading in %s\n", $2, $3, $5, $4 }' \
        "$WORK/resolved"
    log "    a browser given an anchor it cannot find scrolls to the top and"
    log "    reports nothing, so the reader lands somewhere plausible and never"
    log "    learns the section moved. Fix the anchor, or restore the heading."
    fail=1
fi

# 7. Citations. `DR-NNN` is cited from the code and the workflows a cloner
#    receives; an identifier that resolves to nothing is a reference into a
#    document the clone does not contain.
#
#    Unless there is nothing here for one to resolve *to*. When no tracked page
#    declares a `resolves-citations` namespace and no decision record is tracked,
#    every identifier in the tree fails alike, and it fails for a reason the
#    repository chose and wrote down in `.gitignore` rather than for anything a
#    page got wrong. A check with no yield has examined nothing: reporting it as
#    a failure would make the gate permanently red on a settled decision, and
#    reporting it as a pass would claim the citations were followed when none
#    was. It is `n/a` and counts in neither direction — and it is said out loud
#    on the scorecard, because a check that goes quiet is indistinguishable from
#    one that is working. The moment a namespace is declared or a record is
#    tracked, every identifier is checked again exactly as below; BADCITE and
#    DEADCITE are not gated on this at all, since neither can fire without a
#    declaration to police.
cited=$(awk -F'\t' '$1 == "CITETOTAL" { print $2 }' "$WORK/citations")
resolvers=$(awk -F'\t' '$1 == "CITENS" { print $2 + $3 }' "$WORK/citations")
case $resolvers in ''|*[!0-9]*) die "the citation pass emitted no CITENS record" ;; esac
if [ "$resolvers" -eq 0 ]; then
    log ""
    log "citations: n/a — no yield. No tracked page declares a resolves-citations"
    log "    namespace and no decision record is tracked, so there is nothing for"
    log "    a DR-NNN to resolve to and this check has examined none of the $cited"
    log "    it found. They are unresolvable for a cloner by design: the whole"
    log "    design record is working-tree material, and .gitignore says so."
    log "    Neither a pass nor a failure. Declare a namespace in a tracked page,"
    log "    or track a record, and every one of them is checked again."
elif grep -q '^CITE\t' "$WORK/citations"; then
    log ""
    log "FAIL — decision-record citations that resolve to nothing:"
    awk -F'\t' '$1 == "CITE" {
        printf "  %s: cited %s, first at %s:%s\n", $4, ($5 == 1 ? "once" : $5 " times"), $2, $3 }' \
        "$WORK/citations"
    log "    a citation resolves to a tracked record file — docs/decisions/DR-NNN-*.md —"
    log "    or to an id-led row in a tracked page that declares what it resolves:"
    log "      ---"
    log "      resolves-citations: [\"DR-*\"]"
    log "      ---"
    log "    Add the row, or delete the citation. A reference a cloner cannot"
    log "    follow is worse than none: it reads as a promise that it is followable."
    fail=1
fi

# 8. Yield. A gate that extracts nothing and reports PASS is worse than none.
if [ "$yield" -lt "$FLOOR" ]; then
    log ""
    log "FAIL — the extractor found $yield path claims, below the floor of $FLOOR."
    log "    Look at tools/docgate/docgate.sh, not at the documentation: a gate"
    log "    that checks nothing passes silently. Either shape_ok() or the"
    log "    fence/prose split stopped matching. Lower the floor in"
    log "    $BUDGET_FILE only with the measurement that justifies it."
    fail=1
fi

# 9. Bytes. The surface a cloner reads is not allowed to grow unremarked — and
#    the budget is not allowed to keep credit for bytes that are already gone.
#    Failing in both directions is what makes it a ratchet rather than a ceiling
#    that drifts upward once and never comes back down.
if [ "$bytes" -gt "$BUDGET" ]; then
    log ""
    log "FAIL — tracked documentation is $bytes bytes, over the budget of $BUDGET."
    log "    Cut something, or raise the 'bytes' line in $BUDGET_FILE and say"
    log "    in the commit what the new bytes buy. The budget exists so that"
    log "    growth is a reviewed line rather than a side effect."
    fail=1
elif [ "$bytes" -lt "$BUDGET" ]; then
    log ""
    log "FAIL — the budget is stale; lower it to $bytes."
    log "    The surface measures $bytes against a budget of $BUDGET, so"
    log "    $((BUDGET - bytes)) bytes of headroom have been banked. Unspent headroom is"
    log "    how a budget becomes a ceiling nobody has looked at — the next page"
    log "    grows into it in silence. Lower the 'bytes' line in"
    log "      $BUDGET_FILE"
    log "    and the number goes on measuring today rather than some earlier day."
    fail=1
fi

# `measure` prints and changes nothing, but it does not launder the verdict: it
# used to exit 0 while printing a full FAIL report, so a wrapper that asked for
# the numbers got green from a red tree.
# What the scorecard is allowed to say about citations. A run that examined
# none of them says so here too, rather than reporting a number that reads as
# a number checked.
if [ "$resolvers" -eq 0 ]; then
    cite_measure="citations n/a ($cited unresolvable by design)"
    cite_pass="       $yield claims checked and $bytes of $BUDGET budgeted bytes;"$'\n'"       citations n/a — none of the $cited can resolve in a clone, by design."
else
    cite_measure="citations $cited"
    cite_pass="       every citation is followable: $yield claims and $cited citations"$'\n'"       checked, $bytes of $BUDGET budgeted bytes."
fi

if [ "$MODE" = measure ]; then
    log ""
    log "measure: claims $yield  bytes $bytes  $cite_measure  excused $excused ($share%)"
    exit "$fail"
fi

if [ "$fail" -eq 0 ]; then
    log ""
    log "PASS — every path resolves, every anchor lands, every fence closes,"
    log "$cite_pass"
fi
exit "$fail"
