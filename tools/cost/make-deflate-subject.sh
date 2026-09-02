#!/usr/bin/env bash
# Builds the one subject the corpus does not hold: an archive whose large
# entries are deflated, so a rebuild re-compresses rather than copies. R12.1.
#
#   make-deflate-subject.sh [ARCHIVE]
#
# The content is generated from a fixed seed, so the archive is reproducible
# byte for byte from this script and the `rpf` it is run with. It is never
# tracked: DR-006 keeps generated and game bytes out of the repository alike.
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RPF=${RPF_BIN:-$HERE/../../target/release/rpf}
ARCHIVE=${1:-$HERE/../../assets/cost_deflate/deflate.rpf}

# 53 entries of 4 MiB of prose-shaped text, which deflate takes about 4.7:1 —
# so the archive lands at ~44.9 MiB, the size of `test2/test2.rpf` on disk.
LARGE_COUNT=${RPF_DEFLATE_ENTRIES:-53}
LARGE_BYTES=${RPF_DEFLATE_ENTRY_BYTES:-4194304}
SMALL_COUNT=8
SMALL_BYTES=4096
SEED=20260902

[ -x "$RPF" ] || { printf 'no binary at %s; cargo build --release\n' "$RPF" >&2; exit 2; }

TREE=$(mktemp -d "${TMPDIR:-/tmp}/rpf-deflate-tree.XXXXXX")
trap 'rm -rf "$TREE"' EXIT

python3 - "$TREE" "$LARGE_COUNT" "$LARGE_BYTES" "$SMALL_COUNT" "$SMALL_BYTES" "$SEED" <<'PY'
import json, os, sys

tree, large_count, large_bytes, small_count, small_bytes, seed = (
    sys.argv[1], *(int(a) for a in sys.argv[2:]))

# A 256-word vocabulary over the alphabet, ordered by a 64-bit LCG: repeated
# tokens within the deflate window, which is what makes an entry compressible.
alphabet = 'abcdefghijklmnopqrstuvwxyz'
vocabulary = [
    ''.join(alphabet[(i * 7 + j * 13 + 3) % 26] for j in range(3 + i % 6))
    for i in range(256)
]

state = seed


def word():
    global state
    state = (state * 6364136223846793005 + 1442695040888963407) % (1 << 64)
    return vocabulary[(state >> 33) % 256]


def write(path, size):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='ascii') as out:
        written = 0
        while written < size:
            line = ' '.join(word() for _ in range(12))[:size - written - 1] + '\n'
            out.write(line)
            written += len(line)


entries = []
for i in range(small_count):
    path = f'data/small{i:02d}.meta'
    write(os.path.join(tree, path), small_bytes)
    entries.append({'path': path, 'class': 'binary', 'storage': 'stored',
                    'encryption': 0})
for i in range(large_count):
    path = f'text/bulk{i:03d}.txt'
    write(os.path.join(tree, path), large_bytes)
    entries.append({'path': path, 'class': 'binary', 'storage': 'deflate',
                    'encryption': 0})

manifest = {
    'schema': 4,
    'version': 'rpf7',
    'codec': 'deflate',
    'encryption': 0x4E45504F,  # ASCII OPEN: not encrypted
    'directories': ['data', 'text'],
    'entries': entries,
}
with open(os.path.join(tree, '.rpf-manifest.json'), 'w', encoding='utf-8') as out:
    json.dump(manifest, out, indent=2)
PY

mkdir -p "$(dirname -- "$ARCHIVE")"
"$RPF" pack --json "$TREE" "$ARCHIVE"
