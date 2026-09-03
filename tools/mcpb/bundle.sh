#!/usr/bin/env bash
# Assembles the .mcpb from a staging directory already holding
# server/darwin/rpf, server/linux/rpf and server/win32/rpf.exe — whichever of
# them exist. A .mcpb is a zip of those binaries beside a manifest.json.
set -euo pipefail

if [ $# -ne 3 ]; then
  echo "usage: ${0##*/} <version> <staging-dir> <out.mcpb>" >&2
  exit 2
fi

version=$1
stage=$(cd "$2" && pwd)
out=$(cd "$(dirname "$3")" && pwd)/$(basename "$3")
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

present=()
for platform in darwin linux win32; do
  exe=""
  [ "$platform" = win32 ] && exe=.exe
  if [ -f "$stage/server/$platform/rpf$exe" ]; then
    chmod +x "$stage/server/$platform/rpf$exe"
    present+=("$platform")
  fi
done
if [ ${#present[@]} -eq 0 ]; then
  echo "no binaries under $stage/server" >&2
  exit 1
fi

# The manifest names three platforms; a bundle assembled from fewer must not
# claim the ones whose binary is missing, and the platform it runs by default
# has to be one that is actually in the zip.
platforms=$(printf '%s\n' "${present[@]}" | jq -R . | jq -sc .)
jq --arg v "$version" --argjson p "$platforms" '
  .version = $v
  | .compatibility.platforms = $p
  | .server.mcp_config.platform_overrides |= with_entries(select(.key | IN($p[])))
  | if ($p | index("darwin")) then .
    else
      (.server.mcp_config.platform_overrides[$p[0]].command) as $c
      | .server.entry_point = ($c | ltrimstr("${__dirname}/"))
      | .server.mcp_config.command = $c
      | del(.server.mcp_config.platform_overrides[$p[0]])
    end
' "$here/manifest.json" > "$stage/manifest.json"

cp "$root/README.md" "$root/LICENSE-MIT" "$root/LICENSE-APACHE" "$stage/"
# The manifest's `icon` names a path inside the bundle, so the icon travels in
# the zip under the name the manifest uses rather than the one it has in the
# repository.
cp "$root/.github/icon-512.png" "$stage/icon.png"

rm -f "$out"
(cd "$stage" && zip -qrX "$out" manifest.json icon.png server README.md LICENSE-MIT LICENSE-APACHE)
