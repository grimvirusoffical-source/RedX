#!/bin/sh
# Real rootless run of deploy/install.sh --user against built binaries. Usage: install_user_test.sh <bin dir>
set -eu
B="$1"; R=$(cd "$(dirname "$0")/../.." && pwd); T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
HOME="$T" sh "$R/deploy/install.sh" --from "$B" --user --role follower --peers "https://a:1,https://b:2" >/dev/null
C="$T/.redx/redx.toml"
grep -qx 'peers = \["https://a:1", "https://b:2"\]' "$C" || { echo "FAIL peers"; cat "$C"; exit 1; }
"$T/.local/bin/redxd" -h >/dev/null 2>&1 || true
[ "$(stat -c %a "$T/.redx/data")" = 700 ] || { echo "FAIL data perms"; exit 1; }
# config must be parsed by the real binary (follower w/o join should fail ONLY on missing join, not TOML)
OUT=$(timeout 5 "$T/.local/bin/redxd" run --config "$C" --no-open 2>&1 || true)
echo "$OUT" | grep -qi 'toml\|parse' && { echo "FAIL config parse: $OUT"; exit 1; }
echo PASS
