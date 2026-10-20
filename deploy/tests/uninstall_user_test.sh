#!/bin/sh
# Real rootless install.sh --user then uninstall.sh --user, without and with --purge; idempotency and a
# partial install. Usage: uninstall_user_test.sh <bin dir>
set -eu
B="$1"; R=$(cd "$(dirname "$0")/../.." && pwd); T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
FAILS=0; fail() { echo "FAIL $*"; FAILS=$((FAILS+1)); }
cp "$B/redxd" "$B/redx" "$T/"; printf '<svg/>' > "$T/redx.svg"; mkdir "$T/h"; H="$T/h"
HOME="$H" sh "$R/deploy/install.sh" --from "$T" --user >/dev/null
for f in .local/bin/redxd .local/bin/redx .redx/redx.toml .redx/data/keys.red-xai-keys .local/share/applications/redx-console.desktop; do
  [ -e "$H/$f" ] || fail "install missing $f"; done
SUM=$(sha256sum "$H/.redx/redx.toml" "$H/.redx/data/keys.red-xai-keys")
# a running foreground host is stopped by uninstall
P=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')
sed -i "s/127.0.0.1:7777/127.0.0.1:$P/" "$H/.redx/redx.toml"; SUM=$(sha256sum "$H/.redx/redx.toml" "$H/.redx/data/keys.red-xai-keys")
"$H/.local/bin/redxd" run --config "$H/.redx/redx.toml" --no-open >/dev/null 2>&1 & PID=$!
for i in $(seq 50); do curl -fsS "http://127.0.0.1:$P/healthz" >/dev/null 2>&1 && break; sleep 0.2; done
HOME="$H" sh "$R/deploy/uninstall.sh" --user >/dev/null
for i in $(seq 25); do kill -0 $PID 2>/dev/null || break; sleep 0.2; done
kill -0 $PID 2>/dev/null && { fail "running redxd not stopped"; kill $PID; }
for f in .local/bin/redxd .local/bin/redx .local/share/applications/redx-console.desktop .local/share/icons/hicolor/scalable/apps/redx.svg; do
  [ ! -e "$H/$f" ] || fail "uninstall left $f"; done
[ "$(sha256sum "$H/.redx/redx.toml" "$H/.redx/data/keys.red-xai-keys")" = "$SUM" ] || fail "data/config changed without --purge"
HOME="$H" sh "$R/deploy/uninstall.sh" --user >/dev/null || fail "second uninstall not idempotent"
# reinstall keeps existing config + keystore
HOME="$H" sh "$R/deploy/install.sh" --from "$T" --user >"$T/re.log"
grep -q "keeping existing config" "$T/re.log" && grep -q "keystore already exists" "$T/re.log" || fail "reinstall did not keep data"
HOME="$H" sh "$R/deploy/uninstall.sh" --user --purge >/dev/null
[ ! -e "$H/.redx" ] || fail "--purge left ~/.redx"
[ ! -e "$H/.local/bin/redxd" ] || fail "--purge left binary"
HOME="$H" sh "$R/deploy/uninstall.sh" --user --purge >/dev/null || fail "second purge not idempotent"
# partial install: only one binary and nothing else
mkdir -p "$H/.local/bin"; cp "$B/redx" "$H/.local/bin/"
HOME="$H" sh "$R/deploy/uninstall.sh" --user >/dev/null || fail "partial uninstall failed"
[ ! -e "$H/.local/bin/redx" ] || fail "partial: binary left"
# unrelated files are untouched
mkdir -p "$H/.local/bin"; echo keep > "$H/.local/bin/other"; HOME="$H" sh "$R/deploy/uninstall.sh" --user --purge >/dev/null
[ -f "$H/.local/bin/other" ] || fail "removed an unrelated file"
sh "$R/deploy/uninstall.sh" --user --remove-user >/dev/null 2>&1 && fail "--remove-user without --purge accepted"
[ "$FAILS" = 0 ] && echo PASS || { echo "$FAILS failure(s)"; exit 1; }
