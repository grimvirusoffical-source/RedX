#!/bin/sh
# Real rootless install.sh --user runs with hostile values; the written redx.toml is parsed by the real host
# config loader (tomlcheck -> host.Config.ApplyFile) and the exact values must round-trip. Control characters
# and newlines must be rejected before anything is installed. Then the real redxd must read the file.
# Usage: escape_test.sh <bin dir with redxd, redx, tomlcheck>
set -eu
B="$1"; R=$(cd "$(dirname "$0")/../.." && pwd); FAILS=0
fail() { echo "FAIL $*"; FAILS=$((FAILS+1)); }
run_case() { # name key expected-value install-args...   (peers: expected is the raw comma list)
  N="$1"; K="$2"; WANT="$3"; shift 3
  T=$(mktemp -d)
  if ! HOME="$T" sh "$R/deploy/install.sh" --from "$B" --user "$@" >"$T.log" 2>&1; then fail "$N: install failed: $(cat "$T.log")"; rm -rf "$T" "$T.log"; return; fi
  GOT=$("$B/tomlcheck" "$T/.redx/redx.toml" 2>&1) || { fail "$N: toml parse: $GOT"; cat "$T/.redx/redx.toml"; rm -rf "$T" "$T.log"; return; }
  printf '%s' "$GOT" | python3 -c '
import json,sys
got=json.load(sys.stdin)[sys.argv[1]]; want=sys.argv[2]
if sys.argv[1]=="peers": want=[p for p in want.split(",") if p]
sys.exit(0 if got==want else "mismatch: got %r want %r" % (got,want))' "$K" "$WANT" || fail "$N"
  rm -rf "$T" "$T.log"
}
reject_case() { # name install-args...   (must exit non-zero and install nothing)
  N="$1"; shift; T=$(mktemp -d)
  if HOME="$T" sh "$R/deploy/install.sh" --from "$B" --user "$@" >/dev/null 2>&1; then fail "$N: accepted"; fi
  [ ! -e "$T/.local/bin/redxd" ] && [ ! -e "$T/.redx/redx.toml" ] || fail "$N: installed something before rejecting"
  rm -rf "$T"
}
Q='"'; BS='\'
V="127.0.0.1:7777${Q}x = 1";             run_case quote-listen listen "$V" --listen "$V"
V="a${BS}b${BS}${Q}c${BS}${BS}";          run_case backslash listen "$V" --listen "$V"
V="leader${Q} listen = ${Q}0.0.0.0:1";    run_case inject-role role "$V" --role "$V"
V="/tmp/c ${Q}x${Q}.pem";                 run_case tls-cert tls_cert "$V" --tls files --tls-cert "$V" --tls-key k
V="C:${BS}k${BS}${BS}.pem${BS}";          run_case tls-key tls_key "$V" --tls files --tls-cert c --tls-key "$V"
V="https://a:1${Q}],b${BS}${Q},*";        run_case hostile-peers peers "$V" --role follower --peers "$V"
V='$(touch /tmp/pwned_redx)`id`';        run_case shell-meta listen "$V" --listen "$V"
[ ! -e /tmp/pwned_redx ] || fail "shell metacharacters were executed"
V="hé☃:7777";                             run_case unicode listen "$V" --listen "$V"
NL='
'
reject_case newline-listen --listen "127.0.0.1:7777${NL}role = ${Q}follower${Q}"
reject_case newline-peers  --peers "https://a:1${NL}x"
reject_case tab-role       --role "$(printf 'lea\tder')"
reject_case esc-tlskey     --tls-key "$(printf 'k\033[31m')"
reject_case del-tlscert    --tls-cert "$(printf 'c\177')"
reject_case cr-listen      --listen "$(printf '127.0.0.1:7777\rX')"
# the real redxd reads a hostile-but-valid file: config is parsed, then validListen rejects the odd address
T=$(mktemp -d); HOME="$T" sh "$R/deploy/install.sh" --from "$B" --user --listen "127.0.0.1:7777${Q}x" >/dev/null 2>&1
OUT=$(timeout 5 "$B/redxd" run --config "$T/.redx/redx.toml" --no-open 2>&1 || true)
echo "$OUT" | grep -qi 'toml' && fail "redxd toml parse: $OUT"
echo "$OUT" | grep -q 'listen' || fail "redxd did not reach listen validation: $OUT"
# and a normal file starts the real server and serves /healthz
P=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')
rm -rf "$T"; T=$(mktemp -d); HOME="$T" sh "$R/deploy/install.sh" --from "$B" --user --listen "127.0.0.1:$P" >/dev/null
"$B/redxd" run --config "$T/.redx/redx.toml" --no-open >"$T/log" 2>&1 & PID=$!
OK=0; for i in $(seq 50); do curl -fsS "http://127.0.0.1:$P/healthz" >/dev/null 2>&1 && { OK=1; break; }; sleep 0.2; done
kill $PID 2>/dev/null; wait $PID 2>/dev/null || true
[ "$OK" = 1 ] || fail "redxd did not serve /healthz from installer config: $(cat "$T/log")"
rm -rf "$T"
[ "$FAILS" = 0 ] && echo PASS || { echo "$FAILS failure(s)"; exit 1; }
