#!/usr/bin/env bash
# 3-node cluster smoke test on loopback (leader + 2 followers joined with `redx node join`).
# usage: scripts/cluster-smoke.sh [bindir]
set -uo pipefail
BIN="${1:-bin}"; BIN="$(cd "$BIN" && pwd)"
D=${KEEP:-$(mktemp -d)}; PIDS=""; trap 'kill $PIDS 2>/dev/null; [ -n "${KEEP:-}" ] || rm -rf "$D"' EXIT
fail=0; ok() { echo "PASS  $*"; }; bad() { echo "FAIL  $*"; fail=1; }
free() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'; }
P0=$(free); P1=$(free); P2=$(free)
start() { "$BIN/redxd" run --no-open --bootstrap console --data-dir "$D/$1" --listen "127.0.0.1:$2" > "$D/$1.out" 2>&1 & PIDS="$PIDS $!"; for i in $(seq 1 50); do curl -sf "http://127.0.0.1:$2/healthz" >/dev/null && return; sleep 0.1; done; echo "start $1 failed"; cat "$D/$1.out"; exit 1; }
start leader $P0
export REDX_KEY=$(grep -o 'rx_live_[0-9A-Za-z]*' "$D/leader.out" | head -1)
export REDX_ADDR="http://127.0.0.1:$P0"
for n in 1 2; do
  eval P=\$P$n
  TOK=$("$BIN/redx" node token | head -1)
  REDX_KEY= "$BIN/redx" node join "http://127.0.0.1:$P0" --token "$TOK" --data-dir "$D/f$n" --node-id "f$n" --advertise "http://127.0.0.1:$P" >/dev/null && ok "node f$n joined" || bad "join f$n"
  start f$n $P
done
curl -s -o /dev/null -w '' -X PUT -H "Authorization: Bearer $REDX_KEY" --data '"hello"' "http://127.0.0.1:$P0/v1/path/c.red-xai.db:B.K"
for n in 1 2; do
  eval P=\$P$n
  for i in $(seq 1 50); do curl -s -H "Authorization: Bearer $REDX_KEY" "http://127.0.0.1:$P/v1/path/c.red-xai.db:B.K" | grep -q hello && break; sleep 0.1; done
  curl -s -H "Authorization: Bearer $REDX_KEY" "http://127.0.0.1:$P/v1/path/c.red-xai.db:B.K" | grep -q hello && ok "leader write replicated to f$n" || bad "replication to f$n"
done
c=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $REDX_KEY" --data '"via-follower"' "http://127.0.0.1:$P1/v1/path/c.red-xai.db:B.K2")
[ "$c" = 200 ] && ok "write through follower forwarded to leader (200)" || bad "forwarded write ($c)"
curl -s -H "Authorization: Bearer $REDX_KEY" "http://127.0.0.1:$P0/v1/path/c.red-xai.db:B.K2" | grep -q via-follower && ok "forwarded write landed on leader" || bad "forwarded write missing on leader"
sleep 1
"$BIN/redx" node status
"$BIN/redx" node status --json | python3 -c 'import sys,json;d=json.load(sys.stdin);assert len(d["members"])==3 and all(m["healthy"] for m in d["members"])' && ok "3 healthy members" || bad "membership"

# ---- self-signed TLS: promote + repoint must end with exactly one leader ----
T0=$(free); T1=$(free)
startt() { "$BIN/redxd" run --no-open --bootstrap console --tls auto --data-dir "$D/$1" --listen "127.0.0.1:$2" --advertise "https://127.0.0.1:$2" > "$D/$1.out" 2>&1 & PIDS="$PIDS $!"; for i in $(seq 1 80); do curl -skf "https://127.0.0.1:$2/healthz" >/dev/null && return; sleep 0.1; done; echo "start $1 failed"; cat "$D/$1.out"; exit 1; }
fp() { grep -o 'fingerprint: [0-9a-f]\{64\}' "$D/$1.out" | head -1 | cut -d' ' -f2; }
startt tls0 $T0
TK=$(grep -o 'rx_live_[0-9A-Za-z]*' "$D/tls0.out" | head -1); FP0=$(fp tls0)
rx() { REDX_KEY="$TK" "$BIN/redx" "$@"; }
TOK=$(REDX_ADDR="https://127.0.0.1:$T0" REDX_PIN="$FP0" rx node token | head -1)
REDX_KEY= REDX_PIN="$FP0" "$BIN/redx" node join "https://127.0.0.1:$T0" --token "$TOK" --data-dir "$D/tls1" --node-id t1 --advertise "https://127.0.0.1:$T1" >/dev/null && ok "TLS node t1 joined with the leader's pin" || bad "TLS join"
startt tls1 $T1
FP1=$(fp tls1)
curl -sk -o /dev/null -X PUT -H "Authorization: Bearer $TK" --data '"tls"' "https://127.0.0.1:$T0/v1/path/t.red-xai.db:B.K"
for i in $(seq 1 80); do curl -sk -H "Authorization: Bearer $TK" "https://127.0.0.1:$T1/v1/path/t.red-xai.db:B.K" | grep -q tls && break; sleep 0.1; done
curl -sk -H "Authorization: Bearer $TK" "https://127.0.0.1:$T1/v1/path/t.red-xai.db:B.K" | grep -q tls && ok "replicated over pinned TLS" || bad "TLS replication"
REDX_ADDR="https://127.0.0.1:$T1" REDX_PIN="$FP1" rx node promote >/dev/null && ok "t1 promoted" || bad "promote t1"
for i in $(seq 1 60); do REDX_ADDR="https://127.0.0.1:$T0" REDX_PIN="$FP0" rx node status --json | grep -q '"fenced"' && break; sleep 0.1; done
c=$(curl -sk -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $TK" --data '"split"' "https://127.0.0.1:$T0/v1/path/t.red-xai.db:B.Split")
[ "$c" = 503 ] && ok "old leader fenced: writes refused (503)" || bad "old leader still takes writes ($c)"
TOK=$(REDX_ADDR="https://127.0.0.1:$T1" REDX_PIN="$FP1" rx node token | head -1)
REDX_ADDR="https://127.0.0.1:$T0" REDX_PIN="$FP0" rx node repoint "https://127.0.0.1:$T1" --token "$TOK" >/dev/null && ok "repoint old leader over self-signed TLS (pin learned from the fence)" || bad "TLS repoint"
leaders=0
for P in $T0 $T1; do
  F=$FP0; [ "$P" = "$T1" ] && F=$FP1
  REDX_ADDR="https://127.0.0.1:$P" REDX_PIN="$F" rx node status --json | python3 -c 'import sys,json;d=json.load(sys.stdin);sys.exit(0 if d["role"]=="leader" and not d.get("fenced") else 1)' && leaders=$((leaders+1))
done
[ "$leaders" = 1 ] && ok "exactly one leader after promote + repoint" || bad "$leaders leaders after promote + repoint"
curl -sk -o /dev/null -X PUT -H "Authorization: Bearer $TK" --data '"after"' "https://127.0.0.1:$T1/v1/path/t.red-xai.db:B.After"
for i in $(seq 1 80); do curl -sk -H "Authorization: Bearer $TK" "https://127.0.0.1:$T0/v1/path/t.red-xai.db:B.After" | grep -q after && break; sleep 0.1; done
curl -sk -H "Authorization: Bearer $TK" "https://127.0.0.1:$T0/v1/path/t.red-xai.db:B.After" | grep -q after && ok "old leader now follows the new one" || bad "old leader not following"
exit $fail
