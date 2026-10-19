#!/usr/bin/env bash
# Opt-in end-to-end against a LOCAL Red-XAI Accounts (--dev --store mem).
# Requires: redxai-accounts on PATH or REDXAI_ACCOUNTS_BIN, and a built redxd.
# Usage: REDX_ACCOUNTS_E2E=1 scripts/accounts-e2e-real.sh [redxd]
# Never prints the client secret. Owner emails are placeholders only.
set -euo pipefail
if [[ "${REDX_ACCOUNTS_E2E:-}" != "1" ]]; then
  echo "SKIP set REDX_ACCOUNTS_E2E=1 to run against a local Red-XAI Accounts"
  exit 77
fi
REDXD=${1:-./bin/redxd}
ACCOUNTS_BIN=${REDXAI_ACCOUNTS_BIN:-redxai-accounts}
command -v "$ACCOUNTS_BIN" >/dev/null || ACCOUNTS_BIN=/workspace/red-xai-accounts/redxai-accounts
command -v "$ACCOUNTS_BIN" >/dev/null || { echo "redxai-accounts not found"; exit 2; }
DIR=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$DIR"' EXIT
PORT_A=18765
PORT_R=18766
OWNER=owner@example.com
export REDXAI_OWNER_EMAILS="$OWNER"
export REDXAI_LISTEN="127.0.0.1:$PORT_A"
# Start Accounts without seeding redx; we register via owner API after signup.
"$ACCOUNTS_BIN" serve --dev --store mem --offline-dns --listen "127.0.0.1:$PORT_A" \
  --issuer "http://127.0.0.1:$PORT_A" >"$DIR/accounts.log" 2>&1 &
for i in $(seq 1 100); do curl -sf "http://127.0.0.1:$PORT_A/healthz" >/dev/null 2>&1 && break; sleep 0.1; done
ISSUE=http://127.0.0.1:$PORT_A
# Under-13 signup must be refused by Accounts rules (proxied or direct)
UNDER=$(date -u -d '12 years ago' +%m/%d/%Y 2>/dev/null || date -u -v-12y +%m/%d/%Y)
code=$(curl -s -o "$DIR/under.json" -w '%{http_code}' -X POST "$ISSUE/v1/validate/dob" \
  -H 'Content-Type: application/json' -d "{\"dob\":\"$UNDER\",\"app\":\"redx\"}")
grep -q under_min_age "$DIR/under.json" || { echo "FAIL under-13 not refused: $code $(cat $DIR/under.json)"; exit 1; }
echo "ok   under-13 refused by Accounts"
# Confidential client + PKCE still required is covered by RedX unit/fake tests.
# Full OIDC+owner+ban-event against real Accounts needs an owner session (email verify + TOTP);
# that path is exercised in red-xai-accounts' own e2e. This script confirms the local service is up
# and age rules match v1.1; set REDX_ACCOUNTS_E2E_FULL=1 later for the longer browser flow.
echo "ok   local Red-XAI Accounts reachable at $ISSUE (dev mem)"
echo "PASS accounts-e2e-real (smoke). Full OIDC/owner/ban: use red-xai-accounts internal/e2e + fake CI tests."
