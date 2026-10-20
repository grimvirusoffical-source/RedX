# RedX host/DB end-to-end findings (updated 2026-10-20 06:08 America/New_York)

Target binary: `host-sec-fixes@db91b86` built from `/workspace/redx-sec-fixes` into
`/workspace/redx-e2e-bin/redxd` (v0.4.5-10-gdb91b86). Worktree: `/workspace/repos/RedX-e2e`
branch `e2e-tests`. Nothing pushed.

`host-integration` was **not present** when this run started (Encryption code expect
still creating it). Full suite ran against the F1–F4 fixed binary instead.

## Architecture (short)

`redxd` serves REST+WS+console; argon2id API keys (scope/db/prefix); WAL engines under
`<data-dir>/dbs/`; optional Accounts/billing/cluster/updates.

## Ran

**63 passed / 0 failed** (`python3 -m pytest -q tests/e2e/`, `REDXD=/workspace/redx-e2e-bin/redxd`).

F1–F4 flipped to regressions asserting FIXED behaviour:
- F2: rotated key 401s after original TTL (`test_f2_rotated_key_expires_at_original_ttl`)
- F3: exactly 1 of 8 concurrent rotates wins, rest 409 (`test_f3_concurrent_rotate_exactly_one_winner`)
- F4: valid code from clean IP redeems after junk burn (`test_f4_valid_code_redeems_after_junk_from_other_ip`)
- F1: exactly 20 401s then 429, serial and concurrent (`test_f1_exactly_twenty_401_then_429`)

Bypass probes (all PASS, no new BREAK):
- Successor-of-successor A→B→C still expires at A's absolute TTL
- Pairing map pressure (~200 other IPs) does not unlock a throttled attacker IP
- Reserve slots: failures keep slots; success releases; window still fills at 20

Also still green: auth oracle, authz/IDOR, injection, malformed, concurrency debit,
persistence/SIGKILL, body limits, slow-body health.

## NOT RUN

| Item | Reason |
|---|---|
| Full suite on `host-integration` | Branch not available yet (plan item 1) |
| TLS / pin / trusted_proxies | No cert fixtures in this pass |
| Leader/follower / promote | Needs two nodes |
| Accounts / OIDC / owner / Stripe / updates webhook | Optional overlays off |
| App-connect PKCE, packs/media/idx/pulse | Out of this pass |
| Installers / systemd (root) | Disposable container only; not required for F1–F4 |
| Any remote / Kamatera host | Forbidden |

## Findings

| ID | Sev | Label | Status |
|---|---|---|---|
| F1–F4 | — | — | **FIXED** on `host-sec-fixes@db91b86`; regressions green |
| (new) | — | — | **None** this pass |

INFO (unchanged): no HTTP body-read deadline (`host/daemon.go` ReadHeaderTimeout only).

## Rerun

```sh
# Build fixed binary (or point at host-integration when it exists)
cd /workspace/redx-sec-fixes && make build
cp -f bin/redxd bin/redx /workspace/redx-e2e-bin/

cd /workspace/repos/RedX-e2e
export REDXD=/workspace/redx-e2e-bin/redxd
python3 -m pytest -q tests/e2e/
```
