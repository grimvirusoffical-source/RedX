# RedX host/DB end-to-end findings (2026-10-20)

Target: `/workspace/repos/RedX` at `aaafbe1` (v0.4.5-8), worktree `e2e-tests`.
Suite: `tests/e2e/` — real `redxd` processes, empty data dirs, no mocks.
Result: **60 passed / 0 failed**.

Labels follow JF's rule: BREAK = outsider using only the public API / network /
docs / their own guesses. TEST HARNESS = needs insider knowledge (data-dir
access, SIGKILL of our own process, etc.).

## Architecture (short)

- `redxd` (Go, CGO off): single static binary. REST + WebSocket on one port
  (default `127.0.0.1:7777`), embedded web console, WAL engines under
  `<data-dir>/dbs/<name>/`.
- Auth: Bearer `rx_live_…` API keys (argon2id hashed, constant-time verify,
  optional AES-GCM keystore) or `rxs_…` account sessions. Scopes
  `read < write < admin`, per-db binding, path-prefix ACL, per-key RPS.
- Dangerous ops (key create/revoke/rotate, drop DB, pairing, join-token, …)
  answer 401 → 403 → 428 confirm, in that order.
- Persistence: per-file WAL + checkpoints; durability `sync|group|async`
  (default group). Crash recovery is part of engine open.
- Cluster: async leader/follower, join tokens (`rxj_`), node secrets (`rxn_`).
- Hosted tenants / Accounts / billing / updates are optional overlays on the
  same mux; this suite covers the core host+DB path with Accounts off.

## Ran

| Suite | Cases | Notes |
|---|---|---|
| `test_auth.py` | 8 | missing/bad/revoked/expired look identical; query-string token ignored without WS upgrade; XFF spoof ignored; failed-auth throttle; bootstrap race; web-bootstrap CSRF/DNS-rebinding |
| `test_authz.py` | 10 | read can't write; db-bound isolation; prefix boundary; no key mint without admin; db-admin can't escalate; key IDOR; 401/403/428 order; revoke immediate; rotate grace |
| `test_injection.py` | 5 | JSON PUT escaping; BoxQL `$params` not command text; read key can't sneak writes via bx/Tx; control chars in paths; bad DB names |
| `test_malformed.py` | 21 | oversized/deep/binary bodies; path traversal forms; bad TTL; wrong methods; deep BoxQL |
| `test_concurrency.py` | 4 | conditional debit never oversells (exactly 100 of 250); last-writer-wins under 500 parallel PUTs; parallel DB create; rotate fan-out regression (asserts expected) |
| `test_persistence.py` | 6 | SIGKILL mid-load under sync and group; revoked key stays revoked; Tx all-or-nothing across crash; torn WAL tail; flock refuses second daemon |
| `test_key_lifecycle.py` | 3 | F2 TTL-extend via rotate; F3 concurrent rotate fan-out; F4 global pair-fail lockout |
| `test_dos.py` | 3 | 17 MiB body rejected; F1 throttle overshoot; slow-body does not block /healthz |

## NOT RUN (and why)

| Area | Reason |
|---|---|
| TLS / pin / reverse-proxy trusted_proxies | Needs cert fixtures + a second listener; deferred |
| Leader/follower replication & promote fence | Needs two redxd + join token + advertise URLs |
| Accounts / OIDC / TOTP / owner routes | Accounts off in this build; covered by the panel break-map elsewhere |
| Billing / Stripe plan gate | `STRIPE_SECRET_KEY` unset → billing off |
| Updates / GitHub webhook HMAC | Needs webhook secret + signing key ceremony |
| App-connect PKCE end-to-end | Needs a second process acting as the app |
| Packs / media / indexes / pulse / scripts / policy files | Exhaustive extras surface; out of this first pass |
| Windows service / NSIS / launchd / systemd install | Root/service; other owners; disposable container only |
| Kamatera / any remote host | Forbidden |

## Findings

### F2 — HIGH — BREAK — rotate resets TTL clock
- **Where:** `host/keystore.go:609-648` (`Rotate`: `sp.TTL = old.Expires.Sub(old.Created)`, then `create` stamps a new `Created=now`).
- **What:** A key with TTL T can be extended forever by rotating before expiry. Each rotate copies the original duration, not the remaining time.
- **Repro:**
  ```
  redxd run --data-dir /tmp/d --listen 127.0.0.1:7801 --bootstrap console
  # create a 4s admin key, then every 3s: POST /v1/keys/{id}/rotate {"grace":"0s"}
  # with X-RedX-Confirm: rotateKey, using the current key. After 12s the key still works.
  ```
  Covered by `test_key_lifecycle.py::test_rotate_extends_ttl_by_resetting_created`.
- **Fix:** Persist absolute `Expires` on create; rotate must copy `Expires` (or remaining), never re-derive TTL from `Created`.

### F3 — HIGH — BREAK — concurrent rotate fans out many live successors
- **Where:** `host/keystore.go:609-648` (create-new then separately mutate-old; no single-flight / generation).
- **What:** N parallel `POST /v1/keys/{id}/rotate` against the same id each return `201` with a distinct live key. With `grace>0` all N stay live for the grace window; with `grace=0` a TOCTOU still lets several past `Revoke`.
- **Repro:** Hold one admin key with `rate_rps=-1`; create a read key; fire 8 parallel rotates with `grace=1h` → 8 live successors (observed 5/5 trials). Suite: `test_key_lifecycle.py::test_concurrent_rotate_fans_out_many_live_successors`.
- **Fix:** Serialize rotate per key id (mutex or compare-and-swap on a generation / `Replaces` pointer); refuse rotate of an already-superseded id with 409.

### F4 — MEDIUM — BREAK — global pairing fail budget is a lockout DoS
- **Where:** `host/pairing.go:22-26, 148-161` (`pairFailTotal = 40` counted across all source IPs).
- **What:** Unauthenticated `POST /v1/pair/exchange` with junk codes. Once 40 failures land in the one-minute window (e.g. 5 source IPs × 8, the per-IP cap), every subsequent redeem — including a legitimate one with a still-valid unused code from a clean IP — returns `429` for the rest of the window.
- **Repro:** Issue a real code via `POST /v1/keys/pairing`; burn 40 junk codes from several loopback-family source addresses; redeem the real code from `127.0.0.1` → 429. Suite: `test_key_lifecycle.py::test_global_pair_fail_budget_lets_one_ip_lock_out_everyone`.
- **Fix:** Drop the global `pairFailTotal` (keep per-IP), or make the global budget apply only to distinct unknown codes / require a proof-of-work, and never refuse a currently-pending valid code because of unrelated failures.

### F1 — LOW — BREAK — failed-auth throttle overshoots under concurrency
- **Where:** `host/auth.go:202-230` (`failTracker.blocked` then later `record`; not atomic with Verify).
- **What:** Documented 20 failures/min/IP. Under 32 concurrent wrong-key requests the host evaluates ~30–45 argon2 verifies before 429s dominate. Bounded (~2×), so not a free DoS, but the published cap is soft.
- **Repro:** `test_dos.py::test_failed_auth_throttle_overshoots_under_concurrency`.
- **Fix:** Make check-and-increment atomic (or pre-reserve a slot before Verify).

### INFO (not a BREAK)
- No `ReadTimeout` / body-read deadline on the HTTP server (`host/daemon.go:32` sets only `ReadHeaderTimeout` and `IdleTimeout`). 28k half-written bodies left /healthz answering and RSS ~540 MB; recorded for a later hardening pass. Suite: `test_dos.py::test_slow_body_connections_do_not_block_health`.

## What held up (PASS, no finding)

- Auth failure oracle: missing / malformed / wrong / revoked / expired / fake session → identical 401 body.
- `?access_token=` ignored unless the request is a WebSocket upgrade.
- X-Forwarded-For / X-Real-IP ignored unless the peer is in `trusted_proxies`.
- Web bootstrap: closed after first key; refuses DNS-rebinding Host, cross-site Origin, Sec-Fetch-Site, forwarding headers; race issues exactly one key.
- Scope / db / prefix ACL; prefix keys blocked from `/v1/query` and `/v1/bx`; db-admin cannot mint host-admin or cross-db keys; key IDOR returns 404.
- Dangerous-ops order 401 → 403 → 428.
- BoxQL `$params` never parsed as command text; JSON PUT escapes embedded Box delimiters; read key cannot sneak writes via Set/Tx/Add/Delete (incl. `explain:true`).
- Conditional `{Require}+{Set}` debit under 32-way load: exactly 100 of 250 succeed, balance reconciles, never negative.
- SIGKILL mid-load: every ACK'd write present after restart for both `sync` and `group`; committed Tx all-or-nothing; torn WAL tail recovered; second daemon on same data dir refused; revoked key stays revoked across crash.

## Rerun

```sh
cd /workspace/repos/RedX-e2e          # or: git -C /workspace/repos/RedX worktree add -b e2e-tests …
make build
python3 -m pytest -q tests/e2e/
# single finding:
python3 -m pytest -q tests/e2e/test_key_lifecycle.py -k rotate
```

Requires Go 1.22+ (box has 1.27) and Python 3; no root, no Docker, no network beyond loopback.


## Handoff (2026-10-20 01:11 America/New_York)

F1–F4 were fixed on branch `host-sec-fixes` at commit `db91b86` in `/workspace/redx-sec-fixes` (not pushed). Claims: absolute expiry on rotate, atomic rotate with 409 on conflict, pairing 8/min/IP + 5/min/code + 5000/min global, failed-auth reserve-before-verify.

**Retest of the fixed binary: NOT DONE.** Team moved; Host E2E ownership handed off. The four repros in `test_key_lifecycle.py` / `test_dos.py` still assert the *pre-fix* buggy behaviour and will fail against `db91b86` until flipped into regressions. Next owner should point `REDXD` at that binary, flip those asserts, and add the bypass probes (successor-of-successor, multi-IP F4, 10k map cap, reserve leak).
