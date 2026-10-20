# RedX host/DB end-to-end findings (updated 2026-10-20 06:35 America/New_York)

Target binary: `host-integration@ed8051d` (clean; the OIDC IdP is built separately from
`tests/e2e/harness/e2e-oidc-idp.patch`) built into `/workspace/redx-e2e-bin/redxd`
(`v0.4.5-29-ged8051d-dirty`). Worktree: `/workspace/repos/RedX-e2e` branch `e2e-tests`.
Nothing pushed.

## Architecture (short)

`redxd` serves REST+WS+console; argon2id API keys; WAL engines; optional Accounts
(OIDC ES256 + PKCE), TLS auto/files, packs/idx, installers.

## Areas this pass

| Area | Result |
|---|---|
| 1. Accounts/OIDC + app-connect PKCE | **PASS** 11 + 4 |
| 2. TLS / pinning | **PASS** 6 |
| 3. packs / media / idx | **PASS** 9 |
| 4. Installers / systemd (disposable containers) | **PASS** user + root + systemd |
| Stripe / cluster / remote hosts | **SKIPPED** (out of scope) |

### Area 1 — Accounts/OIDC (real external IdP, not mocked)

IdP: `e2e-oidc-idp` (Accounts-contract ES256). Dex unsuitable (RS256 only; host
requires ES256 — `host/accounts_oidc.go`).

Covered: code-verifier mismatch at token endpoint; redirect_uri allow-list;
state/handoff replay; aud/iss confusion; session handoff single-use; email
collision without owner_scope; owner without 2FA AMR; unverified email owner block;
happy owner sign-in. App-connect: PKCE mismatch, state mismatch, exchange replay,
plain method rejected.

### Area 2 — TLS / pinning

tls=auto HTTPS; pin mismatch detection; plaintext to TLS port fails; wrong-CN
cert fails hostname verify; expired leaf refused by verifying client; TLS
handshake against plaintext listener fails (no downgrade).

### Area 3 — packs / media / idx

Round-trip PUT/GET; SHA-256 mismatch → 422 and nothing stored; path traversal
rejected; malformed pack name; prefix ACL 403; oversize (`max_upload_mb=1`)
rejected; idx define/query/rebuild; corrupt `.red-xai-db-idx` → host stays up,
redefine restores; pack survives SIGKILL.

### Area 4 — Installers (containers only)

- `--user`: `~/.redx/data` mode 700, idempotent reinstall keeps config/keystore
- root `--no-service`: `redx` user, `/var/lib/redx` 700, no world-readable secrets,
  second process on same data dir fails, idempotent reinstall
- systemd (`jrei/systemd-ubuntu:24.04`, systemd as PID 1): unit enabled, User=redx,
  healthz OK, data 700

## Findings

| ID | Sev | Label | Status |
|---|---|---|---|
| F1–F4 | — | — | **FIXED** (prior pass; regressions still green on host-sec-fixes) |
| (new) | — | — | **None** this pass — all probes refused/held |

No new BREAK. Harness-only notes: IdP is Accounts-contract stand-in (ES256), not
production Dex/Keycloak (those lack ES256 without custom keys).

## NOT RUN

| Item | Reason |
|---|---|
| Stripe / billing | Out of scope this pass |
| Cluster / leader-follower | Out of scope |
| Remote / Kamatera hosts | Forbidden |
| Production Dex/Keycloak ES256 | Would need custom signing keys; contract IdP used instead |
| TLS downgrade via ALPN/protocol negotiation | Covered plaintext↔TLS; no intentional weak-cipher matrix |
| Pack MaxFileSize 64GiB engine limit | Exercised HTTP `max_upload_mb` cap instead |

## Rerun

```sh
cd /workspace/redx-integration && make build
cp -f bin/redxd bin/redx /workspace/redx-e2e-bin/
/workspace/repos/RedX-e2e/tests/e2e/harness/build-idp.sh   # patch applied in a temp worktree

cd /workspace/repos/RedX-e2e
export REDXD=/workspace/redx-e2e-bin/redxd
export E2E_OIDC_IDP=/workspace/redx-e2e-bin/e2e-oidc-idp

python3 -m pytest -q tests/e2e/test_accounts_oidc.py tests/e2e/test_connect_pkce.py
python3 -m pytest -q tests/e2e/test_tls_pin.py
python3 -m pytest -q tests/e2e/test_packs_media_idx.py
bash tests/e2e/test_install_container.sh

# Full prior suite
python3 -m pytest -q tests/e2e/
```
