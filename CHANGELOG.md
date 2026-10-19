# Changelog

## Unreleased

* Console: the sidebar and the router follow `pages` from `GET /v1/ui/whoami`. A page the server would refuse is not shown, and its address is Page not found. Hosting (`#/hosting`) is there for every signed-in session. Updates (`#/updates`) is there for host admins and owners. The owner audit log on the Owner page filters and pages through `GET /v1/owner/audit`. Hosting shows this account's own database activity (`GET /v1/hosting/activity`).
* Updates: source `both` accepts a Host or GitHub manifest. Sequence stays one counter for the app across both sources, and the signature rules are unchanged. Choosing the source is still owner-only while Accounts is on.
* An owner email that is signed in but not verified (or missing 2FA or the owner scope) is told, on that session only: "Owner access needs a verified email and 2FA. Verify your email, then sign in again."
* Hosted tenants: an API key minted for an account follows the plan gate. After the plan is read-only or suspended, that key gets the same `402` as the console session, and quota checks still apply. Host-admin keys and owner sessions are unchanged.
* Hosted tenants: a signed-in non-owner with an active or trialing RedX Hosted plan creates and uses only its own databases and API keys. Names are namespaced. Quotas (traffic, on-disk storage, host switches) are enforced. A lapsed plan becomes read-only for 3 days after period end, then suspended; databases are kept. See [billing](docs/billing.md) and [API](docs/api.md).
* `trusted_proxies` / `REDX_TRUSTED_PROXIES`: when the direct peer is listed, client IP for rate limits and audit comes from `X-Forwarded-For` (rightmost untrusted hop) or `X-Real-IP`. Other peers cannot spoof it.
* `redx backup --offline` takes a consistent snapshot while redxd is running (no API key). The archive includes databases, key hashes, `tenants.json` and the update signing key. See [backup](docs/backup.md).
* Dangerous routes return 401 or 403 before `428 confirm_required`.

## 0.4.5 (2026-10-19)

* Cluster: installing a full snapshot now swaps the databases directory atomically. A read racing the install could reopen the pre-snapshot databases and keep serving them, so a write discarded by the resync stayed readable (seen on Windows CI). Reads also wait while a snapshot is being swapped in.
* C# and Swift SDKs: a stream reconnecting while the host restarts no longer gives up. A dial that failed while the host was starting, followed by a probe that reached the restarted host, was misread as a refusal (400) and ended the stream.
* Tests: deterministic regressions for both, and for subscriptions armed before the WebSocket handshake.
* `GET /v1/dbs` (SDK `listDatabases`) works with database-scoped keys: a key lists only the databases in its scope, never the master accounts database (`redxai_accounts`); host-admin keys still see every database. It used to answer 403 for every key except host admin.
* Windows: the `.exe` version resources (Properties > Details) are generated at build time from the release version and say "Copyright (c) 2026 Red-XAI LLC". 0.4.4's executables still said 0.4.3.0 and "RedX" (stale committed `.syso` files, which are no longer committed).
* Every release asset ships the LICENSE: each archive, the Windows install folder (`LICENSE.txt`), `RedX.app/Contents/Resources/LICENSE` (and the .dmg), `/usr/local/share/doc/redx/LICENSE` from the .pkg, and `/usr/share/doc/redx/copyright` in the .debs.
* **Breaking (raw HTTP admin clients):** every operation whose danger level is `dangerous` is refused by the **server** with HTTP 428 and `code: "confirm_required"` unless the request carries `X-RedX-Confirm: <operation-id>` (or `?confirm=<operation-id>`). `deleteDatabase`'s existing `?confirm=<db>` still works on its own. All SDKs, the CLI and the web console send the header after their existing prompts. The previous "client-side only" caveat is gone.
* RedX Hosted billing: annual plans at 10× monthly (2 months free) alongside monthly; checkout takes `interval`; webhooks record month/year; per-tier quotas (traffic, storage, host on↔off switches) enforced for signed-in Hosted accounts; usage on `/v1/billing/me` and owner account view. See [billing.md](docs/billing.md).
* Red-XAI Accounts: the web console can sign in and sign up with a Red-XAI Account (OIDC, PKCE S256, ES256 ID tokens; `accounts_issuer`). API keys keep working for SDKs and machines. See [accounts.md](docs/accounts.md).
* Sign-up in the console follows the Red-XAI Accounts rules: ToS gate (scroll to the bottom, Read ToS, Agree to ToS), live red/green hints, email and password entered twice with a copy arrow, date of birth typed or picked (age derived, never stored; under 13 refused), the false-information warning, and 2FA Phone / App / Red-XAI Auth (coming soon) / None (with a warning). redxd re-checks every field.
* Owner role: owner logins come only from deploy config (`owner_emails` / `REDXAI_OWNER_EMAILS`) and need a verified email, a sign-in finished with 2FA (`amr` has `otp` or `sms`), and the `owner` OIDC scope granted on the token (Accounts silently drops it when ineligible). Owners see every hosted database, the master Red-XAI accounts database and every account (Owner page, `/v1/owner/*`); kick/ban/terminate forward to Accounts with the owner's access token; every owner request is audit-logged. Everyone else, including host-wide admin keys, cannot see the master database; online backups and cluster join tokens are owner-only while accounts are on.
* Security: the master accounts DB is hidden on every Authenticate path (`authz` and `authzScope`: BX, subscribe, pulse, media, code), not only HTTP path GET/PUT. Dropping it and cluster leader repoint/promote are owner-only while Accounts is on. Owner-email compare is ASCII-only (Kelvin U+212A and other lookalikes never match).
* Security (H3b): while Accounts is on, applying a preset that sets `join` or changes `role` or `advertise` is owner-only (same gate as cluster repoint/promote). A host-admin key cannot persist a join link for the next start to redeem. The `preset.apply` audit detail includes the join leader URL and never the join secret or token.
* RedX is a confidential Red-XAI Accounts client (secret from `REDX_ACCOUNTS_CLIENT_SECRET` / file only; never committed). Forwards `X-RedXAI-Client-IP` on sign-up/sign-in. Polls `/v1/apps/events` to end console sessions of banned/terminated accounts. Sign-up SMS resend via `POST /v1/signup/resend-sms`. Age from `minAge` (contract v1.1).

## 0.4.4

* The LICENSE copyright holder is now Red-XAI LLC; the Windows installer's LegalCopyright says the same.
* Connect: added the `quicklaunch` provider (QuickLaunch developer tool) and a strict loopback callback rule: `http://127.0.0.1`, `http://[::1]` or `http://localhost` on any port with exactly the registered path; everything else is refused.
* The console Help page has an About card with the ownership notice, also in the README.
* Subscriptions (`/v1/subscribe`) are armed before the WebSocket handshake completes, so a write made right after `subscribe()` returns is always delivered.
* macOS installers: every Mach-O is signed explicitly, inside out, including `Contents/Resources/bin/redx` and the `.pkg`'s `/usr/local/bin` binaries (`codesign --deep` did not reach them). Optional `MACOS_SIGN_IDENTITY` (hardened runtime) / `MACOS_INSTALLER_IDENTITY` (`productbuild --sign`); installers stay unsigned (ad-hoc) by default.
* Release builds refuse a dirty git tree (`REDX_ALLOW_DIRTY=1` overrides and stamps `-dirty`).
* Removed a stray development binary from the repository root; root build outputs are ignored.
* One API description, `api/redx-api.json`, generates `api/openapi.json` and the SDKs (`go run ./scripts/gensdk`; CI checks for drift). Every operation has a danger level (`safe`, `write`, `admin`, `dangerous`); `dangerous` calls need `confirm`. See [SDKs](docs/sdks.md).
* New SDKs: Go (`sdk/go/redx`), a C ABI shared library with headers (`sdk/go/cabi`), Swift (`sdk/swift`) and C# / .NET (`sdk/csharp`). JavaScript gains TypeScript types; JavaScript and Python gain every host and database operation, transactions, files/packs/media, streams that reconnect, and connect helpers (PKCE).
* Game engine recipes for Unity, Godot and Unreal: [game-engines.md](docs/game-engines.md) (not tested in the engines).
* JS/Python: `createKey` and `revokeKey` without `confirm` still work but warn once. `RedXError` has `code`.
* CI runs the Go and C# SDK tests on Linux, Windows and macOS, the C ABI on Linux and macOS, and Swift on macOS.

## 0.4.3

* Security: `redx` and `redxd` help output (`-h`) no longer prints secrets taken from the environment or `redx.toml` as flag defaults. `--key` shows "(currently set from $REDX_KEY)" and `--join` "(currently set from $REDX_JOIN or redx.toml)".
* Clustering: a promoted node now fences the old leader. When the old leader is reachable it stops accepting writes (`503`, `FENCED` in `redx node status`) until it is repointed; the fence survives restarts. See [Clustering](docs/clustering.md#failover-promote-fencing-and-repoint).
* `redx node repoint` and `redx node join --local` accept `--leader-pin` (alias `--fingerprint`) or a join link, so a node can follow a new leader that uses a self-signed certificate. A fenced old leader reuses the fingerprint it learned from the fence.
* `redx doctor` checks the TLS certificate also before the data directory exists, accepts `--tls` / `--tls-cert`, and reports the certificate the running daemon serves.
* Fixed races where a snapshot install or replication pull still in flight during `promote` could overwrite the promoted node's new replication id, or apply one more entry of the old leader.
* The macOS app's executable is the launcher again (the `redx` CLI moved to `RedX.app/Contents/Resources/bin`), and the `.pkg` always installs into `/Applications`.
* `scripts/smoke.sh` runs on macOS (portable `stat`), and its Content-Range checks assert the full size; CI runs it on macOS too.
* `redx doctor --tls-key`; a certificate given alone as a flag no longer fails the config check.
* `redx-launcher` handles `--version` and `-h` (and refuses unknown arguments) without starting the host, and carries the release version.
* `redx node status` no longer shows a stale "last error" after a successful promote.
* Added the app connect handshake (`/v1/connect/*`): an app asks for its own workspace, the owner approves on a consent page in the console, and the app exchanges a one-time code plus its PKCE verifier for a key limited to that workspace. Apps can revoke their own key, and the console lists them under *Connected apps*. See [Connecting apps](docs/connect.md).

## 0.4.2

* Configuration precedence is now flags > environment > `redx.toml` > preset > defaults everywhere, and `<data dir>/redx.toml` is read when the data directory is given as a flag. Invalid `listen` / `advertise` values are refused before they are written.
* An expired, not yet valid or soon-to-expire TLS certificate is reported at startup, in the admin status, in the console and by `redx doctor`.
* The console's pages are tested in a headless browser in both themes.

## 0.4.1

* `redx doctor` checks the running daemon's data directory.
* BoxQL `Get` refreshes sliding TTLs like REST reads; BoxQL on an unknown file returns a clear message.
* Non-numeric or negative `ttl` values return a clear 400.
* `redx key list --json` includes rate limits; `redx key rotate --json` prints JSON.
* Failed BoxQL arithmetic in a write leaves the stored value unchanged.

## 0.4.0

* Added the web console served by `redxd` on its own port: dashboard, data browser, BoxQL editor, keys, devices, cluster, settings, help, light and dark themes, installable as an app (PWA).
* First admin key from the console for a visitor on the same machine (`bootstrap` setting).
* Added presets (`--preset`, `redx preset`) and sign-in and join pairing codes with QR codes; `redxd join` adds a node from a link.
* Desktop installers: Windows setup, macOS `.dmg` / `.pkg`, Debian `.deb` (unsigned), and a launcher that starts the host and opens the console.

## 0.3.0

* Added **BoxQL**, the RedX query and command language, written in the Box grammar: `Get`, `Add`, `Set`, `Delete`, `Require`, `Tx`, `Explain` and `Watch`, with `$name` parameters. Served at `POST /v1/bx` and `/v1/db/{db}/bx`, with a WebSocket watch at `bx/watch`. Available as `redx bx` and as `bx()` and `watch()` in the JavaScript and Python SDKs.
* Replaced the query front-end used in 0.2.0. The 0.2.0 query routes, CLI command and SDK method were removed; use `/v1/bx`, `redx bx` and `bx()`.
* Writing commands and transactions are all-or-nothing: before-images are restored on failure, including indexes.
* Fixed a bug where a write forwarded from a follower lost its request body and failed with 502.
* Added `redx bx` parameters (`--param`, `--sparam`) and `--explain`.

## 0.2.0

* Wired media libraries (`.red-xai-media`) with HTTP `Range` support into the host.
* Added access policy (`.red-xai-sec`) built from API-key grants and roles, enforced in the engines and again at the host.
* Added sandboxed scripts (`.red-xai-code`) with a host-level `code_allowed_boxes` allow-list.
* Added pack encryption (AES-256-GCM) with a master key file and `redxd keygen`.
* Standalone link files (`.red-xai-db-link`) and `.red-xai*` files are loaded from the data directory.
* `GET /v1/path/...` of an absent or expired path now always returns 404.
* `GET /v1/subscribe` with a bare file name or no path now returns 400 instead of closing silently.

## 0.1.x

* Initial host: REST and WebSocket API, API keys, TLS, leader/follower replication, backup and restore, service installers, search indexes, file packs, link resolution and pulse rules.
