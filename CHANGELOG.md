# Changelog

## Unreleased (0.4.4)

* Subscriptions (`/v1/subscribe`) are armed before the WebSocket handshake completes, so a write made right after `subscribe()` returns is always delivered.
* macOS installers: every Mach-O is signed explicitly, inside out, including `Contents/Resources/bin/redx` and the `.pkg`'s `/usr/local/bin` binaries (`codesign --deep` did not reach them). Optional `MACOS_SIGN_IDENTITY` / `MACOS_INSTALLER_IDENTITY`; installers stay unsigned (ad-hoc) by default.
* Release builds refuse a dirty git tree (`REDX_ALLOW_DIRTY=1` overrides and stamps `-dirty`).
* Removed a stray development binary from the repository root; root build outputs are ignored.

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
