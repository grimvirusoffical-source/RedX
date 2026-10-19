# Hosting RedX

`redxd` is the RedX host. It owns the databases (the `.red-xai*` files), the API key store, the REST and WebSocket API and, optionally, the cluster. An API key only works against a running `redxd`, so install and start a host first.

Supported platforms: Windows 10/11 and Server (amd64, arm64), macOS (Intel and Apple silicon), Linux (amd64, arm64, armv7) including Raspberry Pi OS. See the [status matrix](../README.md#status) for what has been tested on each.

Related documents: [Getting started](getting-started.md) · [Configuration](configuration.md) · [Security](security.md) · [Clustering and replication](clustering.md) · [Backup and restore](backup.md)

## Components

| Area | Description |
|---|---|
| REST API | `GET/PUT/DELETE /v1/path/...`, `POST /v1/query`, `/v1/stats`, `/healthz`, multiple databases (`/v1/db/{name}/...`) |
| WebSocket | `/v1/subscribe?path=` change events |
| API keys | argon2id salted hashes, shown once, scopes (read/write/admin), per-database, path-prefix ACL, expiry, revoke, rotate with grace period, per-key rate limit, audit log, optional encryption at rest, brute-force throttle |
| Web console | built-in management UI on the same port (`/`), see [the console guide](console.md) |
| First run | the console offers *Create admin key* to a visitor on this machine, or the key is printed once on first start (`bootstrap` setting) |
| Presets | ten settings profiles (`--preset`, `redx preset`, console *Presets*) |
| App connect | apps get their own workspace and a scoped key after the owner approves, see [Connecting apps](connect.md) |
| TLS | off, automatic self-signed (fingerprint pinning), or your own certificate files |
| Cluster | node identity, join tokens and pairing codes, leader/follower, asynchronous replication with replication id and offset resume, full-snapshot fallback, leader-forwarded writes, heartbeat and membership, manual promote with fencing of the old leader, repoint |
| TTL expiry | leader-driven; followers never expire entries themselves |
| Backup and restore | online snapshot, offline copy |
| Service install | `redxd install/uninstall/start/stop` (Windows service, systemd, launchd), unit files, `install.sh`, `install.ps1`, Dockerfile, three-node compose file |
| Search indexes | `.red-xai-db-idx`: define, drop, rebuild, check; exact, prefix, range and text queries |
| File packs | `.red-xai-pack`: streamed upload and download, HTTP `Range`, listing, SHA-256 verification |
| Links, rules | link resolution on reads; pulse rules (`.red-xai-db-pulse`) with events over WebSocket |
| BoxQL and services | BoxQL (`POST /v1/bx`, WebSocket watch), media libraries (`.red-xai-media`), access policy (`.red-xai-sec`), scripts (`.red-xai-code`), pack encryption with a master key file |
| gRPC | not implemented; `grpc_listen` is accepted and ignored |
| Automatic failover, election, quorum writes | not implemented; failover is manual (`redx node promote`) |
| Sharding, cross-node multi-key transactions | not implemented |
| Binary signing and notarization | not done; see [Known limitations](../README.md#known-limitations) |

## Installation

Download the archive for your platform from the [releases page](https://github.com/grimvirusoffical-source/RedX/releases), or build from source (any machine with Go 1.22 or newer): `scripts/build.sh` (or `make dist`) writes `dist/redx-<ver>-<os>-<arch>/` and the matching archives.
Targets: linux amd64 / arm64 / armv7, darwin amd64 / arm64, windows amd64 / arm64. Verify a download with `sha256sum -c SHA256SUMS`.

Desktop installers (Windows setup `.exe`, macOS `.dmg` / `.pkg`, Debian `.deb`) start the host and open the console with one click; they are **unsigned**. See [Installers](installers.md).

### Linux (systemd), including Raspberry Pi OS (arm64 / armv7)
```sh
tar xzf redx-<ver>-linux-<amd64|arm64|armv7>.tar.gz && cd redx-<ver>-linux-*
sudo ./install.sh --from .                 # installs to /usr/local/bin, creates user "redx", data in /var/lib/redx
# prints the first admin API key once; copy it now
export REDX_KEY=rx_live_...                # keep keys out of shell history: use a password manager / `read -s REDX_KEY`
redx doctor
curl -s http://127.0.0.1:7777/healthz
```
No root? `./install.sh --from . --user` installs to `~/.local/bin`, data in `~/.redx`, no service;
start it with `~/.local/bin/redxd run --config ~/.redx/redx.toml`.
Quick foreground try-out without installing: `./redxd run --data-dir ./data` (the first-run admin key is printed on the console).

### macOS (Intel and Apple silicon)
```sh
tar xzf redx-<ver>-darwin-<amd64|arm64>.tar.gz && cd redx-<ver>-darwin-*
xattr -d com.apple.quarantine redxd redx 2>/dev/null   # binaries are unsigned; needed if they came via browser/AirDrop
sudo ./install.sh --from .                # /usr/local/bin, data /usr/local/var/redx, launchd daemon com.redx.redxd (runs as root)
export REDX_KEY=rx_live_...               # the key printed by the installer
redx doctor
```
Without installing: `./redxd run --data-dir ./data`.

### Windows 10/11, Server (amd64 or arm64) — elevated PowerShell
```powershell
Expand-Archive redx-<ver>-windows-amd64.zip .; cd redx-<ver>-windows-amd64
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1 -From .                     # C:\Program Files\RedX, data C:\ProgramData\RedX\data, Windows service "redxd"
# prints the first admin API key once
$env:REDX_KEY = "rx_live_..."             # in a NEW terminal (PATH was updated)
redx doctor
```
SmartScreen or Defender may warn because the binaries are unsigned. Choose "More info", then "Run anyway", or build the binaries yourself.
Without installing: `.\redxd.exe run --data-dir .\data`. Manual service control: `redxd.exe install|start|stop|uninstall`
(fallback: `deploy\windows\sc-install.ps1`).

### Docker (not yet tested)
```sh
cd deploy/docker && cp env.example .env     # set REDX_CLUSTER_SECRET
docker compose up --build -d                 # 3 nodes: 127.0.0.1:7777 (leader), :7778, :7779 (followers)
docker compose logs node1 | grep -A8 "FIRST RUN"   # the one-time admin key
```

The first admin key and application keys are described in [Getting started](getting-started.md#create-an-application-key).

## Troubleshooting

`redx doctor [--config FILE] [--data-dir DIR]` checks: platform, config validity (the `redx.toml` in the data dir, or `--config`), data dir writability and free space,
keystore permissions/readability, TLS certificate validity, whether the daemon answers, whether your key works, cluster health, and "non-loopback listen without TLS".
The certificate is checked whenever the configuration names one, also before the data dir exists; if you pass the certificate to `redxd` as flags,
repeat them for doctor (`redx doctor --tls files --tls-cert FILE`), and with `--key` doctor also reports the certificate the running daemon serves.
A certificate that has expired, is not valid yet or expires within 14 days is reported as `warn` or `FAIL`; the host still starts and logs a `WARNING:` line.
Secrets are never printed: `-h` shows `--key` as "(currently set from $REDX_KEY)", never its value, and the same holds for join links and other secrets. Common issues:
* `data dir … is in use by another redxd process` — a second instance (or a stale service) holds `redxd.lock`.
* Follower log shows `leader answered 401` — wrong token/secret, or the node id given to `redx node join --node-id` differs from the daemon's (the CLI writes `node.id` for you; don't override `node_id` in the config afterwards).
* `429` while testing wrong keys — you tripped the per-IP failed-auth throttle; wait a minute.
* Termux/Android: Go binaries built for linux cannot read Android's DNS config; use **IP addresses** for `peers`/`advertise`, run with `./install.sh --user`, and keep the app awake (Android may kill background processes). Not tested.

## Building and releases

```sh
go vet ./... && go test -race -count=1 ./...        # whole module
scripts/build.sh                # all 7 targets -> dist/ (tar.gz, zip for Windows, SHA256SUMS); VERSION=1.2.3 scripts/build.sh
scripts/build.sh --only linux/amd64      # one target;   --tags redx_stub  builds the in-memory stub store (not for production)
scripts/smoke.sh bin            # curl-based smoke test of a native build (console, security headers, keys, set/get, idx, pack+range, BoxQL, media range, sec, encrypted pack, code, 404, subscribe); scripts/cluster-smoke.sh bin  for 3 local nodes plus a self-signed TLS promote and repoint
```
`deploy/release.yml.example` is an example GitHub Actions workflow. It is kept outside `.github/` so that it does not run automatically; copy it to `.github/workflows/release.yml` to enable tagged releases.
The `Makefile` wraps the same commands (`make dist`, `make test`). Installers: `scripts/package.sh deb|windows VERSION` (needs NSIS for Windows); the macOS `.dmg`/`.pkg` are built on macOS by `.github/workflows/release-build.yml`, which also runs `scripts/verify-windows.ps1` and `scripts/verify-macos.sh`.
`.github/workflows/ci.yml` builds and tests on Linux, Windows and macOS (Apple silicon and Intel) for every pull request.
