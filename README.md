# RedX

RedX is a database platform with its own file formats and its own query language. It consists of:

* **`redxd`**, a cross-platform host (Windows, macOS, Linux, Raspberry Pi) that serves databases over a REST and WebSocket API, manages API keys, and can run as a leader/follower cluster.
* **Storage engines** for the Box file types: durable, volatile quick-storage and hot persistent tables, search indexes, file packs, media libraries, links, rules, access policies and sandboxed scripts.
* **BoxQL**, a query and command language written in the same grammar as the data files.
* **`redx`**, a command-line client, and **SDKs** for JavaScript and Python.

The current version is 0.3.0.

## Features

* Single static binaries with no runtime dependencies (Go, CGO disabled).
* Write-ahead log with checkpoints, configurable durability (`sync`, `group`, `async`) and crash recovery.
* TTL expiry (fixed and sliding) driven by a timing wheel.
* API keys with scopes (`read`, `write`, `admin`), per-database binding, path-prefix restrictions, expiry, rotation, rate limits and an audit log. Keys are stored as argon2id hashes.
* Optional TLS with self-signed certificates and fingerprint pinning, or your own certificates.
* Asynchronous leader/follower replication with offset resume and snapshot fallback.
* Online and offline backup and restore.
* Access policy documents, pack encryption (AES-256-GCM) and sandboxed scripts.
* Installers for systemd, launchd and Windows services, plus a Dockerfile.

## Install

Download the archive for your platform from the [releases page](https://github.com/grimvirusoffical-source/RedX/releases), verify it against `SHA256SUMS`, and follow [Hosting](docs/hosting.md#installation). To build from source you need Go 1.22 or newer:

```sh
go build ./...
VERSION=0.3.0 scripts/build.sh      # all platforms, archives in dist/
```

## Quick start

Start a host in the foreground. On first start it prints a one-time admin key; copy it.

```sh
./redxd run --data-dir ./data
```

In a second terminal:

```sh
export REDX_KEY=rx_live_...         # the admin key printed on first start
./redx doctor
./redx set 'players.red-xai.db:Player[ID=1].Name' '"Ann"'
./redx bx '{Get[]} = players:Player[ID=*] -> Name'
```

See [Getting started](docs/getting-started.md) for the full walk-through.

## BoxQL example

```boxql
{Get[]} = players:Player[Role = "Admin", WalletBalance > 1000] -> [Username, WalletBalance] @> Guild, Sort = -WalletBalance, Limit = 50
{Set[]} = players:Player[ID=1].Inventory[id=10].Qty = 5
{Tx[]} = [ {Require[]} = players:Player[ID=7, Gold >= 5], {Set[]} = players:Player[ID=7].Gold = Gold - 5 ]
```

Values are passed as `$name` parameters and are never parsed as command text. The full language is documented in [BoxQL](docs/boxql.md).

## Documentation

| Document | Contents |
|---|---|
| [Getting started](docs/getting-started.md) | install, first key, first query |
| [BoxQL](docs/boxql.md) | query and command language reference |
| [Box grammar](docs/box-grammar.md) | file grammar and paths |
| [Hosting](docs/hosting.md) | platforms, services, Docker, troubleshooting, building |
| [Configuration](docs/configuration.md) | `redx.toml`, environment variables, defaults |
| [API reference](docs/api.md) | REST and WebSocket routes |
| [Security](docs/security.md) | keys, TLS, policy, encryption |
| [Clustering and replication](docs/clustering.md) | adding nodes, consistency model, failover |
| [Backup and restore](docs/backup.md) | online and offline backups |
| [Storage engines](docs/engines.md) | on-disk formats, TTL, recovery |
| [Indexes and packs](docs/indexes-and-packs.md), [Links and rules](docs/links-and-rules.md), [Media](docs/media.md), [Policy and encryption](docs/policy-and-encryption.md), [Scripts](docs/scripts.md) | feature references |
| [Query engine](docs/query-engine.md), [SDKs](docs/sdks.md) | embedding and client libraries |
| [Benchmarks](docs/benchmarks.md) | engine measurements |
| [Changelog](CHANGELOG.md), [Contributing](CONTRIBUTING.md), [Security policy](SECURITY.md) | project information |

## Status

| Component | Linux amd64 | Linux arm64 / armv7 | macOS | Windows |
|---|---|---|---|---|
| Unit and integration tests (`go test -race`) | passing | not run | not run | not run |
| Smoke test of the built binaries | passing | not run | not run | not run |
| Service installer | not run | not run | not run | not run |
| Binary signed | no | no | no | no |

Release binaries for every platform are cross-compiled from Linux. Only the Linux amd64 binaries have been executed. Reports from other platforms are welcome.

## Known limitations

* Replication is asynchronous. A write acknowledged by the leader can be lost if the leader fails before followers receive it.
* Failover is manual (`redx node promote`). There is no automatic election, quorum write or multi-leader mode, and a partitioned old leader can keep accepting writes until it is stopped.
* Index, pack and media contents are not replicated; their definitions are.
* Pulse rule timers are held in memory and are lost on restart or failover.
* Database files are not encrypted by RedX; use disk encryption. Pack encryption is available through policy rules.
* Binaries are unsigned. macOS Gatekeeper and Windows SmartScreen will show a warning on first run.
* The Windows, macOS, ARM and Docker paths, and the service installers, have not been run on those platforms.
* gRPC is not implemented. `grpc_listen` is accepted and ignored.
* Sharding and multi-key transactions across nodes are not implemented.
* Per-feature limitations are listed in each feature document, and BoxQL limitations in [BoxQL section 17](docs/boxql.md#17-known-limitations).

## License

All rights reserved. See [LICENSE](LICENSE).
