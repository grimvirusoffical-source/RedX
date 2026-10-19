# Changelog

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
