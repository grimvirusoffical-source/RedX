# API reference

All routes require an API key in the `Authorization: Bearer` header unless noted. See [Getting started](getting-started.md#3-keys) for creating keys and [Security](security.md) for the access model.

## REST API basics

```sh
KEY=$REDX_KEY; H="Authorization: Bearer $KEY"; U=http://127.0.0.1:7777
# paths look like  file.red-xai.db:Box[ID=1].Key   (escape [ ] as %5B %5D if your client needs it)
curl -X PUT    -H "$H" --data '"Ann"' "$U/v1/path/players.red-xai.db:Box%5BID=1%5D.Name"      # raw Box text
curl           -H "$H" "$U/v1/path/players.red-xai.db:Box%5BID=1%5D.Name"                      # {"path":…,"value":"\"Ann\""}
curl -H "$H" -H 'Accept: text/x-redx-box' "$U/v1/path/…"                                       # raw Box text back
curl -X PUT -H "$H" -H 'Content-Type: application/json' --data '{"value":{"hp":10,"tags":["a"]}}' "$U/v1/path/…"   # JSON -> Box (best effort)
curl -X PUT -H "$H" --data '"1234"' "$U/v1/path/sessions.red-xai-db-qs:Q.Otp?ttl=30"           # TTL (needed for -qs files); &sliding=true
curl -X PUT -H "$H" --data '12'      "$U/v1/path/world.red-xai-db-qs-ls:Hot.Counter?checkpoint=5"   # (5)* marker
curl -X DELETE -H "$H" "$U/v1/path/…"
curl -X POST -H "$H" -H 'Content-Type: application/json' --data '{"q":"accounts.red-xai.db:AccountVault[ID=*].Name"}' "$U/v1/query"
curl -H "$H" "$U/v1/stats"
curl -X POST -H "$H" --data '{"name":"game"}' "$U/v1/dbs"      # new database; then use /v1/db/game/path/… , /v1/db/game/query …
```
`redx get|set|delete|query|stats|subscribe` do the same from the CLI (`redx set PATH VALUE --ttl 30`).
WebSocket: `GET /v1/subscribe?path=<prefix>` with the same `Authorization` header (browsers, which cannot set headers, may use `?access_token=`
— URLs get logged by proxies, prefer the header). Events: `{"path","op":"set|delete|expire","value","at"}`.

Errors: `401` bad/missing/revoked/expired key (deliberately identical), `403` key lacks scope/db/prefix, `404`, `400` (bad path, bad Box text, engine validation),
`429` rate limit (`Retry-After`) or too many failed auths from your IP (20/min), `503` follower with no leader.

Dangerous operations (create/revoke/rotate a key, drop a database, pairing, policy replace, cluster join-token/promote/repoint, connect approve/revoke, update apply/promote/rollback/publish) check **authentication and authorisation before confirmation**. A missing credential is `401`. A credential that may not do the operation is `403`. Only a caller who would otherwise be allowed, and who omitted `X-RedX-Confirm: <operation-id>` (or `?confirm=<operation-id>`), gets `428` `confirm_required`.

### RedX Hosted tenants

On a host with Red-XAI Accounts enabled, a signed-in account that is **not** an owner is a tenant. Owners (deploy-config `REDXAI_OWNER_EMAILS` only) stay host-admin and see every database; each of those requests is audit-logged as `owner.read` or `owner.write` with the owner's email. A tenant never sees another tenant's databases, the master `redxai_accounts` database, `default`, or the admin, audit, update, cluster and owner routes (those are `403` or the same `404` as a missing database).

`POST /v1/dbs` with `{"name":"<logical>"}` requires an **active or trialing** plan. The stored name is namespaced (`t` + 10 hex of the account + `_` + logical) so two tenants can both ask for `game` and neither learns that the other did. The response is `{"ok":true,"name":"<physical>","logical":"<logical>","seq":N}`. Use `name` in `/v1/db/{name}/…`. `GET /v1/dbs` returns `dbs` (physical names), `logical` (physical → logical), and `readonly: true` or `suspended: true` when the plan is not fully open. Reserved logical names (`default`, `admin`, `redxai_accounts`, …) and a name this account cannot take answer `409` `name_unavailable` with the same text, which does not say whether some other database exists.

API keys created by a tenant are bound to one database that tenant owns (`db: "*"` and anyone else's name are `404`). The key carries the account. The plan gate and the quotas apply to that key the same way they apply to the console session: a key minted while the plan was active becomes read-only with the plan and stops working after the grace, instead of keeping the access it had on the day it was minted. The key's own scope, database and prefix still apply; the plan gate does not let it see the account's other databases. Host-admin keys and owner sessions are not tenant keys. BoxQL (`POST /v1/db/{name}/bx`) is unchanged.

Plan gate (see [billing](billing.md)):

| Situation | Create database or key | Read | Write / drop |
|---|---|---|---|
| No plan row | `402` `plan_required` | `403` on `GET /v1/dbs` (same as a session with no database rights) | `403` |
| `active` or `trialing`, inside the period (plus 3 days) | allowed, quotas apply | allowed | allowed |
| Lapsed (`past_due`, `canceled`, `unpaid`, `paused`, `incomplete`) and still before period end + 3 days | `402` `plan_readonly` | allowed | `402` `plan_readonly` |
| After that grace, or no tier | `402` `plan_required` | `402` `plan_required`; `GET /v1/dbs` is `200` with `suspended: true` | `402` `plan_required` |

Databases are never deleted because a plan lapsed. A later active or trialing subscription opens them again.

Over a limit: `402` or `429` with `code: "quota_exceeded"` and `limit` of `storage_quota` (402), `traffic_quota` (429) or `host_switch_quota` (402). `error` stays the specific limit name. Monthly and annual prices share one quota. `GET /v1/billing/me` adds `access`: `full`, `readonly`, `suspended` or `none`. `active` is unchanged (it is still true for `past_due` until the grace ends, so the billing page can show the tier).

## Indexes, packs, links and rules

These features are available in the default build. With the in-memory stub backend (`-tags redx_stub`) every
route below answers **501**. All routes live under `/v1/db/{db}/…`; the CLI uses `--db` / `REDX_DB` (default `default`).

### Access control

| Route | Scope needed | Path-prefix keys |
|---|---|---|
| `GET idx` (list sets), `GET idx/{set}/check`, `GET pack` (list packs), `GET pulse` (rules + timers) | read | **403** (they reveal definitions/names) |
| `GET idx/{set}/{index}/query` | read | allowed; **hits are filtered** to records whose path (`file:Box[ID=n]`) starts with the key's prefix |
| `PUT/DELETE idx/{set}`, `POST idx/{set}/rebuild`, `PUT/DELETE pulse`, `POST pack/{pack}/gc`, `GET pack/{pack}/fsck` | **admin** on the db | **403** (even for an admin key that has a prefix) |
| `GET pack/{pack}/ls|stat|file` (and `HEAD`) | read | prefix is matched against `"<pack>.red-xai-pack:<path>"`, boundary-aware: `media.red-xai-pack:public` allows `public/a.png`, not `publicity/` and not the pack root |
| `PUT/DELETE pack/{pack}/file/{path}` | write | same prefix rule |
| `GET path/{p}?resolve=1` | read | the path itself must match the prefix, **and every link target must too**: a target outside the prefix is left as an unresolved link and reported only as "dangling" (indistinguishable from a missing record) |
| `GET pulse/subscribe` (WebSocket) | read | only events about records matching the prefix are delivered; events without a record are dropped |

A key with prefix `players.red-xai.db:Player[ID=1]` therefore sees that one record in index results and rule events, and
nothing reachable only through other records. Access is enforced with the `read < write < admin` scope, the `db` binding and the `prefix` restriction (data prefixes use `file:Box…`, pack prefixes use `<pack>.red-xai-pack:path`, so
one key cannot be accidentally valid for both). Unknown/wrong/revoked keys get **401**; wrong scope/db/prefix gets **403**.

### Indexes

```sh
redx idx define players players.red-xai-db-idx            # admin; declaration is Box text, see [Indexes and packs](indexes-and-packs.md)
redx idx list
redx idx query players PlayerByName --field Name --value ann                    # exact (folded if the index says Fold)
redx idx query players PlayerByPrefix --mode prefix --field Name --value an
redx idx query players PlayerLevel --field Level --lo 10 --hi 50 [--lo-excl]     # range (numbers)
redx idx query players PlayerBio --field Bio --q "red dragon" [--op or]          # text: word tokens, and/or
redx idx query players PlayerBio --mode fuzzy --field Bio --q "red mage"         # = text with op=or (NOT typo-tolerant)
redx idx check players | rebuild players | drop players
```

REST: `GET /v1/db/default/idx/players/PlayerLevel/query?mode=range&field=Level&lo=10&hi=50&limit=100&record=1`.
`limit` defaults to 100 (max 10,000). The response is `{"hits":[{"path":"players.red-xai.db:Player[ID=2]","field":"Level","value":"12"}],"count":1,"mode":"range"}`.

How it stays correct:
* Indexes are in memory and restored from a verified snapshot, or rebuilt from a scan, when first used after a start. They are
  never stale at open time.
* Every write that goes through the host API (`PUT/DELETE /v1/path/…`, rule actions, link-engine writes) updates them synchronously
  after the commit. Writes that bypass the host (e.g. opening the data files with another tool) do not: run `idx check` / `idx rebuild`.
* Records that expire (TTL files) are filtered out of results at query time and removed from the index lazily.
* A wildcard write/delete path triggers a full rebuild of the open sets (slow on big data).
* Limits are the engine's: one index covers one file; no multi-index planner, no sorting, no paging beyond `limit`, 4096 terms per record per index,
  no regex/substring/phrase/fuzzy search.

### Packs (file storage)

```sh
redx pack put media ./cat.png images/cat.png      # streams, sends the SHA-256 so the server verifies; creates the pack on first use
redx pack ls media images
redx pack get media images/cat.png --out cat.png                      # whole file: SHA-256 verified against the ETag
redx pack get media images/cat.png --out head.bin --range 0-1023       # ranged (also --offset N --length N)
redx pack stat media images/cat.png | redx pack rm media images/cat.png | redx pack list
redx pack gc media            # admin: free chunks of deleted/replaced files (deletes only leave them on disk until you run this)
redx pack fsck media --deep   # admin: read + hash every chunk, report problems (changes nothing)
```

REST: `PUT /v1/db/default/pack/media/file/images/cat.png` (raw body; optional `X-Redx-SHA256` header, mismatch → **422** and nothing is stored),
`GET …/file/…` with `Range: bytes=a-b` / `a-` / `-n` (single range → **206**; multi-range is ignored and the whole file is returned; unsatisfiable → **416**),
`HEAD`, `ETag: "sha256-<hex>"` + `If-None-Match` → 304, `GET …/ls[/folder]`, `GET …/stat/path`, `DELETE …/file/path`, admin-only `POST …/gc` and `GET …/fsck[?deep=1]`.

* Chunks are 1 MiB, content-addressed by SHA-256 (identical chunks are stored once). Uploads are streamed one chunk at a time; the largest upload
  is `max_upload_mb` (default 1024, **413** beyond). Folder entries, names and path rules are the engine's (`..`, `//`, `\`, `:`, control characters, Windows device names are rejected with **400**).
* A **whole-file** download is verified chunk by chunk and by the whole-file hash. If stored data is damaged the server aborts the connection
  (clients see a failed/short transfer, never a clean-looking wrong file); `redx pack get` also checks the hash and keeps nothing on failure.
  A **ranged** read verifies the length and SHA-256 of every chunk it touches (so damage in those chunks is a **500**) but cannot check the whole-file hash.
* Files are served inline only for a short allow-list of media types (png, jpeg, gif, webp, mp3, ogg, wav, mp4, webm, pdf, txt, json, csv); everything else, including `.html`, is
  `application/octet-stream` + `Content-Disposition: attachment`, with `nosniff` and `Content-Security-Policy: sandbox`.
* Not implemented: rename and move, folder delete (`rmdir`), mkdir without a file, resumable uploads, multi-range responses; automatic garbage collection (deleted/replaced files leave their chunks on disk until `redx pack gc`), thumbnails/streaming (`.red-xai-media`).

### Links

`GET /v1/path/players.red-xai.db:Player[ID=1].Guild?resolve=1[&depth=N]` (CLI: `redx get PATH --resolve [--depth N]`) returns the value with embedded `@>` links replaced by
their targets, recursively (depth 0 = engine default 8, max 32). Dangling links and cycles are left in place and listed under `dangling` / `cycles` in the JSON response. The path must be concrete
(a file and a record, no wildcards). Resolution reads local data, so it also works on followers.

### Pulse rules

```sh
redx pulse put rules.red-xai-db-pulse        # admin; replaces the whole rule set (validated first; all-or-nothing)
redx pulse get                               # source, rule names, pending timers
redx pulse subscribe --topic 'player.*'      # WebSocket: one JSON event per line; --changes adds raw change.* events
redx pulse rm
```

REST: `PUT/GET/DELETE /v1/db/{db}/pulse`, WebSocket `GET /v1/db/{db}/pulse/subscribe?topic=<pattern>&changes=1` (`Authorization: Bearer` header, or `?access_token=` for browsers).
Event: `{"seq":3,"time":"…","kind":"emit|timer|loop|error|change","topic":"player.died","rule":"PlayerDeath","path":"players.red-xai.db:Player[ID=1]","data":"<record as Box text>"}`.
Topic patterns are `""`/`*` (all), `prefix*`, or an exact topic.

* When rules exist, `PUT /v1/path/…` writes made through the host are routed through the rule engine so rules see before/after state. Whole-record writes (with or without TTL) and field writes to an existing
  record are covered; field writes **with a TTL**, wildcard paths, and field writes to a record that does not exist yet are written directly and **do not run rules**. Deletes never run rules. TTL expiry does not run rules.
* Rules and timers run **only on the leader**. Timers live in memory: a restart or a failover loses pending timers (the rule definitions survive).
* Event delivery is best effort: a subscriber that cannot keep up misses events (the engine's bus drops rather than blocks).

## BoxQL, media, access policy, scripts and encryption

The routes below are available in the default build; the `redx_stub` build answers **501**. Everything is under `/v1/db/{db}/…`; `POST /v1/bx` is the
shorthand for the default database. The path query `POST /v1/query` and the SDK `query()` remain available next to BoxQL.
The language is specified in [BoxQL](boxql.md); it is written in the Box file grammar ([Box grammar](box-grammar.md)).

| Route | Scope | Path-prefix keys |
|---|---|---|
| `POST bx` body `{"q":"{Get[]} = players:Player[Level > $min] -> Name","params":{"min":10},"explain":false}` (or the command as plain text) | read (`Get`/`Require`/`Explain`); **write** for `Add`/`Set`/`Delete` and any `Tx` containing one | prefix must be `file`, `file:Box` or `file:Box.Field` (becomes a policy ceiling); **403** for record-id or wildcard prefixes |
| `GET bx/watch?q={Watch[]}…&params=<json>` (WebSocket) | read | same rule; command checked before the upgrade (400 syntax, 403 not readable, 404 unknown file) |
| `GET media`, `GET media/{lib}`, `GET media/{lib}/stat/{name}`, `GET\|HEAD media/{lib}/file/{name}` (HTTP `Range`, `If-Range`, `If-None-Match`, 304, 416) | read | prefix matched against `<lib>.red-xai-media:<name>`; list is filtered |
| `PUT media/{lib}/file/{name}[?type=image/png]`, `DELETE …` | write | same prefix rule |
| `GET media/{lib}/fsck[?deep=1]`, `POST media/{lib}/sweep` | admin | 403 |
| `GET sec` (summary; source only for admins) | read | 403 |
| `PUT\|DELETE sec` | admin | 403 |
| `GET code` | read | 403 |
| `PUT\|DELETE code/file/{file}` | admin | 403 |
| `POST code/run/{script}` body `{"args":[…]}` | write | needs a `file`/`file:Box[.Field]` prefix (403 otherwise) |

CLI: `redx bx '{Get[]} = …' [--param name=value]… [--sparam name=text]… [--explain] [--json]` (a `{Watch[]}` command streams events), `redx media put|get|ls|stat|rm|fsck`,
`redx code ls|define|rm|run`, `redx sec show|put|rm`, `redx key create … --roles a,b`, and `redxd keygen`.


**BoxQL.** Commands `Get`, `Add`, `Set`, `Delete`, `Require`, `Tx`, `Explain`, `Watch`.
`$name` parameters only for values (never parsed as command text; an unused or missing parameter is an error), one command per
request, files are named `players:Player[…]` (the file name without `.red-xai.db`; quote the full name to create a file), `@>` follows
links, `Delete` cascades along `@!>` links (standalone `.red-xai-db-link` files in the db folder and embedded links), a `Delete`/`Set`
without a record or filter is refused (tested), and the engine has limits on rows/scan/size ([BoxQL](boxql.md#14-limits)). Errors: 400 (syntax,
with `line:col`), 403, 404, 409 (existing record on `Add`, failed `Require`). The result is
`{kind, columns, rows, rows_box, count, affected, matched, paths, access, plan, cascaded, results}`; `results` holds one nested result
per command of a `Tx`; `access` is `index:<name>` when a `.red-xai-db-idx` index served the filter, else `scan`. Every writing command is
all-or-nothing (before-images are restored on failure, including indexes), and a `Tx` extends that to all its commands.
Indexes defined through the API are kept current by BoxQL writes **and** by REST writes. Explicitly naming a field the caller may
not read is **403**; `-> *` silently drops denied fields (the engine's rule, tested).
On a follower BoxQL **reads** run locally (scan, no planner indexes); BoxQL **writes** (including a `Tx`) are forwarded to the leader.

**Watch** (`GET bx/watch`, WebSocket): a data watch delivers `{path, op, value, at}` for each record of the watched box that matches the
filter (value = the whole record as the caller may see it; removals have no value), a `Topic = "x.*"` watch delivers pulse events (served by the
leader). Keys, prefixes and the policy apply exactly as for `Get`.


**Scripts (`.red-xai-code`).** A document of `{Script[n]} = [Name, Params, Uses, Source, Limits]`. Host functions must be declared in `Uses`
(an undeclared one is rejected when the file is defined). The interpreter has step/time/allocation limits (a runaway loop returns 400 `limit`). Every
`db_get`/`db_set`/… call is checked three times: against the host-level **`code_allowed_boxes`** (`file:Box` globs; **empty = scripts may touch no record**),
against the running key's grant, and against the policy. The allow-list is defined in the host
(`code_allowed_boxes` in `redx.toml`, `--code-allowed-boxes`, `REDX_CODE_ALLOWED_BOXES`). Scripts run **on the leader** and need a write key; defining/removing code is admin.
There is no persistent state between runs. Hand-placed `*.red-xai-code` files load when the db opens.


**Hand-placed files and the cluster.** On start `redxd` opens every `.red-xai*` file found in `<data>/dbs/<name>/` (cold/qs/qs-ls data, `.red-xai-db-link`, `.red-xai-db-pulse`,
`.red-xai-db-idx`, `.red-xai-sec`, `.red-xai-code`; packs and media libraries are folders created on first use). Definitions made through the API
(idx, pulse, sec, code) replicate to followers as one log op; **pack, media and index contents do not** (leader-local, like pack contents); BoxQL writes
and script runs are forwarded to / run on the leader.


## Console, pairing, cluster and app connect routes

| Route | Auth | Purpose |
|---|---|---|
| `GET /v1/ui/bootstrap-status`, `POST /v1/ui/bootstrap` | none, loopback only, once | first-run admin key from the console |
| `GET /v1/ui/whoami`, `POST /v1/ui/validate` | key | caller's scope; parse Box text / BoxQL / policy with `line:col` errors |
| `GET /v1/admin/status`, `audit`, `config`, `presets` | host admin | dashboard data (includes `tls_warning`, `tls_cert`, `tls_fingerprint`), audit tail, redacted config, presets |
| `POST /v1/admin/presets/{name}/apply` | host admin; owner while Accounts is on if the apply sets `join` or changes `role` or `advertise` | write the preset into the config file (restart to take effect). Audit detail includes the join leader URL, never the join secret |
| `POST /v1/keys/pairing` → `POST /v1/pair/exchange` | admin → none | one-time sign-in code (`RP-XXXXX-XXXXX`, 5 min) traded for a new key |
| `POST /v1/cluster/join-token` | host admin | join token (`rxj_...`) or pairing code (`{"kind":"code"}`) |
| `GET /v1/cluster/status`, `POST /v1/cluster/promote`, `POST /v1/cluster/leader` | host admin | status (incl. `fenced`), promote, repoint (`{"url","join_token","pin_sha256"}`) |
| `POST /v1/cluster/superseded` | node secret | a promoted node fences the old leader (see [Clustering](clustering.md#failover-promote-fencing-and-repoint)) |
| `/v1/connect/*` | see [Connecting apps](connect.md) | app connect handshake, Connected apps, revoke |

## Host updates (`/v1/updates`)

Phase 1 of the host update system. Manifests are `redx.update-manifest/v1`, signed with Ed25519
(`X-RedX-Signature: ed25519:<base64>` over the exact JSON bytes). The signing key comes from
`REDX_UPDATE_SIGNING_KEY`, `update_signing_key_file` / `REDX_UPDATE_SIGNING_KEY_FILE` (mode 0600),
or a key generated under `<data>/updates/signing.key`. It is never written into config, git, or the audit log.
`GET /v1/updates/keys` needs no key. Every other update read needs a host-admin key.

Mutations need a host-admin key. Apply, rollback, restore and promote call the same `ownerOnlyOK` /
`refuseHiddenDB` gates as backup and cluster changes. While Red-XAI Accounts is on (`AccountsEnabled`),
those calls, plus publish, policy and source, are owner-only. An app id equal to the master accounts database
is hidden (`404`). Snapshots contain only that app's version, update policy, artifact blobs and its own
database. They never include the keystore, the master accounts database, other databases, or host config.
Restore checks the snapshot sha256 before writing anything back.

Apply refuses a semver lower than the installed version and a manifest whose `requires.min_from` the
installed version does not meet (both `409 sequence_regression`). Sequence is bound to app + version and
only increases for a strictly newer semver. Pre-release tags use SemVer 2.0 precedence: numeric
identifiers compare as numbers, so `3.0.0-beta.10` is newer than `3.0.0-beta.9`. Status omits manifests
that fail signature verification and does not advertise a version older than the one installed.

`plan:true` or `dry_run:true` issues a single-use `X-RedX-Update-Confirm` token bound to the app, version,
action, and the API key that requested it. A different key gets `403`. It does not take a snapshot. The
real call still needs `X-RedX-Confirm` with the operation id. The CLI asks before sending the token, or
takes `--yes`. Extra path segments on apply, publish and rollback are `404`.

Publish is limited to apps in `hosted_apps`. The initial artifact URL must be
`https://github.com/{owner}/{repo}/releases/download/{tag}/{file}` for a repo listed in `github_repos`
(`owner/repo=app`), with no query string. A download may then follow at most three `https` redirects onto
`release-assets.githubusercontent.com` or `objects.githubusercontent.com` (query string allowed). Any other
hop is refused. The SHA256 in `SHA256SUMS` still has to match the bytes. A GitHub release is created only
by that publish. The webhook accepts only those repos, requires `X-GitHub-Delivery`, refuses a replay of
the same delivery id, and skips an `edited` event whose version is already stored or not newer than the
installed one.

`X-Hub-Signature-256` is GitHub's HMAC-SHA256 over the raw body. The delivery id is not part of that
signature. Including it would reject GitHub's own deliveries, and a redelivery is defined to use a new
`X-GitHub-Delivery`. Dedupe on the id stops an exact replay (`409`). A captured body presented with a
fresh id still verifies, which is also how a legitimate redelivery looks. Ingest is idempotent per app
and version: a version already stored is skipped (`202`) and is not published or auto-applied again.
A redelivery of a version that was never stored is the first ingest.

Rollout health is the error rate and latency of authenticated, authorized API requests served by the
nodes on the new version, plus whether those nodes are still live. Timing starts once the request body
has been read. Unauthenticated requests, rejected requests, `4xx` responses, `/healthz` and other probes,
`POST /v1/updates/github/webhook`, `/v1/cluster/*`, requests that set `X-Redx-Wait-Seq`,
`X-Redx-Wait-Replicas` or `wait_ms`, and WebSocket and subscribe streams are not samples. A `504` counts
only when the server produced it on an ordinary authorized call; a client wait or long-poll does not.
Fewer than 20 qualifying samples on a canary node is `unknown` for that node (`error_rate` and `p95_ms`
are null) and that alone does not roll back. Each node reports its own samples to the rollout holder on
the authenticated cluster channel. A canary that is down, or that stops reporting, is `bad` even with no
samples, and so is a cluster that has a dead member. Auto-rollback runs only when health is `bad`. There
is no auto-promote.

App ids and database names share one namespace. A snapshot of an app includes the database of the same
name, and restore writes that database back. Do not put a customer database's name in `hosted_apps`.
The master accounts database is refused. This shared namespace is a known limitation of phase 1.

| Route | Auth | Purpose |
|---|---|---|
| `GET /v1/updates/apps`, `GET /v1/updates/apps/{app}` | host admin | hosted, source_pref, installed, available |
| `GET .../manifests/{version}`, `.../{version}.sig`, `.../artifacts/{artifact_id}` | host admin | signed manifest, signature, artifact. With no `?source=`, the app's source preference is used; `github` does not fall back to a host manifest |
| `PUT .../source` | host admin; owner while Accounts is on | `host`/`github`/`both`. `host` or `both` when the app is not hosted → `409 not_hosted`. `both` accepts a manifest from either source; sequence is one counter for the app (the same version keeps the sequence it was first signed with) and the signature rules do not change. A manifest from the source that is not selected is `409 not_hosted` |
| `PUT .../policy` | host admin; owner while Accounts is on | auto-apply |
| `POST .../apply` | host admin; owner while Accounts is on | app snapshot, then direct / canary / blue-green. Snapshot failure refuses the apply |
| `GET /v1/updates/rollouts/{rollout_id}` | host admin | progress and health |
| `POST .../promote`, `POST .../rollback` | host admin; owner while Accounts is on | health gate, rollback mid-rollout |
| `GET .../snapshots` | host admin | list this app's snapshots |
| `POST .../rollback` | host admin; owner while Accounts is on | restore one snapshot for this app |
| `GET .../history` | host admin | publish, apply, snapshot, rollback |
| `POST .../publish` | host admin; owner while Accounts is on, and the app must be hosted | sign a host and/or GitHub manifest |
| `POST /v1/updates/github/webhook` | HMAC `X-Hub-Signature-256` over the body | allowlisted repo, `X-GitHub-Delivery` dedupe, SHA256SUMS, then a signed github-source manifest. No webhook secret configured is `404 not_found`. While the source preference is `host`, a release is `409 not_hosted` and that delivery id is released so it can be replayed after the source is switched |
| `GET /v1/updates/events` | host admin | WebSocket: `update.available`, `update.analysed`, `rollout.state`, `rollout.health`, `rollback.done` |
| `GET /v1/apps/events` | Accounts client auth | Existing Accounts JSON poll. `update.*` events on that feed are forwarded to the WebSocket and do not end sessions |

`GET /v1/hosting/activity` is for the signed-in account (or an API key minted for that account). It lists only that account's databases: request counts, error counts, and recent denied requests (status, method, path, reason). Anyone else gets `403 account_required`. It does not include another tenant's names.

`GET /v1/owner/audit?event=&q=&limit=&offset=` is owner-only and is itself audit-logged as `owner.read`. `event` matches the event name, `q` matches event, actor, target, route, reason, detail, key id and database. `limit` defaults to 50 (max 200). The response is `{events, total, limit, offset}`, newest first.

Errors are `{ "error": { "code", "message" } }` with `not_hosted`, `bad_signature`, `sequence_regression`,
`snapshot_failed`, `rollout_conflict`, `not_found`, `forbidden`. Validation uses `invalid`. Owner-only
refusals stay the flat `{"error":"..."}` string used by the rest of the host.
BoxQL is unchanged: updates are not a query language.
The CLI is `redx update status|check|apply|promote|rollback|snapshots|restore|source`. Apply, promote,
rollback and restore prompt, or take `--yes`.

## Hosted apps (`/v1/hosted`)

Tenant sites and containers. These are not the update-system app ids. A signed-in tenant, or an API key
that tenant minted, sees only that account's apps. An owner session and a host-admin key see every app,
and every owner request is audit-logged. Plan gates are the same as databases: no plan is `402 plan_required`
on a write and `403` on the list; read-only is `402 plan_readonly`; a suspended known account can list
(`suspended: true`) but writes and logs are `402 plan_required`. Over the app cap is `402` with
`limit: "app_quota"`. Over the per-app disk cap is `limit: "app_disk_quota"`. Starting or stopping an app
consumes one `host_switch_quota` switch only when the running state changes.

Cross-tenant reads and writes are `404` (`app not found`, `database not found`, `domain not found`,
`secret not found`) so a caller cannot tell that another tenant's name exists. A custom domain another
tenant still holds (verified, or unverified and newer than 7 days) is `409 domain_taken`.

`DELETE /v1/hosted/apps/{id}` is dangerous: `X-RedX-Confirm: deleteHostedApp` after auth, or `428`.
Secret values are write-only. `GET` shows `••••••••` and never the plaintext. The value is encrypted at
rest and injected through an env file the podman spec references with `--env-file`, not `--env`.

`GET /v1/hosted/apps/{id}/deploys/{deploy}/manifest` returns the exact `redx.update-manifest/v1` bytes
and `X-RedX-Signature: ed25519:…` over those bytes. Rollback and promote use the same snapshot schema as
host updates (`redx.update-snapshot/v1`), stored under the app, not in the host updater's app table.

`GET /v1/hosted/tls/ask?domain=` is the Caddy on-demand ask. `200` only when the name is a verified app
domain. Anything else, including an unverified custom domain, is refused. With no
`REDX_APPS_TLS_ASK_SECRET`, only a loopback socket may ask. With the secret set, the caller must send
`X-RedX-Caddy-Ask`. `GET /v1/hosted/caddy` (owner or host-admin) prints the Caddyfile fragment.

Public traffic for an app hostname is served by redxd itself (static files, or a reverse proxy to
`127.0.0.1:<port>` for a running container). It does not enter `/v1`. A stopped app is `503`. A suspended
plan is `402 plan_required`. The HTTP-01 path `/.well-known/redx-challenge/<token>` is served before the
name is verified, so the check can succeed; the TLS ask still refuses that name until it is verified.

The CLI is `redx app`. See [Hosting apps and sites](hosting-apps.md).
