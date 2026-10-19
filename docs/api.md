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

