# SDKs

RedX has one API description, [`api/redx-api.json`](../api/redx-api.json), and every SDK is generated from it (`go run ./scripts/gensdk`; CI runs `go run ./scripts/gensdk -check` and fails if a generated file drifts). The same file produces [`api/openapi.json`](../api/openapi.json) (OpenAPI 3.1) for anything else.

| Language | Folder | Needs | Streams | TLS pin |
|---|---|---|---|---|
| Go | `sdk/go/redx` (module `github.com/grimvirusoffical-source/RedX/sdk/go`) | Go >= 1.22 | yes, with reconnect | yes (`WithPin`) |
| C / C++ (C ABI) | `sdk/go/cabi` (`include/redx.h`, `include/redx_ops.h`) | a C compiler; built with Go + cgo | yes (`redx_stream_*`) | yes (`"pin"`) |
| JavaScript / TypeScript | `sdk/js` (`redx.d.ts` types) | Node >= 18 | yes, with reconnect | no |
| Python | `sdk/python` | Python >= 3.9, stdlib only | yes, with reconnect | no |
| Swift | `sdk/swift` (Swift package) | Swift 5.7+, macOS 12 / iOS 15 / tvOS 15 | Apple platforms only | Apple platforms only |
| C# / .NET | `sdk/csharp/RedX` | netstandard2.1 or net8.0 | yes, with reconnect | yes (`pin:`) |

None of them is published to a package registry yet; use them from the repository. Game engines: see [game-engines.md](game-engines.md).

## One API everywhere

Every operation in the spec has an id (`getPath`, `listDatabases`, `createKey`, `clusterStatus`, ...) and the same call shape in each language:

* a generated method per operation: `listDatabases` (JS, Swift), `list_databases` (Python), `ListDatabases` (Go), `ListDatabasesAsync` (C#), `redx_call(h, "listDatabases", args)` (C);
* a generic `call(opId, {db, params, query, body, raw, headers, confirm})` (Go `Call(ctx, id, Args{...})`, C# `CallAsync`, Python `call(op_id, ...)`), so a new host route can be used before the SDK has a method for it;
* conveniences on top: `get`/`getBox`/`set` (TTL: `ttl`, `sliding`, `checkpoint`)/`delete`, `bx` (BoxQL), `tx` (several BoxQL commands, all or nothing), `uploadFile`/`downloadFile` (with byte ranges), `uploadMedia`/`downloadMedia`, `subscribe`/`watch`.

Binary uploads send `X-Redx-SHA256` for you; the host refuses data that does not match (422) and stores nothing.

Coverage: database calls (paths, BoxQL, query, keys, files, packs, media, policy, links), and host calls (health, stats, databases, nodes, presets, backups, cluster status/promote/repoint/join tokens, connect and pairing, apps). Restoring a backup is offline only (`redx restore`) and has no API call.

```js
const { RedX } = require('./sdk/js/redx');
const db = new RedX({ url: 'http://127.0.0.1:7777', key: process.env.REDX_KEY, db: 'game' });
await db.set('players.red-xai.db:Player[ID=1]', { Name: 'Ann', Level: 5 });
await db.get('players.red-xai.db:Player[ID=1].Name');                         // 'Ann'
await db.set('sess.red-xai-db-qs:Q[ID=1].Otp', '1234', { ttl: 30, sliding: true });
(await db.bx('{Get[]} = players:Player[Level >= $min] -> Name', { min: 3 })).rows;
const sub = await db.subscribe('players.red-xai.db:*', (ev) => console.log(ev.op, ev.path), { reconnect: true });
```
```python
from redx import RedX
db = RedX("http://127.0.0.1:7777", os.environ["REDX_KEY"], db="game")
db.set("players.red-xai.db:Player[ID=1]", {"Name": "Ann", "Level": 5})
db.list_databases()
```
```go
c, _ := redx.New("http://127.0.0.1:7777", os.Getenv("REDX_KEY"), redx.WithDB("game"))
_ = c.Set(ctx, "players.red-xai.db:Player[ID=1]", map[string]any{"Name": "Ann"}, nil)
s, _ := c.Subscribe(ctx, "players.red-xai.db:*", &redx.StreamOptions{Reconnect: true})
for ev := range s.C { fmt.Println(ev.Op, ev.Path) }
```
```swift
let c = try RedXClient(url: "http://127.0.0.1:7777", key: key, db: "game")
try await c.set("players.red-xai.db:Player[ID=1]", ["Name": "Ann"])
let name = try await c.get("players.red-xai.db:Player[ID=1].Name")
```
```csharp
var c = new RedXClient("http://127.0.0.1:7777", key, db: "game");
await c.SetAsync("players.red-xai.db:Player[ID=1]", new { Name = "Ann" });
var name = await c.GetAsync("players.red-xai.db:Player[ID=1].Name");
```

## Danger levels

Each operation carries a machine-readable danger level (spec field `danger`; OpenAPI `x-redx-danger` and `x-redx-danger-level`; `DANGER`/`dangerOf` in JS, `danger_of` in Python, `DangerOf` in Go, `DangerLevel` in Swift and C#, `redx_danger_level()` and `REDX_DANGER_*` in C):

| Level | Value | Meaning | Rotten Apple SDK level |
|---|---|---|---|
| `safe` | 0 | reads | L1 |
| `write` | 1 | changes data | L1 |
| `admin` | 2 | host or key administration | developer tool |
| `dangerous` | 3 | can lose data or hand out access: delete database, create/revoke/rotate key, pairing codes, policy changes, join tokens, promote, repoint, approve a connect request, revoke an app | developer tool |

`dangerous` calls are refused by the SDK, without sending anything, unless you pass `confirm: true` (error code `confirm_required`, status 0). When confirmed, every SDK sends the header `X-RedX-Confirm: <operation-id>`; the host refuses the same call with HTTP **428** and `code: "confirm_required"` if that header (or `?confirm=<operation-id>`) is missing. `deleteDatabase` with `confirm` also still sends the host's own `?confirm=<db>`, which by itself remains enough for that one operation.

## Streams

`subscribe(pattern)` takes a path pattern (`file.red-xai.db:*`, `file:Box[ID=*]`); a bare file name is rejected with 400. `watch(boxql, params)` streams BoxQL matches. With `reconnect` on, a dropped stream reconnects with exponential backoff and jitter (250 ms to 10 s) and calls `onReconnect` each time; it gives up on 400/401/403/404. **Events missed while disconnected are not replayed**: re-read what you need in `onReconnect`. Swift streams work on Apple platforms only (swift-corelibs-foundation on Linux and Windows does not complete the handshake; the call fails with code `unsupported`).

## Connect (app side)

`connectRequest()` makes a `state` and a PKCE S256 pair, `connectLink()` builds the `redx://connect?...` (or console) link, `parseCallback(url, expectedState)` checks the state in constant time, and `exchangeConnectCode(code, request)` swaps the code for a scoped key without needing a key itself (see [connect.md](connect.md)). `exchangePairingCode` does the same for pairing codes.

## Errors and secrets

`RedXError`/`RedXException`/`*redx.Error` carries `status` (0 = not sent, network, timeout or decode), `code` (the host's code, or `confirm_required`, `unsupported`) and `retryAfter` for 429. The key is never part of an error message, string form or log, and messages are scrubbed of key-like strings. Redirects are not followed, so the key only goes to the URL you gave. A bad, missing, revoked and expired key all give the same 401.

TLS pinning (`pin`: SHA-256 hex of the server certificate) is available in Go, the C ABI, C#, and Swift on Apple platforms. JavaScript and Python use the system trust store only. In Swift on Linux a pin makes every request fail rather than skip the check.

## Migrating from the 0.1 JS and Python clients

The existing `sdk/js` and `sdk/python` APIs keep working. Changes:

* `createKey`/`create_key` and `revokeKey`/`revoke_key` are `dangerous` and need `confirm: true` (`confirm=True`), like every other dangerous operation. Without it the SDK refuses locally; without the `X-RedX-Confirm` header the host refuses with 428.
* `health`, `stats`, `bx`, `createKey` and `revokeKey` keep their hand-written signatures; the generated methods for the other operations are added beside them.
* Streams can reconnect (`reconnect`, `onReconnect`/`on_reconnect`); the default is still no reconnect.
* `RedXError` gained `code`. JS ships TypeScript types (`redx.d.ts`).

## Tests

Every SDK is tested against a real `redxd` built from this repository (or `REDXD_BIN`), started on a free 127.0.0.1 port with a throwaway data dir; the first-run admin key is read from its stdout and never printed. CI runs Go and C# on Linux, Windows and macOS, the C ABI on Linux and macOS, JavaScript and Python on Linux, and Swift on macOS.

```
cd sdk/go && go test ./...
cd sdk/js && npm test
cd sdk/python && python3 -m unittest discover -s tests -t .
cd sdk/swift && swift test
dotnet test sdk/csharp/RedX.Tests
```

Accounts, sign-in and password reset are not part of the API yet. When they arrive, verification and reset email will go through a shared SMTP sender configured by environment (`SUPPORT_EMAIL_PASSWORD`), not through the SDKs.
