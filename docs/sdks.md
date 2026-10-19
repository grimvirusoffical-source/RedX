# SDKs

JavaScript (`sdk/js`) and Python (`sdk/python`) clients.

Dependency-free (Node >= 18 with global `fetch`; Python >= 3.9 stdlib). Neither is published to a package registry yet. Both implement the WebSocket protocol (RFC 6455) themselves, because neither runtime ships a client that can send an `Authorization` header.

```js
const { RedX } = require('./sdk/js/redx');
const db = new RedX({ url: 'http://127.0.0.1:7777', key: process.env.REDX_KEY, db: 'default' });
await db.set('players.red-xai.db:Player[ID=1]', { Name: 'Ann', Level: 5 });
await db.get('players.red-xai.db:Player[ID=1].Name');            // 'Ann'  (getBox() = raw Box text)
await db.set('sess.red-xai-db-qs:Q[ID=1].Otp', '1234', { ttl: 30, sliding: true });
(await db.query('players.red-xai.db:Player[ID=*].Name')).values;  // ['Ann']
const sub = await db.subscribe('players.red-xai.db:*', (ev) => console.log(ev.op, ev.path, ev.data));
sub.close();
```
```python
import os
from redx import RedX
db = RedX("http://127.0.0.1:7777", os.environ["REDX_KEY"])
db.set("players.red-xai.db:Player[ID=1]", {"Name": "Ann", "Level": 5})
db.get("players.red-xai.db:Player[ID=1].Name")                    # 'Ann'
with db.subscribe("players.red-xai.db:*") as sub:                 # or subscribe(path, handler)
    for ev in sub: print(ev["op"], ev["path"], ev["data"]); break
```

Methods (same in both, JS camelCase / Python snake_case): `health stats databases get getBox getOr set setBox delete query bx watch subscribe createKey revokeKey withDb`.
* **Values.** `set` takes JSON-compatible data (objects become boxes, `null` becomes NELL); `setBox` takes raw Box text. `get` decodes the host's Box text into plain data (links become `{"$link": "<text>"}`, ids in keys as `"Name[ID=2]"`); `getBox`/`get_box` returns it untouched. TTL options: `ttl` seconds, `sliding`, `checkpoint`. A `.red-xai-db-qs` file needs a `ttl`.
* **Errors.** `RedXError` with `status` (0 = network/timeout/decode), `retryAfter`/`retry_after` for 429, and helpers (`unauthorized`, `forbidden`, `notFound`, `rateLimited`). A bad, missing, revoked and expired key all give the same 401. The key is never in a message, `repr`, `JSON.stringify` or a pickle, and error text is scrubbed of `rx_live_...` strings. Redirects are not followed and Python ignores environment proxies, so the key is only sent to the URL you gave.
* **Paths** are percent-encoded for you (`[ ] : =`). Database names are lower-case `[a-z0-9_-]`.
* **Subscribe** paths are *path patterns* (`file.red-xai.db:*`, `file:Box[ID=*]`, `file:Box[ID=1]`), not string prefixes: a bare file name or `""` is rejected with 400 (host >= 0.2.0; it used to close silently); `file:` means every box of the file. Events are `{path, op: set|delete|expire, value (Box text), at, data (decoded)}`. The SDK does **not** reconnect; `onClose`/`on_close` reports the code (1006 = connection lost) so the caller can resubscribe. Pings are answered; the host pings every 30 s. Max message 16 MiB.
* **Not provided:** TLS client options (system trust store only), retries, connection pooling beyond the runtime's, browser support (subscribe needs Node sockets), TypeScript types, the pack/idx/pulse/`?resolve=1` endpoints.

Tests (`sdk/js/test`, `sdk/python/tests`) build `cmd/redxd` into a temp dir (or use `REDXD_BIN`), start it on a free 127.0.0.1 port with a throwaway data dir and minimal environment, take the first-run admin key from its stdout (never printed), create read/write/prefix/rate-limited keys with `POST /v1/keys`, and kill it and delete the dir afterwards. Run:
`cd sdk/js && npm test` (= `node --test test/sdk.test.js test/ws.test.js`), `cd sdk/python && python3 -m unittest discover -s tests -t .`.

Host behaviour (>= 0.2.0): reading an absent or expired path is always 404 (a stored NELL is a real value and returns 200 `NELL`), so `get` raises `notFound` and `getOr` returns the default. Keys restricted to a path prefix cannot use `/v1/query` (403); they can use `bx()` when the prefix is `file`, `file:Box` or `file:Box.Field`. `bx()` and `watch()` are covered by the host tests (`host/engineadapter/services_test.go`) and the live SDK tests.

Not yet available: more languages, TypeScript types and a browser WebSocket client. A Go client is in `host/client`.
