# Connecting apps

An app (for example the Rotten Apple store and its launcher, or Gendragoon) can ask a RedX host for **its own workspace** (a
database) and a **scoped key**. The owner approves once in the console; the app receives the key through a code exchange that
needs a secret only the app holds. Nothing secret ever travels in a link, a QR code or a callback URL.

## 1. The flow

```
app                                  console (host admin)                 redxd
 │ makes state (≥128 bits) and a PKCE verifier; keeps both
 │ opens redx://connect?v=1&provider=…&state=…&pkce_challenge=…&callback=…
 │   or https://<host>/#/connect?<same parameters>  ─────────────►  POST /v1/connect/start ──► pending request
 │                                    consent page: Approve / Deny
 │                                                      ─────────────►  POST /v1/connect/approve ─► workspace created,
 │                                                                                                one-time code
 │ ◄──── callback rottenapple://redx-callback?code=RX-…&state=…&host=…&pin=…   (or the code is copied by hand)
 │ POST /v1/connect/exchange {code, pkce_verifier, state} ───────────────────────────────────────► key minted, returned once
 │ … uses the key …
 │ POST /v1/connect/revoke (with its key) on uninstall ─────────────────────────────────────────► key revoked
```

* The link is read by the console in the URL fragment (never sent to a server) and survives the first-run setup and sign-in.
* `start` needs the host admin key, so nobody on the network can push consent prompts at the owner.
* The **key is minted at the exchange**, after the PKCE verifier and the state check out. Nothing between approve and exchange can
  leak a key, and an unused code leaves nothing to revoke.

## 2. Link parameters

| Parameter | Required | Meaning |
|---|---|---|
| `v` | yes | protocol version, `1`. Missing or lower: `client_too_old` |
| `provider` | yes | `rottenapple` (the store's own database), `rottenapple-launcher` (one installed app), `gendragoon`, `quicklaunch` (the QuickLaunch developer tool, workspace `quicklaunch`); anything else is shown as *Unverified app* and needs a typed confirmation |
| `state` | yes | 22-128 characters `[A-Za-z0-9_-]`, at least 128 random bits |
| `pkce_challenge` | yes | `base64url(SHA-256(verifier))` without padding (43 characters). Only `S256` (`pkce_method`, optional) |
| `callback` | no | exact match with RedX's list (`rottenapple://redx-callback`, `gendragoon://redx-callback`) or a loopback redirect (see below). Anything else is ignored and the code is shown for copy and paste |
| `app` | `rottenapple-launcher` | the app id; the workspace is then fixed to `ra-<app id, lower case, dots as dashes, ≤40 chars>-<8 hex of sha256(app id)>` |
| `workspace` | no | the database name (`^[a-z0-9][a-z0-9_-]{0,62}$`). Defaults: `ra` (rottenapple), `gendragoon`, the provider id |
| `scope` | no | `read` or `write` (default `write`). `admin` is never granted |
| `prefix` | no | path prefix for the key, e.g. `saves` (then the key reaches only `saves…` paths in the workspace) |
| `label` | no | key label; default `app:<app id>` or `app:<provider>` |
| `host`, `pin` | no | the address the app will call and the certificate pin it expects; echoed in the callback |
| `name` | no | a label shown as "the link calls itself …" (never used as the app's name) |

The provider's name and wording come from RedX's own list, never from the link.

**Loopback callbacks** (RFC 8252 section 7.3, used by desktop tools such as QuickLaunch that receive the code on
their own short-lived local HTTP service): `http://127.0.0.1:<port><path>`, `http://[::1]:<port><path>` or
`http://localhost:<port><path>`, any port 1-65535, where `<path>` is the provider's registered path
(`/redx-callback` for every provider today). Refused: any other scheme (also `https`), user info (`user@`), any other host
name or address (RedX resolves no names, so a name that points at 127.0.0.1 elsewhere is refused too, as are
`127.0.0.2`, `0.0.0.0`, `[::ffff:127.0.0.1]` and decimal forms), a missing or zero-padded port, a query or fragment,
percent-encoding, and any other path (also a trailing `/`). PKCE (`S256`) is required as for every provider.

## 3. Endpoints

All live on the leader (followers forward writes; reads answer `503 not_leader`). Errors are `{"error": "...", "code": "..."}`.

### `POST /v1/connect/start` (host admin key)

```json
{"v":1,"provider":"rottenapple-launcher","app":"com.acme.stardrift","scope":"write","prefix":"saves","label":"app:com.acme.stardrift",
 "state":"<state>","pkce_challenge":"<b64url>","callback":"rottenapple://redx-callback","name":"Rotten Apple","host":"https://h:7777","pin":"<hex>"}
```
→ `201` (or `200` when the same link is started again: the request id is derived from provider, app and state)
```json
{"api":"v1","request_id":"rq_…","ref":"3fa2…","status":"pending","expires_at":"2026-10-19T07:30:00Z",
 "provider":{"id":"rottenapple-launcher","display":"Rotten Apple launcher","verified":true,"callback_ok":true,"wording":"…"},
 "defaults":{"workspace":"ra-com-acme-stardrift-1a2b3c4d","scope":"write","prefix":"saves","storage":"local","workspace_fixed":true},
 "workspace":{"exists":false,"owned_by_this_app":false,"other_owner":false},
 "can":["read and change data in this workspace only"],"cannot":["see your other databases","create or delete databases","manage keys"],
 "single_key":false,"active_key":false}
```
A newer request for the same provider and app supersedes the older one (its exchange answers `superseded`).

### `GET /v1/connect/pending` (host admin)

`{"requests":[{"ref","provider","display","verified","app","name","workspace","scope","prefix","status","expires_at"}]}`. Request ids are not listed.

### `POST /v1/connect/approve` (host admin)

`{"request_id":"rq_…","workspace":"…","scope":"read|write","confirm":"<provider id, unverified apps only>","replace":false}` →
```json
{"api":"v1","code":"RX-7K2QF-9HXMD","expires_at":"…","workspace":"ra-com-acme-stardrift-1a2b3c4d","scope":"write","prefix":"saves",
 "host":"https://h:7777","pin":"<hex or empty>","paste":"https://h:7777 RX-7K2QF-9HXMD","deliver":"callback",
 "callback_template":"rottenapple://redx-callback?code=RX-7K2QF-9HXMD&state={state}&host=https%3A%2F%2Fh%3A7777&pin=<hex>"}
```
The workspace is created here if missing. An existing database that this flow did not create for the same app is refused
(`409 workspace_exists_other_owner`). The store's own database (`rottenapple`) allows one active key; a second approve needs
`"replace":true` (the old key is revoked when the new one is issued) or gets `409 key_exists`. The console replaces `{state}` with the
state from the link (RedX keeps only its hash) and opens the callback. Approving again issues a new code and voids the old one.

Cross-site protection: approve, deny, start and admin revoke need the admin key in the `Authorization` header (the console uses no
cookies), `Content-Type: application/json`, and are refused (`403 csrf`) when the browser marks the request cross-site
(`Sec-Fetch-Site`) or sends a foreign `Origin`.

### `POST /v1/connect/deny` (host admin)

`{"request_id":"rq_…"}` or `{"ref":"…"}` → `{"status":"denied"}`.

### `POST /v1/connect/exchange` (no key; the code and verifier are the credential)

```json
{"code":"RX-7K2QF-9HXMD","pkce_verifier":"<43-128 chars>","state":"<state>","device_label":"my laptop","provider_grant":"<optional>"}
```
→ `200`
```json
{"api":"v1","connection_id":"cn_…",
 "workspace":{"db":"ra-com-acme-stardrift-1a2b3c4d","name":"com.acme.stardrift"},
 "key":"rx_live_…","key_id":"ab12cd34","scope":"write","prefix":"saves",
 "endpoints":{"base":"https://h:7777","path":"/v1/db/ra-com-acme-stardrift-1a2b3c4d/path/","bx":"/v1/db/ra-com-acme-stardrift-1a2b3c4d/bx",
              "subscribe":"wss://h:7777/v1/db/ra-com-acme-stardrift-1a2b3c4d/subscribe","revoke":"/v1/connect/revoke"},
 "host":{"node_id":"…","version":"0.4.3","tls_pin":"<hex>"},
 "storage":{"mode":"local","provider":"","status":"local"},
 "warning":"this is the only time the key is shown"}
```
Checks, in order: rate limit per client address, transport (https, or plain http only from this machine's loopback:
`400 insecure_transport`), known code, request status, code age, state (constant-time), `S256(verifier) == challenge`
(constant-time). The request is marked used before the key is created, so a repeated or concurrent exchange never yields a
second key.

`provider_grant` (optional, at most 512 characters) is a one-time storage grant from the storage provider. RedX accepts each
grant once (a replay is `409 grant_used`, and the code stays usable without it) and reports `storage.status:
"pending-provider-grant"`. Redeeming the grant at the provider is not built yet; the workspace uses storage on this host.

### `POST /v1/connect/revoke` (the app's own key)

The app, or Rotten Apple's launcher when it uninstalls the app, revokes its key: `Authorization: Bearer <the app key>`, empty
body → `{"revoked":true,"connection_id":"cn_…","key_id":"ab12cd34"}`. The key stops working at once (`401`), the connection is
marked revoked and `connect.revoke` is audit-logged. A key that was not issued by the connect flow gets `404 not_connected`.

### `GET /v1/connect/apps`, `DELETE /v1/connect/apps/{connection_id}` (host admin)

`{"apps":[{"id","provider","display","verified","app","device","workspace","key_id","scope","prefix","storage","created","revoked","revoked_by"}]}`.
A key revoked under *API Keys* shows as revoked here too. `DELETE` revokes. The console's *Connected apps* page uses both.

### `POST /v1/connect/claim`

Invites started from RedX are not built: `501 not_built`.

## 4. Lifetimes and limits

| What | Value |
|---|---|
| Request (start → exchange) | 30 minutes |
| Code (approve → exchange) | 5 minutes, single use |
| Wrong state or verifier | 5 per request, then the request is closed (`429 too_many_attempts`) |
| Exchange and revoke calls | 20 per minute per client address (`429 rate_limited` with `Retry-After`) |
| Open requests | 50 |

## 5. Error codes

| Code | HTTP | When |
|---|---|---|
| `invalid_request` | 400 / 404 | bad JSON or parameter, unknown code or request |
| `client_too_old` | 400 | `v` missing or below 1 |
| `unknown_provider` | 400 | provider id malformed, or an unverified app approved without the typed confirmation |
| `insecure_transport` | 400 | exchange over plain http from another machine |
| `state_mismatch`, `pkce_mismatch` | 400 | the state or the verifier does not match |
| `csrf` | 403 | cross-site browser request on an admin endpoint |
| `denied` | 403 | the owner denied the request |
| `code_used`, `superseded`, `grant_used`, `key_exists`, `workspace_exists_other_owner` | 409 | see above |
| `expired` | 410 | request or code too old |
| `too_many_attempts`, `rate_limited` | 429 | see section 4 |
| `not_built` | 501 | invites |
| `not_leader`, `unavailable` | 503 | follower without a leader, connect store could not be opened |

## 6. What is stored

`<data>/connect/connect.json` (0600, rewritten atomically) holds: SHA-256 of the request id, the state, the code and used
provider grants; the PKCE challenge (public by design); provider, app, workspace, scope, prefix, status and expiry; and the list of
connections (key id, never the key). `<data>/connect/id.key` is the random key that derives request ids. Pending requests survive a
restart. The audit log records `connect.start`, `connect.approve`, `connect.deny`, `connect.exchange`, `connect.fail` (with a
reason) and `connect.revoke`, never a code, verifier, state or key.

Connections are kept on the leader. After a failover the keys still work (keys replicate), but the new leader's *Connected apps*
list starts empty; revoke such keys under *API Keys*.

## 7. Least privilege

The key gets `read` or `write` on the one workspace and, if asked, one path prefix. It cannot create or delete databases, see
other databases, manage keys or use `/v1/connect/apps`. A prefix key cannot use `POST /v1/db/{db}/query` (use BoxQL `/bx`). The
store's own key (`rottenapple`) has no prefix, so `ra-core` can list records with `/query`.

## 8. For Rotten Apple

Rotten Apple's connect client already uses this wire format: the link from `ServiceLink`, the callback
`rottenapple://redx-callback?code&state&host&pin`, `POST /v1/connect/exchange` with `{code, pkce_verifier, state, device_label}` and the
error codes `pkce_mismatch`, `state_mismatch`, `code_used`, `expired`, `too_many_attempts`, `denied`, `superseded`, `client_too_old`.
Two additions: the response carries `connection_id` and `endpoints.revoke`, and the launcher can now call `POST /v1/connect/revoke`
with the app key on uninstall instead of asking the person to revoke it by hand. The callback carries `host` (the address the app gave in
the link, otherwise the host's advertised address) and `pin` (only on https).
