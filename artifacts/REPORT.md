# QA security review — PR #22 lifetime-cert owner-only read

**Verdict: HOLD. Do not merge.**

| | |
|---|---|
| Target | https://github.com/grimvirusoffical-source/RedX/pull/22 |
| Head | `171e059f4ea5b63dd0a624c047116e13490da506` (`cursor/lifetime-cert-owner-gate-7ab7`) |
| Prior HOLD | head `86f6275cde42f3078a56c6ae8fc2c7f881a55855`, report on PR #26 |
| Product vs `86f6275` | Array-index match in `certExpandFeeds` (`host/accounts_guard.go` and its tests). |
| Product vs `a09baece` | Cert gate unchanged. The only diff is `host/hosted_test.go`: the sign-in limiter test no longer follows the authorize redirect. |
| Harness | `host/qa_lifetime_attack_test.go` (`//go:build qa`) on `cursor/qa-lifetime-cert-array-retest-d80e`. Not merged. PR #26 left unmerged. |

Field values below are **present** or **absent** only. No ciphertext, key, seed, or PEM material is included.

## What the freeze requires

From `host/accounts_guard.go`:

- Kind `rxa-lifetime-cert` is owner-only for the entire record, including `private_enc`, `pubkey`, `cert_id`, `owner_emails`, `issued`, and `sig_id_prefix`.
- Non-owner reads are 403. Ciphertext must not appear in non-owner responses or audit text.
- An accounts service key may write the cert and set `idVerified` / `idVerifiedMs`, and must not read any cert field back.

## Author claim for this head

Recorded `Bag[0]` now counts as inside the request field `Bag`, including `Wrap.Bag[0]` and nested `Bag[0][1]`. Claimed closed for host-admin, a db write key, and the accounts service key:

- `Player[ID=8].Bag?resolve=1`
- `Player[ID=9].Bag?resolve=1` (`private_enc`, `text/plain`)
- `Player[ID=10].Wrap.Bag?resolve=1&depth=4`

Prior closures kept. The cert-gate claim is unchanged from `a09baece`.

That claim is true for those three rows, and the prior closures still hold. It is not true when the link entry itself carries an ID attribute. On that path a non-owner, including the accounts service key, still receives the cert field. When the link targets `private_enc`, the ciphertext comes back.

## Attack result

Harness: real engine (`engineadapter.Opener`), `CodeAllowedBoxes: ["*"]` so the script sandbox is not what blocks a read. The harness raises the per-key rate burst so a 429 is not what ends a probe. Callers: host-admin key, db-scoped write key, accounts service key (`db=redxai_accounts`, scope write), and an owner console session.

`go test -tags qa -count=1 -timeout 12m -run TestQALifetimeCertAttack ./host/`: **exit 1**. **37 LEAK**, **436 CLOSED**, **74 QUIET**, **9 CONTROL-OK**, **13 OWNER-OK**, plus one pulse-define status line (**200**, cert fields **absent**). Ciphertext **present** on 10 of the LEAK probes and **absent** on every CLOSED and QUIET probe. PEM banners in server logs: **0**.

### Array resolve the author closed

Status **403**. Every cert field **absent**. Ciphertext **absent**. Owner on the same URL is **200** with the requested field **present**.

| Channel | host-admin | write key | accounts service | owner |
|---|---|---|---|---|
| GET `Player[ID=8].Bag?resolve=1` (pubkey), including `depth=1`, `depth=4`, `depth=32`, `resolve=true`, `text/plain`, `text/x-redx-box`, HEAD | 403, pubkey **absent** | 403, pubkey **absent** | 403, pubkey **absent** | 200, pubkey **present**, ciphertext **absent** |
| GET `Player[ID=9].Bag?resolve=1` (`private_enc`), including `text/plain` and `application/json` | 403, ciphertext **absent** | 403, ciphertext **absent** | 403, ciphertext **absent** | 200, ciphertext **present** |
| GET `Player[ID=10].Wrap.Bag?resolve=1&depth=4`, including `resolve=true` and `text/plain` | 403, cert_id **absent** | 403, cert_id **absent** | 403, cert_id **absent** | 200, cert_id **present**, ciphertext **absent** |
| GET `Player[ID=10].Wrap?resolve=1&depth=4` and the player record for IDs 8, 9, and 10 | 403, all fields **absent** | 403, all fields **absent** | 403, all fields **absent** | — |
| GET `Player[ID=10].Bag?resolve=1` (array link to the whole cert) | 403, all fields **absent** | 403, all fields **absent** | 403, all fields **absent** | — |
| BoxQL `{Get[]} = players:Player[ID=8\|9] -> Bag @> Bag` and `Player[ID=10] -> Wrap.Bag @> Wrap.Bag` | 403, all fields **absent** | 403, all fields **absent** | 403, all fields **absent** | — |

Adjacent shapes with no ID on the entry are also **403**, fields **absent**: nested index `Bag[0][1]` read as `.Bag`, a cert link at index 1, a link inside a box that is an array element, and a two-hop array link at `depth=4`. `Bag[0][1]` is not a path (**400**, fields **absent**). `Player[ID=8].Bag[0]` and `Bag[ID=0]` on a field that has no ID are **404**, fields **absent**. A two-hop read at `depth=1` is **200** with every cert field **absent** (the inner link is not followed). A short-prefix target inside an array is **200** with every cert field **absent** (it does not resolve). BoxQL `@>` of the nested-index array is **200** with every cert field **absent** (the follow does not return the field). Those are not leaks.

### New hole — entry ID on the link field

`expandStepMatches` treats a numeric `[n]` suffix as part of the field. An entry that has an ID is recorded as `Name[ID=n]`, and an array element under it as `Name[ID=n][0]`. `[ID=n]` is not a numeric suffix, so a request for `Name` does not count that copy. Lookup without an ID still returns that entry. The selected value is one field string, which `TextIsLifetimeCert` does not treat as a cert body, so the response is **200** and the field is **present**.

The same request with the ID in the path (`Bag[ID=0]`, `Bag[0]`, `Steal[ID=1]`, `Wrap[ID=3].Bag`) is **403**, fields **absent**. The whole player record is **403**. A link to the whole cert record, stored in an ID'd array, is **403** (the expanded value is a cert body). A non-ID attribute on the same array field stays **403**. BoxQL `@>` of the ID'd array and of the ID'd box field is **403**, fields **absent**. The hole is HTTP `?resolve=1` of the field name without the ID.

Observed non-owner **200**, named field **present**. Ciphertext is **present** only on the rows marked secret **present**. The same URLs for an owner session are **200** with that field **present**.

| Channel | host-admin | write key | accounts service |
|---|---|---|---|
| GET `Player[ID=17].Bag?resolve=1` (ID'd array, pubkey), including `text/plain`, `resolve=true`, `depth=1`, `depth=4` | pubkey **present** | pubkey **present** | pubkey **present** |
| GET `Player[ID=18].Bag?resolve=1` (ID'd array, `private_enc`), including `text/plain`, JSON, and `text/x-redx-box` | secret **present** | secret **present** | secret **present** (`text/plain`) |
| GET `Player[ID=19].Wrap.Bag?resolve=1&depth=4` and `.Wrap?resolve=1&depth=4` (ID on `Wrap`, link to cert_id) | cert_id **present** | cert_id **present** | cert_id **present** |
| GET `Player[ID=20].Steal?resolve=1` (box field with an ID, `private_enc`), `text/plain` | secret **present** | secret **present** | secret **present** |
| GET `Player[ID=21].Bag?resolve=1` (ID'd array of pubkey and cert_id links) | pubkey **present**, cert_id **present** | both **present** | both **present** |
| GET `Player[ID=23].Bag?resolve=1` (ID'd nested index, sig_id_prefix) | sig **present** | sig **present** | sig **present** |
| GET `Player[ID=25].Bag?resolve=1` (lowercase `id` attribute, owner_emails), `text/plain` | owner_emails **present** | owner_emails **present** | owner_emails **present** |
| GET `Player[ID=26].Hop?resolve=1&depth=4` (ID'd two-hop to owner_emails) | owner_emails **present** | owner_emails **present** | owner_emails **present** |

### Prior closures that still hold

Same callers as the last review, except where a row names one caller. Status **403**. Every cert field **absent**. Ciphertext **absent**.

| Channel | Fields |
|---|---|
| REST GET of the short and full record, including `text/plain` and HEAD | pubkey, cert_id, owner_emails, issued, sig_id_prefix, private_enc |
| POST `/query` of the short path, `*.<field>`, `*.*`, `Record[ID=1].<field>`, `Record[ID=1].*`, `Record[ID=*].pubkey`, `*[ID=1].pubkey`, `*[ID=1].*`, surrounding whitespace, and the JSON forms | same fields |
| The same empty-file queries after a second `Record` box exists | same fields |
| REST GET `Record[ID=1].<field>` while that box is unique, including `text/plain` and `text/x-redx-box`, and the whole `Record[ID=1]` | same fields. With a sibling `Record`, REST and BoxQL of the bare record are **400**, fields **absent** |
| GET `?resolve=1` of `Player.Cert.<field>`, of a box field aimed at one cert field (including `private_enc` and `text/plain`), of a nested box field, and of a two-hop link | same fields |
| BoxQL `{Get[]}` of the short file, BoxQL `@>` into each cert field, a field link, `Min`, a left follow, and both the matching and the non-matching pubkey filter | **403**, no match/miss oracle |
| BoxQL `@>` of the no-ID array links, including `private_enc` and the whole cert | **403** |
| `prefix:` of the full file and of `rxa-lifetime-cert.red-xai` | **403**. `prefix:rxa` does not select the cert file |
| Subscribe of the full file, the short file, and the short pubkey | **403** before upgrade |
| BoxQL Watch of the full file and of the short file | **403** |
| Index exact query on cert_id, pubkey, private_enc, owner_emails, including `record=1` | **403** |
| Non-owner backup, accounts off and accounts on | **403**. No cert fields |
| Script `db_get` of the short and full record | **403** |

### Service key write

| Action | Result |
|---|---|
| PUT canonical cert | **200**. Ack fields **absent**. |
| PUT `rxa-account...idVerified` | **200**. Cert fields **absent**. |
| GET/query/BoxQL short and full names, empty-file query, unique no-file REST, box-field `?resolve=1`, no-ID array `?resolve=1`, and BoxQL `@>` | **403**. All fields **absent**. |
| GET `?resolve=1` of an ID'd field whose link targets pubkey, cert_id, owner_emails, sig_id_prefix, or `private_enc` | **200**. That field **present**. Ciphertext **present** on the `private_enc` link. |

Write and `idVerified` match the freeze. "Must not read the cert back" does not, once the link entry has an ID.

### Owner positive control

Owner session on the accounts database: **13 OWNER-OK**, **0 OWNER-FAIL**.

- GET canonical record: **200**. Ciphertext **present**. Other fields **present**.
- GET short pubkey and POST `/query` `*.pubkey`: **200**. Pubkey **present**. Ciphertext **absent**.
- POST `/query` `Record[ID=1].*`: **200**. Ciphertext **present**. Other fields **present**.
- GET `?resolve=1` of `Cert.pubkey`, of the `private_enc` field link, of the no-ID array pubkey link, of the no-ID array `private_enc` link, and of `Wrap.Bag`: **200**. The requested field **present**. Ciphertext **present** only on the `private_enc` reads.
- GET `?resolve=1` of the ID'd array pubkey link, the ID'd array `private_enc` link, the ID'd box field, and the ID'd wrap: **200**. The requested field **present**.

### Leak scan

Two real-engine servers (accounts off, and accounts on):

| Check | Result |
|---|---|
| Server log lines | 1 per server |
| Ciphertext in server logs | **absent** |
| PEM banners in server logs | **absent** |
| Audit files containing ciphertext | **0** |
| Audit files containing PEM or key headers | **0** |
| Data files containing the stored ciphertext | **2** per server |

The data-file hits are the database copies of the record the test stored. The ciphertext that is **present** is in the non-owner HTTP body of the ID'd `?resolve=1` reads above.

## Tests

Go attack suite only. Product `./...` was not re-run here. CI on this head was still running at review time and was not used as evidence.

**Harness** `go test -tags qa -count=1 -timeout 12m -run TestQALifetimeCertAttack ./host/`: exit 1. Sole failure class is LEAK. Probe classes: 37 LEAK, 436 CLOSED, 74 QUIET, 9 CONTROL-OK, 13 OWNER-OK, plus the pulse-define status line.

**CI** on `171e059` (https://github.com/grimvirusoffical-source/RedX/actions/runs/40484159756), not a merge gate for this review:

| Job | Status |
|---|---|
| linux-amd64 | pass |
| linux-amd64-go1.22 | pass |
| windows-amd64 | pending |
| macos-arm64 | pending |
| macos-intel | pending |

## HOLD conditions

Do not merge PR #22 until a non-owner, including the accounts service key, gets **403** and a body with no cert field for every read the engine will satisfy:

1. Keep the closures that already hold, including the no-ID array resolve (`Player[ID=8].Bag`, `Player[ID=9].Bag`, `Player[ID=10].Wrap.Bag`), empty-file query, unique no-file REST, box-field `?resolve=1`, short-prefix reads, and BoxQL `@>`.
2. Treat an entry ID as part of the same field. `?resolve=1` on the field name, with no ID in the request, must be **403** with every cert field **absent** when that entry's link targets the cert. This includes an ID'd array (`Bag`), an ID'd parent box (`Wrap.Bag` and `Wrap`), an ID'd box field (`Steal`), a nested index under an ID'd field, and a two-hop link stored on an ID'd field. Host-admin, a db-scoped write key, and the accounts service key are the callers. `text/plain` is included. A request that already names the ID is not this hole.
3. Keep the accounts service key able to write the cert and `idVerified` / `idVerifiedMs`, and unable to read any cert field back, including the ID'd resolve above.
4. An owner session must still be able to read the cert, including `?resolve=1` through the no-ID array and through the ID'd field.

## Harness

Leave unmerged. https://github.com/grimvirusoffical-source/RedX/pull/26 stays unmerged.

This review's harness is a separate PR against `cursor/lifetime-cert-owner-gate-7ab7`. It does not change product behavior.
