# QA security review — PR #22 lifetime-cert owner-only read

**Verdict: HOLD. Do not merge.**

| | |
|---|---|
| Target | https://github.com/grimvirusoffical-source/RedX/pull/22 |
| Head | `86f6275cde42f3078a56c6ae8fc2c7f881a55855` (`cursor/lifetime-cert-owner-gate-7ab7`) |
| Prior HOLD | head `a210a459ada8083504f55993112dd00b3bad6769`, report on PR #25 |
| Product code | Unchanged. This review added only an attack harness. |
| Harness | `host/qa_lifetime_attack_test.go` (`//go:build qa`) |

The author's empty-file query, unique no-file REST, and box-field `?resolve=1` fixes hold. The freeze does not. A non-owner, including the accounts service key, can still read a cert field when the link sits in an array. On that path the ciphertext comes back.

Field values below are **present** or **absent** only. No ciphertext, key, seed, or PEM material is included.

## What the freeze requires

From `host/accounts_guard.go` (package comment):

- Kind `rxa-lifetime-cert` (file `rxa-lifetime-cert.red-xai.db`, box `Record`) is owner-only for the **entire** record, including `private_enc`, `pubkey`, `cert_id`, `owner_emails`, `issued`, and `sig_id_prefix`.
- Non-owner reads are 403. Ciphertext must not appear in non-owner responses or audit text.
- An accounts service key may write the cert and set `idVerified` / `idVerifiedMs`, and must not read any cert field back.

## Author claim for this head

Empty-file query, unique no-file REST, and `?resolve=1` now gate on the file or link target the engine resolved, not the request path string. Short-prefix and BoxQL `@>` closures are kept.

That claim is true for empty-file query, for unique no-file REST, and for `?resolve=1` when the link is a box field. It is not true when the link is an element of an array.

## Attack result

Harness: real engine (`engineadapter.Opener`), `CodeAllowedBoxes: ["*"]` so the script sandbox is not what blocks a read. Callers: host-admin key, db-scoped write key, accounts service key (`db=redxai_accounts`, scope write), and an owner console session. The cert is stored as Box text at the canonical file. A player record holds an `@>` link to that cert, links aimed at one field, a two-hop link, a nested box link, and array links. The test fails when a non-owner response contains a record field.

`go test -tags qa` log for `TestQALifetimeCertAttack`: **10 LEAK**, **344 CLOSED**, **55 QUIET**, **9 CONTROL-OK**, **8 OWNER-OK**, plus one pulse-define status line (**200**, cert fields **absent**). Ciphertext **present** on 3 of the LEAK probes (the array link aimed at `private_enc`, for each non-owner caller) and **absent** on every CLOSED and QUIET probe. Canary string and PEM banners in that log: **0**.

### Prior HOLD items that are closed

Same callers as the last review (host-admin, db write key, accounts service key), except where a row names one caller. Status **403**. Every cert field **absent**. Ciphertext **absent**.

| Channel | Fields |
|---|---|
| REST GET `rxa-lifetime-cert.red-xai:Record[ID=1].<field>`, including `Accept: text/plain` and HEAD | pubkey, cert_id, owner_emails, issued, sig_id_prefix, private_enc |
| POST `/query` of that short path, including JSON `{"q": ...owner_emails}` | same fields |
| Script `db_get` of the short record and of the canonical record | same fields |
| BoxQL `{Get[]}` of the short file, including pubkey, cert_id, owner_emails, issued, sig_id_prefix, private_enc, star, and a `Tx` wrapper | same fields |
| BoxQL `@>` from `players:Player` into `Cert.pubkey`, `Cert.cert_id`, `Cert.owner_emails`, `Cert.issued`, `Cert.sig_id_prefix`, `Cert.private_enc`, the whole `Cert`, `Min(Cert.pubkey)`, a left follow, and a filter on `Cert.pubkey` | **403**, all fields **absent** (no match/miss oracle: both the matching filter and the non-matching filter are 403) |
| BoxQL `@>` of a link aimed at one field, including `private_enc` | **403**, all fields **absent** |
| Service key GET/query/BoxQL of the short pubkey, cert_id, and the other fields, and BoxQL follow of pubkey / cert_id / owner_emails / private_enc | **403**, all fields **absent** |
| `prefix:` of the full file and of `rxa-lifetime-cert.red-xai` | **403** |
| Subscribe of the full file, the short file, and the short pubkey | **403** before upgrade |
| BoxQL Watch of the full file and of the short file | **403** |

### Empty-file query, unique no-file REST, and box-field resolve — closed

These are the rows the previous HOLD left open. On this head they are **403**, every cert field **absent**, ciphertext **absent**, for host-admin, the db write key, and the accounts service key.

| Channel | Result |
|---|---|
| POST `/query` `*.<field>`, `*.*`, `Record[ID=1].<field>`, `Record[ID=1].*`, `Record[ID=*].pubkey`, `*[ID=1].pubkey`, `*[ID=1].*`, and the same with surrounding whitespace | **403**. `*.*` and `Record[ID=1].*` do not return ciphertext |
| JSON `{"q":"*.pubkey"}`, `{"q":"*.*"}`, `{"q":"Record[ID=1].pubkey"}`, `{"q":"Record[ID=1].*"}` | **403** |
| The same `Record[ID=1].pubkey`, `*.pubkey`, `*.*`, and `Record[ID=1].*` after a second `Record` box exists (`account.red-xai.db` or `rxa-account.red-xai.db`) | **403**. Ciphertext **absent** |
| REST GET `Record[ID=1].<field>` while that box is unique, including `Accept: text/plain` and `Accept: text/x-redx-box`, and HEAD of `Record[ID=1].pubkey` | **403** |
| REST GET `Record[ID=1]` (the whole record) while unique | **403** |
| GET `players...Player[ID=1].Cert.<field>?resolve=1`, including `text/plain`, `depth=4`, and `resolve=true` | **403** |
| GET `?resolve=1` on a box field whose link target is one cert field (full file name), including `private_enc` with `Accept: text/plain` | **403**. Ciphertext **absent** |
| GET `?resolve=1` on a nested box field (`Meta.Steal`, and the parent `Meta`) and on a two-hop link (`Hop.Ptr`, and the parent `Hop`), `depth=4` | **403** |
| Service key on every row above, before and after a successful `idVerified` write where a second `Record` exists | **403** |

`*.private_enc` and `Record[ID=1].private_enc` stay **403**. The new check is the stored path on each query hit (`QueryHits` / `QuerySourced`) and the stored file on a no-file REST get (`GetFile` / `GetRouted`). A single field string is still invisible to `TextIsLifetimeCert`; the path is what closes these rows.

With a second `Record` box, REST `Record[ID=1].pubkey` is **400** and every field is **absent** (the route is ambiguous). BoxQL `{Get[]} = Record[ID=1] -> pubkey` is **403** while `Record` is unique and **400** with every field **absent** once a sibling exists. Script `db_get("Record[ID=1]", field)` is **403**, fields **absent**: `recordArg` still requires a file, so this is not a script read of the cert. Script `db_get` of `Player.Cert.<field>` is **200** with every cert field **absent** (the link is not followed), except `Cert.private_enc`, which is **403**.

### Still open

`?resolve=1` records each substituted link (`Expansion.Copied`) and `resolveReadsCert` keeps the copy only when `certExpandFeeds` says that link is part of the selected field. For a box field the recorded path is the entry name (`Cert`, `Meta.Steal`), and those reads are **403**. For an array element the recorded path is `Bag[0]` (a 0-based index). The request segment is `Bag`. Those strings are not equal, so the copy is ignored. The selected value is then one field string. `TextIsLifetimeCert` does not treat that string as a cert body, so the response is **200** and the field is **present**. When the link target is `private_enc`, the ciphertext is **present**.

`Bag[0]` itself is not a Box path to the array element: GET `Player[ID=8].Bag[0]?resolve=1` is **404**, every field **absent**. The leak is the array field.

A link to the **whole** cert record, stored in an array, is still **403** (the expanded value is a cert body). Reading the player record that contains the array is **403**. Reading the parent box of a nested array (`Wrap`) is **403**. BoxQL `{Get[]} = players:Player[ID=8] -> Bag @> Bag` is **403** (the followed record path is the cert file). The hole is HTTP resolve of the array field.

Observed non-owner **200**, named field **present**. Ciphertext is **present** only on the rows marked secret **present**. Owner sessions on the same URLs return **200** with that field **present** (positive control).

| Channel | Caller | secret | other fields |
|---|---|---|---|
| GET `Player[ID=8].Bag?resolve=1` (array link aimed at pubkey), including `depth=4` and `Accept: text/plain` | host-admin, write key | absent | pubkey **present** |
| GET `Player[ID=9].Bag?resolve=1` (array link aimed at private_enc), including `Accept: text/plain` | host-admin, write key | **present** | other fields absent |
| GET `Player[ID=10].Wrap.Bag?resolve=1&depth=4` (link inside a nested array, aimed at cert_id) | host-admin, write key | absent | cert_id **present** |
| GET `Player[ID=8].Bag?resolve=1&depth=4` | accounts service key, after a successful cert write | absent | pubkey **present** |
| GET `Player[ID=9].Bag?resolve=1`, `Accept: text/plain` | accounts service key | **present** | other fields absent |

### Service key write

| Action | Result |
|---|---|
| PUT canonical cert | **200**. Ack fields **absent**. |
| PUT `rxa-account...idVerified` | **200**. Cert fields **absent**. |
| GET/query/BoxQL short and full names, empty-file query, unique no-file REST, box-field `?resolve=1`, and BoxQL `@>` follow | **403**. All fields **absent**. |
| GET `?resolve=1` of an array field whose link targets pubkey or `private_enc` | **200**. That field **present**. Ciphertext **present** on the `private_enc` link. |

Write and `idVerified` match the freeze. "Must not read the cert back" does not, for the array resolve.

### Owner positive control

Owner session on the master database:

- GET canonical record: **200**. Ciphertext **present**. Other fields **present**.
- GET short pubkey: **200**. Pubkey **present**. Ciphertext **absent**.
- POST `/query` `*.pubkey`: **200**. Pubkey **present**. Ciphertext **absent**.
- POST `/query` `Record[ID=1].*`: **200**. Ciphertext **present**. Other fields **present**.
- GET `?resolve=1` of `Cert.pubkey` and of the `private_enc` field link: **200**. The requested field **present**. Ciphertext **present** only on the `private_enc` read.
- GET `?resolve=1` of the array pubkey link and of the array `private_enc` link: **200**. That field **present**. Ciphertext **present** only on the `private_enc` read.

### Channels that held

All of these: ciphertext **absent**, and no other cert field present, unless noted.

| Channel | Result |
|---|---|
| REST/query/BoxQL/script of the canonical file and of the short prefix, every field | **403** |
| REST `?resolve=1` of the player link field and of the player record (`depth=2`), including a player whose cert link is inside an array | **403** |
| REST `Record[ID=1]` and `Record[ID=1].private_enc` while `Record` is unique | **403** |
| REST `rxa-lifetime-cert.red-xai.d:...` and `rxa-lifetime-cert.red:...` | **404**. All fields **absent** |
| `prefix:` full and short | **403**. `prefix:rxa` is **200**, all fields **absent** (not an engine prefix of the cert file) |
| POST `/query` `*` | **403** |
| BoxQL direct Get, follow, aggregate, left follow, filter, explain of the short pubkey Get, Tx, and `@>` through an array link | **403** |
| Explain of the `@>` follow and of a bare `Record[ID=1] -> pubkey`, including JSON `"explain":true` | **200**. All fields **absent** (plan only) |
| BoxQL `{Get[]} = * -> pubkey` | **400**. All fields **absent** |
| Index exact query on cert_id, pubkey, private_enc, owner_emails, including `record=1` | **403** |
| Index check and index list | **200**, no cert fields |
| Subscribe full, short, short pubkey | **403** |
| Watch full and short | **403** |
| Subscribe `*` and subscribe `Record` (no file) | **400** before upgrade. All fields **absent** |
| Watch `{Watch[]} = Record` (no file) | **400**. All fields **absent** |
| Subscribe `notes.red-xai.db:*` while a cert field is written | 1 frame. Cert path **absent**. No cert fields |
| A link target with no file name | **400** at PUT. Box grammar requires a file on the reference, so this is not a stored read |
| Short-prefix link target `rxa-lifetime-cert.red-xai:...issued`, GET `?resolve=1` | **200**. All fields **absent** (the short target does not resolve; not a field value) |
| Non-owner backup, accounts off and accounts on | **403**. Gzip body scanned. No cert fields |
| Console audit, file list, raw file text, cluster log, stats, script list | **200** / **400** / **401**, no cert fields |
| Pulse rule install by host-admin, with the destination notes created first, then a trigger write | **200** on install. The copy destinations stay the placeholder. Cert fields **absent**. Not a demonstrated leak. Write-key install **403** |
| Player `Name` via REST, via `?resolve=1`, and via `db_get` | **200**. Cert fields **absent** |
| Host-admin GET/query of the master database | **404**. All fields **absent** |

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

The data-file hits are the database/WAL copies of the record the test stored. That is storage, not an audit or log leak. The ciphertext that is **present** is in the non-owner HTTP body of the array `?resolve=1` reads above.

## Tests

Go 1.22.2. Product tests do not build the harness (`//go:build qa`). The harness failure is the finding.

**`go test ./... -json -count=1 -timeout 25m`** (no `qa` tag):

| | pass | fail | skip |
|---|---:|---:|---:|
| Tests | 760 | 0 | 2 |
| Packages | 17 | 0 | 5 |

Skipped tests: `redx/engine.TestChildWriter`, `redx/cmd/redxd.TestConsolePagesHeadlessChrome`. Skipped packages: `host/accountsfake`, `host/client`, `host/internal/stubstore`, `host/stubopen`, `scripts/fake-accounts`.

**Harness** `go test -tags qa -count=1 -timeout 12m -run TestQALifetimeCertAttack ./host/`: exit 1. Sole failure `TestQALifetimeCertAttack`. Probe classes: 10 LEAK, 344 CLOSED, 55 QUIET, 9 CONTROL-OK, 8 OWNER-OK, plus the pulse-define status line.

**Harness under `-race`** `go test -race -tags qa -count=1 -timeout 15m -run 'TestQALifetimeCertAttack|TestPathAndTextLifetimeCert|TestGuardBoxQL|TestLifetimeCertOwnerOnly|TestLifetimeCertResolved' ./host/`: `TestQALifetimeCertAttack` fails with the same 10 LEAK rows. `TestPathAndTextLifetimeCert`, `TestGuardBoxQL`, `TestLifetimeCertOwnerOnly`, and `TestLifetimeCertResolvedReadsOnEngine` pass. No data race.

**`go test -race -count=1 -p 2 -timeout 40m ./...`** (no `qa` tag): same totals as the non-race run (tests 760 pass, 0 fail, 2 skip; packages 17 pass, 5 skip), exit 0. No data race. `redx/host` ok.

## HOLD conditions

Do not merge PR #22 until a non-owner, including the accounts service key, gets **403** and a body with no cert field for every read the engine will satisfy:

1. Keep the closures that already hold: short-prefix REST/query/scripts/BoxQL, BoxQL `@>` into any cert field, empty-file query (`*.pubkey`, `*.*`, `Record[ID=1].pubkey`, `Record[ID=1].*`, `*[ID=1].pubkey`, JSON forms, including a second `Record` box), and unique no-file REST `Record[ID=1].<field>` (including `text/plain`) while that box is unique.
2. Keep `?resolve=1` closed for a box field (`Player.Cert.<field>` and a link aimed at one cert field, including `private_enc` and `text/plain`).
3. Treat an array element the same way. `?resolve=1` on the array field, and on a nested array field, must be **403** with every cert field **absent** when any substituted link targets the cert, including a link aimed at `private_enc`. Host-admin, a db-scoped write key, and the accounts service key are the callers. `text/plain` is included. A `Bag[0]` path that does not select the array is not this hole.
4. Keep the accounts service key able to write the cert and `idVerified` / `idVerifiedMs`, and unable to read any cert field back, including the array resolve above.
5. An owner session must still be able to read the cert, including `?resolve=1` through that array.

The ciphertext controls that already hold (named `private_enc` paths, whole-record array expand, BoxQL `@>` of the same array, owner read, backup, index, subscribe, watch, console, cluster log) can stay as they are.
