# QA security review — PR #22 lifetime-cert owner-only read

**Verdict: HOLD. Do not merge.**

| | |
|---|---|
| Target | https://github.com/grimvirusoffical-source/RedX/pull/22 |
| Head | `a210a459ada8083504f55993112dd00b3bad6769` (`cursor/lifetime-cert-owner-gate-7ab7`) |
| Prior HOLD | head `5cc7375048e7b544422b63d24c064e8fecff3c0c`, report on PR #23 |
| Product code | Unchanged. This review added only an attack harness. |
| Harness | `host/qa_lifetime_attack_test.go` (`//go:build qa`) |

The author's short-prefix and BoxQL `@>` fixes hold. The freeze does not. A non-owner, including the accounts service key, can still read every field of `rxa-lifetime-cert`, and the ciphertext comes back on two of those paths.

Field values below are **present** or **absent** only. No ciphertext, key, seed, or PEM material is included.

## What the freeze requires

From `host/accounts_guard.go` (package comment):

- Kind `rxa-lifetime-cert` (file `rxa-lifetime-cert.red-xai.db`, box `Record`) is owner-only for the **entire** record, including `private_enc`, `pubkey`, `cert_id`, `owner_emails`, `issued`, and `sig_id_prefix`.
- Non-owner reads are 403. Ciphertext must not appear in non-owner responses or audit text.
- An accounts service key may write the cert and set `idVerified` / `idVerifiedMs`, and must not read any cert field back.

## Author claim

Short-prefix names and BoxQL `@>` follows into any cert field return 403 with an empty record body, and the service key is write-only.

That claim is true for those two channels. It is not true for the other ways the engine reads a field.

## Attack result

Harness: real engine (`engineadapter.Opener`), `CodeAllowedBoxes: ["*"]` so the script sandbox is not what blocks a read. Callers: host-admin key, db-scoped write key, accounts service key (`db=redxai_accounts`, scope write), and an owner console session. The cert is stored as Box text at the canonical file. A player record holds an `@>` link to that cert. Another player holds an `@>` link aimed at one field of the cert. The test fails when a non-owner response contains a record field.

`go test -tags qa` log for `TestQALifetimeCertAttack`: **84 LEAK**, **193 CLOSED**, **27 QUIET**, **10 CLEAR**. Ciphertext **present** on 13 of the LEAK probes and **absent** on every CLOSED probe. Canary string and PEM banners in that log: **0**.

### Prior HOLD items that are closed

Same callers as the last review (host-admin, db write key, accounts service key). Status **403**. Every cert field **absent**. Ciphertext **absent**.

| Channel | Fields |
|---|---|
| REST GET `rxa-lifetime-cert.red-xai:Record[ID=1].<field>`, including `Accept: text/plain` and HEAD | pubkey, cert_id, owner_emails, issued, sig_id_prefix, private_enc |
| POST `/query` of that short path, including JSON `{"q": ...owner_emails}` | same fields |
| Script `db_get` of the short record and of the canonical record | same fields |
| BoxQL `{Get[]}` of the short file, including pubkey, cert_id, owner_emails, issued, sig_id_prefix, private_enc, star, and a `Tx` wrapper | same fields |
| BoxQL `@>` from `players:Player` into `Cert.pubkey`, `Cert.cert_id`, `Cert.owner_emails`, `Cert.issued`, `Cert.sig_id_prefix`, `Cert.private_enc`, the whole `Cert`, `Min(Cert.pubkey)`, a left follow, and a filter on `Cert.pubkey` | **403**, all fields **absent** (no match/miss oracle: both the matching filter and the non-matching filter are 403) |
| Service key GET/query/BoxQL of the short pubkey, cert_id, and the other fields, and BoxQL follow of pubkey / cert_id / owner_emails / private_enc | **403**, all fields **absent** |
| `prefix:` of the full file and of `rxa-lifetime-cert.red-xai` | **403** |
| Subscribe of the full file, the short file, and the short pubkey | **403** before upgrade |
| BoxQL Watch of the full file and of the short file | **403** (the previous short-name upgrade is gone) |

`fileNamesKind` (`host/accounts_guard.go`) now treats a name as the cert when the stored file `rxa-lifetime-cert.red-xai.db` starts with that name plus a dot. BoxQL records every `@>` target (`engine/query/get.go` `noteFollows`) and `bxLeaksLifetimeCert` (`host/accounts_guard.go`) refuses a non-owner result whose followed path is the cert, including a one-field projection.

### Still open

The gate decides from the request string. A path with no file, or a link expand that returns one field, never looks like the cert file. `TextIsLifetimeCert` (`host/accounts_guard.go`) flags a value only when it has a `private_enc` entry or **both** `cert_id` and `pubkey`. A single field string is invisible. `PathReadsLifetimeSecret` still flags any segment whose name is `private_enc`, which is why a path that spells that name 403s while a wildcard or a renamed link does not.

Observed non-owner **200**, named field **present**. Ciphertext is **present** only on the rows marked secret **present**.

| Channel | Caller | secret | other fields |
|---|---|---|---|
| POST `/query` `*.pubkey`, `*.cert_id`, `*.owner_emails`, `*.issued`, `*.sig_id_prefix`, `Record[ID=1].<field>`, `Record[ID=*].pubkey`, `*[ID=1].pubkey`, JSON `{"q":"*.pubkey"}` | host-admin, write key | absent | that field present |
| POST `/query` `*.*`, `Record[ID=1].*`, JSON `{"q":"Record[ID=1].*"}` | host-admin, write key | **present** | pubkey, cert_id, owner_emails, issued, sig_id_prefix present |
| Same `Record[ID=1].pubkey` and `Record[ID=1].*` after a second `Record` box exists (`account.red-xai.db`) | host-admin, write key | pubkey query absent; `.*` **present** | pubkey present; `.*` all fields present |
| REST GET `Record[ID=1].<field>` while that box is unique, including `Accept: text/plain` | host-admin, write key | absent | pubkey, cert_id, owner_emails, issued, sig_id_prefix present |
| GET `players...Player[ID=1].Cert.<field>?resolve=1`, including `text/plain` and `depth=4` | host-admin, write key | absent | pubkey, cert_id, owner_emails, issued, sig_id_prefix present |
| GET `?resolve=1` on the caller's own link aimed at one cert field (full file name) | host-admin, write key | **present** for the private_enc link; absent for the others | pubkey, cert_id, owner_emails, sig_id_prefix present |
| POST `/query` `*.<field>`, `*.*`, `Record[ID=1].pubkey`, `Record[ID=1].*`, JSON `{"q":"*.pubkey"}` | accounts service key, after a successful cert write | `*.*` and `Record[ID=1].*` **present**; field queries absent | pubkey, cert_id, owner_emails, issued, sig_id_prefix present on the matching query |
| GET `Player[ID=1].Cert.pubkey?resolve=1` and `Cert.cert_id?resolve=1` | accounts service key | absent | that field present |
| GET `?resolve=1` on a service-key link aimed at private_enc, `Accept: text/plain` | accounts service key | **present** | other fields absent |

`*.private_enc` and `Record[ID=1].private_enc` are **403**, ciphertext **absent**, because the segment is named `private_enc`. `*.*` and `Record[ID=1].*` are not: the engine returns each field as its own value (`engine/db.go` `tablesFor` with an empty file walks every table; `engine/table2.go` `query`), and the post-check in `host/server.go` only calls `TextIsLifetimeCert`.

REST of a bare `Record[ID=1].pubkey` uses the no-file route in `engine/db.go` (`route`): the one table whose top-level box is `Record` is the cert, until a second `Record` exists. With the sibling, that GET is **400** and every field is **absent**. The query walk does not become ambiguous; it still returns the cert field.

`GET ?resolve=1` (`host/extras_api.go` `resolveRead`) expands links and then keeps the requested field. A link to the whole cert, read as `Cert.pubkey`, returns only that string. A link whose target is already one field (`engine/link/engine.go` expand of a reference that names a field) returns that field even when the HTTP path never says `private_enc`. A link aimed at the short name `rxa-lifetime-cert.red-xai:...issued` returned **200** with every field **absent** (the short target did not resolve). The full file name did.

BoxQL `{Get[]} = Record[ID=1] -> pubkey` is **403** while `Record` is unique (the result path is the cert file). With a sibling it is **400**, fields **absent**. Script `db_get("Record[ID=1]", field)` is **403**, fields **absent**: `host/engineadapter/code.go` `recordArg` requires a file in the path, so this is not a script read of the cert. Script `db_get` of `Player.Cert.<field>` is **200** with every cert field **absent** (the link is not followed), except `Cert.private_enc`, which is **403**.

### Service key write

| Action | Result |
|---|---|
| PUT canonical cert | **200**. Ack fields **absent**. |
| PUT `rxa-account...idVerified` | **200**. Cert fields **absent**. |
| GET/query/BoxQL short and full names, and BoxQL `@>` follow | **403**. All fields **absent**. |
| Query and resolve rows in the open table above | **200**. Those fields **present**. |

Write and `idVerified` match the freeze. "Must not read the cert back" does not.

### Owner positive control

Owner session on the master database:

- GET canonical record: **200**. Ciphertext **present**. Other fields **present**.
- GET short pubkey: **200**. Pubkey **present**. Ciphertext **absent**.

### Channels that held

All of these: ciphertext **absent**, and no other cert field present, unless noted.

| Channel | Result |
|---|---|
| REST/query/BoxQL/script of the canonical file and of the short prefix, every field | **403** |
| REST `?resolve=1` of the player link field and of the player record (`depth=2`) | **403** |
| REST `Record[ID=1]` (the whole record) and `Record[ID=1].private_enc` | **403** |
| REST `rxa-lifetime-cert.red-xai.d:...` and `rxa-lifetime-cert.red:...` | **404**. All fields **absent** (not an engine prefix of the cert file) |
| `prefix:` full and short | **403** |
| POST `/query` `*` | **403** (the whole cert record fails the text check) |
| BoxQL direct Get, follow, aggregate, left follow, explain of the short pubkey Get, Tx | **403** |
| Explain of the `@>` follow | **200**. All fields **absent** (plan only; not a value leak) |
| Index exact query on cert_id, pubkey, private_enc, owner_emails, including `record=1` | **403** |
| Index check and index list | **200**, no cert fields |
| Subscribe full, short, short pubkey | **403** |
| Watch full and short | **403** |
| Subscribe `notes.red-xai.db:*` while a cert field is written | 1 frame. No cert path. No cert fields |
| Non-owner backup, accounts off and accounts on | **403**. Gzip body scanned. No cert fields |
| Console audit, file list, raw file text, cluster log, stats | **200** / **400** / **401**, no cert fields |
| Pulse rule install by host-admin | **200**, no cert fields. The copy destinations were **404**, every field **absent**. Not a demonstrated leak. Write-key install **403** |
| Player `Name` via REST and via `db_get` | **200**. Cert fields **absent** |

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

The data-file hits are the database/WAL copies of the record the test stored. That is storage, not an audit or log leak.

## Tests

Go 1.22.2. Product tests do not build the harness (`//go:build qa`). The harness failure is the finding.

**`go test ./... -json -count=1 -timeout 25m`** (no `qa` tag):

| | pass | fail | skip |
|---|---:|---:|---:|
| Tests | 757 | 0 | 2 |
| Packages | 17 | 0 | 5 |

Skipped tests: `redx/engine.TestChildWriter`, `redx/cmd/redxd.TestConsolePagesHeadlessChrome`. Skipped packages: `host/accountsfake`, `host/client`, `host/internal/stubstore`, `host/stubopen`, `scripts/fake-accounts`.

**`go test -race -count=1 -p 2 -timeout 40m ./...`** (no `qa` tag): same totals, exit 0. No data race. `redx/host` ok.

**Harness** `go test -tags qa -count=1 -timeout 6m -run TestQALifetimeCertAttack ./host/`: exit 1. Sole failure `TestQALifetimeCertAttack`. Probe classes: 84 LEAK, 193 CLOSED, 27 QUIET, 10 CLEAR, 3 control ok, 2 owner ok.

**Harness under `-race`** `go test -race -tags qa -count=1 -timeout 15m -run 'TestQALifetimeCertAttack|TestPathAndTextLifetimeCert|TestGuardBoxQL|TestLifetimeCertOwnerOnly' ./host/`: 3 pass, 1 fail (`TestQALifetimeCertAttack`). No data race.

## HOLD conditions

Do not merge PR #22 until a non-owner, including the accounts service key, gets **403** and a body with no cert field for every read the engine will satisfy:

1. Keep the short-prefix and `@>` follow closures. They are doing the job.
2. Treat an empty-file query (`*.pubkey`, `*.*`, `Record[ID=1].pubkey`, `Record[ID=1].*`, `*[ID=1].pubkey`) as a cert read when any selected value is a field of the cert, not only when the path names the cert file or a segment is spelled `private_enc`. A second `Record` box must not leave the cert field in the combined result.
3. Treat a no-file REST get that uniquely routes to the cert the same way. `Record[ID=1].pubkey` (and the other fields, including `text/plain`) must be 403 while that box is unique.
4. Treat link expand as a cert read when the expanded value is a cert field or the cert record: `?resolve=1` on `Player.Cert.<field>`, and `?resolve=1` on a link whose target is one cert field, including `private_enc`. The response must not contain that field.
5. Keep the accounts service key able to write the cert and `idVerified` / `idVerifiedMs`, and unable to read any cert field back on the query and resolve paths above.

The ciphertext controls that already hold (named `private_enc` paths, owner read, backup, index, subscribe, watch, console, cluster log) can stay as they are.
