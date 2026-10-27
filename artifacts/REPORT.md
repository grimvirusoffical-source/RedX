# QA security review — PR #22 lifetime-cert owner-only read

**Verdict: HOLD. Do not merge.**

| | |
|---|---|
| Target | https://github.com/grimvirusoffical-source/RedX/pull/22 |
| Head | `5cc7375048e7b544422b63d24c064e8fecff3c0c` (`cursor/lifetime-cert-owner-gate-7ab7`) |
| Author agent | bc-bfc34418 |
| Reviewer run | bc-7ed799a7-8281-5603-b9e3-64b809a20b1d |
| Product code | Unchanged. This review added only an attack harness. |
| Harness | `host/qa_lifetime_attack_test.go` on `qa/lifetime-cert-acl-0b1d` |

Ciphertext did not leak. The freeze still fails: a non-owner can read every field of `rxa-lifetime-cert` except `private_enc`, and the accounts service key can read `pubkey` and `cert_id` back after writing the record.

Field values below are **present** or **absent** only. No ciphertext, key, seed, or PEM material is included.

## What the freeze requires

From `host/accounts_guard.go:5-23`:

- Kind `rxa-lifetime-cert` (file `rxa-lifetime-cert.red-xai.db`, box `Record`) is owner-only for the **entire** record, including `private_enc`.
- Non-owner reads are 403. Ciphertext must not appear in non-owner responses or audit text.
- An accounts service key (API key bound to the master accounts database) may write the cert and set `idVerified` / `idVerifiedMs`, and must not read the cert back.
- `pubkey` and `cert_id` are owner-only on purpose: the host has no signature-verification reader.

## Author note (pubkey / cert_id public half)

**Intentional and non-blocking for this PR.** Not a HOLD by itself.

`docs/connect.md` describes Rotten Apple / RottenCore as PKCE plus a host pin. Nothing in this tree reads `pubkey` or `cert_id` to verify a lifetime cert. Keeping those fields owner-only does not block a host verify path, because that path does not exist yet. The HOLD is that the implementation does not enforce the owner-only rule the PR states. `owner_emails` is not a public half, and it leaks with the other non-secret fields.

## Attack result

Harness: real engine (`engineadapter.Opener`), `CodeAllowedBoxes: ["*"]` so the script sandbox is not what blocks a read. Callers: host-admin key, db-scoped write key, accounts service key (`db=redxai_accounts`, scope write), and an owner console session. The cert is stored as Box text at the canonical file. A player record holds an `@>` link to that cert. The test fails on purpose when a non-owner response contains a record field.

`go test -race` log for `TestQALifetimeCertAttack`: **21 LEAK**, **0 MISS**. Ciphertext **absent** on every non-owner body. Canary string, `PRIVATE KEY`, and `BEGIN` headers in that log: **0**.

### 1. Short file prefix (REST, path query, scripts, service key)

The engine resolves a file by unique prefix. `engine/db.go:271` and `engine/db.go:340` match a stored name when it has prefix `requested + "."`. `engine/query/exec.go:560` does the same for BoxQL. The stored file `rxa-lifetime-cert.red-xai.db` therefore answers requests for `rxa-lifetime-cert.red-xai`.

The gate does not. `namesKind` (`host/accounts_guard.go:46-52`) accepts only the bare kind or the exact `*.red-xai.db` file. `pathNamesKind` (`host/accounts_guard.go:62-75`, the prefix at line 74) accepts `rxa-lifetime-cert.red-xai.db...` and `rxa-lifetime-cert:...`. It does not accept `rxa-lifetime-cert.red-xai:Record[ID=1].<field>`.

`PathReadsLifetimeSecret` (`host/accounts_guard.go:79-93`) still catches a segment named `private_enc`, which is why the ciphertext field 403s on the short path. `TextIsLifetimeCert` (`host/accounts_guard.go:140-163` and `218-232`) flags a value only when it contains `private_enc` or **both** `cert_id` and `pubkey`. A single field string is invisible to the post-check.

REST applies that post-check to the returned field string at `host/server.go:372-374`. Path query does the same at `host/server.go:557-580` after `queryReadsLifetimeCert` (`host/accounts_guard.go:316-324`). Scripts check `ScriptCertReadBlocked` (`host/accounts_guard.go:593-597`, called from `host/engineadapter/code.go:206-218`) and then `TextIsLifetimeCert` on the field text; the HTTP response scan at `host/services_api.go:539-543` uses the same detector.

Observed non-owner **200**, ciphertext **absent**, named field **present**:

| Channel | Caller | Fields |
|---|---|---|
| REST GET `rxa-lifetime-cert.red-xai:Record[ID=1].<field>` | host-admin | pubkey, cert_id, owner_emails, issued, sig_id_prefix |
| REST GET same pubkey path | db write key | pubkey |
| REST GET pubkey, `Accept: text/plain` | host-admin | pubkey |
| POST `/query` short pubkey, short cert_id | host-admin | pubkey, cert_id |
| POST `/query` JSON `{"q": short owner_emails}` | host-admin | owner_emails |
| Script `db_get(short record, field)` | db write key | pubkey, cert_id, owner_emails, issued, sig_id_prefix |
| REST GET short pubkey and short cert_id | accounts service key | pubkey, cert_id |
| POST `/query` short pubkey | accounts service key | pubkey |

The harness logs this directly: `gate does not flag shortened pubkey path`, `script gate does not flag shortened pubkey`, `script gate does not flag shortened cert_id`, and `gate flags shortened private_enc path`.

`prefix:` queries and subscribe use `prefixSelectsCert` (`host/accounts_guard.go:327-342`), which treats any string starting with `rxa-lifetime-cert.` as the cert. Those two channels 403 the short name. REST, path query, and `db_get` do not use that helper.

### 2. BoxQL link follow

Direct BoxQL `Get` of the short file **403s**, including a pubkey projection. Result `Paths` are the resolved full file (`host/engineadapter/bx.go:273-274` via `recPath` at `host/engineadapter/extras.go:127-133`), and `bxLeaksLifetimeCert` (`host/accounts_guard.go:553-567`) flags those paths. That is why a short-name Get is blocked only after the engine rewrites the name.

Follow is not a cert read unless the link field itself is named `private_enc` (`stmtReadsLifetimeCert`, `host/accounts_guard.go:470-473`). A player link `Cert @> <cert record>` therefore passes `guardBoxQL` (`host/services_api.go:212-214`). The follow result's paths are the player. Column `Cert.pubkey` is not `private_enc`. The cell is a bare string, so `TextIsLifetimeCert` misses it (`host/accounts_guard.go:569-581`).

Observed non-owner **200**, ciphertext **absent**, named field **present** (db write key):

- `{Get[]} = players:Player[ID=1] -> [Name, Cert.pubkey] @> Cert`
- same shape for `Cert.cert_id`
- same shape for `Cert.owner_emails`

`Cert.private_enc` is **403**, ciphertext **absent**. Projecting the whole followed `Cert` is **200** with every scanned record field **absent** (not a demonstrated field leak). `{Explain[]}` of the short pubkey Get is **200** with every field **absent**.

The attacker only needs a writable record of their own. The cert path is the fixed kind file.

### Service key

| Action | Result |
|---|---|
| PUT canonical cert | **200**. Ack ciphertext **absent**. |
| PUT `rxa-account...idVerified` | **200**. No cert fields. |
| GET canonical record and `.private_enc` | **403**. All fields **absent**. |
| GET short whole record | **403**. All fields **absent**. |
| BoxQL full record and short pubkey | **403**. All fields **absent**. |
| GET short pubkey, GET short cert_id, query short pubkey | **200**. That field **present**. Ciphertext **absent**. |

Write and `idVerified` match the freeze. "Must not read the cert back" does not: the service key reads `pubkey` and `cert_id` through the short prefix.

### Owner positive control

Owner session on the master database:

- GET canonical record: **200**. Ciphertext **present**. Other fields **present**.
- GET `.private_enc`: **200**. Ciphertext **present**. Other fields **absent**.
- GET short pubkey: **200**. Pubkey **present**. Ciphertext **absent**.
- GET `/v1/admin/backup`: **200**. Inflated archive ciphertext **present**.

### Channels that held

All of these: ciphertext **absent**, and no other cert field present, unless noted.

| Channel | Result |
|---|---|
| REST/HEAD/box-accept of the canonical record and of pubkey, cert_id, owner_emails, private_enc | **403** |
| REST short whole record and short `private_enc` | **403** |
| REST `?resolve=1` on the player link and on the player record | **403** |
| Path query of the canonical record, canonical pubkey, `*`, short whole record, short `private_enc` | **403** (`*` is refused by the row scan at `host/server.go:574-579`, because the row is the whole cert) |
| `prefix:` of the full file and of the short prefix | **403** |
| BoxQL direct Get, full and short file, including pubkey, star, filter, alias of `private_enc`, and a `Tx` wrapper | **403** |
| BoxQL link `private_enc` | **403** |
| Index exact query on cert_id, pubkey, private_enc, owner_emails, including `record=1` | **403** (`host/extras_api.go:365-368` and `426-438`; hit paths are the stored full file) |
| Index check and index list | **200**, no cert fields |
| Script `db_get` of the canonical path, every field, and short `private_enc` | **403** |
| Script read of the link field itself | **200**, no cert fields (the link text, not a cert field) |
| Subscribe full file, short file, and short pubkey | **403** before upgrade (`host/ws.go:41-43`; short names hit `prefixSelectsCert` at `host/accounts_guard.go:355`) |
| BoxQL Watch of the full file | **403** |
| Subscribe `notes.red-xai.db:*` while a cert field is written | 1 note frame. No cert path. No cert fields. Filter: `host/ws.go:93` |
| Pulse `changes=1` while the cert record is rewritten | 1 note frame (`pulse-qa`). No cert path. No cert fields. Filter: `host/ws.go:160` |
| Non-owner backup, accounts off and accounts on | **403**. Gzip body scanned. No cert fields (`host/backup.go:356-358`) |
| Console audit, status, config, file list, whoami, stats, unrelated player name | **200**, no cert fields |
| Console raw text of `rxa-lifetime-cert.red-xai.db` | **400** (`host/admin_api.go:579`) |
| Owner overview and owner accounts as a non-owner | **403** |
| Cluster log and snapshot with a user API key | **401** (`host/cluster.go:808-812`; node auth, not a user key) |

### Watch of the short file

BoxQL Watch of `"rxa-lifetime-cert.red-xai":Record` upgrades (**101**). `guardBoxQL` uses `sourceIsKind` (`host/accounts_guard.go:358-359`, `487-491`), which misses the short name, so `host/services_api.go:302` does not 403. After a cert field write, **0 frames** in 1.5s, cert path **absent**, ciphertext **absent**. The event filter at `host/services_api.go:345` drops frames whose path is the resolved full file. This is a gate inconsistency, not a demonstrated data leak, and it is not the HOLD by itself.

### Leak scan

Two real-engine servers (accounts off, and accounts on):

| Check | Result |
|---|---|
| Server log lines | 1 per server |
| Ciphertext in server logs | **absent** |
| PEM / `PRIVATE KEY` / `BEGIN` in server logs | **absent** |
| Audit files containing ciphertext | **0** |
| Audit files containing PEM or key headers | **0** |
| Data files containing the stored ciphertext | **2** per server |

The data-file hits are the database/WAL copies of the record the test stored. That is storage, not an audit or log leak. Audit denial reasons are the static string from `denyLifetimeCert` (`host/accounts_guard.go:296-302`) and `redactAuditReason` (`host/accounts_guard.go:289-294`).

## Tests

Go 1.22.2. The only failure in both runs is `redx/host.TestQALifetimeCertAttack`. That failure is the finding. Product tests passed.

**`go test ./... -json -count=1 -timeout 25m`** (same tree, before `-race`):

| | pass | fail | skip |
|---|---:|---:|---:|
| Tests | 756 | 1 | 2 |
| Packages | 16 | 1 | 5 |

Failing package: `redx/host`. Failing test: `TestQALifetimeCertAttack`.

**`go test -race -count=1 -p 2 -timeout 35m ./...`** (this review; exit 1):

| Result | Packages |
|---|---|
| ok (16) | billing, box, cmd/redx, cmd/redx-launcher, cmd/redxd, engine, engine/code, engine/idx, engine/link, engine/media, engine/pack, engine/pulse, engine/query, engine/sec, host/engineadapter, scripts/gensdk |
| FAIL (1) | `redx/host` (86.641s). Sole `--- FAIL`: `TestQALifetimeCertAttack` (5.63s) |
| no tests (5) | host/accountsfake, host/client, host/internal/stubstore, host/stubopen, scripts/fake-accounts |

`-race` was package-level plus the failing test's log. It was not re-counted with `-json`, so the 756/1/2 test totals are the non-race run. No race failure other than the harness.

Existing product tests (`host/accounts_lifetime_test.go`, `host/engineadapter/services_test.go` `TestScriptCannotReadLifetimeCert`) use the canonical full filename. They do not cover the unique-prefix alias or `@>` follow, which is why they stay green.

## HOLD conditions

Do not merge PR #22 until a non-owner, including the accounts service key, gets **403** and an empty body for every field of the cert, on every name the engine will resolve:

1. Treat the engine's unique file prefix as the cert kind wherever `namesKind` / `pathNamesKind` decide a read. REST, path query, and `db_get` must use the same rule `prefixSelectsCert` already uses for subscribe.
2. Treat a BoxQL follow whose target is the cert as a cert read, and treat a projected cert field (not only a column named `private_enc`, and not only a cell that contains both `cert_id` and `pubkey`) as a leak in `bxLeaksLifetimeCert`.
3. Keep the accounts service key able to write the cert and `idVerified` / `idVerifiedMs`, and unable to read any cert field back.

The ciphertext controls, owner read, backup, index, subscribe, console, and cluster-log checks above can stay as they are.
