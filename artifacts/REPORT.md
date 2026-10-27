# QA security review — PR #22 lifetime-cert owner-only read

**Verdict: HOLD. Do not merge.**

| | |
|---|---|
| Target | https://github.com/grimvirusoffical-source/RedX/pull/22 |
| Head | `6455153efebac10308bd27d1dc422df88fbd9125` (`cursor/lifetime-cert-owner-gate-7ab7`) |
| Prior HOLD | head `171e059f4ea5b63dd0a624c047116e13490da506`, report on PR #27 |
| Product vs `171e059` | `expandStepMatches` now strips one leading `[ID=n]` / `[id=n]` before numeric indexes (`host/accounts_guard.go`). |
| Harness | `host/qa_lifetime_attack_test.go` (`//go:build qa`) on `cursor/qa-lifetime-cert-id-retest-a0ea`. Not merged. PR #26 and PR #27 left unmerged. |

Field values below are **present** or **absent** only. No ciphertext, key, seed, or PEM material is included.

## What the freeze requires

From `host/accounts_guard.go`:

- Kind `rxa-lifetime-cert` is owner-only for the entire record, including `private_enc`, `pubkey`, `cert_id`, `owner_emails`, `issued`, and `sig_id_prefix`.
- Non-owner reads are 403. Ciphertext must not appear in non-owner responses or audit text.
- An accounts service key may write the cert and set `idVerified` / `idVerifiedMs`, and must not read any cert field back.

## Author claim for this head

`expandStepMatches` treats a leading `[ID=n]` or `[id=n]`, then numeric indexes, as inside the bare field name. Claimed closed for host-admin, a db write key, and the accounts service key: ID'd Bag, Wrap / Wrap.Bag, Steal, lowercase `id`, nested index, and two-hop Hop are 403, with no cert fields and no ciphertext. Owner reads of those URLs stay 200. Prior closures kept. Author notes unmerged harness #27 as 0 LEAK. That harness result was not used as evidence.

The claim holds for every prior ID'd-entry row and every prior no-ID array row. It does not hold when the recorded entry ID is negative, or when the number parser stores the attribute as a negative int64. On that path a non-owner, including the accounts service key, still receives the cert field. When the link targets `private_enc`, the ciphertext comes back.

## Attack result

Harness: real engine (`engineadapter.Opener`), `CodeAllowedBoxes: ["*"]` so the script sandbox is not what blocks a read. The harness raises the per-key rate burst so a 429 is not what ends a probe. Callers: host-admin key, db-scoped write key, accounts service key (`db=redxai_accounts`, scope write), and an owner console session.

`go test -tags qa -count=1 -timeout 15m -run TestQALifetimeCertAttack ./host/`: **exit 1**. **78 LEAK**, **686 CLOSED**, **114 QUIET**, **3 CLEAR**, **12 CONTROL-OK**, **20 OWNER-OK**, plus one pulse-define status line (**200**, cert fields **absent**). Ciphertext **present** on 24 of the LEAK probes and **absent** on every CLOSED, QUIET, and CLEAR probe. PEM banners in server logs: **0**.

The 3 CLEAR lines are HEAD of `Player[ID=31].Bag?resolve=1`. Status **200**, body empty, every cert field **absent**. The same URL with GET returns the ciphertext. HEAD did not disclose the field. It also did not return 403.

### Prior ID'd rows the author closed

Status **403**. Every cert field **absent**. Ciphertext **absent**. Owner on the same URL is **200** with the requested field **present**.

| Channel | host-admin | write key | accounts service | owner |
|---|---|---|---|---|
| GET `Player[ID=17].Bag?resolve=1` (ID'd array, pubkey), including `text/plain`, `resolve=true`, `depth=1`, `depth=4`, `Bag[id=0]`, `Bag[Id=0]`, `Bag[iD=0]`, `Bag[ ID = 0 ]`, HEAD | 403, pubkey **absent** | 403, pubkey **absent** | 403, pubkey **absent** | 200, pubkey **present**, ciphertext **absent** |
| GET `Player[ID=18].Bag?resolve=1` (ID'd array, `private_enc`), including `text/plain`, JSON, `text/x-redx-box`, `*/*`, `text/html`, `application/octet-stream`, `text/plain; charset=utf-8`, param order `depth=4&resolve=1`, `resolve=true&depth=32`, HEAD | 403, ciphertext **absent** | 403, ciphertext **absent** | 403, ciphertext **absent** | 200, ciphertext **present** |
| GET `Player[ID=19].Wrap.Bag?resolve=1&depth=4` and `.Wrap?resolve=1&depth=4`, including `Wrap[id=3].Bag` and `Wrap[ID=3]` | 403, cert_id **absent** | 403, cert_id **absent** | 403, cert_id **absent** | 200, cert_id **present**, ciphertext **absent** |
| GET `Player[ID=20].Steal?resolve=1` (box field with an ID, `private_enc`), `text/plain`, `Steal[id=1]`, HEAD | 403, ciphertext **absent** | 403, ciphertext **absent** | 403, ciphertext **absent** | 200, ciphertext **present** |
| GET `Player[ID=21].Bag?resolve=1` (ID'd array of pubkey and cert_id links), including `depth=1` | 403, both **absent** | 403, both **absent** | 403, both **absent** | — |
| GET `Player[ID=23].Bag?resolve=1` (ID'd nested index, sig_id_prefix), including `Bag[ID=4]` | 403, sig **absent** | 403, sig **absent** | 403, sig **absent** | — |
| GET `Player[ID=25].Bag?resolve=1` (lowercase `id` attribute, owner_emails), `text/plain`, `Bag[ID=7]`, `Bag[id=7]` | 403, owner_emails **absent** | 403, owner_emails **absent** | 403, owner_emails **absent** | — |
| GET `Player[ID=26].Hop?resolve=1&depth=4` (ID'd two-hop), `.Hop.Ptr`, `Hop[ID=1]`, `Hop[id=1].Ptr` | 403, owner_emails **absent** | 403, owner_emails **absent** | 403, owner_emails **absent** | — |
| GET `Player[ID=28].Bag` (`Id=8`) and `Player[ID=29].Bag` (`iD=9`) | 403, field **absent** | 403, field **absent** | 403, field **absent** | 200, pubkey **present** on 28 |
| GET `Player[ID=38].Wrap.Bag` and `.Wrap` (positive ID on both parent and child), including the named path | 403, cert_id **absent** | 403, cert_id **absent** | 403, cert_id **absent** | 200, cert_id **present** |
| GET `Player[ID=36].Bag` (string `"+7"`), `Player[ID=42].Bag` (`ID=007`), `Player[ID=44].Steal` (`ID` plus a second attribute), `Player[ID=51].Bag` (string `"-0"`, stored as 0) | 403, field **absent** | 403, field **absent** | 403, field **absent** | — |

A wrong ID (`Bag[ID=99]`, `Wrap[ID=9]`, `Bag[ID=-2]` on an entry stored as 0) is **404**, fields **absent**. `Bag[ID=*]` and `Bag[*]` are **400**, fields **absent**. `bag` and `Baggage` are **404**, fields **absent**. `resolve=TRUE` and `resolve=yes` do not follow the link: **200**, fields **absent**. Those are not leaks.

BoxQL `{Get[]} = players:Player[ID=17|18|19|20|21|22|25|28|42] -> … @>` of these ID'd links is **403**, fields **absent**, for host-admin, the write key, and the accounts service key.

### Array resolve that stayed closed

Status **403**. Every cert field **absent**. Ciphertext **absent**. Owner on the same URL is **200** with the requested field **present**.

| Channel | host-admin | write key | accounts service | owner |
|---|---|---|---|---|
| GET `Player[ID=8].Bag?resolve=1` (pubkey), including `depth=1`, `depth=4`, `depth=32`, `resolve=true`, `text/plain`, `text/x-redx-box`, `*/*`, `text/html`, param order, HEAD | 403, pubkey **absent** | 403, pubkey **absent** | 403, pubkey **absent** | 200, pubkey **present**, ciphertext **absent** |
| GET `Player[ID=9].Bag?resolve=1` (`private_enc`), including `text/plain` and `application/json` | 403, ciphertext **absent** | 403, ciphertext **absent** | 403, ciphertext **absent** | 200, ciphertext **present** |
| GET `Player[ID=10].Wrap.Bag?resolve=1&depth=4`, including `resolve=true` and `text/plain` | 403, cert_id **absent** | 403, cert_id **absent** | 403, cert_id **absent** | 200, cert_id **present**, ciphertext **absent** |
| GET `Player[ID=10].Wrap?resolve=1&depth=4` and the player record for IDs 8, 9, and 10 | 403, all fields **absent** | 403, all fields **absent** | 403, all fields **absent** | — |
| GET `Player[ID=10].Bag?resolve=1` (array link to the whole cert) | 403, all fields **absent** | 403, all fields **absent** | 403, all fields **absent** | — |
| BoxQL `{Get[]} = players:Player[ID=8\|9] -> Bag @> Bag` and `Player[ID=10] -> Wrap.Bag @> Wrap.Bag` | 403, all fields **absent** | 403, all fields **absent** | 403, all fields **absent** | — |

Adjacent shapes with no ID on the entry are also **403**, fields **absent**: nested index `Bag[0][1]` read as `.Bag`, a cert link at index 1, a link inside a box that is an array element, a two-hop array link at `depth=4`, a non-integer `ID=1.5`, an `IDX` attribute, a bare `ID` flag, a string ID `" -1"`, and a string ID `"1e2"`. `Bag[0][1]` is not a path (**400**, fields **absent**). `Player[ID=8].Bag[0]` and `Bag[ID=0]` on a field that has no ID are **404**, fields **absent**. A two-hop read at `depth=1` is **200** with every cert field **absent** (the inner link is not followed). A short-prefix target inside an array is **200** with every cert field **absent**. BoxQL `@>` of the nested-index array, of the element box, and of the two-hop array is **200** with every cert field **absent**. Those are not leaks.

### New hole — negative entry ID

`stripRecordedID` keeps a leading bracket only when the value is digits. `EKey.String` writes `[ID=` plus `strconv.FormatInt`, so a negative ID is recorded as `Name[ID=-n]` and an array element under it as `Name[ID=-n][0]`. The minus fails the digit check, so a request for the bare field does not count that copy. Lookup without an ID still returns that entry. The selected value is one field string, which `TextIsLifetimeCert` does not treat as a cert body, so the response is **200** and the field is **present**.

The same request with the negative ID in the path (`Bag[ID=-1]`, `Bag[-1]`, `Bag[id=-1]`, `Steal[ID=-4]`, `Wrap[ID=-3].Bag`, the minimum int64 named on Steal) is **403**, fields **absent**. The whole player record is **403**. BoxQL `@>` of the negative array, the negative box field, the negative wrap, the overflow ID, and the sibling bag is **403**, fields **absent**. The hole is HTTP `?resolve=1` of the field name without the ID.

A whole float that does not fit in an int64 is stored by `int64(float64)`. On this build, `1e20`, `9223372036854775807`, and `9223372036854775808` all become the minimum int64, so they take the same path as an explicit negative ID.

A positive sibling does not close the hole when lookup returns the negative entry. `Player[ID=50]` stores `Bag[ID=-20]` (link to `private_enc`) first and `Bag[ID=20]` (a non-cert string) second. Bare `Bag?resolve=1` returns the ciphertext.

Observed non-owner **200**, named field **present**. Ciphertext is **present** only on the rows marked secret **present**. The same URLs for an owner session are **200** with that field **present**.

| Channel | host-admin | write key | accounts service |
|---|---|---|---|
| GET `Player[ID=30].Bag?resolve=1` (array `ID=-1`, pubkey), including `text/plain`, `resolve=true`, `depth=4` | pubkey **present** | pubkey **present** | pubkey **present** |
| GET `Player[ID=31].Bag?resolve=1` (array `ID=-2`, `private_enc`), including `text/plain`, `*/*`, JSON, and `text/x-redx-box` | secret **present** | secret **present** | secret **present** |
| GET `Player[ID=32].Wrap.Bag?resolve=1&depth=4` and `.Wrap?resolve=1&depth=4` (`Wrap[ID=-3]`, cert_id) | cert_id **present** | cert_id **present** | cert_id **present** |
| GET `Player[ID=33].Steal?resolve=1` (box field `ID=-4`, `private_enc`), `text/plain` | secret **present** | secret **present** | secret **present** |
| GET `Player[ID=34].Bag?resolve=1` (string `ID="-5"`, owner_emails), `text/plain` | owner_emails **present** | owner_emails **present** | owner_emails **present** |
| GET `Player[ID=35].Bag?resolve=1` (bare `[-6]`, sig_id_prefix) | sig **present** | sig **present** | sig **present** |
| GET `Player[ID=37].Bag?resolve=1` (`ID=1e20`, pubkey), including `text/plain` | pubkey **present** | pubkey **present** | pubkey **present** |
| GET `Player[ID=39].Hop?resolve=1&depth=4` and `.Hop.Ptr` (`ID=-8`, two-hop to owner_emails) | owner_emails **present** | owner_emails **present** | owner_emails **present** |
| GET `Player[ID=40].Bag?resolve=1&depth=4` (nested index under `ID=-9`, issued) | issued **present** | issued **present** | issued **present** |
| GET `Player[ID=41].Wrap.Bag?resolve=1&depth=4` and `.Wrap` (`Id=-10`, child `id=3`, pubkey), `text/plain` on the parent | pubkey **present** | pubkey **present** | pubkey **present** |
| GET `Player[ID=45].Bag?resolve=1` (lowercase `id="-11"`, `private_enc`), `text/plain` | secret **present** | secret **present** | secret **present** |
| GET `Player[ID=46].Bag?resolve=1&depth=4` (digit string past max int64, pubkey) | pubkey **present** | pubkey **present** | pubkey **present** |
| GET `Player[ID=47].Steal?resolve=1` (minimum int64, `private_enc`), `text/plain` | secret **present** | secret **present** | secret **present** |
| GET `Player[ID=48].Bag?resolve=1&depth=4` (max int64 literal, cert_id) | cert_id **present** | cert_id **present** | cert_id **present** |
| GET `Player[ID=49].Bag?resolve=1` (spaces around `ID = -12`, sig_id_prefix) | sig **present** | sig **present** | sig **present** |
| GET `Player[ID=50].Bag?resolve=1` (oldest entry `ID=-20` links to `private_enc`; sibling `ID=20` is not a cert link), `text/plain` | secret **present** | secret **present** | secret **present** |
| GET `Player[ID=55].Bag?resolve=1` (spaced lowercase `id = "-13"`, owner_emails), `text/plain` | owner_emails **present** | owner_emails **present** | owner_emails **present** |

`Player[ID=39].Hop?resolve=1&depth=1` is **200** with every cert field **absent**. BoxQL `@>` of that hop is **200** with every cert field **absent**. The inner link is not what those reads return.

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

Broad subscribe of `*` and of `Record`, and BoxQL Watch of bare `Record`, ended at **400** with every cert field **absent**. A note-path subscribe that did upgrade delivered no cert field (cert path **absent** in the frame).

### Service key write

| Action | Result |
|---|---|
| PUT canonical cert | **200**. Ack fields **absent**. |
| PUT `rxa-account...idVerified` | **200**. Cert fields **absent**. |
| GET/query/BoxQL short and full names, empty-file query, unique no-file REST, box-field `?resolve=1`, no-ID array `?resolve=1`, positive ID'd `?resolve=1`, and BoxQL `@>` | **403**. All fields **absent**. |
| GET `?resolve=1` of a negative-ID field whose link targets pubkey, cert_id, owner_emails, sig_id_prefix, issued, or `private_enc` | **200**. That field **present**. Ciphertext **present** on the `private_enc` link. |

Write and `idVerified` match the freeze. "Must not read the cert back" does not, once the link entry's recorded ID is negative.

### Owner positive control

Owner session on the accounts database: **20 OWNER-OK**, **0 OWNER-FAIL**.

- GET canonical record: **200**. Ciphertext **present**. Other fields **present**.
- GET short pubkey and POST `/query` `*.pubkey`: **200**. Pubkey **present**. Ciphertext **absent**.
- POST `/query` `Record[ID=1].*`: **200**. Ciphertext **present**. Other fields **present**.
- GET `?resolve=1` of `Cert.pubkey`, of the `private_enc` field link, of the no-ID array pubkey link, of the no-ID array `private_enc` link, and of `Wrap.Bag`: **200**. The requested field **present**. Ciphertext **present** only on the `private_enc` reads.
- GET `?resolve=1` of the positive ID'd array pubkey link, the positive ID'd array `private_enc` link, the positive ID'd box field, the positive ID'd wrap, mixed-case `Id`, both-ID wrap, and the negative-ID array, secret, wrap, box field, and lowercase negative string: **200**. The requested field **present**.

Name on a player that holds a negative-ID link stays **200** with every cert field **absent** (**12 CONTROL-OK**, **0 CONTROL-FAIL**).

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

The data-file hits are the database copies of the record the test stored. The ciphertext that is **present** is in the non-owner HTTP body of the negative-ID `?resolve=1` reads above.

## Tests

Go attack suite only. Product `./...` was not re-run here. CI on this head had finished at review time and was not used as evidence.

**Harness** `go test -tags qa -count=1 -timeout 15m -run TestQALifetimeCertAttack ./host/`: exit 1. Sole failure class is LEAK. Probe classes: 78 LEAK, 686 CLOSED, 114 QUIET, 3 CLEAR, 12 CONTROL-OK, 20 OWNER-OK, plus the pulse-define status line.

**CI** on `6455153` (https://github.com/grimvirusoffical-source/RedX/actions/runs/40488122566), not a merge gate for this review:

| Job | Status |
|---|---|
| linux-amd64 | pass |
| linux-amd64-go1.22 | pass |
| windows-amd64 | pass |
| macos-arm64 | pass |
| macos-intel | pass |

## HOLD conditions

Do not merge PR #22 until a non-owner, including the accounts service key, gets **403** and a body with no cert field for every read the engine will satisfy:

1. Keep the closures that already hold, including the positive ID'd resolve (`Player[ID=17].Bag` through `Player[ID=26].Hop`, mixed-case `Id` / `iD`, `"+7"`, leading zeros, and an ID on both parent and child), the no-ID array resolve, empty-file query, unique no-file REST, box-field `?resolve=1`, short-prefix reads, and BoxQL `@>`.
2. Treat a negative recorded ID as part of the same field. `?resolve=1` on the field name, with no ID in the request, must be **403** with every cert field **absent** when that entry's link targets the cert. This includes an array (`Bag[ID=-1]`, `Bag[-6]`, string `"-5"`, spaced and lowercase forms), an ID'd parent box (`Wrap.Bag` and `Wrap`), an ID'd box field (`Steal`), a nested index under a negative ID, and a two-hop link stored on a negative ID. The same rule covers a whole number the engine stores as a negative int64, including `1e20` and the int64 boundary literals used above. Host-admin, a db-scoped write key, and the accounts service key are the callers. `text/plain` is included. A request that already names the negative ID is already **403** and is not this hole.
3. Keep BoxQL `@>` of those negative-ID links at **403**.
4. Keep the accounts service key able to write the cert and `idVerified` / `idVerifiedMs`, and unable to read any cert field back, including the negative-ID resolve above.
5. An owner session must still be able to read the cert, including `?resolve=1` through the positive ID'd field and through the negative-ID field.

## Harness

Leave unmerged. https://github.com/grimvirusoffical-source/RedX/pull/26 and https://github.com/grimvirusoffical-source/RedX/pull/27 stay unmerged.

This review's harness is the pull request opened from `cursor/qa-lifetime-cert-id-retest-a0ea`. It does not change product behavior. Leave it unmerged.
