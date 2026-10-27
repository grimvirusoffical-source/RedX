# QA security review — PR #22 lifetime-cert owner-only read (retest)

**Verdict: MERGE.**

| | |
|---|---|
| Target | https://github.com/grimvirusoffical-source/RedX/pull/22 |
| Head | `c1c4be9d19ec7c226257c865de931c335c06d1f8` (`cursor/lifetime-cert-owner-gate-7ab7`) |
| Prior HOLD | head `6455153efebac10308bd27d1dc422df88fbd9125`, report on PR #28 |
| Product vs `7fdaa5c` | `host/cluster_test.go` only: the static-secret follower wait is 20s. `host/accounts_guard.go` is byte-identical to `7fdaa5c`. |
| Harness | `host/qa_lifetime_attack_test.go` (`//go:build qa`) on `cursor/qa-lifetime-cert-c1c4-retest-cc19`. Not merged. https://github.com/grimvirusoffical-source/RedX/pull/29 . PR #26, PR #27, and PR #28 left unmerged. |

Field values below are **present** or **absent** only. No ciphertext, key, seed, or PEM material is included.

## What the freeze requires

Kind `rxa-lifetime-cert` is owner-only for the entire record, including `private_enc`, `pubkey`, `cert_id`, `owner_emails`, `issued`, and `sig_id_prefix`. Non-owner reads are 403. Ciphertext must not appear in non-owner responses or audit text. An accounts service key may write the cert and set `idVerified` / `idVerifiedMs`, and must not read any cert field back.

## Author claim for this head

The expand matcher accepts canonical `[ID=` plus `strconv.FormatInt` of the stored int64, including a leading minus and the minimum int64. Source forms are folded to that spelling before the step is compared. Claimed closed for host-admin, a db write key, and the accounts service key: every negative and overflow `?resolve=1` row that leaked at `6455153` is 403, every cert field absent, ciphertext absent. Owner reads of those URLs stay 200. Prior positive-ID and no-ID closures stay closed. The unmerged harness result cited by the author was not used as evidence.

The claim holds on this head. The `6455153` negative-ID hole is **CLOSED**.

## Attack result

Harness: real engine (`engineadapter.Opener`), `CodeAllowedBoxes: ["*"]`. Per-key rate burst is raised so a 429 is not what ends a probe. Callers: host-admin key, db-scoped write key, accounts service key (`db=redxai_accounts`, scope write), and an owner console session.

`go test -tags qa -count=1 -timeout 15m -v -run TestQALifetimeCertAttack ./host/`: **exit 0**.

| Class | Count |
|---|---|
| LEAK | **0** |
| CLOSED | **960** |
| QUIET | **158** |
| CLEAR | **0** |
| CONTROL-OK | **12** |
| CONTROL-FAIL | **0** |
| OWNER-OK | **38** |
| OWNER-FAIL | **0** |
| OPEN | **0** |
| ODD | **0** |

One pulse-define line is **STATUS 200**, every cert field **absent**. Ciphertext is **absent** on every probe (`leak_ciphertext_present=0`). PEM banners in server logs: **0**.

HEAD of `Player[ID=31].Bag?resolve=1`, which was 200 with an empty body at `6455153`, is **403** with every cert field **absent**.

### Former leak rows, now closed

Status **403**. Every cert field **absent**. Ciphertext **absent**. The same URL for an owner session is **200** with the requested field **present**.

| Channel | host-admin | write key | accounts service | owner |
|---|---|---|---|---|
| GET `Player[ID=30].Bag?resolve=1` (array `ID=-1`, pubkey), including `text/plain`, `resolve=true`, `depth=4` | pubkey **absent** | pubkey **absent** | pubkey **absent** | 200, pubkey **present** |
| GET `Player[ID=31].Bag?resolve=1` (array `ID=-2`, `private_enc`), including `text/plain`, `*/*`, JSON, `text/x-redx-box`, `depth=0`, `depth=00`, duplicate `resolve=1`, HEAD | ciphertext **absent** | ciphertext **absent** | ciphertext **absent** | 200, ciphertext **present** |
| GET `Player[ID=32].Wrap.Bag?resolve=1&depth=4` and `.Wrap?resolve=1&depth=4` (`Wrap[ID=-3]`, cert_id) | cert_id **absent** | cert_id **absent** | cert_id **absent** | 200, cert_id **present** |
| GET `Player[ID=33].Steal?resolve=1` (box field `ID=-4`, `private_enc`), `text/plain` | ciphertext **absent** | ciphertext **absent** | ciphertext **absent** | 200, ciphertext **present** |
| GET `Player[ID=34].Bag?resolve=1` (string `ID="-5"`, owner_emails), `text/plain` | owner_emails **absent** | owner_emails **absent** | owner_emails **absent** | — |
| GET `Player[ID=35].Bag?resolve=1` (bare `[-6]`, sig_id_prefix) | sig **absent** | sig **absent** | sig **absent** | — |
| GET `Player[ID=37].Bag?resolve=1` (`ID=1e20`, pubkey), including `text/plain`, and the stored minimum-int64 name | pubkey **absent** | pubkey **absent** | pubkey **absent** | — |
| GET `Player[ID=39].Hop?resolve=1&depth=4` and `.Hop.Ptr` (`ID=-8`, two-hop) | owner_emails **absent** | owner_emails **absent** | owner_emails **absent** | — |
| GET `Player[ID=40].Bag?resolve=1&depth=4` (nested index under `ID=-9`, issued) | issued **absent** | issued **absent** | issued **absent** | — |
| GET `Player[ID=41].Wrap.Bag?resolve=1&depth=4` and `.Wrap` (`Id=-10`, child `id=3`, pubkey) | pubkey **absent** | pubkey **absent** | pubkey **absent** | — |
| GET `Player[ID=45].Bag?resolve=1` (lowercase `id="-11"`, `private_enc`), `text/plain` | ciphertext **absent** | ciphertext **absent** | ciphertext **absent** | 200, ciphertext **present** |
| GET `Player[ID=46].Bag?resolve=1&depth=4` (digit string past max int64, pubkey) | pubkey **absent** | pubkey **absent** | pubkey **absent** | — |
| GET `Player[ID=47].Steal?resolve=1` (minimum int64, `private_enc`), `text/plain`, and the named minimum | ciphertext **absent** | ciphertext **absent** | ciphertext **absent** | — |
| GET `Player[ID=48].Bag?resolve=1&depth=4` (max int64 literal, cert_id) and the stored minimum-int64 name | cert_id **absent** | cert_id **absent** | cert_id **absent** | — |
| GET `Player[ID=49].Bag?resolve=1` (spaces around `ID = -12`, sig_id_prefix) | sig **absent** | sig **absent** | sig **absent** | — |
| GET `Player[ID=50].Bag?resolve=1` (oldest `ID=-20` links to `private_enc`; sibling `ID=20` is not a cert link), `text/plain` | ciphertext **absent** | ciphertext **absent** | ciphertext **absent** | — |
| GET `Player[ID=55].Bag?resolve=1` (spaced lowercase `id = "-13"`, owner_emails), `text/plain` | owner_emails **absent** | owner_emails **absent** | owner_emails **absent** | — |

A request that names the negative ID (`Bag[ID=-1]`, `Bag[-1]`, `Bag[id=-1]`, `Steal[ID=-4]`, `Wrap[ID=-3].Bag`, padded `Bag[ID=-02]`, spaced `Bag[ ID = -2 ]`) is **403**, fields **absent**. The whole player record is **403**. A wrong ID is **404**, fields **absent**.

`Player[ID=39].Hop?resolve=1&depth=1` is **200** with every cert field **absent**. The inner link is not followed at that depth.

BoxQL `{Get[]} = players:Player[ID=30|31|32|33|37|50] -> … @>` of these links is **403**, fields **absent**, for host-admin, the write key, and the accounts service key.

### Adjacent spellings hunted on this head

Same callers. Status **403**. Every cert field **absent**. Ciphertext **absent**. Owner on the sampled URLs is **200** with the requested field **present**.

| Channel | host-admin | write key | accounts service |
|---|---|---|---|
| GET `Player[ID=60].Bag?resolve=1` (whole float `ID=-1.0`, pubkey), `text/plain` | pubkey **absent** | pubkey **absent** | pubkey **absent** |
| GET `Player[ID=61].Bag?resolve=1` (`ID=-1e2`, `private_enc`) and named `Bag[ID=-100]` | ciphertext **absent** | ciphertext **absent** | ciphertext **absent** |
| GET `Player[ID=62].Bag?resolve=1` (`ID=1e19`, stored as the minimum int64), `text/plain`, and the minimum-int64 name | pubkey **absent** | pubkey **absent** | pubkey **absent** |
| GET `Player[ID=63].Bag?resolve=1` (`ID=-1e20`, `private_enc`) and `Player[ID=64].Bag` (`ID=1E20`, cert_id) | field **absent** | field **absent** | field **absent** |
| GET `Player[ID=65].Bag?resolve=1` (`ID=1e18`, fits in int64, `private_enc`) and the canonical positive name | ciphertext **absent** | ciphertext **absent** | ciphertext **absent** |
| GET `Player[ID=66].Steal?resolve=1` (negative ID plus a second attribute, `private_enc`) | ciphertext **absent** | ciphertext **absent** | ciphertext **absent** |
| GET `Player[ID=67].Bag?resolve=1` (ID attribute not first, pubkey) | pubkey **absent** | pubkey **absent** | pubkey **absent** |
| GET `Player[ID=68].Bag?resolve=1` (cert link at index 1 under `ID=-26`, `private_enc`) | ciphertext **absent** | ciphertext **absent** | ciphertext **absent** |
| GET `Player[ID=69].Bag?resolve=1&depth=4` (negative ID on a field inside an array element, `private_enc`) | ciphertext **absent** | ciphertext **absent** | ciphertext **absent** |
| GET `Player[ID=70].Wrap.Bag?resolve=1&depth=4` and `.Wrap` (negative ID on parent and child, cert_id), including the named path | cert_id **absent** | cert_id **absent** | cert_id **absent** |
| GET `Player[ID=71].Hop?resolve=1&depth=4` and `.Hop.Ptr` (negative ID, three-hop to owner_emails) | owner_emails **absent** | owner_emails **absent** | owner_emails **absent** |
| GET `Player[ID=72].Bag` (string `"-0002"`, sig), `Player[ID=73].Bag` (string minimum int64, `private_enc`), `Player[ID=74].Bag` (string maximum int64, cert_id) | field **absent** | field **absent** | field **absent** |
| GET `Player[ID=75].Steal?resolve=1` (bare reference, `private_enc`) and `Player[ID=76].Steal?resolve=1` (cascade `@!>`, `private_enc`) | ciphertext **absent** | ciphertext **absent** | ciphertext **absent** |
| GET `Player[ID=77].Bag?resolve=1` (oldest entry is a positive pubkey link; newer entry is `ID=-40` to `private_enc`) and the named negative ID | ciphertext **absent** | ciphertext **absent** | ciphertext **absent** |
| GET `Player[ID=78].Bag?resolve=1` (oldest entry is not a cert link) and `Bag[ID=41]` (`private_enc`) | ciphertext **absent** | ciphertext **absent** | ciphertext **absent** |
| GET `Player[ID=79].Bag` (`ID=-0.0`, issued), `Player[ID=80].Bag` (`Id=-42`, `private_enc`), `Player[ID=84].Bag` (`ID=10.0`, pubkey), `Player[ID=85].Bag` (float at the int64 boundary, cert_id) | field **absent** | field **absent** | field **absent** |
| GET `Player[ID=81].Wrap.Bag` and `.Wrap` (negative ID on the parent, box field, pubkey) | pubkey **absent** | pubkey **absent** | pubkey **absent** |
| GET `Player[ID=-45].Bag?resolve=1` and `Player[-45].Bag` (negative record ID, no-ID array, `private_enc`) | ciphertext **absent** | ciphertext **absent** | ciphertext **absent** |
| GET `Player[ID=86].Steal?resolve=1` (spaces around a negative ID, owner_emails) and the named ID | owner_emails **absent** | owner_emails **absent** | owner_emails **absent** |

`Player[ID=69].Bag.Steal` is **404**, fields **absent**. That path does not select the inner field. `Player[ID=71].Hop?resolve=1&depth=2` is **200** with every cert field **absent**. `Player[ID=82].Bag?resolve=1` (short file prefix on a negative ID) is **200** with every cert field **absent**, the same shape as the earlier short-prefix array. POST of the resolve URL is **405**, fields **absent**. `resolve=0` as the first query value does not follow the link: **200**, fields **absent**. `Player[ID=31].*` is **400**, fields **absent**.

BoxQL `@>` of the float, fitting scientific, index-1, both-negative, bare-reference, string-max, near-max, and negative-record links is **403**, fields **absent**. BoxQL `@>` of the inner-element link, the three-hop, and the cascade link is **200** with every cert field **absent**: those follows do not return the cert field. HTTP `?resolve=1` of the same records is **403**. BoxQL of `Player[ID=31] -> Bag` and `-> *` without `@>` is **200** with every cert field **absent**. POST `/query` of `Player[ID=31].Bag`, `Player[ID=31].*`, and `Player[ID=65].Bag` is **200** with every cert field **absent**.

### Prior closures that still hold

OPEN count is **0**. Every `must403` row stayed **403** with every cert field **absent** and ciphertext **absent**.

| Channel | Fields |
|---|---|
| REST GET of the short and full record, including `text/plain` and HEAD | pubkey, cert_id, owner_emails, issued, sig_id_prefix, private_enc |
| POST `/query` of the short path, `*.<field>`, `*.*`, `Record[ID=1].<field>`, `Record[ID=1].*`, `Record[ID=*].pubkey`, `*[ID=1].pubkey`, `*[ID=1].*`, surrounding whitespace, and the JSON forms | same fields |
| The same empty-file queries after a second `Record` box exists | same fields |
| REST GET `Record[ID=1].<field>` while that box is unique, including `text/plain` and `text/x-redx-box`, and the whole `Record[ID=1]` | same fields. With a sibling `Record`, REST and BoxQL of the bare record are **400**, fields **absent** |
| GET `?resolve=1` of `Player.Cert.<field>`, of a box field aimed at one cert field (including `private_enc` and `text/plain`), of a nested box field, and of a two-hop link | same fields |
| GET `?resolve=1` of the no-ID arrays `Player[ID=8].Bag`, `Player[ID=9].Bag`, `Player[ID=10].Wrap.Bag` and `.Wrap`, including depth, `resolve=true`, `text/plain`, and HEAD | same fields |
| GET `?resolve=1` of the positive ID'd rows `Player[ID=17].Bag` through `Player[ID=26].Hop`, mixed-case `Id` / `iD`, `"+7"`, leading zeros, an ID on both parent and child, and `text/plain` | same fields. Owner on those URLs is **200** with the requested field **present** |
| BoxQL `{Get[]}` of the short file, BoxQL `@>` into each cert field, a field link, `Min`, a left follow, and both the matching and the non-matching pubkey filter | **403**, fields **absent** |
| BoxQL `@>` of the no-ID array links and of the positive ID'd links, including `private_enc` | **403**, fields **absent** |
| `prefix:` of the full file and of `rxa-lifetime-cert.red-xai` | **403**. `prefix:rxa` does not select the cert file |
| Subscribe of the full file, the short file, and the short pubkey | **403** before upgrade |
| BoxQL Watch of the full file and of the short file | **403** |
| Index exact query on cert_id, pubkey, private_enc, owner_emails, including `record=1` | **403** |
| Non-owner backup, accounts off and accounts on | **403**. No cert fields |
| Script `db_get` of the short and full record | **403** |

`resolve=TRUE` and `resolve=yes` do not follow the link: **200**, fields **absent**. `Bag[ID=*]` and `Bag[*]` are **400**, fields **absent**. A two-hop read at `depth=1` is **200** with every cert field **absent**. A short-prefix target inside an array is **200** with every cert field **absent**. Broad subscribe of `*` and of `Record`, and BoxQL Watch of bare `Record`, ended at **400** with every cert field **absent**. A note-path subscribe that did upgrade delivered no cert field (cert path **absent** in the frame).

### Service key write

| Action | Result |
|---|---|
| PUT canonical cert | **200**. Ack fields **absent**. |
| PUT `rxa-account...idVerified` | **200**. Cert fields **absent**. |
| GET/query/BoxQL short and full names, empty-file query, unique no-file REST, box-field `?resolve=1`, no-ID array `?resolve=1`, positive ID'd `?resolve=1`, negative-ID `?resolve=1`, overflow `?resolve=1`, and BoxQL `@>` of those links | **403**. All fields **absent**. Ciphertext **absent**. |

Write and `idVerified` match the freeze. The service key does not read a cert field back, including the rows that leaked at `6455153`.

### Owner positive control

Owner session on the accounts database: **38 OWNER-OK**, **0 OWNER-FAIL**.

- GET canonical record: **200**. Ciphertext **present**. Other fields **present**.
- GET short pubkey and POST `/query` `*.pubkey`: **200**. Pubkey **present**. Ciphertext **absent**.
- POST `/query` `Record[ID=1].*`: **200**. Ciphertext **present**. Other fields **present**.
- GET `?resolve=1` of `Cert.pubkey`, of the `private_enc` field link, of the no-ID array pubkey link, of the no-ID array `private_enc` link, and of `Wrap.Bag`: **200**. The requested field **present**. Ciphertext **present** only on the `private_enc` reads.
- GET `?resolve=1` of the positive ID'd array pubkey link, the positive ID'd array `private_enc` link, the positive ID'd box field, the positive ID'd wrap, and mixed-case `Id`: **200**. The requested field **present**.
- GET `?resolve=1` of the former leak rows (negative array, secret, wrap, box field, lowercase negative string) and of the new signed forms (whole float, `1e19`, fitting `1e18`, index 1, inner field, both-negative wrap, three-hop, string minimum, string maximum, bare reference, cascade, positive-oldest sibling, named positive secret, negative zero, mixed-case negative, negative record ID, spaced negative ID): **200**. The requested field **present**.

Name on a player that holds a cert link stays **200** with every cert field **absent** (**12 CONTROL-OK**, **0 CONTROL-FAIL**).

### Leak scan

Two real-engine servers (accounts off, and accounts on):

| Check | Result |
|---|---|
| Server log lines | 1 per server |
| Ciphertext in server logs | **absent** |
| PEM banners in server logs | **0** |
| Audit files containing ciphertext | **0** |
| Audit files containing PEM or key headers | **0** |
| Data files containing the stored ciphertext | **2** per server |

The data-file hits are the database copies of the record the test stored.

## Tests

Go attack suite only. Product `./...` was not re-run here. CI on `c1c4be9` was not used as evidence.

**Harness** `go test -tags qa -count=1 -timeout 15m -v -run TestQALifetimeCertAttack ./host/`: exit 0. Probe classes: 0 LEAK, 960 CLOSED, 158 QUIET, 0 CLEAR, 12 CONTROL-OK, 38 OWNER-OK, plus the pulse-define status line (200, cert fields absent).

## Harness

Leave unmerged. https://github.com/grimvirusoffical-source/RedX/pull/26, https://github.com/grimvirusoffical-source/RedX/pull/27, and https://github.com/grimvirusoffical-source/RedX/pull/28 stay unmerged.

This review's harness is https://github.com/grimvirusoffical-source/RedX/pull/29 against `cursor/lifetime-cert-owner-gate-7ab7`. It does not change product behavior. Leave it unmerged. The product PR stays unmerged by this review.
