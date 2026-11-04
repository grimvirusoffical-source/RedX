# Native DB persistent account ownership prototype

Source-only follow-up to `5f5ea5242e6f768426be274341e5f8b31ed049df`.
Nothing is deployed, pushed, enabled, provisioned or migrated in production.
`websiteSessionFromEnv` still refuses every nonempty
`REDX_WEBSITE_SESSION_REALMS` value. The original website authority, account
cookie, owner policy and legacy client defaults remain active by default.

## Identity and ownership

The agreed authority envelope is unchanged: `identityRealm` contains version 1,
issuer, raw subject and public canonical ID. Public account ID remains the
legacy bare ID or, for fresh accounts, `rxf1_` plus lowercase SHA-256 of UTF-8
`issuer + NUL + subject`. That public DTO is **not an ownership key**: a valid
legacy bare ID may equal it exactly.

The fresh private key is the literal leading ASCII space plus `rxf1:`, followed
by unpadded base64url UTF-8 issuer, `.`, and unpadded base64url UTF-8 subject.
`internal/accountscope` validates decoding and canonical re-encoding. Legacy
subjects are nonempty valid UTF-8, at most 256 bytes, with no whitespace/control;
the realm envelope restricts both subjects to 200 bytes. Native OIDC callbacks,
stored native sessions, website IDs and key-owner metadata reject the private
space/control domain as legacy. Valid legacy IDs, including every valid
`rxf1_*` bare ID, retain their exact ownership key and physical DB derivation.

`realm-owners.json` is private integration metadata containing version 1 and
immutable issuer/subject/public-ID/private-key bindings. Binding is persisted
by private temporary file, file sync and rename before fresh access succeeds;
POSIX directory sync follows. Each new binding refuses any pre-existing tenant,
key, plan or usage row under its unclaimed key, including invalid/unlabelled
rows. No email, username, caller header, role claim, hash DTO or initial
inventory can adopt an existing namespace. Losing the registry causes fresh
resource/key access to fail closed; it is not reconstructed from resource rows.

Database tenant records, native key records, billing plans and usage records
carry additive `ownerIssuer` and `ownerSubject` fields. Missing fields mean
legacy only. Fresh records must match the exact reversible tuple; fresh key
authentication additionally requires the persisted registry. Plan lookup
requires the map key to equal the record's account field. Tenant DB ownership,
plan/quota lookup, audit/rate keys, key rotation, developer-key descendants and
device pairing retain the private key. Fresh API-key scopes, DB ACLs, path
prefixes, plan state and quotas remain enforced. Password login does not grant
a paid plan. Only temporary tests create fixture entitlements.

Website `account.sub` remains the public DTO. Only fresh account views add a
trusted `storage_subject` for browser caches. UI identity changes, saved
queries/drafts, selected DB and in-flight responses use it, preventing caches
from merging when a legacy public ID equals a fresh public ID. WebSocket
revalidation compares private ownership keys as well as owner status.

Fresh roles still require exactly `['user']`, verified email and active flags.
Fresh accounts cannot inherit the legacy owner allowlist. Legacy owner access
retains actual ID, authoritative owner role and MFA requirements. Both cookies,
forged caller realm headers, authority failures, expiry and revocation retain
the existing fail-closed behavior and exact-origin mutation checks.

## Backups and restoration

Realm-bearing host online/offline archives retain the existing custom DB files and add known
metadata members `realm-owners.json`, `billing/plans.json` and
`billing/usage.json`. Legacy-only archives omit the new members, preserving the
older archive layout. `tenants.json` and `keys.json` retain additive tuple
metadata. `ExtractSnapshot` recognizes the new members, bounds their sizes,
rejects duplicate new members, and verifies every fresh key/tenant/plan/usage
tuple against the registry before restore. Missing fresh fields or missing
registry do not silently downgrade to legacy. Offline metadata read errors
propagate rather than silently dropping ownership information.

Online backups freeze new registry bindings until keys/metadata are collected;
ordinary engine writes retain the existing pause/checkpoint behavior. This is
not a transaction with external provider webhooks and does not establish
power-loss or cross-filesystem atomicity. Use a stopped daemon backup for
clean recovery verification.

Realm-bearing restores require a fresh ownership-metadata destination, even
with `--force`; existing keys, tenants, registry or billing files are preserved
and mixed restore is refused before moving DBs. Restore to a new data directory,
start the candidate privately, validate it, and switch only through a reviewed
reversible deployment. Existing legacy-only archive behavior remains covered.
An older recovery binary/tool pinned to 8512 must **not** restore a new candidate
archive; its manifest/binary pin and archive-member whitelist require separate
review. This source task does not edit production recovery tools or backups.
Do not roll an older binary back over fresh realm metadata; restore the matching
verified pre-activation data backup through the reviewed rollback procedure.

## Remaining activation gates

- All fresh checkout and customer-portal operations remain disabled. The legacy
  provider adapter does not acquire fresh realm support through email metadata.
  Existing legacy purchases/webhooks retain their existing path.
- Fresh multi-node replication is unsupported. Cluster snapshots do not carry
  these ownership/billing metadata members; orphan fresh keys/snapshots fail
  closed. Legacy clustering remains covered by the existing suite. Do not enable
  fresh accounts on a cluster until issuer metadata has a reviewed replication
  and promotion protocol.
- The private resolver, gateway selection, account lifecycle, mail delivery,
  real owner/phone MFA/Quick Login/CLI/Secrets compatibility and real normal-user
  A/B acceptance still require coordinated tests. Default native/manual Bridge
  login remains legacy-only; fresh manual client support is not claimed.
- Local tests use Windows. File mode 0600 is a POSIX check, not a claim of Windows
  ACL hardening. Linux daemon/process restart, failure injection, race testing,
  production migration and power-loss recovery remain unverified here.

No engine, BoxQL, adapter implementation, custom DB data format, native token
syntax, customer account, paid subscription or production service is replaced.

## Validation

The real unchanged `engineadapter` test creates custom Box data and scoped keys,
including rotated, descendant and paired keys, under explicit temporary plans.
It covers fresh A/B and legacy same-email users, a legacy bare ID exactly equal
to a fresh public ID, plan non-inheritance, owner denial, cross-tenant read
denial, close/reopen of the native daemon over the same disk data, stopped-daemon
backup, fresh-directory restore, post-restore access and missing-registry denial.
Daemon reopen is within one test process, not an OS process restart claim.

Additional tests verify canonical cross-language key vectors, strict subject
domains, immutable persisted bindings, unclaimed-row refusal, native-session
domain rejection, per-record metadata validation, plan/usage reopen isolation,
missing restore tuples, mixed restore refusal and browser public-ID collision
isolation. Standard host/billing/adapter tests and UI tests provide legacy
regression coverage. Test results are recorded with the commit handoff; no live
behavior is inferred from these fixtures.

Local receipt, 2026-11-03, Windows:

- `go test ./internal/accountscope ./billing ./host ./host/engineadapter -count=1`
  passed: accountscope 0.706s, billing 1.751s, host 91.502s, adapter 16.204s.
- The strengthened real-engine provider-denial assertion passed in a subsequent
  focused run (host 0.849s); it requires the realm-specific denial code rather
  than accepting an unrelated disabled-provider response.
- `go vet ./internal/accountscope ./billing ./host` passed.
- `node --test host/uitest/*.test.mjs`: 48 passed, zero failed/skipped.
- `git diff --check` passed. `engine/`, `box/`, `cmd/redxd/` and
  `host/engineadapter/` have no diff from
  `8512e1704e589d24535e08082c3ab9f832d7655d`.
