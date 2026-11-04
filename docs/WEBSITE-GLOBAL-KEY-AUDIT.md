# Required audit for website-mode global API keys

This source-only extension starts at owner-audit backport
`8a6905999332a66ab7a77b2ffe9ea7d3a8e26a92`, itself based directly on
`8512e1704e589d24535e08082c3ab9f832d7655d`. It is a separate change from PR37;
source ancestry does not establish the current production binary or configuration.
No deployment, credential, account record or data migration is included.

Previously a verified API key could receive a principal even if its optional
`auth.ok` audit append failed. Wildcard keys can span visible databases, including
read/write keys without host-admin scope. Prefixes or an `Owner` field do not
remove every global metadata/admin path, so the required-audit classification is
conservatively **every verified `KeyRecord.DB == AllDBs` (`"*"`)** in website mode,
regardless of scope, prefix, label, owner metadata or other key metadata.

`Host` privately wires a callback following its actual `h.website != nil` state.
The always-assigned website account resolver is deliberately not used as the mode
test. There is no new public flag or request-controlled policy switch. Tests can
inject their existing adapter after `New` and the callback follows that adapter.

After native key verification and the existing per-key rate limit, successful
global-key authentication now requires `LogRequired`: a complete JSON-line append
and successful file `Sync` before returning a principal. The event is
`global_key.access_attempt`, with public key ID, time, method, remote IP,
normalized target and route. A database route retains database name and operation
kind; legacy `/v1/path/` targets are reduced to the normalized route. No presented
token, credential hash/salt, body/query value or record path is logged. Key owner
and label metadata do not establish a human actor, so `Actor` remains empty.

The event precedes route ACL checks and mutations: it is an access attempt, not
proof of authorization to that route or a completed read/write. Existing rate
limits run first; a throttled request gains no authorization. For website-mode
wildcard requests this required event replaces optional `auth.ok`, independently
of `audit_success`; log consumers should account for that intentional event-name
change. Other operation logs remain best effort and do not substitute for it.

Missing/closed/failed sinks and short/write/Sync failures return the existing
`ErrAuditUnavailable`. Existing HTTP handlers return503 `audit_unavailable`
without a login challenge, cookie clearing or bad-login increment. The gate
does not demote an account, grant an owner role, bypass MFA, change key scope or
change tenant/billing checks. Existing owner-account required auditing stays in
place. Append/Sync is an OS acknowledgment, not proof of power-loss durability
or durable directory metadata after rotation.

## Compatibility boundaries

- Standalone mode retains existing native-key defaults even though its resolver
  function is wired. It does not acquire this website-only required-audit policy.
- Concrete own-database project-admin/read/write/prefix keys keep their existing
  credential, scope, ownership and plan checks. Admin scope on one DB is not a
  global key. Tests retain own access and existing foreign-DB denial.
- Exact-master account/service keys are concrete-DB keys, intentionally outside
  this minimal wildcard policy. Their existing protected-master behavior remains
  unchanged. This is not a claim that every advanced administrative service-key
  privilege now has required auditing; any broader policy needs separate review.
- Website global-key CLI/automation/update clients intentionally receive503 if
  required audit is unavailable. Their credential formats, scopes and paths do
  not change, but actual clients and log consumers need staged acceptance.
- RedX engine, BoxQL, custom files/formats, dependencies, website session/tenant
  policy and realm activation are unchanged. Browser API keys remain optional
  advanced developer credentials; this gate adds no navigation/login key prompt.

## Validation and production gates

Generated disposable fixtures cover all twelve read/write/admin × prefix × owner
metadata classes, successful normalized/redacted events, closed and nil/disabled/
short/write/Sync denial, twenty-five repeated failures without bad-login effects,
concrete project/exact-master compatibility and standalone/adapter changes.
An actual loopback HTTP fixture verifies503 with no challenge or cookie clearing,
no mutation before audit, normal website/project-key own access and existing
cross-tenant denial. Existing owner sink/rotation fault tests remain applicable.
No production endpoint, credential, private configuration or live account is used.

Before any rollout, the sole production controller must verify actual binary,
source/config and adapter selection; take current consistent native/CMS/support
and audit backups with isolated restore proof; verify sink identity/permissions,
readable complete tail, space/inodes, exclusive writer and append/Sync/rotation on
a separate disposable same-filesystem/service fixture. Do not fault-inject into
the live sink or repair/truncate its tail automatically.

Then stage authorized owner and global-key read/write/admin requests, normal A/B
project/session access, unavailable-audit503/session preservation, actual CLI/
automation and concrete account/CMS-service compatibility. Preserve existing
credentials, scopes, MFA, sessions, tenant data and current audit evidence through
code/config rollback. Never disable website mode, weaken the gate or edit native
account data to conceal an audit-storage fault. Source tests and CI do not establish
these live acceptance or recovery results.
