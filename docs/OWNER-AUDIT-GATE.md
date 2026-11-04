# Required audit for privileged account access

This backport is based directly on deployed-source revision
`8512e1704e589d24535e08082c3ab9f832d7655d`, with the audit change reviewed from
`f5dd21ddb22ea0148c613f2313e8f645428b2ee5`. It does not include the persistent-realm
prototype. It does not change account identity policy, deploy a binary, or modify
the RedX engine, BoxQL, database formats, records, API-key credentials or ordinary
tenant authorization. Exact source ancestry is not current live deployment proof;
the controller must verify the running binary and service configuration first.

Previously `Authenticator.accountResult` called best-effort `Auditor.Log` for an
owner request and granted access even if the sink was absent, closed, failed
rotation or could not write the event. An owner read or database creation could
therefore succeed without its required audit record.

Owner account authorization now requires a complete attributed `owner.read` or
`owner.write` append and a successful file `Sync` before returning a principal.
Any missing sink, short/write/Sync/rotation failure denies the request. Sink
failures stay latched in that auditor instance. Reopening an unterminated audit
tail refuses further appends, preserving the fragment rather than joining it to
an apparently valid new privileged event. No automatic log repair is performed.
`Sync` is an operating-system acknowledgment, not proof of power-loss durability
or durable directory metadata after rotation.

Every HTTP authentication entry point returns503 `audit_unavailable` for this
condition. It does not challenge login, clear cookies, increment bad-login
counters, demote the owner, bypass MFA or fall back to a developer key. Existing
API-key clients retain their credential/scoping path; this required-event gate is
for privileged account sessions. Ordinary account reads/writes keep the existing
tenant and billing gates, including after an owner audit failure.

## Existing backend boundaries retained

- `website_session.go`: each opaque website cookie is revalidated against the
  fixed authoritative profile service; caller identity/role headers are ignored.
  Website owner authority requires a configured immutable account ID, the
  authoritative owner role and an actual MFA method. It does not infer ownership
  from email. The legacy treatment of omitted email-verification metadata is
  unchanged; explicit inactive/revoked/banned/deleted/negative states are refused.
- `tenant.go`: persisted ownership selects physical DB names and filters lists;
  cross-tenant reads, writes, metadata and BoxQL return missing-database404.
  Browser sessions need no mandatory API key. Explicit developer keys retain
  their original scope/database/prefix and owner-bound plan restrictions.
- `auth.go` and `accounts_owner.go`: owner overview/data/create requests retain
  checked role/MFA authority and attributed audit events without record values.

The deployed legacy ownership model is retained byte-for-byte. This backport
neither admits fresh-realm sessions nor imports their ownership schema. A separate
realm migration cannot be inferred from the audit tests.

## Preconditions before any rollout

The sole production controller must first verify the actual configured audit
path, effective service identity, existing file and parent-directory ownership,
mount layout, available storage/inodes and ordinary read/append/Sync behavior.
The existing sink must be readable for its one-byte tail check, appendable by the
service and either empty or newline-terminated. Its parent and rotated `.1`
destination must support the reviewed close/rename/reopen operation. A synthetic
append/rotation drill must use a separate disposable fixture under the same
reviewed filesystem/service conditions, never the live audit file.
Confirm this auditor is the sole writer and that no uncoordinated external
rotation/truncation process changes the sink. An unreadable/incomplete existing
tail disables privileged audit writes without turning the new tail check into a
failure of ordinary service startup.

Missing/disabled/unhealthy audit sinks deliberately prevent owner operations.
Do not enable this gate without proving a real authorized owner read and create
event on the privately staged candidate, session preservation on503, normal A/B
isolation and a code/config rollback plan. Repairing a sink or a partial tail and
reinitializing the auditor is a separate reviewed administrative operation; this
patch makes no production permissions, configuration or data changes. Never
relax the gate or change owner identity/MFA to hide an audit-storage fault.

Tests use only disposable synthetic accounts, records and log files. They cover
own-user access, other-user denial, owner ID/MFA requirements, canonical audit
attribution/redaction,503 without login challenge/cookie change, nil/closed/
short/write/Sync/rotation failures, incomplete tails and concurrent Close/append.
No live normal-user, owner, billing, mail, device or production durability proof
is implied by these tests.
