# Durable revisioned service records (source candidate)

This isolated candidate is based on deployed source pin
`0e7aaef1ed968e44f42881773077b19b2a2d1046` of RedX. It adds a source-level
storage contract for the Bridge service. It has not been deployed, provisioned
with a service credential, or tested against production. No existing account,
session, billing-plan or tenant records are migrated by this change.

## HTTP contract

Use an authenticated server-side RedX API key. Both methods use:

`/v1/db/{database}/record-cas/{encoded-record-path}`

`record-path` must be the canonical, complete name of one top-level record in a
`.red-xai.db` file. For Bridge the existing namespace can remain:

`rxa-bridge-platform.red-xai.db:Record[ID=<existing deterministic numeric ID>]`

Encode this entire path as one URL component. File aliases, quoted aliases,
noncanonical numeric IDs, subfields, wildcards, TTL files, query parameters, and
other methods are rejected. There is no default-database shorthand.

### Read

`GET` requires read scope. It routes to the leader and returns:

```json
{"record":{"key":"bridge-platform-v1","revision":1,"payload":"{\"schema\":1,\"revision\":1}"}}
```

The payload is an opaque string. Decode `response.record.payload` once as JSON
in Bridge, then validate its schema, namespace and safe integer revision against
the outer envelope. Do not parse Box grammar or treat string escaping as state.
Authenticated, supported requests carry `X-Redx-Record-CAS: 1`. A missing record
returns 404 with `{"code":"record_not_found","error":"record not found"}`.
Bridge must require both marker and this code before treating 404 as empty;
an old binary's generic route-not-found response is unavailable, not empty state.
A missing database retains the existing database-not-found response.
A malformed stored envelope is an integrity
error, not an empty record and not permission to overwrite it.

### Compare and swap

`POST` requires write scope and a JSON body:

```json
{"expected_revision":1,"record":{"key":"bridge-platform-v1","revision":2,"payload":"{\"schema\":1,\"revision\":2}"}}
```

`expected_revision: 0` means the record must be absent. It never matches an
existing record. The next revision must equal expected + 1. Revisions must be
exact integers in `1..9007199254740991`; the maximum cannot be incremented.
The namespace key must match `[A-Za-z0-9_-]{3,64}` and cannot change on updates.
Payload remains opaque: this API does not grant account roles or interpret any
account, payment, entitlement, retention or legal claims inside that string.

Successful response:

```json
{"ok":true,"revision":2,"seq":17}
```

The sequence is a positive safe integer. The response also carries the existing
`X-Redx-Seq` replication sequence. The
existing optional `X-Redx-Wait-Replicas` acknowledgement header is supported;
replica acknowledgement counts are separate from local WAL durability.

A stale revision, duplicate initial creation, concurrent ordinary write, or
namespace collision returns 409:

```json
{"code":"record_conflict","error":"record revision conflict"}
```

No current payload or revision is disclosed by that conflict. Reload the
authoritative state and retry the entire idempotent domain transaction. After a
lost response, a committed retry can correctly conflict; reconcile from state
rather than assuming either failure or a second entitlement grant.

## Atomicity and boundaries

The adapter validates the revision and captures the complete native record value.
The native `Database.CompareAndSwap` checks that whole value (or absence) again
under the table's commit lock and replaces it in one WAL frame. All ordinary
REST, native transaction and BoxQL writes use the same table commit lock.
Partial record writes between the read and native CAS therefore produce a
conflict. The native WAL sync/group durability wait completes before success.
Exact native table lookup prevents full-filename prefix fallback, and failed WAL
tables refuse reads of uncertain in-memory state.
Reads also wait for the WAL ticket behind their snapshot, so concurrent group
commit cannot expose an in-memory entitlement before its fsync succeeds. This
includes absence snapshots: a pending or failed delete cannot masquerade as an
empty ledger.
Async durability is refused with 503. Unsupported backends return 501; there is
no fallback to `Get` followed by `Set` or to BoxQL's undo journal.

The operation rechecks leader status and fencing after any request-body or host
lock wait. A fenced former leader cannot return an authoritative record or
commit a request that was authorized before the fence arrived.

The existing authentication, key scope/database/path prefix, protected master
database, tenant ownership/plan/storage/traffic limits, trusted proxy/IP audit,
website-cookie same-origin check, leader/cluster write gates and native
replication hooks continue to apply. Policy checks require the complete envelope
to be readable and writable; redacted/partial envelopes are refused. Active
Pulse rules make this capability unavailable (503), because the native CAS does
not execute Pulse side effects. Policy/rule definition changes and snapshot
replacement cannot race the host's policy/read/native-commit section.

Provisioning must be a separate reviewed operation. A Bridge key should be bound
to the explicitly chosen existing database, write scope and the application-only
file/box namespace `rxa-bridge-platform.red-xai.db:Record`. The policy engine
cannot express a key prefix containing a record ID; do not rely on that prefix
when policy files are active. This does not authorize a host-admin wildcard key
or website-owner cookie inside Bridge. No keys or permissions are created here.

## Evidence and remaining rollout work

The candidate's tests cover concurrent initial writers and replacements, normal
subfield interference, sync/group acknowledgement followed by simulated crash,
torn final WAL frames, failed fsync, async/follower/path refusal, exact typed and
native Box envelope round trips, restart state, namespace/stale conflicts,
malformed stored state, key/policy denials, website CSRF, cross-tenant and plan
denials, protected-master hiding, and unsupported engines. HTTP tests use real
Host handlers and the real RedX engine with an in-memory HTTP transport; they do
not connect to a production server or open network sockets.

Before Bridge production storage is ready: review/build this exact source,
deploy it through the existing RedX rollout procedure, verify the actual binary
and sync/group configuration, provision a least-privilege service credential,
and run authorized isolated namespace conflict/restart tests on the actual
deployment. The Bridge adapter must use this explicit typed API and remain
unready when it is absent or unverified. These storage changes do not establish
canonical owner/MFA freshness, global moderation/deletion contracts, cross-app
subscription projection, or payment/legal launch approval.

The existing native replication callback logs cluster-log append failures rather
than propagating them back to the engine commit. A positive `seq` is therefore
not independent proof that this particular record reached a replica or that
failover is safe for a paid ledger. This candidate preserves that upstream
mechanism; multi-node error propagation/failover requires separate verification.

The focused `bridge-record-cas` workflow runs this source contract with the race
detector and a four-minute test timeout on hosted Linux and Windows, then builds
`redxd`. It has read-only repository permissions and no deployment/publishing
steps. macOS validation is deferred. Passing it is source evidence, not proof of
production durability, credential scope, account integration or launch readiness.
