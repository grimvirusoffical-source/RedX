# Isolated service-record CAS through the existing native transaction API

This host/adapter capability adds no engine files, BoxQL syntax or data-format changes. It preserves the deployed DB presentation at base `8512e170`. It uses the existing `engine.Database.Begin`, `Txn.Get`, `Txn.Set`, `Txn.Commit`, `Files` and `Checkpoint` methods.

The typed route is `/v1/db/{database}/record-cas/{encoded canonical full record path}`. Every capable response has `X-Redx-Record-CAS: 1`. GET returns `{record:{key,revision,payload}}`; only marked404 `record_not_found` means absence. POST accepts `{expected_revision,record:{key,revision,payload}}` and returns200 `{ok:true,revision,seq}` after native durability. The revision must increase by exactly one, remain a JavaScript-safe positive integer, and retain the immutable key. A stale read/write or first-insert race returns409. Payload is an opaque string, not account identity or authorization evidence.

## Provisioning and supported mode

Provision a **separate Bridge database** with exactly one persistent `rxa-bridge-platform.red-xai.db` file before using this capability. Use the ordinary authenticated administrator API to seed a dedicated bootstrap record such as `Record[ID=0]`; do not overwrite the real ledger record. Missing/multiple/wrong-type files fail503. Exact-file checking prevents convenience routing from aliasing another filename and ensures an absent native transaction read actually registers its version. Do not point this at the legacy canonical account database. Restrict the application credential to this database and the `rxa-bridge-platform.red-xai.db:Record` prefix; give browser users no direct ledger-write credential.

Use sync or group durability, with no active Pulse rules. Async mode is refused. The host currently supports this capability only as a standalone leader: configured peers/static cluster secret, members, promoted-parent history or a remembered former leader fail503. Role/fence/membership changes share a host-level gate with record operations; slow request bodies hold no such gate. This is **not HA or replicated-durability certification**. The legacy replication callback can swallow append failures, and an offset alone does not prove a particular record reached another node. Normal cluster functionality remains available, but this dedicated capability refuses those modes.

## Atomic writes and durable reads

A write reads and validates the current record inside one existing native optimistic transaction, then sets the complete replacement and commits. Native commit validates the read version while holding its table lock, including against REST/BoxQL writers, and uses one WAL frame. Commit waits for sync/group durability. It does not use the separate BoxQL query transaction/undo implementation.

A read captures a native transaction snapshot, checks full-field read policy, forces an existing native checkpoint to flush pending WAL/detect failed or closed storage, then validates the captured read version with read-only transaction commit. Absence follows the same barrier. A changed snapshot retries at most four times. Checkpoint failure refuses the read rather than returning tentative group state or treating a failed delete as absence. Checkpoints rotate/write the isolated database's snapshots and cost I/O; size/rate-limit the ledger accordingly. No logical record changes are made by GET.

All route authentication, key scope/prefix, tenant ownership/paid-plan, protected-master, CSRF/IP, quotas, field policy, safe parsing, leader and replay-state gates remain in effect. This capability is service persistence, not a replacement identity authority, owner/MFA proof, canonical app-membership deletion contract, payment verification or legal approval.

## Verification

Host tests exercise real HTTP/native round trips, first-write races, restart persistence, malformed envelopes, key and field restrictions, tenant/plan/CSRF/master gates, unsupported modes, slow bodies, pending-body fencing and in-flight demotion synchronization. Adapter tests exercise exact pre-provisioned file isolation, native concurrency and deterministic group-fsync success/failure for values and deletions. Fault injection accesses the native engine's pre-existing internal test I/O seam through fixture-only reflection/unsafe; production code imports no unsafe and engine files remain byte-identical to the base.

Before production use, review the complete candidate, verify backup/restore and actual scoped namespace provisioning, then rerun real BridgeStore-to-native-daemon checks on the final candidate. Local synthetic identity/plans and standalone WAL tests do not establish canonical account/MFA, production or payment readiness.
