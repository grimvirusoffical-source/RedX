# Backup and restore

```sh
redx backup --out nightly.tgz                      # ONLINE: owner login or host-admin key; writes paused briefly
redx backup --offline --data-dir /var/lib/redx --out cold.tgz
redx restore cold.tgz --data-dir /var/lib/redx [--force]
```

`--offline` does not need an API key. If redxd is **stopped**, it copies the data dir directly (it holds `redxd.lock` while it does). If redxd is **running**, the command drops a request under `<data>/backup/` and the daemon pauses writes, then writes a consistent archive. That wait is 30 seconds. `--force` is only the fallback when the running daemon does not answer: the copy can then be inconsistent. Stop redxd before `redx restore`. `--force` on restore moves existing databases aside; it does not delete them.

A host backup (online or offline) contains:

- every database under `dbs/`
- `keys.json` — key records, **hashes only**, never the key material
- `ttl.json` — TTL deadlines
- `tenants.json` — which account owns which hosted database, when that file exists
- `updates/signing.key` and `updates/signing.key.meta` — the update-signing private key

It does **not** contain TLS keys, the cluster secret, the audit log or `cluster.json`. A cluster replication snapshot is smaller on purpose: followers do not receive the signing key or `tenants.json`.

## Restore

1. Stop redxd (`redxd.lock` must be free).
2. `redx restore FILE --data-dir DIR`. If `DIR` already has databases, pass `--force`; they are renamed to `dbs.pre-restore-<time>`, not deleted.
3. The signing key is written to `<data>/updates/signing.key` (mode 0600). If this host was configured with `update_signing_key_file` pointing somewhere else, copy the restored file there (or point the setting at `updates/signing.key`) before the next start. A key that lived only in `REDX_UPDATE_SIGNING_KEY` is in the archive when the backup was taken by the running daemon; put it back in the environment or in the file.
4. Start redxd. Restore starts a **new replication history** (the oplog and replication id are removed). Followers full-resync from the restored leader. Hosted tenants see their databases again because `tenants.json` is restored with them.

Protect backup files the way you protect the key store. They hold every database and the update-signing key.
