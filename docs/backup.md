# Backup and restore

```sh
redx backup --out nightly.tgz                      # ONLINE: admin key; writes paused briefly (snapshot)
redx backup --offline --data-dir /var/lib/redx --out cold.tgz   # OFFLINE: refuses while redxd runs (cleanest)
redx restore nightly.tgz --data-dir /var/lib/redx [--force]     # stop redxd first; --force moves existing dbs aside, never deletes
```
Backups contain databases + key records (hashes only) + TTL deadlines. They do **not** contain TLS keys, node secrets, the audit log or `cluster.json`.
A restore starts a new replication history: followers will full-resync from the restored leader. Protect backups like the key store — they include key hashes and all your data.
