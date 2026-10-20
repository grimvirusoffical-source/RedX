# Backup and restore

```sh
redx backup --out nightly.rxbk                     # ONLINE: owner login or host-admin key; writes paused briefly
redx backup --offline --data-dir /var/lib/redx --out cold.rxbk
redx restore cold.rxbk --data-dir /var/lib/redx [--force]
```

`--offline` does not need an API key. If redxd is **stopped**, it copies the data dir directly (it holds `redxd.lock` while it does). If redxd is **running**, the command drops a request under `<data>/backup/` and the daemon pauses writes, then writes a consistent archive. That wait is 30 seconds. `--force` is only the fallback when the running daemon does not answer: the copy can then be inconsistent. Stop redxd before `redx restore`.

## Encryption

Backups are always encrypted. Nothing in the file is readable without the key: not the databases, not `keys.json`, not `tenants.json`, not the update signing key. The file is `RXBK2`: a short header line (mode, Argon2id parameters, salt, key fingerprint), then a Red-SecretsXAI RSX3 v2 stream (ChaCha20-Poly1305 chunks under a random data key wrapped by the passphrase-derived or host backup key; the header is bound as associated data, and a truncated file fails).

Two key modes:

- **Passphrase (recommended).** Set `REDX_BACKUP_PASSPHRASE`, or pass `--passphrase-file FILE`. At least 12 characters. The key is derived with Argon2id (t=3, 64 MiB, p=4, random 16-byte salt per backup). For an online backup the CLI sends it in `X-RedX-Backup-Passphrase`, which the server accepts only over TLS or from loopback; the server can also use its own `REDX_BACKUP_PASSPHRASE`.
- **Host backup key (fallback).** Without a passphrase, the host's `<data>/backup.key` (32 random bytes, mode 0600, created on first use) is used. This keeps SDK `backup()` calls working. **Copy `backup.key` somewhere other than the host**: a backup of a lost disk cannot be restored without it. The file fingerprint is in the backup header so a wrong key is reported as such.

`redx restore` uses `REDX_BACKUP_PASSPHRASE` / `--passphrase-file` for passphrase backups and `--backup-key-file FILE` (or the target's own `<data>/backup.key`) for host-key backups. A wrong passphrase, a wrong key or a changed byte is refused before anything is written.

Older backups (plain `.tgz`, and `RXBK1` files from the AES-GCM era) are refused with "unsupported legacy backup format; create a new backup with this version". They are not decrypted or unpacked.

## Contents

A host backup (online or offline) contains:

- every database under `dbs/`
- `keys.json` — key records, **hashes only**, never the key material
- `ttl.json` — TTL deadlines
- `tenants.json` — which account owns which hosted database, when that file exists
- `updates/signing.key` and `updates/signing.key.meta` — the update-signing private key
- `connect/connect.json` and `connect/id.key` — connected apps (grants), so app keys can still be listed and revoked after a restore
- `manifest.json` — format version and the SHA-256 and size of every other entry

It does **not** contain TLS keys, the cluster secret, the audit log, hosted apps (`hosted/`), `backup.key` or `cluster.json`. A cluster replication snapshot is smaller on purpose: followers do not receive the signing key, `tenants.json` or connect state.

## Restore

1. Stop redxd (`redxd.lock` must be free).
2. `redx restore FILE --data-dir DIR`. The archive is decrypted and unpacked into a temporary directory and checked first: every entry must match the manifest (and nothing may be missing or extra), and the manifest and `keys.json` versions must be ones this release knows. Only then is anything moved into place.
3. If `DIR` already has state, pass `--force`. Existing `dbs/`, `connect/`, `hosted/` and `audit.log` are renamed to `<name>.pre-restore-<time>`, not deleted, and the paths are printed.
4. The signing key is written to `<data>/updates/signing.key` (mode 0600). If this host was configured with `update_signing_key_file` pointing somewhere else, copy the restored file there (or point the setting at `updates/signing.key`) before the next start. A key that lived only in `REDX_UPDATE_SIGNING_KEY` is in the archive when the backup was taken by the running daemon; put it back in the environment or in the file.
5. Start redxd. Restore starts a **new replication history** (the oplog and replication id are removed). Followers full-resync from the restored leader. Hosted tenants see their databases again because `tenants.json` is restored with them. Hosted apps are not in the backup: redeploy them.
