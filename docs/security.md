# Security

This page collects the security model of the host. See also [SECURITY.md](../SECURITY.md) for how to report a vulnerability.

## Host security notes

* **Keys are secrets.** They are shown once, stored only as salted argon2id hashes (m=19 MiB, t=2 by default), compared in constant time, and never logged (the audit log
  records only the 8-character key id, the source IP, route class and reason; request data paths are not logged). Put keys in env vars or a secret manager, not in command lines
  (`--key` shows up in process lists), source control or client-side code. Use the narrowest scope/db/prefix and a TTL; rotate with `redx key rotate`.
* **TLS.** The default listen address is loopback. If you listen on anything else without TLS, `redxd` prints a warning: keys and data would be readable on the network.
  Use `tls = "auto"` (self-signed; clients pin the printed SHA-256 with `--pin`/`REDX_PIN`) or `tls = "files"` with a real certificate, or terminate TLS in a reverse proxy.
  Node-to-node traffic (replication, snapshots, join) also needs TLS across untrusted networks; followers pin the leader's certificate fingerprint.
* **Firewall.** Expose the port only to the networks that need it (private LAN/VPN such as WireGuard/Tailscale). Do not port-forward a bare redxd to the internet.
* **Brute force.** 20 failed authentications per minute per source IP → `429`, and the sign-in endpoints have their own per-IP bucket. The source IP is the socket peer unless `trusted_proxies` / `REDX_TRUSTED_PROXIES` lists that peer (an IP or a CIDR). Only then is the client taken from `X-Forwarded-For` (the rightmost hop that is not itself a trusted proxy) or, if that header is empty, `X-Real-IP`. A spoofed forwarding header from any other peer is ignored, and audit lines use this same address. Behind Caddy on the same machine set `trusted_proxies = ["127.0.0.1"]` (and `::1` if it connects over IPv6). Leave the list empty when redxd is reached directly.
* **At rest.** `keystore_encrypt = true` + env `REDX_KEYSTORE_PASSPHRASE` encrypts `keys.red-xai-keys` (`REDXKS2`: ChaCha20-Poly1305 under an Argon2id-derived key, Red-SecretsXAI; an older `REDXKS1` AES-GCM keystore is refused at startup and must be recreated). Database files (`.red-xai.db`, `-qs`, `-qs-ls`) are **not** encrypted by the host (use disk encryption). **Packs** are encrypted when a `.red-xai-sec` `Encrypt` rule names them (master key from a key file, see below); media libraries and indexes are not.
  The data directory is created 0700 and the keystore 0600 (engine data files rely on the 0700 directory; Windows: the installer restricts `C:\ProgramData\RedX` to SYSTEM and Administrators).
* **Secrets are never shown as defaults.** `redx`/`redxd -h` print where a secret comes from ("currently set from $REDX_KEY"), never its value; `GET /v1/admin/config` shows `cluster_secret` and `join` as "(set, hidden)".
* **Pairing codes** (`RP-...` sign-in, `RX-...` join and app connect) are single use, short-lived, rate-limited and stored only as SHA-256; the key is created when a code is redeemed. App connect codes also need the app's PKCE verifier, see [Connecting apps](connect.md).
* **Join tokens** are single-use and short-lived; **node secrets** and the optional `cluster_secret` grant replication access (read everything, including key hashes). Treat them like admin keys.
* **Offline commands** (`redx key … --offline`, `restore`) need filesystem access to the data dir — by design that equals root of the host. Offline key changes made while a leader runs are noticed within ~1 s and replicated.
* **Updating:** replace the binaries and restart the service. Keep followers on the same or a newer version than the leader's *log format* (there is currently one log format).

## Access policy and API keys

The host builds the policy the engines enforce from **two** sources:
(1) a generated grant per API key from its scope/db/prefix, which is a **hard ceiling** (a policy file can narrow a key but never widen
it; a read key stays read-only whatever the file says), and (2) your policy: hand-placed `*.red-xai-sec` files in the db folder
and/or the API-managed one (`PUT sec`). Keys carry **roles** (`redx key create --roles guest`); the policy refers to them as `role:guest`.
Default is deny for everything a key's grant does not cover; deny beats allow at equal specificity. The policy is checked
**inside the engines** (BoxQL: `query.Authorizer`, scripts: `code` host functions) and **again at the host** for REST reads/writes/deletes, resolve, index hits,
packs, media, pulse events. Behaviour you should know:

* Record reads over REST are **redacted** (denied fields removed, also inside nested boxes and resolved links); a denied whole file/box is 403; a write that contains a denied field is 403.
* Once any policy exists, the raw path query `POST /v1/query` is **admin only** (it returns whole records and cannot be field-filtered). Use `/v1/bx`.
* Pulse event `data` is dropped for non-admin keys when a policy exists.
* Policy changes via the API apply immediately and replicate as definitions; **hand-placed `.red-xai-sec` files are read when the db opens** (no hot reload; restart or use `PUT sec`). A policy file that fails to parse stops the database from opening: it never falls back to "no policy".
* `Encrypt` rules (`{Encrypt[1]} = [ {File[]} = "vault*", {Key[]} = "main" ]`) apply to **packs only** (see below). They are *not* enforced for `.red-xai.db` / `-qs` / `-qs-ls` data files (use disk encryption), and a media library matched by an Encrypt rule is refused (501), because Range reads over ciphertext are not implemented.
* Keys with a record-id or wildcard prefix (e.g. `file:Box[ID=1]`) keep working on the old REST routes but get **403** on BoxQL, scripts and the other policy-checked operations, because those prefixes cannot be expressed as policy resources.

## Master key and encrypted packs

`redxd keygen [--out FILE] [--id ID] [--data-dir DIR]` writes 32 random bytes
as `<id> <64 hex chars>` lines (`#` comments; mode 0600; refuses to overwrite; prints nothing secret). `redxd` loads `master_key_file`
(`--master-key-file`, `REDX_MASTER_KEY_FILE` = a *path*) or, if present, `<data_dir>/master.key`. On POSIX a file readable by group/others is
**refused** and the daemon does not start; a configured but missing file is an error. Several lines = key rotation (the first line is the current key; older ids still decrypt).
Error messages never echo key material. **Back the key file up separately from the data: without it encrypted packs are unreadable.** Windows: ACL
permissions are not checked by the daemon (the installer restricts the folder).


A pack whose name matches an `Encrypt` rule is stored as ChaCha20-Poly1305 chunks (RXSEC v2; v1 AES-GCM files are refused) (the key id is in every ciphertext).
Verified: no plaintext at rest; a byte flipped on disk is detected and the download fails; a plaintext file found in a pack that is now under a rule fails closed (500);
with no master key loaded the write is **503** and no pack folder is created. Limits: encrypted packs have **no HTTP `Range`** and no `Content-Length`
(`Accept-Ranges: none`, `X-Redx-Encrypted: 1`; a `Range` request gets the whole file), and the size/ETag the API reports are for the stored (ciphertext) form.

