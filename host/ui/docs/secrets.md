# Red-SecretsXAI record seals

The console can seal and open **one record value** with Red-SecretsXAI password mode. This is separate from pack encryption.

It does **not** encrypt database files. It does **not** read, re-wrap, migrate, or rewrite existing packs, RXSEC ciphertext, keystores, or any Red-SecretsXAI payload already stored. Seal and Open return text to the editor. The only write is the ordinary record Save you press afterwards, and that write is that one record.

## What you do in the console

1. Open **Data Explorer**, open a record, and stay on **Box text**.
2. **Seal** asks for a data password (at least 8 characters). That password is not your Red-XAI Account password and it is not an API key. RedX does not store it and does not write it on the audit line.
3. The editor shows an envelope. Nothing is stored yet. Press **Save** to keep it on that record.
4. **Open** puts the plaintext back in the editor and does not write. Saving afterwards stores plaintext for **this record only**.

If the editor already contains `red-xai-encrypt/rsxc1`, Seal refuses. Wrapping that text again would replace an envelope, and the console will not do that.

BoxQL Studio does not seal queries. A second seal path would use different associated data and could not open the Data Explorer envelope.

Sign-in is unchanged. An API key or an existing Red-XAI Accounts console session (`rxs_…`) authorizes the call. There is no new user store.

## API

| Method | Path | Scope | Effect |
|---|---|---|---|
| `GET` | `/v1/db/{db}/secrets` | read | Status. Does not read stored ciphertext. |
| `POST` | `/v1/db/{db}/secrets/seal` | write | Body `password`, `plaintext`, `path`. Returns Box text. `stored` is false. |
| `POST` | `/v1/db/{db}/secrets/open` | read | Body `password`, `box`, `path`. Returns plaintext. `stored` is false. |

`path` is the record address, for example `players.red-xai.db:Player[ID=1]`. It is bound into the seal as associated data (`redx-secrets/v1`, the database name, and the path). Opening the same envelope at another path fails. A prefix-restricted key must send a path inside its prefix.

A wrong password is **422**, not 401, so the console does not sign you out. Eight failed opens per minute per key return **429**. A short password is **400**. If the host cannot spare the Argon2id memory, the call is **503** and nothing is written.

Audit events are `secrets.seal` and `secrets.open` (`bytes=… stored=false`) and `secrets.open.denied` (`reason` is `open failed`). The password, the plaintext, and the ciphertext are not on the line.

The password is sent to **this** host over the existing authenticated API and wiped after the request. The browser does not run the library.

## Binding

`redxd` links a pure-Go port of Red-SecretsXAI at `internal/rsx`, pinned to commit `77f81c9abc5e09fb4015ebc5b8a752c31ea190e2` (`sdk/go/rsx` on the `go-port` branch). `CGO_ENABLED=0` stays the product default. CGO and `librsx` are **not** wired: a cgo build would not be the static binary this project ships, and a JavaScript copy of the library would violate the console CSP (`script-src 'self'`, no build step, no CDN).

To refresh the vendor, copy the library sources from that package at a chosen commit into `internal/rsx` and update `internal/rsx/VENDOR.txt`. Do not point the copy at existing ciphertext, and do not add a migration that rewrites stored envelopes. The test vectors are intentionally not imported.

The envelope is Box text. The password-wrapped key lives inside that new envelope (`KXAI`), in a temporary directory that is removed when the call returns. There is no host-wide keymap and no re-wrap of older data.

## Configuration

| Key | Env | Flag | Default |
|---|---|---|---|
| `secrets_kdf` | `REDX_SECRETS_KDF` | `--secrets-kdf` | `interactive` |

* `interactive`: Argon2id t=2, m=65536 KiB (64 MiB), p=1. This is the default for new seals.
* `librsx`: Argon2id t=3, m=262144 KiB (256 MiB), p=4, the library defaults. A small host returns 503 and writes nothing.

Changing the profile applies to the **next** seal only. It does not re-wrap envelopes already stored, and it does not touch pack AES. Opening an envelope uses the cost stored in that envelope.

`Config.SecretsKDFOverride` is a test-only field. It is not read from TOML or the environment.

## Limits

* Losing the password means that envelope cannot be opened. RedX has no recovery.
* Anyone who can read the record can read the ciphertext. This is not file encryption and not access control.
* Pack `Encrypt` rules stay AES-256-GCM. See [Policy and encryption](policy-and-encryption.md).

Existing encrypted-at-rest content is not migrated by this feature.
