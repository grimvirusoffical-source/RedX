# Access policy and encryption

Package `engine/sec`. The host builds the effective policy from API-key grants and your `.red-xai-sec` files; see [Security](security.md#access-policy-and-api-keys) for how the host applies it.

## Policy documents (`.red-xai-sec`)

### Policy document

A Box document. Unknown entries or unknown keys inside an entry are errors (a typo must not silently open or close access).

```
{Role[1]}    = [ {Name[]} = "mod", {Scopes[]} = ;["chat.write"]:, {Inherits[]} = ;["player"]: ];
{Scope[1]}   = [ {Name[]} = "chat.write", {Actions[]} = ;["read","write"]:, {Resource[]} = "chat.red-xai-db-qs" ];
{Rule[1]}    = [ {Effect[]} = "deny", {Who[]} = ;["role:guest"]:, {Actions[]} = "*",
                 {Resource[]} = "players.red-xai.db:Player.Email", {Priority[]} = 0, {Owner[]} = FALSE ];
{Encrypt[1]} = [ {File[]} = "vault*", {Key[]} = "main-2026" ];
```

* **Role**: `Name`, optional `Scopes` (names), optional `Inherits` (other roles; cycles and unknown names are errors).
* **Scope**: `Name`, `Actions`, `Resource`. Holding the scope (directly, or through a role) grants those actions on that resource (an allow with priority 0).
* **Rule**: `Effect` (`allow` / `deny`), `Who` (`*`, `role:NAME`, `scope:NAME`, `user:ID`; one string or an array), `Actions` (`read`, `write`, `delete`, `exec`, or `*`), `Resource`, optional `Priority` (integer, `-1000..1000`, default 0), optional `Owner` (TRUE = only when `Resource.Owner` equals the principal id).
* **Encrypt**: `File` glob and master key `Key` id; `Policy.EncryptionFor(file)` returns the first match.
* Resource patterns are `file`, `file:Box` or `file:Box.Field`, with `*` and `?` wildcards per segment. A pattern covers everything below the level it names (`players.red-xai.db` covers every box and field in it), but a pattern naming a deeper level does **not** match a request for the coarser level.
* Limits: 4 MiB document, 10 000 entries, 256-byte patterns, 64-byte names.

### `Authorize(Principal{ID, Roles, Scopes}, Action, Resource{File, Box, Field, Owner}) Decision`

**Default deny.** Candidates are the scope grants the principal holds plus all matching rules. The winner is, in order:

1. highest `Priority` (scope grants count as 0);
2. most specific resource pattern (more segments named, then more segments without wildcards);
3. `deny` beats `allow`.

No candidate → deny. Invalid input (unknown action, empty file, control characters, field without box) → deny. Unknown roles grant nothing. The `Decision` names the deciding rule (`Rule[ID=3]`) for audit. `Check` returns an error wrapping `ErrDenied`. `FilterFields` helps with whole-box reads: the caller must authorize per field.

### Encryption (`Encrypt`, `Decrypt`, `Rewrap`, plus `*Bytes` forms)

* AES-256-GCM, standard library only. Each file gets a fresh random 32-byte data key, wrapped by a caller-supplied 32-byte **master key** (`NewMasterKey(id, key)`, held in a `Keyring`).
* The master key is never written to disk, logged or printed: it exists only in memory; `%v %+v %#v %s %x %q`, JSON and text marshalling all print or return only the id (tested, including through reflection-based printers); `Destroy()` zeroes it.
* Streaming: the plaintext is split into segments (default 64 KiB, `Options.SegmentSize` 4 KiB..1 MiB), each with its own random 96-bit nonce (tested for uniqueness over many segments and files).
* Layout (big-endian): `"RXSEC" | 1 | flags | keyIDLen | keyID | fileID(16) | segSize(4) | salt(16) | wrapNonce(12) | wrappedKey(48)`, then per segment `ctLen(4) | nonce(12) | ciphertext+tag`.
* Authenticated data: the wrap covers key id, file id, segment size and the caller's `Options.Context`; each segment covers file id, segment size, index, a final-segment flag and the context. So tampering, reordering, dropping, duplicating or appending segments, truncation, and moving ciphertext to another file or context (pass the file name or record address as `Context`) all fail with `ErrAuth` / `ErrTruncated`. A wrong master key fails with `ErrAuth`; an unknown key id with `ErrUnknownKey`; garbage with `ErrFormat`. On any error `DecryptBytes` returns no plaintext; the streaming `Decrypt` may already have written earlier, verified segments to `dst`, so write to a temp location and commit on success.
* The wrap key is derived per wrap (HKDF-SHA256 from master key, random salt), so one master key never encrypts under the same key twice.
* **Rotation**: `Rewrap(dst, src, from KeySource, to *MasterKey, opts)` unwraps the data key with the old key and re-wraps it under the new key, rewriting only the header. The segments are unchanged, so rotation is cheap and does not read the file's data. Add the new key to the keyring, `SetCurrent`, rewrap each file, then `Remove` the old key.

## Limitations

* There is no automatic rotation driver; the caller iterates over files and calls `Rewrap`.
* `Rewrap` does not change the data key. Someone who held the old master key and a copy of the old header can still decrypt old data, so recovering from a key compromise requires a full re-encrypt.
* The policy decision carries the rule name only; there is no per-decision audit log.
* `Encrypt` rules apply to packs only. Database files are not encrypted by RedX; use disk encryption. The console can seal one new record value with Red-SecretsXAI ([secrets.md](secrets.md)). That path does not change pack AES and does not rewrite existing ciphertext.
* The master key is read from a key file with strict permissions (see [Security](security.md#master-key-and-encrypted-packs)). Other sources such as a KMS are not supported.
* Hand-placed `.red-xai-sec` files are read when the database opens.
