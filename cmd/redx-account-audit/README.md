# Read-only checkpoint account metadata

Build and test from the RedX module root:

```sh
go test ./cmd/redx-account-audit
go build -o /protected/path/redx-account-audit ./cmd/redx-account-audit
/protected/path/redx-account-audit /protected/path/checkpoint-copy TARGET_LOGIN
```

Use a protected, read-only checkpoint copy. The helper never opens a RedX engine,
replays WALs, changes account data, or contacts another service. It rejects inputs
over 64 MiB and validates the checkpoint footer, body length, CRC32C, and Box
grammar before inspecting records. Errors omit paths and private parser input.

The supplied target must exactly match a direct string `username` or `email`
field, ignoring case. There are no substring, alias, or provider-specific email
rules. Box-valued and JSON-object-string `Record` entries are supported. Nested
Box containers and arrays are visited; links are not followed.

Output contains Record-type/readable/matching counts, sorted safe field names,
and only boolean values of `emailVerified`, `email_verified`, and `emailOK`.
`activatedMs` is reduced to presence, type, and whether its numeric value is
positive. Usernames, addresses, IDs, timestamps, credentials, and other field
values are never printed. Unusual field names are suppressed.

This is metadata inspection, not verification of an email, authentication proof,
or proof of the deployed account schema. Boolean names and a positive activation
number have no assumed operational meaning. The available `redx/box` parser may
differ from a legacy deployment. JSON duplicate keys use Go's last-key-wins
behavior. A zero match does not establish that an account is absent: encoding,
schema differences, or unreplayed WAL data can explain it. A checkpoint copy is
not a complete account-system backup or a restore test. All test data is synthetic.
