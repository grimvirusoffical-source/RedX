# Query engine

Package `engine/query` implements [BoxQL](boxql.md). It is used by `redxd` (`POST /v1/bx`, `/v1/db/{db}/bx`, the WebSocket `bx/watch`), the `redx bx` command and the `bx()` / `watch()` methods of both SDKs. Scope, path-prefix and `.red-xai-sec` policy are enforced for every request ([API reference](api.md)).

## Using the engine

```go
db, _ := query.New(query.Config{Store: st, Auth: policy, Indexes: ix, Links: le}) // Auth is required
res, err := db.Exec(ctx, principal, `{Get[]} = players:Player[Level >= $min] -> Name, Sort = Name, Limit = 10`, map[string]interface{}{"min": 5})
```

```boxql
{Get[]} = players:Player[Role = "Admin", WalletBalance > 1000] -> [Username, WalletBalance] @> Guild, Sort = -WalletBalance, Limit = 50
{Set[]} = players:Player[ID=1].Inventory[id=10].Qty = 5
{Tx[]} = [ {Require[]} = players:Player[ID=7, Gold >= 5], {Set[]} = players:Player[ID=7].Gold = Gold - 5 ]
```

One command per call (a trailing `;` is fine). Values go in `$name` parameters, never into the text; a parameter is never
parsed. The front-end is in `lex.go`, `parse.go`, `ast.go` and `format.go`.

* **Commands.** `Get`, `Add`, `Set`, `Delete`, `Require`, `Tx`, `Explain`, `Watch` ([BoxQL](boxql.md)).
* **Expressions.** `& | !`, `= != < <= > >=`, `+ - * /`, `in ;[..]:`, `in lo..hi`, `starts`, `has` / `hasany` (text search), `= NELL`, `TRUE FALSE NELL`, `$param`. Nested fields use dots and `[id=n]`.
* **Semantics.** Two-valued logic: NELL, a missing field or a type mismatch makes an ordering comparison false. Arithmetic on non-numbers or `/0` gives NELL. `Sort` uses NELL < bool < number < string < array < box < link. The default order is record address, so the chosen plan never changes the result.
* **Round trip.** `query.StmtString` prints any parsed command as canonical text; parsing it again yields the same tree (tested, plus a fuzz target `FuzzParse`/`FuzzExec`).
* **Aggregates and grouping** (`Count Sum Avg Min Max`, `Group =`) stream; **links** are read with `@>` and written as link values; `@!>` cascades on `Delete`.
* **Writes are all-or-nothing** : each writing command, and a whole `{Tx[]}`, journals before-images under the database write lock and restores them on failure.

### Planner and Explain
The access path comes from conditions on the primary source only: primary-key lookup (`ID=n`/`in`), exact index (`=`, `in`), text index (`has`), prefix index (`starts`), range index (comparisons, `in lo..hi`), or a union of indexed `|` branches; otherwise a scan. Indexes are only a prefilter: the full filter is always re-applied, so Fold/array indexes stay correct. Strings over 256 bytes are not indexable (scan). `Result.Access` and `Result.Scanned` report what happened. The planner is a fixed ranking with no statistics. `{Explain[]}` prints the plan (tested to agree with execution on 600 random filters, indexed versus scan).

### Authorization (fail closed)
`Config.Auth` is mandatory (`nil` is `ErrNoAuth`; `query.AllowAll{}` is the explicit opt-out; a nil `*sec.Policy` denies everything). Checks run before any storage read when the box is fixed: box-level read, then fields named in the command (filters, sort keys, follows). Rows are gated at runtime (with `OwnerOf` if given) and every returned field is masked (denied field = NELL, removed from `-> *`, also inside nested boxes). `Add` needs box write plus per-field write; `Set` needs the read gate plus per-field write; `Delete` needs delete on the box and on every cascaded record; a `Tx` authorizes each command. A field-only grant does not open a box for querying. An unknown file is authorized first, so "forbidden" and "missing" look alike to an unauthorized caller. `Explain` is authorized like the command.

### Limits (`query.Limits`, zero = default)
| Limit | Default | Limit | Default |
|---|---|---|---|
| MaxQueryBytes | 64 KiB | MaxRows | 10,000 |
| MaxTokens | 8192 | MaxScan | 1,000,000 records |
| MaxDepth | 64 | MaxWrites | 10,000 (incl. cascades, whole Tx) |
| MaxInList | 1000 | MaxResultBytes | 16 MiB |
| MaxJoins (`@>` follows) | 4 | MaxColumns | 1024 |
| MaxTxStmts | 1000 | MaxParamBytes | 1 MiB |
| MaxPathDepth | 16 | | |

A result over `MaxRows` is `ErrLimit`. The context is checked every 256 rows. Errors wrap sentinels (`ErrSyntax`, `ErrLimit`, `ErrParams`, `ErrNoFile`, `ErrAmbiguous`, `ErrExists`, `ErrConflict`, `ErrType`, `ErrNoLinks`, `ErrNoAuth`, `ErrTooLarge`, `ErrBadStatement`) plus `sec.ErrDenied`; syntax errors are `*SyntaxError` with line/column and `Context(src)` prints a caret.

### Known limits
See [BoxQL](boxql.md#17-known-limitations) (bare-box scans, standalone link files not followed by `@>`, transaction isolation = the write lock, Watch delivery, aggregates, hyphenated names).
