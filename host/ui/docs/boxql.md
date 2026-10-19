# BoxQL: the RedX query and command language

BoxQL is RedX's own language for reading, changing, searching and watching data. It is written in the
**same grammar as Box files** ([Box grammar](box-grammar.md)): braces, `[ID=N]`, `=`, `[...]`, `;[...]:` arrays,
`<< comments >>`, `@>` / `@!>` link operators and `(N)` TTL markers. A command is itself a Box entry:

```
{Verb[]} = <body>
```

so one grammar covers data, rules and queries, and there is nothing else to learn or to escape. It is
implemented by `engine/query`, served at `POST /v1/bx` and `GET /v1/db/{db}/bx/watch`, and available as `redx bx`,
`bx()` / `watch()` in the JS and Python SDKs.

* Test coverage includes parser round-trip, injection resistance, every command, scope/prefix/policy
  enforcement, planner agreement and fuzzing. See [section 17](#17-known-limitations) for known limitations.
* Every `boxql` code block in this document is parsed by the test-suite (`engine/query/docs_test.go`), so the
  examples cannot rot.

## 1. At a glance

```boxql
<< read: filter in [...], columns after ->, follows with @>, options after commas >>
{Get[]} = players:Player[Role = "Admin", WalletBalance > 1000] -> [Username, WalletBalance] @> Guild, Sort = -WalletBalance, Limit = 50

<< write one field, add a record, delete records >>
{Set[]} = players:Player[ID=1].Inventory[id=10].Qty = 5
{Add[]} = players:Player[ID=9] = [ {Username[]} = "ann", {WalletBalance[]} = 0 ]
{Delete[]} = players:Player[WalletBalance < 1 & Role != "Admin"]

<< all-or-nothing transaction with a guard >>
{Tx[]} = [
    {Require[]} = players:Player[ID=7, WalletBalance >= 5],
    {Set[]} = players:Player[ID=7].WalletBalance = WalletBalance - 5,
    {Set[]} = players:Player[ID=8].WalletBalance = WalletBalance + 5
]

<< aggregate, full-text search, plan, subscription >>
{Get[]} = players:Player[ID=*] -> [Guild, n = Count(), total = Sum(WalletBalance)], Group = Guild, Sort = -total
{Get[]} = posts:Post[Body has "dragon slayer"] -> [Title]
{Explain[]} = [ {Get[]} = players:Player[Username = $name] -> Username ]
{Watch[]} = players:Player[WalletBalance > 1000]
```

## 2. Lexical structure

The lexical rules are those of Box files ([Box grammar](box-grammar.md), section 1) plus operators and `$name` parameters.

| Item | Rule |
|------|------|
| whitespace | space, tab, CR, LF between tokens; newlines carry no meaning |
| comment | `<< ... >>`, may span lines, does not nest; a comment is whitespace |
| identifier | letter or `_`, then letters, digits, `_` and `-` (so `Qty-1` is **one** name; write `Qty - 1`) |
| keywords | `TRUE`, `FALSE`, `NELL` (case-insensitive); `ID` (case-insensitive, only inside `[...]`); `in`, `starts`, `has`, `hasany` (lower case, only after an operand); verbs and option names are case-sensitive |
| string | `"..."` with JSON escapes; the only quoting, there are no single-quoted strings |
| number | `12`, `-3`, `1.5`, `2e3` (a leading `-` is a sign only where an operand is expected) |
| parameter | `$name` (letters, digits, `_`), a value supplied by the caller (§13) |
| operators | `= != < <= > >= + - * / & \| ! -> @> @!> .. ;[ ]: ?` and `,` `;` `.` `:` `( ) [ ] { }` |

Line and column in error messages are 1-based; columns count characters.

## 3. Grammar (EBNF)

ISO 14977 flavoured, as in the [Box grammar](box-grammar.md). `ws`/comments are allowed between any two tokens.

```
command    = "{" verb "[]" "}" "=" body [ ";" ] ;
verb       = "Get" | "Add" | "Set" | "Delete" | "Require" | "Tx" | "Explain" | "Watch" ;

body       = get | add | set | delete | require | tx | explain | watch ;

get        = source [ "->" projection ] { follow } { "," option } ;
projection = "*" | item | "[" item { "," item } [ "," ] "]" ;
item       = "*" | ident "." "*" | [ ident "=" ] expr ;           (* ident "=" names the column *)
follow     = ( "@>" ) [ ident "=" ] fieldpath [ "?" ] ;            (* read through a link field; ? = optional *)
option     = "Sort" "=" sortkeys | "Limit" "=" count | "Offset" "=" count | "Group" "=" exprs ;
sortkeys   = sortkey | ";[" sortkey { "," sortkey } "]:" ;
sortkey    = [ "-" | "+" ] additive ;                              (* - = descending *)
count      = number | param ;
exprs      = additive | ";[" additive { "," additive } "]:" ;

add        = source "=" record [ ttl ] ;                           (* source must be file:Box[ID=n] or file:Box *)
set        = source "." assign [ ttl ]                             (* one assignment *)
           | source "." "[" assign { "," assign } "]" [ ttl ]      (* several *)
           | source "=" record [ ttl ] ;                           (* replace / upsert the whole record *)
assign     = fieldpath "=" expr ;
delete     = source [ "." fieldpath ] ;                            (* records, or one field of them *)
require    = source [ "," "Count" "=" count ] ;
tx         = "[" command { ( "," | ";" ) command } [ "," ] "]" ;   (* no Tx, Explain or Watch inside *)
explain    = "[" command [ "," ] "]" ;
watch      = source | "Topic" "=" string ;

source     = ( ident | string ) ":" ( ident | "*" ) [ filter ]     (* file ":" box *)
           | ident [ filter ] ;                                    (* bare box: the one readable file that has it *)
filter     = "[" ( "*" | "ID" "=" "*" | number | param | expr { "," expr } ) "]" ;
                                                                   (* number/param = ID=...; "," between filters = AND *)

record     = "[" { entry [ "," | ";" ] } "]" ;
entry      = "{" ident [ "[" [ [ "ID" "=" ] number ] "]" ] "}" "=" ( record | link | expr ) [ ttl ] ;
link       = string ":" refpath [ ( "@>" | "@!>" ) string ":" refpath ] ;
ttl        = "(" [ "~" ] number ")" [ "*" ] ;                      (* (N) fixed, (~N) sliding, (N)* checkpoint *)

expr       = and { "|" and } ;                                     (* or *)
and        = not { "&" not } ;                                     (* and *)
not        = "!" not | predicate ;
predicate  = additive [ ( "=" | "!=" | "<" | "<=" | ">" | ">=" ) additive
                      | "in" ( array | param | additive ".." additive )
                      | "starts" additive
                      | ( "has" | "hasany" ) additive ] ;          (* has/hasany: left side must be a field *)
additive   = term { ( "+" | "-" ) term } ;
term       = unary { ( "*" | "/" ) unary } ;
unary      = "-" unary | primary ;
primary    = number | string | param | "TRUE" | "FALSE" | "NELL" | array | record
           | aggregate | fieldpath | "(" expr ")" ;
aggregate  = ( "Count" "(" ")" ) | ( ( "Sum" | "Avg" | "Min" | "Max" ) "(" additive ")" ) ;
array      = ";[" [ expr { "," expr } ] "]:" ;
fieldpath  = seg { "." seg } ;
seg        = ident [ "[" [ "ID" "=" ] number "]" ] ;
param      = "$" name ;
```

Precedence, loosest to tightest: `|`, `&`, `!`, comparison/`in`/`starts`/`has`, `+ -`, `* /`, unary `-`.

Notes on the shape:

* `,` between the filters inside `[...]` is AND, so `[Role = "Admin", Gold > 5]` equals `[Role = "Admin" & Gold > 5]`.
  Commas **after** the projection start options (`Sort`, `Limit`, `Offset`, `Group`), in any order, each once.
* `Box[3]` is `Box[ID=3]`; `Box[$id]` is `Box[ID=$id]`; `Box[ID=*]` and `Box[*]` mean every record.
* `ID` is also a column: `-> [ID, Name]`, `Sort = ID`. `_file` and `_box` are pseudo columns.
* A file may be written with or without its type extension (`players` for `players.red-xai.db`) if unique;
  quote the full name to create a file (`"arena.red-xai.db":Match[ID=1]`) or to name it exactly.
* One command per request. To run several together use `{Tx[]}`.

## 4. Values and evaluation

* Types are Box types: string, number (float64), `TRUE`/`FALSE`, `NELL`, array, box, link. There is **no implicit
  conversion**: `Level = "5"` does not match `Level = 5`.
* A field that does not exist reads as `NELL` (the data model is schema-less). `Field = NELL` / `Field != NELL`
  test for absence; `<`, `>`, … against a missing field are false (the record is simply not selected).
  `NELL` can only be compared with `=` and `!=`.
* Arithmetic works on numbers only; anything else (including division by zero and overflow) gives `NELL`.
* `Sort` orders `NELL < bool < number < string < array < box < link`; ties are broken by record address, so results
  are deterministic. Without `Sort` records come back in address order.
* `starts` is a case-sensitive string prefix test; `in ;[a, b]:` is membership; `in lo..hi` is an inclusive range;
  `in $list` takes an array parameter.
* `has "words"` is a text search: all terms must occur in the field's tokens; `hasany` needs one. With an `idx`
  text index on the field the term lookup is served by the index, otherwise by scanning; the result is the same.

## 5. Sources, files and records

A *file* holds *records* (top-level entries such as `Player[ID=1]`); a record is a box of fields.

* `players:Player[...]` — file `players`, box `Player`. `players:*[...]` — every box of the file.
* A bare `Player[...]` is allowed in reads: it resolves to the **one file the caller may read** that holds a
  `Player`. Ambiguity is an error naming the files (`name the file, as in file:Player`). Writes must name the file.
* Field paths descend into nested boxes and arrays of boxes by ID: `Inventory[id=10].Qty`, `Stats.Gold`.

## 6. Get

```boxql
{Get[]} = players:Player[Level >= 5] -> [Name, Level], Sort = -Level, Limit = 10, Offset = 20
{Get[]} = players:Player[ID=*] -> *
{Get[]} = players:Player[4]
{Get[]} = players:Player[Stats.Gold != NELL] -> [Name, gold = Stats.Gold], Sort = -gold
{Get[]} = players:Player[ID in ;[3, 4]:] -> [ID, Name]
{Get[]} = "players.red-xai.db":*[Name = "ann"] -> [_box, ID]
```

* No `->` returns every field the caller may read. `-> *` is the same. `-> Alias.*` expands one followed record.
* Items may be computed (`gold = Level * 10`); the name before `=` is the column name.
* The result has `columns`, `rows` (typed JSON), `rows_box` (the same cells as exact Box text), `paths` (the source
  record behind each row), `access` (how records were found) and `scanned`.
* `Limit`/`Offset` take a number or `$param`. A Get returns at most `MaxRows` (default 10 000) rows; exceeding the
  limit is an error, not a truncation.

### Aggregates and grouping

```boxql
{Get[]} = players:Player[ID=*] -> [n = Count(), top = Max(Level), avg = Avg(Level)]
{Get[]} = players:Player[ID=*] -> [Guild, n = Count(), total = Sum(WalletBalance)], Group = Guild, Sort = -total
```

`Count()`, `Sum(x)`, `Avg(x)`, `Min(x)`, `Max(x)`. Aggregates are whole projection items (they cannot be nested or
used in filters). With `Group`, every plain item must be a group key; `Sort` then names output columns.
Aggregation streams: it holds one accumulator per group, not the records.

### Following links: `@>`

A field holding a link (`{Guild[]} = "players":Player[ID=1] @> "guilds":Guild[ID=3]`, or an array of links) is read
through with `@>`. The followed record is addressed by the field name or by an alias:

```boxql
{Get[]} = players:Player[ID=*] -> [Name, Guild.Title, Guild.Rank] @> Guild
{Get[]} = players:Player[ID=*] -> [Name, g.Title] @> g = Guild?
{Get[]} = players:Player[1] -> [Name, owner = o.Name] @> g = Guild @> o = g.Owner
```

* `@> Field` is an inner follow (rows whose link is absent or dangling disappear); `@> Field?` is optional (the
  followed columns are `NELL`). An array of links yields one row per target. Follows chain (up to 4).
* Targets are read through the link engine and authorized before they are read; a target the caller may not read is
  skipped like a dangling link. `@!>` (cascade) links are *not* followed by `@>`; they matter for `Delete`.
* A filter may use followed fields: `players:Player[Guild.Rank >= 3] -> Name @> Guild`.

### Search and indexes

`has`/`hasany` (text), `starts` (prefix), `=`, ranges and `in` use `.red-xai-db-idx` indexes automatically when an
index matches the filter; otherwise the box is scanned. The filter is **always** applied to every fetched record, so
a stale or missing index can change the speed, never the answer. `{Explain[]}` shows the choice (`access: idx
ByName (exact) ...` or `scan`) and `access` in a result says what was used (`scan`, `pk`, `index:<name>`, `union(...)`).

## 7. Add, Set, Delete, Require

```boxql
{Add[]} = players:Player[ID=9] = [ {Name[]} = $name, {Level[]} = 1, {Tags[]} = ;["new"]:, {Home[]} = [ {X[]} = 0, {Y[]} = 0 ] ]
{Add[]} = sessions:Session[ID=1] = [ {User[]} = "ann" ] (3600)
{Set[]} = players:Player[ID=7].Level = Level + 1
{Set[]} = players:Player[Level < 3].[Level = 3, Healed = TRUE]
{Set[]} = players:Player[ID=1].Inventory[id=10].Qty = 5
{Set[]} = players:Player[ID=2] = [ {Name[]} = "bob", {Level[]} = 4 ]
{Delete[]} = players:Player[ID=4]
{Delete[]} = players:Player[Level < 1 | Name starts "tmp-"]
{Delete[]} = players:Player[ID=*].Bio
{Require[]} = players:Player[ID=7, Gold >= 5]
{Require[]} = players:Player[Guild = "red"], Count = 3
```

* **Add** creates one record and fails with `409` if it exists. A record literal holds *values only* (it cannot refer
  to fields: use `Set` for computed values). Nested boxes, arrays and link literals are allowed; `{Item[ID=3]}`
  writes an entry with an ID.
* **Set** with `.field = expr` changes matching records; the expression can read the record (`Level + 1`) and is
  evaluated against the record **before** the command. A record the filter does not match is untouched; a missing
  record is not created. `Set Box[ID=n] = [ ... ]` replaces the whole record and **creates** it if absent (upsert).
  The `[ID=n]`, `[filter]` or `[ID=*]` is mandatory: `{Set[]} = players:Player...` without it is refused.
* **Delete** removes records (`Box[filter]`) or one field of matching records (`Box[...].Path`). A record, or a
  filter, is mandatory (`{Delete[]} = players:Player` is refused; say `[ID=*]` to delete all). `@!>` links on the
  deleted record cascade to their targets, authorized per target (the standalone `.red-xai-db-link` files are
  honoured too). A cascade the caller may not perform fails the whole command.
* **Require** is a guard: it succeeds if at least one record matches (or exactly `Count`) and otherwise fails with
  `409`, aborting the surrounding `Tx`. It reads; it never writes.
* Result of a write: `{"kind":"set","affected":N,...}` (`cascaded` lists extra records a Delete removed).
* Each writing command is **all-or-nothing**: if it fails part-way its earlier writes are undone.

### TTL on written data

`(N)` after the record or assignment sets the entry's TTL in seconds: `(N)` fixed, `(~N)` sliding, `(N)*`
checkpointed (qs-ls files), the same markers as in Box files. It applies to what is written (the record for `Add`
and replace, the assigned field for `Set`).

## 8. Transactions

```boxql
{Tx[]} = [
    {Require[]} = players:Player[ID=7, Gold >= 5],
    {Set[]} = players:Player[ID=7].Gold = Gold - 5,
    {Add[]} = receipts:Receipt[ID=100] = [ {Who[]} = 7, {Cost[]} = 5 ]
]
```

* Commands run in order; the first failure (a `Require`, a conflict, a denied write, a limit) undoes everything the
  transaction wrote and fails the request with that command's error. The response has one nested result per
  command in `results`.
* The whole `Tx` runs under the database's write lock, so no other BoxQL or REST write interleaves with it.
* `Tx` does not nest and cannot contain `Explain` or `Watch`. A `Tx` needs write scope if any command writes, and
  every command is authorized individually.
* Rollback restores before-images through the store, so indexes and index observers stay consistent. See §17 for
  what a rollback does **not** undo (outside writers, rule side effects).

## 9. Explain

```boxql
{Explain[]} = [ {Get[]} = players:Player[Name = $n] -> Name ]
```

Returns the plan as rows of text (`plan`), without running anything and without touching data: source file, access
path (`scan`, `pk`, `idx <name> (exact|prefix|range|text|in)`, `union(...)`), the filter, ordering and limits.
Explain of a write describes it; it needs the same read/write authorization as running it would.

## 10. Watch (subscribe → pulse)

```boxql
{Watch[]} = players:Player[Level > $min]
{Watch[]} = Topic = "player.*"
```

A Watch is not run; it opens a stream. Over HTTP it is a WebSocket on
`GET /v1/db/{db}/bx/watch?q=<command>&params=<json object>`.

* **Data watch** — every change to a record of the file and box that passes the filter is delivered as
  `{"path": "file:Box[ID=n]", "op": "set|delete|expire", "value": "<the whole record as Box text>", "at": ...}`.
  The value is the record **as the caller may see it** (denied fields removed). A change deep inside a record is
  reported as that whole record. A removed record is announced with no value, for every record of the watched box
  the caller may read (the filter cannot be evaluated on a record that is gone).
* **Topic watch** — `Topic = "player.*"` delivers the fired events of the database's pulse rules
  (`.red-xai-db-pulse`), filtered by the key's path prefix. On a follower it is served by the leader.
* The command is checked **before** the upgrade: syntax errors are 400, a source the key may not read is 403, an
  unknown file is 404.
* Watch commands cannot run through `POST /v1/bx` (400, with a pointer to the watch URL) or inside `Tx`.

## 11. Authorization

BoxQL asks the same authorizer as everything else, and **default-denies**:

* API-key scope: reads need `read`, any writing command (`Add`, `Set`, `Delete`, or a `Tx` containing one) needs
  `write`. `Explain` of a write is not a write.
* The key's database and path prefix. A prefix of the form `file`, `file:Box` or `file:Box.Field` is enforced
  inside the engine for every file, box and field the command touches, including filter fields, sort keys,
  followed links and cascade targets. A bare box name only searches the files the key may read. Prefixes that name a
  record id or wildcard (`file:Box[ID=1]`) cannot be expressed and are refused (403) for BoxQL.
* The database policy (`.red-xai-sec`), ceilinged by the key's own scope: denied files/boxes/fields are refused
  when named explicitly (`-> Email` is 403), silently left out of `-> *`, and cannot be used to filter or sort
  (that would leak them). Writes are checked field by field.
* Parameters are values, never syntax (§13), so a client cannot use data to widen its own access.
* A refused command changes nothing, and a missing and a forbidden file look the same to an unauthorized caller.

## 12. Errors

Engine messages start with `query: `; the host prefixes the class (`invalid request:`, `conflict:`). All parse errors carry `line:column` of the offending token, the problem, and the text near it. The HTTP status is in
brackets.

| Situation | Message (real output) |
|-----------|----------------------|
| not a command [400] | `query: syntax error at 1:1: expected a command such as {Get[]} = Box[...] -> [...], found `SELEKT` (near "SELEKT")` |
| wrong case [400] | `query: syntax error at 1:2: unknown command "get"; command names are case-sensitive: did you mean Get? (near "get")` |
| missing operand [400] | `query: syntax error at 1:33: expected a value, field or `(`, found `]` (near "]")` |
| second command [400] | `query: syntax error at 1:40: one command per request; to run several together wrap them: {Tx[]} = [ {Set[]} = ..., {Add[]} = ... ] (near "{")` |
| array without `:` [400] | `query: syntax error at 1:35: an array is written ;[a, b]: and needs its closing `:` (near ";")` |
| unterminated string [400] | `query: syntax error at 1:33: unterminated string (missing closing ")` |
| repeated option [400] | `query: syntax error at 1:51: option Sort given twice (near "Sort")` |
| `@!>` in a read [400] | `query: syntax error at 1:29: @!> is the cascade-delete link; to read through a link use @> Field (near "@!>")` |
| nested Tx [400] | `query: syntax error at 1:13: transactions do not nest (near "Tx")` |
| field in a record literal [400] | `query: syntax error at 1:47: a record literal holds values only; it cannot refer to fields (use {Set[]} = Box[...].Field = expr for computed values)` |
| `$name` not supplied [400] | `query: missing, unused or badly typed $parameter: $min has no value` |
| unused parameter [400] | `... the query does not use x` |
| unscoped write [400] | `query: command refused: Delete must say which records: Player[ID=1], a filter such as Player[Level < 3], or Player[ID=*] for every record` |
| unknown file [404] | `query: unknown file: "nosuch"` |
| ambiguous bare box / file [400] | `query: ambiguous file name: box Player exists in a.red-xai.db, b.red-xai.db; name the file, as in file:Player` |
| `Add` of an existing record [409] | `conflict: query: record already exists` |
| failed `Require` [409] | `conflict: command 1 of 1 failed, nothing was changed: query: Require failed: players:Player[ID=1, Level > 100] matched 0 record(s), needed at least 1` (the whole `Tx` is undone) |
| not allowed [403] | `forbidden: ...` naming the action and resource |
| bad `Limit` [400] | `query: syntax error at 1:49: Limit must be a non-negative whole number (near "-1")` |
| too big / too slow [400] | `limit exceeded: ...` (rows, records read, writes, result size) |

Syntax errors never reach storage and never depend on data. JSON error bodies are `{"error": "..."}`; the Go type is
`*query.SyntaxError` (`Pos`, `Msg`, `Near`, and `Context(src)` to draw a caret under the line).

## 13. Parameters and injection

```boxql
{Get[]} = players:Player[Name = $name, Level >= $min] -> Name, Limit = $n
{Set[]} = players:Player[ID=$id].Name = $name
```

* `$name` may stand wherever a **value** is allowed (a literal, a list item, a `Limit`/`Offset`, an ID) and nowhere
  else: never a verb, file, box, field name or operator. Values are bound after parsing, so their content is never
  parsed: `{"name": "\" ] {Delete[]} = players:Player[ID=*] [\""}` is a string that matches nothing.
* A parameter that is not used, or a `$name` with no value, is an error (typos do not silently pass).
* Over HTTP: `{"q": "...", "params": {"name": value}}` (numbers stay exact; `null` = `NELL`; arrays allowed). The same
  command may also be posted as plain text (no parameters).
* Build commands with parameters, **not** by concatenating strings. If you must interpolate a name, validate it
  against `^[A-Za-z_][A-Za-z0-9_-]*$` first.
* Only one command is accepted per request, so a successful injection could not add a second command anyway; the
  tests assert both properties.

## 14. Limits

Defaults (`query.Limits`): query text 64 KiB, 8192 tokens, nesting 64, `in` list 1000, 4 follows, 1000 commands per
`Tx`, field path depth 16, string parameter 1 MiB, 10 000 rows, 1 000 000 records read, 10 000 records written (cascades
and whole `Tx` included), 16 MiB result, 1024 columns, and a 30 s time limit per request at the host. A command that
exceeds a limit fails; it is never silently truncated.

## 15. Using it

**HTTP** — `POST /v1/bx` (default database) or `POST /v1/db/{db}/bx`:

```
curl -s -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  --data '{"q":"{Get[]} = players:Player[Level > $min] -> [Name, Level], Sort = -Level","params":{"min":10}}' \
  http://127.0.0.1:7878/v1/bx
```

Response: `{"kind","columns","rows","rows_box","count","affected","matched","paths","cascaded","access","scanned","plan","results"}`
(`results` holds one nested object per command of a `Tx`). The header `X-Redx-Applied` carries the replication offset
after a write. On a follower, reads are answered locally (from replicated data, without planner indexes) and writes
are forwarded to the leader. `GET /v1/db/{db}/bx/watch` is the WebSocket (§10). The paths `/v1/query` (native path
queries) and `/v1/path/...` are unchanged.

**CLI**

```
redx bx '{Get[]} = players:Player[Level > $min] -> Name' --param min=10
redx bx '{Set[]} = players:Player[ID=$id].Name = $n' --param id=2 --sparam n=Bob
redx bx '{Get[]} = players:Player[ID=1]' --explain          # plan only
redx bx '{Watch[]} = players:Player[Level > 10]'            # streams JSON events until Ctrl-C
redx bx - < command.bx                                      # command from stdin
```

`--param name=value` types the value (numbers, `true`/`false`, `null`), `--sparam` forces a string, `--json` prints the raw result.

**SDKs** — `await rx.bx(q, {min: 10})` / `rx.bx(q, {"min": 10})`, and `rx.watch(q, handler, {params})` /
`rx.watch(q, handler, params=...)`; `query()` (path queries) is kept.

**Go** — `query.New(query.Config{Store, Auth, Indexes, Links})`, then `db.Exec(ctx, principal, q, params)`,
`db.Explain`, `db.Watch`, `query.Parse`, `query.Analyze`, and `query.StmtString` to print a parsed command back
(canonical text; parsing it again gives the same tree).

## 16. Cheat-sheet

```
read     {Get[]} = file:Box[filter, filter] -> [Col, alias = expr, n = Count()] @> LinkField, Sort = -Col, Limit = 50, Offset = 0, Group = Col
filter   = != < <= > >=   & | !   in ;[1,2]:   in 5..9   starts "x"   has "words"   hasany "words"   = NELL   Box[3]  Box[$id]  Box[ID=*]
add      {Add[]}     = file:Box[ID=n] = [ {A[]} = 1, {B[]} = "x", {Arr[]} = ;[1,2]:, {Sub[]} = [ ... ] ] (ttl)
set      {Set[]}     = file:Box[filter].Path = expr        |  .[A = 1, B = 2]   |   file:Box[ID=n] = [ whole record ]
delete   {Delete[]}  = file:Box[filter]                    |  file:Box[filter].Field
guard    {Require[]} = file:Box[filter], Count = 1
all-or-nothing  {Tx[]} = [ cmd, cmd, ... ]
plan     {Explain[]} = [ cmd ]
stream   {Watch[]}   = file:Box[filter]        {Watch[]} = Topic = "pattern.*"
literals "string"  12  TRUE FALSE NELL  ;[a, b]:  $param      COMMENT << ... >>      TTL (N) (~N) (N)*
links    @> Field  @> alias = Field?  (read)      @!> in data = cascade on Delete
```

## 17. Known limitations

* **Bare-box sources scan.** `Player[...]` without a file is resolved by scanning the files the caller may read for a
  record of that box (bounded by the scan limit). Name the file in production code.
* **Standalone link files.** `.red-xai-db-link` edges drive `Delete` cascades but are not followed by `@>` in reads;
  only link values stored in records are.
* **Transactions are isolated by the database write lock only.** Concurrent writers outside BoxQL (for instance a
  pulse rule action or a timer) can interleave their own changes; rollback restores before-images of what the
  transaction itself wrote, but does **not** undo side effects of rules it fired. Index and pulse observers see
  the rollback writes as ordinary writes. A crash in the middle of a `Tx` is not atomic on disk beyond what the
  engine's per-write durability gives (there is no multi-record WAL transaction); rollback after a crash is not
  performed.
* **Watch** is delivered over WebSocket only (no SSE/long-poll), at-most-once with no resume, and a slow reader's events
  are dropped by the engine's bounded subscriber buffer. Deletions are announced for every readable record of the box
  regardless of the filter. A change deep in a record is delivered as the whole record.
* **Aggregates** are whole projection items; no nesting, no `Having` (filter the result client-side or use `Group`+`Sort`),
  no `Distinct`.
* **Record literals** hold values only (no field references); computed values go through `Set`.
* **Set on a missing record** with an assignment changes nothing (use the replace form to upsert).
* **Hyphenated names**: because `-` is legal inside identifiers (Box grammar), `Qty-1` is a field named `Qty-1`;
  write `Qty - 1`.
* **Numbers** are float64: whole numbers above 2^53 lose precision (IDs are limited to 2^53).
* **No joins other than `@>` follows**, no sub-queries, no `union` of commands; use a `Tx`.
* **Followers**: reads there use scans (planner indexes are leader-local); a Watch on a follower is local for data
  and proxied for topics. Replication caveats from [Clustering](clustering.md#consistency-model) apply unchanged (async, acked writes may be lost on
  failover).
* **Prefix keys** with record-id or wildcard prefixes cannot use BoxQL (403) because they cannot be expressed as a
  policy resource.
