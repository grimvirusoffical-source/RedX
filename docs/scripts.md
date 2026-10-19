# Scripts

Package `engine/code`. Scripts run in a sandboxed interpreter with no access to the operating system, files, network or clock; the only way out is through declared host functions. See the [API reference](api.md#boxql-media-access-policy-scripts-and-encryption) for the host routes.

## Scripts (`.red-xai-code`)

A small tree-walking interpreter written for this project. It is not Lua, JS or anything embedded: there are no imports, reflection, first-class functions, globals, goroutines or `eval`, and nothing that names a file, socket, process or the clock. The only way out is a **host function**.

### File format

```
{Script[1]} = [
    {Name[]}   = "heal",
    {Params[]} = ;["target", "amount"]:,
    {Uses[]}   = ;["db_get", "db_set"]:,
    {Limits[]} = [ {MaxSteps[]} = 5000, {TimeoutMs[]} = 50 ],
    {Source[]} = "let hp = db_get(target, \"Health\"); db_set(target, \"Health\", hp + amount); return hp + amount;"
];
```

`Name` and `Source` are required. `Params`, `Uses`, `Limits` (`MaxSteps`, `TimeoutMs`, `MaxStringLen`, `MaxArrayLen`, `MaxAlloc`, `MaxDepth`, `MaxHostCalls`) are optional. Unknown keys are errors. Every script is compiled at load; the first error is returned with the script name. ≤ 4 MiB per file, ≤ 1000 scripts.

### Language

Values: number (finite float64), string (UTF-8), bool, nil, array. Comments: `// to end of line`. Strings: `"..."` with `\n \t \" \\` escapes. Statements end in `;`.

```
fn name(a, b) { ... return x; }            // top level only, may recurse (depth-limited)
let x = expr;                              // declares (block scoped)
x = expr;      a[i] = expr;                // assigns
if cond { ... } else if cond { ... } else { ... }
while cond { ... }                         // break; continue;
for i in 0..n { ... }                      // i = 0 .. n-1
for e in array { ... }
return expr;                               // or return;
expr;                                      // call for effect
```

Operators, loosest first: `or` `||`; `and` `&&`; `==` `!=`; `<` `<=` `>` `>=`; `+` `-`; `*` `/` `%`; unary `-` `not` `!`; postfix `a[i]`, `f(x)`. `+` adds numbers or concatenates strings; the rest are numeric (comparisons also work on two strings). **Conditions must be booleans** (no truthiness) and operands must have the right type, otherwise a runtime error with line and column. Overflow to Inf/NaN is an error, not a value. Division or modulo by zero is an error. Arrays are by reference; index must be an integer in range.

Built-ins (pure): `len str num type push pop abs floor ceil round sqrt min max substr find contains upper lower`. `substr(s, start[, count])` counts runes; `find` returns an index or -1. Host function names may not shadow these.

### Host functions and authorization

The embedder builds a `Host` from `HostFunc{Name, Action, Resource, Fn}`. A call goes through only if **all three** hold:

1. the script listed the name in `Uses` (checked at compile time: calling anything else is a compile error);
2. the `Host` registered it;
3. `RunOptions.Auth.Authorize(Principal, Action, Resource)` (a `*sec.Policy`) allows it. `Resource` is computed from the arguments by the host function (default `{File: "host", Box: <name>}`) and may refuse the call. No `Auth` means deny everything.

Arguments are deep-copied into plain Go values (`nil, bool, float64, string, []any`); results are converted back, with a node/depth bound so cyclic or shared arrays cannot blow up. Host functions get a `context.Context` that expires with the run's time limit and **must honour it**. Every attempted call is listed in `Result.Calls` (allowed or denied, with the reason) for audit.

### Limits

| limit | default | meaning |
|-------|---------|---------|
| `MaxSteps` | 100 000 | every expression node, statement and loop iteration costs 1; walking built-ins cost extra |
| `MaxDuration` | 1 s | wall clock, checked every 64 steps and at each host call; the context deadline also applies |
| `MaxStringLen` | 64 KiB | longest string a script can create |
| `MaxArrayLen` | 10 000 | longest array |
| `MaxAlloc` | 8 MiB | **cumulative** allocation budget (string bytes, 16 per array element), not live memory |
| `MaxDepth` | 32 | nested user-function calls |
| `MaxHostCalls` | 100 | per run |
| `MaxSourceBytes` | 64 KiB | compile time |
| `MaxNesting` | 64 | block/expression nesting, compile time |
| `MaxConvertNodes` | 100 000 | values converted when crossing the host boundary (constant) |

`RunOptions.Limits` is the host's ceiling; a script's own `Limits` can only lower it (`Effective`). Limit errors wrap `ErrLimit` (`ErrStepLimit`, `ErrTimeout`, …). Errors: `*SyntaxError` (line, col), `*RuntimeError` (line, col, wrapped cause), `ErrNotGranted`, `sec.ErrDenied`, `ErrHostFunc`. An internal panic is recovered and returned as `ErrInternal` (never expected; the fuzz tests treat it as a failure).

## Limitations

* No persistent state between runs.
* No first-class functions or modules; conditions are boolean only.
* The interpreter cannot preempt a host function that ignores its context.
* `MaxAlloc` is cumulative allocation, not live memory.
* Default limits (100,000 steps, 1 s, 8 MiB) can be lowered per script but not raised above the host's ceiling.
