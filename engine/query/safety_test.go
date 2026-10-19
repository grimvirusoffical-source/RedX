package query

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"redx/box"
)

var hostile = []string{
	`x" ] , {Delete[]} = players:Player[ID=*] , [ "`,
	`"; {Delete[]} = players:Player[ID=*]; "`,
	`" | "" = "`,
	`bob" >> `,
	`<< bob`,
	`\" | 1 = 1 `,
	`$other`,
	`$`,
	"a\x00b",
	`"`,
	`""`,
	`) | (1 = 1`,
	`ann"] {Set[]} = players:Player[ID=*].Level = 0 {Get[]} = P[`,
	"newline\n]{Delete[]}",
	`日本語 " | 1=1`,
	`players:Player; DROP`,
	`;[1, 2]:`,
	`@> "x":Y[ID=1]`,
	strings.Repeat(`"`, 1000),
}

func snapshot(f *fixture) string {
	var sb strings.Builder
	for _, file := range f.mem.Files() {
		f.mem.Scan(file, func(a linkAddr, e *box.Entry) bool {
			fmt.Fprintf(&sb, "%s=%s\n", a, e.Value.String())
			return true
		})
	}
	return sb.String()
}

func TestParametersAreNeverParsedAsQueryText(t *testing.T) {
	f := newFixture(t, fixOpt{indexes: true, links: true})
	before := snapshot(f)
	for _, h := range hostile {
		// as a comparison value, an `in` member, a prefix, a range bound, words to find
		for _, q := range []string{
			`{Get[]} = players:Player[Name = $h] -> ID`,
			`{Get[]} = players:Player[Name in ;[$h, "ann"]:] -> ID`,
			`{Get[]} = players:Player[Name != $h, Name = "cy"] -> ID`,
			`{Get[]} = players:Player[Bio = NELL | Name in $h..$h] -> ID`,
			`{Get[]} = players:Player[Bio has $h] -> ID`,
			`{Get[]} = players:Player[Name starts $h] -> ID`,
			`{Set[]} = players:Player[Name = $h].Name = Name`,
			`{Delete[]} = players:Player[Name = $h]`,
			`{Require[]} = players:Player[Name = $h], Count = 0`,
			`{Tx[]} = [ {Require[]} = players:Player[Name = $h], Count = 0 ]`,
		} {
			if strings.Contains(q, "Require") && strings.Contains(q, "Tx") {
				continue
			}
			res, err := f.db.Exec(context.Background(), anyone, q, P{"h": h})
			if err != nil {
				t.Fatalf("%s with %q: %v", q, h, err)
			}
			if strings.Contains(q, "Name in ;[$h") {
				eq(t, col(res, "ID"), "1") // only "ann" matches; the hostile text is just a string
			}
			if strings.Contains(q, "Name = $h] -> ID") && len(res.Rows) != 0 {
				t.Fatalf("%q matched %d rows", h, len(res.Rows))
			}
		}
		if got := snapshot(f); got != before {
			t.Fatalf("data changed by parameter %q", h)
		}
	}
	// stored verbatim by Add / Set and read back unchanged
	for i, h := range hostile {
		id := int64(100 + i)
		f.q(t, `{Add[]} = players:Player[ID=$id] = [ {Name[]} = $n, {Level[]} = $l, {Note[]} = ;[$n, $n]: ]`, P{"id": id, "n": h, "l": i})
		r := f.q(t, `{Get[]} = players:Player[$id] -> Name`, P{"id": id})
		if r.Rows[0][0].Str != h {
			t.Fatalf("stored %q came back as %q", h, r.Rows[0][0].Str)
		}
		r = f.q(t, `{Get[]} = players:Player[Name = $n] -> ID`, P{"n": h}) // via the exact index
		if len(r.Rows) != 1 || (len(h) <= 256 && r.Access != "index:ByName") {
			t.Fatalf("%q: %v %s", h, col(r, "ID"), r.Access)
		}
		f.q(t, `{Set[]} = players:Player[ID=$id].Name = $n`, P{"id": id, "n": h + "!"})
		eq(t, col(f.q(t, `{Get[]} = players:Player[$id] -> Name`, P{"id": id}), "Name"), h+"!")
	}
	if n := len(f.q(t, `{Get[]} = players:Player[ID=*] -> ID`).Rows); n != 5+len(hostile) {
		t.Fatalf("row count %d", n)
	}
}

func TestConcatenatedQueriesFailOrStayInsideTheString(t *testing.T) {
	f := newFixture(t, fixOpt{})
	before := snapshot(f)
	evil := `x"]; {Delete[]} = players:Player[ID=*]; {Get[]} = P[Name="`
	q := `{Get[]} = players:Player[Name = "` + evil + `"] -> ID`
	if err := f.qerr(t, q); !errors.Is(err, ErrSyntax) {
		t.Fatal(err)
	}
	if err := f.qerr(t, `{Get[]} = players:Player -> ID; {Delete[]} = players:Player[ID=*]`); !errors.Is(err, ErrSyntax) {
		t.Fatal(err)
	}
	if err := f.qerr(t, `{Get[]} = players:Player -> ID {Delete[]} = players:Player[ID=*]`); !errors.Is(err, ErrSyntax) || !strings.Contains(err.Error(), "{Tx[]}") {
		t.Fatal(err)
	}
	if snapshot(f) != before {
		t.Fatal("data changed")
	}
	// a quote typed by a user can only end the string early, which leaves text the parser rejects,
	// or, when it happens to balance, a different but still single read-only Get
	r := f.q(t, `{Get[]} = players:Player[Name = "x" | ID > 0] -> ID`) // what concatenation of `x" | ID > 0 | Name = "` could build
	if len(r.Rows) != 5 {
		t.Fatal("expected the concatenation attack to work in this demonstration")
	}
	r = f.q(t, `{Get[]} = players:Player[Name = $n] -> ID`, P{"n": `x" | ID > 0 | Name = "`})
	if len(r.Rows) != 0 {
		t.Fatal("parameter must not be interpreted")
	}
	// even a successful injection into a Get cannot become a write: one command per request
	if snapshot(f) != before {
		t.Fatal("data changed")
	}
}

func TestPlaceholdersOnlyStandForValues(t *testing.T) {
	f := newFixture(t, fixOpt{})
	// a $param can never name a file, box, field, option or command
	for _, q := range []string{
		`{Get[]} = $x`,
		`{Get[]} = $x:Player`,
		`{Get[]} = players:$x`,
		`{Get[]} = players:Player[$x.y = 1]`,
		`{Get[]} = players:Player -> $x.y`,
		`{Get[]} = players:Player @> $x`,
		`{Get[]} = players:Player @> $x = Guild`,
		`{Set[]} = players:Player[1].$x = 1`,
		`{Set[]} = players:Player[ID=*].[$x = 1]`,
		`{Add[]} = players:Player[ID=1] = [ {$x[]} = 1 ]`,
		`{$x[]} = players:Player`,
		`{Get[]} = players:Player, $x = 1`,
		`{Get[]} = players:Player, Sort = $x.y`,
		`{Delete[]} = players:Player[ID=1].$x`,
	} {
		if err := f.qerr(t, q, P{"x": "Name"}); !errors.Is(err, ErrSyntax) {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// in a projection or Sort a $param is a constant, not a column
	r := f.q(t, `{Get[]} = players:Player[1] -> x = $c`, P{"c": "Name"})
	eq(t, col(r, "x"), "Name")
	r = f.q(t, `{Get[]} = players:Player[ID=*] -> ID, Sort = $c`, P{"c": "Name"})
	eq(t, col(r, "ID"), "1", "2", "3", "4", "5") // constant key: stable, address order
}

func TestParameterTypesAndBinding(t *testing.T) {
	f := newFixture(t, fixOpt{})
	one := func(v interface{}) []string {
		return col(f.q(t, `{Get[]} = players:Player[Level = $v] -> ID`, P{"v": v}), "ID")
	}
	// no implicit coercion between strings and numbers
	eq(t, one("7"))
	eq(t, one(7), "3", "4")
	eq(t, one(int8(7)), "3", "4")
	eq(t, one(uint64(7)), "3", "4")
	eq(t, one(7.0), "3", "4")
	eq(t, one(box.String("seven")), "5")
	eq(t, col(f.q(t, `{Get[]} = players:Player[Class = $v] -> ID`, P{"v": nil}), "ID"), "4")
	eq(t, col(f.q(t, `{Get[]} = players:Player[Name in $v] -> ID`, P{"v": []string{"ann", "cy"}}), "ID"), "1", "4")
	f.q(t, `{Set[]} = players:Player[5].Tags = $v`, P{"v": []string{"x", "y"}})
	r := f.q(t, `{Get[]} = players:Player[5] -> Tags`)
	if r.Rows[0][0].Kind != box.KindArray || len(r.Rows[0][0].Arr) != 2 {
		t.Fatal(r.Rows[0][0])
	}
	// names may be given with or without the $
	eq(t, col(f.q(t, `{Get[]} = players:Player[Level = $v] -> ID`, P{"$v": 12}), "ID"), "2")
	// every $name needs a value, and every value a $name
	if err := f.qerr(t, `{Get[]} = players:Player[Level = $v] -> ID`); !errors.Is(err, ErrParams) || !strings.Contains(err.Error(), "$v has no value") {
		t.Fatal(err)
	}
	if err := f.qerr(t, `{Get[]} = players:Player[Level = $v] -> ID`, P{"w": 1}); !errors.Is(err, ErrParams) {
		t.Fatal(err)
	}
	if err := f.qerr(t, `{Get[]} = players:Player[Level = 1] -> ID`, P{"v": 1}); !errors.Is(err, ErrParams) || !strings.Contains(err.Error(), "does not use v") {
		t.Fatal(err)
	}
	if err := f.qerr(t, `{Get[]} = players:Player[Level = $v] -> ID`, P{"v": 1, "v2": 2}); !errors.Is(err, ErrParams) {
		t.Fatal(err)
	}
	for _, bad := range []interface{}{struct{}{}, map[string]int{}, make(chan int), func() {}, []byte("x"), strings.Repeat("x", 2<<20), "bad\xffutf8", math.Inf(1), math.NaN()} {
		if err := f.qerr(t, `{Get[]} = players:Player[Name = $v] -> ID`, P{"v": bad}); !errors.Is(err, ErrParams) {
			t.Fatalf("%T: %v", bad, err)
		}
	}
}

func TestResourceLimits(t *testing.T) {
	small := func(l Limits) *fixture { return newFixture(t, fixOpt{lim: l, links: true}) }
	exec := func(f *fixture, q string, p ...P) error {
		_, err := f.db.Exec(context.Background(), anyone, q, params(p))
		return err
	}
	const all = `{Get[]} = players:Player[ID=*] -> ID`
	f := small(Limits{MaxRows: 3})
	if err := exec(f, all); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	if err := exec(f, all+`, Limit = 3`); err != nil {
		t.Fatal(err)
	}
	if err := exec(f, all+`, Limit = 4`); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	if err := exec(f, all+`, Offset = 2, Limit = 3`); err != nil {
		t.Fatal(err)
	}
	if err := exec(f, all+`, Sort = ID, Offset = 2`); err != nil {
		t.Fatal(err)
	}
	if err := exec(f, all+`, Sort = ID, Offset = 1`); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	if err := exec(f, `{Get[]} = players:Player[ID=*] -> [ID, n = Count()], Group = ID`); !errors.Is(err, ErrLimit) {
		t.Fatalf("groups are bounded too: %v", err)
	}
	f = small(Limits{MaxScan: 4})
	if err := exec(f, `{Get[]} = players:Player[Name = "zz"] -> ID`); !errors.Is(err, ErrLimit) {
		t.Fatalf("scan of 5 records with MaxScan=4: %v", err)
	}
	if err := exec(f, `{Get[]} = players:Player[ID = 1] -> ID`); err != nil {
		t.Fatal(err)
	}
	// writes: nothing is written when the limit trips
	f = small(Limits{MaxWrites: 2})
	before := snapshot(f)
	for _, q := range []string{
		`{Set[]} = players:Player[ID=*].Level = 0`,
		`{Delete[]} = players:Player[ID=*]`,
		`{Tx[]} = [ {Add[]} = players:P[ID=91] = [ {A[]} = 1 ], {Add[]} = players:P[ID=92] = [ {A[]} = 1 ], {Add[]} = players:P[ID=93] = [ {A[]} = 1 ] ]`,
	} {
		if err := exec(f, q); !errors.Is(err, ErrLimit) {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if snapshot(f) != before {
		t.Fatal("a refused command changed data")
	}
	f = small(Limits{MaxResultBytes: 200})
	if err := exec(f, `{Get[]} = players:Player[ID=*]`); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	f = small(Limits{MaxColumns: 3})
	if err := exec(f, `{Get[]} = players:Player[ID=*] -> *`); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	f = small(Limits{MaxQueryBytes: 40})
	if err := exec(f, `{Get[]} = players:Player[Name = "a long string"]`); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	f = small(Limits{MaxInList: 2, MaxDepth: 4})
	if err := exec(f, `{Get[]} = players:Player[Name in ;["a","b","c"]:]`); !errors.Is(err, ErrSyntax) {
		t.Fatal(err)
	}
	if err := exec(f, `{Get[]} = players:Player[((((Name = "a"))))]`); !errors.Is(err, ErrSyntax) {
		t.Fatal(err)
	}
	f = small(Limits{MaxTxStmts: 2})
	if err := exec(f, `{Tx[]} = [ {Get[]} = P[1], {Get[]} = P[1], {Get[]} = P[1] ]`); !errors.Is(err, ErrSyntax) {
		t.Fatal(err)
	}
	// an enormous Offset/Limit does no work and no allocation
	f = small(Limits{})
	if err := exec(f, all+`, Limit = 9999999`); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	r, err := f.db.Exec(context.Background(), anyone, all+`, Offset = 99999999999`, nil)
	if err != nil || len(r.Rows) != 0 {
		t.Fatal(err)
	}
}

func TestCascadeCountsTowardWriteLimit(t *testing.T) {
	f := newFixture(t, fixOpt{lim: Limits{MaxWrites: 2}, links: true})
	for i := int64(20); i < 23; i++ {
		must(t, f.mem.Put(addrOf(guildsFile, "Guild", i), mkEntry(t, "Guild", i)))
	}
	e, _, _ := f.mem.Get(addrOf(playersFile, "Player", 1))
	for i := int64(20); i < 23; i++ {
		l, _ := linkParse(fmt.Sprintf(`"players.red-xai.db":Player[ID=1] @!> "guilds.red-xai.db":Guild[ID=%d]`, i))
		e.Value.Box.Put(box.NewEntry(fmt.Sprintf("C%d", i), nil, box.LinkValue(l)))
	}
	must(t, f.mem.Put(addrOf(playersFile, "Player", 1), e))
	before := snapshot(f)
	if err := f.qerr(t, `{Delete[]} = players:Player[ID=1]`); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	if snapshot(f) != before {
		t.Fatal("cascade over the limit must delete nothing")
	}
}

func TestWatchCommandIsNotRunByExec(t *testing.T) {
	f := newFixture(t, fixOpt{})
	if err := f.qerr(t, `{Watch[]} = players:Player[Level > 1]`); !errors.Is(err, ErrBadStatement) {
		t.Fatal(err)
	}
}
