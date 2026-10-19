package query

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

var fuzzSeeds = []string{
	`{Get[]} = players:Player[ID=*]`,
	`{Get[]} = players:Player[Level >= $a, Name starts "b" | Name in ;["ann", $b]:] -> [Name, g = Stats.Gold], Sort = ;[-g, Name]:, Limit = 5, Offset = 1`,
	`{Get[]} = players:Player[Guild.Rank in 1..5] -> [Name, Guild.Title] @> Guild?`,
	`{Get[]} = players:Player[Bio has "red dragon", !(Class = NELL)] -> ID`,
	`{Get[]} = players:Player[ID=*] -> [Class, n = Count(), s = Sum(Level)], Group = Class`,
	`{Add[]} = players:Player[ID=9] = [ {Name[]} = "x", {Stats[]} = [ {Gold[]} = 1 ] ] (30)`,
	`{Set[]} = players:Player[Level > 3].[Level = Level * 2 + 1, Meta.A = "x"]`,
	`{Set[]} = players:Player[1] = [ {Name[]} = $a ]`,
	`{Delete[]} = players:Player[ID in ;[1, 2]: | Name = "cy"]`,
	`{Delete[]} = players:Player[1].Stats.Gold`,
	`{Require[]} = players:Player[Level > 1], Count = 3`,
	`{Tx[]} = [ {Set[]} = players:Player[1].A = 1, {Require[]} = players:Player[ID=404] ]`,
	`{Explain[]} = [ {Get[]} = a:b[a = 1] ]`,
	`{Watch[]} = players:Player[Level > 3]`,
	`{Get[]} = P[((((a)))) - -1 = Inv[ID=3].b[4]]`,
	`{Get[]} = P[a = 1e400]`,
	`{Get[]} = P[a = 1.2.3]`,
	`'`, `"`, `(`, `$`, `{`, `{Get`, `{Get[]}`, `{Get[]} =`, "\x00", "\xff\xfe", `<<`, `>>`, `;[`, `@>`,
}

func FuzzParse(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, q string) {
		st, names, err := Parse(q)
		if err != nil {
			var se *SyntaxError
			if !errors.As(err, &se) && !errors.Is(err, ErrTooLarge) {
				t.Fatalf("unexpected error type %T: %v", err, err)
			}
			if se != nil {
				if se.Pos.Line < 1 || se.Pos.Col < 1 || se.Pos.Offset < 0 || se.Pos.Offset > len(q) {
					t.Fatalf("bad position %+v for %q", se.Pos, q)
				}
				_ = se.Context(q)
				_ = se.Error()
			}
			return
		}
		if st == nil || len(names) > len(q) {
			t.Fatalf("bad result %v %v", st, names)
		}
		if !utf8.ValidString(q) {
			t.Fatal("invalid UTF-8 was accepted")
		}
		// the printer's output must parse again and be a fixed point
		out := StmtString(st)
		st2, _, err := Parse(out)
		if err != nil {
			t.Fatalf("%q printed as %q does not parse: %v", q, out, err)
		}
		if again := StmtString(st2); again != out {
			t.Fatalf("%q: printing is not a fixed point:\n%s\n%s", q, out, again)
		}
	})
}

// FuzzExec runs arbitrary text against two databases that differ only in having indexes, and
// requires that they agree on results and on the data left behind, that nothing panics, and
// that the indexes are still exact after any write.
func FuzzExec(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Add(`{Get[]} = players:Player[Name = "ann" | Level > 6] -> ID, Sort = Level`)
	f.Add(`{Set[]} = players:Player[Name starts "b"].Name = "zz"`)
	f.Add(`{Delete[]} = players:Player[Level in 5..7]`)
	f.Fuzz(func(t *testing.T, q string) {
		if len(q) > 600 {
			t.Skip()
		}
		a := newFixture(t, fixOpt{indexes: true, links: true})
		b := newFixture(t, fixOpt{links: true})
		vals := []interface{}{"bob", 7, nil, "r%"}
		run := func(f *fixture) (*Result, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, names, perr := Parse(q)
			p := P{}
			if perr == nil {
				for i, n := range names {
					p[n] = vals[i%len(vals)]
				}
			}
			return f.db.Exec(ctx, anyone, q, p)
		}
		ra, ea := run(a)
		rb, eb := run(b)
		if (ea == nil) != (eb == nil) {
			t.Fatalf("%q: indexed err=%v, scan err=%v", q, ea, eb)
		}
		if ea == nil {
			if ra.Kind != "explain" && fmt.Sprint(ra.Columns, ra.Rows, ra.Affected, ra.Kind) != fmt.Sprint(rb.Columns, rb.Rows, rb.Affected, rb.Kind) {
				t.Fatalf("%q:\nindexed %v %v %d\nscan    %v %v %d", q, ra.Columns, ra.Rows, ra.Affected, rb.Columns, rb.Rows, rb.Affected)
			}
			if len(ra.Rows) > 10000 {
				t.Fatal("MaxRows exceeded")
			}
		} else if !strings.HasPrefix(ea.Error(), "query:") && !strings.HasPrefix(ea.Error(), "link:") && !strings.Contains(ea.Error(), "sec:") && !strings.Contains(ea.Error(), "command ") && !errors.Is(ea, context.DeadlineExceeded) {
			t.Fatalf("%q: error without a package prefix: %v", q, ea)
		}
		if snapshot(a) != snapshot(b) {
			t.Fatalf("%q: data differ after the command:\n--indexed\n%s\n--scan\n%s", q, snapshot(a), snapshot(b))
		}
		if d, err := a.mgr.Check(a.cs); err == nil {
			for n, diff := range d {
				if diff.Stale() {
					t.Fatalf("%q left index %s stale", q, n)
				}
			}
		}
	})
}
