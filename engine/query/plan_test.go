package query

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func planOf(t *testing.T, f *fixture, q string, p ...P) string {
	t.Helper()
	res, err := f.db.Explain(context.Background(), anyone, q, params(p))
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return strings.Join(res.Plan, "\n")
}

func TestExplainShowsPlan(t *testing.T) {
	f := newFixture(t, fixOpt{indexes: true, links: true})
	const get = `{Get[]} = players:Player`
	cases := []struct {
		q    string
		want []string
	}{
		{get + `[Name = "bob"]`, []string{`idx ByName (exact) on Name: Name = "bob"`}},
		{get + `[Name = $n, Level > 3]`, []string{"idx ByName (exact)", `filter: Name = "bob" & Level > 3`}},
		{get + `[Name starts "bo"]`, []string{"idx ByNamePfx (prefix)"}},
		{get + `[Level >= 5, Level < 10]`, []string{"idx ByLevel (range) on Level", "Level >= 5"}},
		{get + `[Level in 5..10]`, []string{"idx ByLevel (range)"}},
		{get + `[Stats.Gold > 100]`, []string{"idx ByLevel (range) on Stats.Gold"}},
		{get + `[Bio has "red dragon"]`, []string{"idx ByBio (text-all)"}},
		{get + `[Bio hasany "red blue"]`, []string{"idx ByBio (text-any)"}},
		{get + `[ID = 3]`, []string{"direct ID lookup"}},
		{get + `[3]`, []string{"direct ID lookup"}},
		{get + `[ID in ;[1, 2]:]`, []string{"direct ID lookup", "2 record(s)"}},
		{get + `[Name in ;["ann", "bob"]:]`, []string{"idx ByName (in)"}},
		{get + `[Name = "ann" | Level > 11]`, []string{"union of 2 lookups"}},
		{get + `[Name = "ann" | Class = "x"]`, []string{"union of 2 lookups", "ByClass"}},
		// not indexable: falls back to a scan
		{get + `[Name != "bob"]`, []string{"scan of every record"}},
		{get + `[Level + 1 = 6]`, []string{"scan of every record"}},
		{get + `[Name = "ann" | Tags = "x"]`, []string{"scan of every record"}},
		{get + `[!(Name = "ann")]`, []string{"scan of every record"}},
		{get + `[Name = NELL]`, []string{"scan of every record"}},
		{get + `[Level > "x"]`, []string{"scan of every record"}},
		{`{Get[]} = "players.red-xai.db":*[Name = "ann"]`, []string{"scan of every record"}}, // idx is limited to Player
		{get + `[Level starts "x"]`, []string{"scan of every record"}},
		{get, []string{"scan of every record"}},
		// exact beats range when both are possible
		{get + `[Level > 3, Name = "bob"]`, []string{"idx ByName (exact)"}},
		// follows and writes
		{get + `[Name = "ann", Guild.Title starts "Red"] -> [Name, Guild.Title] @> Guild?`,
			[]string{"idx ByName", "follow: optional @> Guild as Guild", "after-follow filter: Guild.Title starts \"Red\""}},
		{`{Set[]} = players:Player[Name = "ann"].Level = 1`, []string{"Set on", "idx ByName"}},
		{`{Delete[]} = players:Player[ID = 1]`, []string{"Delete from", "direct ID lookup", "cascade: follows @!>"}},
		{`{Add[]} = players:Player[ID=9] = [ {Name[]} = "x" ]`, []string{"Add ", "[ID=9]"}},
		{`{Require[]} = players:Player[Name = "ann"], Count = 1`, []string{"Require on", "idx ByName", "exactly 1"}},
		{get + `[ID=*] -> [Count(), n = Sum(Level)], Group = Class`, []string{"aggregate: one row per distinct (Class)"}},
		{`{Tx[]} = [ ` + get + `[1], {Delete[]} = players:Player[2] ]`, []string{"[1] Get from", "[2] Delete from"}},
	}
	for _, c := range cases {
		var p []P
		if strings.Contains(c.q, "$n") {
			p = []P{{"n": "bob"}}
		}
		pl := planOf(t, f, c.q, p...)
		for _, w := range c.want {
			if !strings.Contains(pl, w) {
				t.Errorf("%s\nplan:\n%s\nmissing %q", c.q, pl, w)
			}
		}
	}
	// {Explain[]} = [...] gives the same text and runs nothing
	before := f.cs.puts.Load() + f.cs.dels.Load()
	r := f.q(t, `{Explain[]} = [ {Delete[]} = players:Player[ID = 1] ]`)
	if r.Kind != "explain" || len(r.Plan) == 0 || f.cs.puts.Load()+f.cs.dels.Load() != before {
		t.Fatal("Explain must not execute")
	}
	if r.Rows[0][0].Str != r.Plan[0] || r.Columns[0] != "plan" {
		t.Fatal("rows mirror plan")
	}
}

func TestIndexPlanAvoidsScan(t *testing.T) {
	f := newFixture(t, fixOpt{indexes: true})
	f.cs.scans.Store(0)
	r := f.q(t, `{Get[]} = players:Player[Name = "bob"] -> ID`)
	eq(t, col(r, "ID"), "2")
	if f.cs.scans.Load() != 0 || r.Access != "index:ByName" || r.Scanned != 1 {
		t.Fatalf("scans=%d access=%s scanned=%d", f.cs.scans.Load(), r.Access, r.Scanned)
	}
	r = f.q(t, `{Get[]} = players:Player[Name != "bob"] -> ID`)
	if f.cs.scans.Load() != 1 || r.Access != "scan" {
		t.Fatalf("expected a scan: %d %s", f.cs.scans.Load(), r.Access)
	}
	r = f.q(t, `{Get[]} = players:Player[ID = 3] -> ID`)
	eq(t, col(r, "ID"), "3")
	if r.Access != "pk" || r.Scanned != 1 {
		t.Fatal(r.Access)
	}
	// a folded index finds a superset; the residual filter keeps scan semantics
	r = f.q(t, `{Get[]} = players:Player[Class = "Mage"] -> ID`)
	eq(t, col(r, "ID"), "1")
	if r.Access != "index:ByClass" || r.Scanned != 2 {
		t.Fatalf("%s scanned %d", r.Access, r.Scanned)
	}
	r = f.q(t, `{Get[]} = players:Player[Bio has "red DRAGON"] -> ID`)
	eq(t, col(r, "ID"), "1", "3")
	r = f.q(t, `{Get[]} = players:Player[Bio hasany "blue slayer"] -> ID`)
	eq(t, col(r, "ID"), "1", "2")
	g := newFixture(t, fixOpt{})
	r = g.q(t, `{Get[]} = players:Player[Bio has "red DRAGON"] -> ID`)
	eq(t, col(r, "ID"), "1", "3")
	// a prefix is matched literally: % and " are ordinary characters
	r = f.q(t, `{Get[]} = players:Player[Name starts "%"] -> ID`)
	eq(t, col(r, "ID"))
}

func TestStaleIndexEntriesAreIgnored(t *testing.T) {
	f := newFixture(t, fixOpt{indexes: true})
	f.mem.Delete(addrOf(playersFile, "Player", 2)) // behind the index's back
	r := f.q(t, `{Get[]} = players:Player[Name = "bob"] -> ID`)
	eq(t, col(r, "ID"))
}

// The planner must never change results: run many random conditions with and without indexes.
func TestIndexedAndScanResultsAgree(t *testing.T) {
	a := newFixture(t, fixOpt{indexes: true})
	b := newFixture(t, fixOpt{})
	rng := rand.New(rand.NewSource(7))
	names := []string{"ann", "bob", "bobby", "cy", "dee", "zed", "Bob", ""}
	atoms := func() string {
		switch rng.Intn(9) {
		case 0:
			return fmt.Sprintf(`Name = "%s"`, names[rng.Intn(len(names))])
		case 1:
			return fmt.Sprintf(`Name starts "%s"`, names[rng.Intn(len(names))])
		case 2:
			return fmt.Sprintf("Level %s %d", []string{"<", "<=", ">", ">=", "=", "!="}[rng.Intn(6)], rng.Intn(15))
		case 3:
			return fmt.Sprintf("Level in %d..%d", rng.Intn(10), rng.Intn(15))
		case 4:
			return fmt.Sprintf(`Class = "%s"`, []string{"Mage", "mage", "MAGE", "healer", "warrior"}[rng.Intn(5)])
		case 5:
			return fmt.Sprintf("Stats.Gold %s %d", []string{"<", ">=", ">"}[rng.Intn(3)], rng.Intn(300))
		case 6:
			return fmt.Sprintf(`Bio has "%s"`, []string{"red", "dragon", "red dragon", "knight", "zzz", "the"}[rng.Intn(6)])
		case 7:
			return fmt.Sprintf("ID in ;[%d, %d]:", rng.Intn(7), rng.Intn(7))
		}
		return fmt.Sprintf(`Name in ;["%s", "%s"]:`, names[rng.Intn(len(names))], names[rng.Intn(len(names))])
	}
	var gen func(d int) string
	gen = func(d int) string {
		if d == 0 || rng.Intn(3) == 0 {
			return atoms()
		}
		switch rng.Intn(4) {
		case 0:
			return "(" + gen(d-1) + " & " + gen(d-1) + ")"
		case 1:
			return "(" + gen(d-1) + " | " + gen(d-1) + ")"
		case 2:
			return "!(" + gen(d-1) + ")"
		}
		return "(" + atoms() + " & " + atoms() + " & " + atoms() + ")"
	}
	indexedUsed := 0
	for i := 0; i < 600; i++ {
		w := gen(3)
		q := "{Get[]} = players:Player[" + w + "] -> [ID, _box]"
		ra, err1 := a.db.Exec(context.Background(), anyone, q, nil)
		rb, err2 := b.db.Exec(context.Background(), anyone, q, nil)
		if err1 != nil || err2 != nil {
			t.Fatalf("%s: %v / %v", q, err1, err2)
		}
		if !reflect.DeepEqual(col(ra, "ID"), col(rb, "ID")) {
			t.Fatalf("%s\nindexed %v (%s)\nscan    %v", q, col(ra, "ID"), ra.Access, col(rb, "ID"))
		}
		if ra.Access != "scan" {
			indexedUsed++
		}
	}
	if indexedUsed < 100 {
		t.Fatalf("only %d of 600 queries used an index; the generator is not exercising the planner", indexedUsed)
	}
}

func TestIndexesFollowWritesThroughTheDB(t *testing.T) {
	f := newFixture(t, fixOpt{indexes: true, links: true})
	f.q(t, `{Add[]} = players:Player[ID=20] = [ {Name[]} = "newbie", {Level[]} = 1 ]`)
	r := f.q(t, `{Get[]} = players:Player[Name = "newbie"] -> ID`)
	eq(t, col(r, "ID"), "20")
	if r.Access != "index:ByName" {
		t.Fatal(r.Access)
	}
	f.q(t, `{Set[]} = players:Player[ID=20].[Name = "veteran", Level = 99]`)
	eq(t, col(f.q(t, `{Get[]} = players:Player[Name = "newbie"] -> ID`), "ID"))
	eq(t, col(f.q(t, `{Get[]} = players:Player[Name = "veteran"] -> ID`), "ID"), "20")
	eq(t, col(f.q(t, `{Get[]} = players:Player[Level > 90] -> ID`), "ID"), "20")
	f.q(t, `{Delete[]} = players:Player[Name = "veteran"]`)
	eq(t, col(f.q(t, `{Get[]} = players:Player[Name = "veteran"] -> ID`), "ID"))
	checkIndexes(t, f)
}

func checkIndexes(t *testing.T, f *fixture) {
	t.Helper()
	d, err := f.mgr.Check(f.cs)
	if err != nil {
		t.Fatal(err)
	}
	for n, diff := range d {
		if diff.Stale() {
			t.Fatalf("index %s drifted: %+v", n, diff)
		}
	}
}

func TestIndexesStayExactAfterARolledBackTx(t *testing.T) {
	f := newFixture(t, fixOpt{indexes: true, links: true})
	err := f.qerr(t, `{Tx[]} = [
		{Set[]} = players:Player[ID=1].[Name = "changed", Level = 99],
		{Add[]} = players:Player[ID=30] = [ {Name[]} = "temp", {Level[]} = 1 ],
		{Delete[]} = players:Player[ID=2],
		{Require[]} = players:Player[ID=404]
	]`)
	if err == nil {
		t.Fatal("expected the Tx to fail")
	}
	checkIndexes(t, f)
	eq(t, col(f.q(t, `{Get[]} = players:Player[Name = "ann"] -> ID`), "ID"), "1")
	eq(t, col(f.q(t, `{Get[]} = players:Player[Name = "temp"] -> ID`), "ID"))
	eq(t, col(f.q(t, `{Get[]} = players:Player[Name = "bob"] -> ID`), "ID"), "2")
}
