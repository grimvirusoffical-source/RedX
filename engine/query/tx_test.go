package query

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"redx/box"
	"redx/engine/link"
	"redx/engine/sec"
)

func gold(t *testing.T, f *fixture, id int64) string {
	t.Helper()
	return col(f.q(t, `{Get[]} = players:Player[$id] -> g = Stats.Gold`, P{"id": id}), "g")[0]
}

func TestTxCommitsAllCommands(t *testing.T) {
	f := newFixture(t, fixOpt{})
	r := f.q(t, `{Tx[]} = [
		{Require[]} = players:Player[ID=1, Stats.Gold >= 30],
		{Set[]} = players:Player[ID=1].Stats.Gold = Stats.Gold - 30,
		{Set[]} = players:Player[ID=2].Stats.Gold = Stats.Gold + 30,
		{Add[]} = players:Ledger[ID=1] = [ {From[]} = 1, {To[]} = 2, {Amt[]} = 30 ]
	]`)
	if r.Kind != "tx" || len(r.Results) != 4 || r.Affected != 3 {
		t.Fatalf("%+v", r)
	}
	if r.Results[0].Kind != "require" || r.Results[3].Kind != "add" {
		t.Fatal("results")
	}
	eq(t, []string{gold(t, f, 1), gold(t, f, 2)}, "70", "35")
	eq(t, col(f.q(t, `{Get[]} = players:Ledger[1] -> Amt`), "Amt"), "30")
	// read-your-writes inside the Tx
	f.q(t, `{Tx[]} = [ {Add[]} = players:Memo[ID=1] = [ {N[]} = 1 ], {Require[]} = players:Memo[ID=1, N = 1], {Set[]} = players:Memo[1].N = N + 1 ]`)
	eq(t, col(f.q(t, `{Get[]} = players:Memo[1] -> N`), "N"), "2")
}

func TestTxRollsBackEverythingOnFailure(t *testing.T) {
	f := newFixture(t, fixOpt{links: true})
	before := func() string {
		var sb strings.Builder
		for _, a := range []string{playersFile} {
			_ = f.mem.Scan(a, func(ad link.Addr, e *box.Entry) bool {
				sb.WriteString(ad.String() + "=" + e.Value.String() + "\n")
				return true
			})
		}
		return sb.String()
	}
	snap := before()
	for name, q := range map[string]string{
		"require":  `{Tx[]} = [ {Set[]} = players:Player[1].Stats.Gold = 0, {Add[]} = players:New[ID=1] = [ {A[]} = 1 ], {Require[]} = players:Player[ID=1, Stats.Gold = 100] ]`,
		"exists":   `{Tx[]} = [ {Set[]} = players:Player[ID=*].Touched = TRUE, {Add[]} = players:Player[ID=2] = [ {Name[]} = "dup" ] ]`,
		"delete":   `{Tx[]} = [ {Delete[]} = players:Player[ID in ;[1, 2]:], {Set[]} = players:Player[3].Level = 1, {Require[]} = players:Player[ID=999] ]`,
		"fielddel": `{Tx[]} = [ {Delete[]} = players:Player[ID=*].Bio, {Set[]} = players:Player[1].Level.Sub = 1 ]`,
		"replace":  `{Tx[]} = [ {Set[]} = players:Player[2] = [ {Name[]} = "x" ], {Set[]} = players:Player[88] = [ {Name[]} = "y" ], {Set[]} = players:Player[1].Level.Sub = 1 ]`,
	} {
		err := f.qerr(t, q)
		if !strings.Contains(err.Error(), "nothing was changed") && !errors.Is(err, ErrExists) {
			t.Fatalf("%s: %v", name, err)
		}
		if got := before(); got != snap {
			t.Fatalf("%s: the data changed after a failed Tx:\n%s\nvs\n%s", name, got, snap)
		}
	}
	// the error names the failing command
	err := f.qerr(t, `{Tx[]} = [ {Set[]} = players:Player[1].A = 1, {Require[]} = players:Player[ID=404] ]`)
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "command 2 of 2") {
		t.Fatal(err)
	}
}

func TestSingleCommandIsAtomicToo(t *testing.T) {
	f := newFixture(t, fixOpt{})
	// the third record cannot take the sub-field (Level is a string there? no: a number), so the whole Set fails
	if err := f.qerr(t, `{Set[]} = players:Player[ID in ;[1, 2, 3]:].Level.Sub = 1`); !errors.Is(err, ErrType) {
		t.Fatal(err)
	}
	eq(t, col(f.q(t, `{Get[]} = players:Player[ID in ;[1,2,3]:] -> Level, Sort = ID`), "Level"), "5", "12", "7")
	// a failure after some records were stored: Set over a file where a late record is a non-box
	must(t, f.mem.Put(addrOf(playersFile, "Zed", 1), box.NewEntry("Zed", idp(1), box.String("scalar"))))
	must(t, f.mem.Put(addrOf(playersFile, "Zed", 0), box.NewEntry("Zed", idp(0), box.BoxValue(box.NewBox()))))
	if err := f.qerr(t, `{Set[]} = players:Zed[ID=*].A = 1`); !errors.Is(err, ErrType) {
		t.Fatal(err)
	}
	e, _, _ := f.mem.Get(addrOf(playersFile, "Zed", 0))
	if e.Value.Box.Get("A", 0, false) != nil {
		t.Fatal("first record kept its change although the command failed")
	}
}

func idp(i int64) *int64 { return &i }

func TestTxLimitsAndShape(t *testing.T) {
	f := newFixture(t, fixOpt{lim: Limits{MaxWrites: 2}})
	err := f.qerr(t, `{Tx[]} = [ {Set[]} = players:Player[1].A = 1, {Set[]} = players:Player[2].A = 1, {Set[]} = players:Player[3].A = 1 ]`)
	if !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	eq(t, col(f.q(t, `{Get[]} = players:Player[A = 1] -> ID`), "ID"))
	for _, q := range []string{
		`{Tx[]} = []`,
		`{Tx[]} = [ {Tx[]} = [ {Set[]} = players:Player[1].A = 1 ] ]`,
		`{Tx[]} = [ {Explain[]} = [ {Get[]} = players:Player[1] ] ]`,
		`{Tx[]} = [ {Watch[]} = players:Player[1] ]`,
		`{Tx[]} = {Get[]} = players:Player[1]`,
		`{Tx[]} = [ {Get[]} = players:Player[1]`,
		`{Get[]} = players:Player[1] {Get[]} = players:Player[2]`,
	} {
		if err := f.qerr(t, q); !errors.Is(err, ErrSyntax) {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// a Tx with only reads is fine and returns every result
	r := f.q(t, `{Tx[]} = [ {Get[]} = players:Player[1] -> Name, {Get[]} = players:Player[2] -> Name ]`)
	if len(r.Results) != 2 || col(r.Results[1], "Name")[0] != "bob" {
		t.Fatal("results")
	}
}

func TestTxAuthorizationRollsBack(t *testing.T) {
	f := newFixture(t, fixOpt{auth: policy(t), links: true})
	// writer may write Name but not Level: the second command is denied, so the first is not kept
	_, err := f.db.Exec(context.Background(), as("writer"), `{Tx[]} = [
		{Set[]} = players:Player[1].Name = "zed",
		{Set[]} = players:Player[2].Level = 1
	]`, nil)
	if !errors.Is(err, sec.ErrDenied) {
		t.Fatal(err)
	}
	r, err := run1(t, f, as("writer"), `{Get[]} = players:Player[1] -> Name`)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, col(r, "Name"), "ann")
}

func TestConcurrentTxsDoNotInterleave(t *testing.T) {
	f := newFixture(t, fixOpt{})
	f.q(t, `{Add[]} = players:Counter[ID=1] = [ {N[]} = 0 ]`)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.db.Exec(context.Background(), anyone, `{Tx[]} = [ {Set[]} = players:Counter[1].N = N + 1, {Set[]} = players:Counter[1].M = N ]`, nil)
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	r := f.q(t, `{Get[]} = players:Counter[1] -> [N, M]`)
	eq(t, col(r, "N"), "20")
	eq(t, col(r, "M"), "20")
}
