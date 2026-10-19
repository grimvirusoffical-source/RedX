package query

import (
	"context"
	"errors"
	"testing"

	"redx/box"
	"redx/engine/link"
)

func TestAdd(t *testing.T) {
	f := newFixture(t, fixOpt{})
	r := f.q(t, `{Add[]} = players:Player[ID=10] = [ {Name[]} = "eve", {Level[]} = 3, {Stats[]} = [ {Gold[]} = 7 ] ]`)
	if r.Affected != 1 || r.Kind != "add" {
		t.Fatal(r.Affected, r.Kind)
	}
	r = f.q(t, `{Add[]} = players:Player[ID=11] = [ {Name[]} = $n, {Level[]} = $l, {Tags[]} = ;["a", $t]:, {Bio[]} = NELL ]`, P{"n": "fay", "l": 4, "t": "z"})
	got := f.q(t, `{Get[]} = players:Player[ID >= 10] -> [Name, Level, g = Stats.Gold, Tags], Sort = ID`)
	eq(t, col(got, "Name"), "eve", "fay")
	eq(t, col(got, "g"), "7", "NELL")
	if got.Rows[1][3].Kind != box.KindArray || len(got.Rows[1][3].Arr) != 2 {
		t.Fatalf("%v", got.Rows[1][3])
	}
	// it exists
	if err := f.qerr(t, `{Add[]} = players:Player[ID=10] = [ {Name[]} = "dup" ]`); !errors.Is(err, ErrExists) {
		t.Fatal(err)
	}
	// a record without an ID, and IDs inside a record
	f.q(t, `{Add[]} = players:Config = [ {Motd[]} = "hi", {Slot[ID=2]} = [ {Qty[]} = 9 ], {Slot[ID=3]} = [ {Qty[]} = 1 ] ]`)
	eq(t, col(f.q(t, `{Get[]} = players:Config -> [Motd, q = Slot[ID=3].Qty]`), "q"), "1")
	// link literals and the Box text format round-trip
	f.q(t, `{Add[]} = players:Player[ID=12] = [ {Name[]} = "gil", {Guild[]} = "players.red-xai.db":Player[ID=12].Guild @> "guilds.red-xai.db":Guild[ID=10] ]`)
	e, ok, _ := f.mem.Get(addrOf(playersFile, "Player", 12))
	if !ok || e.Value.Box.Get("Guild", 0, false).Value.Kind != box.KindLink {
		t.Fatal("link not stored")
	}
	if _, err := box.ParseValue(e.Value.String()); err != nil {
		t.Fatal(err)
	}
	// TTL on the record
	f.q(t, `{Add[]} = players:Temp[ID=1] = [ {X[]} = 1 ] (30)`)
	te, _, _ := f.mem.Get(addrOf(playersFile, "Temp", 1))
	if te.TTL.Kind != box.TTLFixed || te.TTL.Seconds != 30 {
		t.Fatalf("ttl %d %d", te.TTL.Kind, te.TTL.Seconds)
	}
	for _, q := range []string{
		`{Add[]} = players:Player[ID=20] = [ {Name[]} = Name ]`,                // no field references
		`{Add[]} = players:Player[ID=20] = [ {Name[]} = "a", {Name[]} = "b" ]`, // twice
		`{Add[]} = players:Player[ID=20] = [ {"bad name"[]} = 1 ]`,
		`{Add[]} = players:Player[ID=20] = [ {ID[]} = 1 ]`,
		`{Add[]} = players:Player[ID=*] = [ {Name[]} = "x" ]`,
		`{Add[]} = players:Player[Level > 1] = [ {Name[]} = "x" ]`,
		`{Add[]} = players:Player[ID=1.5] = [ {Name[]} = "x" ]`,
		`{Add[]} = players:Player[ID=20]`,
		`{Add[]} = players:*[ID=20] = [ {Name[]} = "x" ]`,
		`{Add[]} = players:Player[ID=20] = [ {Name[]} = "x" ] (0)`,
		`{Add[]} = players:Player[ID=20] = [ {Name[]} = "x" ] (~5)*`,
		`{Add[]} = players:Player[ID=20] = [ {Name[]} = "x" ] [ {Name[]} = "y" ]`,
	} {
		if err := f.qerr(t, q); err == nil {
			t.Fatal(q)
		}
	}
	eq(t, col(f.q(t, `{Get[]} = players:Player[ID=20] -> ID`), "ID"))
	if err := f.qerr(t, `{Add[]} = players:Player[ID=20] = [ {Name[]} = $x ]`, P{"x": map[string]interface{}{"a": 1}}); !errors.Is(err, ErrParams) {
		t.Fatal(err)
	}
}

func TestSet(t *testing.T) {
	f := newFixture(t, fixOpt{})
	r := f.q(t, `{Set[]} = players:Player[Level >= 7, Level < 100].[Level = Level + 1, Stats.Gold = Stats.Gold * 2]`)
	if r.Affected != 3 || r.Kind != "set" {
		t.Fatalf("affected %d", r.Affected) // bob, bobby, cy (dee has Level "seven")
	}
	got := f.q(t, `{Get[]} = players:Player[ID=*] -> [Level, g = Stats.Gold], Sort = ID`)
	eq(t, col(got, "Level"), "5", "13", "8", "8", "seven")
	eq(t, col(got, "g"), "100", "10", "500", "0", "NELL")
	// the right-hand sides see the old values: swapping works
	f.q(t, `{Set[]} = players:Player[1].[Level = Stats.Gold, Stats.Gold = Level]`)
	got = f.q(t, `{Get[]} = players:Player[1] -> [Level, g = Stats.Gold]`)
	eq(t, col(got, "Level"), "100")
	eq(t, col(got, "g"), "5")
	// new nested field; unchanged records are not counted
	if r = f.q(t, `{Set[]} = players:Player[2].Meta.Seen = 1`); r.Affected != 1 {
		t.Fatal(r.Affected)
	}
	if r = f.q(t, `{Set[]} = players:Player[2].Meta.Seen = 1`); r.Affected != 0 {
		t.Fatal("unchanged record counted", r.Affected)
	}
	// NELL, and parameters that are not parsed as BoxQL
	f.q(t, `{Set[]} = players:Player[1].Class = NELL`)
	eq(t, col(f.q(t, `{Get[]} = players:Player[Class = NELL] -> ID`), "ID"), "1", "4")
	f.q(t, `{Set[]} = players:Player[Name = $old].Name = $new`, P{"old": "ann", "new": `it's "quoted" ] {Delete[]}`})
	eq(t, col(f.q(t, `{Get[]} = players:Player[1] -> Name`), "Name"), `it's "quoted" ] {Delete[]}`)
	// Set on an ID that does not exist changes nothing
	if r = f.q(t, `{Set[]} = players:Player[999].Level = 1`); r.Affected != 0 {
		t.Fatal(r.Affected)
	}
	// every record
	if r = f.q(t, `{Set[]} = players:Player[ID=*].Seen = TRUE`); r.Affected != 5 {
		t.Fatal(r.Affected)
	}
	// ID-selected entries inside a record
	f.q(t, `{Add[]} = players:Bag[ID=1] = [ {Item[ID=10]} = [ {Qty[]} = 1 ] ]`)
	f.q(t, `{Set[]} = players:Bag[1].Item[id=10].Qty = 5`)
	eq(t, col(f.q(t, `{Get[]} = players:Bag[1] -> q = Item[ID=10].Qty`), "q"), "5")
	// TTL marker on a Set applies to the record
	f.q(t, `{Set[]} = players:Bag[1].Open = TRUE (~60)`)
	be, _, _ := f.mem.Get(addrOf(playersFile, "Bag", 1))
	if be.TTL.Kind != box.TTLSliding || be.TTL.Seconds != 60 {
		t.Fatalf("ttl %d %d", be.TTL.Kind, be.TTL.Seconds)
	}
	// type conflict: Level is a number, not a box
	if err := f.qerr(t, `{Set[]} = players:Player[1].Level.Sub = 1`); !errors.Is(err, ErrType) {
		t.Fatal(err)
	}
	for _, q := range []string{
		`{Set[]} = players:Player.Level = 1`,                 // no scope
		`{Set[]} = players:Player[ID=1]`,                     // nothing to set
		`{Set[]} = players:Player[1].ID = 5`,                 // ID is read-only
		`{Set[]} = players:Player[1].[Level = 1, Level = 2]`, // twice
		`{Set[]} = players:Player[1]._box = "x"`,             // read-only
		`{Set[]} = players:Player[1].Level = Sum(Level)`,     // aggregate
		`{Set[]} = players:Player[1].[]`,                     // empty
		`{Set[]} = players:*[ID=*].Level = 1`,                // needs a box
		`{Set[]} = players:Player[1].Level = 1 (5) (6)`,
	} {
		if err := f.qerr(t, q); err == nil {
			t.Fatal(q)
		}
	}
	if _, ok, _ := f.mem.Get(addrOf(playersFile, "Player", 1)); !ok {
		t.Fatal("record lost")
	}
}

func TestSetReplaceRecord(t *testing.T) {
	f := newFixture(t, fixOpt{})
	r := f.q(t, `{Set[]} = players:Player[2] = [ {Name[]} = "bobby2", {Level[]} = 1 ]`)
	if r.Affected != 1 {
		t.Fatal(r.Affected)
	}
	got := f.q(t, `{Get[]} = players:Player[2]`)
	eq(t, got.Columns, "Name", "Level") // replaced: Class, Stats, ... are gone
	// replacing with the same content is a no-op
	if r = f.q(t, `{Set[]} = players:Player[2] = [ {Name[]} = "bobby2", {Level[]} = 1 ]`); r.Affected != 0 {
		t.Fatal(r.Affected)
	}
	// a missing record is created (upsert)
	if r = f.q(t, `{Set[]} = players:Player[77] = [ {Name[]} = "new" ] (45)`); r.Affected != 1 {
		t.Fatal(r.Affected)
	}
	e, ok, _ := f.mem.Get(addrOf(playersFile, "Player", 77))
	if !ok || e.TTL.Seconds != 45 {
		t.Fatal(ok, e)
	}
	for _, q := range []string{
		`{Set[]} = players:Player[ID=*] = [ {Name[]} = "x" ]`,
		`{Set[]} = players:Player[Level > 1] = [ {Name[]} = "x" ]`,
	} {
		if err := f.qerr(t, q); err == nil {
			t.Fatal(q)
		}
	}
}

func TestDeleteAndCascade(t *testing.T) {
	f := newFixture(t, fixOpt{links: true})
	must(t, link.PutDoc(f.mem, "inv.red-xai.db", `
{Inv[100]} = [ {Items[]} = 3 ];
{Inv[101]} = [ {Items[]} = 4 ];
{Inv[102]} = [ {Items[]} = 5 ];
`))
	put := func(file, boxName string, id int64, mutate func(b *box.Box)) {
		e, _, _ := f.mem.Get(addrOf(file, boxName, id))
		mutate(e.Value.Box)
		must(t, f.mem.Put(addrOf(file, boxName, id), e))
	}
	cascade := func(from, to link.Addr) box.Value {
		l, err := link.ParseLink(`"` + from.File + `":` + from.Box + `[ID=` + itoa(from.ID) + `] @!> "` + to.File + `":` + to.Box + `[ID=` + itoa(to.ID) + `]`)
		must(t, err)
		return box.LinkValue(l)
	}
	put(playersFile, "Player", 1, func(b *box.Box) {
		b.Put(box.NewEntry("Inv", nil, cascade(addrOf(playersFile, "Player", 1), addrOf("inv.red-xai.db", "Inv", 100))))
	})
	put("inv.red-xai.db", "Inv", 100, func(b *box.Box) {
		b.Put(box.NewEntry("Next", nil, cascade(addrOf("inv.red-xai.db", "Inv", 100), addrOf("inv.red-xai.db", "Inv", 101))))
	})
	r := f.q(t, `{Delete[]} = players:Player[Name = "ann"]`)
	if r.Affected != 1 || len(r.Cascaded) != 2 || r.Kind != "delete" {
		t.Fatalf("affected %d cascaded %v", r.Affected, r.Cascaded)
	}
	eq(t, col(f.q(t, `{Get[]} = inv:Inv[ID=*] -> ID`), "ID"), "102")
	eq(t, col(f.q(t, `{Get[]} = players:Player[1] -> ID`), "ID"))
	r = f.q(t, `{Delete[]} = players:Player[Name starts "bob" | ID in ;[4, 99]:]`)
	if r.Affected != 3 {
		t.Fatal(r.Affected)
	}
	eq(t, col(f.q(t, `{Get[]} = players:Player[ID=*] -> ID`), "ID"), "5")
	if r = f.q(t, `{Delete[]} = players:Player[Name = "nobody"]`); r.Affected != 0 {
		t.Fatal(r.Affected)
	}
	// [ID=*] deletes every record of the box (and only that box)
	f.q(t, `{Delete[]} = players:Player[ID=*]`)
	eq(t, col(f.q(t, `{Get[]} = players:Player[ID=*] -> ID`), "ID"))
	eq(t, col(f.q(t, `{Get[]} = players:Npc[ID=*] -> ID`), "ID"), "1")
	// no scope, no delete
	if err := f.qerr(t, `{Delete[]} = players:Npc`); !errors.Is(err, ErrBadStatement) {
		t.Fatal(err)
	}
	if err := f.qerr(t, `{Delete[]} = players:*[ID=*]`); !errors.Is(err, ErrSyntax) {
		t.Fatal(err)
	}
}

func itoa(i int64) string { return box.Int(i).String() }

func TestDeleteField(t *testing.T) {
	f := newFixture(t, fixOpt{})
	if r := f.q(t, `{Delete[]} = players:Player[1].Stats.Secret`); r.Affected != 1 {
		t.Fatal(r.Affected)
	}
	eq(t, col(f.q(t, `{Get[]} = players:Player[1] -> [g = Stats.Gold, s = Stats.Secret]`), "s"), "NELL")
	eq(t, col(f.q(t, `{Get[]} = players:Player[1] -> g = Stats.Gold`), "g"), "100")
	if r := f.q(t, `{Delete[]} = players:Player[1].Stats.Secret`); r.Affected != 0 {
		t.Fatal("deleting an absent field must change nothing")
	}
	if r := f.q(t, `{Delete[]} = players:Player[ID=*].Bio`); r.Affected != 3 {
		t.Fatal(r.Affected)
	}
	if _, ok, _ := f.mem.Get(addrOf(playersFile, "Player", 1)); !ok {
		t.Fatal("record must stay")
	}
	if err := f.qerr(t, `{Delete[]} = players:Player[1].ID`); err == nil {
		t.Fatal("ID cannot be deleted as a field")
	}
}

func TestDeleteWithoutLinkEngineRefusesCascadeRecords(t *testing.T) {
	f := newFixture(t, fixOpt{})
	e, _, _ := f.mem.Get(addrOf(playersFile, "Player", 1))
	l, _ := link.ParseLink(`"players.red-xai.db":Player[ID=1] @!> "guilds.red-xai.db":Guild[ID=10]`)
	e.Value.Box.Put(box.NewEntry("Own", nil, box.LinkValue(l)))
	must(t, f.mem.Put(addrOf(playersFile, "Player", 1), e))
	if err := f.qerr(t, `{Delete[]} = players:Player[1]`); !errors.Is(err, ErrNoLinks) {
		t.Fatal(err)
	}
	if _, ok, _ := f.mem.Get(addrOf(playersFile, "Player", 1)); !ok {
		t.Fatal("must not delete")
	}
	f.q(t, `{Delete[]} = players:Player[2]`)
}

func TestRequire(t *testing.T) {
	f := newFixture(t, fixOpt{})
	if r := f.q(t, `{Require[]} = players:Player[Level > 5]`); r.Matched != 3 || r.Kind != "require" {
		t.Fatal(r.Matched)
	}
	if err := f.qerr(t, `{Require[]} = players:Player[Level > 500]`); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	f.q(t, `{Require[]} = players:Player[Level > 5], Count = 3`)
	if err := f.qerr(t, `{Require[]} = players:Player[Level > 5], Count = 2`); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	f.q(t, `{Require[]} = players:Player[Level > 500], Count = 0`)
	f.q(t, `{Require[]} = players:Player[ID=2, Name = $n]`, P{"n": "bob"})
	if err := f.qerr(t, `{Require[]} = players:Player[ID=2, Name = $n]`, P{"n": "x"}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
}

func TestContextCancelled(t *testing.T) {
	f := newFixture(t, fixOpt{})
	for i := 0; i < 600; i++ {
		must(t, f.mem.Put(addrOf(playersFile, "Player", int64(100+i)), mkEntry(t, "Player", int64(100+i))))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.db.Exec(ctx, anyone, `{Get[]} = players:Player[Name = "x"]`, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// a write that divides by zero (or overflows) fails and leaves the stored value unchanged;
// the same arithmetic in a read still gives NELL.
func TestSetArithmeticFailureLeavesValueUnchanged(t *testing.T) {
	f := newFixture(t, fixOpt{})
	before := col(f.q(t, `{Get[]} = players:Player[ID=1] -> Level`), "Level")
	for _, q := range []string{
		`{Set[]} = players:Player[ID=1].Level = Level / 0`,
		`{Set[]} = players:Player[ID=1].Level = Level / (Level - Level)`,
		`{Set[]} = players:Player[ID=1].Level = 1e308 * 1e308`,
	} {
		err := f.qerr(t, q)
		if !errors.Is(err, ErrType) {
			t.Fatalf("%s: want ErrType, got %v", q, err)
		}
		if got := col(f.q(t, `{Get[]} = players:Player[ID=1] -> Level`), "Level"); len(got) != len(before) || got[0] != before[0] {
			t.Fatalf("%s changed the value: %v -> %v", q, before, got)
		}
	}
	if err := f.qerr(t, `{Add[]} = players:Player[ID=40] = [ {Name[]} = "z", {Level[]} = 1 / 0 ]`); !errors.Is(err, ErrType) {
		t.Fatalf("Add with division by zero: %v", err)
	}
	r := f.q(t, `{Get[]} = players:Player[ID=1] -> [x = Level / 0]`)
	if r.Rows[0][0].String() != "NELL" {
		t.Fatalf("read arithmetic must still give NELL, got %v", r.Rows[0][0])
	}
	// non-numeric operands stay NELL in a write (documented)
	f.q(t, `{Set[]} = players:Player[ID=1].Note = Missing + 1`)
}
