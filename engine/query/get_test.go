package query

import (
	"errors"
	"strings"
	"testing"

	"redx/engine/link"
)

func TestGetBasics(t *testing.T) {
	f := newFixture(t, fixOpt{})
	r := f.q(t, `{Get[]} = players:Player[ID=*] -> [Name, Level], Sort = ID`)
	eq(t, r.Columns, "Name", "Level")
	eq(t, col(r, "Name"), "ann", "bob", "bobby", "cy", "dee")
	eq(t, col(r, "Level"), "5", "12", "7", "7", "seven")
	if r.Kind != "get" || r.Access != "scan" {
		t.Fatal(r.Kind, r.Access)
	}
	// default order is the record address
	r = f.q(t, `{Get[]} = players:Player[ID=*] -> ID`)
	eq(t, col(r, "ID"), "1", "2", "3", "4", "5")
	if len(r.Addrs) != 5 || r.Addrs[0].ID != 1 {
		t.Fatalf("addrs %v", r.Addrs)
	}
	// a bare number in [] is an ID; a single projection item needs no brackets
	eq(t, col(f.q(t, `{Get[]} = players:Player[3] -> Name`), "Name"), "bobby")
	// the trailing ; and << comments >> are fine; {Get} without [] too
	eq(t, col(f.q(t, "{Get} = players:Player[2] << who? >> -> Name ;"), "Name"), "bob")
}

func TestFilterOperators(t *testing.T) {
	f := newFixture(t, fixOpt{})
	ids := func(filter string, p ...P) []string {
		return col(f.q(t, `{Get[]} = players:Player[`+filter+`] -> ID`, p...), "ID")
	}
	eq(t, ids(`Level = 7`), "3", "4")
	eq(t, ids(`Level != 7`), "1", "2", "5") // "seven" != 7 and so on
	eq(t, ids(`Level > 5`), "2", "3", "4")
	eq(t, ids(`Level >= 7, Level < 12`), "3", "4") // comma = AND
	eq(t, ids(`Level >= 7 & Level < 12`), "3", "4")
	eq(t, ids(`Level < 6 | Name = "cy"`), "1", "4")
	eq(t, ids(`!(Level >= 7)`), "1", "5")
	eq(t, ids(`Level in ;[5, 12]:`), "1", "2")
	eq(t, ids(`!(Level in ;[5, 12, 7]:)`), "5")
	eq(t, ids(`Name starts "bob"`), "2", "3")
	eq(t, ids(`!(Name starts "bob")`), "1", "4", "5")
	eq(t, ids(`Level in 6..12`), "2", "3", "4")
	eq(t, ids(`!(Level in 6..12)`), "1", "5")
	eq(t, ids(`Stats.Gold >= 100`), "1", "3")
	eq(t, ids(`Stats.Gold * 2 = 200`), "1")
	eq(t, ids(`Name = $n`, P{"n": "bob"}), "2")
	eq(t, ids(`Level = $l`, P{"l": 12}), "2")
	eq(t, ids(`$l < Level`, P{"l": 7}), "2")
	eq(t, ids(`7 = Level`), "3", "4")
	eq(t, ids(`Level in $many`, P{"many": []interface{}{5, 12}}), "1", "2")
	eq(t, ids(`Level in $one`, P{"one": 12}), "2")
	eq(t, ids(`Level in $a..$b`, P{"a": 6, "b": 8}), "3", "4")
	eq(t, ids(`ID in ;[1, 3]:`), "1", "3")
	eq(t, ids(`ID in 2..3`), "2", "3")
	eq(t, ids(`Bio has "red dragon"`), "1", "3")
	eq(t, ids(`Bio hasany "blue slayer"`), "1", "2")
	// ID in a path selector
	eq(t, ids(`ID=2`), "2")
	eq(t, ids(`id=2`), "2")
}

func TestNellSemantics(t *testing.T) {
	f := newFixture(t, fixOpt{})
	ids := func(filter string) []string {
		return col(f.q(t, `{Get[]} = players:Player[`+filter+`] -> ID`), "ID")
	}
	eq(t, ids(`Class = NELL`), "4")
	eq(t, ids(`Class != NELL`), "1", "2", "3", "5")
	eq(t, ids(`nell = Class`), "4")
	eq(t, ids(`Nope = NELL`), "1", "2", "3", "4", "5")
	eq(t, ids(`Nope = 1`))
	eq(t, ids(`Nope.Deeper.Still = NELL`), "1", "2", "3", "4", "5")
	eq(t, ids(`Nope < 5 | Nope >= 5`))
	r := f.q(t, `{Get[]} = players:Player[4] -> [Name, Class]`)
	eq(t, col(r, "Class"), "NELL")
	r = f.q(t, `{Get[]} = players:Player[1] -> [a = Level + 1, b = Level / 0, c = Class + 1, d = Level - 1]`)
	eq(t, col(r, "a"), "6")
	eq(t, col(r, "b"), "NELL")
	eq(t, col(r, "c"), "NELL")
	eq(t, col(r, "d"), "4")
	r = f.q(t, `{Get[]} = players:Player[ID=*] -> ID, Sort = ;[Level, ID]:`)
	eq(t, col(r, "ID"), "1", "3", "4", "2", "5")
	r = f.q(t, `{Get[]} = players:Player[ID=*] -> ID, Sort = ;[-Class, ID]:`)
	eq(t, col(r, "ID"), "2", "5", "1", "3", "4") // warrior, healer, Mage, MAGE, NELL
	// bare boolean field as a condition
	f.q(t, `{Set[]} = players:Player[2].Active = TRUE`)
	eq(t, ids(`Active`), "2")
	eq(t, ids(`Active = TRUE`), "2")
	eq(t, ids(`!Active`), "1", "3", "4", "5")
}

func TestSortLimitOffset(t *testing.T) {
	f := newFixture(t, fixOpt{})
	r := f.q(t, `{Get[]} = players:Player[Level >= 5] -> Name, Sort = ;[-Level, Name]:, Limit = 3`)
	eq(t, col(r, "Name"), "bob", "bobby", "cy")
	r = f.q(t, `{Get[]} = players:Player[ID=*] -> Name, Sort = -Name, Limit = 2, Offset = 1`)
	eq(t, col(r, "Name"), "cy", "bobby")
	r = f.q(t, `{Get[]} = players:Player[ID=*] -> Name, Sort = Name, Offset = 3`)
	eq(t, col(r, "Name"), "cy", "dee")
	r = f.q(t, `{Get[]} = players:Player[ID=*] -> Name, Sort = +Name, Limit = $n, Offset = $o`, P{"n": 2, "o": 1})
	eq(t, col(r, "Name"), "bob", "bobby")
	// options in any order
	r = f.q(t, `{Get[]} = players:Player[ID=*] -> Name, Offset = 1, Limit = 1, Sort = Name`)
	eq(t, col(r, "Name"), "bob")
	if r = f.q(t, `{Get[]} = players:Player[ID=*] -> Name, Limit = 0`); len(r.Rows) != 0 {
		t.Fatal("limit 0")
	}
	if r = f.q(t, `{Get[]} = players:Player[ID=*] -> Name, Offset = 100`); len(r.Rows) != 0 {
		t.Fatal("offset past the end")
	}
	// Sort by a projected name
	r = f.q(t, `{Get[]} = players:Player[Stats.Gold != NELL] -> [Name, gold = Stats.Gold], Sort = -gold`)
	eq(t, col(r, "Name"), "bobby", "ann", "bob", "cy")
	r = f.q(t, `{Get[]} = players:Player[ID=*] -> ID, Limit = 2`)
	eq(t, col(r, "ID"), "1", "2")
	for _, q := range []string{
		`{Get[]} = players:Player[ID=*] -> Name, Limit = -1`,
		`{Get[]} = players:Player[ID=*] -> Name, Limit = 1.5`,
		`{Get[]} = players:Player[ID=*] -> Name, Limit = 1, Limit = 2`,
		`{Get[]} = players:Player[ID=*] -> Name, Bogus = 2`,
	} {
		if err := f.qerr(t, q); !errors.Is(err, ErrSyntax) {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := f.qerr(t, `{Get[]} = players:Player[ID=*] -> Name, Limit = $n`, P{"n": "x"}); !errors.Is(err, ErrParams) {
		t.Fatal(err)
	}
	if err := f.qerr(t, `{Get[]} = players:Player[ID=*] -> Name, Limit = $n`, P{"n": -4}); !errors.Is(err, ErrParams) {
		t.Fatal(err)
	}
}

func TestStarAndNested(t *testing.T) {
	f := newFixture(t, fixOpt{})
	r := f.q(t, `{Get[]} = players:Player[4]`) // no projection = every field
	eq(t, r.Columns, "Name", "Level", "Stats", "Guild")
	r = f.q(t, `{Get[]} = players:Player[ID in ;[3, 4]:] -> *`)
	eq(t, r.Columns, "Name", "Level", "Class", "Bio", "Stats", "Guild")
	eq(t, col(r, "Class"), "MAGE", "NELL")
	r = f.q(t, `{Get[]} = players:Player[1] -> Stats`)
	if r.Rows[0][0].Box == nil || r.Rows[0][0].Box.Len() != 2 {
		t.Fatalf("%v", r.Rows[0][0])
	}
	r = f.q(t, `{Get[]} = players:Player[2] -> [_file, _box, ID]`)
	eq(t, col(r, "_file"), playersFile)
	eq(t, col(r, "_box"), "Player")
	r = f.q(t, `{Get[]} = "players.red-xai.db":*[Name = "ann"] -> [_box, ID]`) // whole file
	eq(t, col(r, "_box"), "Npc", "Player")
	r = f.q(t, `{Get[]} = "players.red-xai.db":Player[2] -> [Name, Player.Level]`)
	eq(t, r.Columns, "Name", "Player.Level")
}

func TestSourceResolution(t *testing.T) {
	f := newFixture(t, fixOpt{})
	f.q(t, `{Get[]} = "players.red-xai.db":Player[1]`)
	f.q(t, `{Get[]} = players:Player[1]`)
	// a bare box name is looked up across the files you may read
	eq(t, col(f.q(t, `{Get[]} = Guild[10] -> Title`), "Title"), "Red Order")
	eq(t, col(f.q(t, `{Get[]} = Npc[1] -> Name`), "Name"), "ann")
	if err := f.qerr(t, `{Get[]} = nosuch:Player[1]`); !errors.Is(err, ErrNoFile) {
		t.Fatal(err)
	}
	if err := f.qerr(t, `{Get[]} = Nothing[1]`); !errors.Is(err, ErrNoFile) {
		t.Fatal(err)
	}
	// ambiguity
	must(t, f.mem.Put(link.Addr{File: "players.red-xai-db-qs", Box: "X", ID: 1, HasID: true}, mkEntry(t, "X", 1)))
	if err := f.qerr(t, `{Get[]} = players:Player[1]`); !errors.Is(err, ErrAmbiguous) {
		t.Fatal(err)
	}
	f.q(t, `{Get[]} = "players.red-xai.db":Player[1]`)
	must(t, f.mem.Put(link.Addr{File: "other.red-xai.db", Box: "Guild", ID: 10, HasID: true}, mkEntry(t, "Guild", 10)))
	if err := f.qerr(t, `{Get[]} = Guild[10]`); !errors.Is(err, ErrAmbiguous) {
		t.Fatal(err)
	}
	// a write names its file
	if err := f.qerr(t, `{Set[]} = Player[1].Name = "x"`); !errors.Is(err, ErrSyntax) {
		t.Fatal(err)
	}
}

func TestFollow(t *testing.T) {
	f := newFixture(t, fixOpt{links: true})
	r := f.q(t, `{Get[]} = players:Player[ID=*] -> [Name, Guild.Title, Guild.Rank] @> Guild`)
	eq(t, col(r, "Name"), "ann", "bob", "dee") // 3 has no link, 4 dangles
	eq(t, col(r, "Guild.Title"), "Red Order", "Red Order", "Red Order")
	r = f.q(t, `{Get[]} = players:Player[ID=*] -> [Name, g.Title] @> g = Guild?`)
	eq(t, col(r, "Name"), "ann", "bob", "bobby", "cy", "dee")
	eq(t, col(r, "g.Title"), "Red Order", "Red Order", "NELL", "NELL", "Red Order")
	// filter on the followed side, ID of the followed record
	r = f.q(t, `{Get[]} = players:Player[Level > 5] -> [Name, g.ID] @> g = Guild, Sort = Name`)
	eq(t, col(r, "Name"), "bob")
	eq(t, col(r, "g.ID"), "10")
	// chained: player -> guild -> owner
	r = f.q(t, `{Get[]} = players:Player[1] -> [Name, owner = o.Name] @> g = Guild @> o = g.Owner`)
	eq(t, col(r, "owner"), "bob")
	// alias.* expands the followed record
	r = f.q(t, `{Get[]} = players:Player[1] -> g.* @> g = Guild`)
	eq(t, r.Columns, "g.Title", "g.Owner", "g.Rank")
	// sort and limit apply to followed rows
	r = f.q(t, `{Get[]} = players:Player[ID=*] -> Name @> Guild, Sort = -Name, Limit = 1`)
	eq(t, col(r, "Name"), "dee")
	// the filter in [...] may use followed names (applied after the follow)
	r = f.q(t, `{Get[]} = players:Player[Guild.Rank >= 3, Level > 5] -> Name @> Guild`)
	eq(t, col(r, "Name"), "bob")
	// no link engine
	g := newFixture(t, fixOpt{})
	if err := g.qerr(t, `{Get[]} = players:Player[ID=*] -> Name @> Guild`); !errors.Is(err, ErrNoLinks) {
		t.Fatal(err)
	}
	for _, q := range []string{
		`{Get[]} = players:Player[ID=*] @> ID`,
		`{Get[]} = players:Player[ID=*] @> Guild @> Guild`,
		`{Get[]} = players:Player[ID=*] @> Player = Guild`,
		`{Get[]} = players:Player[ID=*] @!> Guild`,
		`{Get[]} = players:Player[ID=*] @>`,
	} {
		if err := f.qerr(t, q); !errors.Is(err, ErrSyntax) {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func TestFollowArrayOfLinksAndCascadeLinkNotFollowed(t *testing.T) {
	f := newFixture(t, fixOpt{links: true})
	must(t, link.PutDoc(f.mem, "teams.red-xai.db", `
{Team[1]} = [ {Name[]} = "alpha", {Members[]} = ;["x":Y[ID=1] @> "players.red-xai.db":Player[ID=1], "x":Y[ID=1] @> "players.red-xai.db":Player[ID=2], "x":Y[ID=1] @> "players.red-xai.db":Player[ID=77]]:,
   {Boss[]} = "teams.red-xai.db":Team[ID=1].Boss @!> "players.red-xai.db":Player[ID=1] ];
`))
	r := f.q(t, `{Get[]} = teams:Team[ID=*] -> [Name, member = m.Name] @> m = Members`)
	eq(t, col(r, "member"), "ann", "bob")
	// a @!> link is a cascade link, not a read link
	r = f.q(t, `{Get[]} = teams:Team[ID=*] -> m.Name @> m = Boss`)
	eq(t, col(r, "m.Name"))
}

func TestAggregates(t *testing.T) {
	f := newFixture(t, fixOpt{})
	r := f.q(t, `{Get[]} = players:Player[ID=*] -> [Count(), Total = Sum(Stats.Gold), Mean = Avg(Stats.Gold), Lo = Min(Level), Hi = Max(Level)]`)
	eq(t, r.Columns, "Count", "Total", "Mean", "Lo", "Hi")
	eq(t, col(r, "Count"), "5")
	eq(t, col(r, "Total"), "355")
	eq(t, col(r, "Mean"), "88.75")
	eq(t, col(r, "Lo"), "5") // numbers sort before strings
	eq(t, col(r, "Hi"), "seven")
	// filter first, then aggregate
	r = f.q(t, `{Get[]} = players:Player[Level > 5] -> [n = Count(), gold = Sum(Stats.Gold)]`)
	eq(t, col(r, "n"), "3")
	eq(t, col(r, "gold"), "255")
	// an empty set still gives one row
	r = f.q(t, `{Get[]} = players:Player[Level > 1000] -> [n = Count(), gold = Sum(Stats.Gold), m = Avg(Stats.Gold), x = Max(Level)]`)
	eq(t, col(r, "n"), "0")
	eq(t, col(r, "gold"), "0")
	eq(t, col(r, "m"), "NELL")
	eq(t, col(r, "x"), "NELL")
	// Group
	r = f.q(t, `{Get[]} = players:Player[Level in 5..12] -> [Level, n = Count()], Group = Level, Sort = ;[-n, Level]:`)
	eq(t, col(r, "Level"), "7", "5", "12")
	eq(t, col(r, "n"), "2", "1", "1")
	r = f.q(t, `{Get[]} = players:Player[ID=*] -> [Class, n = Count()], Group = ;[Class]:, Sort = Class, Limit = 2`)
	eq(t, col(r, "Class"), "NELL", "MAGE")
	// Group on a followed name
	g := newFixture(t, fixOpt{links: true})
	r = g.q(t, `{Get[]} = players:Player[ID=*] -> [t = Guild.Title, n = Count()] @> Guild, Group = Guild.Title`)
	eq(t, col(r, "t"), "Red Order")
	eq(t, col(r, "n"), "3")
	// Group with no aggregate = distinct
	r = f.q(t, `{Get[]} = players:Player[ID=*] -> Level, Group = Level, Sort = Level`)
	eq(t, col(r, "Level"), "5", "7", "12", "seven")
	for _, q := range []string{
		`{Get[]} = players:Player[ID=*] -> [Name, Count()]`,                     // Name is not a key
		`{Get[]} = players:Player[ID=*] -> [Count()], Sort = Name`,              // Sort names a column
		`{Get[]} = players:Player[Count() > 1] -> Name`,                         // aggregate in a filter
		`{Get[]} = players:Player[ID=*] -> [Sum(Level) + 1]`,                    // aggregate inside an expression
		`{Get[]} = players:Player[ID=*] -> [Sum(Sum(Level))]`,                   // nested
		`{Get[]} = players:Player[ID=*] -> [Count(Level)]`,                      // Count takes no argument
		`{Get[]} = players:Player[ID=*] -> [Sum()]`,                             // Sum needs one
		`{Get[]} = players:Player[ID=*] -> [*, Count()]`,                        // * with aggregates
		`{Get[]} = players:Player[ID=*] -> [Level, n = Count()], Group = Class`, // Level not a key
	} {
		if err := f.qerr(t, q); err == nil {
			t.Fatal("expected an error: " + q)
		}
	}
}

func TestErrorsAreSyntaxErrorsWithPositions(t *testing.T) {
	f := newFixture(t, fixOpt{})
	err := f.qerr(t, "{Get[]} = players:Player[Level >]\n")
	var se *SyntaxError
	if !errors.As(err, &se) || se.Pos.Line != 1 || se.Pos.Col != 33 {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(se.Context("{Get[]} = players:Player[Level >]\n"), "^") {
		t.Fatal("no caret")
	}
}

func TestLimitsAreEnforced(t *testing.T) {
	f := newFixture(t, fixOpt{lim: Limits{MaxRows: 3, MaxScan: 4}})
	if err := f.qerr(t, `{Get[]} = players:Player[ID=*] -> Name`); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	if err := f.qerr(t, `{Get[]} = players:Player[ID=*] -> Name, Limit = 10`); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	g := newFixture(t, fixOpt{lim: Limits{MaxRows: 3}})
	if err := g.qerr(t, `{Get[]} = players:Player[ID=*] -> Name`); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	g.q(t, `{Get[]} = players:Player[ID=*] -> Name, Limit = 3`)
	h := newFixture(t, fixOpt{lim: Limits{MaxScan: 2}})
	if err := h.qerr(t, `{Get[]} = players:Player[Level > 1] -> Name`); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
}
