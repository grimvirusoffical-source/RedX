package query

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"redx/box"
	"redx/engine/link"
	"redx/engine/sec"
)

const testPolicy = `
{Role[1]}  = [ {Name[]} = "reader" ];
{Role[2]}  = [ {Name[]} = "writer" ];
{Role[3]}  = [ {Name[]} = "snoop" ];
{Role[4]}  = [ {Name[]} = "joiner" ];
{Role[5]}  = [ {Name[]} = "deleter" ];
{Role[6]}  = [ {Name[]} = "fullwrite" ];
{Rule[1]}  = [ {Effect[]} = "allow", {Who[]} = "role:reader", {Actions[]} = "read", {Resource[]} = "players.red-xai.db" ];
{Rule[2]}  = [ {Effect[]} = "deny",  {Who[]} = "*", {Actions[]} = "*", {Resource[]} = "players.red-xai.db:Player.Stats.Secret" ];
{Rule[3]}  = [ {Effect[]} = "deny",  {Who[]} = "role:reader", {Actions[]} = "read", {Resource[]} = "players.red-xai.db:Player.Bio" ];
{Rule[4]}  = [ {Effect[]} = "allow", {Who[]} = "role:writer", {Actions[]} = ;["read","write","delete"]:, {Resource[]} = "players.red-xai.db:Player" ];
{Rule[5]}  = [ {Effect[]} = "deny",  {Who[]} = "role:writer", {Actions[]} = "write", {Resource[]} = "players.red-xai.db:Player.Level" ];
{Rule[6]}  = [ {Effect[]} = "allow", {Who[]} = "role:snoop", {Actions[]} = "read", {Resource[]} = "players.red-xai.db:Player.Name" ];
{Rule[7]}  = [ {Effect[]} = "allow", {Who[]} = "role:joiner", {Actions[]} = "read", {Resource[]} = ;["players.red-xai.db","guilds.red-xai.db"]: ];
{Rule[8]}  = [ {Effect[]} = "allow", {Who[]} = "role:deleter", {Actions[]} = ;["read","delete"]:, {Resource[]} = ;["players.red-xai.db","guilds.red-xai.db"]: ];
{Rule[9]}  = [ {Effect[]} = "allow", {Who[]} = "role:fullwrite", {Actions[]} = ;["read","write","delete"]:, {Resource[]} = ;["players.red-xai.db","guilds.red-xai.db","inv.red-xai.db"]: ];
{Rule[10]} = [ {Effect[]} = "allow", {Who[]} = "user:*", {Actions[]} = "read", {Resource[]} = "players.red-xai.db", {Owner[]} = TRUE ];
`

func policy(t testing.TB) *sec.Policy {
	t.Helper()
	p, err := sec.Parse(testPolicy)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func as(roles ...string) sec.Principal { return sec.Principal{ID: "u-" + roles[0], Roles: roles} }

func run1(t testing.TB, f *fixture, pr sec.Principal, q string, p ...P) (*Result, error) {
	t.Helper()
	return f.db.Exec(context.Background(), pr, q, params(p))
}

func TestAuthorizerRequired(t *testing.T) {
	if _, err := New(Config{Store: link.NewMemStore()}); !errors.Is(err, ErrNoAuth) {
		t.Fatal(err)
	}
	// a nil *sec.Policy denies everything
	f := newFixture(t, fixOpt{auth: (*sec.Policy)(nil)})
	if _, err := run1(t, f, anyone, `{Get[]} = players:Player -> ID`); !errors.Is(err, sec.ErrDenied) {
		t.Fatal(err)
	}
}

func TestDeniedCommandNeverTouchesStorage(t *testing.T) {
	f := newFixture(t, fixOpt{auth: policy(t)})
	for _, q := range []string{
		`{Get[]} = players:Player`,
		`{Get[]} = players:Player[ID=1]`,
		`{Set[]} = players:Player[ID=1].Name = "x"`,
		`{Set[]} = players:Player[ID=1] = [ {Name[]} = "x" ]`,
		`{Delete[]} = players:Player[ID=1]`,
		`{Delete[]} = players:Player[ID=1].Name`,
		`{Add[]} = players:Player[ID=50] = [ {Name[]} = "x" ]`,
		`{Require[]} = players:Player[ID=1]`,
		`{Tx[]} = [ {Set[]} = players:Player[ID=1].Name = "x" ]`,
	} {
		_, err := run1(t, f, as("nobody"), q)
		if !errors.Is(err, sec.ErrDenied) {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if f.cs.scans.Load()+f.cs.gets.Load()+f.cs.puts.Load()+f.cs.dels.Load() != 0 {
		t.Fatalf("storage was touched: scans=%d gets=%d puts=%d dels=%d", f.cs.scans.Load(), f.cs.gets.Load(), f.cs.puts.Load(), f.cs.dels.Load())
	}
	// a forbidden file and a missing file look the same to an unauthorized caller
	_, e1 := run1(t, f, as("nobody"), `{Get[]} = players:Player`)
	_, e2 := run1(t, f, as("nobody"), `{Get[]} = nosuchfile:Player`)
	if !errors.Is(e1, sec.ErrDenied) || !errors.Is(e2, sec.ErrDenied) {
		t.Fatalf("%v / %v", e1, e2)
	}
	if _, err := run1(t, f, as("reader"), `{Get[]} = nosuchfile:Player`); !errors.Is(err, sec.ErrDenied) {
		t.Fatal("reader has no rule for nosuchfile, so this is a deny too:", err)
	}
	// a bare box name only searches files the principal may read: a hidden box looks like a missing one
	if _, err := run1(t, f, as("nobody"), `{Get[]} = Player[1]`); !errors.Is(err, ErrNoFile) {
		t.Fatal(err)
	}
	if _, err := run1(t, f, as("reader"), `{Get[]} = Guild[10]`); !errors.Is(err, ErrNoFile) {
		t.Fatal(err)
	}
}

func TestAuthorizeBeforeRead(t *testing.T) {
	var firstScans int64 = -1
	var calls atomic.Int64
	var f *fixture
	az := authFunc(func(pr sec.Principal, act sec.Action, res sec.Resource) sec.Decision {
		if calls.Add(1) == 1 {
			atomic.StoreInt64(&firstScans, f.cs.scans.Load()+f.cs.gets.Load())
		}
		return sec.Decision{Allowed: true}
	})
	f = newFixture(t, fixOpt{auth: az})
	f.q(t, `{Get[]} = players:Player[Level > 1] -> Name`)
	if atomic.LoadInt64(&firstScans) != 0 {
		t.Fatal("the first authorization must come before the first storage read")
	}
	if c := calls.Load(); c > 10 {
		t.Fatalf("%d Authorize calls for one command: decisions should be cached", c)
	}
}

type authFunc func(sec.Principal, sec.Action, sec.Resource) sec.Decision

func (f authFunc) Authorize(p sec.Principal, a sec.Action, r sec.Resource) sec.Decision {
	return f(p, a, r)
}

func TestReadMasking(t *testing.T) {
	f := newFixture(t, fixOpt{auth: policy(t)})
	rd := as("reader")
	r, err := run1(t, f, rd, `{Get[]} = players:Player[ID=1] -> [Name, Stats.Gold]`)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, col(r, "Name"), "ann")
	// explicitly asking for a denied field is an error, wherever it appears
	for _, q := range []string{
		`{Get[]} = players:Player -> Stats.Secret`,
		`{Get[]} = players:Player[Stats.Secret = "s1"] -> Name`,
		`{Get[]} = players:Player -> Name, Sort = Bio`,
		`{Get[]} = players:Player -> Bio`,
		`{Get[]} = players:Player -> [Count(), x = Max(Bio)]`,
		`{Get[]} = players:Player -> [n = Count()], Group = Bio`,
		`{Get[]} = players:Player[Bio has "red"] -> Name`,
		`{Require[]} = players:Player[Bio = "x"]`,
	} {
		if _, err := run1(t, f, rd, q); !errors.Is(err, sec.ErrDenied) {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// * and whole boxes are filtered silently, at every depth
	r, err = run1(t, f, rd, `{Get[]} = players:Player[ID=1] -> *`)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Columns {
		if c == "Bio" {
			t.Fatal("Bio leaked through *")
		}
	}
	r, err = run1(t, f, rd, `{Get[]} = players:Player[ID=1] -> Stats`)
	if err != nil {
		t.Fatal(err)
	}
	st := r.Rows[0][0].Box
	if st == nil || st.Len() != 1 || st.Get("Gold", 0, false) == nil || st.Get("Secret", 0, false) != nil {
		t.Fatalf("Secret leaked through the Stats box: %v", r.Rows[0][0])
	}
	// a whole-file query cannot use a denied field to learn anything: it reads as NELL
	r, err = run1(t, f, rd, `{Get[]} = "players.red-xai.db":*[Stats.Secret = "s1"] -> ID`)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Rows) != 0 {
		t.Fatal("filter on a denied field matched")
	}
	// the Secret deny covers everyone, writers too
	if _, err := run1(t, f, as("writer"), `{Get[]} = players:Player -> Stats.Secret`); !errors.Is(err, sec.ErrDenied) {
		t.Fatal(err)
	}
	if _, err := run1(t, f, as("writer"), `{Get[]} = players:Player -> Bio`); err != nil {
		t.Fatal(err)
	}
}

func TestDenyOnPrefixCoversChildren(t *testing.T) {
	p, err := sec.Parse(`
{Rule[1]} = [ {Effect[]} = "allow", {Who[]} = "*", {Actions[]} = "read", {Resource[]} = "players.red-xai.db" ];
{Rule[2]} = [ {Effect[]} = "deny",  {Who[]} = "*", {Actions[]} = "read", {Resource[]} = "players.red-xai.db:Player.Stats" ];
`)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, fixOpt{auth: p})
	if _, err := run1(t, f, anyone, `{Get[]} = players:Player -> Stats.Gold`); !errors.Is(err, sec.ErrDenied) {
		t.Fatalf("a deny on Stats must cover Stats.Gold: %v", err)
	}
	r, err := run1(t, f, anyone, `{Get[]} = "players.red-xai.db":*[ID=1, _box = "Player"] -> [Name, g = Stats.Gold]`)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, col(r, "g"), "NELL")
}

func TestFieldOnlyGrantDoesNotOpenTheBox(t *testing.T) {
	f := newFixture(t, fixOpt{auth: policy(t)})
	if _, err := run1(t, f, as("snoop"), `{Get[]} = players:Player -> Name`); !errors.Is(err, sec.ErrDenied) {
		t.Fatal(err)
	}
}

func TestWriteAuthorization(t *testing.T) {
	f := newFixture(t, fixOpt{auth: policy(t), links: true})
	wr := as("writer")
	for _, q := range []string{
		`{Set[]} = players:Player[ID=1].Name = "x"`,
		`{Add[]} = players:Player[ID=60] = [ {Name[]} = "x" ]`,
		`{Delete[]} = players:Player[ID=1]`,
		`{Set[]} = players:Player[ID=1] = [ {Name[]} = "x" ]`,
	} {
		if _, err := run1(t, f, as("reader"), q); !errors.Is(err, sec.ErrDenied) {
			t.Fatalf("%s: %v", q, err)
		}
	}
	r, err := run1(t, f, wr, `{Set[]} = players:Player[ID=1].Name = "zed"`)
	if err != nil || r.Affected != 1 {
		t.Fatal(err, r)
	}
	if _, err := run1(t, f, wr, `{Set[]} = players:Player[ID=2].[Name = "q", Level = 1]`); !errors.Is(err, sec.ErrDenied) {
		t.Fatalf("Level write must be denied: %v", err)
	}
	ent, _, _ := f.mem.Get(addrOf(playersFile, "Player", 2))
	if ent.Value.Box.Get("Name", 0, false).Value.Str != "bob" {
		t.Fatal("a denied Set must change nothing")
	}
	if _, err := run1(t, f, wr, `{Add[]} = players:Player[ID=61] = [ {Name[]} = "n", {Level[]} = 1 ]`); !errors.Is(err, sec.ErrDenied) {
		t.Fatal(err)
	}
	if _, ok, _ := f.mem.Get(addrOf(playersFile, "Player", 61)); ok {
		t.Fatal("denied Add stored a record")
	}
	// nested paths are checked leaf by leaf
	if _, err := run1(t, f, wr, `{Add[]} = players:Player[ID=63] = [ {Name[]} = "n", {Stats[]} = [ {Secret[]} = "x" ] ]`); !errors.Is(err, sec.ErrDenied) {
		t.Fatal(err)
	}
	if _, err := run1(t, f, wr, `{Add[]} = players:Player[ID=62] = [ {Name[]} = "n" ]`); err != nil {
		t.Fatal(err)
	}
	// a replace is checked against what actually changes: Level differs, so it is denied; same Level is fine
	if _, err := run1(t, f, wr, `{Set[]} = players:Player[ID=62] = [ {Name[]} = "n", {Level[]} = 3 ]`); !errors.Is(err, sec.ErrDenied) {
		t.Fatal(err)
	}
	if _, err := run1(t, f, wr, `{Set[]} = players:Player[ID=62] = [ {Name[]} = "m" ]`); err != nil {
		t.Fatal(err)
	}
	// the denied field cannot be probed through a Set or Delete filter either
	if _, err := run1(t, f, wr, `{Set[]} = players:Player[Stats.Secret = "s1"].Name = "x"`); !errors.Is(err, sec.ErrDenied) {
		t.Fatal(err)
	}
	if _, err := run1(t, f, wr, `{Delete[]} = players:Player[Stats.Secret = "s1"]`); !errors.Is(err, sec.ErrDenied) {
		t.Fatal(err)
	}
	// field delete needs write on that field
	if _, err := run1(t, f, wr, `{Delete[]} = players:Player[ID=2].Level`); !errors.Is(err, sec.ErrDenied) {
		t.Fatal(err)
	}
	if r, err := run1(t, f, wr, `{Delete[]} = players:Player[ID=2].Class`); err != nil || r.Affected != 1 {
		t.Fatal(err, r)
	}
	if r, err := run1(t, f, wr, `{Delete[]} = players:Player[ID=62]`); err != nil || r.Affected != 1 {
		t.Fatal(err, r)
	}
}

func TestCascadeDeleteIsAuthorizedPerTarget(t *testing.T) {
	f := newFixture(t, fixOpt{auth: policy(t), links: true})
	must(t, link.PutDoc(f.mem, "inv.red-xai.db", `{Inv[100]} = [ {Items[]} = 3 ];`))
	e, _, _ := f.mem.Get(addrOf(playersFile, "Player", 1))
	l, _ := link.ParseLink(`"players.red-xai.db":Player[ID=1] @!> "inv.red-xai.db":Inv[ID=100]`)
	e.Value.Box.Put(box.NewEntry("Inv", nil, box.LinkValue(l)))
	must(t, f.mem.Put(addrOf(playersFile, "Player", 1), e))
	_, err := run1(t, f, as("deleter"), `{Delete[]} = players:Player[ID=1]`)
	if !errors.Is(err, sec.ErrDenied) {
		t.Fatalf("cascade into a forbidden file must be refused: %v", err)
	}
	if _, ok, _ := f.mem.Get(addrOf(playersFile, "Player", 1)); !ok {
		t.Fatal("the player must not be deleted when its cascade is refused")
	}
	if _, ok, _ := f.mem.Get(addrOf("inv.red-xai.db", "Inv", 100)); !ok {
		t.Fatal("inv must survive")
	}
	r, err := run1(t, f, as("fullwrite"), `{Delete[]} = players:Player[ID=1]`)
	if err != nil || r.Affected != 1 || len(r.Cascaded) != 1 {
		t.Fatal(err, r)
	}
}

func TestFollowTargetAuthorization(t *testing.T) {
	f := newFixture(t, fixOpt{auth: policy(t), links: true})
	q := `{Get[]} = players:Player[ID=1] -> [Name, Guild.Title] @> Guild`
	r, err := run1(t, f, as("reader"), q)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Rows) != 0 { // reader may not read guilds: the target is invisible, like a dangling link
		t.Fatal("followed a record the principal may not read")
	}
	r, err = run1(t, f, as("reader"), `{Get[]} = players:Player[ID=1] -> [Name, Guild.Title] @> Guild?`)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, col(r, "Guild.Title"), "NELL")
	r, err = run1(t, f, as("joiner"), q)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, col(r, "Guild.Title"), "Red Order")
}

func TestOwnerRules(t *testing.T) {
	owner := func(a link.Addr, e *box.Entry) string {
		if e != nil && e.Value.Kind == box.KindBox {
			if n := e.Value.Box.Get("Name", 0, false); n != nil {
				return n.Value.Str
			}
		}
		return ""
	}
	f := newFixture(t, fixOpt{auth: policy(t), owner: owner})
	bob := sec.Principal{ID: "bob"}
	r, err := run1(t, f, bob, `{Get[]} = players:Player -> Name`)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, col(r, "Name"), "bob") // only the record bob owns
	r, err = run1(t, f, bob, `{Get[]} = "players.red-xai.db":* -> [_box, Name]`)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, col(r, "Name"), "bob")
	// a bare box name works with owner rules too
	r, err = run1(t, f, bob, `{Get[]} = Player -> Name`)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, col(r, "Name"), "bob")
}

func TestExplainDoesNotLeak(t *testing.T) {
	f := newFixture(t, fixOpt{auth: policy(t)})
	ex := func(pr sec.Principal, q string) error {
		_, err := f.db.Explain(context.Background(), pr, q, nil)
		return err
	}
	if err := ex(as("nobody"), `{Get[]} = players:Player`); !errors.Is(err, sec.ErrDenied) {
		t.Fatal(err)
	}
	if err := ex(as("reader"), `{Get[]} = players:Player -> Bio`); !errors.Is(err, sec.ErrDenied) {
		t.Fatal(err)
	}
	if err := ex(as("reader"), `{Get[]} = players:Player -> Name`); err != nil {
		t.Fatal(err)
	}
	// {Explain[]} = [...] is the same thing, and it writes nothing
	r, err := f.db.Exec(context.Background(), as("writer"), `{Explain[]} = [ {Set[]} = players:Player[ID=1].Name = "x" ]`, nil)
	if err != nil || r.Kind != "explain" {
		t.Fatal(err)
	}
	e, _, _ := f.mem.Get(addrOf(playersFile, "Player", 1))
	if e.Value.Box.Get("Name", 0, false).Value.Str != "ann" {
		t.Fatal("Explain wrote")
	}
	if _, err := f.db.Exec(context.Background(), as("reader"), `{Explain[]} = [ {Set[]} = players:Player[ID=1].Name = "x" ]`, nil); !errors.Is(err, sec.ErrDenied) {
		t.Fatal(err)
	}
}
