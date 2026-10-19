package engineadapter_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"redx/host"
	"redx/host/engineadapter"
)

// startFull starts a host on the real engine with a custom adapter config. pre may place
// hand-written .red-xai-* files into the default database's folder before it is opened.
func startFull(t *testing.T, ac engineadapter.Config, pre func(dbDir string)) *node {
	t.Helper()
	n := &node{srv: httptest.NewUnstartedServer(nil)}
	n.url = "http://" + n.srv.Listener.Addr().String()
	cfg := host.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.ArgonMemKiB, cfg.ArgonTime = 64, 1
	cfg.Heartbeat = 1
	cfg.Advertise = n.url
	cfg.ClusterKey = "engine-test-cluster-secret"
	if pre != nil {
		dir := filepath.Join(cfg.DataDir, "dbs", "default")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		pre(dir)
	}
	if ac.SweepMS == 0 {
		ac.SweepMS = 50
	}
	h, err := host.New(cfg, engineadapter.Opener(ac), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	n.h, n.key = h, h.BootstrapKey
	n.srv.Config.Handler = h.Handler()
	n.srv.Start()
	t.Cleanup(func() { n.srv.Close(); n.h.Close() })
	return n
}

func mkKeyFull(t *testing.T, n *node, spec map[string]interface{}) string {
	t.Helper()
	body, _ := json.Marshal(spec)
	st, b, _ := req(t, "POST", n.url+"/v1/keys", n.key, body, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("create key %d %s", st, b)
	}
	var m map[string]interface{}
	json.Unmarshal(b, &m)
	return m["key"].(string)
}

type bxOut struct {
	Kind     string              `json:"kind"`
	Columns  []string            `json:"columns"`
	Rows     [][]json.RawMessage `json:"rows"`
	RowsBox  [][]string          `json:"rows_box"`
	Count    int                 `json:"count"`
	Affected int                 `json:"affected"`
	Matched  int                 `json:"matched"`
	Access   string              `json:"access"`
	Plan     []string            `json:"plan"`
	Paths    []string            `json:"paths"`
	Cascaded []string            `json:"cascaded"`
	Results  []bxOut             `json:"results"`
}

// bxp is a set of $name parameters.
type bxp = map[string]interface{}

func bx(t *testing.T, n *node, key, db, q string, params ...bxp) (int, bxOut, string) {
	t.Helper()
	body := map[string]interface{}{"q": q}
	if len(params) > 0 {
		body["params"] = params[0]
	}
	raw, _ := json.Marshal(body)
	u := n.url + "/v1/bx"
	if db != "" {
		u = n.url + "/v1/db/" + db + "/bx"
	}
	st, b, _ := req(t, "POST", u, key, raw, "Content-Type", "application/json")
	var o bxOut
	json.Unmarshal(b, &o)
	return st, o, string(b)
}

func cell(t *testing.T, o bxOut, row int, col string) string {
	t.Helper()
	for i, c := range o.Columns {
		if c == col {
			return string(o.Rows[row][i])
		}
	}
	t.Fatalf("no column %q in %v", col, o.Columns)
	return ""
}

func seedPlayers(t *testing.T, n *node) {
	t.Helper()
	putPlayerFull := func(id int, name, email string, level int) {
		body := fmt.Sprintf(`[ {Name[]} = %q, {Email[]} = %q, {Level[]} = %d, {Health[]} = 10 ]`, name, email, level)
		if st, b, _ := req(t, "PUT", fmt.Sprintf("%s/v1/path/players.red-xai.db:Player[ID=%d]", n.url, id), n.key, []byte(body)); st != 200 {
			t.Fatalf("seed player %d: %d %s", id, st, b)
		}
	}
	putPlayerFull(1, "Ann", "ann@x.test", 30)
	putPlayerFull(2, "Bob", "bob@x.test", 5)
	putPlayerFull(3, "Cy", "cy@x.test", 12)
	if st, b, _ := req(t, "PUT", n.url+"/v1/path/guilds.red-xai.db:Guild[ID=10]", n.key, []byte(`[ {Title[]} = "Dragons" ]`)); st != 200 {
		t.Fatalf("seed guild: %d %s", st, b)
	}
}

func TestBXEndpointBasics(t *testing.T) {
	n := startFull(t, engineadapter.Config{}, nil)
	seedPlayers(t, n)

	st, o, raw := bx(t, n, n.key, "", `{Get[]} = players:Player[Level >= $min] -> [Name, Level], Sort = Name`, bxp{"min": 10})
	if st != 200 || o.Kind != "get" || o.Count != 2 || cell(t, o, 0, "Name") != `"Ann"` || cell(t, o, 1, "Name") != `"Cy"` || cell(t, o, 0, "Level") != "30" {
		t.Fatalf("get: %d %s", st, raw)
	}
	if len(o.Paths) != 2 || o.Paths[0] != "players.red-xai.db:Player[ID=1]" {
		t.Fatalf("paths: %v", o.Paths)
	}
	// the per-database route is the same engine; aggregates
	if st, o, raw := bx(t, n, n.key, "default", `{Get[]} = players:Player[ID=*] -> [n = Count(), top = Max(Level), total = Sum(Level)]`); st != 200 || o.Count != 1 ||
		cell(t, o, 0, "n") != "3" || cell(t, o, 0, "top") != "30" || cell(t, o, 0, "total") != "47" {
		t.Fatalf("aggregate: %d %s", st, raw)
	}
	// writes
	if st, o, raw := bx(t, n, n.key, "", `{Add[]} = players:Player[ID=4] = [ {Name[]} = $name, {Email[]} = $email, {Level[]} = $lvl ]`,
		bxp{"name": "Di", "email": "di@x.test", "lvl": 1}); st != 200 || o.Affected != 1 || o.Kind != "add" {
		t.Fatalf("add: %d %s", st, raw)
	}
	if st, o, raw := bx(t, n, n.key, "", `{Set[]} = players:Player[ID=$id].Level = Level + 1`, bxp{"id": 4}); st != 200 || o.Affected != 1 {
		t.Fatalf("set: %d %s", st, raw)
	}
	if _, b, _ := req(t, "GET", n.url+"/v1/path/players.red-xai.db:Player[ID=4].Level", n.key, nil); !strings.Contains(string(b), "2") {
		t.Fatalf("bx write is visible through REST: %s", b)
	}
	if st, _, raw := bx(t, n, n.key, "", `{Add[]} = players:Player[ID=4] = [ {Name[]} = "dup" ]`); st != 409 {
		t.Fatalf("duplicate add should be 409: %d %s", st, raw)
	}
	if st, o, raw := bx(t, n, n.key, "", `{Delete[]} = players:Player[ID=4]`); st != 200 || o.Affected != 1 {
		t.Fatalf("delete: %d %s", st, raw)
	}
	if st, _, _ := req(t, "GET", n.url+"/v1/path/players.red-xai.db:Player[ID=4]", n.key, nil); st != 404 {
		t.Fatal("deleted record must be 404")
	}
	// transactions: all or nothing, one nested result per command
	st, o, raw = bx(t, n, n.key, "", `{Tx[]} = [
		{Require[]} = players:Player[ID=1, Level >= 30],
		{Set[]} = players:Player[ID=1].Level = Level - 5,
		{Set[]} = players:Player[ID=2].Level = Level + 5
	]`)
	if st != 200 || o.Kind != "tx" || len(o.Results) != 3 || o.Results[1].Affected != 1 {
		t.Fatalf("tx: %d %s", st, raw)
	}
	st, _, raw = bx(t, n, n.key, "", `{Tx[]} = [
		{Set[]} = players:Player[ID=1].Level = 1000,
		{Require[]} = players:Player[ID=1, Level < 10]
	]`)
	if st != 409 && st != 400 {
		t.Fatalf("failing tx should be refused: %d %s", st, raw)
	}
	if _, b, _ := req(t, "GET", n.url+"/v1/path/players.red-xai.db:Player[ID=1].Level", n.key, nil); !strings.Contains(string(b), "25") {
		t.Fatalf("a failed tx must roll back: %s", b)
	}
	// a new file is created by naming it in full
	if st, o, raw := bx(t, n, n.key, "", `{Add[]} = "arena.red-xai.db":Match[ID=1] = [ {Score[]} = 3 ]`); st != 200 || o.Affected != 1 {
		t.Fatalf("add into a new file: %d %s", st, raw)
	}
	if st, o, raw := bx(t, n, n.key, "", `{Get[]} = arena:Match[1] -> Score`); st != 200 || cell(t, o, 0, "Score") != "3" {
		t.Fatalf("read it back by its short name: %d %s", st, raw)
	}
	// errors carry line and column
	if st, _, raw := bx(t, n, n.key, "", `{Get[]} = players:Player[Level >]`); st != 400 || !strings.Contains(raw, "at 1:") {
		t.Fatalf("syntax error: %d %s", st, raw)
	}
	if st, _, raw := bx(t, n, n.key, "", `fetch Name of players`); st != 400 {
		t.Fatalf("foreign syntax: %d %s", st, raw)
	}
	if st, _, raw := bx(t, n, n.key, "", `{Get[]} = nosuch:Thing -> Name`); st != 404 && st != 403 {
		t.Fatalf("unknown file: %d %s", st, raw)
	}
	if st, _, raw := bx(t, n, n.key, "", `{Get[]} = players:Player[Level > $min] -> Name`); st != 400 {
		t.Fatalf("missing parameter: %d %s", st, raw)
	}
	if st, _, raw := bx(t, n, n.key, "", `{Delete[]} = players:Player`); st != 400 {
		t.Fatalf("delete without a filter is refused: %d %s", st, raw)
	}
	if st, _, raw := req(t, "POST", n.url+"/v1/bx", n.key, []byte(`{"q":"{Get[]} = players:Player[1]","params":[1]}`), "Content-Type", "application/json"); st != 400 {
		t.Fatalf("params must be an object: %d %s", st, raw)
	}
	// injection stays a value, and a hostile value cannot add a command
	if st, o, raw := bx(t, n, n.key, "", `{Get[]} = players:Player[Name = $n] -> Name`, bxp{"n": `x" ] {Delete[]} = players:Player[ID=*] ["`}); st != 200 || o.Count != 0 {
		t.Fatalf("param injection: %d %s", st, raw)
	}
	if st, o, _ := bx(t, n, n.key, "", `{Get[]} = players:Player[ID=*] -> ID`); st != 200 || o.Count != 3 {
		t.Fatalf("records survived the injection attempt: %d", o.Count)
	}
	if st, _, raw := bx(t, n, n.key, "", `{Get[]} = players:Player[ID=*] -> Name {Delete[]} = players:Player[ID=*]`); st != 400 {
		t.Fatalf("two commands in one request: %d %s", st, raw)
	}
	// a plain text body works too; method and auth checks
	if st, b, _ := req(t, "POST", n.url+"/v1/bx", n.key, []byte(`{Get[]} = players:Player[1] -> Name`)); st != 200 || !strings.Contains(string(b), "Ann") {
		t.Fatalf("text body: %d %s", st, b)
	}
	if st, _, _ := req(t, "GET", n.url+"/v1/bx", n.key); st != 405 {
		t.Fatalf("GET bx: %d", st)
	}
	if st, _, _ := req(t, "POST", n.url+"/v1/bx", "", []byte(`{Get[]} = players:Player[1]`)); st != 401 {
		t.Fatalf("no key: %d", st)
	}
	// the old route is gone
	if st, _, _ := req(t, "POST", n.url+"/v1/sq"+"l", n.key, []byte(`{Get[]} = players:Player[1]`)); st != 404 {
		t.Fatalf("removed route: %d", st)
	}
	// a Watch cannot be run over POST
	if st, _, raw := bx(t, n, n.key, "", `{Watch[]} = players:Player[Level > 3]`); st != 400 || !strings.Contains(raw, "bx/watch") {
		t.Fatalf("watch over POST: %d %s", st, raw)
	}
	// the path query is still there next to BoxQL
	if st, b, _ := req(t, "POST", n.url+"/v1/query", n.key, []byte("players.red-xai.db:Player[ID=*].Name")); st != 200 || !strings.Contains(string(b), "Ann") {
		t.Fatalf("path query: %d %s", st, b)
	}
}

func TestBXScopesAndPrefixKeys(t *testing.T) {
	n := startFull(t, engineadapter.Config{}, nil)
	seedPlayers(t, n)
	ro := mkKey(t, n, "read", "default", "")
	if st, _, raw := bx(t, n, ro, "", `{Get[]} = players:Player[ID=*] -> Name`); st != 200 {
		t.Fatalf("read key get: %d %s", st, raw)
	}
	for _, q := range []string{
		`{Add[]} = players:Player[ID=9] = [ {Name[]} = "x" ]`,
		`{Set[]} = players:Player[1].Level = 1`,
		`{Delete[]} = players:Player[1]`,
		`{Tx[]} = [ {Get[]} = players:Player[1], {Set[]} = players:Player[1].Level = 1 ]`,
	} {
		if st, _, raw := bx(t, n, ro, "", q); st != 403 {
			t.Fatalf("read key must not write (%s): %d %s", q, st, raw)
		}
	}
	if st, o, _ := bx(t, n, ro, "", `{Explain[]} = [ {Set[]} = players:Player[1].Level = 1 ]`); st != 403 && !(st == 200 && o.Kind == "explain") {
		t.Fatalf("explain of a write by a read key: %d", st)
	}
	if _, b, _ := req(t, "GET", n.url+"/v1/path/players.red-xai.db:Player[ID=1].Level", n.key, nil); !strings.Contains(string(b), "30") {
		t.Fatalf("a refused write changed data: %s", b)
	}
	// wrong database
	other := mkKey(t, n, "write", "other", "")
	if st, _, _ := bx(t, n, other, "", `{Get[]} = players:Player[ID=*] -> Name`); st != 403 {
		t.Fatalf("key for another db: %d", st)
	}
	// prefix keys: file level and box level work, other files do not, record-id prefixes are refused
	fk := mkKey(t, n, "read", "default", "players.red-xai.db:")
	if st, o, raw := bx(t, n, fk, "", `{Get[]} = players:Player[ID=*] -> Name`); st != 200 || o.Count != 3 {
		t.Fatalf("file-prefix key: %d %s", st, raw)
	}
	if st, _, raw := bx(t, n, fk, "", `{Get[]} = guilds:Guild[ID=*] -> Title`); st != 403 {
		t.Fatalf("file-prefix key must not read guilds: %d %s", st, raw)
	}
	if st, _, raw := bx(t, n, fk, "", `{Get[]} = Guild[ID=*] -> Title`); st != 403 && st != 404 {
		t.Fatalf("a bare box name must not reach a file outside the prefix: %d %s", st, raw)
	}
	bk := mkKey(t, n, "write", "default", "players.red-xai.db:Player")
	if st, o, raw := bx(t, n, bk, "", `{Set[]} = players:Player[1].Level = 31`); st != 200 || o.Affected != 1 {
		t.Fatalf("box-prefix key write: %d %s", st, raw)
	}
	if st, _, raw := bx(t, n, bk, "", `{Get[]} = guilds:Guild[ID=*] -> Title`); st != 403 {
		t.Fatalf("box-prefix key vs guilds: %d %s", st, raw)
	}
	if st, _, raw := bx(t, n, bk, "", `{Tx[]} = [ {Set[]} = players:Player[1].Level = 5, {Set[]} = guilds:Guild[10].Title = "x" ]`); st != 403 {
		t.Fatalf("tx reaching outside the prefix: %d %s", st, raw)
	}
	if _, b, _ := req(t, "GET", n.url+"/v1/path/players.red-xai.db:Player[ID=1].Level", n.key, nil); !strings.Contains(string(b), "31") {
		t.Fatalf("a refused tx must leave no trace: %s", b)
	}
	ik := mkKey(t, n, "read", "default", "players.red-xai.db:Player[ID=1]")
	if st, _, raw := bx(t, n, ik, "", `{Get[]} = players:Player[ID=*] -> Name`); st != 403 {
		t.Fatalf("record-id prefix cannot be expressed: %d %s", st, raw)
	}
	// field prefix: only that field
	flk := mkKey(t, n, "read", "default", "players.red-xai.db:Player.Name")
	if st, o, raw := bx(t, n, flk, "", `{Get[]} = players:Player[ID=*] -> Name, Sort = Name`); st == 200 {
		if o.Count != 3 {
			t.Fatalf("field prefix get: %s", raw)
		}
	}
	if st, _, raw := bx(t, n, flk, "", `{Get[]} = players:Player[ID=*] -> Email`); st == 200 {
		t.Fatalf("field-prefix key read Email: %s", raw)
	}
}

func TestBXUsesIndexesAndKeepsThemCurrent(t *testing.T) {
	n := startFull(t, engineadapter.Config{}, nil)
	for i := 1; i <= 30; i++ {
		putPlayer(t, n, i, fmt.Sprintf("p%02d", i), i, "bio")
	}
	if st, b, _ := req(t, "PUT", n.url+"/v1/db/default/idx/byname", n.key, []byte(idxDecl)); st != 200 {
		t.Fatalf("define idx: %d %s", st, b)
	}
	byName := func(name string) (int, bxOut, string) {
		return bx(t, n, n.key, "", `{Get[]} = players:Player[Name = $n] -> Name`, bxp{"n": name})
	}
	st, o, raw := byName("p07")
	if st != 200 || o.Count != 1 || !strings.HasPrefix(o.Access, "index:") {
		t.Fatalf("expected an index access path: %d %s", st, raw)
	}
	if st, o, raw := bx(t, n, n.key, "", `{Explain[]} = [ {Get[]} = players:Player[Name = $n] -> Name ]`, bxp{"n": "p07"}); st != 200 || !strings.Contains(strings.Join(o.Plan, "\n"), "idx PlayerByName") {
		t.Fatalf("explain: %d %s", st, raw)
	}
	// writes through BoxQL and REST both keep the planner's indexes current
	if st, _, raw := bx(t, n, n.key, "", `{Set[]} = players:Player[7].Name = $n`, bxp{"n": "renamed"}); st != 200 {
		t.Fatalf("set: %d %s", st, raw)
	}
	putPlayer(t, n, 31, "p31", 31, "bio")
	if _, o, raw := byName("p07"); o.Count != 0 {
		t.Fatalf("stale index hit: %s", raw)
	}
	if _, o, raw := byName("renamed"); o.Count != 1 || !strings.HasPrefix(o.Access, "index:") {
		t.Fatalf("renamed via index: %s", raw)
	}
	if _, o, raw := byName("p31"); o.Count != 1 {
		t.Fatalf("REST write after the planner opened: %s", raw)
	}
	// a rolled-back Tx leaves the index as it was
	if st, _, _ := bx(t, n, n.key, "", `{Tx[]} = [ {Set[]} = players:Player[8].Name = "ghost", {Require[]} = players:Player[ID=8, Level > 1000] ]`); st == 200 {
		t.Fatal("tx should fail")
	}
	if _, o, raw := byName("ghost"); o.Count != 0 {
		t.Fatalf("index kept a rolled-back value: %s", raw)
	}
	if _, o, raw := byName("p08"); o.Count != 1 {
		t.Fatalf("index lost the restored value: %s", raw)
	}
	// dropping the set falls back to a scan
	if st, _, _ := req(t, "DELETE", n.url+"/v1/db/default/idx/byname", n.key, nil); st != 200 {
		t.Fatal("drop idx")
	}
	if _, o, raw := byName("p31"); o.Count != 1 || strings.HasPrefix(o.Access, "index:") {
		t.Fatalf("after drop: %s", raw)
	}
}

// ---- policy ----

const guestPolicy = `{Role[1]} = [ {Name[]} = "guest" ];
{Rule[1]} = [
    {Effect[]}   = "deny",
    {Who[]}      = ;["role:guest"]:,
    {Actions[]}  = "*",
    {Resource[]} = "players.red-xai.db:Player.Email"
];
{Rule[2]} = [
    {Effect[]}   = "deny",
    {Who[]}      = ;["role:guest"]:,
    {Actions[]}  = "*",
    {Resource[]} = "guilds.red-xai.db"
];
`

func TestPolicyBuiltFromKeysAndEnforcedEverywhere(t *testing.T) {
	n := startFull(t, engineadapter.Config{}, nil)
	seedPlayers(t, n)
	D := n.url + "/v1/db/default"
	guest := mkKeyFull(t, n, map[string]interface{}{"scope": "write", "db": "default", "roles": []string{"guest"}})
	plain := mkKey(t, n, "write", "default", "")

	if st, b, _ := req(t, "PUT", D+"/sec", n.key, []byte("{Rule[1]} = [ {Effect[]} = ")); st != 400 {
		t.Fatalf("bad policy: %d %s", st, b)
	}
	if st, b, _ := req(t, "PUT", D+"/sec", n.key, []byte(`{Scope[1]} = [ {Name[]} = "rxkey.write.deadbeef", {Actions[]} = "read", {Resource[]} = "*" ];`)); st != 400 {
		t.Fatalf("reserved scope name: %d %s", st, b)
	}
	if st, b, _ := req(t, "PUT", D+"/sec", guest, []byte(guestPolicy)); st != 403 {
		t.Fatalf("non-admin define: %d %s", st, b)
	}
	if st, b, _ := req(t, "PUT", D+"/sec", n.key, []byte(guestPolicy)); st != 200 {
		t.Fatalf("define: %d %s", st, b)
	}
	if st, b, _ := req(t, "GET", D+"/sec", n.key, nil); st != 200 || !strings.Contains(string(b), `"loaded":true`) || !strings.Contains(string(b), "guest") || !strings.Contains(string(b), "Rule[1]") {
		t.Fatalf("sec info for admin: %d %s", st, b)
	}
	if _, b, _ := req(t, "GET", D+"/sec", plain, nil); strings.Contains(string(b), "Rule[1]") {
		t.Fatalf("policy source shown to a non-admin: %s", b)
	}

	// BoxQL (engine-side enforcement): the denied field is masked, the denied file is refused
	st, o, raw := bx(t, n, guest, "", `{Get[]} = players:Player[ID=*] -> *, Sort = Name`)
	if st != 200 || o.Count != 3 || strings.Contains(raw, "ann@x.test") || strings.Contains(raw, "Email") || cell(t, o, 0, "Name") != `"Ann"` {
		t.Fatalf("guest Get -> * must drop Email: %d %s", st, raw)
	}
	if st, _, raw := bx(t, n, guest, "", `{Get[]} = players:Player[ID=*] -> Email`); st != 403 || strings.Contains(raw, "x.test") {
		t.Fatalf("explicitly asking for a denied field: %d %s", st, raw)
	}
	if st, _, raw := bx(t, n, guest, "", `{Get[]} = players:Player[ID=*] -> Name, Sort = Email`); st != 403 {
		t.Fatalf("ordering by a denied field: %d %s", st, raw)
	}
	if st, _, raw := bx(t, n, guest, "", `{Get[]} = guilds:Guild[ID=*] -> Title`); st != 403 {
		t.Fatalf("guest guilds: %d %s", st, raw)
	}
	if st, _, raw := bx(t, n, guest, "", `{Set[]} = players:Player[1].Email = "x"`); st != 403 {
		t.Fatalf("guest write to Email: %d %s", st, raw)
	}
	if st, o, raw := bx(t, n, plain, "", `{Get[]} = players:Player[1] -> Email`); st != 200 || cell(t, o, 0, "Email") != `"ann@x.test"` {
		t.Fatalf("a key without the role sees Email: %d %s", st, raw)
	}
	// REST (host-side enforcement)
	P := n.url + "/v1/path/"
	st, b, _ := req(t, "GET", P+"players.red-xai.db:Player[ID=1]", guest, nil)
	if st != 200 || strings.Contains(string(b), "ann@x.test") || !strings.Contains(string(b), "Ann") {
		t.Fatalf("record read must be redacted: %d %s", st, b)
	}
	if st, b, _ := req(t, "GET", P+"players.red-xai.db:Player[ID=1]", plain, nil); st != 200 || !strings.Contains(string(b), "ann@x.test") {
		t.Fatalf("plain key sees the full record: %d %s", st, b)
	}
	if st, _, _ := req(t, "GET", P+"players.red-xai.db:Player[ID=1].Email", guest, nil); st != 403 {
		t.Fatalf("denied field read: %d", st)
	}
	if st, _, _ := req(t, "GET", P+"guilds.red-xai.db:Guild[ID=10]", guest, nil); st != 403 {
		t.Fatalf("denied file read: %d", st)
	}
	if st, _, _ := req(t, "PUT", P+"players.red-xai.db:Player[ID=1].Email", guest, []byte(`"evil"`)); st != 403 {
		t.Fatalf("denied field write: %d", st)
	}
	if st, _, _ := req(t, "PUT", P+"players.red-xai.db:Player[ID=5]", guest, []byte(`[ {Name[]} = "E", {Email[]} = "e@x" ]`)); st != 403 {
		t.Fatalf("a record write containing a denied field: %d", st)
	}
	if st, _, _ := req(t, "PUT", P+"players.red-xai.db:Player[ID=5]", guest, []byte(`[ {Name[]} = "E" ]`)); st != 200 {
		t.Fatalf("an allowed record write: %d", st)
	}
	if st, _, _ := req(t, "DELETE", P+"guilds.red-xai.db:Guild[ID=10]", guest, nil); st != 403 {
		t.Fatalf("denied delete: %d", st)
	}
	// raw path queries return whole records: admin-only while a policy exists
	if st, _, _ := req(t, "POST", n.url+"/v1/query", guest, []byte("players.red-xai.db:Player[ID=*].Email")); st != 403 {
		t.Fatalf("path query under a policy: %d", st)
	}
	if st, b, _ := req(t, "POST", n.url+"/v1/query", n.key, []byte("players.red-xai.db:Player[ID=*].Email")); st != 200 || !strings.Contains(string(b), "ann@x.test") {
		t.Fatalf("admin path query: %d %s", st, b)
	}
	// resolve is redacted as well
	if st, b, _ := req(t, "GET", P+"players.red-xai.db:Player[ID=1]?resolve=1", guest, nil); st != 200 || strings.Contains(string(b), "ann@x.test") {
		t.Fatalf("resolve leaked: %d %s", st, b)
	}
	// the ceiling: a read-only key cannot be widened by the policy file
	ro := mkKey(t, n, "read", "default", "")
	if st, _, _ := bx(t, n, ro, "", `{Set[]} = players:Player[1].Level = 99`); st != 403 {
		t.Fatalf("read key write: %d", st)
	}
	// removing the policy restores the unfiltered view
	if st, _, _ := req(t, "DELETE", D+"/sec", n.key, nil); st != 200 {
		t.Fatal("remove policy")
	}
	if st, o, _ := bx(t, n, guest, "", `{Get[]} = players:Player[1] -> Email`); st != 200 || cell(t, o, 0, "Email") != `"ann@x.test"` {
		t.Fatalf("after removing the policy: %d", st)
	}
}

func TestHandPlacedSecFileLoadsAndBrokenOneRefusesToOpen(t *testing.T) {
	n := startFull(t, engineadapter.Config{}, func(dir string) {
		if err := os.WriteFile(filepath.Join(dir, "guests.red-xai-sec"), []byte(guestPolicy), 0o644); err != nil {
			t.Fatal(err)
		}
	})
	seedPlayers(t, n)
	guest := mkKeyFull(t, n, map[string]interface{}{"scope": "read", "db": "default", "roles": []string{"guest"}})
	if st, _, raw := bx(t, n, guest, "", `{Get[]} = players:Player[1] -> Email`); st != 403 {
		t.Fatalf("hand-placed policy not applied: %d %s", st, raw)
	}
	// a policy that does not parse: the database must not open (never fall back to "no policy")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.red-xai-sec"), []byte("{Rule[1]} = [ {Effect[]} = "), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := engineadapter.Opener(engineadapter.Config{})(dir, false); err == nil || !strings.Contains(err.Error(), "policy") {
		t.Fatalf("broken .red-xai-sec must refuse to open: %v", err)
	}
}

// ---- media ----

func pngBytes(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{uint8(x * 7), uint8(y * 9), 128, 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	// pad with ancillary-looking data so the file spans several ranges
	return buf.Bytes()
}

func wavBytes(seconds int) []byte {
	const rate = 8000
	data := make([]byte, rate*seconds)
	var b bytes.Buffer
	b.WriteString("RIFF")
	binary.Write(&b, binary.LittleEndian, uint32(36+len(data)))
	b.WriteString("WAVEfmt ")
	binary.Write(&b, binary.LittleEndian, uint32(16))
	binary.Write(&b, binary.LittleEndian, uint16(1))
	binary.Write(&b, binary.LittleEndian, uint16(1))
	binary.Write(&b, binary.LittleEndian, uint32(rate))
	binary.Write(&b, binary.LittleEndian, uint32(rate))
	binary.Write(&b, binary.LittleEndian, uint16(1))
	binary.Write(&b, binary.LittleEndian, uint16(8))
	b.WriteString("data")
	binary.Write(&b, binary.LittleEndian, uint32(len(data)))
	b.Write(data)
	return b.Bytes()
}

func TestMediaAPIRangeAndSniffing(t *testing.T) {
	n := startFull(t, engineadapter.Config{}, nil)
	M := n.url + "/v1/db/default/media/art"
	img := pngBytes(t, 16, 12)

	if st, b, _ := req(t, "PUT", M+"/file/hero.png?type=audio", n.key, img); st != 415 {
		t.Fatalf("declared audio but PNG bytes: %d %s", st, b)
	}
	if st, b, _ := req(t, "PUT", M+"/file/notes.txt", n.key, []byte("just text, not media")); st != 415 {
		t.Fatalf("text is not media: %d %s", st, b)
	}
	st, b, hd := req(t, "PUT", M+"/file/hero.png?type=image/png", n.key, img)
	if st != 201 {
		t.Fatalf("put: %d %s", st, b)
	}
	var meta struct {
		Name, Type, MIME, SHA256 string
		Size                     int64
		Width, Height            int
	}
	json.Unmarshal(b, &meta)
	if meta.Type != "image" || meta.MIME != "image/png" || meta.Width != 16 || meta.Height != 12 || meta.Size != int64(len(img)) || hd.Get("ETag") == "" {
		t.Fatalf("manifest: %s", b)
	}
	// whole file
	st, b, hd = req(t, "GET", M+"/file/hero.png", n.key, nil)
	if st != 200 || !bytes.Equal(b, img) || hd.Get("Content-Type") != "image/png" || hd.Get("Accept-Ranges") != "bytes" || hd.Get("ETag") != `"sha256-`+meta.SHA256+`"` {
		t.Fatalf("get: %d type=%s ranges=%s len=%d", st, hd.Get("Content-Type"), hd.Get("Accept-Ranges"), len(b))
	}
	// ranges
	st, b, hd = req(t, "GET", M+"/file/hero.png", n.key, nil, "Range", "bytes=8-23")
	if st != 206 || !bytes.Equal(b, img[8:24]) || hd.Get("Content-Range") != fmt.Sprintf("bytes 8-23/%d", len(img)) {
		t.Fatalf("range: %d %q cr=%s", st, b, hd.Get("Content-Range"))
	}
	st, b, hd = req(t, "GET", M+"/file/hero.png", n.key, nil, "Range", "bytes=-10")
	if st != 206 || !bytes.Equal(b, img[len(img)-10:]) {
		t.Fatalf("suffix range: %d", st)
	}
	st, b, _ = req(t, "GET", M+"/file/hero.png", n.key, nil, "Range", "bytes=5-")
	if st != 206 || !bytes.Equal(b, img[5:]) {
		t.Fatalf("open range: %d", st)
	}
	if st, _, hd = req(t, "GET", M+"/file/hero.png", n.key, nil, "Range", fmt.Sprintf("bytes=%d-", len(img)+5)); st != 416 || !strings.Contains(hd.Get("Content-Range"), fmt.Sprintf("*/%d", len(img))) {
		t.Fatalf("unsatisfiable: %d %s", st, hd.Get("Content-Range"))
	}
	if st, _, _ = req(t, "GET", M+"/file/hero.png", n.key, nil, "Range", "bytes=0-3", "If-Range", `"sha256-0000"`); st != 200 {
		t.Fatalf("stale If-Range gets the whole file: %d", st)
	}
	if st, b, _ = req(t, "GET", M+"/file/hero.png", n.key, nil, "Range", "bytes=0-3", "If-Range", hd.Get("ETag")); st != 200 && st != 206 {
		t.Fatalf("if-range: %d", st)
	}
	if st, _, _ = req(t, "GET", M+"/file/hero.png", n.key, nil, "If-None-Match", `"sha256-`+meta.SHA256+`"`); st != 304 {
		t.Fatalf("etag: %d", st)
	}
	st, b, hd = req(t, "HEAD", M+"/file/hero.png", n.key, nil)
	if st != 200 || len(b) != 0 || hd.Get("Content-Length") != fmt.Sprint(len(img)) {
		t.Fatalf("head: %d %v", st, hd)
	}
	// audio: duration
	wav := wavBytes(3)
	st, b, _ = req(t, "PUT", M+"/file/beep.wav", n.key, wav)
	var wm struct {
		Type       string
		DurationMS int64 `json:"duration_ms"`
	}
	json.Unmarshal(b, &wm)
	if st != 201 || wm.Type != "audio" || wm.DurationMS < 2900 || wm.DurationMS > 3100 {
		t.Fatalf("wav: %d %s", st, b)
	}
	// list / stat
	if st, b, _ = req(t, "GET", M, n.key, nil); st != 200 || !strings.Contains(string(b), "hero.png") || !strings.Contains(string(b), "beep.wav") {
		t.Fatalf("list: %d %s", st, b)
	}
	if st, b, _ = req(t, "GET", M+"/stat/hero.png", n.key, nil); st != 200 || !strings.Contains(string(b), "image/png") {
		t.Fatalf("stat: %d %s", st, b)
	}
	if st, b, _ = req(t, "GET", n.url+"/v1/db/default/media", n.key, nil); st != 200 || !strings.Contains(string(b), `"art"`) {
		t.Fatalf("libraries: %d %s", st, b)
	}
	// uploaded sha256 verification: wrong digest stores nothing
	if st, _, _ = req(t, "PUT", M+"/file/bad.png", n.key, img, "X-Redx-SHA256", strings.Repeat("0", 64)); st != 422 {
		t.Fatalf("checksum: %d", st)
	}
	if st, _, _ = req(t, "GET", M+"/stat/bad.png", n.key, nil); st != 404 {
		t.Fatal("rejected upload must not exist")
	}
	// the pack API cannot reach media manifests
	if st, _, _ = req(t, "GET", n.url+"/v1/db/default/pack/art-media/ls", n.key, nil); st != 404 {
		t.Fatalf("pack API must not see the media folder: %d", st)
	}
	// names and methods
	if st, _, _ = req(t, "GET", M+"/file/..%2Fescape", n.key, nil); st != 400 && st != 404 {
		t.Fatalf("path escape: %d", st)
	}
	if st, _, _ = req(t, "GET", M+"/file/nope.png", n.key, nil); st != 404 {
		t.Fatalf("missing: %d", st)
	}
	// scopes / prefix / policy
	ro := mkKey(t, n, "read", "default", "")
	if st, _, _ = req(t, "GET", M+"/file/hero.png", ro, nil); st != 200 {
		t.Fatalf("read key get: %d", st)
	}
	if st, _, _ = req(t, "PUT", M+"/file/x.png", ro, img); st != 403 {
		t.Fatalf("read key put: %d", st)
	}
	if st, _, _ = req(t, "DELETE", M+"/file/hero.png", ro, nil); st != 403 {
		t.Fatalf("read key delete: %d", st)
	}
	pk := mkKey(t, n, "read", "default", "art.red-xai-media:hero")
	if st, _, _ = req(t, "GET", M+"/file/hero.png", pk, nil); st != 200 {
		t.Fatalf("prefix key own item: %d", st)
	}
	if st, _, _ = req(t, "GET", M+"/file/beep.wav", pk, nil); st != 403 {
		t.Fatalf("prefix key other item: %d", st)
	}
	if _, b, _ = req(t, "GET", M, pk, nil); strings.Contains(string(b), "beep.wav") || !strings.Contains(string(b), "hero.png") {
		t.Fatalf("prefix key list must be filtered: %s", b)
	}
	if st, _, _ = req(t, "GET", M+"/fsck", ro, nil); st != 403 {
		t.Fatalf("fsck needs admin: %d", st)
	}
	if st, b, _ = req(t, "GET", M+"/fsck?deep=1", n.key, nil); st != 200 || !strings.Contains(string(b), `"ok":true`) {
		t.Fatalf("fsck: %d %s", st, b)
	}
	// delete
	if st, _, _ = req(t, "DELETE", M+"/file/hero.png", n.key, nil); st != 200 {
		t.Fatalf("delete: %d", st)
	}
	if st, _, _ = req(t, "GET", M+"/file/hero.png", n.key, nil); st != 404 {
		t.Fatalf("deleted: %d", st)
	}
	// a policy deny on the library file blocks it for that role
	if st, b, _ := req(t, "PUT", n.url+"/v1/db/default/sec", n.key, []byte(`{Role[1]} = [ {Name[]} = "guest" ]; {Rule[1]} = [ {Effect[]} = "deny", {Who[]} = ;["role:guest"]:, {Actions[]} = "*", {Resource[]} = "art.red-xai-media" ];`)); st != 200 {
		t.Fatalf("policy: %d %s", st, b)
	}
	guest := mkKeyFull(t, n, map[string]interface{}{"scope": "write", "db": "default", "roles": []string{"guest"}})
	if st, _, _ = req(t, "GET", M+"/file/beep.wav", guest, nil); st != 403 {
		t.Fatalf("policy deny on media: %d", st)
	}
	if st, _, _ = req(t, "GET", M+"/file/beep.wav", ro, nil); st != 200 {
		t.Fatalf("others unaffected: %d", st)
	}
}

// ---- scripts ----

const healScript = `{Script[1]} = [
    {Name[]}   = "heal",
    {Params[]} = ;["target", "amount"]:,
    {Uses[]}   = ;["db_get", "db_set"]:,
    {Source[]} = "let hp = db_get(target, \"Health\"); db_set(target, \"Health\", hp + amount); return hp + amount;"
];
{Script[2]} = [
    {Name[]}   = "peek_guild",
    {Params[]} = ;["target"]:,
    {Uses[]}   = ;["db_get"]:,
    {Source[]} = "return db_get(target, \"Title\");"
];
{Script[3]} = [
    {Name[]}   = "forever",
    {Params[]} = ;[]:,
    {Uses[]}   = ;[]:,
    {Limits[]} = [ {MaxSteps[]} = 5000 ],
    {Source[]} = "let i = 0; while (true) { i = i + 1; } return i;"
];
`

func TestCodeSandboxAllowedBoxesAndPolicy(t *testing.T) {
	n := startFull(t, engineadapter.Config{CodeAllowedBoxes: []string{"players.red-xai.db:Player"}}, nil)
	seedPlayers(t, n)
	D := n.url + "/v1/db/default"
	if st, b, _ := req(t, "PUT", D+"/code/file/game", n.key, []byte("{Script[1]} = [ {Name[]} = ")); st != 400 {
		t.Fatalf("bad code file: %d %s", st, b)
	}
	wr := mkKey(t, n, "write", "default", "")
	ro := mkKey(t, n, "read", "default", "")
	if st, b, _ := req(t, "PUT", D+"/code/file/game", wr, []byte(healScript)); st != 403 {
		t.Fatalf("only admin defines code: %d %s", st, b)
	}
	if st, b, _ := req(t, "PUT", D+"/code/file/game", n.key, []byte(healScript)); st != 200 {
		t.Fatalf("define code: %d %s", st, b)
	}
	if st, b, _ := req(t, "GET", D+"/code", ro, nil); st != 200 || !strings.Contains(string(b), "heal") || !strings.Contains(string(b), "db_set") {
		t.Fatalf("list scripts: %d %s", st, b)
	}
	run := func(key, script string, args ...interface{}) (int, map[string]interface{}, string) {
		body, _ := json.Marshal(map[string]interface{}{"args": args})
		st, b, _ := req(t, "POST", D+"/code/run/"+script, key, body, "Content-Type", "application/json")
		m := map[string]interface{}{}
		json.Unmarshal(b, &m)
		return st, m, string(b)
	}
	st, m, raw := run(wr, "heal", "players.red-xai.db:Player[ID=2]", 7)
	if st != 200 || m["value"] != float64(17) {
		t.Fatalf("heal: %d %s", st, raw)
	}
	if _, b, _ := req(t, "GET", n.url+"/v1/path/players.red-xai.db:Player[ID=2].Health", n.key, nil); !strings.Contains(string(b), "17") {
		t.Fatalf("script write not visible: %s", b)
	}
	if st, _, raw := run(ro, "heal", "players.red-xai.db:Player[ID=2]", 1); st != 403 {
		t.Fatalf("read key must not run scripts: %d %s", st, raw)
	}
	// outside AllowedBoxes: refused although the key could read guilds
	if st, _, raw := run(n.key, "peek_guild", "guilds.red-xai.db:Guild[ID=10]"); st == 200 {
		t.Fatalf("script read a box outside AllowedBoxes: %s", raw)
	}
	// a script that uses a host function it did not declare is rejected when the file is defined
	if st, b, _ := req(t, "PUT", D+"/code/file/sneaky", n.key, []byte(`{Script[4]} = [
    {Name[]}   = "sneaky",
    {Params[]} = ;["target"]:,
    {Uses[]}   = ;["db_get"]:,
    {Source[]} = "db_set(target, \"Health\", 0); return 1;"
];
`)); st != 400 || !strings.Contains(string(b), "Uses") {
		t.Fatalf("undeclared host function: %d %s", st, b)
	}
	// limits
	t0 := time.Now()
	if st, _, raw := run(wr, "forever"); st != 400 || !strings.Contains(raw, "limit") || time.Since(t0) > 5*time.Second {
		t.Fatalf("runaway script: %d %s (%v)", st, raw, time.Since(t0))
	}
	if st, _, _ := run(wr, "nosuch"); st != 404 {
		t.Fatalf("unknown script: %d", st)
	}
	// the policy applies to what a script touches: deny the Health field to role guest
	pol := `{Role[1]} = [ {Name[]} = "guest" ]; {Rule[1]} = [ {Effect[]} = "deny", {Who[]} = ;["role:guest"]:, {Actions[]} = "write", {Resource[]} = "players.red-xai.db:Player.Health" ];`
	if st, b, _ := req(t, "PUT", D+"/sec", n.key, []byte(pol)); st != 200 {
		t.Fatalf("policy: %d %s", st, b)
	}
	guest := mkKeyFull(t, n, map[string]interface{}{"scope": "write", "db": "default", "roles": []string{"guest"}})
	if st, _, raw := run(guest, "heal", "players.red-xai.db:Player[ID=2]", 1); st != 403 {
		t.Fatalf("policy must stop the script's write: %d %s", st, raw)
	}
	if st, _, raw := run(wr, "heal", "players.red-xai.db:Player[ID=2]", 1); st != 200 {
		t.Fatalf("others still run it: %d %s", st, raw)
	}
	// a database without AllowedBoxes: scripts cannot touch any record
	n2 := startFull(t, engineadapter.Config{}, nil)
	seedPlayers(t, n2)
	if st, b, _ := req(t, "PUT", n2.url+"/v1/db/default/code/file/game", n2.key, []byte(healScript)); st != 200 {
		t.Fatalf("define: %d %s", st, b)
	}
	body, _ := json.Marshal(map[string]interface{}{"args": []interface{}{"players.red-xai.db:Player[ID=2]", 1}})
	if st, b, _ := req(t, "POST", n2.url+"/v1/db/default/code/run/heal", n2.key, body, "Content-Type", "application/json"); st == 200 {
		t.Fatalf("empty AllowedBoxes must deny record access: %s", b)
	}
	// removing the file removes the scripts
	if st, _, _ := req(t, "DELETE", D+"/code/file/game", n.key, nil); st != 200 {
		t.Fatal("rm code")
	}
	if st, _, _ := run(wr, "heal", "players.red-xai.db:Player[ID=2]", 1); st != 404 {
		t.Fatalf("after removal: %d", st)
	}
}

// ---- encryption (master key from a key file) ----

func TestMasterKeyFileAndEncryptedPacks(t *testing.T) {
	kf := filepath.Join(t.TempDir(), "master.key")
	if err := engineadapter.GenerateKeyFile(kf, "main-2026"); err != nil {
		t.Fatal(err)
	}
	if err := engineadapter.GenerateKeyFile(kf, "main-2026"); err == nil {
		t.Fatal("GenerateKeyFile must not overwrite")
	}
	ring, err := engineadapter.LoadKeyFile(kf)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(ring.IDs()) != "[main-2026]" {
		t.Fatalf("ids %v", ring.IDs())
	}
	if runtime.GOOS != "windows" { // Windows has no Unix permission bits
		if err := os.Chmod(kf, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := engineadapter.LoadKeyFile(kf); err == nil || !strings.Contains(err.Error(), "readable by group or others") {
			t.Fatalf("a world-readable key file must be refused: %v", err)
		}
		os.Chmod(kf, 0o600)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(kf), "short.key"), []byte("main abcd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := engineadapter.LoadKeyFile(filepath.Join(filepath.Dir(kf), "short.key")); err == nil || strings.Contains(err.Error(), "abcd") {
		t.Fatalf("bad key file must fail without echoing it: %v", err)
	}

	n := startFull(t, engineadapter.Config{Keyring: ring}, nil)
	D := n.url + "/v1/db/default"
	rule := `{Encrypt[1]} = [ {File[]} = "vault*", {Key[]} = "main-2026" ];`
	if st, b, _ := req(t, "PUT", D+"/sec", n.key, []byte(rule)); st != 200 {
		t.Fatalf("policy: %d %s", st, b)
	}
	secret := bytes.Repeat([]byte("TOP-SECRET-LAUNCH-CODES-0451 "), 5000)
	if st, b, _ := req(t, "PUT", D+"/pack/vault/file/plans/launch.txt", n.key, secret); st != 201 || !strings.Contains(string(b), `"encrypted":true`) {
		t.Fatalf("put into encrypted pack: %d %s", st, b)
	}
	st, b, hd := req(t, "GET", D+"/pack/vault/file/plans/launch.txt", n.key, nil)
	if st != 200 || !bytes.Equal(b, secret) || hd.Get("X-Redx-Encrypted") != "1" || hd.Get("Accept-Ranges") != "none" {
		t.Fatalf("decrypted download: %d len=%d hdr=%v", st, len(b), hd)
	}
	if st, b, _ := req(t, "GET", D+"/pack/vault/file/plans/launch.txt", n.key, nil, "Range", "bytes=0-9"); st != 200 || len(b) != len(secret) {
		t.Fatalf("ranges are not honoured on encrypted packs (whole file): %d %d", st, len(b))
	}
	// at rest: no plaintext anywhere under the pack folder
	root := filepath.Join(n.h.Cfg.DataDir, "dbs", "default", "vault.red-xai-pack")
	found := 0
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			found++
			if data, _ := os.ReadFile(p); bytes.Contains(data, []byte("TOP-SECRET")) {
				t.Fatalf("plaintext found at rest in %s", p)
			}
		}
		return nil
	})
	if found == 0 {
		t.Fatal("pack files not found")
	}
	// an unencrypted pack is unaffected
	if st, _, _ := req(t, "PUT", D+"/pack/plain/file/a.txt", n.key, secret); st != 201 {
		t.Fatal("plain pack")
	}
	if _, b, _ := req(t, "GET", D+"/pack/plain/stat/a.txt", n.key, nil); strings.Contains(string(b), "encrypted") {
		t.Fatalf("plain pack marked encrypted: %s", b)
	}
	// a plaintext file in a pack that is now under a rule is refused, never served as if authentic
	if st, _, _ := req(t, "PUT", D+"/sec", n.key, []byte(`{Encrypt[1]} = [ {File[]} = "vault*", {Key[]} = "main-2026" ]; {Encrypt[2]} = [ {File[]} = "plain*", {Key[]} = "main-2026" ];`)); st != 200 {
		t.Fatal("policy 2")
	}
	if st, _, _ := req(t, "GET", D+"/pack/plain/file/a.txt", n.key, nil); st != 500 {
		t.Fatalf("plaintext under an Encrypt rule must fail closed: %d", st)
	}
	// media libraries cannot be encrypted: refused when a rule names them
	if st, _, _ := req(t, "PUT", D+"/sec", n.key, []byte(`{Encrypt[1]} = [ {File[]} = "*.red-xai-media", {Key[]} = "main-2026" ];`)); st != 200 {
		t.Fatal("policy 3")
	}
	if st, _, _ := req(t, "PUT", D+"/media/art/file/h.png?type=image", n.key, pngBytes(t, 4, 4)); st != 501 {
		t.Fatalf("media under an Encrypt rule must be refused: %d", st)
	}
	// a node without the master key refuses encrypted packs (503), never stores plaintext
	n2 := startFull(t, engineadapter.Config{}, nil)
	if st, _, _ := req(t, "PUT", n2.url+"/v1/db/default/sec", n2.key, []byte(rule)); st != 200 {
		t.Fatal("policy on n2")
	}
	if st, _, _ := req(t, "PUT", n2.url+"/v1/db/default/pack/vault/file/x.txt", n2.key, []byte("x")); st != 503 {
		t.Fatalf("no master key: %d", st)
	}
	if _, err := os.Stat(filepath.Join(n2.h.Cfg.DataDir, "dbs", "default", "vault.red-xai-pack")); err == nil {
		t.Fatal("no pack folder may be created when encryption is impossible")
	}
	// tamper with the ciphertext at rest: the download must fail, never deliver altered bytes
	var biggest string
	var size int64
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() && fi.Size() > size {
			biggest, size = p, fi.Size()
		}
		return nil
	})
	data, _ := os.ReadFile(biggest)
	data[len(data)/2] ^= 0xff
	if err := os.WriteFile(biggest, data, 0o600); err != nil {
		t.Fatal(err)
	}
	st, b, _ = req(t, "GET", D+"/pack/vault/file/plans/launch.txt", n.key, nil)
	if st == 200 && bytes.Equal(b, secret) {
		t.Fatal("tampered ciphertext was served as if intact")
	}
	if st == 200 {
		t.Logf("note: tamper surfaced mid-stream (status already sent), %d bytes", len(b))
	}
}

// ---- host quirks found by the SDK tests ----

func TestAbsentPathIs404AndBareSubscribeIsAnError(t *testing.T) {
	n := startFull(t, engineadapter.Config{}, nil)
	P := n.url + "/v1/path/"
	// .red-xai.db: absent
	for _, p := range []string{
		"nofile.red-xai.db:Box[ID=1].X",
		"sess.red-xai-db-qs:Q[ID=9].Otp",
		"chat.red-xai-db-qs-ls:Msg[ID=9].Text",
	} {
		if st, b, _ := req(t, "GET", P+p, n.key, nil); st != 404 {
			t.Fatalf("absent %s must be 404, got %d %s", p, st, b)
		}
	}
	// qs: present, then expired, then stored NELL
	if st, _, _ := req(t, "PUT", P+"sess.red-xai-db-qs:Q[ID=1].Otp?", n.key, []byte(`{"value":"abc","ttl_seconds":1}`), "Content-Type", "application/json"); st != 200 {
		t.Fatal("put qs")
	}
	if st, b, _ := req(t, "GET", P+"sess.red-xai-db-qs:Q[ID=1].Otp", n.key, nil); st != 200 || !strings.Contains(string(b), "abc") {
		t.Fatalf("qs get: %d %s", st, b)
	}
	if st, _, _ := req(t, "PUT", P+"sess.red-xai-db-qs:Q[ID=2].Nothing", n.key, []byte(`{"value":null,"ttl_seconds":60}`), "Content-Type", "application/json"); st != 200 {
		t.Fatal("put NELL")
	}
	if st, b, _ := req(t, "GET", P+"sess.red-xai-db-qs:Q[ID=2].Nothing", n.key, nil); st != 200 || !strings.Contains(string(b), "NELL") {
		t.Fatalf("a stored NELL is a real value (200): %d %s", st, b)
	}
	time.Sleep(2300 * time.Millisecond)
	if st, b, _ := req(t, "GET", P+"sess.red-xai-db-qs:Q[ID=1].Otp", n.key, nil); st != 404 {
		t.Fatalf("expired must be 404: %d %s", st, b)
	}
	// subscribe: bare names are errors, not silently-closing streams
	for _, q := range []string{"", "?path=players", "?path=players.red-xai.db", "?path=:Box"} {
		st, b, _ := req(t, "GET", n.url+"/v1/subscribe"+q, n.key, nil)
		if st != 400 || !strings.Contains(string(b), "path") {
			t.Fatalf("subscribe%s: %d %s", q, st, b)
		}
	}
	// file: = every box of the file and really delivers
	c := wsDial(t, n.url+"/v1/subscribe?path=players.red-xai.db:", n.key)
	defer c.Close()
	go func() {
		time.Sleep(100 * time.Millisecond)
		req(t, "PUT", P+"players.red-xai.db:Player[ID=1].Name", n.key, []byte(`"Zed"`))
	}()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var ev host.Event
	if err := c.ReadJSON(&ev); err != nil || ev.Op != "set" || !strings.Contains(ev.Path, "Player[ID=1]") {
		t.Fatalf("file: subscription: %+v %v", ev, err)
	}
}

var _ = http.StatusOK
