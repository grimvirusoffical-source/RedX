package engineadapter_test

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"redx/host"
	"redx/host/engineadapter"
)

func watchURL(n *node, q string, params bxp) string {
	v := url.Values{"q": {q}}
	if params != nil {
		b, _ := json.Marshal(params)
		v.Set("params", string(b))
	}
	return n.url + "/v1/db/default/bx/watch?" + v.Encode()
}

func readWatch(c *websocket.Conn, d time.Duration) (host.Event, bool) {
	c.SetReadDeadline(time.Now().Add(d))
	var ev host.Event
	if err := c.ReadJSON(&ev); err != nil {
		return ev, false
	}
	return ev, true
}

func TestBXWatchDeliversMatchingChangesOnly(t *testing.T) {
	n := startFull(t, engineadapter.Config{}, nil)
	seedPlayers(t, n)
	ws := wsDial(t, watchURL(n, `{Watch[]} = players:Player[Level > $min]`, bxp{"min": 20}), n.key)
	time.Sleep(100 * time.Millisecond)

	// does not match the filter: Bob (5) goes to 6; another file changes; matches: Cy (12) goes to 40.
	// (A read timeout kills a websocket for good, so "not delivered" is proven by order: the first
	// event that arrives must be Cy's.)
	bx(t, n, n.key, "", `{Set[]} = players:Player[2].Level = 6`)
	if st, b, _ := req(t, "PUT", n.url+"/v1/path/guilds.red-xai.db:Guild[ID=10].Title", n.key, []byte(`"Wyverns"`)); st != 200 {
		t.Fatalf("put guild: %d %s", st, b)
	}
	bx(t, n, n.key, "", `{Set[]} = players:Player[3].Level = 40`)
	ev, ok := readWatch(ws, 3*time.Second)
	if !ok || ev.Path != "players.red-xai.db:Player[ID=3]" || ev.Op != "set" || !strings.Contains(ev.Value, "40") || !strings.Contains(ev.Value, "Cy") {
		t.Fatalf("expected only the Cy change, as a whole record, got %+v ok=%v", ev, ok)
	}
	// REST writes are watched too; a record removal is announced without a value
	if st, b, _ := req(t, "PUT", n.url+"/v1/path/players.red-xai.db:Player[ID=3].Level", n.key, []byte(`50`)); st != 200 {
		t.Fatalf("put: %d %s", st, b)
	}
	if ev, ok := readWatch(ws, 3*time.Second); !ok || !strings.Contains(ev.Value, "50") {
		t.Fatalf("REST write not delivered: %+v ok=%v", ev, ok)
	}
	bx(t, n, n.key, "", `{Delete[]} = players:Player[3]`)
	if ev, ok := readWatch(ws, 3*time.Second); !ok || ev.Op != "delete" || ev.Value != "" || ev.Path != "players.red-xai.db:Player[ID=3]" {
		t.Fatalf("removal: %+v ok=%v", ev, ok)
	}
}

func TestBXWatchEnforcesScopePrefixAndPolicy(t *testing.T) {
	n := startFull(t, engineadapter.Config{}, nil)
	seedPlayers(t, n)
	if st, b, _ := req(t, "PUT", n.url+"/v1/db/default/sec", n.key, []byte(guestPolicy)); st != 200 {
		t.Fatalf("policy: %d %s", st, b)
	}
	deny := func(what, key, q string, want int) {
		t.Helper()
		if st, b, _ := req(t, "GET", watchURL(n, q, nil), key); st != want {
			t.Fatalf("%s: got %d, want %d (%s)", what, st, want, b)
		}
	}
	guest := mkKeyFull(t, n, map[string]interface{}{"scope": "read", "db": "default", "roles": []string{"guest"}})
	pk := mkKey(t, n, "read", "default", "guilds.red-xai.db:")
	other := mkKey(t, n, "read", "other", "")

	deny("no key", "", `{Watch[]} = players:Player[Level > 1]`, 401)
	deny("a key for another database", other, `{Watch[]} = players:Player[Level > 1]`, 403)
	deny("a prefix key outside its prefix", pk, `{Watch[]} = players:Player[Level > 1]`, 403)
	deny("a guest on a denied file", guest, `{Watch[]} = guilds:Guild[ID=*]`, 403)
	deny("a guest filtering on a denied field", guest, `{Watch[]} = players:Player[Email starts "a"]`, 403)
	deny("bad syntax", n.key, `{Watch[]} = players:Player[Level >`, 400)
	deny("not a watch", n.key, `{Get[]} = players:Player[1]`, 400)
	deny("empty", n.key, ``, 400)

	// the guest may watch players but never sees Email
	ws := wsDial(t, watchURL(n, `{Watch[]} = players:Player[Level > 1]`, nil), guest)
	time.Sleep(100 * time.Millisecond)
	bx(t, n, n.key, "", `{Set[]} = players:Player[1].Level = 31`)
	ev, ok := readWatch(ws, 3*time.Second)
	if !ok || !strings.Contains(ev.Value, "Ann") || strings.Contains(ev.Value, "ann@x.test") || strings.Contains(ev.Value, "Email") {
		t.Fatalf("guest must see the record without Email: %+v ok=%v", ev, ok)
	}
	// the prefix key may watch what its prefix covers
	ws2 := wsDial(t, watchURL(n, `{Watch[]} = guilds:Guild[ID=*]`, nil), pk)
	time.Sleep(100 * time.Millisecond)
	if st, b, _ := req(t, "PUT", n.url+"/v1/path/guilds.red-xai.db:Guild[ID=10].Title", n.key, []byte(`"Wyverns"`)); st != 200 {
		t.Fatalf("put: %d %s", st, b)
	}
	if ev, ok := readWatch(ws2, 3*time.Second); !ok || !strings.Contains(ev.Value, "Wyverns") {
		t.Fatalf("prefix key watch: %+v ok=%v", ev, ok)
	}
}

func TestBXWatchPulseTopic(t *testing.T) {
	n := startFull(t, engineadapter.Config{}, nil)
	seedPlayers(t, n)
	D := n.url + "/v1/db/default"
	if st, b, _ := req(t, "PUT", D+"/pulse", n.key, []byte(deathRule)); st != 200 {
		t.Fatalf("define: %d %s", st, b)
	}
	c := wsDial(t, watchURL(n, `{Watch[]} = Topic = "player.*"`, nil), n.key)
	time.Sleep(100 * time.Millisecond)
	bx(t, n, n.key, "", `{Set[]} = players:Player[2].Health = 0`)
	ev, ok := readEvent(t, c, 3*time.Second)
	if !ok || ev.Topic != "player.died" {
		t.Fatalf("pulse watch: %+v ok=%v", ev, ok)
	}
}
