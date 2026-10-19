package engineadapter_test

import (
	"strings"
	"testing"
	"time"

	"redx/host"
)

func TestBXOnFollower(t *testing.T) {
	leader := start(t, nil)
	f := start(t, func(c *host.Config, _ string) {
		c.Role = "follower"
		c.Peers = []string{leader.url}
		c.NodeID = "bx-f1"
	})
	f.key = leader.key
	eventually(t, "keys replicated", 6*time.Second, func() bool { return f.h.KS.Count() > 0 })

	// a BoxQL write sent to the follower is forwarded to the leader
	if st, o, raw := bx(t, f, leader.key, "", `{Add[]} = "players.red-xai.db":Player[ID=1] = [ {Name[]} = "Ann", {Level[]} = 5 ]`); st != 200 || o.Affected != 1 {
		t.Fatalf("add via follower: %d %s", st, raw)
	}
	if st, o, raw := bx(t, f, leader.key, "", `{Tx[]} = [ {Set[]} = players:Player[1].Level = Level + 1, {Set[]} = players:Player[1].Name = "Anna" ]`); st != 200 || len(o.Results) != 2 {
		t.Fatalf("tx via follower: %d %s", st, raw)
	}
	if _, b, _ := req(t, "GET", leader.url+"/v1/path/players.red-xai.db:Player[ID=1].Level", leader.key, nil); !strings.Contains(string(b), "6") {
		t.Fatalf("leader has the write: %s", b)
	}
	// reads are answered by the follower from its replicated data
	eventually(t, "BoxQL read on the follower", 6*time.Second, func() bool {
		st, o, _ := bx(t, f, leader.key, "", `{Get[]} = players:Player[Level >= $n] -> Name`, bxp{"n": 6})
		return st == 200 && o.Count == 1 && string(o.Rows[0][0]) == `"Anna"`
	})
	// a syntax error is answered locally with 400 (never forwarded as a write)
	if st, _, _ := bx(t, f, leader.key, "", `{Set[]} = players:Player[1].Level = `); st != 400 {
		t.Fatalf("syntax error via follower: %d", st)
	}
	// a read-only key still cannot write through the follower
	ro := mkKey(t, leader, "read", "default", "")
	eventually(t, "read key replicated", 6*time.Second, func() bool {
		st, _, _ := bx(t, f, ro, "", `{Get[]} = players:Player[1] -> Name`)
		return st == 200
	})
	if st, _, _ := bx(t, f, ro, "", `{Set[]} = players:Player[1].Level = 0`); st != 403 {
		t.Fatalf("read key write via follower: %d", st)
	}
	// a pulse watch opened on the follower is served by the leader
	if st, b, _ := req(t, "PUT", f.url+"/v1/db/default/pulse", leader.key, []byte(deathRule)); st != 200 {
		t.Fatalf("define rules: %d %s", st, b)
	}
	c := wsDial(t, watchURL(f, `{Watch[]} = Topic = "player.*"`, nil), leader.key)
	time.Sleep(100 * time.Millisecond)
	bx(t, f, leader.key, "", `{Set[]} = players:Player[1].Health = 0`)
	if ev, ok := readEvent(t, c, 3*time.Second); !ok || ev.Topic != "player.died" {
		t.Fatalf("pulse watch through the follower: %+v %v", ev, ok)
	}
}
