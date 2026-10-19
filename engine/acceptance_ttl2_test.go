package engine

import (
	"testing"
	"time"

	"redx/box"
)

// Query BEFORE any Get/sweep, at/after the deadline, fixed TTL. (No lazy purge has happened yet.)
func TestTTL_QueryHidesExpiredWithoutPriorGet(t *testing.T) {
	for _, tc := range []struct{ name, q string }{
		{"whole-box", qsF + "Sess[ID=*]"},
		{"exact-leaf", qsF + "Sess[ID=1].A"},
		{"leaf-wildcard", qsF + "Sess[ID=*].A"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clk := newFakeClock()
			db := open(t, t.TempDir(), Config{Clock: clk.Now})
			defer db.Close()
			mustSet(t, db, qsF+"Sess[ID=1].A", num(1), SetOpts{TTLSeconds: 30})
			clk.Advance(30 * time.Second) // exactly the deadline; sweeper (fake clock) has not run
			r, err := db.Query(tc.q)
			if err != nil || len(r) != 0 {
				t.Fatalf("Query(%q) at deadline returned %v (err %v), want nothing", tc.q, r, err)
			}
		})
	}
}

func TestTTL_QueryHidesExpiredBoxLevelTTL(t *testing.T) {
	clk := newFakeClock()
	db := open(t, t.TempDir(), Config{Clock: clk.Now})
	defer db.Close()
	v, _ := box.ParseValue(`[ {X[]} = 1 ]`)
	mustSet(t, db, qsF+"Sess[ID=1]", v, SetOpts{TTLSeconds: 30})
	clk.Advance(30 * time.Second)
	r, _ := db.Query(qsF + "Sess[ID=*]")
	if len(r) != 0 {
		t.Fatalf("box-level expired subtree returned by Query before any purge: %v", r)
	}
}

// Same on the qs-ls table and with real-time sweeper disabled (long SweepMS) but real clock.
func TestTTL_QueryExpiredQSLS(t *testing.T) {
	clk := newFakeClock()
	db := open(t, t.TempDir(), Config{Clock: clk.Now})
	defer db.Close()
	mustSet(t, db, "w.red-xai-db-qs-ls:H.A", num(1), SetOpts{TTLSeconds: 5})
	clk.Advance(5 * time.Second)
	r, _ := db.Query("w.red-xai-db-qs-ls:H.A")
	if len(r) != 0 {
		t.Fatalf("qs-ls query returned expired: %v", r)
	}
}
