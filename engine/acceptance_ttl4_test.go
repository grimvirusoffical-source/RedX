package engine

import (
	"testing"
	"time"
)

func TestTTL_GetWholeBoxHidesExpiredChild(t *testing.T) {
	clk := newFakeClock()
	db := open(t, t.TempDir(), Config{Clock: clk.Now})
	defer db.Close()
	mustSet(t, db, qsF+"Sess[ID=1].A", num(1), SetOpts{TTLSeconds: 30})
	mustSet(t, db, qsF+"Sess[ID=1].B", num(2), SetOpts{TTLSeconds: 100})
	clk.Advance(31 * time.Second)
	v, err := db.Get(qsF + "Sess[ID=1]")
	if err != nil {
		t.Fatal(err)
	}
	s := v.String()
	if containsA(s) {
		t.Fatalf("Get of whole box includes expired child A: %s", s)
	}
}
func containsA(s string) bool {
	for i := 0; i+3 < len(s); i++ {
		if s[i:i+3] == "{A[" {
			return true
		}
	}
	return false
}
