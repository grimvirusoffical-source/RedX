package engine

import (
	"testing"
	"time"
)

// R2 says follower Query must skip logically-expired entries. Whole-box query variant.
func TestTTL_R2_FollowerWholeBoxQueryHidesExpired(t *testing.T) {
	p := newPair(t)
	mustSet(t, p.L, "q.red-xai-db-qs:Sess[ID=1].A", num(1), SetOpts{TTLSeconds: 30})
	p.ship()
	p.FC.Advance(31 * time.Second) // follower clock past deadline, no expire op yet
	if r, _ := p.F.Query("q.red-xai-db-qs:Sess[ID=*]"); len(r) != 0 {
		t.Fatalf("follower whole-box Query shows logically expired data: %v", r)
	}
	if !absentOrNell(t, p.F, "q.red-xai-db-qs:Sess[ID=1].A") {
		t.Fatal("follower Get shows expired")
	}
}
