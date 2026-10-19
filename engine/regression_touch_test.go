package engine

import (
	"testing"
	"time"

	"redx/box"
	"redx/engine/link"
)

// A BoxQL Get reads through RecordStore; Touch must slide the sliding TTLs inside the record it read
// and must not resurrect anything expired.
func TestRecordStoreTouchSlidesSlidingTTL(t *testing.T) {
	clk := newFakeClock()
	db := open(t, t.TempDir(), Config{Clock: clk.Now})
	defer db.Close()
	mustSet(t, db, qsF+"Sl[ID=1].A", num(1), SetOpts{TTLSeconds: 5, Sliding: true})
	mustSet(t, db, qsF+"Sl[ID=2].A", num(2), SetOpts{TTLSeconds: 5, Sliding: true})
	a1 := link.Addr{File: "s.red-xai-db-qs", Box: "Sl", ID: 1, HasID: true}
	for i := 0; i < 4; i++ { // 4 x 3 s = 12 s, far past the 5 s TTL, but touched every 3 s
		clk.Advance(3 * time.Second)
		db.Records().Touch([]link.Addr{a1})
	}
	if v, _ := db.Get(qsF + "Sl[ID=1].A"); v.String() != "1" {
		t.Fatalf("touched sliding key expired: %q", v.String())
	}
	if v, _ := db.Get(qsF + "Sl[ID=2].A"); v.Kind.String() != "NELL" && v.String() != "NELL" {
		t.Fatalf("untouched key should have expired, got %q", v.String())
	}
	// touching an expired record never revives it
	clk.Advance(10 * time.Second)
	db.Records().Touch([]link.Addr{a1})
	if v, _ := db.Get(qsF + "Sl[ID=1].A"); v.String() != "NELL" {
		t.Fatalf("expired record revived by Touch: %q", v.String())
	}
}

// The adapter used by BoxQL must hide expired children of a record too (B1 on the adapter path).
func TestRecordStoreGetHidesExpiredChildren(t *testing.T) {
	clk := newFakeClock()
	db := open(t, t.TempDir(), Config{Clock: clk.Now})
	defer db.Close()
	mustSet(t, db, qsF+"Sess[ID=1].A", num(1), SetOpts{TTLSeconds: 30})
	mustSet(t, db, qsF+"Sess[ID=1].B", num(2), SetOpts{TTLSeconds: 100})
	mustSet(t, db, qsF+"Sess[ID=2].A", num(3), SetOpts{TTLSeconds: 30})
	clk.Advance(31 * time.Second)
	a1 := link.Addr{File: "s.red-xai-db-qs", Box: "Sess", ID: 1, HasID: true}
	e, ok, err := db.Records().Get(a1)
	if err != nil || !ok {
		t.Fatalf("record 1 should still exist (child B live): ok=%v err=%v", ok, err)
	}
	if containsA(e.Value.String()) {
		t.Fatalf("expired child A visible through RecordStore.Get: %s", e.Value.String())
	}
	if _, ok, _ := db.Records().Get(link.Addr{File: "s.red-xai-db-qs", Box: "Sess", ID: 2, HasID: true}); ok {
		t.Fatal("record 2 has only expired children and must read as absent")
	}
	n := 0
	_ = db.Records().Scan("s.red-xai-db-qs", func(link.Addr, *box.Entry) bool { n++; return true })
	if n != 1 {
		t.Fatalf("scan saw %d records, want 1", n)
	}
}
