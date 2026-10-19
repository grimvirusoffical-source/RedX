package engineadapter_test

import (
	"strings"
	"testing"
	"time"

	"redx/host/engineadapter"
)

// BoxQL Get must refresh sliding TTLs the way REST reads do.
func TestBoxQLGetSlidesSlidingTTL(t *testing.T) {
	n := startFull(t, engineadapter.Config{}, nil)
	P := n.url + "/v1/path/"
	if st, b, _ := req(t, "PUT", P+"sl.red-xai-db-qs:Sl[ID=1].A?ttl=2&sliding=true", n.key, []byte(`1`)); st != 200 {
		t.Fatalf("put: %d %s", st, b)
	}
	if st, b, _ := req(t, "PUT", P+"sl.red-xai-db-qs:Sl[ID=2].A?ttl=2&sliding=true", n.key, []byte(`2`)); st != 200 {
		t.Fatalf("put: %d %s", st, b)
	}
	for i := 0; i < 4; i++ { // 4 x 1.1 s: well past the 2 s TTL unless the reads slide it
		time.Sleep(1100 * time.Millisecond)
		st, o, raw := bx(t, n, n.key, "", `{Get[]} = sl:Sl[ID=1] -> A`)
		if st != 200 || o.Count != 1 {
			t.Fatalf("read %d: sliding key vanished although BoxQL reads it every 1.1 s: %d %s", i, st, raw)
		}
	}
	// record 2 was never read and has expired
	if _, o, raw := bx(t, n, n.key, "", `{Get[]} = sl:Sl[ID=2] -> A`); o.Count != 0 {
		t.Fatalf("unread sliding key should have expired: %s", raw)
	}
}

// BoxQL on an unknown file gives the documented message, not a bare "not found".
func TestBoxQLUnknownFileMessage(t *testing.T) {
	n := startFull(t, engineadapter.Config{}, nil)
	st, _, raw := bx(t, n, n.key, "", `{Get[]} = nosuch:Player[ID=*] -> Name`)
	if st != 404 || !strings.Contains(raw, `query: unknown file: \"nosuch\"`) {
		t.Fatalf("want 404 with the documented message, got %d %s", st, raw)
	}
}
