package host_test

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"redx/host"
)

// Rotating must never extend a key's absolute expiry, however often it is repeated.
func TestRotateKeepsOriginalExpiry(t *testing.T) {
	var mu sync.Mutex
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	ks, _ := newKS(t, "", clock)
	_, rec, err := ks.Create(host.CreateSpec{DB: "app", Scope: "read", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	want := *rec.Expires
	id := rec.ID
	for i := 0; i < 5; i++ {
		mu.Lock()
		now = now.Add(50 * time.Minute / 5)
		mu.Unlock()
		_, nr, err := ks.Rotate(id, 0)
		if err != nil {
			t.Fatalf("rotate %d: %v", i, err)
		}
		if nr.Expires == nil || !nr.Expires.Equal(want) {
			t.Fatalf("rotate %d: expiry %v, want %v", i, nr.Expires, want)
		}
		id = nr.ID
	}
	mu.Lock()
	now = want.Add(time.Second)
	mu.Unlock()
	if _, _, err := ks.Rotate(id, 0); err == nil {
		t.Fatal("rotating an expired key must fail")
	}
	// a key without expiry stays without expiry
	_, r2, _ := ks.Create(host.CreateSpec{DB: "app", Scope: "read"})
	_, n2, err := ks.Rotate(r2.ID, time.Minute)
	if err != nil || n2.Expires != nil {
		t.Fatalf("no-ttl rotate: %v %v", err, n2.Expires)
	}
}

// Concurrent rotates of one key produce exactly one successor; the others get a conflict.
func TestRotateConcurrentSingleSuccessor(t *testing.T) {
	for _, grace := range []time.Duration{0, time.Hour} {
		ks, _ := newKS(t, "", nil)
		_, rec, _ := ks.Create(host.CreateSpec{DB: "app", Scope: "write"})
		const n = 16
		var wg sync.WaitGroup
		var okN, confN int32
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, _, err := ks.Rotate(rec.ID, grace)
				switch {
				case err == nil:
					atomic.AddInt32(&okN, 1)
				case errors.Is(err, host.ErrConflict) || errors.Is(err, host.ErrKeyRevoked):
					atomic.AddInt32(&confN, 1)
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}()
		}
		close(start)
		wg.Wait()
		if okN != 1 || confN != n-1 {
			t.Fatalf("grace=%v: ok=%d conflicts=%d", grace, okN, confN)
		}
		live := 0
		for _, r := range ks.List() {
			if r.RotatedFrom == rec.ID && r.Revoked == nil {
				live++
			}
		}
		if live != 1 {
			t.Fatalf("grace=%v: %d live successors", grace, live)
		}
		if grace > 0 {
			if _, _, err := ks.Rotate(rec.ID, grace); !errors.Is(err, host.ErrConflict) {
				t.Fatalf("second rotate during grace: %v", err)
			}
		}
	}
}
