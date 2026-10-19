package host

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// memBackend loads one value at open time and serves it from memory, like the
// stub store: a handle opened on the old tree keeps serving the old data.
type memBackend struct{ v string }

func (m *memBackend) Get(string) (string, error)        { return m.v, nil }
func (m *memBackend) Set(string, string, SetOpts) error { return nil }
func (m *memBackend) Delete(string) error               { return nil }
func (m *memBackend) Query(string) ([]string, error)    { return nil, nil }
func (m *memBackend) Subscribe(string) (<-chan Event, func()) {
	return make(chan Event), func() {}
}
func (m *memBackend) Stats() map[string]float64 { return nil }
func (m *memBackend) Close() error              { return nil }

func memOpener(dir string, _ bool) (Backend, error) {
	b, err := os.ReadFile(filepath.Join(dir, "val"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return &memBackend{string(b)}, nil
}

func writeTree(t *testing.T, root, val string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "d", "val"), []byte(val), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Regression for the 0.4.4 Windows CI failure in
// TestDivergedOldLeaderGetsSnapshotAndLosesUnreplicatedWrites: snapshot install closed
// every database, released the registry lock and only then renamed the dbs tree, so
// a read racing the install could reopen the OLD tree and cache that handle forever
// (the discarded write stayed readable). SwapRoot must be atomic w.r.t. Get.
func TestRegistrySwapRootNeverServesOldTree(t *testing.T) {
	data := t.TempDir()
	r, err := NewRegistry(data, memOpener, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	writeTree(t, r.Root(), "gen-init")
	for i := 0; i < 150; i++ {
		want := fmt.Sprintf("gen-%d", i)
		next := filepath.Join(data, fmt.Sprintf(".snap-%d", i))
		writeTree(t, next, want)
		var stop atomic.Bool
		var missing atomic.Int64
		var wg sync.WaitGroup
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for !stop.Load() {
					b, err := r.Get("d")
					if errors.Is(err, ErrNoDB) {
						missing.Add(1)
						continue
					}
					if err != nil {
						continue
					}
					_, _ = b.Get("")
				}
			}()
		}
		if err := r.SwapRoot(next); err != nil {
			stop.Store(true)
			wg.Wait()
			t.Fatal(err)
		}
		// let the readers run against the new tree for a moment, then check
		for k := 0; k < 200; k++ {
			if b, err := r.Get("d"); err == nil {
				_, _ = b.Get("")
			}
		}
		stop.Store(true)
		wg.Wait()
		b, err := r.Get("d")
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if got, _ := b.Get(""); got != want {
			t.Fatalf("iteration %d: registry serves %q after swap, want %q (stale handle on the old tree)", i, got, want)
		}
		if n := missing.Load(); n != 0 {
			t.Fatalf("iteration %d: %d reads saw the database as missing mid-swap", i, n)
		}
	}
}
