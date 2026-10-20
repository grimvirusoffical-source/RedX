package host

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestRepointPullOnceConcurrent is the -race regression for the failover path:
// Repoint swaps the follower's leader connection while pullOnce is using it.
// A sleep cannot hide that; the detector has to stay quiet across the loop.
func TestRepointPullOnceConcurrent(t *testing.T) {
	const rounds = 80
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"replid":"race-repl","entries":[],"last":0}`)
	}))
	t.Cleanup(srv.Close)

	cfg := DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Role = "follower"
	cfg.Peers = []string{srv.URL}
	cfg.NodeID = "race-follower"
	cfg.Heartbeat = 1
	cfg.LogLevel = "quiet"
	cfg.ArgonMemKiB, cfg.ArgonTime = 64, 1
	h, err := New(cfg, memOpener, func(string, ...interface{}) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds*8; i++ {
			_ = h.Cluster.pullOnce(ctx, stop)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if err := h.Cluster.Repoint(ctx, srv.URL, "", ""); err != nil {
				t.Errorf("repoint %d: %v", i, err)
				cancel()
				return
			}
		}
	}()
	wg.Wait()
	close(stop)
}
