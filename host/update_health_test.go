package host

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHealthExcludesWaitsClusterAndNeedsSamples(t *testing.T) {
	req := func(method, raw string, hdr ...string) *http.Request {
		t.Helper()
		r := httptest.NewRequest(method, raw, nil)
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		return r
	}
	cases := []struct {
		name   string
		r      *http.Request
		status int
		skip   bool
	}{
		{"cluster log", req("GET", "http://h/v1/cluster/log?from=1&wait_ms=3000"), 200, true},
		{"cluster status", req("GET", "http://h/v1/cluster/status"), 200, true},
		{"wait seq", req("GET", "http://h/v1/path/a:b", "X-Redx-Wait-Seq", "999999999"), 504, true},
		{"wait replicas", req("GET", "http://h/v1/path/a:b", "X-Redx-Wait-Replicas", "2"), 200, true},
		{"client 504", req("GET", "http://h/v1/path/a:b"), 504, true},
		{"events socket", req("GET", "http://h/v1/updates/events", "Upgrade", "websocket"), 101, true},
		{"subscribe", req("GET", "http://h/v1/db/default/subscribe"), 200, true},
		{"ordinary read", req("GET", "http://h/v1/path/a:b"), 200, false},
		{"server error", req("GET", "http://h/v1/path/a:b"), 500, false},
	}
	for _, tc := range cases {
		if got := healthExcluded(tc.r, tc.status); got != tc.skip {
			t.Errorf("%s excluded=%v want %v", tc.name, got, tc.skip)
		}
	}

	h := &Host{NodeID: "a-node"}
	for i := 0; i < updateMinHealthSamples-1; i++ {
		h.noteRequest(500, 3001*time.Millisecond)
	}
	if g := h.liveHealthFor([]string{"a-node"}); g.Status != "unknown" || g.ErrorRate != nil || g.P95MS != nil {
		t.Fatalf("below minimum: %+v", g)
	}
	h.noteRequest(500, 3001*time.Millisecond)
	g := h.liveHealthFor([]string{"a-node"})
	if g.Status != "bad" || g.ErrorRate == nil || *g.ErrorRate < 0.9 || g.P95MS == nil || *g.P95MS < 3000 {
		t.Fatalf("canary errors: %+v err=%v p95=%v", g, g.ErrorRate, g.P95MS)
	}
	if g := h.liveHealthFor([]string{"zzz-node"}); g.Status != "unknown" || g.ErrorRate != nil {
		t.Fatalf("other node counted: %+v", g)
	}
}
