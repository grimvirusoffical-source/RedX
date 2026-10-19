package host

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

const updateMetricWindow = 2 * time.Minute

type reqSample struct {
	at     time.Time
	status int
	ms     float64
	node   string
}

// statusCapture records the HTTP status and still supports websocket upgrade.
type statusCapture struct {
	http.ResponseWriter
	code int
}

func (s *statusCapture) WriteHeader(code int) {
	if s.code == 0 {
		s.code = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusCapture) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.code = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusCapture) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijacker not supported")
	}
	return h.Hijack()
}

func (h *Host) noteRequest(status int, d time.Duration) {
	if h == nil || status < 100 {
		return
	}
	h.metricMu.Lock()
	h.metricSamples = append(h.metricSamples, reqSample{
		at: time.Now(), status: status, ms: float64(d) / float64(time.Millisecond), node: h.NodeID,
	})
	if len(h.metricSamples) > 512 {
		h.metricSamples = append([]reqSample(nil), h.metricSamples[len(h.metricSamples)-512:]...)
	}
	h.metricMu.Unlock()
}

// observeRequest records one served request for rollout health.
// Cluster replication, client waits, long-polls and client-induced 504s are left out:
// a read key can hold a request open, and an idle follower's poll is not user traffic.
func (h *Host) observeRequest(r *http.Request, status int, d time.Duration) {
	if healthExcluded(r, status) {
		return
	}
	h.noteRequest(status, d)
}

func healthExcluded(r *http.Request, status int) bool {
	if r == nil || r.URL == nil {
		return true
	}
	p := r.URL.Path
	if p == "/v1/cluster" || strings.HasPrefix(p, "/v1/cluster/") {
		return true
	}
	if r.Header.Get("X-Redx-Wait-Seq") != "" || r.Header.Get("X-Redx-Wait-Replicas") != "" {
		return true
	}
	if _, ok := r.URL.Query()["wait_ms"]; ok {
		return true
	}
	if status == http.StatusGatewayTimeout {
		return true
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return true
	}
	if p == "/v1/subscribe" || strings.HasSuffix(p, "/subscribe") || p == "/v1/bx/watch" || strings.HasSuffix(p, "/bx/watch") || p == "/v1/updates/events" {
		return true
	}
	return false
}

func (h *Host) resetRequestMetrics() {
	h.metricMu.Lock()
	h.metricSamples = nil
	h.metricMu.Unlock()
}

// liveHealthFor is error rate and latency for nodes in only.
// only empty means every sample on this process. Below updateMinHealthSamples the status
// is unknown and the rates are nil: callers must not invent zeros, and nothing auto-rolls back.
func (h *Host) liveHealthFor(only []string) healthView {
	allow := map[string]struct{}{}
	for _, id := range only {
		if id != "" {
			allow[id] = struct{}{}
		}
	}
	now := time.Now()
	h.metricMu.Lock()
	samples := make([]reqSample, 0, len(h.metricSamples))
	for _, s := range h.metricSamples {
		if now.Sub(s.at) > updateMetricWindow {
			continue
		}
		if len(allow) > 0 {
			if _, ok := allow[s.node]; !ok {
				continue
			}
		}
		samples = append(samples, s)
	}
	h.metricMu.Unlock()
	view := healthView{Status: "unknown"}
	live, nodes := 0, 0
	if h.Cluster != nil {
		st := h.Cluster.Status()
		nodes = len(st.Members)
		for _, m := range st.Members {
			if m.Healthy {
				live++
			}
		}
		view.LiveNodes = live
		view.Nodes = nodes
	}
	if len(samples) < updateMinHealthSamples {
		return view
	}
	bad := 0
	lat := make([]float64, len(samples))
	for i, s := range samples {
		if s.status >= 500 {
			bad++
		}
		lat[i] = s.ms
	}
	sort.Float64s(lat)
	idx := int(float64(len(lat)-1) * 0.95)
	rate := float64(bad) / float64(len(samples))
	p95 := lat[idx]
	view.ErrorRate = &rate
	view.P95MS = &p95
	view.Status = "ok"
	if rate > updateMaxErrorRate || p95 > updateMaxP95MS || (nodes > 0 && live < nodes) {
		view.Status = "bad"
	}
	return view
}
