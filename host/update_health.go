package host

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"sort"
	"time"
)

const updateMetricWindow = 2 * time.Minute

type reqSample struct {
	at     time.Time
	status int
	ms     float64
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
	h.metricSamples = append(h.metricSamples, reqSample{at: time.Now(), status: status, ms: float64(d) / float64(time.Millisecond)})
	if len(h.metricSamples) > 512 {
		h.metricSamples = append([]reqSample(nil), h.metricSamples[len(h.metricSamples)-512:]...)
	}
	h.metricMu.Unlock()
}

func (h *Host) resetRequestMetrics() {
	h.metricMu.Lock()
	h.metricSamples = nil
	h.metricMu.Unlock()
}

// liveHealth is the host's own error rate, latency and node liveness.
// With no samples the status is unknown and the rates are nil: callers must not invent zeros.
func (h *Host) liveHealth() healthView {
	now := time.Now()
	h.metricMu.Lock()
	samples := make([]reqSample, 0, len(h.metricSamples))
	for _, s := range h.metricSamples {
		if now.Sub(s.at) <= updateMetricWindow {
			samples = append(samples, s)
		}
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
	if len(samples) == 0 {
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
