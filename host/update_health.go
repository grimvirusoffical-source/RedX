package host

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
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

// healthMark is per request. ok is set only after authentication and authorization succeed.
// bodyReady is the moment the body has been fully read, so a slow client does not
// look like a slow server.
type healthMark struct {
	ok        bool
	bodyReady time.Time
}

type healthMarkKey struct{}

func healthMarkOf(r *http.Request) *healthMark {
	if r == nil {
		return nil
	}
	m, _ := r.Context().Value(healthMarkKey{}).(*healthMark)
	return m
}

func allowHealth(r *http.Request) {
	if m := healthMarkOf(r); m != nil {
		m.ok = true
	}
}

func clearHealth(r *http.Request) {
	if m := healthMarkOf(r); m != nil {
		m.ok = false
	}
}

// bodyClock notes when the body read finishes (EOF or a terminal error).
type bodyClock struct {
	io.ReadCloser
	mark *healthMark
}

func (b *bodyClock) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && b.mark != nil && b.mark.bodyReady.IsZero() {
		b.mark.bodyReady = time.Now()
	}
	return n, err
}

// healthDuration is handler time after the body is fully read.
// A request that never reads its body (a typical GET) keeps the whole handler time.
func healthDuration(started time.Time, mark *healthMark) time.Duration {
	if mark != nil && !mark.bodyReady.IsZero() {
		return time.Since(mark.bodyReady)
	}
	return time.Since(started)
}

// statusCapture records the HTTP status and still supports websocket upgrade.
type statusCapture struct {
	http.ResponseWriter
	code    int
	written int64
	reason  string
}

func (s *statusCapture) setReason(msg string) {
	if s == nil || s.reason != "" || msg == "" {
		return
	}
	if len(msg) > 200 {
		msg = msg[:200]
	}
	s.reason = msg
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
	n, err := s.ResponseWriter.Write(b)
	if n > 0 {
		s.written += int64(n)
	}
	return n, err
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
// Only an authenticated and authorized API call counts, and a 4xx does not:
// unauthenticated probes, rejected keys and client mistakes are not the canary's health.
func (h *Host) observeRequest(r *http.Request, status int, d time.Duration) {
	if !requestCountsForHealth(r, status) {
		return
	}
	h.noteRequest(status, d)
}

func requestCountsForHealth(r *http.Request, status int) bool {
	if status < 100 || (status >= 400 && status <= 499) {
		return false
	}
	if healthExcluded(r, status) {
		return false
	}
	m := healthMarkOf(r)
	return m != nil && m.ok
}

// healthExcluded leaves out routes that are not user API traffic.
// A 504 is excluded only when the client asked to wait or the request is a long-poll;
// a gateway timeout on an ordinary authorized call still counts.
func healthExcluded(r *http.Request, status int) bool {
	if r == nil || r.URL == nil {
		return true
	}
	p := r.URL.Path
	if p == "/healthz" || p == "/readyz" || p == "/livez" {
		return true
	}
	if p == "/v1/updates/github/webhook" {
		return true
	}
	if p == "/v1/cluster" || strings.HasPrefix(p, "/v1/cluster/") {
		return true
	}
	if r.Header.Get("X-Redx-Wait-Seq") != "" || r.Header.Get("X-Redx-Wait-Replicas") != "" {
		return true
	}
	if _, ok := r.URL.Query()["wait_ms"]; ok {
		return true
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return true
	}
	if p == "/v1/subscribe" || strings.HasSuffix(p, "/subscribe") || p == "/v1/bx/watch" || strings.HasSuffix(p, "/bx/watch") || p == "/v1/updates/events" {
		return true
	}
	_ = status
	return false
}

func (h *Host) resetRequestMetrics() {
	h.metricMu.Lock()
	h.metricSamples = nil
	h.metricMu.Unlock()
}

func (h *Host) healthSamples(only []string) []reqSample {
	allow := map[string]struct{}{}
	for _, id := range only {
		if id != "" {
			allow[id] = struct{}{}
		}
	}
	now := time.Now()
	h.metricMu.Lock()
	defer h.metricMu.Unlock()
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
	return samples
}

// liveHealthFor is the sample verdict for nodes in only.
// only empty means every sample on this process. Below updateMinHealthSamples the status
// is unknown and the rates are nil. Liveness is not decided here.
func (h *Host) liveHealthFor(only []string) healthView {
	samples := h.healthSamples(only)
	view := healthView{Status: "unknown"}
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
	if rate > updateMaxErrorRate || p95 > updateMaxP95MS {
		view.Status = "bad"
	}
	return view
}

// nodeHealthWire is what a follower sends on the authenticated replication poll.
// Live is true because this process is up enough to ask for the log; a node that
// stops polling cannot clear it, so the holder treats a stale report as down.
type nodeHealthWire struct {
	Status    string   `json:"status"`
	ErrorRate *float64 `json:"error_rate,omitempty"`
	P95MS     *float64 `json:"p95_ms,omitempty"`
	Samples   int      `json:"samples"`
	Live      bool     `json:"live"`
}

type storedNodeHealth struct {
	wire nodeHealthWire
	at   time.Time
}

func (h *Host) nodeHealthHeader() string {
	if h == nil {
		return ""
	}
	sh := h.liveHealthFor([]string{h.NodeID})
	w := nodeHealthWire{
		Status: sh.Status, ErrorRate: sh.ErrorRate, P95MS: sh.P95MS,
		Samples: len(h.healthSamples([]string{h.NodeID})), Live: true,
	}
	b, err := json.Marshal(w)
	if err != nil {
		return ""
	}
	return string(b)
}

// rolloutReportMaxAge is how long a canary's own health report stays fresh.
// It is tighter than the cluster member Healthy window so a canary that stops
// polling fails the rollout without waiting out Heartbeat*5+10s.
func (h *Host) rolloutReportMaxAge() time.Duration {
	hb := 1
	if h != nil && h.Cfg.Heartbeat > 0 {
		hb = h.Cfg.Heartbeat
	}
	return time.Duration(hb) * 3 * time.Second
}

// rolloutHealth is the canary verdict the rollout holder uses.
// Each canary node contributes its own samples (local, or the report it sent on
// the cluster log poll). A dead member, or a canary that stopped reporting,
// is bad even when there are no samples.
func (h *Host) rolloutHealth(updated []string) healthView {
	view := healthView{Status: "unknown"}
	var members []Member
	if h.Cluster != nil {
		st := h.Cluster.Status()
		members = st.Members
		view.Nodes = len(members)
		for _, m := range members {
			if m.Healthy {
				view.LiveNodes++
			}
		}
	}
	if view.Nodes > 0 && view.LiveNodes < view.Nodes {
		view.Status = "bad"
		return view
	}
	if len(updated) == 0 {
		sh := h.liveHealthFor(nil)
		sh.LiveNodes, sh.Nodes = view.LiveNodes, view.Nodes
		return sh
	}
	known := map[string]Member{}
	for _, m := range members {
		known[m.ID] = m
	}
	var worstRate, maxP95 float64
	saw := false
	anyBad, anyUnknown := false, false
	maxAge := h.rolloutReportMaxAge()
	for _, id := range updated {
		var sh healthView
		switch {
		case id == h.NodeID:
			sh = h.liveHealthFor([]string{id})
		default:
			m, ok := known[id]
			if !ok {
				// Injected planner ids are not cluster members and are not dead nodes.
				anyUnknown = true
				continue
			}
			if !m.Healthy {
				anyBad = true
				continue
			}
			rep, age, seen := h.Cluster.nodeHealthReport(id)
			if !seen {
				anyUnknown = true
				continue
			}
			if !rep.Live || age > maxAge {
				anyBad = true
				continue
			}
			if rep.Samples < updateMinHealthSamples || (rep.Status != "ok" && rep.Status != "bad") {
				anyUnknown = true
				continue
			}
			sh = healthView{Status: rep.Status, ErrorRate: rep.ErrorRate, P95MS: rep.P95MS}
			if sh.Status != "bad" && ((sh.ErrorRate != nil && *sh.ErrorRate > updateMaxErrorRate) || (sh.P95MS != nil && *sh.P95MS > updateMaxP95MS)) {
				sh.Status = "bad"
			}
		}
		if sh.Status == "unknown" {
			anyUnknown = true
			continue
		}
		if sh.ErrorRate != nil && (!saw || *sh.ErrorRate > worstRate) {
			worstRate = *sh.ErrorRate
			saw = true
		}
		if sh.P95MS != nil && *sh.P95MS > maxP95 {
			maxP95 = *sh.P95MS
		}
		if sh.Status == "bad" {
			anyBad = true
		}
	}
	if anyBad {
		view.Status = "bad"
	} else if anyUnknown {
		return view
	} else {
		view.Status = "ok"
	}
	if saw && view.Status != "unknown" {
		rate, p95 := worstRate, maxP95
		view.ErrorRate = &rate
		view.P95MS = &p95
	}
	return view
}
