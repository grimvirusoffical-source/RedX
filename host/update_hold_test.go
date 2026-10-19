package host_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"redx/host"
)

func rolloutStateHealth(t *testing.T, body string) (state, health string) {
	t.Helper()
	m := jsonOf(t, body)
	state, _ = m["state"].(string)
	if h, ok := m["health"].(map[string]interface{}); ok {
		health, _ = h["status"].(string)
	}
	return state, health
}

func publishBeta(t *testing.T, n *node, ver string) (int, string) {
	t.Helper()
	req := map[string]interface{}{
		"version": ver, "channel": "beta", "notes_md": ver, "outcome_tags": []string{"+stability"},
		"targets": []string{"host"},
		"artifacts": []map[string]string{{
			"id": "linux-amd64", "filename": "redx-" + ver + "-linux-amd64.tar.gz",
			"os": "linux", "arch": "amd64", "kind": "tar.gz",
		}},
	}
	b, _ := json.Marshal(req)
	return withPermit(t, n, n.Key, "POST", "/v1/updates/apps/redx/publish", string(b))
}

// A db-scoped read key holding X-Redx-Wait-Seq open used to mint 504s that
// counted as errors and as slow, and the canary restored the app database.
func TestUpdateReadKeyCannotForceCanaryRollback(t *testing.T) {
	n := startNode(t, t.TempDir(), func(c *host.Config, _ string) {
		hostUpdate(c)
		c.NodeID = "a-node"
	})
	if st, body, _ := do(t, "POST", n.URL+"/v1/dbs", n.Key, `{"name":"redx"}`, "Content-Type", "application/json"); st != 201 && st != 409 {
		t.Fatalf("db %d %s", st, body)
	}
	path := "/v1/db/redx/path/app.red-xai.db:Cfg.V"
	if st, body, _ := do(t, "PUT", n.URL+path, n.Key, `"before-canary"`); st != 200 {
		t.Fatalf("before %d %s", st, body)
	}
	publishHost(t, n, "redx", "1.0.0", "canary", nil)
	host.SetUpdateMembers(n.H, []string{"a-node", "zzz-node"})
	st, applied := applyUpdate(t, n, "redx", "1.0.0", "host", "canary", map[string]int{"percent": 50, "min_minutes": 60})
	if st != 202 {
		t.Fatalf("canary %d %v", st, applied)
	}
	id := applied["rollout_id"].(string)
	if st, body, _ := do(t, "PUT", n.URL+path, n.Key, `"written-during-canary"`); st != 200 {
		t.Fatalf("during %d %s", st, body)
	}
	readKey, _ := mkKey(t, n, map[string]interface{}{"db": "default", "scope": "read"})
	host.ResetUpdateMetrics(n.H)

	// More than the minimum sample count, so a floor alone cannot hide these.
	// The original report used three of these GETs.
	nReq := host.UpdateMinHealthSamples() + 5
	codes := make([]int, nReq)
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 8 * time.Second}
	for i := 0; i < nReq; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, err := http.NewRequest(http.MethodGet, n.URL+"/v1/path/app.red-xai.db:Probe", nil)
			if err != nil {
				codes[i] = -1
				return
			}
			req.Header.Set("Authorization", "Bearer "+readKey)
			req.Header.Set("X-Redx-Wait-Seq", "999999999")
			resp, err := client.Do(req)
			if err != nil {
				codes[i] = -1
				return
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
			codes[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()
	got504 := 0
	for _, c := range codes {
		if c == http.StatusGatewayTimeout {
			got504++
		}
	}
	if got504 < host.UpdateMinHealthSamples() {
		t.Fatalf("wait-seq statuses %v", codes)
	}
	time.Sleep(2 * time.Second)
	st, body, _ := do(t, "GET", n.URL+"/v1/updates/rollouts/"+id, n.Key, "")
	state, health := rolloutStateHealth(t, body)
	if st != 200 || state != "canary" || health == "bad" {
		t.Fatalf("rollout after wait-seq %d state=%s health=%s %s", st, state, health, body)
	}
	st, body, _ = do(t, "GET", n.URL+path, n.Key, "")
	if st != 200 || !strings.Contains(body, "written-during-canary") {
		t.Fatalf("canary write was rewound: %d %s", st, body)
	}
}

// Idle follower replication polls at the default 3s heartbeat used to exceed the
// latency limit with no user traffic. This test does not call SetUpdateHealth.
func TestUpdateIdleClusterDefaultHeartbeat(t *testing.T) {
	leader := startNode(t, t.TempDir(), func(c *host.Config, _ string) {
		hostUpdate(c)
		c.Heartbeat = 3
		c.NodeID = "a-leader"
	})
	dir := t.TempDir()
	joinOffline(t, leader, dir, "z-follower", "")
	f := startNode(t, dir, func(c *host.Config, _ string) {
		c.NodeID = "z-follower"
		c.Role = "follower"
		c.Heartbeat = 3
	})
	f.Key = leader.Key
	eventually(t, "follower joined", 8*time.Second, func() bool {
		cs := status(t, leader)
		if cs.NodeID != "a-leader" || len(cs.Members) < 2 {
			return false
		}
		for _, m := range cs.Members {
			if !m.Healthy {
				return false
			}
		}
		return true
	})
	if st, body, _ := do(t, "POST", leader.URL+"/v1/dbs", leader.Key, `{"name":"redx"}`, "Content-Type", "application/json"); st != 201 && st != 409 {
		t.Fatalf("db %d %s", st, body)
	}
	publishHost(t, leader, "redx", "1.0.0", "idle", nil)
	st, applied := applyUpdate(t, leader, "redx", "1.0.0", "host", "canary", map[string]int{"percent": 50, "min_minutes": 60})
	if st != 202 {
		t.Fatalf("canary %d %v", st, applied)
	}
	id := applied["rollout_id"].(string)
	st, body, _ := do(t, "GET", leader.URL+"/v1/updates/rollouts/"+id, leader.Key, "")
	state, _ := rolloutStateHealth(t, body)
	if st != 200 || state != "canary" {
		t.Fatalf("canary did not start: %s", body)
	}
	host.ResetUpdateMetrics(leader.H)
	time.Sleep(10 * time.Second)
	st, body, _ = do(t, "GET", leader.URL+"/v1/updates/rollouts/"+id, leader.Key, "")
	state, health := rolloutStateHealth(t, body)
	if st != 200 || state != "canary" || health == "bad" {
		t.Fatalf("idle cluster rolled back: state=%s health=%s %s", state, health, body)
	}

	secret := followerNodeSecret(t, dir)
	cs := status(t, leader)
	nReq := host.UpdateMinHealthSamples() + 5
	codes := make([]int, nReq)
	slow := make([]bool, nReq)
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 8 * time.Second}
	for i := 0; i < nReq; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := fmt.Sprintf("%s/v1/cluster/log?from=%d&replid=%s&wait_ms=3000&limit=1", leader.URL, cs.Offset+1, cs.ReplID)
			req, err := http.NewRequest(http.MethodGet, u, nil)
			if err != nil {
				codes[i] = -1
				return
			}
			req.Header.Set("Authorization", "Bearer "+secret)
			req.Header.Set("X-Redx-Node", "z-follower")
			start := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				codes[i] = -1
				return
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
			codes[i] = resp.StatusCode
			slow[i] = time.Since(start) >= 2*time.Second
		}(i)
	}
	wg.Wait()
	waited := 0
	for i := range codes {
		if codes[i] == 200 && slow[i] {
			waited++
		}
	}
	if waited < host.UpdateMinHealthSamples() {
		t.Fatalf("replication long-polls did not wait: %d of %v", waited, codes)
	}
	time.Sleep(2 * time.Second)
	st, body, _ = do(t, "GET", leader.URL+"/v1/updates/rollouts/"+id, leader.Key, "")
	state, health = rolloutStateHealth(t, body)
	if st != 200 || state != "canary" || health == "bad" {
		t.Fatalf("long-polls rolled the canary back: state=%s health=%s %s", state, health, body)
	}
}

func followerNodeSecret(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "cluster", "cluster.json"))
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		NodeSecret string `json:"node_secret"`
	}
	if json.Unmarshal(b, &st) != nil || st.NodeSecret == "" {
		t.Fatal("follower is missing its node secret")
	}
	return st.NodeSecret
}

func TestUpdateCanaryRollsBackOnRealErrors(t *testing.T) {
	n := startNode(t, t.TempDir(), func(c *host.Config, _ string) {
		hostUpdate(c)
		c.NodeID = "a-node"
	})
	publishHost(t, n, "redx", "1.0.0", "errors", nil)
	host.SetUpdateMembers(n.H, []string{"a-node", "zzz-node"})
	st, applied := applyUpdate(t, n, "redx", "1.0.0", "host", "canary", map[string]int{"percent": 50, "min_minutes": 60})
	if st != 202 {
		t.Fatalf("canary %d %v", st, applied)
	}
	id := applied["rollout_id"].(string)
	host.ResetUpdateMetrics(n.H)
	for i := 0; i < host.UpdateMinHealthSamples()-1; i++ {
		host.NoteUpdateSample(n.H, 500, 20)
	}
	st, body, _ := do(t, "GET", n.URL+"/v1/updates/rollouts/"+id, n.Key, "")
	state, health := rolloutStateHealth(t, body)
	if st != 200 || state != "canary" || health != "unknown" {
		t.Fatalf("below minimum: state=%s health=%s %s", state, health, body)
	}
	for i := 0; i < 5; i++ {
		host.NoteUpdateSample(n.H, 500, 20)
	}
	eventually(t, "health rollback", 3*time.Second, func() bool {
		st, body, _ := do(t, "GET", n.URL+"/v1/updates/rollouts/"+id, n.Key, "")
		state, health := rolloutStateHealth(t, body)
		return st == 200 && state == "rolled_back" && health == "bad"
	})
}

func TestUpdateHealthIgnoresNonCanaryNode(t *testing.T) {
	n := startNode(t, t.TempDir(), func(c *host.Config, _ string) {
		hostUpdate(c)
		c.NodeID = "leader-node"
	})
	publishHost(t, n, "redx", "1.0.0", "other", nil)
	host.SetUpdateMembers(n.H, []string{"other-a", "other-b"})
	st, applied := applyUpdate(t, n, "redx", "1.0.0", "host", "canary", map[string]int{"percent": 50, "min_minutes": 60})
	if st != 202 {
		t.Fatalf("canary %d %v", st, applied)
	}
	id := applied["rollout_id"].(string)
	host.ResetUpdateMetrics(n.H)
	for i := 0; i < host.UpdateMinHealthSamples()+10; i++ {
		host.NoteUpdateSample(n.H, 500, 4000)
	}
	time.Sleep(2 * time.Second)
	st, body, _ := do(t, "GET", n.URL+"/v1/updates/rollouts/"+id, n.Key, "")
	state, health := rolloutStateHealth(t, body)
	if st != 200 || state != "canary" || health != "unknown" {
		t.Fatalf("non-canary traffic moved the rollout: state=%s health=%s %s", state, health, body)
	}
}

func TestUpdatePrereleaseNumericOrder(t *testing.T) {
	n := startNode(t, t.TempDir(), func(c *host.Config, _ string) { hostUpdate(c) })
	if st, body := publishBeta(t, n, "3.0.0-beta.9"); st != 201 {
		t.Fatalf("beta.9 %d %s", st, body)
	}
	if st, body := publishBeta(t, n, "3.0.0-beta.10"); st != 201 {
		t.Fatalf("beta.10 %d %s", st, body)
	}
	if st, body := publishBeta(t, n, "3.0.0-beta.8"); st != 409 || errCode(t, body) != "sequence_regression" {
		t.Fatalf("beta.8 %d %s", st, body)
	}
}

func TestUpdateConfirmTokenBoundToKey(t *testing.T) {
	n := startNode(t, t.TempDir(), func(c *host.Config, _ string) { hostUpdate(c) })
	publishHost(t, n, "redx", "1.0.0", "token", nil)
	other, _ := mkKey(t, n, map[string]interface{}{"db": "*", "scope": "admin"})
	plan := `{"version":"1.0.0","source":"host","strategy":"direct","plan":true}`
	st, body, _ := do(t, "POST", n.URL+"/v1/updates/apps/redx/apply", n.Key, plan, "Content-Type", "application/json")
	if st != 200 {
		t.Fatalf("plan %d %s", st, body)
	}
	tok, _ := jsonOf(t, body)["confirm"].(string)
	if tok == "" {
		t.Fatalf("no token: %s", body)
	}
	apply := `{"version":"1.0.0","source":"host","strategy":"direct"}`
	st, body, _ = do(t, "POST", n.URL+"/v1/updates/apps/redx/apply", other, apply, "Content-Type", "application/json", host.UpdateConfirmHeader, tok)
	if st != 403 || errCode(t, body) != "forbidden" {
		t.Fatalf("other key %d %s", st, body)
	}
	st, body, _ = do(t, "POST", n.URL+"/v1/updates/apps/redx/apply", n.Key, apply, "Content-Type", "application/json", host.UpdateConfirmHeader, tok)
	if st != 202 {
		t.Fatalf("issuing key %d %s", st, body)
	}
}

func startDefaultHeartbeatPair(t *testing.T, leaderID, followerID string, mod func(*host.Config)) (*node, *node) {
	t.Helper()
	leader := startNode(t, t.TempDir(), func(c *host.Config, _ string) {
		hostUpdate(c)
		c.Heartbeat = 3
		c.NodeID = leaderID
		if mod != nil {
			mod(c)
		}
	})
	dir := t.TempDir()
	joinOffline(t, leader, dir, followerID, "")
	f := startNode(t, dir, func(c *host.Config, _ string) {
		c.NodeID = followerID
		c.Role = "follower"
		c.Heartbeat = 3
	})
	f.Key = leader.Key
	eventually(t, "pair healthy", 8*time.Second, func() bool {
		cs := status(t, leader)
		if cs.NodeID != leaderID || len(cs.Members) < 2 {
			return false
		}
		for _, m := range cs.Members {
			if !m.Healthy {
				return false
			}
		}
		return true
	})
	return leader, f
}

func beginCanary(t *testing.T, leader *node) (id, path string) {
	t.Helper()
	if st, body, _ := do(t, "POST", leader.URL+"/v1/dbs", leader.Key, `{"name":"redx"}`, "Content-Type", "application/json"); st != 201 && st != 409 {
		t.Fatalf("db %d %s", st, body)
	}
	path = "/v1/db/redx/path/app.red-xai.db:Cfg.V"
	if st, body, _ := do(t, "PUT", leader.URL+path, leader.Key, `"before-canary"`); st != 200 {
		t.Fatalf("before %d %s", st, body)
	}
	publishHost(t, leader, "redx", "1.0.0", "canary", nil)
	st, applied := applyUpdate(t, leader, "redx", "1.0.0", "host", "canary", map[string]int{"percent": 50, "min_minutes": 60})
	if st != 202 {
		t.Fatalf("canary %d %v", st, applied)
	}
	id, _ = applied["rollout_id"].(string)
	if id == "" {
		t.Fatalf("no rollout: %v", applied)
	}
	if st, body, _ := do(t, "PUT", leader.URL+path, leader.Key, `"written-during-canary"`); st != 200 {
		t.Fatalf("during %d %s", st, body)
	}
	host.ResetUpdateMetrics(leader.H)
	return id, path
}

func rolloutDetail(t *testing.T, n *node, id string) (state, health string, p95, rate *float64, body string) {
	t.Helper()
	st, body, _ := do(t, "GET", n.URL+"/v1/updates/rollouts/"+id, n.Key, "")
	if st != 200 {
		t.Fatalf("rollout %d %s", st, body)
	}
	m := jsonOf(t, body)
	state, _ = m["state"].(string)
	if hv, ok := m["health"].(map[string]interface{}); ok {
		health, _ = hv["status"].(string)
		if v, ok := hv["p95_ms"].(float64); ok {
			p95 = &v
		}
		if v, ok := hv["error_rate"].(float64); ok {
			rate = &v
		}
	}
	return state, health, p95, rate, body
}

func drip(total time.Duration, steps int, payload []byte) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		sent := 0
		step := total / time.Duration(steps)
		chunk := len(payload) / steps
		if chunk < 1 {
			chunk = 1
		}
		for i := 0; i < steps; i++ {
			time.Sleep(step)
			if sent >= len(payload) {
				break
			}
			end := sent + chunk
			if end > len(payload) || i == steps-1 {
				end = len(payload)
			}
			_, _ = pw.Write(payload[sent:end])
			sent = end
		}
		if sent < len(payload) {
			_, _ = pw.Write(payload[sent:])
		}
		_ = pw.Close()
	}()
	return pr
}

func burstSlow(t *testing.T, n int, method, url, key, contentType string, payload []byte) []int {
	t.Helper()
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, err := http.NewRequest(method, url, drip(3*time.Second, 6, payload))
			if err != nil {
				codes[i] = -1
				return
			}
			req.ContentLength = -1
			if key != "" {
				req.Header.Set("Authorization", "Bearer "+key)
			}
			if contentType != "" {
				req.Header.Set("Content-Type", contentType)
			}
			client := &http.Client{Timeout: 12 * time.Second}
			start := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				codes[i] = -1
				return
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
			if time.Since(start) < 2*time.Second {
				codes[i] = -2
				return
			}
			codes[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()
	return codes
}

// Unauthenticated webhook posts, slow rejected bodies and /healthz probes must not
// move a canary. Real authorized errors still do. Default heartbeat, no SetUpdateHealth.
func TestUpdateAttackTrafficCannotRollBackCanary(t *testing.T) {
	leader, follower := startDefaultHeartbeatPair(t, "aa-leader", "zz-follower", nil)
	id, path := beginCanary(t, leader)
	if nodes := host.UpdateRolloutNodes(leader.H, id); len(nodes) != 1 || nodes[0] != "aa-leader" {
		t.Fatalf("leader should be the canary, got %v", nodes)
	}
	host.ResetUpdateMetrics(follower.H)

	for i := 0; i < 10; i++ {
		st, body, _ := do(t, "POST", leader.URL+"/v1/updates/github/webhook", "", `{"x":1}`, "Content-Type", "application/json")
		if st != 404 || errCode(t, body) != "not_found" {
			t.Fatalf("webhook %d %s", st, body)
		}
	}
	for i := 0; i < 30; i++ {
		if st, body, _ := do(t, "GET", leader.URL+"/healthz", "", ""); st != 200 {
			t.Fatalf("healthz %d %s", st, body)
		}
	}
	state, health, _, _, body := rolloutDetail(t, leader, id)
	if state != "canary" || health == "bad" {
		t.Fatalf("webhook 404 rolled back: state=%s health=%s %s", state, health, body)
	}

	readKey, _ := mkKey(t, leader, map[string]interface{}{"db": "default", "scope": "read"})
	codes := burstSlow(t, host.UpdateMinHealthSamples()+2, "POST", leader.URL+"/v1/query", readKey, "application/json", []byte("{{{"))
	for _, c := range codes {
		if c != 400 {
			t.Fatalf("slow query codes %v", codes)
		}
	}
	time.Sleep(1500 * time.Millisecond)
	state, health, p95, _, body := rolloutDetail(t, leader, id)
	if state != "canary" || health != "unknown" || (p95 != nil && *p95 > 1500) {
		t.Fatalf("slow 400 counted: state=%s health=%s p95=%v %s", state, health, p95, body)
	}
	if st, got, _ := do(t, "GET", leader.URL+path, leader.Key, ""); st != 200 || !strings.Contains(got, "written-during-canary") {
		t.Fatalf("db rewound: %d %s", st, got)
	}

	host.ResetUpdateMetrics(leader.H)
	host.ResetUpdateMetrics(follower.H)
	codes = burstSlow(t, host.UpdateMinHealthSamples()+2, "PUT", leader.URL+path, leader.Key, "", []byte(`"written-during-canary"`))
	for _, c := range codes {
		if c != 200 {
			t.Fatalf("slow put codes %v", codes)
		}
	}
	time.Sleep(1500 * time.Millisecond)
	state, health, p95, _, body = rolloutDetail(t, leader, id)
	if state != "canary" || health != "ok" || p95 == nil || *p95 > 1500 {
		t.Fatalf("slow authorized body: state=%s health=%s p95=%v %s", state, health, p95, body)
	}

	host.ResetUpdateMetrics(leader.H)
	for i := 0; i < 400; i++ {
		if st, _, _ := do(t, "GET", leader.URL+"/healthz", "", ""); st != 200 {
			t.Fatalf("healthz %d", st)
		}
	}
	for i := 0; i < 15; i++ {
		host.NoteUpdateSample(leader.H, 500, 40)
	}
	state, health, _, rate, body := rolloutDetail(t, leader, id)
	if state != "canary" || health != "unknown" || rate != nil {
		t.Fatalf("healthz diluted real errors into a verdict: state=%s health=%s rate=%v %s", state, health, rate, body)
	}
	for i := 0; i < host.UpdateMinHealthSamples(); i++ {
		host.NoteUpdateSample(leader.H, 500, 40)
	}
	eventually(t, "real errors roll back", 3*time.Second, func() bool {
		state, health, _, rate, _ := rolloutDetail(t, leader, id)
		return state == "rolled_back" && health == "bad" && rate != nil && *rate > 0.2
	})
}

func TestUpdateSlowWebhookRejectCannotRollBack(t *testing.T) {
	sec := filepath.Join(t.TempDir(), "hook.secret")
	if err := os.WriteFile(sec, []byte("hook-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	leader, follower := startDefaultHeartbeatPair(t, "aa-leader", "zz-follower", func(c *host.Config) {
		c.GithubWebhookSecretFile = sec
	})
	id, _ := beginCanary(t, leader)
	host.ResetUpdateMetrics(follower.H)
	codes := burstSlow(t, host.UpdateMinHealthSamples()+5, "POST", leader.URL+"/v1/updates/github/webhook", "", "application/json", []byte(`{"action":"published"}`))
	for _, c := range codes {
		if c != 401 {
			t.Fatalf("slow webhook codes %v", codes)
		}
	}
	for i := 0; i < 40; i++ {
		if st, _, _ := do(t, "GET", leader.URL+"/healthz", "", ""); st != 200 {
			t.Fatalf("healthz %d", st)
		}
	}
	time.Sleep(1500 * time.Millisecond)
	state, health, p95, _, body := rolloutDetail(t, leader, id)
	if state != "canary" || health != "unknown" || (p95 != nil && *p95 > 1500) {
		t.Fatalf("slow webhook 401: state=%s health=%s p95=%v %s", state, health, p95, body)
	}
}

func TestUpdateFollowerCanaryReportsHealth(t *testing.T) {
	leader, follower := startDefaultHeartbeatPair(t, "zz-leader", "aa-follower", nil)
	id, _ := beginCanary(t, leader)
	if nodes := host.UpdateRolloutNodes(leader.H, id); len(nodes) != 1 || nodes[0] != "aa-follower" {
		t.Fatalf("follower should be the canary, got %v", nodes)
	}
	host.ResetUpdateMetrics(leader.H)
	host.ResetUpdateMetrics(follower.H)
	time.Sleep(10 * time.Second)
	state, health, _, _, body := rolloutDetail(t, leader, id)
	if state != "canary" || health == "bad" {
		t.Fatalf("idle follower canary: state=%s health=%s %s", state, health, body)
	}
	for i := 0; i < 60; i++ {
		host.NoteUpdateSample(leader.H, 500, 2500)
	}
	time.Sleep(4 * time.Second)
	state, health, _, _, body = rolloutDetail(t, leader, id)
	if state != "canary" || health == "bad" {
		t.Fatalf("non-canary leader errors: state=%s health=%s %s", state, health, body)
	}
	host.ResetUpdateMetrics(leader.H)
	for i := 0; i < 60; i++ {
		host.NoteUpdateSample(follower.H, 500, 2500)
	}
	eventually(t, "follower canary rollback", 12*time.Second, func() bool {
		state, health, _, _, _ := rolloutDetail(t, leader, id)
		return state == "rolled_back" && health == "bad"
	})
}

func TestUpdateDeadFollowerCanaryRollsBack(t *testing.T) {
	leader, follower := startDefaultHeartbeatPair(t, "zz-leader", "aa-follower", nil)
	id, _ := beginCanary(t, leader)
	if nodes := host.UpdateRolloutNodes(leader.H, id); len(nodes) != 1 || nodes[0] != "aa-follower" {
		t.Fatalf("canary nodes %v", nodes)
	}
	host.ResetUpdateMetrics(leader.H)
	host.ResetUpdateMetrics(follower.H)
	time.Sleep(2 * time.Second)
	state, health, _, _, body := rolloutDetail(t, leader, id)
	if state != "canary" || health == "bad" {
		t.Fatalf("before stop: state=%s health=%s %s", state, health, body)
	}
	follower.Stop()
	eventually(t, "dead canary rollback", 20*time.Second, func() bool {
		st, got, _ := do(t, "GET", leader.URL+"/v1/updates/rollouts/"+id, leader.Key, "")
		if st != 200 {
			return false
		}
		state, health := rolloutStateHealth(t, got)
		return state == "rolled_back" && health == "bad"
	})
}
