package host_test

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/websocket"

	"redx/host"
	"redx/host/accountsfake"
)

func errCode(t *testing.T, body string) string {
	t.Helper()
	var e struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal([]byte(body), &e) != nil || e.Error.Code == "" {
		t.Fatalf("error shape: %s", body)
	}
	return e.Error.Code
}

func publishHost(t *testing.T, n *node, app, ver, notes string, tags []string) {
	t.Helper()
	if tags == nil {
		tags = []string{"+security", "+stability"}
	}
	req := map[string]interface{}{
		"version": ver, "channel": "stable", "notes_md": notes, "outcome_tags": tags,
		"targets": []string{"host"},
		"artifacts": []map[string]string{{
			"id": "linux-amd64", "filename": "redx-" + ver + "-linux-amd64.tar.gz",
			"os": "linux", "arch": "amd64", "kind": "tar.gz",
		}},
	}
	b, _ := json.Marshal(req)
	st, body, _ := do(t, "POST", n.URL+"/v1/updates/apps/"+app+"/publish", n.Key, string(b), "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("publish %s %s: %d %s", app, ver, st, body)
	}
}

func applyUpdate(t *testing.T, n *node, app, ver, source, strategy string, canary interface{}) (int, map[string]interface{}) {
	t.Helper()
	req := map[string]interface{}{"version": ver, "source": source, "strategy": strategy}
	if canary != nil {
		req["canary"] = canary
	}
	b, _ := json.Marshal(req)
	st, body, _ := do(t, "POST", n.URL+"/v1/updates/apps/"+app+"/apply", n.Key, string(b), "Content-Type", "application/json")
	if st != 202 {
		return st, map[string]interface{}{"raw": body}
	}
	return st, jsonOf(t, body)
}

func TestUpdateKeysAndStatus(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	st, body, hdr := do(t, "GET", n.URL+"/v1/updates/keys", "", "")
	if st != 200 {
		t.Fatalf("keys %d %s", st, body)
	}
	if hdr.Get("X-RedX-Key-Id") == "" {
		t.Fatal("missing X-RedX-Key-Id")
	}
	var keys []struct {
		Kid      string `json:"kid"`
		Alg      string `json:"alg"`
		Pub      string `json:"pub"`
		NotAfter string `json:"not_after"`
	}
	if json.Unmarshal([]byte(body), &keys) != nil || len(keys) != 1 || keys[0].Alg != "ed25519" || keys[0].Kid == "" || keys[0].Pub == "" || keys[0].NotAfter == "" {
		t.Fatalf("keys body %s", body)
	}
	st, body, _ = do(t, "GET", n.URL+"/v1/updates/apps/redx", n.Key, "")
	if st != 200 {
		t.Fatalf("status %d %s", st, body)
	}
	m := jsonOf(t, body)
	if m["hosted"] != false || m["source_pref"] != "github" || m["app"] != "redx" {
		t.Fatalf("status %s", body)
	}
	st, body, _ = do(t, "GET", n.URL+"/v1/updates/apps", "", "")
	if st != 401 || errCode(t, body) != "forbidden" {
		t.Fatalf("list unauth %d %s", st, body)
	}
}

func TestUpdateAuthDenials(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	readKey, _ := mkKey(t, n, map[string]interface{}{"db": "default", "scope": "read"})
	dbAdmin, _ := mkKey(t, n, map[string]interface{}{"db": "default", "scope": "admin"})
	mutations := []struct{ method, path, body string }{
		{"PUT", "/v1/updates/apps/redx/source", `{"source":"github"}`},
		{"PUT", "/v1/updates/apps/redx/policy", `{"auto_apply":"off","channel":"stable"}`},
		{"POST", "/v1/updates/apps/redx/apply", `{"version":"1.0.0","source":"host","strategy":"direct"}`},
		{"POST", "/v1/updates/apps/redx/rollback", `{"snapshot_id":"snap_missing"}`},
		{"POST", "/v1/updates/apps/redx/publish", `{"version":"1.0.0","targets":["host"]}`},
		{"POST", "/v1/updates/rollouts/ro_missing/promote", `{}`},
		{"POST", "/v1/updates/rollouts/ro_missing/rollback", `{"reason":"no"}`},
	}
	for _, c := range mutations {
		st, body, _ := do(t, c.method, n.URL+c.path, "", c.body, "Content-Type", "application/json")
		if st != 401 || errCode(t, body) != "forbidden" {
			t.Fatalf("no key %s %s: %d %s", c.method, c.path, st, body)
		}
		for _, key := range []string{readKey, dbAdmin} {
			st, body, _ = do(t, c.method, n.URL+c.path, key, c.body, "Content-Type", "application/json")
			if st != 403 || errCode(t, body) != "forbidden" {
				t.Fatalf("non host-admin %s %s: %d %s", c.method, c.path, st, body)
			}
		}
	}
	reads := []string{
		"/v1/updates/apps",
		"/v1/updates/apps/redx",
		"/v1/updates/apps/redx/history",
		"/v1/updates/apps/redx/snapshots",
		"/v1/updates/apps/redx/manifests/1.0.0",
		"/v1/updates/rollouts/ro_missing",
		"/v1/updates/events",
	}
	for _, p := range reads {
		st, body, _ := do(t, "GET", n.URL+p, "", "")
		if st != 401 || errCode(t, body) != "forbidden" {
			t.Fatalf("read unauth %s: %d %s", p, st, body)
		}
	}
	st, body, _ := do(t, "GET", n.URL+"/v1/updates/apps/redx", readKey, "")
	if st != 200 {
		t.Fatalf("read key status %d %s", st, body)
	}
}

func TestUpdateNotHostedAndPreferences(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	for _, src := range []string{"host", "both"} {
		st, body, _ := do(t, "PUT", n.URL+"/v1/updates/apps/redx/source", n.Key, `{"source":"`+src+`"}`, "Content-Type", "application/json")
		if st != 409 || errCode(t, body) != "not_hosted" {
			t.Fatalf("source %s: %d %s", src, st, body)
		}
	}
	st, body, _ := do(t, "PUT", n.URL+"/v1/updates/apps/redx/source", n.Key, `{"source":"github"}`, "Content-Type", "application/json")
	if st != 200 {
		t.Fatalf("github source %d %s", st, body)
	}
	st, body, _ = do(t, "POST", n.URL+"/v1/updates/apps/redx/apply", n.Key, `{"version":"1.0.0","source":"host","strategy":"direct"}`, "Content-Type", "application/json")
	if st != 409 || errCode(t, body) != "not_hosted" {
		t.Fatalf("apply host unhosted %d %s", st, body)
	}
	st, body, _ = do(t, "PUT", n.URL+"/v1/updates/apps/redx/policy", n.Key, `{"auto_apply":"off","channel":"stable","window":"0 0 1 1 0"}`, "Content-Type", "application/json")
	if st != 200 {
		t.Fatalf("policy %d %s", st, body)
	}
	st, body, _ = do(t, "PUT", n.URL+"/v1/updates/apps/redx/policy", n.Key, `{"auto_apply":"sometimes","channel":"stable"}`, "Content-Type", "application/json")
	if st != 400 || errCode(t, body) != "invalid" {
		t.Fatalf("bad policy %d %s", st, body)
	}
}

func TestUpdatePublishApplyDirectAndSequence(t *testing.T) {
	dir := t.TempDir()
	n := startNode(t, dir, nil)
	publishHost(t, n, "redx", "1.0.0", "First", []string{"+stability"})
	publishHost(t, n, "redx", "1.0.1", "Second security fix", []string{"+security"})

	st, body, hdr := do(t, "GET", n.URL+"/v1/updates/apps/redx/manifests/1.0.1?source=host", n.Key, "")
	if st != 200 {
		t.Fatalf("manifest %d %s", st, body)
	}
	sig := hdr.Get("X-RedX-Signature")
	if !strings.HasPrefix(sig, "ed25519:") {
		t.Fatalf("signature header %q", sig)
	}
	if !strings.Contains(body, `"schema":"redx.update-manifest/v1"`) || !strings.Contains(body, `"certificate":null`) || !strings.Contains(body, `"live_patch":[]`) {
		t.Fatalf("manifest body %s", body)
	}
	if !strings.Contains(body, "RedX 1.0.1 (Linux)") {
		t.Fatalf("label missing: %s", body)
	}
	kst, kbody, _ := do(t, "GET", n.URL+"/v1/updates/keys", "", "")
	if kst != 200 {
		t.Fatal(kbody)
	}
	var keys []struct {
		Pub string `json:"pub"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal([]byte(kbody), &keys) != nil || len(keys) != 1 {
		t.Fatal(kbody)
	}
	if hdr.Get("X-RedX-Key-Id") != keys[0].Kid {
		t.Fatalf("kid %s vs %s", hdr.Get("X-RedX-Key-Id"), keys[0].Kid)
	}
	pub, err := base64.StdEncoding.DecodeString(keys[0].Pub)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sig, "ed25519:"))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(body), raw) {
		t.Fatal("manifest signature does not verify")
	}
	st, sigBody, _ := do(t, "GET", n.URL+"/v1/updates/apps/redx/manifests/1.0.1.sig?source=host", n.Key, "")
	if st != 200 || strings.TrimSpace(sigBody) != sig {
		t.Fatalf("sig file %d %q", st, sigBody)
	}
	st, sigBody, _ = do(t, "GET", n.URL+"/v1/updates/apps/redx/manifests/1.0.1/manifest.sig?source=host", n.Key, "")
	if st != 200 || strings.TrimSpace(sigBody) != sig {
		t.Fatalf("manifest.sig %d %q", st, sigBody)
	}

	st, statusBody, _ := do(t, "GET", n.URL+"/v1/updates/apps/redx", n.Key, "")
	if st != 200 || !strings.Contains(statusBody, `"hosted":true`) || !strings.Contains(statusBody, `"source_pref":"both"`) {
		t.Fatalf("hosted status %d %s", st, statusBody)
	}

	st, applied := applyUpdate(t, n, "redx", "1.0.1", "host", "direct", nil)
	if st != 202 {
		t.Fatalf("apply %d %v", st, applied)
	}
	rollout := applied["rollout_id"].(string)
	snap := applied["snapshot_id"].(string)
	st, body, _ = do(t, "GET", n.URL+"/v1/updates/rollouts/"+rollout, n.Key, "")
	if st != 200 || !strings.Contains(body, `"state":"done"`) {
		t.Fatalf("rollout %d %s", st, body)
	}
	st, body, _ = do(t, "GET", n.URL+"/v1/updates/apps/redx", n.Key, "")
	if st != 200 || !strings.Contains(body, `"version":"1.0.1"`) {
		t.Fatalf("installed %s", body)
	}
	st, body, _ = do(t, "GET", n.URL+"/v1/updates/apps/redx/history", n.Key, "")
	if st != 200 || !strings.Contains(body, "publish") || !strings.Contains(body, "apply") {
		t.Fatalf("history %d %s", st, body)
	}
	st, body, _ = do(t, "GET", n.URL+"/v1/updates/apps/redx/snapshots", n.Key, "")
	if st != 200 || !strings.Contains(body, snap) {
		t.Fatalf("snapshots %d %s", st, body)
	}

	st, body, _ = do(t, "POST", n.URL+"/v1/updates/apps/redx/apply", n.Key, `{"version":"1.0.0","source":"host","strategy":"direct"}`, "Content-Type", "application/json")
	if st != 409 || errCode(t, body) != "sequence_regression" {
		t.Fatalf("regression %d %s", st, body)
	}

	// single-node canary is applied directly
	publishHost(t, n, "redx", "1.0.2", "Third", nil)
	st, applied = applyUpdate(t, n, "redx", "1.0.2", "host", "canary", map[string]int{"percent": 10, "min_minutes": 60})
	if st != 202 {
		t.Fatalf("single canary %d %v", st, applied)
	}
	st, body, _ = do(t, "GET", n.URL+"/v1/updates/rollouts/"+applied["rollout_id"].(string), n.Key, "")
	if st != 200 || !strings.Contains(body, `"state":"done"`) || !strings.Contains(body, `"strategy":"direct"`) {
		t.Fatalf("single canary rollout %s", body)
	}

	audit, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), "update.publish") || !strings.Contains(string(audit), "update.apply") {
		t.Fatalf("audit missing update events")
	}
	keyFile, err := os.ReadFile(filepath.Join(dir, "updates", "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	secret := strings.TrimSpace(string(keyFile))
	if secret != "" && strings.Contains(string(audit), secret) {
		t.Fatal("audit log contains the signing key")
	}
}

func TestUpdateTamperedManifestRefused(t *testing.T) {
	dir := t.TempDir()
	n := startNode(t, dir, nil)
	key := n.Key
	publishHost(t, n, "redx", "1.2.0", "Tamper me", nil)
	n.Stop()

	statePath := filepath.Join(dir, "updates", "state.json")
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]interface{}
	if json.Unmarshal(raw, &st) != nil {
		t.Fatal("state")
	}
	mans := st["manifests"].(map[string]interface{})
	var flipped bool
	for _, v := range mans {
		sm := v.(map[string]interface{})
		body, err := base64.StdEncoding.DecodeString(sm["body"].(string))
		if err != nil || len(body) < 8 {
			t.Fatal(err)
		}
		body[20] ^= 0x1
		sm["body"] = base64.StdEncoding.EncodeToString(body)
		flipped = true
		break
	}
	if !flipped {
		t.Fatal("no manifest")
	}
	out, _ := json.Marshal(st)
	if err := os.WriteFile(statePath, out, 0o600); err != nil {
		t.Fatal(err)
	}
	n2 := startNode(t, dir, nil)
	code, body, _ := do(t, "GET", n2.URL+"/v1/updates/apps/redx/manifests/1.2.0?source=host", key, "")
	if code != 400 || errCode(t, body) != "bad_signature" {
		t.Fatalf("tampered get %d %s", code, body)
	}
}

func TestUpdateCanaryRollbackMidway(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	path := "/v1/path/app.red-xai.db:Cfg.V"
	if st, body, _ := do(t, "PUT", n.URL+path, n.Key, `"before"`); st != 200 {
		t.Fatalf("put before %d %s", st, body)
	}
	publishHost(t, n, "redx", "2.0.0", "Canary", nil)
	host.SetUpdateMembers(n.H, []string{"node-a", "node-b"})
	host.SetUpdateHealth(n.H, 0, 0)
	st, applied := applyUpdate(t, n, "redx", "2.0.0", "host", "canary", map[string]int{"percent": 10, "min_minutes": 60})
	if st != 202 {
		t.Fatalf("canary apply %d %v", st, applied)
	}
	id := applied["rollout_id"].(string)
	st, body, _ := do(t, "GET", n.URL+"/v1/updates/rollouts/"+id, n.Key, "")
	if st != 200 || !strings.Contains(body, `"state":"canary"`) {
		t.Fatalf("canary state %s", body)
	}
	rm := jsonOf(t, body)
	prog := rm["progress"].(map[string]interface{})
	if prog["updated"].(float64) != 1 || prog["total"].(float64) != 2 {
		t.Fatalf("progress %s", body)
	}
	if st, body, _ := do(t, "PUT", n.URL+path, n.Key, `"after"`); st != 200 {
		t.Fatalf("put after %d %s", st, body)
	}
	st, body, _ = do(t, "POST", n.URL+"/v1/updates/apps/redx/apply", n.Key, `{"version":"2.0.0","source":"host","strategy":"direct"}`, "Content-Type", "application/json")
	if st != 409 || errCode(t, body) != "rollout_conflict" {
		t.Fatalf("second apply %d %s", st, body)
	}
	st, body, _ = do(t, "POST", n.URL+"/v1/updates/rollouts/"+id+"/promote", n.Key, `{}`, "Content-Type", "application/json")
	if st != 409 || errCode(t, body) != "rollout_conflict" {
		t.Fatalf("early promote %d %s", st, body)
	}
	st, body, _ = do(t, "POST", n.URL+"/v1/updates/rollouts/"+id+"/rollback", n.Key, `{"reason":"mid-canary"}`, "Content-Type", "application/json")
	if st != 200 || !strings.Contains(body, `"state":"rolled_back"`) {
		t.Fatalf("rollback %d %s", st, body)
	}
	st, body, _ = do(t, "GET", n.URL+path, n.Key, "")
	if st != 200 || !strings.Contains(body, "before") || strings.Contains(body, "after") {
		t.Fatalf("restored value %d %s", st, body)
	}
	st, body, _ = do(t, "GET", n.URL+"/v1/updates/apps/redx", n.Key, "")
	if st != 200 {
		t.Fatalf("status after rollback %d %s", st, body)
	}
	if inst := jsonOf(t, body)["installed"]; inst != nil {
		t.Fatalf("version survived rollback %s", body)
	}
}

func TestUpdatePromoteBlueGreenHealthAndSnapshotFail(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	publishHost(t, n, "redx", "3.0.0", "Blue", nil)
	host.SetUpdateMembers(n.H, []string{"n1", "n2", "n3", "n4"})
	st, applied := applyUpdate(t, n, "redx", "3.0.0", "host", "blue_green", nil)
	if st != 202 {
		t.Fatalf("blue %d %v", st, applied)
	}
	id := applied["rollout_id"].(string)
	st, body, _ := do(t, "GET", n.URL+"/v1/updates/rollouts/"+id, n.Key, "")
	if st != 200 || !strings.Contains(body, `"state":"canary"`) {
		t.Fatalf("blue state %s", body)
	}
	prog := jsonOf(t, body)["progress"].(map[string]interface{})
	if prog["updated"].(float64) != 2 || prog["total"].(float64) != 4 {
		t.Fatalf("blue progress %s", body)
	}
	st, body, _ = do(t, "POST", n.URL+"/v1/updates/rollouts/"+id+"/promote", n.Key, `{}`, "Content-Type", "application/json")
	if st != 200 || !strings.Contains(body, `"state":"done"`) {
		t.Fatalf("promote %d %s", st, body)
	}

	publishHost(t, n, "redx", "3.0.1", "Sick", nil)
	host.SetUpdateHealth(n.H, 0.9, 10)
	st, applied = applyUpdate(t, n, "redx", "3.0.1", "host", "canary", map[string]int{"percent": 25, "min_minutes": 0})
	if st != 202 {
		t.Fatalf("sick apply %d %v", st, applied)
	}
	st, body, _ = do(t, "GET", n.URL+"/v1/updates/rollouts/"+applied["rollout_id"].(string), n.Key, "")
	if st != 200 || !strings.Contains(body, `"state":"rolled_back"`) {
		t.Fatalf("auto rollback %s", body)
	}
	host.SetUpdateHealth(n.H, 0, 0)

	publishHost(t, n, "redx", "3.0.2", "Snap", nil)
	host.SetUpdateSnapshotFail(n.H, true)
	st, body, _ = do(t, "POST", n.URL+"/v1/updates/apps/redx/apply", n.Key,
		`{"version":"3.0.2","source":"host","strategy":"direct"}`, "Content-Type", "application/json")
	if st != 409 || errCode(t, body) != "snapshot_failed" {
		t.Fatalf("snap fail %d %s", st, body)
	}
	host.SetUpdateSnapshotFail(n.H, false)
	st, applied = applyUpdate(t, n, "redx", "3.0.2", "host", "direct", nil)
	if st != 202 {
		t.Fatalf("apply after snap fail %d %v", st, applied)
	}
}

func TestUpdateOwnerGates(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	if !n.H.AccountsEnabled() {
		t.Fatal("accounts should be on")
	}
	publishHost(t, n, "redx", "4.0.0", "Owner", nil)
	st, body, _ := do(t, "POST", n.URL+"/v1/updates/apps/redx/apply", n.Key, `{"version":"4.0.0","source":"host","strategy":"direct"}`, "Content-Type", "application/json")
	if st != 403 || !strings.Contains(body, "only an owner login can do this on this host") {
		t.Fatalf("non-owner apply %d %s", st, body)
	}
	st, body, _ = do(t, "GET", n.URL+"/v1/updates/apps/redxai_accounts", n.Key, "")
	if st != 404 || !strings.Contains(body, "database not found") {
		t.Fatalf("hidden app %d %s", st, body)
	}
	st, body, _ = do(t, "POST", n.URL+"/v1/updates/apps/redxai_accounts/publish", n.Key, `{"version":"1.0.0","channel":"stable","targets":["host"],"notes_md":"x"}`, "Content-Type", "application/json")
	if st != 404 || !strings.Contains(body, "database not found") {
		t.Fatalf("hidden publish %d %s", st, body)
	}
	// source on a normal app is not a topology change and does not snapshot the master database
	st, body, _ = do(t, "PUT", n.URL+"/v1/updates/apps/redx/source", n.Key, `{"source":"both"}`, "Content-Type", "application/json")
	if st != 200 {
		t.Fatalf("source while accounts on %d %s", st, body)
	}
	tok, acct := signIn(t, n, f, ownerOK)
	if acct["owner"] != true {
		t.Fatalf("owner sign-in: %v", acct)
	}
	st, body, _ = do(t, "POST", n.URL+"/v1/updates/apps/redx/apply", tok, `{"version":"4.0.0","source":"host","strategy":"direct"}`, "Content-Type", "application/json")
	if st != 202 {
		t.Fatalf("owner apply %d %s", st, body)
	}
}

func TestUpdateEventsOnAccountsFeed(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	_, acct := signIn(t, n, f, accountsfake.Identity{Sub: "rxa_REGULAR00000000000000000009", Email: "feed@example.com", EmailVerified: true, Username: "feed_user", AMR: []string{"pwd"}})
	sub, _ := acct["sub"].(string)
	wsURL := "ws" + strings.TrimPrefix(n.URL, "http") + "/v1/updates/events"
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+n.Key)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, hdr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	f.AddEvent("account.banned", sub)
	f.Add(accountsfake.Event{Type: "update.available", App: "widget", Version: "9.1.0", Source: "github"})
	ended, err := n.H.PollAccountEventsNow(context.Background())
	if err != nil || ended != 1 {
		t.Fatalf("poll ended=%d err=%v", ended, err)
	}
	var ev struct {
		Type    string `json:"type"`
		App     string `json:"app"`
		Version string `json:"version"`
		Source  string `json:"source"`
	}
	if err := conn.ReadJSON(&ev); err != nil {
		t.Fatal(err)
	}
	if ev.Type != "update.available" || ev.App != "widget" || ev.Version != "9.1.0" || ev.Source != "github" {
		t.Fatalf("forwarded event %+v", ev)
	}
	ended, err = n.H.PollAccountEventsNow(context.Background())
	if err != nil || ended != 0 {
		t.Fatalf("second poll ended=%d err=%v", ended, err)
	}
}

func TestUpdateGitHubWebhookAndEvents(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "hook.secret")
	const secret = "hook-secret-value"
	if err := os.WriteFile(secretPath, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	n := startNode(t, dir, func(c *host.Config, _ string) {
		c.GithubWebhookSecretFile = secretPath
	})
	host.SetUpdateAllowLoopback(n.H, true)

	payload := []byte(`{"action":"published","repository":{"full_name":"acme/widget"},"release":{"tag_name":"v9.9.9","body":"no sums"}}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	good := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	st, body, _ := do(t, "POST", n.URL+"/v1/updates/github/webhook", "", string(payload), "Content-Type", "application/json", "X-Hub-Signature-256", "sha256=00", "X-GitHub-Event", "release")
	if st != 401 || errCode(t, body) != "bad_signature" {
		t.Fatalf("bad hmac %d %s", st, body)
	}

	// missing SUMS with a real commit still refuses to sign
	commit := strings.Repeat("ab", 20)
	payload = []byte(`{"action":"published","repository":{"full_name":"acme/widget"},"release":{"id":7,"tag_name":"v1.4.0","body":"Security fix","target_commitish":"` + commit + `","assets":[{"name":"widget-1.4.0-linux-amd64.tar.gz","browser_download_url":"http://127.0.0.1/nope"}]}}`)
	mac = hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	st, body, _ = do(t, "POST", n.URL+"/v1/updates/github/webhook", "", string(payload), "Content-Type", "application/json", "X-Hub-Signature-256", sig, "X-GitHub-Event", "release")
	if st != 400 || errCode(t, body) != "bad_signature" {
		t.Fatalf("missing sums %d %s", st, body)
	}

	blob := []byte("artifact-bytes")
	sum := sha256.Sum256(blob)
	sumHex := hex.EncodeToString(sum[:])
	sums := sumHex + "  widget-1.4.0-linux-amd64.tar.gz\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/SHA256SUMS":
			_, _ = w.Write([]byte(sums))
		case "/widget-1.4.0-linux-amd64.tar.gz":
			_, _ = w.Write(blob)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	badSums := strings.Repeat("ab", 32) + "  widget-1.4.0-linux-amd64.tar.gz\n"
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/SHA256SUMS" {
			_, _ = w.Write([]byte(badSums))
			return
		}
		_, _ = w.Write(blob)
	}))
	defer badSrv.Close()

	badPayload := []byte(`{"action":"published","repository":{"full_name":"acme/widget"},"release":{"id":8,"tag_name":"v1.4.1","body":"bad","target_commitish":"` + commit + `","assets":[{"name":"SHA256SUMS","browser_download_url":"` + badSrv.URL + `/SHA256SUMS"},{"name":"widget-1.4.0-linux-amd64.tar.gz","browser_download_url":"` + badSrv.URL + `/widget-1.4.0-linux-amd64.tar.gz"}]}}`)
	mac = hmac.New(sha256.New, []byte(secret))
	mac.Write(badPayload)
	st, body, _ = do(t, "POST", n.URL+"/v1/updates/github/webhook", "", string(badPayload), "Content-Type", "application/json", "X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)), "X-GitHub-Event", "release")
	if st != 400 || errCode(t, body) != "bad_signature" {
		t.Fatalf("bad sums %d %s", st, body)
	}
	st, body, _ = do(t, "GET", n.URL+"/v1/updates/apps/widget/manifests/1.4.1?source=github", n.Key, "")
	if st != 404 {
		t.Fatalf("signed despite bad sums %d %s", st, body)
	}

	wsURL := "ws" + strings.TrimPrefix(n.URL, "http") + "/v1/updates/events"
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+n.Key)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, hdr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	goodPayload := []byte(`{"action":"published","repository":{"full_name":"acme/widget"},"release":{"id":9,"tag_name":"v1.4.2","body":"Security fix","target_commitish":"` + commit + `","assets":[{"name":"SHA256SUMS","browser_download_url":"` + srv.URL + `/SHA256SUMS"},{"name":"widget-1.4.0-linux-amd64.tar.gz","browser_download_url":"` + srv.URL + `/widget-1.4.0-linux-amd64.tar.gz"}]}}`)
	mac = hmac.New(sha256.New, []byte(secret))
	mac.Write(goodPayload)
	st, body, _ = do(t, "POST", n.URL+"/v1/updates/github/webhook", "", string(goodPayload), "Content-Type", "application/json", "X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)), "X-GitHub-Event", "release")
	if st != 202 {
		t.Fatalf("webhook %d %s", st, body)
	}
	st, manBody, mhdr := do(t, "GET", n.URL+"/v1/updates/apps/widget/manifests/1.4.2?source=github", n.Key, "")
	if st != 200 || !strings.HasPrefix(mhdr.Get("X-RedX-Signature"), "ed25519:") || !strings.Contains(manBody, `"kind":"github"`) {
		t.Fatalf("github manifest %d %s", st, manBody)
	}
	if !strings.Contains(manBody, commit) || strings.Contains(manBody, zeroCommit()) {
		t.Fatalf("commit %s", manBody)
	}
	var ev struct {
		Type string `json:"type"`
		App  string `json:"app"`
	}
	if err := conn.ReadJSON(&ev); err != nil {
		t.Fatal(err)
	}
	if ev.Type != "update.available" || ev.App != "widget" {
		t.Fatalf("event %+v", ev)
	}
	st, art, ah := do(t, "GET", n.URL+"/v1/updates/widget/1.4.2/artifacts/widget-1-4-0-linux-amd64?source=github", n.Key, "")
	if st != 200 || art != string(blob) {
		t.Fatalf("short artifact %d %q", st, art)
	}
	if ah.Get("X-Redx-SHA256") != sumHex {
		t.Fatalf("artifact hash %s", ah.Get("X-Redx-SHA256"))
	}

	audit, _ := os.ReadFile(filepath.Join(dir, "audit.log"))
	if strings.Contains(string(audit), secret) {
		t.Fatal("audit contains the webhook secret")
	}
	if !strings.Contains(string(audit), "update.webhook") {
		t.Fatal("webhook was not audited")
	}

	// unconfigured secret
	n2 := startNode(t, t.TempDir(), nil)
	st, body, _ = do(t, "POST", n2.URL+"/v1/updates/github/webhook", "", `{}`, "Content-Type", "application/json", "X-Hub-Signature-256", good, "X-GitHub-Event", "release")
	if st != 503 || errCode(t, body) != "forbidden" {
		t.Fatalf("no secret %d %s", st, body)
	}
}

func zeroCommit() string { return strings.Repeat("0", 40) }
