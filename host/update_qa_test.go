package host_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"redx/host"
)

func TestUpdateQABlockers(t *testing.T) {
	t.Run("B1", testNoDowngrade)
	t.Run("B2", testRestoreStaysInApp)
	t.Run("B3", testPublishOwnerAndAllowlist)
	t.Run("B4", testWebhookAllowlistReplayEdited)
	t.Run("B5", testConfirmArityAndToken)
	t.Run("B6", testHealthUnknown)
	t.Run("B7", testStatusHidesBadSignature)
	t.Run("B8", testSnapshotHash)
	t.Run("B9", testDryRunAndRetention)
	t.Run("B10", testUpdateReadsNeedHostAdmin)
}

func testNoDowngrade(t *testing.T) {
	n := startNode(t, t.TempDir(), func(c *host.Config, _ string) { hostUpdate(c) })
	publishHost(t, n, "redx", "1.0.0", "first", nil)
	publishHost(t, n, "redx", "1.1.0", "second", nil)
	if st, _ := applyUpdate(t, n, "redx", "1.1.0", "host", "direct", nil); st != 202 {
		t.Fatalf("apply 1.1.0: %d", st)
	}
	st, body, _ := do(t, "GET", n.URL+"/v1/updates/apps/redx/manifests/1.0.0?source=host", n.Key, "")
	if st != 200 || !strings.Contains(body, `"sequence":1`) {
		t.Fatalf("1.0.0 sequence: %d %s", st, body)
	}
	publishHost(t, n, "redx", "1.0.0", "republish must not mint a sequence", nil)
	st, body, _ = do(t, "GET", n.URL+"/v1/updates/apps/redx/manifests/1.0.0?source=host", n.Key, "")
	if st != 200 || !strings.Contains(body, `"sequence":1`) || strings.Contains(body, "republish must not") {
		t.Fatalf("republish changed the signed manifest: %s", body)
	}
	st, body, _ = do(t, "POST", n.URL+"/v1/updates/apps/redx/apply", n.Key, `{"version":"1.0.0","source":"host","strategy":"direct"}`, "Content-Type", "application/json")
	if st != 409 || errCode(t, body) != "sequence_regression" {
		t.Fatalf("downgrade %d %s", st, body)
	}
	st, body, _ = do(t, "GET", n.URL+"/v1/updates/apps/redx", n.Key, "")
	status := jsonOf(t, body)
	latest := status["latest"].(map[string]interface{})["host"].(map[string]interface{})
	if latest["version"] != "1.1.0" {
		t.Fatalf("latest advertised %v", latest)
	}
	for _, row := range status["available"].([]interface{}) {
		if row.(map[string]interface{})["version"] == "1.0.0" {
			t.Fatalf("older version advertised: %s", body)
		}
	}
	b, _ := json.Marshal(map[string]interface{}{
		"version": "2.0.0", "channel": "stable", "notes_md": "needs 1.5", "outcome_tags": []string{"+security"},
		"targets": []string{"host"}, "min_from": "1.5.0",
		"artifacts": []map[string]string{{"filename": "redx-2.0.0-linux-amd64.tar.gz", "os": "linux", "arch": "amd64", "kind": "tar.gz"}},
	})
	if st, body := withPermit(t, n, n.Key, "POST", "/v1/updates/apps/redx/publish", string(b)); st != 201 {
		t.Fatalf("publish min_from %d %s", st, body)
	}
	st, got := applyUpdate(t, n, "redx", "2.0.0", "host", "direct", nil)
	if st != 409 || !strings.Contains(got["raw"].(string), "min_from") {
		t.Fatalf("min_from %d %v", st, got)
	}
}

func testRestoreStaysInApp(t *testing.T) {
	dir := t.TempDir()
	n := startNode(t, dir, func(c *host.Config, _ string) { hostUpdate(c) })
	if st, body, _ := do(t, "POST", n.URL+"/v1/dbs", n.Key, `{"name":"redx"}`, "Content-Type", "application/json"); st != 201 {
		t.Fatalf("db %d %s", st, body)
	}
	if st, body, _ := do(t, "POST", n.URL+"/v1/dbs", n.Key, `{"name":"other"}`, "Content-Type", "application/json"); st != 201 {
		t.Fatalf("other %d %s", st, body)
	}
	put := func(url, val string) {
		t.Helper()
		if st, body, _ := do(t, "PUT", n.URL+url, n.Key, val); st != 200 {
			t.Fatalf("put %s %d %s", url, st, body)
		}
	}
	put("/v1/db/redx/path/app.red-xai.db:V", `"before"`)
	publishHost(t, n, "redx", "1.0.0", "snap", nil)
	st, applied := applyUpdate(t, n, "redx", "1.0.0", "host", "direct", nil)
	if st != 202 {
		t.Fatalf("apply %d %v", st, applied)
	}
	snap := applied["snapshot_id"].(string)
	key, id := mkKey(t, n, map[string]interface{}{"db": "*", "scope": "admin", "label": "doomed"})
	if st, body, _ := do(t, "DELETE", n.URL+"/v1/keys/"+id, n.Key, ""); st != 200 {
		t.Fatalf("revoke %d %s", st, body)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/updates/apps/redx", key, ""); st != 401 {
		t.Fatalf("revoked key still works: %d", st)
	}
	put("/v1/db/redx/path/app.red-xai.db:V", `"after"`)
	put("/v1/db/other/path/app.red-xai.db:V", `"kept"`)
	markerDir := filepath.Join(dir, "dbs", "redxai_accounts")
	if err := os.MkdirAll(markerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(markerDir, "marker"), []byte("BANNED"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st, body := withPermit(t, n, n.Key, "POST", "/v1/updates/apps/redx/rollback", `{"snapshot_id":"`+snap+`"}`); st != 200 {
		t.Fatalf("restore %d %s", st, body)
	}
	if st, body, _ := do(t, "GET", n.URL+"/v1/db/redx/path/app.red-xai.db:V", n.Key, ""); st != 200 || !strings.Contains(body, "before") || strings.Contains(body, "after") {
		t.Fatalf("app data %d %s", st, body)
	}
	if st, body, _ := do(t, "GET", n.URL+"/v1/db/other/path/app.red-xai.db:V", n.Key, ""); st != 200 || !strings.Contains(body, "kept") {
		t.Fatalf("other db %d %s", st, body)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/updates/apps/redx", key, ""); st != 401 {
		t.Fatalf("revoked key returned after restore: %d", st)
	}
	banned, err := os.ReadFile(filepath.Join(dir, "dbs", "redxai_accounts", "marker"))
	if err != nil || string(banned) != "BANNED" {
		t.Fatalf("master marker %q %v", banned, err)
	}
	names := archiveNames(t, filepath.Join(dir, "updates", "snapshots", snap+".tgz"))
	for _, name := range names {
		low := strings.ToLower(name)
		if strings.Contains(low, "key") || strings.Contains(name, "redxai_accounts") || strings.Contains(name, "other") {
			t.Fatalf("snapshot contains %s (%v)", name, names)
		}
	}
}

func testPublishOwnerAndAllowlist(t *testing.T) {
	f, iss := startFake(t)
	hits := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Error(w, "no", 500)
	}))
	defer api.Close()
	n := startNode(t, t.TempDir(), func(c *host.Config, _ string) {
		hostUpdate(c)
		c.AccountsIssuer = iss
		c.AccountsClientSecret = "test-client-secret"
		c.AccountsEventsPoll = 3600
		c.OwnerEmails = []string{ownerA, ownerB}
	})
	host.SetUpdateGitHubAPI(n.H, api.URL)
	body := `{"version":"4.0.2","channel":"stable","targets":["host"],"notes_md":"x","outcome_tags":["+security"]}`
	st, resp, _ := do(t, "POST", n.URL+"/v1/updates/apps/redx/publish", n.Key, body, "Content-Type", "application/json")
	if st != 403 || !strings.Contains(resp, "only an owner login") {
		t.Fatalf("non-owner publish %d %s", st, resp)
	}
	st, resp, _ = do(t, "POST", n.URL+"/v1/updates/apps/redx/publish", n.Key, `{"version":"4.0.2","channel":"stable","targets":["github"],"notes_md":"x","outcome_tags":["+security"]}`, "Content-Type", "application/json")
	if st != 403 || hits != 0 {
		t.Fatalf("non-owner github publish %d hits=%d %s", st, hits, resp)
	}
	tok, _ := signIn(t, n, f, ownerOK)
	st, resp = withPermit(t, n, tok, "POST", "/v1/updates/apps/notlisted/publish", body)
	if st != 409 || errCode(t, resp) != "not_hosted" {
		t.Fatalf("unlisted %d %s", st, resp)
	}
	evil := `{"version":"4.0.3","channel":"stable","targets":["host"],"notes_md":"x","outcome_tags":["+security"],"artifacts":[{"filename":"a.tar.gz","os":"linux","arch":"amd64","kind":"tar.gz","upload_url":"https://gist.githubusercontent.com/evil/a.tar.gz","sha256":"` + strings.Repeat("ab", 32) + `"}]}`
	st, resp = withPermit(t, n, tok, "POST", "/v1/updates/apps/redx/publish", evil)
	if st != 400 || !strings.Contains(resp, "refused artifact url") {
		t.Fatalf("open artifact url %d %s", st, resp)
	}
	if hits != 0 {
		t.Fatal("github api was called")
	}
}

func testWebhookAllowlistReplayEdited(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "hook.secret")
	const secret = "hook-secret-value"
	if err := os.WriteFile(secretPath, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	n := startNode(t, dir, func(c *host.Config, _ string) {
		hostUpdate(c)
		c.GithubWebhookSecretFile = secretPath
	})
	host.SetUpdateAllowLoopback(n.H, true)
	if st, body, _ := do(t, "PUT", n.URL+"/v1/updates/apps/redx/policy", n.Key, `{"auto_apply":"all","channel":"stable"}`, "Content-Type", "application/json"); st != 200 {
		t.Fatalf("policy %d %s", st, body)
	}
	blob := []byte("bytes")
	sum := sha256.Sum256(blob)
	sumHex := hex.EncodeToString(sum[:])
	commit := strings.Repeat("cd", 20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/SHA256SUMS") {
			_, _ = io.WriteString(w, sumHex+"  redx.tar.gz\n")
			return
		}
		_, _ = w.Write(blob)
	}))
	defer srv.Close()
	post := func(delivery, payload string) (int, string) {
		t.Helper()
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(payload))
		st, body, _ := do(t, "POST", n.URL+"/v1/updates/github/webhook", "", payload, "Content-Type", "application/json",
			"X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)), "X-GitHub-Event", "release", "X-GitHub-Delivery", delivery)
		return st, body
	}
	evil := `{"action":"published","repository":{"full_name":"evil-org/redx"},"release":{"tag_name":"v0.0.1","target_commitish":"` + commit + `"}}`
	if st, body := post("evil-1", evil); st != 403 {
		t.Fatalf("evil repo %d %s", st, body)
	}
	payload := func(action, tag, repo string) string {
		rel := "/" + repo + "/releases/download/" + tag + "/"
		return `{"action":"` + action + `","repository":{"full_name":"` + repo + `"},"release":{"id":1,"tag_name":"` + tag + `","body":"notes","target_commitish":"` + commit + `","assets":[{"name":"SHA256SUMS","browser_download_url":"` + srv.URL + rel + `SHA256SUMS"},{"name":"redx.tar.gz","browser_download_url":"` + srv.URL + rel + `redx.tar.gz"}]}}`
	}
	// acme/redx is mapped to app redx. Use a release path the allowlist accepts.
	if st, body := post("rel-045", payload("published", "v0.4.5", "acme/redx")); st != 202 {
		t.Fatalf("install 0.4.5 %d %s", st, body)
	}
	st, body, _ := do(t, "GET", n.URL+"/v1/updates/apps/redx", n.Key, "")
	if st != 200 || !strings.Contains(body, `"version":"0.4.5"`) {
		t.Fatalf("not installed: %d %s", st, body)
	}
	if st, body := post("rel-045", payload("published", "v0.4.5", "acme/redx")); st != 409 || !strings.Contains(body, "replayed") {
		t.Fatalf("replay %d %s", st, body)
	}
	if st, body := post("edit-044", payload("edited", "v0.4.4", "acme/redx")); st != 202 || !strings.Contains(body, "skipped") {
		t.Fatalf("edited downgrade %d %s", st, body)
	}
	st, body, _ = do(t, "GET", n.URL+"/v1/updates/apps/redx", n.Key, "")
	if strings.Contains(body, "0.4.4") || !strings.Contains(body, `"version":"0.4.5"`) {
		t.Fatalf("status after edited: %s", body)
	}
}

func testConfirmArityAndToken(t *testing.T) {
	n := startNode(t, t.TempDir(), func(c *host.Config, _ string) { hostUpdate(c) })
	publishHost(t, n, "redx", "1.0.0", "tok", nil)
	publishHost(t, n, "redx", "1.0.1", "other", nil)
	for _, p := range []string{"/v1/updates/apps/redx/apply/x", "/v1/updates/apps/redx/publish/x", "/v1/updates/apps/redx/rollback/x"} {
		st, body, _ := do(t, "POST", n.URL+p, n.Key, `{}`, "Content-Type", "application/json", host.ConfirmHeader, "")
		if st != 404 {
			t.Fatalf("%s %d %s", p, st, body)
		}
	}
	st, body, _ := do(t, "POST", n.URL+"/v1/updates/apps/redx/apply", n.Key, `{"version":"1.0.0","source":"host","strategy":"direct"}`, "Content-Type", "application/json")
	if st != 403 || errCode(t, body) != "forbidden" {
		t.Fatalf("static confirm alone %d %s", st, body)
	}
	plan := `{"version":"1.0.0","source":"host","strategy":"direct","plan":true}`
	st, body, _ = do(t, "POST", n.URL+"/v1/updates/apps/redx/apply", n.Key, plan, "Content-Type", "application/json")
	if st != 200 {
		t.Fatalf("plan %d %s", st, body)
	}
	tok := jsonOf(t, body)["confirm"].(string)
	st, body, _ = do(t, "POST", n.URL+"/v1/updates/apps/redx/apply", n.Key, `{"version":"1.0.1","source":"host","strategy":"direct"}`, "Content-Type", "application/json", host.UpdateConfirmHeader, tok)
	if st != 403 {
		t.Fatalf("wrong version %d %s", st, body)
	}
	// A failed snapshot still consumes the token, and the version stays uninstalled,
	// so a second use is a confirmation failure rather than a sequence regression.
	host.SetUpdateSnapshotFail(n.H, true)
	st, body, _ = do(t, "POST", n.URL+"/v1/updates/apps/redx/apply", n.Key, plan, "Content-Type", "application/json")
	if st != 200 {
		t.Fatalf("plan before snap fail %d %s", st, body)
	}
	once := jsonOf(t, body)["confirm"].(string)
	st, body, _ = do(t, "POST", n.URL+"/v1/updates/apps/redx/apply", n.Key, `{"version":"1.0.0","source":"host","strategy":"direct"}`, "Content-Type", "application/json", host.UpdateConfirmHeader, once)
	if st != 409 || errCode(t, body) != "snapshot_failed" {
		t.Fatalf("snap fail %d %s", st, body)
	}
	st, body, _ = do(t, "POST", n.URL+"/v1/updates/apps/redx/apply", n.Key, `{"version":"1.0.0","source":"host","strategy":"direct"}`, "Content-Type", "application/json", host.UpdateConfirmHeader, once)
	if st != 403 || errCode(t, body) != "forbidden" {
		t.Fatalf("reused token %d %s", st, body)
	}
	host.SetUpdateSnapshotFail(n.H, false)
	host.SetUpdatePermitTTL(n.H, time.Millisecond)
	st, body, _ = do(t, "POST", n.URL+"/v1/updates/apps/redx/apply", n.Key, plan, "Content-Type", "application/json")
	if st != 200 {
		t.Fatalf("short plan %d %s", st, body)
	}
	short := jsonOf(t, body)["confirm"].(string)
	time.Sleep(5 * time.Millisecond)
	st, body, _ = do(t, "POST", n.URL+"/v1/updates/apps/redx/apply", n.Key, `{"version":"1.0.0","source":"host","strategy":"direct"}`, "Content-Type", "application/json", host.UpdateConfirmHeader, short)
	if st != 403 {
		t.Fatalf("expired token %d %s", st, body)
	}
	host.SetUpdatePermitTTL(n.H, 0)
	if st, applied := applyUpdate(t, n, "redx", "1.0.0", "host", "direct", nil); st != 202 {
		t.Fatalf("good apply %d %v", st, applied)
	}
}

func testHealthUnknown(t *testing.T) {
	n := startNode(t, t.TempDir(), func(c *host.Config, _ string) { hostUpdate(c) })
	publishHost(t, n, "redx", "1.0.0", "health", nil)
	host.SetUpdateMembers(n.H, []string{"a", "b"})
	host.ClearUpdateHealth(n.H)
	host.ResetUpdateMetrics(n.H)
	st, applied := applyUpdate(t, n, "redx", "1.0.0", "host", "canary", map[string]int{"percent": 10, "min_minutes": 60})
	if st != 202 {
		t.Fatalf("canary %d %v", st, applied)
	}
	host.ResetUpdateMetrics(n.H)
	st, body, _ := do(t, "GET", n.URL+"/v1/updates/rollouts/"+applied["rollout_id"].(string), n.Key, "")
	if st != 200 || !strings.Contains(body, `"status":"unknown"`) || strings.Contains(body, `"error_rate":0`) || strings.Contains(body, `"p95_ms":0`) {
		t.Fatalf("health %s", body)
	}
	if strings.Contains(body, `"state":"done"`) || strings.Contains(body, `"state":"rolled_back"`) {
		t.Fatalf("unknown health changed the rollout: %s", body)
	}
}

func testStatusHidesBadSignature(t *testing.T) {
	dir := t.TempDir()
	n := startNode(t, dir, func(c *host.Config, _ string) { hostUpdate(c) })
	key := n.Key
	publishHost(t, n, "redx", "1.2.1", "hide me", nil)
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
	for _, v := range st["manifests"].(map[string]interface{}) {
		sm := v.(map[string]interface{})
		sm["sig"] = "ed25519:" + strings.Repeat("A", 88)
	}
	out, _ := json.Marshal(st)
	if err := os.WriteFile(statePath, out, 0o600); err != nil {
		t.Fatal(err)
	}
	n2 := startNode(t, dir, func(c *host.Config, _ string) { hostUpdate(c) })
	code, body, _ := do(t, "GET", n2.URL+"/v1/updates/apps/redx", key, "")
	if code != 200 || strings.Contains(body, "1.2.1") {
		t.Fatalf("bad signature still listed: %d %s", code, body)
	}
}

func testSnapshotHash(t *testing.T) {
	dir := t.TempDir()
	n := startNode(t, dir, func(c *host.Config, _ string) { hostUpdate(c) })
	if st, body, _ := do(t, "POST", n.URL+"/v1/dbs", n.Key, `{"name":"redx"}`, "Content-Type", "application/json"); st != 201 {
		t.Fatalf("db %d %s", st, body)
	}
	if st, body, _ := do(t, "PUT", n.URL+"/v1/db/redx/path/app.red-xai.db:V", n.Key, `"before"`); st != 200 {
		t.Fatalf("put %d %s", st, body)
	}
	publishHost(t, n, "redx", "1.0.0", "hash", nil)
	st, applied := applyUpdate(t, n, "redx", "1.0.0", "host", "direct", nil)
	if st != 202 {
		t.Fatalf("apply %d %v", st, applied)
	}
	snap := applied["snapshot_id"].(string)
	path := filepath.Join(dir, "updates", "snapshots", snap+".tgz")
	b, err := os.ReadFile(path)
	if err != nil || len(b) < 8 {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 0x1
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if st, body, _ := do(t, "PUT", n.URL+"/v1/db/redx/path/app.red-xai.db:V", n.Key, `"after"`); st != 200 {
		t.Fatalf("after %d %s", st, body)
	}
	code, body := withPermit(t, n, n.Key, "POST", "/v1/updates/apps/redx/rollback", `{"snapshot_id":"`+snap+`"}`)
	if code != 409 || errCode(t, body) != "snapshot_failed" {
		t.Fatalf("hash %d %s", code, body)
	}
	code, body, _ = do(t, "GET", n.URL+"/v1/db/redx/path/app.red-xai.db:V", n.Key, "")
	if code != 200 || !strings.Contains(body, "after") {
		t.Fatalf("tampered snapshot was applied: %s", body)
	}
}

func testDryRunAndRetention(t *testing.T) {
	dir := t.TempDir()
	n := startNode(t, dir, func(c *host.Config, _ string) { hostUpdate(c) })
	publishHost(t, n, "redx", "1.0.0", "dry", nil)
	st, body, _ := do(t, "POST", n.URL+"/v1/updates/apps/redx/apply", n.Key, `{"version":"1.0.0","source":"host","strategy":"direct","dry_run":true}`, "Content-Type", "application/json")
	if st != 200 || jsonOf(t, body)["confirm"] == "" {
		t.Fatalf("dry run %d %s", st, body)
	}
	if ents, _ := os.ReadDir(filepath.Join(dir, "updates", "snapshots")); len(ents) != 0 {
		t.Fatalf("dry run wrote %d snapshots", len(ents))
	}
	for i := 1; i <= 6; i++ {
		ver := "1.0." + string(rune('0'+i))
		publishHost(t, n, "redx", ver, "keep", nil)
		if st, got := applyUpdate(t, n, "redx", ver, "host", "direct", nil); st != 202 {
			t.Fatalf("apply %s %d %v", ver, st, got)
		}
	}
	ents, err := os.ReadDir(filepath.Join(dir, "updates", "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) > 5 {
		t.Fatalf("kept %d snapshots", len(ents))
	}
}

func testUpdateReadsNeedHostAdmin(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	if st, _, _ := do(t, "GET", n.URL+"/v1/updates/keys", "", ""); st != 200 {
		t.Fatalf("keys %d", st)
	}
	readKey, _ := mkKey(t, n, map[string]interface{}{"db": "default", "scope": "read"})
	if st, body, _ := do(t, "GET", n.URL+"/v1/updates/apps/redx", readKey, ""); st != 403 {
		t.Fatalf("read key %d %s", st, body)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/updates/apps/redx", n.Key, ""); st != 200 {
		t.Fatalf("host admin %d", st)
	}
}

func archiveNames(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
	}
	return names
}
