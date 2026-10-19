package host_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"redx/host"
)

type pkce struct{ verifier, challenge, state string }

func newPKCE(i int) pkce {
	v := fmt.Sprintf("verifier-%03d-%s", i, strings.Repeat("abcdefghij", 5))
	d := sha256.Sum256([]byte(v))
	return pkce{verifier: v, challenge: base64.RawURLEncoding.EncodeToString(d[:]), state: fmt.Sprintf("state%03d%s", i, strings.Repeat("Zz09_-", 6))}
}

func cjson(t *testing.T, s string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("not JSON: %s", s)
	}
	return m
}

var jsonHdr = []string{"Content-Type", "application/json"}

func cpost(t *testing.T, n *node, path, key, body string, hdr ...string) (int, map[string]interface{}) {
	t.Helper()
	st, b, _ := do(t, "POST", n.URL+path, key, body, append(append([]string{}, jsonHdr...), hdr...)...)
	return st, cjson(t, b)
}

// startConnect mimics the console: it read the link and calls start with the admin key.
func startConnect(t *testing.T, n *node, p pkce, extra string) map[string]interface{} {
	t.Helper()
	body := fmt.Sprintf(`{"v":1,"state":%q,"pkce_challenge":%q,"callback":"rottenapple://redx-callback"%s}`, p.state, p.challenge, extra)
	st, out := cpost(t, n, "/v1/connect/start", n.Key, body)
	if st != 201 && st != 200 {
		t.Fatalf("start %d %v", st, out)
	}
	return out
}

func approve(t *testing.T, n *node, id string, extra string) map[string]interface{} {
	t.Helper()
	st, out := cpost(t, n, "/v1/connect/approve", n.Key, fmt.Sprintf(`{"request_id":%q%s}`, id, extra))
	if st != 200 {
		t.Fatalf("approve %d %v", st, out)
	}
	return out
}

func exchange(t *testing.T, n *node, code string, p pkce, extra string) (int, map[string]interface{}) {
	t.Helper()
	return cpost(t, n, "/v1/connect/exchange", "", fmt.Sprintf(`{"code":%q,"pkce_verifier":%q,"state":%q,"device_label":"test laptop"%s}`, code, p.verifier, p.state, extra))
}

const launcherApp = `,"provider":"rottenapple-launcher","app":"com.acme.stardrift","scope":"write","prefix":"saves","label":"app:com.acme.stardrift","name":"Rotten Apple"`

func TestConnectHappyPathRottenAppleLauncher(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	p := newPKCE(1)
	ws := host.AppWorkspaceName("com.acme.stardrift")
	s := startConnect(t, n, p, launcherApp)
	id := s["request_id"].(string)
	prov := s["provider"].(map[string]interface{})
	if prov["display"] != "Rotten Apple launcher" || prov["verified"] != true || prov["callback_ok"] != true || s["defaults"].(map[string]interface{})["workspace"] != ws {
		t.Fatalf("start: %v", s)
	}
	// the same link fired again (after an install): same request
	if again := startConnect(t, n, p, launcherApp); again["request_id"] != id {
		t.Fatal("start must dedupe on (provider, app, state)")
	}
	st, b, _ := do(t, "GET", n.URL+"/v1/connect/pending", n.Key, "")
	if st != 200 || !strings.Contains(b, ws) || strings.Contains(b, id) {
		t.Fatalf("pending (must not list request ids): %d %s", st, b)
	}
	a := approve(t, n, id, "")
	code := a["code"].(string)
	if a["deliver"] != "callback" || !strings.HasPrefix(a["callback_template"].(string), "rottenapple://redx-callback?code="+code+"&state={state}&host=") {
		t.Fatalf("approve: %v", a)
	}
	st, x := exchange(t, n, code, p, "")
	if st != 200 {
		t.Fatalf("exchange %d %v", st, x)
	}
	key := x["key"].(string)
	if x["scope"] != "write" || x["prefix"] != "saves" || x["workspace"].(map[string]interface{})["db"] != ws || !strings.HasPrefix(key, "rx_live_") || x["api"] != "v1" {
		t.Fatalf("exchange body: %v", x)
	}
	// least privilege: its own workspace, its own prefix, nothing else
	if st, b, _ := do(t, "PUT", n.URL+"/v1/db/"+ws+"/path/saves.red-xai.db:Save[ID=1].Slot", key, `"a"`); st != 200 {
		t.Fatalf("own prefix write %d %s", st, b)
	}
	for _, c := range []struct{ m, u, body string }{
		{"PUT", "/v1/db/" + ws + "/path/other.red-xai.db:Save[ID=1].Slot", `"x"`},
		{"GET", "/v1/db/default/path/x.red-xai.db:B[ID=1]", ""},
		{"POST", "/v1/dbs", `{"name":"evil"}`},
		{"GET", "/v1/keys", ""},
		{"GET", "/v1/connect/apps", ""},
	} {
		if st, _, _ := do(t, c.m, n.URL+c.u, key, c.body); st != 403 {
			t.Fatalf("%s %s with the app key: want 403, got %d", c.m, c.u, st)
		}
	}
	st, b, _ = do(t, "GET", n.URL+"/v1/connect/apps", n.Key, "")
	if st != 200 || !strings.Contains(b, x["key_id"].(string)) || !strings.Contains(b, "com.acme.stardrift") {
		t.Fatalf("apps %d %s", st, b)
	}
	// nothing secret at rest or in the audit log
	raw, _ := os.ReadFile(filepath.Join(n.Dir, "connect", "connect.json"))
	audit, _ := os.ReadFile(n.H.Cfg.AuditLog)
	for _, sec := range []string{id, code, p.state, p.verifier, key} {
		if strings.Contains(string(raw), sec) || strings.Contains(string(audit), sec) {
			t.Fatal("a request id, state, code, verifier or key was stored in plain text")
		}
	}
	if fi, err := os.Stat(filepath.Join(n.Dir, "connect", "connect.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("connect.json must be 0600: %v %v", fi, err)
	}
}

func TestConnectReplayOfCodeAndGrantRefused(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	p := newPKCE(2)
	id := startConnect(t, n, p, `,"provider":"gendragoon","callback":"gendragoon://redx-callback"`)["request_id"].(string)
	code := approve(t, n, id, "")["code"].(string)
	st, x := exchange(t, n, code, p, `,"provider_grant":"gdg_one_time_123"`)
	if st != 200 || x["storage"].(map[string]interface{})["status"] != "pending-provider-grant" {
		t.Fatalf("exchange %d %v", st, x)
	}
	if st, x := exchange(t, n, code, p, ""); st != 409 || x["code"] != "code_used" || x["key"] != nil {
		t.Fatalf("replayed code: %d %v", st, x)
	}
	// approving the finished request again cannot mint a new code
	if st, x := cpost(t, n, "/v1/connect/approve", n.Key, fmt.Sprintf(`{"request_id":%q}`, id)); st != 410 || x["code"] != "code_used" {
		t.Fatalf("re-approve finished request: %d %v", st, x)
	}
	// a provider_grant works once
	p2 := newPKCE(3)
	id2 := startConnect(t, n, p2, `,"provider":"gendragoon","workspace":"gendragoon"`)["request_id"].(string)
	code2 := approve(t, n, id2, "")["code"].(string)
	if st, x := exchange(t, n, code2, p2, `,"provider_grant":"gdg_one_time_123"`); st != 409 || x["code"] != "grant_used" {
		t.Fatalf("replayed provider_grant: %d %v", st, x)
	}
	if st, _ := exchange(t, n, code2, p2, ""); st != 200 {
		t.Fatal("the code is not burnt by a refused grant")
	}
}

func TestConnectExpired(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	var mu sync.Mutex
	now := time.Now()
	host.SetConnectClock(n.H, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	adv := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	p := newPKCE(4)
	id := startConnect(t, n, p, `,"provider":"gendragoon"`)["request_id"].(string)
	code := approve(t, n, id, "")["code"].(string)
	adv(5*time.Minute + time.Second)
	if st, x := exchange(t, n, code, p, ""); st != 410 || x["code"] != "expired" {
		t.Fatalf("expired code: %d %v", st, x)
	}
	// request lifetime: 30 minutes from start
	p2 := newPKCE(5)
	id2 := startConnect(t, n, p2, `,"provider":"gendragoon"`)["request_id"].(string)
	adv(31 * time.Minute)
	if st, x := cpost(t, n, "/v1/connect/approve", n.Key, fmt.Sprintf(`{"request_id":%q}`, id2)); st != 410 || x["code"] != "expired" {
		t.Fatalf("expired request: %d %v", st, x)
	}
}

func TestConnectWrongPKCEAndStateAndAttemptLimit(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	p := newPKCE(6)
	id := startConnect(t, n, p, `,"provider":"gendragoon"`)["request_id"].(string)
	code := approve(t, n, id, "")["code"].(string)
	wrong := p
	wrong.verifier = strings.Repeat("x", 50)
	if st, x := exchange(t, n, code, wrong, ""); st != 400 || x["code"] != "pkce_mismatch" {
		t.Fatalf("wrong verifier: %d %v", st, x)
	}
	ws := p
	ws.state = strings.Repeat("Q", 30)
	if st, x := exchange(t, n, code, ws, ""); st != 400 || x["code"] != "state_mismatch" {
		t.Fatalf("wrong state: %d %v", st, x)
	}
	for i := 0; i < 2; i++ {
		exchange(t, n, code, wrong, "")
	}
	if st, x := exchange(t, n, code, wrong, ""); st != 429 || x["code"] != "too_many_attempts" {
		t.Fatalf("5th wrong attempt: %d %v", st, x)
	}
	if st, x := exchange(t, n, code, p, ""); st == 200 || x["key"] != nil {
		t.Fatalf("a killed request must not issue a key even with the right verifier: %d %v", st, x)
	}
}

func TestConnectCSRFOnApprove(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	p := newPKCE(7)
	id := startConnect(t, n, p, `,"provider":"gendragoon"`)["request_id"].(string)
	body := fmt.Sprintf(`{"request_id":%q}`, id)
	for _, hdr := range [][]string{
		{"Sec-Fetch-Site", "cross-site"},
		{"Sec-Fetch-Site", "same-site"},
		{"Origin", "https://evil.example"},
		{"Content-Type", "text/plain"},
		{"Content-Type", "application/x-www-form-urlencoded"},
	} {
		h := append([]string{"Content-Type", "application/json"}, hdr...)
		st, b, _ := do(t, "POST", n.URL+"/v1/connect/approve", n.Key, body, h...)
		if st != 403 || !strings.Contains(b, `"csrf"`) {
			t.Fatalf("approve with %v: want 403 csrf, got %d %s", hdr, st, b)
		}
	}
	// no admin key, or a non-admin key: refused
	if st, _, _ := do(t, "POST", n.URL+"/v1/connect/approve", "", body, jsonHdr...); st != 401 {
		t.Fatalf("approve without a key: %d", st)
	}
	rk, _ := mkKey(t, n, map[string]interface{}{"scope": "write", "db": "default"})
	if st, _, _ := do(t, "POST", n.URL+"/v1/connect/approve", rk, body, jsonHdr...); st != 403 {
		t.Fatalf("approve with a non-admin key: %d", st)
	}
	// a request that was never started cannot be approved
	if st, x := cpost(t, n, "/v1/connect/approve", n.Key, `{"request_id":"rq_made_up"}`); st != 404 {
		t.Fatalf("approve unknown: %d %v", st, x)
	}
	// same-origin console request works
	if st, x := cpost(t, n, "/v1/connect/approve", n.Key, body, "Origin", n.URL, "Sec-Fetch-Site", "same-origin"); st != 200 {
		t.Fatalf("same-origin approve: %d %v", st, x)
	}
}

func TestConnectRevokeThenKeyRejected(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	connectOne := func(i int) map[string]interface{} {
		p := newPKCE(i)
		id := startConnect(t, n, p, `,"provider":"rottenapple-launcher","app":"com.acme.app`+fmt.Sprint(i)+`","prefix":"saves"`)["request_id"].(string)
		st, x := exchange(t, n, approve(t, n, id, "")["code"].(string), p, "")
		if st != 200 {
			t.Fatalf("exchange %d %v", st, x)
		}
		return x
	}
	// the launcher revokes on uninstall, with the app's own key
	x := connectOne(10)
	key, ws := x["key"].(string), x["workspace"].(map[string]interface{})["db"].(string)
	u := n.URL + "/v1/db/" + ws + "/path/saves.red-xai.db:S[ID=1].A"
	if st, _, _ := do(t, "PUT", u, key, "1"); st != 200 {
		t.Fatal("key works before revoke")
	}
	st, out := cpost(t, n, "/v1/connect/revoke", key, "")
	if st != 200 || out["revoked"] != true || out["key_id"] != x["key_id"] {
		t.Fatalf("self revoke %d %v", st, out)
	}
	if st, _, _ := do(t, "PUT", u, key, "2"); st != 401 {
		t.Fatalf("revoked key must get 401, got %d", st)
	}
	if st, _ := cpost(t, n, "/v1/connect/revoke", key, ""); st != 401 {
		t.Fatalf("revoking again with a dead key: %d", st)
	}
	// an admin key (not issued by connect) cannot use the app revoke endpoint
	if st, out := cpost(t, n, "/v1/connect/revoke", n.Key, ""); st != 404 || out["code"] != "not_connected" {
		t.Fatalf("admin key on /revoke: %d %v", st, out)
	}
	// the admin revokes from Connected apps
	y := connectOne(11)
	st, b, _ := do(t, "GET", n.URL+"/v1/connect/apps", n.Key, "")
	var apps struct{ Apps []host.Connection }
	json.Unmarshal([]byte(b), &apps)
	var cid string
	revokedSeen := false
	for _, a := range apps.Apps {
		if a.KeyID == y["key_id"] {
			cid = a.ID
		}
		if a.KeyID == x["key_id"] && a.Revoked != nil && a.RevokedBy == "app" {
			revokedSeen = true
		}
	}
	if st != 200 || cid == "" || !revokedSeen {
		t.Fatalf("apps list: %s", b)
	}
	if st, _, _ := do(t, "DELETE", n.URL+"/v1/connect/apps/"+cid, n.Key, ""); st != 200 {
		t.Fatalf("admin revoke %d", st)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/db/"+y["workspace"].(map[string]interface{})["db"].(string)+"/stats", y["key"].(string), ""); st != 401 {
		t.Fatalf("admin-revoked key must get 401, got %d", st)
	}
	audit, _ := os.ReadFile(n.H.Cfg.AuditLog)
	if strings.Count(string(audit), `"connect.revoke"`) < 2 {
		t.Fatal("revokes must be audit-logged")
	}
}

func TestConnectExchangeRateLimit(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	p := newPKCE(20)
	last := 0
	var hdr http.Header
	for i := 0; i < 21; i++ {
		st, _, h := do(t, "POST", n.URL+"/v1/connect/exchange", "", fmt.Sprintf(`{"code":"RX-AAAAA-%05d","pkce_verifier":%q,"state":%q}`, i, p.verifier, p.state), jsonHdr...)
		last, hdr = st, h
		if i < 20 && st == 429 {
			t.Fatalf("throttled too early at %d", i)
		}
	}
	if last != 429 || hdr.Get("Retry-After") == "" {
		t.Fatalf("21st exchange in a minute: want 429 with Retry-After, got %d", last)
	}
}

func TestConnectPendingSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	n := startNode(t, dir, nil)
	key := n.Key
	p := newPKCE(30)
	id := startConnect(t, n, p, `,"provider":"rottenapple"`)["request_id"].(string)
	n.Stop()
	n2 := startNode(t, dir, nil)
	n2.Key = key
	// the console re-fires the link after the restart: same request, still pending
	if again := startConnect(t, n2, p, `,"provider":"rottenapple"`); again["request_id"] != id || again["status"] != "pending" {
		t.Fatalf("after restart: %v", again)
	}
	code := approve(t, n2, id, "")["code"].(string)
	n2.Stop()
	n3 := startNode(t, dir, nil)
	n3.Key = key
	st, x := exchange(t, n3, code, p, "")
	if st != 200 || x["workspace"].(map[string]interface{})["db"] != "ra" || x["prefix"] != "" {
		t.Fatalf("approved code after restart: %d %v", st, x)
	}
}

func TestConnectWorkspaceOwnerUnverifiedAndSingleKey(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	// an existing database that this flow did not create is never handed to an app
	p := newPKCE(40)
	id := startConnect(t, n, p, `,"provider":"gendragoon","workspace":"default"`)["request_id"].(string)
	if st, x := cpost(t, n, "/v1/connect/approve", n.Key, fmt.Sprintf(`{"request_id":%q}`, id)); st != 409 || x["code"] != "workspace_exists_other_owner" {
		t.Fatalf("existing db: %d %v", st, x)
	}
	// unknown provider: shown as unverified, callback ignored, typed confirmation needed
	pu := newPKCE(41)
	s := startConnect(t, n, pu, `,"provider":"someapp","callback":"https://evil.example/cb","name":"Totally Gendragoon"`)
	prov := s["provider"].(map[string]interface{})
	if prov["verified"] != false || prov["callback_ok"] != false || !strings.HasPrefix(prov["display"].(string), "Unverified app") {
		t.Fatalf("unverified: %v", s)
	}
	if st, x := cpost(t, n, "/v1/connect/approve", n.Key, fmt.Sprintf(`{"request_id":%q}`, s["request_id"])); st != 400 || x["code"] != "unknown_provider" {
		t.Fatalf("unverified approve without confirm: %d %v", st, x)
	}
	a := approve(t, n, s["request_id"].(string), `,"confirm":"someapp"`)
	if a["deliver"] != "paste" || a["callback_template"] != nil {
		t.Fatalf("a bad callback must fall back to paste: %v", a)
	}
	// Rotten Apple Store: one active key per workspace unless replaced
	p1 := newPKCE(42)
	id1 := startConnect(t, n, p1, `,"provider":"rottenapple"`)["request_id"].(string)
	_, x1 := exchange(t, n, approve(t, n, id1, "")["code"].(string), p1, "")
	p2 := newPKCE(43)
	id2 := startConnect(t, n, p2, `,"provider":"rottenapple"`)["request_id"].(string)
	if st, x := cpost(t, n, "/v1/connect/approve", n.Key, fmt.Sprintf(`{"request_id":%q}`, id2)); st != 409 || x["code"] != "key_exists" {
		t.Fatalf("second rottenapple key: %d %v", st, x)
	}
	if st, x := exchange(t, n, approve(t, n, id2, `,"replace":true`)["code"].(string), p2, ""); st != 200 {
		t.Fatalf("replace: %d %v", st, x)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/db/ra/stats", x1["key"].(string), ""); st != 401 {
		t.Fatalf("replaced key must be revoked, got %d", st)
	}
	// the store's key can do what ra-core needs in its db (query is allowed: no prefix)
	if st, b, _ := do(t, "POST", n.URL+"/v1/db/ra/query", x1["key"].(string), `{"q":"x.red-xai.db:B[ID=*]"}`); st != 401 {
		t.Fatalf("sanity %d %s", st, b)
	}
	// deny
	p3 := newPKCE(44)
	id3 := startConnect(t, n, p3, `,"provider":"gendragoon","workspace":"gd2"`)["request_id"].(string)
	code3 := approve(t, n, id3, "")["code"].(string)
	if st, _ := cpost(t, n, "/v1/connect/deny", n.Key, fmt.Sprintf(`{"request_id":%q}`, id3)); st != 200 {
		t.Fatal("deny")
	}
	if st, x := exchange(t, n, code3, p3, ""); st == 200 || x["key"] != nil {
		t.Fatalf("denied request: %d %v", st, x)
	}
}

func TestConnectInsecureTransportAndBadInput(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	req := httptest.NewRequest("POST", "/v1/connect/exchange", strings.NewReader(`{"code":"RX-AAAAA-BBBBB"}`))
	req.RemoteAddr = "192.168.1.50:5555"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	n.H.Handler().ServeHTTP(rec, req)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "insecure_transport") {
		t.Fatalf("plain http from the LAN: %d %s", rec.Code, rec.Body.String())
	}
	p := newPKCE(50)
	for _, body := range []string{
		fmt.Sprintf(`{"v":1,"provider":"gendragoon","state":"short","pkce_challenge":%q}`, p.challenge),
		fmt.Sprintf(`{"v":1,"provider":"gendragoon","state":%q,"pkce_challenge":"plain"}`, p.state),
		fmt.Sprintf(`{"v":1,"provider":"gendragoon","state":%q,"pkce_challenge":%q,"pkce_method":"plain"}`, p.state, p.challenge),
		fmt.Sprintf(`{"v":1,"provider":"gendragoon","state":%q,"pkce_challenge":%q,"scope":"admin"}`, p.state, p.challenge),
		fmt.Sprintf(`{"v":1,"provider":"rottenapple-launcher","app":"com.a.b","workspace":"default","state":%q,"pkce_challenge":%q}`, p.state, p.challenge),
		fmt.Sprintf(`{"v":1,"provider":"Bad Provider","state":%q,"pkce_challenge":%q}`, p.state, p.challenge),
	} {
		if st, x := cpost(t, n, "/v1/connect/start", n.Key, body); st != 400 {
			t.Fatalf("bad start %s: %d %v", body, st, x)
		}
	}
	if st, x := cpost(t, n, "/v1/connect/start", n.Key, fmt.Sprintf(`{"provider":"gendragoon","state":%q,"pkce_challenge":%q}`, p.state, p.challenge)); st != 400 || x["code"] != "client_too_old" {
		t.Fatalf("missing v: %d %v", st, x)
	}
}

func TestConnectConcurrentExchangeExactlyOneKey(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	p := newPKCE(60)
	id := startConnect(t, n, p, `,"provider":"gendragoon"`)["request_id"].(string)
	code := approve(t, n, id, "")["code"].(string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, _ := exchange(t, n, code, p, "")
			mu.Lock()
			if st == 200 {
				ok++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("want exactly one key from one code, got %d", ok)
	}
}
