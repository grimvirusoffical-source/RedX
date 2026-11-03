package host_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"redx/host"
)

func TestWebsiteAccountsUseNativeTenantGatesWithoutKeys(t *testing.T) {
	var revoked atomic.Bool
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("redx_session")
		if err != nil {
			w.WriteHeader(401)
			return
		}
		if r.Header.Get("Authorization") != "" || len(r.Cookies()) != 1 {
			t.Error("credential/header forwarding")
		}
		if (c.Value == "alpha" && revoked.Load()) || (c.Value != "alpha" && c.Value != "beta" && c.Value != "owner" && c.Value != "unpaid") {
			w.WriteHeader(401)
			return
		}
		roles := []string{"user"}
		amr := []string{"pwd"}
		if c.Value == "owner" {
			roles = []string{"owner"}
			amr = append(amr, "call")
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"account": map[string]interface{}{"id": "canonical-" + c.Value, "email": "shared-fixture@example.invalid", "username": c.Value, "roles": roles}, "amr": amr, "expiresMs": time.Now().Add(time.Hour).UnixMilli()})
	}))
	defer authority.Close()
	n := startNode(t, t.TempDir(), nil)
	host.SetWebsiteAuthorityForTest(n.H, authority.URL, n.URL, authority.Client(), map[string]bool{"canonical-owner": true})
	for _, id := range []string{"canonical-alpha", "canonical-beta"} {
		if err := host.SetPlanForTest(n.H, hostedPlan(id, "basic", "month", "active", time.Now().Add(time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	call := func(method, path, cookie, body string) (int, string) {
		return rawReq(t, method, n.URL+path, "", body, "Cookie", "redx_session="+cookie, "Origin", n.URL, "Content-Type", "application/json")
	}
	st, body := call("GET", "/v1/ui/whoami", "alpha", "")
	if st != 200 || !strings.Contains(body, "canonical-alpha") || jsonOf(t, body)["owner"] != false {
		t.Fatalf("normal website identity: %d %s", st, body)
	}
	if st, _ = call("GET", "/v1/ui/whoami", "unpaid", ""); st != 200 {
		t.Fatalf("account login incorrectly requires a plan: %d", st)
	}
	if st, _ = call("POST", "/v1/dbs", "unpaid", `{"name":"unpaid"}`); st != 402 {
		t.Fatalf("website login bypassed native plan gate: %d", st)
	}
	if st, _ = rawReq(t, "GET", n.URL+"/v1/ui/whoami", "", "", "X-Account-ID", "canonical-owner", "X-Role", "owner"); st != 401 {
		t.Fatalf("caller identity header authenticated: %d", st)
	}
	st, body = call("POST", "/v1/dbs", "alpha", `{"name":"notes"}`)
	if st != 201 {
		t.Fatalf("alpha create: %d %s", st, body)
	}
	a := jsonOf(t, body)["name"].(string)
	st, body = call("POST", "/v1/dbs", "beta", `{"name":"notes"}`)
	if st != 201 {
		t.Fatalf("beta create: %d %s", st, body)
	}
	b := jsonOf(t, body)["name"].(string)
	if a == b {
		t.Fatal("tenant names collided")
	}
	st, body = call("PUT", "/v1/db/"+a+"/path/b:B.K", "alpha", `{"value":"alpha-only"}`)
	if st != 200 && st != 201 {
		t.Fatalf("alpha write: %d %s", st, body)
	}
	if st, body = call("GET", "/v1/db/"+a+"/path/b:B.K", "alpha", ""); st != 200 || !strings.Contains(body, "alpha-only") {
		t.Fatalf("alpha read: %d %s", st, body)
	}
	if st, body = call("GET", "/v1/db/"+a+"/path/b:B.K", "beta", ""); st != 404 || strings.Contains(body, "alpha-only") {
		t.Fatalf("cross-tenant read: %d %s", st, body)
	}
	if st, _ = call("PUT", "/v1/db/"+a+"/path/b:B.K", "beta", `{"value":"wrong"}`); st != 404 {
		t.Fatalf("cross-tenant write: %d", st)
	}
	for _, path := range []string{"/v1/db/" + a + "/files", "/v1/db/" + a + "/stats", "/v1/db/" + a + "/path/b:B.K"} {
		if st, body = call("GET", path, "beta", ""); st != 404 || strings.Contains(body, "alpha-only") {
			t.Fatalf("cross-tenant metadata route %s: %d %s", path, st, body)
		}
	}
	if st, body = call("POST", "/v1/db/"+a+"/bx", "beta", `{"q":"{Get[]} = b:B[ID=*] -> *"}`); st != 404 || strings.Contains(body, "alpha-only") {
		t.Fatalf("cross-tenant BoxQL: %d %s", st, body)
	}
	if st, _ = call("GET", "/v1/admin/status", "alpha", ""); st != 403 {
		t.Fatalf("password-only tenant has service administration: %d", st)
	}
	if st, body = call("GET", "/v1/dbs", "alpha", ""); st != 200 || strings.Contains(body, b) {
		t.Fatalf("list leaked beta: %d %s", st, body)
	}
	if st, _ = call("GET", "/v1/owner/dbs", "alpha", ""); st != 403 {
		t.Fatalf("customer owner access: %d", st)
	}
	if st, body = call("GET", "/v1/owner/dbs", "owner", ""); st != 200 || !strings.Contains(body, a) || !strings.Contains(body, b) {
		t.Fatalf("owner overview: %d %s", st, body)
	}
	audit, err := os.ReadFile(n.H.Cfg.AuditLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), `"event":"owner.read"`) || !strings.Contains(string(audit), `"key_id":"acct:canonical-owner"`) {
		t.Fatal("privileged access not audited with canonical actor")
	}
	if st, body, _ = do(t, "GET", n.URL+"/v1/ui/whoami", n.Key, ""); st != 200 {
		t.Fatalf("existing developer key broken: %d %s", st, body)
	}
	if st, body = call("GET", "/v1/auth/config", "alpha", ""); st != 200 || jsonOf(t, body)["mode"] != "website" {
		t.Fatalf("account discovery: %d %s", st, body)
	}
	if n.H.WebSetupPending() {
		t.Fatal("website mode exposes admin bootstrap")
	}
	// Genuine native WebSocket plus cookie authentication; no query-string key.
	u := "ws" + strings.TrimPrefix(n.URL, "http") + "/v1/db/" + a + "/subscribe?path=b:"
	denied, deniedResponse, deniedErr := websocket.DefaultDialer.Dial(u, http.Header{"Cookie": []string{"redx_session=beta"}, "Origin": []string{n.URL}})
	if denied != nil {
		_ = denied.Close()
	}
	if deniedErr == nil || deniedResponse == nil || deniedResponse.StatusCode != http.StatusNotFound {
		t.Fatal("cross-tenant watch did not fail closed as a missing database")
	}
	_ = deniedResponse.Body.Close()
	ws, response, err := websocket.DefaultDialer.Dial(u, http.Header{"Cookie": []string{"redx_session=alpha"}, "Origin": []string{n.URL}})
	if err != nil {
		if response != nil {
			t.Fatalf("watch: %v status%d", err, response.StatusCode)
		}
		t.Fatal(err)
	}
	defer ws.Close()
	revoked.Store(true)
	if st, _ = call("GET", "/v1/dbs", "alpha", ""); st != 401 {
		t.Fatalf("revoked website still reads: %d", st)
	}
	_ = ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err = ws.ReadMessage(); err == nil {
		t.Fatal("revoked watch remained open")
	}
	if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
		t.Fatal("watch timed out instead of closing on revocation")
	}
	// Account changes do not affect the second account or grant it owner scope.
	if st, _ = call("GET", "/v1/dbs", "beta", ""); st != 200 {
		t.Fatalf("beta lost independent access: %d", st)
	}
}
