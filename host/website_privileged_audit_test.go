package host_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"redx/host"
)

func TestWebsiteOwnerAuditFailureDeniesPrivilegesWithoutBreakingTenantIsolation(t *testing.T) {
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("redx_session")
		if err != nil || !strings.Contains("|alpha|beta|owner|owner-no-mfa|role-only|", "|"+cookie.Value+"|") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		id, role, amr := "canonical-"+cookie.Value, "user", []string{"pwd"}
		if strings.HasPrefix(cookie.Value, "owner") || cookie.Value == "role-only" {
			role = "owner"
		}
		if cookie.Value == "owner" || cookie.Value == "role-only" {
			amr = append(amr, "totp")
		}
		if cookie.Value == "owner-no-mfa" {
			id = "canonical-owner"
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"account": map[string]interface{}{"id": id, "email": "fixture@example.invalid", "roles": []string{role}},
			"amr":     amr, "expiresMs": time.Now().Add(time.Hour).UnixMilli(),
		})
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
	status, body := call("POST", "/v1/dbs", "alpha", `{"name":"notes"}`)
	if status != http.StatusCreated {
		t.Fatalf("own database creation failed: %d", status)
	}
	db := jsonOf(t, body)["name"].(string)
	path := "/v1/db/" + db + "/path/fixture:B.K"
	if status, _ := call("PUT", path, "alpha", `{"value":"synthetic-private-record"}`); status != 200 && status != 201 {
		t.Fatalf("own record write failed: %d", status)
	}
	if status, _ := call("GET", path, "beta", ""); status != http.StatusNotFound {
		t.Fatalf("other tenant read allowed: %d", status)
	}
	for _, cookie := range []string{"owner-no-mfa", "role-only"} {
		if status, _ := call("GET", "/v1/owner/dbs", cookie, ""); status != http.StatusForbidden {
			t.Fatalf("unverified privileged identity accepted (%s): %d", cookie, status)
		}
	}
	if status, _ := call("GET", path, "owner", ""); status != http.StatusOK {
		t.Fatalf("audited owner read failed: %d", status)
	}
	if status, _ := call("POST", "/v1/dbs", "owner", `{"name":"fixture-system"}`); status != http.StatusCreated {
		t.Fatalf("audited owner create failed: %d", status)
	}
	data, err := os.ReadFile(n.H.Cfg.AuditLog)
	if err != nil {
		t.Fatal(err)
	}
	read, write := false, false
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var ev host.AuditEvent
		if json.Unmarshal([]byte(line), &ev) != nil {
			t.Fatal("invalid audit record")
		}
		if ev.KeyID == "acct:canonical-owner" && ev.Actor == "fixture@example.invalid" && !ev.Time.IsZero() {
			read = read || ev.Event == "owner.read" && ev.Target == "db:"+db+" path"
			write = write || ev.Event == "owner.write" && ev.Target == "/v1/dbs"
		}
	}
	if !read || !write || strings.Contains(string(data), "synthetic-private-record") {
		t.Fatal("privileged audit attribution missing or record value logged")
	}
	if err := n.H.Audit.Close(); err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct{ method, path, body string }{
		{"GET", path, ""}, {"GET", "/v1/owner/dbs", ""}, {"POST", "/v1/dbs", `{"name":"must-not-create"}`},
		{"GET", "/v1/dbs", ""}, {"GET", "/v1/keys", ""}, {"GET", "/v1/ui/whoami", ""},
		{"GET", "/v1/db/" + db + "/files", ""}, {"GET", "/v1/billing/me", ""},
		{"GET", "/v1/updates/apps", ""}, {"POST", "/v1/ui/validate", `{}`}, {"POST", "/v1/connect/revoke", `{}`},
	} {
		req, err := http.NewRequest(request.method, n.URL+request.path, strings.NewReader(request.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Cookie", "redx_session=owner")
		req.Header.Set("Origin", n.URL)
		req.Header.Set("Content-Type", "application/json")
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), "audit_unavailable") || response.Header.Get("WWW-Authenticate") != "" || response.Header.Get("Set-Cookie") != "" {
			t.Fatalf("audit failure did not preserve the login as a service failure: %s %s status%d", request.method, request.path, response.StatusCode)
		}
	}
	if n.H.Reg.Exists("must-not-create") {
		t.Fatal("database created before required audit")
	}
	if status, body := call("GET", path, "alpha", ""); status != http.StatusOK || !strings.Contains(body, "synthetic-private-record") {
		t.Fatalf("tenant own access changed after audit failure: %d", status)
	}
	if status, _ := call("GET", path, "beta", ""); status != http.StatusNotFound {
		t.Fatalf("audit failure bypassed cross-tenant boundary: %d", status)
	}
}
