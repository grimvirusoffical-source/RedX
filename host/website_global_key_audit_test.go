package host_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"redx/host"
)

func TestWebsiteGlobalKeyAuditHTTP503PreservesSessionAndProjectKeys(t *testing.T) {
	t.Setenv("REDX_WEBSITE_SESSION", "")
	n := startNode(t, t.TempDir(), func(c *host.Config, _ string) {
		c.AuditOK = false
	})
	if err := n.H.Audit.Close(); err != nil {
		t.Fatal(err)
	}
	// Host has always wired its resolver, but no actual website adapter yet.
	if status, _, _ := do(t, http.MethodGet, n.URL+"/v1/dbs", n.Key, ""); status != http.StatusOK {
		t.Fatalf("standalone key behavior changed on unavailable audit: %d", status)
	}
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("redx_session")
		if err != nil || (cookie.Value != "alpha" && cookie.Value != "beta") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"account": map[string]interface{}{"id": "canonical-" + cookie.Value, "email": "same@example.invalid", "roles": []string{"user"}},
			"amr":     []string{"pwd"}, "expiresMs": time.Now().Add(time.Hour).UnixMilli(),
		})
	}))
	defer authority.Close()
	// Test-only adapter injection happens after New: the private mode callback
	// must follow the actual adapter rather than caching a startup false value.
	host.SetWebsiteAuthorityForTest(n.H, authority.URL, n.URL, authority.Client(), nil)
	dbs := map[string]string{}
	for _, who := range []string{"alpha", "beta"} {
		if err := host.SetPlanForTest(n.H, hostedPlan("canonical-"+who, "basic", "month", "active", time.Now().Add(time.Hour))); err != nil {
			t.Fatal(err)
		}
		status, body, _ := do(t, http.MethodPost, n.URL+"/v1/dbs", "", `{"name":"notes"}`,
			"Cookie", "redx_session="+who, "Origin", n.URL, "Content-Type", "application/json")
		if status != http.StatusCreated {
			t.Fatalf("normal account own database creation changed: %d", status)
		}
		dbs[who] = jsonOf(t, body)["name"].(string)
	}
	projectKey, _, err := n.H.KS.Create(host.CreateSpec{DB: dbs["alpha"], Scope: host.ScopeAdmin, Owner: "canonical-alpha"})
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/db/" + dbs["alpha"] + "/path/fixture.red-xai.db:Box.Value"
	if status, _, _ := do(t, http.MethodPut, n.URL+path, projectKey, `{"value":"synthetic-own-value"}`, "Content-Type", "application/json"); status != http.StatusOK {
		t.Fatalf("own concrete project-admin write changed: %d", status)
	}
	for _, request := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/dbs", ""},
		{http.MethodPost, "/v1/dbs", `{"name":"must-not-create"}`},
	} {
		status, body, headers := do(t, request.method, n.URL+request.path, n.Key, request.body,
			"Cookie", "redx_session=alpha", "Origin", n.URL, "Content-Type", "application/json")
		if status != http.StatusServiceUnavailable || !strings.Contains(body, "audit_unavailable") || headers.Get("WWW-Authenticate") != "" || headers.Get("Set-Cookie") != "" {
			t.Fatalf("global audit failure did not preserve session as503: %s status%d", request.method, status)
		}
	}
	if n.H.Reg.Exists("must-not-create") {
		t.Fatal("global mutation happened before required audit")
	}
	if status, body, _ := do(t, http.MethodGet, n.URL+path, projectKey, ""); status != http.StatusOK || !strings.Contains(body, "synthetic-own-value") {
		t.Fatalf("project key own access changed after global audit denial: %d", status)
	}
	if status, _, _ := do(t, http.MethodGet, n.URL+path, "", "", "Cookie", "redx_session=alpha", "Origin", n.URL); status != http.StatusOK {
		t.Fatalf("normal website session stopped working after global audit denial: %d", status)
	}
	if status, _, _ := do(t, http.MethodGet, n.URL+"/v1/db/"+dbs["beta"]+"/files", projectKey, ""); status != http.StatusForbidden {
		t.Fatalf("project key crossed tenant boundary after global audit denial: %d", status)
	}
}
