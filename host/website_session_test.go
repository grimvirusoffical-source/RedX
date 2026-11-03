package host

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func websiteFixtureProfile(id string) map[string]interface{} {
	return map[string]interface{}{"account": map[string]interface{}{"id": id, "email": "fixture@example.invalid", "username": "fixture", "roles": []string{"owner"}}, "amr": []string{"pwd", "call"}, "expiresMs": time.Now().Add(time.Hour).UnixMilli()}
}

func TestWebsiteSessionAuthorityAndOwnerBinding(t *testing.T) {
	profile := websiteFixtureProfile("account-a")
	status := 200
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/me" || r.Header.Get("Cookie") != "redx_session=fixture" || r.Header.Get("Authorization") != "" || r.Header.Get("X-Account-ID") != "" {
			t.Error("unexpected authority request")
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(profile)
	}))
	defer authority.Close()
	adapter := &websiteSessionAdapter{authority: authority.URL + "/me", origin: "https://red-xai.com", client: authority.Client(), ownerIDs: map[string]bool{"account-a": true}, now: time.Now}
	r := httptest.NewRequest("GET", "https://red-xai.com/v1/ui/whoami", nil)
	r.Header.Set("Cookie", "redx_session=fixture; unrelated=private")
	r.Header.Set("Authorization", "Bearer untrusted")
	r.Header.Set("X-Account-ID", "account-a")
	id, ok := adapter.identity(r)
	if !ok || !id.Owner || id.EmailVerified {
		t.Fatal("canonical owner/MFA not recognized, or email verification invented")
	}
	profile["account"].(map[string]interface{})["id"] = "account-b"
	id, ok = adapter.identity(r)
	if !ok || id.Owner {
		t.Fatal("email match must not elevate different account")
	}
	profile["account"].(map[string]interface{})["id"] = "account-a"
	profile["account"].(map[string]interface{})["roles"] = []string{"user"}
	id, ok = adapter.identity(r)
	if !ok || id.Owner {
		t.Fatal("owner allowlist without authoritative owner role")
	}
	profile["account"].(map[string]interface{})["roles"] = []string{"owner"}
	profile["amr"] = []string{"pwd"}
	id, ok = adapter.identity(r)
	if !ok || id.Owner {
		t.Fatal("owner without MFA")
	}
	profile["amr"] = []string{"pwd", "call"}
	status = 401
	if _, ok = adapter.identity(r); ok {
		t.Fatal("revoked authority session accepted")
	}
	status = 200
	profile["expiresMs"] = time.Now().Add(-time.Minute).UnixMilli()
	if _, ok = adapter.identity(r); ok {
		t.Fatal("expired session accepted")
	}
	profile["expiresMs"] = time.Now().Add(time.Hour).UnixMilli()
	profile["account"].(map[string]interface{})["emailVerified"] = false
	if _, ok = adapter.identity(r); ok {
		t.Fatal("explicitly unverified account accepted")
	}
	delete(profile["account"].(map[string]interface{}), "emailVerified")
	r.Header.Set("Cookie", "redx_session=fixture; redx_session=ambiguous")
	if _, ok = adapter.identity(r); ok {
		t.Fatal("ambiguous cookies accepted")
	}
}

func TestWebsiteBoundaryRejectsCrossOriginCookieWrites(t *testing.T) {
	h := &Host{website: &websiteSessionAdapter{origin: "https://red-xai.com"}}
	called := 0
	next := h.websiteBoundary(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called++; w.WriteHeader(204) }))
	for _, origin := range []string{"", "null", "https://other.invalid", "http://red-xai.com", "https://red-xai.com/"} {
		r := httptest.NewRequest("POST", "https://red-xai.com/v1/dbs", strings.NewReader("{}"))
		r.AddCookie(&http.Cookie{Name: websiteCookie, Value: "fixture"})
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		next.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("origin %q: %d", origin, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "https://red-xai.com/v1/dbs", nil)
	r.AddCookie(&http.Cookie{Name: websiteCookie, Value: "fixture"})
	r.Header.Set("Origin", "https://red-xai.com")
	w := httptest.NewRecorder()
	next.ServeHTTP(w, r)
	if w.Code != 204 || called != 1 {
		t.Fatal("same-origin request rejected")
	}
	r = httptest.NewRequest("POST", "https://red-xai.com/v1/dbs", nil)
	r.Header.Set("Authorization", "Bearer fixture-developer-key")
	w = httptest.NewRecorder()
	next.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatal("explicit API client incorrectly requires a website cookie")
	}
}

// Exported only into the test build: production cannot select an authority URL
// through request headers, environment or a public endpoint.
func SetWebsiteAuthorityForTest(h *Host, authority, origin string, client *http.Client, owners map[string]bool) {
	h.website = &websiteSessionAdapter{authority: authority, origin: origin, client: client, ownerIDs: owners, now: time.Now, watchInterval: 20 * time.Millisecond}
}
