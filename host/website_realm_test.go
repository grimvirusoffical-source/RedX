package host

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebsiteRealmCanonicalSeparation(t *testing.T) {
	for sub, want := range map[string]string{"same-subject": "rxf1_f7fb084c3229d8dcc7bcf980bbb75b59afa1ff9224066c7bf4786145ec99015f", "normal-ü-😀": "rxf1_76fe6aa0ebd69ef522f99f5aa1806aabc00119cbf04010504b641e2e9740d2d4"} {
		if got, ok := websiteCanonicalSubject(websiteFreshIssuer, sub); !ok || got != want {
			t.Fatal("JS/Go contract vector mismatch")
		}
	}
	legacy, ok := websiteCanonicalSubject(websiteLegacyIssuer, "shared-subject")
	if !ok || legacy != "shared-subject" {
		t.Fatal("legacy ownership changed")
	}
	fresh, ok := websiteCanonicalSubject(websiteFreshIssuer, "shared-subject")
	if !ok || fresh == legacy || !strings.HasPrefix(fresh, websiteFreshPrefix) {
		t.Fatal("realm collision")
	}
	if got, ok := websiteCanonicalSubject(websiteLegacyIssuer, fresh); !ok || got != fresh {
		t.Fatal("valid legacy public-hash-shaped ID changed")
	}
	private, ok := websiteOwnershipKey(websiteFreshIssuer, "shared-subject")
	if !ok || private == fresh || private == legacy {
		t.Fatal("private ownership namespace collided with public IDs")
	}
	for _, sub := range []string{"", "has space", "bad\x00", strings.Repeat("ü", 101)} {
		if _, ok := websiteCanonicalSubject(websiteFreshIssuer, sub); ok {
			t.Fatal("malformed subject accepted")
		}
	}
	if _, ok := websiteCanonicalSubject("urn:attacker", "shared-subject"); ok {
		t.Fatal("unknown issuer accepted")
	}
}

func TestWebsiteRealmRuntimeRefusesActivation(t *testing.T) {
	t.Setenv("REDX_WEBSITE_SESSION", "true")
	t.Setenv("REDX_WEBSITE_SESSION_REALMS", "prototype-v1")
	defer func() {
		if recover() == nil {
			t.Fatal("unproven realm prototype activated from environment")
		}
	}()
	websiteSessionFromEnv()
}

func TestWebsiteRealmEnvelopeAuthorityAndRevocation(t *testing.T) {
	fresh, _ := websiteCanonicalSubject(websiteFreshIssuer, "shared-subject")
	profile := map[string]interface{}{"identityRealm": map[string]interface{}{"version": 1, "issuer": websiteFreshIssuer, "subject": "shared-subject", "canonicalId": fresh},
		"account": map[string]interface{}{"id": fresh, "email": "owner@example.invalid", "roles": []string{"user"}, "active": true, "emailVerified": true}, "active": true, "amr": []string{"pwd", "call"}, "expiresMs": time.Now().Add(time.Hour).UnixMilli()}
	revoked, ambiguous := false, false
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-RedX-Realm") != "" {
			t.Error("caller headers forwarded")
		}
		if len(r.Cookies()) > 1 {
			ambiguous = true
			w.WriteHeader(409)
			return
		}
		if revoked {
			w.WriteHeader(401)
			return
		}
		_ = json.NewEncoder(w).Encode(profile)
	}))
	defer authority.Close()
	s := &websiteSessionAdapter{authority: authority.URL, origin: "https://red-xai.com", client: authority.Client(), ownerIDs: map[string]bool{fresh: true, "shared-subject": true}, now: time.Now, realms: true}
	r := httptest.NewRequest("GET", "https://red-xai.com/v1/dbs", nil)
	r.AddCookie(&http.Cookie{Name: websiteFreshCookie, Value: "synthetic"})
	r.Header.Set("X-RedX-Realm", websiteLegacyIssuer)
	id, ok := s.identity(r)
	if !ok || id.Sub != fresh || id.Owner {
		t.Fatal("fresh inherited legacy ownership")
	}
	account := profile["account"].(map[string]interface{})
	account["roles"] = []string{"owner"}
	if _, ok = s.identity(r); ok {
		t.Fatal("fresh owner role accepted")
	}
	account["roles"] = []string{"user"}
	profile["expiresMs"] = time.Now().Add(-time.Hour).UnixMilli()
	if _, ok = s.identity(r); ok {
		t.Fatal("expired identity accepted")
	}
	profile["expiresMs"] = time.Now().Add(time.Hour).UnixMilli()
	r.AddCookie(&http.Cookie{Name: websiteCookie, Value: "legacy"})
	if _, ok = s.identity(r); ok || !ambiguous {
		t.Fatal("ambiguous cookies gained priority")
	}
	r = httptest.NewRequest("GET", "https://red-xai.com/v1/dbs", nil)
	r.AddCookie(&http.Cookie{Name: websiteFreshCookie, Value: "synthetic"})
	revoked = true
	if _, ok = s.identity(r); ok {
		t.Fatal("revoked identity accepted")
	}
}

func TestWebsiteRealmFreshCookiesRequireCSRF(t *testing.T) {
	h := &Host{website: &websiteSessionAdapter{origin: "https://red-xai.com", realms: true}}
	next := h.websiteBoundary(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	for _, origin := range []string{"", "https://attacker.invalid", "https://red-xai.com"} {
		r := httptest.NewRequest("POST", "https://red-xai.com/v1/dbs", nil)
		r.AddCookie(&http.Cookie{Name: websiteFreshCookie, Value: "synthetic"})
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		next.ServeHTTP(w, r)
		want := 403
		if origin == "https://red-xai.com" {
			want = 204
		}
		if w.Code != want {
			t.Fatal("fresh cookie CSRF boundary mismatch")
		}
	}
}

// Synthetic native integration fixture only; no production authority/config.
func SetWebsiteRealmAuthorityForTest(h *Host, authority, origin string, client *http.Client, owners map[string]bool) {
	h.website = &websiteSessionAdapter{authority: authority, origin: origin, client: client, ownerIDs: owners, now: time.Now, watchInterval: 20 * time.Millisecond, realms: true}
}
