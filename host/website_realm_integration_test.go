package host_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"redx/host"
	"redx/host/engineadapter"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebsiteRealmsKeepNativeDBAndKeyOwnershipDisjoint(t *testing.T) {
	const legacyIssuer = "urn:redxai:legacy-site"
	const freshIssuer = "urn:redxai:fresh-normal-prototype:v1"
	canonical := func(sub string) string {
		sum := sha256.Sum256([]byte(freshIssuer + "\x00" + sub))
		return "rxf1_" + hex.EncodeToString(sum[:])
	}
	var revoked atomic.Bool
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.Cookies()) != 1 {
			w.WriteHeader(409)
			return
		}
		cookie := r.Cookies()[0]
		issuer, subject, roles := legacyIssuer, "same-subject", []string{"user"}
		if cookie.Name == "redx_fresh_normal_prototype_session" {
			issuer = freshIssuer
			if cookie.Value == "b" {
				subject = "other-subject"
			}
			if revoked.Load() && cookie.Value == "a" {
				w.WriteHeader(401)
				return
			}
		}
		id := subject
		if issuer == freshIssuer {
			id = canonical(subject)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"identityRealm": map[string]interface{}{"version": 1, "issuer": issuer, "subject": subject, "canonicalId": id}, "account": map[string]interface{}{"id": id, "email": "same@example.invalid", "roles": roles, "active": true, "emailVerified": true}, "active": true, "expiresMs": time.Now().Add(time.Hour).UnixMilli(), "amr": []string{"pwd"}})
	}))
	defer authority.Close()
	// Use the unchanged real RedX engine adapter, not the host package's normal
	// stubstore helper, so ownership gates also wrap native custom storage.
	n := &node{Dir: t.TempDir(), Srv: httptest.NewUnstartedServer(nil)}
	n.URL = "http://" + n.Srv.Listener.Addr().String()
	cfg := baseCfg(n.Dir)
	cfg.Advertise = n.URL
	h, err := host.New(cfg, engineadapter.Opener(engineadapter.Config{Durability: "sync"}), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	n.H = h
	n.Key = h.BootstrapKey
	n.Srv.Config.Handler = h.Handler()
	n.Srv.Start()
	t.Cleanup(n.Stop)
	host.SetWebsiteRealmAuthorityForTest(n.H, authority.URL, n.URL, authority.Client(), map[string]bool{"same-subject": true, canonical("same-subject"): true})
	call := func(method, path, cookie, body string) (int, string) {
		contentType := "application/json"
		if method == "PUT" {
			contentType = "text/x-redx-box"
		}
		return rawReq(t, method, n.URL+path, "", body, "Cookie", cookie, "Origin", n.URL, "Content-Type", contentType, "X-RedX-Confirm", "createKey")
	}
	legacy := "redx_session=legacy"
	freshA := "redx_fresh_normal_prototype_session=a"
	freshB := "redx_fresh_normal_prototype_session=b"
	if err := host.SetPlanForTest(n.H, hostedPlan("same-subject", "basic", "month", "active", time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	st, body := call("POST", "/v1/dbs", legacy, `{"name":"legacy"}`)
	if st != 201 {
		t.Fatal("legacy fixture create failed", st)
	}
	oldDB := jsonOf(t, body)["name"].(string)
	if st, _ = call("POST", "/v1/dbs", freshA, `{"name":"fresh"}`); st != 402 {
		t.Fatal("fresh inherited legacy plan", st)
	}
	for _, cookie := range []string{freshA, freshB} {
		if st, _ = call("GET", "/v1/db/"+oldDB+"/files", cookie, ""); st != 404 && st != 403 {
			t.Fatal("fresh read legacy DB", st)
		}
		if st, _ = call("GET", "/v1/owner/dbs", cookie, ""); st != 403 {
			t.Fatal("fresh acquired owner", st)
		}
	}
	for _, sub := range []string{"same-subject", "other-subject"} {
		if err := host.SetPlanForTest(n.H, hostedPlan(canonical(sub), "basic", "month", "active", time.Now().Add(time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	st, body = call("POST", "/v1/dbs", freshA, `{"name":"fresh"}`)
	if st != 201 {
		t.Fatal("fresh fixture create failed", st)
	}
	freshDB := jsonOf(t, body)["name"].(string)
	if freshDB == oldDB {
		t.Fatal("realm DB collision")
	}
	if st, _ = call("PUT", "/v1/db/"+freshDB+"/path/realm.red-xai.db:Box[ID=1].Name", freshA, `"fresh-only"`); st != 200 && st != 201 {
		t.Fatal("fresh write failed", st)
	}
	for _, cookie := range []string{legacy, freshB} {
		for _, route := range []string{"/files", "/path/realm.red-xai.db:Box[ID=1].Name"} {
			if st, body = call("GET", "/v1/db/"+freshDB+route, cookie, ""); st != 404 || strings.Contains(body, "fresh-only") {
				t.Fatal("cross-realm/tenant DB read", st)
			}
		}
	}
	st, body = call("POST", "/v1/keys", freshA, `{"db":"`+freshDB+`","scope":"write","label":"realm-fixture","ttl":"1h"}`)
	if st != 201 {
		t.Fatal("fresh key fixture failed", st)
	}
	key := jsonOf(t, body)["key"].(string)
	if st, _, _ := do(t, "GET", n.URL+"/v1/db/"+freshDB+"/path/realm.red-xai.db:Box[ID=1].Name", key, ""); st != 200 {
		t.Fatal("fresh scoped key cannot read its DB", st)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/db/"+oldDB+"/files", key, ""); st != 404 && st != 403 {
		t.Fatal("fresh scoped key read legacy DB", st)
	}
	if st, body = call("GET", "/v1/keys", legacy, ""); st != 200 || strings.Contains(body, "realm-fixture") {
		t.Fatal("legacy sees fresh key metadata", st)
	}
	if st, body = call("GET", "/v1/keys", freshB, ""); st != 200 || strings.Contains(body, "realm-fixture") {
		t.Fatal("fresh B sees A key metadata", st)
	}
	if st, _ = call("GET", "/v1/dbs", legacy+"; "+freshA, ""); st != 401 {
		t.Fatal("ambiguous realms did not fail closed", st)
	}
	revoked.Store(true)
	if st, _ = call("GET", "/v1/dbs", freshA, ""); st != 401 {
		t.Fatal("revocation ignored", st)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/ui/whoami", n.Key, ""); st != 200 {
		t.Fatal("existing developer key changed", st)
	}
}
