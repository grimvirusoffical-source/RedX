package host_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"redx/host"
	"redx/host/engineadapter"
	"redx/internal/accountscope"
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
		if cookie.Name == "redx_session" && cookie.Value == "collision" {
			subject = canonical("same-subject")
		}
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
	start := func(dir string) *node {
		n := &node{Dir: dir, Srv: httptest.NewUnstartedServer(nil)}
		n.URL = "http://" + n.Srv.Listener.Addr().String()
		cfg := baseCfg(n.Dir)
		cfg.Advertise = n.URL
		h, err := host.New(cfg, engineadapter.Opener(engineadapter.Config{Durability: "sync"}), t.Logf)
		if err != nil {
			t.Fatal(err)
		}
		n.H, n.Key = h, h.BootstrapKey
		n.Srv.Config.Handler = h.Handler()
		n.Srv.Start()
		t.Cleanup(n.Stop)
		host.SetWebsiteRealmAuthorityForTest(n.H, authority.URL, n.URL, authority.Client(), map[string]bool{"same-subject": true, canonical("same-subject"): true})
		return n
	}
	n := start(t.TempDir())
	developerKey := n.Key
	call := func(method, path, cookie, body string) (int, string) {
		contentType := "application/json"
		confirm := "createKey"
		if strings.HasSuffix(path, "/rotate") {
			confirm = "rotateKey"
		}
		if method == "PUT" {
			contentType = "text/x-redx-box"
		}
		return rawReq(t, method, n.URL+path, "", body, "Cookie", cookie, "Origin", n.URL, "Content-Type", contentType, "X-RedX-Confirm", confirm)
	}
	legacy := "redx_session=legacy"
	legacyDTO := "redx_session=collision"
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
	// A legitimate legacy bare ID is exactly the fresh public hash DTO. Its
	// existing plan and database must remain separate without renaming it.
	if err := host.SetPlanForTest(n.H, hostedPlan(canonical("same-subject"), "basic", "month", "active", time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	st, body = call("POST", "/v1/dbs", legacyDTO, `{"name":"fresh"}`)
	if st != 201 {
		t.Fatal("legacy public-DTO fixture failed", st)
	}
	collisionDB := jsonOf(t, body)["name"].(string)
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
		private, _ := accountscope.Key(freshIssuer, sub)
		// Bind the authoritative identity before test-only entitlement setup.
		cookie := freshA
		if sub == "other-subject" {
			cookie = freshB
		}
		if st, _ := call("GET", "/v1/ui/whoami", cookie, ""); st != 200 {
			t.Fatal("fresh identity fixture failed", st)
		}
		p := hostedPlan(private, "basic", "month", "active", time.Now().Add(time.Hour))
		p.OwnerIssuer, p.OwnerSubject = freshIssuer, sub
		if err := host.SetPlanForTest(n.H, p); err != nil {
			t.Fatal(err)
		}
	}
	st, body = call("POST", "/v1/dbs", freshA, `{"name":"fresh"}`)
	if st != 201 {
		t.Fatal("fresh fixture create failed", st)
	}
	freshDB := jsonOf(t, body)["name"].(string)
	if freshDB == oldDB || freshDB == collisionDB {
		t.Fatal("realm DB collision")
	}
	if st, _ = call("PUT", "/v1/db/"+freshDB+"/path/realm.red-xai.db:Box[ID=1].Name", freshA, `"fresh-only"`); st != 200 && st != 201 {
		t.Fatal("fresh write failed", st)
	}
	for _, cookie := range []string{legacy, legacyDTO, freshB} {
		for _, route := range []string{"/files", "/path/realm.red-xai.db:Box[ID=1].Name"} {
			if st, body = call("GET", "/v1/db/"+freshDB+route, cookie, ""); st != 404 || strings.Contains(body, "fresh-only") {
				t.Fatal("cross-realm/tenant DB read", st)
			}
		}
	}
	st, body = call("POST", "/v1/keys", freshA, `{"db":"`+freshDB+`","scope":"admin","label":"realm-fixture","ttl":"1h"}`)
	if st != 201 {
		t.Fatal("fresh key fixture failed", st)
	}
	key := jsonOf(t, body)["key"].(string)
	keyID := jsonOf(t, body)["id"].(string)
	if st, _ := call("POST", "/v1/keys/"+keyID+"/rotate", legacyDTO, `{}`); st != 404 {
		t.Fatal("legacy public-DTO identity rotated fresh key", st)
	}
	st, body = call("POST", "/v1/keys/"+keyID+"/rotate", freshA, `{}`)
	if st != 201 {
		t.Fatal("fresh key rotation lost tuple", st)
	}
	key = jsonOf(t, body)["key"].(string)
	// Administrative developer-key descendants and device pairing must retain
	// paid-tenant ownership too; omitting it would bypass hosted quota gates.
	st, body, _ = do(t, "POST", n.URL+"/v1/keys", key, `{"scope":"read","label":"child-fixture"}`)
	if st != 201 {
		t.Fatal("fresh developer-key descendant failed", st)
	}
	childID := jsonOf(t, body)["id"].(string)
	st, body, _ = do(t, "POST", n.URL+"/v1/keys/pairing", key, `{"scope":"read","label":"paired-fixture"}`)
	if st != 201 {
		t.Fatal("fresh device pairing issue failed", st)
	}
	code := jsonOf(t, body)["code"].(string)
	st, body, _ = do(t, "POST", n.URL+"/v1/pair/exchange", "", `{"code":"`+code+`"}`)
	if st != 201 {
		t.Fatal("fresh device pairing redemption failed", st)
	}
	pairedID := jsonOf(t, body)["id"].(string)
	for _, id := range []string{childID, pairedID} {
		rec, ok := n.H.KS.Get(id)
		private, _ := accountscope.Key(freshIssuer, "same-subject")
		if !ok || rec.Owner != private || rec.OwnerIssuer != freshIssuer || rec.OwnerSubject != "same-subject" {
			t.Fatal("developer/pairing key lost realm ownership")
		}
	}
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
	assertPersistentIsolation := func() {
		t.Helper()
		for _, tc := range []struct{ cookie, own, other string }{{legacyDTO, collisionDB, freshDB}, {freshA, freshDB, collisionDB}} {
			st, body := call("GET", "/v1/dbs", tc.cookie, "")
			if st != 200 || !strings.Contains(body, tc.own) || strings.Contains(body, tc.other) {
				t.Fatal("persistent DB namespace crossover", st)
			}
			if st, _ := call("GET", "/v1/db/"+tc.other+"/files", tc.cookie, ""); st != 404 {
				t.Fatal("persistent DB read crossover", st)
			}
		}
		if st, _, _ := do(t, "GET", n.URL+"/v1/db/"+freshDB+"/path/realm.red-xai.db:Box[ID=1].Name", key, ""); st != 200 {
			t.Fatal("persistent scoped key failed", st)
		}
		if st, _ := call("GET", "/v1/keys", legacyDTO, ""); st != 200 {
			t.Fatal("legacy key list failed", st)
		}
		st, oldBody := call("GET", "/v1/ui/whoami", legacyDTO, "")
		if st != 200 {
			t.Fatal("legacy whoami failed", st)
		}
		st, freshBody := call("GET", "/v1/ui/whoami", freshA, "")
		if st != 200 {
			t.Fatal("fresh whoami failed", st)
		}
		oldAccount := jsonOf(t, oldBody)["account"].(map[string]interface{})
		freshAccount := jsonOf(t, freshBody)["account"].(map[string]interface{})
		if oldAccount["sub"] != freshAccount["sub"] || oldAccount["storage_subject"] != nil || freshAccount["storage_subject"] == nil {
			t.Fatal("public DTO or private browser namespace changed")
		}
		for _, path := range []string{"/v1/billing/checkout", "/v1/billing/portal"} {
			if st, body := call("POST", path, freshA, `{}`); st != 503 || !strings.Contains(body, "realm_billing_unavailable") {
				t.Fatal("unreviewed fresh provider operation enabled", st)
			}
		}
	}
	assertPersistentIsolation()
	originalDir := n.Dir
	n.Stop()
	n = start(originalDir)
	assertPersistentIsolation()
	n.Stop()
	var backup bytes.Buffer
	if err := host.OfflineBackup(originalDir, &backup, "", false); err != nil {
		t.Fatal(err)
	}
	sc, err := host.ExtractSnapshot(bytes.NewReader(backup.Bytes()), filepath.Join(t.TempDir(), "dbs"))
	if err != nil || len(sc.RealmOwners) == 0 || len(sc.BillingPlans) == 0 || len(sc.BillingUsage) == 0 {
		t.Fatal("backup lost persistent namespace metadata", err)
	}
	restoredDir := t.TempDir()
	if _, err := host.OfflineRestore(restoredDir, bytes.NewReader(backup.Bytes()), "", false); err != nil {
		t.Fatal(err)
	}
	n = start(restoredDir)
	assertPersistentIsolation()
	revoked.Store(true)
	if st, _ = call("GET", "/v1/dbs", freshA, ""); st != 401 {
		t.Fatal("revocation ignored", st)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/ui/whoami", developerKey, ""); st != 200 {
		t.Fatal("existing developer key changed", st)
	}
	// A missing registry is not re-created by adopting resource metadata. Old
	// legacy users still work, and no fresh cookie/key can acquire the orphan.
	n.Stop()
	if err := os.Remove(filepath.Join(restoredDir, "realm-owners.json")); err != nil {
		t.Fatal(err)
	}
	n = start(restoredDir)
	revoked.Store(false)
	if st, _ := call("GET", "/v1/dbs", freshA, ""); st != 401 {
		t.Fatal("fresh orphan metadata adopted", st)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/db/"+freshDB+"/files", key, ""); st != 401 {
		t.Fatal("orphan fresh key authenticated", st)
	}
	if st, _ := call("GET", "/v1/dbs", legacyDTO, ""); st != 200 {
		t.Fatal("legacy collision owner locked out", st)
	}
}
