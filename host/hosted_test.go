package host_test

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"redx/billing"
	"redx/host"
	"redx/host/accountsfake"
)

func hostedPlan(account, tier, interval, status string, end time.Time) billing.Plan {
	return billing.Plan{
		Account: account, Tier: tier, Interval: interval, Status: status,
		PeriodEnd: end, Subscription: "sub_" + account, Customer: "cus_test", Updated: time.Now().UTC(),
	}
}

func codeOf(t *testing.T, body string) string {
	t.Helper()
	c, _ := jsonOf(t, body)["code"].(string)
	return c
}

func rawReq(t *testing.T, method, url, key, body string, hdr ...string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestHostedTenantGate(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	end := time.Now().Add(30 * 24 * time.Hour)
	tokA, _ := signIn(t, n, f, regular)

	st, b, _ := do(t, "POST", n.URL+"/v1/dbs", tokA, `{"name":"game"}`, "Content-Type", "application/json")
	if st != 402 || codeOf(t, b) != "plan_required" {
		t.Fatalf("no plan create: %d %s", st, b)
	}
	if st, b, _ = do(t, "GET", n.URL+"/v1/dbs", tokA, ""); st != 403 {
		t.Fatalf("no plan list: %d %s", st, b)
	}

	if err := host.SetPlanForTest(n.H, hostedPlan(regular.Sub, "basic", "year", "active", end)); err != nil {
		t.Fatal(err)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/dbs", tokA, `{"name":"game"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	created := jsonOf(t, b)
	physA, _ := created["name"].(string)
	if created["logical"] != "game" || physA == "" || physA == "game" {
		t.Fatalf("names: %s", b)
	}
	want, err := host.TenantPhysicalName(regular.Sub, "game")
	if err != nil || want != physA {
		t.Fatalf("physical %s want %s err %v", physA, want, err)
	}
	st, b, _ = do(t, "PUT", n.URL+"/v1/db/"+physA+"/path/b:B.K", tokA, `"keep"`)
	if st != 200 && st != 201 {
		t.Fatalf("put: %d %s", st, b)
	}
	if st, b, _ = do(t, "GET", n.URL+"/v1/db/"+physA+"/path/b:B.K", tokA, ""); st != 200 || !strings.Contains(b, "keep") {
		t.Fatalf("get: %d %s", st, b)
	}
	// BoxQL route is reachable for this account. The stub backend has no BoxQL engine (501);
	// a real engine serves POST /v1/db/{name}/bx. Suspended accounts never get that far.
	if st, _, _ = do(t, "POST", n.URL+"/v1/db/"+physA+"/bx", tokA, `{"q":"b:B.K"}`, "Content-Type", "application/json"); st == 401 || st == 403 || st == 402 {
		t.Fatalf("bx should pass the tenant gate, got %d", st)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/dbs", tokA, `{"name":"admin"}`, "Content-Type", "application/json")
	if st != 409 || codeOf(t, b) != "name_unavailable" || !strings.Contains(b, "not available") {
		t.Fatalf("reserved: %d %s", st, b)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/dbs", tokA, `{"name":"default"}`, "Content-Type", "application/json")
	if st != 409 || codeOf(t, b) != "name_unavailable" {
		t.Fatalf("default name: %d %s", st, b)
	}

	other := accountsfake.Identity{Sub: "rxa_OTHER000000000000000000001", Email: "other@example.com", EmailVerified: true, Username: "other_user", AMR: []string{"pwd"}}
	tokB, _ := signIn(t, n, f, other)
	if err := host.SetPlanForTest(n.H, hostedPlan(other.Sub, "basic", "month", "active", end)); err != nil {
		t.Fatal(err)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/dbs", tokB, `{"name":"game"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("other create: %d %s", st, b)
	}
	physB, _ := jsonOf(t, b)["name"].(string)
	if physB == physA {
		t.Fatal("tenants share a physical name")
	}
	if st, b, _ = do(t, "GET", n.URL+"/v1/db/"+physA+"/path/b:B.K", tokB, ""); st != 404 {
		t.Fatalf("cross read: %d %s", st, b)
	}
	if st, b, _ = do(t, "GET", n.URL+"/v1/dbs", tokB, ""); st != 200 || strings.Contains(b, physA) || strings.Contains(b, "redxai_accounts") || strings.Contains(b, `"default"`) {
		t.Fatalf("other list: %d %s", st, b)
	}
	for _, p := range []string{"/v1/admin/status", "/v1/cluster/status", "/v1/owner/accounts", "/v1/updates/apps"} {
		if st, b, _ = do(t, "GET", n.URL+p, tokA, ""); st != 403 {
			t.Fatalf("%s: %d %s", p, st, b)
		}
	}
	if st, b, _ = do(t, "GET", n.URL+"/v1/db/redxai_accounts/path/a:A.K", tokA, ""); st != 404 {
		t.Fatalf("master: %d %s", st, b)
	}
	if st, b, _ = do(t, "GET", n.URL+"/v1/db/default/path/a:A.K", tokA, ""); st != 404 {
		t.Fatalf("default db: %d %s", st, b)
	}

	st, b, _ = do(t, "POST", n.URL+"/v1/keys", tokA, `{"db":"`+physA+`","scope":"read","label":"mine"}`, "Content-Type", "application/json", host.ConfirmHeader, "")
	if st != 428 || codeOf(t, b) != "confirm_required" {
		t.Fatalf("key without confirm: %d %s", st, b)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/keys", tokA, `{"db":"*","scope":"read"}`, "Content-Type", "application/json")
	if st != 404 {
		t.Fatalf("key on *: %d %s", st, b)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/keys", tokA, `{"db":"`+physB+`","scope":"read"}`, "Content-Type", "application/json")
	if st != 404 {
		t.Fatalf("key on other db: %d %s", st, b)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/keys", tokA, `{"db":"`+physA+`","scope":"read","label":"mine"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("key: %d %s", st, b)
	}
	apiKey, _ := jsonOf(t, b)["key"].(string)
	if st, b, _ = do(t, "GET", n.URL+"/v1/db/"+physA+"/path/b:B.K", apiKey, ""); st != 200 {
		t.Fatalf("own key: %d %s", st, b)
	}
	if st, b, _ = do(t, "GET", n.URL+"/v1/db/"+physB+"/path/b:B.K", apiKey, ""); st != 403 && st != 404 {
		t.Fatalf("key cross: %d %s", st, b)
	}
	if st, b, _ = do(t, "GET", n.URL+"/v1/keys", tokA, ""); st != 200 || strings.Contains(b, `"db":"*"`) || !strings.Contains(b, physA) {
		t.Fatalf("key list: %d %s", st, b)
	}

	// Annual basic has the same two-switch budget as monthly basic.
	st, b, _ = do(t, "POST", n.URL+"/v1/dbs", tokA, `{"name":"shop"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("second db: %d %s", st, b)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/dbs", tokA, `{"name":"extra"}`, "Content-Type", "application/json")
	if st != 402 || codeOf(t, b) != "quota_exceeded" || jsonOf(t, b)["limit"] != "host_switch_quota" {
		t.Fatalf("switch cap: %d %s", st, b)
	}

	tokO, _ := signIn(t, n, f, ownerOK)
	if st, b, _ = do(t, "GET", n.URL+"/v1/dbs", tokO, ""); st != 200 || !strings.Contains(b, physA) || !strings.Contains(b, physB) {
		t.Fatalf("owner list: %d %s", st, b)
	}
	audit, err := os.ReadFile(n.H.Cfg.AuditLog)
	if err != nil || !strings.Contains(string(audit), `"event":"owner.read"`) || !strings.Contains(string(audit), "Owner@Example.com") {
		t.Fatalf("owner read audit: %v %s", err, audit)
	}

	if err := host.SetPlanForTest(n.H, hostedPlan(regular.Sub, "basic", "year", "past_due", end)); err != nil {
		t.Fatal(err)
	}
	if st, b, _ = do(t, "GET", n.URL+"/v1/db/"+physA+"/path/b:B.K", tokA, ""); st != 200 {
		t.Fatalf("readonly get: %d %s", st, b)
	}
	if st, b, _ = do(t, "PUT", n.URL+"/v1/db/"+physA+"/path/b:B.K", tokA, `"no"`); st != 402 || codeOf(t, b) != "plan_readonly" {
		t.Fatalf("readonly put: %d %s", st, b)
	}
	if st, b, _ = do(t, "DELETE", n.URL+"/v1/db/"+physA+"?confirm="+physA, tokA, ""); st != 402 {
		t.Fatalf("readonly drop: %d %s", st, b)
	}

	if err := host.SetPlanForTest(n.H, hostedPlan(regular.Sub, "basic", "year", "canceled", time.Now().Add(-4*24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if st, b, _ = do(t, "GET", n.URL+"/v1/db/"+physA+"/path/b:B.K", tokA, ""); st != 402 || codeOf(t, b) != "plan_required" {
		t.Fatalf("suspended get: %d %s", st, b)
	}
	if st, b, _ = do(t, "GET", n.URL+"/v1/dbs", tokA, ""); st != 200 || jsonOf(t, b)["suspended"] != true {
		t.Fatalf("suspended list: %d %s", st, b)
	}
	if _, err := os.Stat(filepath.Join(n.Dir, "dbs", physA)); err != nil {
		t.Fatal("suspended plan must keep the database:", err)
	}

	em := accountsfake.Identity{Sub: "rxa_EMERALD0000000000000000001", Email: "em@example.com", EmailVerified: true, Username: "em_user", AMR: []string{"pwd"}}
	tokE, _ := signIn(t, n, f, em)
	if err := host.SetPlanForTest(n.H, hostedPlan(em.Sub, "emerald", "year", "trialing", end)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two", "three"} {
		st, b, _ = do(t, "POST", n.URL+"/v1/dbs", tokE, `{"name":"`+name+`"}`, "Content-Type", "application/json")
		if st != 201 {
			t.Fatalf("emerald %s: %d %s", name, st, b)
		}
	}

	storer := accountsfake.Identity{Sub: "rxa_STORE000000000000000000001", Email: "store@example.com", EmailVerified: true, Username: "store_user", AMR: []string{"pwd"}}
	tokS, _ := signIn(t, n, f, storer)
	if err := host.SetPlanForTest(n.H, hostedPlan(storer.Sub, "basic", "month", "active", end)); err != nil {
		t.Fatal(err)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/dbs", tokS, `{"name":"pad"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("pad db: %d %s", st, b)
	}
	physS, _ := jsonOf(t, b)["name"].(string)
	pad := filepath.Join(n.Dir, "dbs", physS, "pad")
	pf, err := os.Create(pad)
	if err != nil {
		t.Fatal(err)
	}
	if err := pf.Truncate(1 << 30); err != nil {
		pf.Close()
		t.Fatal(err)
	}
	pf.Close()
	st, b, _ = do(t, "PUT", n.URL+"/v1/db/"+physS+"/path/b:B.K", tokS, `"x"`)
	if st != 402 || codeOf(t, b) != "quota_exceeded" || jsonOf(t, b)["limit"] != "storage_quota" {
		t.Fatalf("storage: %d %s", st, b)
	}
	q, _ := billing.QuotaFor("basic")
	if err := host.AddTrafficForTest(n.H, storer.Sub, q.TrafficBytes); err != nil {
		t.Fatal(err)
	}
	st, b, _ = do(t, "GET", n.URL+"/v1/db/"+physS+"/path/b:B.K", tokS, "")
	if st != 429 || codeOf(t, b) != "quota_exceeded" || jsonOf(t, b)["limit"] != "traffic_quota" {
		t.Fatalf("traffic: %d %s", st, b)
	}
}

func TestTrustedProxyClientIP(t *testing.T) {
	// Untrusted peer: a spoofed X-Forwarded-For is the socket address, so one
	// visitor's failures still share the bucket — and a second header does not split it.
	n := startNode(t, t.TempDir(), nil)
	for i := 0; i < 20; i++ {
		st, _ := rawReq(t, "GET", n.URL+"/v1/dbs", "nope", "", "X-Forwarded-For", "203.0.113.9")
		if st != 401 {
			t.Fatalf("fail %d: %d", i, st)
		}
	}
	if st, _ := rawReq(t, "GET", n.URL+"/v1/dbs", "nope", "", "X-Forwarded-For", "203.0.113.10"); st != 429 {
		t.Fatalf("spoofed XFF must not get its own bucket, got %d", st)
	}
	audit, _ := os.ReadFile(n.H.Cfg.AuditLog)
	if !strings.Contains(string(audit), `"remote":"127.0.0.1"`) || strings.Contains(string(audit), "203.0.113.9") {
		t.Fatalf("audit used the forwarding header from an untrusted peer:\n%s", audit)
	}

	f, iss := startFake(t)
	trusted := startNode(t, t.TempDir(), func(c *host.Config, _ string) {
		c.AccountsIssuer = iss
		c.AccountsClientSecret = "test-client-secret"
		c.AccountsEventsPoll = 3600
		c.OwnerEmails = []string{ownerA, ownerB}
		c.TrustedProxies = []string{"127.0.0.1", "::1"}
	})
	for i := 0; i < 20; i++ {
		st, _ := rawReq(t, "GET", trusted.URL+"/v1/dbs", "nope", "", "X-Forwarded-For", "203.0.113.9")
		if st != 401 {
			t.Fatalf("trusted fail %d: %d", i, st)
		}
	}
	if st, _ := rawReq(t, "GET", trusted.URL+"/v1/dbs", "nope", "", "X-Forwarded-For", "203.0.113.9"); st != 429 {
		t.Fatalf("same client should be limited, got %d", st)
	}
	if st, b := rawReq(t, "GET", trusted.URL+"/v1/dbs", "nope", "", "X-Forwarded-For", "198.51.100.8, 203.0.113.10"); st != 401 {
		t.Fatalf("rightmost untrusted hop should be a different client: %d %s", st, b)
	}
	if st, b := rawReq(t, "GET", trusted.URL+"/v1/dbs", "nope", "", "X-Real-IP", "198.51.100.20"); st != 401 {
		t.Fatalf("X-Real-IP: %d %s", st, b)
	}
	audit, _ = os.ReadFile(trusted.H.Cfg.AuditLog)
	if !strings.Contains(string(audit), "203.0.113.9") || !strings.Contains(string(audit), "203.0.113.10") || !strings.Contains(string(audit), "198.51.100.20") {
		t.Fatalf("audit client IPs:\n%s", audit)
	}

	// Sign-in limiter uses the same client IP. Twenty starts from one address
	// do not lock a second address when the peer is the trusted proxy.
	for i := 0; i < 20; i++ {
		st, b := rawReq(t, "GET", trusted.URL+"/v1/auth/login", "", "", "X-Forwarded-For", "203.0.113.50")
		if st == 429 {
			t.Fatalf("login %d limited early: %s", i, b)
		}
	}
	if st, b := rawReq(t, "GET", trusted.URL+"/v1/auth/login", "", "", "X-Forwarded-For", "203.0.113.50"); st != 429 || !strings.Contains(b, "rate_limited") {
		t.Fatalf("login limit: %d %s", st, b)
	}
	if st, b := rawReq(t, "GET", trusted.URL+"/v1/auth/login", "", "", "X-Forwarded-For", "203.0.113.51"); st == 429 {
		t.Fatalf("other sign-in IP limited: %d %s", st, b)
	}
	_ = f
}

func TestDangerConfirmAfterAuth(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	st, b := rawReq(t, "POST", n.URL+"/v1/keys", "", `{"db":"default","scope":"read"}`, "Content-Type", "application/json")
	if st != 401 {
		t.Fatalf("unauthenticated createKey: %d %s", st, b)
	}
	st, b = rawReq(t, "DELETE", n.URL+"/v1/db/default", "", "")
	if st != 401 {
		t.Fatalf("unauthenticated drop: %d %s", st, b)
	}
	key, _ := mkKey(t, n, map[string]interface{}{"scope": "read", "db": "default"})
	st, b = rawReq(t, "POST", n.URL+"/v1/keys", key, `{"db":"default","scope":"read"}`, "Content-Type", "application/json")
	if st != 403 {
		t.Fatalf("read key createKey: %d %s", st, b)
	}
	st, b = rawReq(t, "DELETE", n.URL+"/v1/db/default", key, "")
	if st != 403 {
		t.Fatalf("read key drop: %d %s", st, b)
	}
	st, b = rawReq(t, "POST", n.URL+"/v1/keys", n.Key, `{"db":"default","scope":"read"}`, "Content-Type", "application/json")
	if st != 428 || codeOf(t, b) != host.ConfirmRequired {
		t.Fatalf("admin without confirm: %d %s", st, b)
	}
	st, b = rawReq(t, "POST", n.URL+"/v1/cluster/promote", n.Key, "")
	if st != 428 {
		t.Fatalf("promote without confirm: %d %s", st, b)
	}
}
