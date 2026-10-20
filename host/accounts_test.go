package host_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"redx/host"
	"redx/host/accountsfake"
)

// Placeholders only: real owner addresses live in deploy config, never in the repository.
const (
	ownerA = "owner@example.com"
	ownerB = "support-owner@example.com"
)

func startFake(t *testing.T) (*accountsfake.Server, string) {
	t.Helper()
	f := accountsfake.New()
	srv := httptest.NewServer(f.Handler())
	t.Cleanup(srv.Close)
	f.Issuer = srv.URL
	return f, srv.URL
}

func startAcctNode(t *testing.T, issuer string) *node {
	t.Helper()
	return startNode(t, t.TempDir(), func(c *host.Config, u string) {
		c.AccountsIssuer = issuer
		c.AccountsClientSecret = "test-client-secret"
		c.AccountsEventsPoll = 3600 // tests call PollAccountEventsNow; don't race the loop
		c.OwnerEmails = []string{ownerA, ownerB}
	})
}

// signIn runs the whole browser flow: /v1/auth/login -> fake authorize -> /v1/auth/callback -> handoff.
func signIn(t *testing.T, n *node, f *accountsfake.Server, id accountsfake.Identity) (token string, account map[string]interface{}) {
	t.Helper()
	f.SetNext(id)
	loc := browse(t, n.URL+"/v1/auth/login?return=owner")
	u, _ := url.Parse(loc)
	if u.Path != "/" || !strings.HasPrefix(u.Fragment, "/signin?") {
		t.Fatalf("callback did not return to the console: %s", loc)
	}
	q, _ := url.ParseQuery(strings.TrimPrefix(u.Fragment, "/signin?"))
	if q.Get("error") != "" || q.Get("handoff") == "" || q.Get("return") != "owner" {
		t.Fatalf("sign-in failed: %s", loc)
	}
	st, b, _ := do(t, "POST", n.URL+"/v1/auth/handoff", "", `{"code":"`+q.Get("handoff")+`"}`, "Content-Type", "application/json")
	if st != 200 {
		t.Fatalf("handoff: %d %s", st, b)
	}
	m := jsonOf(t, b)
	if st, _, _ := do(t, "POST", n.URL+"/v1/auth/handoff", "", `{"code":"`+q.Get("handoff")+`"}`, "Content-Type", "application/json"); st != 401 {
		t.Fatalf("handoff code must be single use, got %d", st)
	}
	token, _ = m["token"].(string)
	if !strings.HasPrefix(token, "rxs_") {
		t.Fatalf("token: %v", m)
	}
	account, _ = m["account"].(map[string]interface{})
	return token, account
}

// browse follows redirects with a cookie jar and returns the final console location (with its fragment).
func browse(t *testing.T, start string) string {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	final := ""
	c := &http.Client{Jar: jar, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if strings.Contains(r.URL.String(), "#") || r.URL.Fragment != "" {
			final = r.URL.String()
			return http.ErrUseLastResponse
		}
		return nil
	}}
	res, err := c.Get(start)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if final == "" {
		final = res.Header.Get("Location")
	}
	return final
}

var (
	regular      = accountsfake.Identity{Sub: "rxa_REGULAR00000000000000000001", Email: "user@example.com", EmailVerified: true, Username: "regular_user", AMR: []string{"pwd"}}
	ownerNo2FA   = accountsfake.Identity{Sub: "rxa_OWNER0000000000000000000001", Email: ownerA, EmailVerified: true, Username: "owner_account", AMR: []string{"pwd"}}
	ownerUnverf  = accountsfake.Identity{Sub: "rxa_OWNER0000000000000000000001", Email: ownerA, EmailVerified: false, Username: "owner_account", AMR: []string{"pwd", "otp"}}
	ownerOK      = accountsfake.Identity{Sub: "rxa_OWNER0000000000000000000001", Email: "Owner@Example.com", EmailVerified: true, Username: "owner_account", AMR: []string{"pwd", "otp"}, OwnerScope: true}
	owner2SMS    = accountsfake.Identity{Sub: "rxa_OWNER0000000000000000000002", Email: ownerB, EmailVerified: true, Username: "support_owner", AMR: []string{"pwd", "sms"}, OwnerScope: true}
	ownerNoScope = accountsfake.Identity{Sub: "rxa_OWNER0000000000000000000001", Email: ownerA, EmailVerified: true, Username: "owner_account", AMR: []string{"pwd", "otp"}}
)

func TestAccountsConfigEndpoint(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	st, b, _ := do(t, "GET", n.URL+"/v1/auth/config", "", "")
	if st != 200 || jsonOf(t, b)["enabled"] != false {
		t.Fatalf("accounts must be off by default: %d %s", st, b)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/auth/login", "", ""); st != 404 {
		t.Fatalf("login with accounts off = %d", st)
	}
	// with accounts off nothing is hidden: an admin key sees a database called redxai_accounts
	do(t, "POST", n.URL+"/v1/dbs", n.Key, `{"name":"redxai_accounts"}`)
	if _, b, _ := do(t, "GET", n.URL+"/v1/dbs", n.Key, ""); !strings.Contains(b, "redxai_accounts") {
		t.Fatalf("accounts off: %s", b)
	}
	_, iss := startFake(t)
	n2 := startAcctNode(t, iss)
	st, b, _ = do(t, "GET", n2.URL+"/v1/auth/config", "", "")
	m := jsonOf(t, b)
	if st != 200 || m["enabled"] != true || m["issuer"] != iss || m["client_id"] != "redx" || m["min_age"] != float64(13) {
		t.Fatalf("config: %s", b)
	}
	if strings.Contains(b, ownerA) {
		t.Fatal("owner emails must never be exposed")
	}
	_, b, _ = do(t, "GET", n2.URL+"/v1/admin/config", n2.Key, "")
	if strings.Contains(b, ownerA) || !strings.Contains(b, "(2 set, hidden)") {
		t.Fatalf("admin config must redact owner_emails: %s", b)
	}
}

func TestAccountsConfigValidation(t *testing.T) {
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	c := host.DefaultConfig()
	if err := c.ApplyEnv(get(map[string]string{"REDXAI_OWNER_EMAILS": " Owner@Example.com , " + ownerB, "REDX_ACCOUNTS_ISSUER": "https://accounts.red-xai.example/",
		"REDX_ACCOUNTS_CLIENT_SECRET": "not-a-real-secret"})); err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(c.OwnerEmails) != 2 || c.OwnerEmails[0] != ownerA || c.AccountsIssuer != "https://accounts.red-xai.example" || c.AccountsMasterDB != "redxai_accounts" || c.AccountsClientID != "redx" {
		t.Fatalf("normalised config: %+v", c)
	}
	for _, bad := range []string{"http://accounts.red-xai.example", "ftp://x", "not a url"} {
		c := host.DefaultConfig()
		c.AccountsIssuer = bad
		if err := c.Validate(); err == nil {
			t.Fatalf("issuer %q must be refused", bad)
		}
	}
	c = host.DefaultConfig()
	c.OwnerEmails = []string{"not-an-email"}
	if err := c.Validate(); err == nil {
		t.Fatal("bad owner email must be refused")
	}
	c = host.DefaultConfig()
	c.AccountsIssuer = "http://127.0.0.1:9"
	c.AccountsClientSecret = "dev-secret"
	if err := c.Validate(); err != nil {
		t.Fatalf("loopback http issuer is fine for development: %v", err)
	}
	c = host.DefaultConfig()
	c.AccountsIssuer = "https://accounts.red-xai.example"
	if err := c.Validate(); err == nil {
		t.Fatal("confidential client must refuse to start without a client secret")
	}
}

func TestAccountsSignInRegularUser(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	tok, acct := signIn(t, n, f, regular)
	if acct["owner"] != false || acct["username"] != "regular_user" {
		t.Fatalf("account: %v", acct)
	}
	st, b, _ := do(t, "GET", n.URL+"/v1/ui/whoami", tok, "")
	m := jsonOf(t, b)
	if st != 200 || m["owner"] != false || m["host_admin"] != false || m["scope"] != "none" {
		t.Fatalf("whoami: %d %s", st, b)
	}
	// no database rights, no owner pages, and no hint of the master database
	for _, p := range []string{"/v1/owner/accounts", "/v1/owner/overview", "/v1/owner/dbs", "/v1/owner/audit"} {
		st, b, _ := do(t, "GET", n.URL+p, tok, "")
		if st != 403 || strings.Contains(b, "redxai") || strings.Contains(b, "reason") {
			t.Fatalf("%s for a regular account = %d %s", p, st, b)
		}
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/dbs", tok, ""); st != 403 {
		t.Fatalf("regular account lists dbs: %d", st)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/owner/accounts", "", ""); st != 401 {
		t.Fatalf("anonymous owner route = %d", st)
	}
	// API keys keep working next to account sessions
	if st, _, _ := do(t, "GET", n.URL+"/v1/dbs", n.Key, ""); st != 200 {
		t.Fatalf("api key: %d", st)
	}
	// sign-out ends the session
	do(t, "POST", n.URL+"/v1/auth/logout", tok, "")
	if st, _, _ := do(t, "GET", n.URL+"/v1/ui/whoami", tok, ""); st != 401 {
		t.Fatalf("after logout = %d", st)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/ui/whoami", "rxs_forged", ""); st != 401 {
		t.Fatal("forged session accepted")
	}
}

func TestAccountsOwnerNeeds2FAAndVerifiedEmail(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	for _, c := range []struct {
		id     accountsfake.Identity
		reason string
	}{{ownerNo2FA, "owner_2fa_required"}, {ownerUnverf, "owner_email_unverified"}, {ownerNoScope, "owner_scope_missing"}} {
		tok, acct := signIn(t, n, f, c.id)
		if acct["owner"] != false || acct["owner_blocked"] != c.reason {
			t.Fatalf("%s: %v", c.reason, acct)
		}
		st, b, _ := do(t, "GET", n.URL+"/v1/owner/accounts", tok, "")
		if st != 403 || jsonOf(t, b)["reason"] != c.reason {
			t.Fatalf("%s: owner route = %d %s", c.reason, st, b)
		}
		if st, _, _ := do(t, "GET", n.URL+"/v1/dbs", tok, ""); st != 403 {
			t.Fatalf("%s: no host rights without owner rights, got %d", c.reason, st)
		}
	}
}

func seedMaster(t *testing.T, n *node, tok string) {
	t.Helper()
	if st, b, _ := do(t, "POST", n.URL+"/v1/dbs", tok, `{"name":"redxai_accounts"}`); st != 201 {
		t.Fatalf("owner creates master db: %d %s", st, b)
	}
	recs := []map[string]interface{}{
		{"key": "rxa_AAAA", "username": "grim_player1", "email": "player1@example.com", "emailVerified": true, "passHash": "argon2id$SECRET",
			"totpSecretEnc": "SEALED", "phoneEnc": "SEALED", "dob": "2001-07-04", "status": "active", "twoFactor": "app", "createdMs": 2},
		{"key": "rxa_BBBB", "username": "teen_player", "email": "teen@example.com", "emailVerified": false, "passHash": "argon2id$SECRET2",
			"dob": time.Now().AddDate(-14, 0, -1).Format("2006-01-02"), "status": "banned", "banReason": "spam", "createdMs": 1},
	}
	for i, r := range recs {
		body, _ := json.Marshal(map[string]interface{}{"value": r})
		p := url.PathEscape("account.red-xai.db:Record[ID=" + string(rune('1'+i)) + "]")
		if st, b, _ := do(t, "PUT", n.URL+"/v1/db/redxai_accounts/path/"+p, tok, string(body), "Content-Type", "application/json"); st != 200 {
			t.Fatalf("seed: %d %s", st, b)
		}
	}
}

func TestAccountsOwnerSeesEverythingAndIsAudited(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	tok, acct := signIn(t, n, f, ownerOK)
	if acct["owner"] != true {
		t.Fatalf("owner: %v", acct)
	}
	if _, b, _ := do(t, "GET", n.URL+"/v1/ui/whoami", tok, ""); jsonOf(t, b)["host_admin"] != true || jsonOf(t, b)["owner"] != true {
		t.Fatalf("whoami: %s", b)
	}
	seedMaster(t, n, tok)
	do(t, "POST", n.URL+"/v1/dbs", n.Key, `{"name":"game"}`)

	st, b, _ := do(t, "GET", n.URL+"/v1/owner/accounts", tok, "")
	m := jsonOf(t, b)
	if st != 200 || m["total"] != float64(2) {
		t.Fatalf("owner accounts: %d %s", st, b)
	}
	for _, secret := range []string{"argon2id", "SEALED", "passHash", "totpSecretEnc", "phoneEnc", "2001-07-04", `"dob"`} {
		if strings.Contains(b, secret) {
			t.Fatalf("owner view leaks %q: %s", secret, b)
		}
	}
	first := m["accounts"].([]interface{})[0].(map[string]interface{})
	if first["username"] != "grim_player1" || first["ageBand"] != "18plus" || first["age"] == nil {
		t.Fatalf("account view: %v", first)
	}
	if _, b, _ := do(t, "GET", n.URL+"/v1/owner/accounts?q=teen", tok, ""); jsonOf(t, b)["total"] != float64(1) || !strings.Contains(b, `"13to17"`) {
		t.Fatalf("search: %s", b)
	}
	if st, b, _ := do(t, "GET", n.URL+"/v1/owner/accounts/rxa_BBBB", tok, ""); st != 200 || !strings.Contains(b, "spam") {
		t.Fatalf("one account: %d %s", st, b)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/owner/accounts/rxa_NOPE", tok, ""); st != 404 {
		t.Fatal("unknown account")
	}
	_, b, _ = do(t, "GET", n.URL+"/v1/owner/dbs", tok, "")
	if !strings.Contains(b, `"name":"redxai_accounts","master":true`) || !strings.Contains(b, `"game"`) {
		t.Fatalf("owner dbs: %s", b)
	}
	if _, b, _ := do(t, "GET", n.URL+"/v1/dbs", tok, ""); !strings.Contains(b, "redxai_accounts") {
		t.Fatalf("owner lists the master db: %s", b)
	}
	// the second owner (SMS 2FA) has the same rights
	tok2, acct2 := signIn(t, n, f, owner2SMS)
	if acct2["owner"] != true {
		t.Fatalf("second owner: %v", acct2)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/owner/accounts", tok2, ""); st != 200 {
		t.Fatal("second owner")
	}

	// audit: every owner read is logged with the acting owner and the target, and never with a token
	raw, _ := os.ReadFile(n.H.Cfg.AuditLog)
	log := string(raw)
	for _, must := range []string{`"event":"owner.read"`, `"actor":"Owner@Example.com"`, `"actor":"` + ownerB + `"`, `"target":"account rxa_BBBB"`,
		`"target":"/v1/owner/dbs"`, `"event":"owner.signin"`} {
		if !strings.Contains(log, must) {
			t.Fatalf("audit lacks %s", must)
		}
	}
	if strings.Contains(log, tok) || strings.Contains(log, "rxs_") || strings.Contains(log, "argon2id") {
		t.Fatal("audit log contains a session token or secret")
	}
	if _, b, _ := do(t, "GET", n.URL+"/v1/owner/audit", tok, ""); !strings.Contains(b, "owner.read") {
		t.Fatalf("owner audit: %s", b)
	}
	if _, b, _ := do(t, "GET", n.URL+"/v1/owner/overview", tok, ""); jsonOf(t, b)["accounts"] != float64(2) || jsonOf(t, b)["master_exists"] != true {
		t.Fatalf("overview: %s", b)
	}
}

func TestAccountsMasterDBHiddenFromNonOwners(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	tok, _ := signIn(t, n, f, ownerOK)
	seedMaster(t, n, tok)
	admin := n.Key // a host-wide admin API key ("*"): still not an owner
	p := "/path/" + url.PathEscape("account.red-xai.db:Record[ID=1]")
	stM, bM, _ := do(t, "GET", n.URL+"/v1/db/redxai_accounts"+p, admin, "")
	stX, bX, _ := do(t, "GET", n.URL+"/v1/db/nosuchdb"+p, admin, "")
	if stM != 404 || stM != stX || bM != bX {
		t.Fatalf("master db must look like a missing db: %d %s vs %d %s", stM, bM, stX, bX)
	}
	if st, _, _ := do(t, "POST", n.URL+"/v1/db/redxai_accounts/query", admin, "prefix:"); st != 404 {
		t.Fatalf("query master as admin = %d", st)
	}
	if st, _, _ := do(t, "PUT", n.URL+"/v1/db/redxai_accounts"+p, admin, "1"); st != 404 {
		t.Fatalf("write master as admin = %d", st)
	}
	if _, b, _ := do(t, "GET", n.URL+"/v1/dbs", admin, ""); strings.Contains(b, "redxai_accounts") {
		t.Fatalf("admin key lists the master db: %s", b)
	}
	if _, b, _ := do(t, "GET", n.URL+"/v1/stats", admin, ""); strings.Contains(b, "redxai_accounts") {
		t.Fatalf("stats leak: %s", b)
	}
	if st, _, _ := do(t, "POST", n.URL+"/v1/dbs", admin, `{"name":"redxai_accounts"}`); st != 403 {
		t.Fatalf("admin may not create/probe the master db: %d", st)
	}
	if st, _, _ := do(t, "POST", n.URL+"/v1/keys", admin, `{"db":"redxai_accounts","scope":"read"}`); st != 403 {
		t.Fatalf("admin may not mint a master-db key: %d", st)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/admin/backup", admin, ""); st != 403 {
		t.Fatalf("full backup includes the master db: owner only, got %d", st)
	}
	if st, _, _ := do(t, "POST", n.URL+"/v1/cluster/join-token", admin, `{}`); st != 403 {
		t.Fatalf("join token replicates the master db: owner only, got %d", st)
	}
	// the owner can mint the accounts service's key scoped to exactly the master db; that key works
	st, b, _ := do(t, "POST", n.URL+"/v1/keys", tok, `{"db":"redxai_accounts","scope":"write","label":"red-xai-accounts service"}`)
	if st != 201 {
		t.Fatalf("owner mints service key: %d %s", st, b)
	}
	svc := jsonOf(t, b)["key"].(string)
	if st, _, _ := do(t, "GET", n.URL+"/v1/db/redxai_accounts"+p, svc, ""); st != 200 {
		t.Fatalf("service key reads master: %d", st)
	}
	if _, b, _ := do(t, "GET", n.URL+"/v1/keys", admin, ""); strings.Contains(b, "redxai_accounts") {
		t.Fatalf("admin key sees master-db keys: %s", b)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/admin/backup", tok, ""); st != 200 {
		t.Fatalf("owner backup = %d", st)
	}
}

func TestAccountsCallbackRejectsForgedState(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	// a callback without the browser's state cookie (login CSRF) is refused
	loc := browse(t, n.URL+"/v1/auth/callback?code=abc&state=forged")
	if !strings.Contains(loc, "error=state") {
		t.Fatalf("forged state: %s", loc)
	}
	// the provider refusing (e.g. under the app's minimum age) comes back as access_denied
	f.SetNext(accountsfake.Identity{Error: "access_denied"})
	if loc := browse(t, n.URL+"/v1/auth/login"); !strings.Contains(loc, "error=access_denied") {
		t.Fatalf("access_denied: %s", loc)
	}
	f.SetNext(accountsfake.Identity{Error: "email_unverified", Login: "new@example.com"})
	if loc := browse(t, n.URL+"/v1/auth/login"); !strings.Contains(loc, "error=email_unverified") || !strings.Contains(loc, "login=new%40example.com") {
		t.Fatalf("email_unverified: %s", loc)
	}
	f.SetNext(accountsfake.Identity{Error: "email_unverified", Login: "https://evil.example/phish"})
	if loc := browse(t, n.URL+"/v1/auth/login"); !strings.Contains(loc, "error=email_unverified") || strings.Contains(loc, "login=") {
		t.Fatalf("unsafe login hint must be dropped: %s", loc)
	}
	f.SetNext(accountsfake.Identity{Error: "server_error"})
	if loc := browse(t, n.URL+"/v1/auth/login"); !strings.Contains(loc, "error=provider") {
		t.Fatalf("other provider error: %s", loc)
	}
	// login sends PKCE S256 and the exact redirect
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := c.Get(n.URL + "/v1/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	u, _ := url.Parse(res.Header.Get("Location"))
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 || q.Get("redirect_uri") != n.URL+"/v1/auth/callback" ||
		q.Get("client_id") != "redx" || q.Get("nonce") == "" || q.Get("state") == "" || q.Get("scope") != "openid profile email owner" {
		t.Fatalf("authorize request: %s", u)
	}
	ck := res.Header.Get("Set-Cookie")
	if !strings.Contains(ck, "HttpOnly") || !strings.Contains(ck, "SameSite=Lax") || !strings.Contains(ck, "Path=/v1/auth/callback") {
		t.Fatalf("state cookie: %s", ck)
	}
}

func postJSON(t *testing.T, u, body string) (int, map[string]interface{}) {
	t.Helper()
	st, b, _ := do(t, "POST", u, "", body, "Content-Type", "application/json")
	return st, jsonOf(t, b)
}

func TestAccountsSignupProxy(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	A := n.URL + "/v1/auth"
	st, b, _ := do(t, "GET", A+"/tos", "", "")
	tos := jsonOf(t, b)
	if st != 200 || tos["version"] != "2026-10-19" || !strings.Contains(tos["text"].(string), "Terms") {
		t.Fatalf("tos: %d %s", st, b)
	}
	if st, m := postJSON(t, A+"/tos/agree", `{"grant":"rxa_t_nope"}`); st != 409 || m["error"] != "tos_not_read" {
		t.Fatalf("agree before read: %d %v", st, m)
	}
	if st, m := postJSON(t, A+"/tos/read", `{"version":"old"}`); st != 409 || m["error"] != "tos_changed" {
		t.Fatalf("old version: %d %v", st, m)
	}
	grant := func() string {
		_, m := postJSON(t, A+"/tos/read", `{"version":"2026-10-19"}`)
		g := m["grant"].(string)
		if st, m := postJSON(t, A+"/tos/agree", `{"grant":"`+g+`"}`); st != 200 || m["stage"] != "agreed" {
			t.Fatalf("agree: %d %v", st, m)
		}
		return g
	}
	// live validation
	if _, m := postJSON(t, A+"/validate/username", `{"username":"takenuser1"}`); m["ok"] != false {
		t.Fatalf("taken username: %v", m)
	}
	if _, m := postJSON(t, A+"/validate/username", `{"username":"good_name1"}`); m["ok"] != true {
		t.Fatalf("good username: %v", m)
	}
	if _, m := postJSON(t, A+"/validate/email", `{"email":"x@mailinator.com"}`); m["ok"] != false {
		t.Fatalf("disposable: %v", m)
	}
	if _, m := postJSON(t, A+"/validate/password", `{"password":"Abcdefgh123!"}`); m["ok"] != true {
		t.Fatalf("password: %v", m)
	}
	under := time.Now().AddDate(-12, 0, 0).Format("01/02/2006")
	if _, m := postJSON(t, A+"/validate/dob", `{"dob":"`+under+`"}`); m["ok"] != false || m["error"] != "under_min_age" || m["age"] != float64(12) {
		t.Fatalf("dob: %v", m)
	}
	body := func(mod map[string]interface{}) string {
		r := map[string]interface{}{"firstName": "Josh", "lastName": "Franklinn", "username": "grim_player1", "password": "Abcdefgh123!", "passwordConfirm": "Abcdefgh123!",
			"email": "new@example.com", "emailConfirm": "new@example.com", "dob": "07/04/2001", "tosGrant": "x",
			"twoFactor": "app", "acknowledgeFalseInfo": true}
		for k, v := range mod {
			r[k] = v
		}
		b, _ := json.Marshal(r)
		return string(b)
	}
	for _, c := range []struct {
		mod  map[string]interface{}
		st   int
		code string
	}{
		{map[string]interface{}{"firstName": ""}, 400, "first_name_required"},
		{map[string]interface{}{"lastName": " "}, 400, "last_name_required"},
		{map[string]interface{}{"firstName": "Josh2"}, 400, "first_name_chars"},
		{map[string]interface{}{"middleName": "---"}, 400, "middle_name_chars"},
		{map[string]interface{}{"lastName": strings.Repeat("a", 51)}, 400, "last_name_long"},
		{map[string]interface{}{"dob": under}, 403, "under_min_age"},
		{map[string]interface{}{"twoFactor": "redxai_auth"}, 400, "twofactor_unavailable"},
		{map[string]interface{}{"twoFactor": "none"}, 400, "no2fa_ack_required"},
		{map[string]interface{}{"twoFactor": "phone", "phone": "555"}, 400, "phone_invalid"},
		{map[string]interface{}{"acknowledgeFalseInfo": false}, 400, "false_info_ack_required"},
		{map[string]interface{}{"emailConfirm": "other@example.com"}, 400, "email_mismatch"},
		{map[string]interface{}{"passwordConfirm": "Abcdefgh123?"}, 400, "password_mismatch"},
		{map[string]interface{}{"username": "ab_12345"}, 400, "username_letters"},
		{map[string]interface{}{"password": "short1A!"}, 400, "password_short"},
		{map[string]interface{}{"tosGrant": ""}, 400, "tos_required"},
		{map[string]interface{}{"tosGrant": "rxa_t_unknown"}, 400, "tos_grant_invalid"}, // passes RedX, refused by Red-XAI Accounts
	} {
		if st, m := postJSON(t, A+"/signup", body(c.mod)); st != c.st || m["error"] != c.code {
			t.Fatalf("%v: %d %v", c.mod, st, m)
		}
	}
	if len(f.Signups) != 0 {
		t.Fatal("invalid sign-ups must not create accounts")
	}
	st, m := postJSON(t, A+"/signup", body(map[string]interface{}{"tosGrant": grant()}))
	if st != 201 || m["handle"] != nil || m["step"] != "verify_email" || m["emailSent"] != true || m["totp"] == nil {
		t.Fatalf("signup: %d %v", st, m)
	}
	if _, has := m["session"]; has {
		t.Fatal("the Red-XAI session must stay on the server")
	}
	until, _ := m["pendingUntilMs"].(float64)
	if until < float64(time.Now().Add(23*time.Hour).UnixMilli()) {
		t.Fatalf("pendingUntilMs: %v", m["pendingUntilMs"])
	}
	acct, _ := m["account"].(map[string]interface{})
	if acct["email"] != "new@example.com" || acct["firstName"] != "Josh" {
		t.Fatalf("account: %v", acct)
	}
	if len(f.Signups) != 1 || f.Signups[0].App != "redx" || f.Signups[0].FirstName != "Josh" || f.Signups[0].LastName != "Franklinn" || !f.Signups[0].AcknowledgeFalseInfo || f.Signups[0].TwoFactor != "app" {
		t.Fatalf("forwarded: %+v", f.Signups)
	}
	rst, raw, _ := do(t, "POST", A+"/email/resend", "", `{"login":"grim_player1"}`, "Content-Type", "application/json")
	rm := jsonOf(t, raw)
	if rst != 200 || rm["ok"] != true || len(f.EmailResendLogins) != 1 || f.EmailResendLogins[0] != "grim_player1" {
		t.Fatalf("resend: %d %v logins=%v", rst, rm, f.EmailResendLogins)
	}
	if len(f.ClientIPs) == 0 || f.ClientIPs[len(f.ClientIPs)-1] == "" {
		t.Fatal("resend must forward the client IP")
	}
	f.SetEmailResendAfter("120")
	rst, raw, rh := do(t, "POST", A+"/email/resend", "", `{"login":"grim_player1"}`, "Content-Type", "application/json")
	rm = jsonOf(t, raw)
	if rst != 429 || rm["error"] != "rate_limited" || rh.Get("Retry-After") != "120" || rm["retryAfter"] != float64(120) {
		t.Fatalf("resend limited: %d %v retry=%q", rst, rm, rh.Get("Retry-After"))
	}
	f.SetEmailResendAfter("")
	if st, m := postJSON(t, A+"/email/resend", `{"login":""}`); st != 400 || m["error"] != "bad_request" {
		t.Fatalf("empty resend: %d %v", st, m)
	}
	// the mail server can refuse the first send; the screen still has Resend
	f.SetEmailSendFails(true)
	st, m = postJSON(t, A+"/signup", body(map[string]interface{}{"tosGrant": grant(), "username": "second_user", "email": "two@example.com",
		"emailConfirm": "two@example.com", "twoFactor": "none", "acceptNo2faRisk": true}))
	if st != 201 || m["handle"] != nil || m["step"] != "verify_email" || m["emailSent"] != false {
		t.Fatalf("signup email not sent: %d %v", st, m)
	}
	f.SetEmailSendFails(false)
	// same email and password resumes the pending sign-up and does not return the authenticator key again
	st, m = postJSON(t, A+"/signup", body(map[string]interface{}{"tosGrant": grant(), "username": "other_user1"}))
	if st != 201 || m["resumed"] != true || m["totp"] != nil || m["step"] != "verify_email" {
		t.Fatalf("resume: %d %v", st, m)
	}
	acct, _ = m["account"].(map[string]interface{})
	if acct["username"] != "grim_player1" || f.Resumes != 1 {
		t.Fatalf("resume kept the first username: %v resumes=%d", acct, f.Resumes)
	}
	// even if an Accounts build still attaches totp to a resume, RedX does not show it
	f.SetResumeIncludesTOTP(true)
	st, m = postJSON(t, A+"/signup", body(map[string]interface{}{"tosGrant": grant(), "username": "third_user1"}))
	if st != 201 || m["resumed"] != true || m["totp"] != nil {
		t.Fatalf("resume must not carry totp: %d %v", st, m)
	}
	f.SetResumeIncludesTOTP(false)
	// a different password is another pending sign-up for the same email, not a conflict
	st, m = postJSON(t, A+"/signup", body(map[string]interface{}{"tosGrant": grant(), "username": "rival_user1",
		"password": "Abcdefgh124!", "passwordConfirm": "Abcdefgh124!"}))
	rb, _ := json.Marshal(m)
	if st != 201 || m["resumed"] == true || m["totp"] == nil || strings.Contains(string(rb), "email_pending") {
		t.Fatalf("second pending signup: %d %s", st, rb)
	}
	// an older Accounts server still returns a session: 2FA is confirmed during sign-up, as before
	f.SetLegacySignup(true)
	st, m = postJSON(t, A+"/signup", body(map[string]interface{}{"tosGrant": grant(), "username": "legacy_user", "email": "legacy@example.com",
		"emailConfirm": "legacy@example.com"}))
	if st != 201 || m["handle"] == nil || m["totp"] == nil || m["step"] != nil {
		t.Fatalf("legacy signup: %d %v", st, m)
	}
	h := m["handle"].(string)
	if st, m := postJSON(t, A+"/signup/2fa", `{"handle":"`+h+`","code":"000000"}`); st != 400 || m["error"] != "code_invalid" {
		t.Fatalf("wrong code: %d %v", st, m)
	}
	if st, m := postJSON(t, A+"/signup/2fa", `{"handle":"`+h+`","code":"123456"}`); st != 200 {
		t.Fatalf("confirm: %d %v", st, m)
	}
	if st, _ := postJSON(t, A+"/signup/2fa", `{"handle":"`+h+`","code":"123456"}`); st != 401 {
		t.Fatal("handle must be single use after 2FA is set up")
	}
	f.SetLegacySignup(false)
	// duplicate username is refused by Red-XAI Accounts and relayed
	st, m = postJSON(t, A+"/signup", body(map[string]interface{}{"tosGrant": grant(), "email": "three@example.com", "emailConfirm": "three@example.com"}))
	if st != 409 || m["error"] != "username_taken" || m["field"] != "username" {
		t.Fatalf("dup: %d %v", st, m)
	}
	// v1.2.2: email_taken is also what an owner address returns. The message stays ordinary.
	f.SetSignupError(409, "email_taken", "Refused: this is an owner email")
	calls := f.SignupCalls
	st, m = postJSON(t, A+"/signup", body(map[string]interface{}{"tosGrant": grant(), "username": "ownerish1", "email": "ownerish@example.com", "emailConfirm": "ownerish@example.com"}))
	takenRaw, _ := json.Marshal(m)
	if st != 409 || m["error"] != "email_taken" || m["message"] != "That email is already in use." || strings.Contains(strings.ToLower(string(takenRaw)), "owner") || m["detail"] != nil {
		t.Fatalf("email_taken: %d %s", st, takenRaw)
	}
	if f.SignupCalls != calls+1 {
		t.Fatalf("email_taken reached Accounts %d times", f.SignupCalls-calls)
	}
	f.SetSignupError(429, "too_many_pending", "please retry immediately")
	calls = f.SignupCalls
	st, m = postJSON(t, A+"/signup", body(map[string]interface{}{"tosGrant": grant(), "username": "pending1", "email": "pending@example.com", "emailConfirm": "pending@example.com"}))
	if st != 429 || m["error"] != "too_many_pending" || m["message"] != "Too many pending sign-ups for this email. Verify one, or try again later." {
		t.Fatalf("too_many_pending: %d %v", st, m)
	}
	if f.SignupCalls != calls+1 {
		t.Fatalf("too_many_pending reached Accounts %d times", f.SignupCalls-calls)
	}
	f.SetSignupError(0, "", "")
	if st, _, _ := do(t, "POST", A+"/signup", "", body(nil), "Content-Type", "text/plain"); st != 415 {
		t.Fatal("non-JSON POST must be refused")
	}
}

func TestAccountsClientIPAndUserinfoFallback(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	id := regular
	id.ProfileOnlyInUserinfo = true
	id.Email, id.Username = "user@example.com", "regular_user"
	tok, acct := signIn(t, n, f, id)
	if acct["email"] != "user@example.com" || acct["username"] != "regular_user" {
		t.Fatalf("userinfo fallback: %v", acct)
	}
	_ = tok
	if len(f.ClientIPs) == 0 || f.ClientIPs[len(f.ClientIPs)-1] == "" {
		t.Fatalf("token exchange must forward X-RedXAI-Client-IP: %v", f.ClientIPs)
	}
	A := n.URL + "/v1/auth"
	_, m := postJSON(t, A+"/tos/read", `{"version":"2026-10-19"}`)
	g := m["grant"].(string)
	postJSON(t, A+"/tos/agree", `{"grant":"`+g+`"}`)
	body, _ := json.Marshal(map[string]interface{}{"firstName": "Ada", "lastName": "Lovelace", "username": "ip_user1", "password": "Abcdefgh123!", "passwordConfirm": "Abcdefgh123!",
		"email": "ip@example.com", "emailConfirm": "ip@example.com", "dob": "07/04/2001", "tosGrant": g,
		"twoFactor": "none", "acceptNo2faRisk": true, "acknowledgeFalseInfo": true})
	st, _ := postJSON(t, A+"/signup", string(body))
	if st != 201 {
		t.Fatalf("signup: %d", st)
	}
	if len(f.ClientIPs) < 2 || f.ClientIPs[len(f.ClientIPs)-1] == "" {
		t.Fatalf("signup must forward client IP: %v", f.ClientIPs)
	}
}

func TestAccountsSMSResend(t *testing.T) {
	f, iss := startFake(t)
	f.SetLegacySignup(true) // phone 2FA is confirmed during sign-up only when the server still returns a session
	n := startAcctNode(t, iss)
	A := n.URL + "/v1/auth"
	_, m := postJSON(t, A+"/tos/read", `{"version":"2026-10-19"}`)
	g := m["grant"].(string)
	postJSON(t, A+"/tos/agree", `{"grant":"`+g+`"}`)
	body, _ := json.Marshal(map[string]interface{}{"firstName": "Ada", "lastName": "Lovelace", "username": "phone_user1", "password": "Abcdefgh123!", "passwordConfirm": "Abcdefgh123!",
		"email": "phone@example.com", "emailConfirm": "phone@example.com", "dob": "07/04/2001", "tosGrant": g,
		"twoFactor": "phone", "phone": "+15551234567", "acknowledgeFalseInfo": true})
	st, m := postJSON(t, A+"/signup", string(body))
	if st != 201 || m["handle"] == nil {
		t.Fatalf("signup phone: %d %v", st, m)
	}
	h := m["handle"].(string)
	st, m = postJSON(t, A+"/signup/2fa/resend", `{"handle":"`+h+`"}`)
	if st != 202 && st != 200 {
		t.Fatalf("resend: %d %v", st, m)
	}
	if f.Resends != 1 {
		t.Fatalf("fake resends: %d", f.Resends)
	}
	cfg := jsonOf(t, mustDo(t, "GET", A+"/config", "", ""))
	if cfg["sms_resend"] != true {
		t.Fatalf("config sms_resend: %v", cfg)
	}
}

func mustDo(t *testing.T, method, url, key, body string) string {
	t.Helper()
	_, b, _ := do(t, method, url, key, body)
	return b
}

func TestAccountsModerationAndEvents(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	ownerTok, _ := signIn(t, n, f, ownerOK)
	userTok, acct := signIn(t, n, f, regular)
	sub, _ := acct["sub"].(string)
	if sub == "" {
		t.Fatal("no sub")
	}
	// kick through RedX owner API
	st, b, _ := do(t, "POST", n.URL+"/v1/owner/accounts/"+sub+"/kick", ownerTok, `{"reason":"spam"}`, "Content-Type", "application/json")
	if st != 200 {
		t.Fatalf("kick: %d %s", st, b)
	}
	if len(f.Moderations) != 1 || f.Moderations[0].Action != "kick" || f.Moderations[0].Account != sub {
		t.Fatalf("moderations: %+v", f.Moderations)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/ui/whoami", userTok, ""); st != 401 {
		t.Fatalf("kicked session must end immediately, got %d", st)
	}
	// ban via event poller (another account still signed in)
	userTok2, acct2 := signIn(t, n, f, accountsfake.Identity{Sub: "rxa_REGULAR00000000000000000002", Email: "u2@example.com", EmailVerified: true, Username: "user_two", AMR: []string{"pwd"}})
	sub2 := acct2["sub"].(string)
	f.AddEvent("account.banned", sub2)
	ended, err := n.H.PollAccountEventsNow(context.Background())
	if err != nil || ended < 1 {
		t.Fatalf("poll: ended=%d err=%v", ended, err)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/ui/whoami", userTok2, ""); st != 401 {
		t.Fatalf("banned session must end via events, got %d", st)
	}
	// cursor persisted
	ended2, err := n.H.PollAccountEventsNow(context.Background())
	if err != nil || ended2 != 0 {
		t.Fatalf("second poll must be a no-op: ended=%d err=%v", ended2, err)
	}
	raw, _ := os.ReadFile(n.Dir + "/accounts/events.json")
	if !strings.Contains(string(raw), `"since"`) {
		t.Fatalf("cursor file: %s", raw)
	}
}

func stopRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func noRedirectClient(jar http.CookieJar) *http.Client {
	return &http.Client{Jar: jar, CheckRedirect: stopRedirect}
}

func newJar(t *testing.T) http.CookieJar {
	t.Helper()
	j, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

// stateSetCookies are the per-login cookies a response stores (not deletions, not the index or retry cookie).
func stateSetCookies(res *http.Response) []*http.Cookie {
	var out []*http.Cookie
	for _, c := range res.Cookies() {
		if strings.HasPrefix(c.Name, "redx_oidc_") && c.Name != "redx_oidc_retry" && c.Name != "redx_oidc_idx" && c.MaxAge > 0 {
			out = append(out, c)
		}
	}
	return out
}

func assertLoginCookie(t *testing.T, c *http.Cookie, https bool) {
	t.Helper()
	if !strings.HasPrefix(c.Name, "redx_oidc_") || c.Name == "redx_oidc" || len(strings.TrimPrefix(c.Name, "redx_oidc_")) != 16 {
		t.Fatalf("cookie name: %s", c.Name)
	}
	if !strings.HasPrefix(c.Value, strings.TrimPrefix(c.Name, "redx_oidc_")) {
		t.Fatalf("cookie value does not match its state prefix: %s", c.Name)
	}
	if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/v1/auth/callback" || c.MaxAge != int(host.AccountsLoginTTL()/time.Second) {
		t.Fatalf("cookie flags: HttpOnly=%v SameSite=%v Path=%s MaxAge=%d", c.HttpOnly, c.SameSite, c.Path, c.MaxAge)
	}
	if c.Secure != https {
		t.Fatalf("Secure=%v, https=%v", c.Secure, https)
	}
}

func beginLogin(t *testing.T, c *http.Client, rawURL string) (authLoc string, ck *http.Cookie) {
	t.Helper()
	res, err := c.Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("login: %d %s", res.StatusCode, b)
	}
	got := stateSetCookies(res)
	if len(got) != 1 {
		t.Fatalf("login set %d state cookies", len(got))
	}
	return res.Header.Get("Location"), got[0]
}

func authorizeLocation(t *testing.T, c *http.Client, authLoc string) string {
	t.Helper()
	res, err := c.Get(authLoc)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("authorize: %d %s", res.StatusCode, b)
	}
	return res.Header.Get("Location")
}

func handoffToken(t *testing.T, n *node, loc string) string {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.ParseQuery(strings.TrimPrefix(u.Fragment, "/signin?"))
	if q.Get("error") != "" || q.Get("handoff") == "" {
		t.Fatalf("sign-in failed: %s", loc)
	}
	st, b, _ := do(t, "POST", n.URL+"/v1/auth/handoff", "", `{"code":"`+q.Get("handoff")+`"}`, "Content-Type", "application/json")
	if st != 200 {
		t.Fatalf("handoff: %d %s", st, b)
	}
	tok, _ := jsonOf(t, b)["token"].(string)
	if !strings.HasPrefix(tok, "rxs_") {
		t.Fatalf("token: %s", b)
	}
	return tok
}

func finishLogin(t *testing.T, n *node, c *http.Client, authLoc string) (token, loc string) {
	t.Helper()
	cb := authorizeLocation(t, c, authLoc)
	res, err := c.Get(cb)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	loc = res.Header.Get("Location")
	return handoffToken(t, n, loc), loc
}

func callbackReq(t *testing.T, n *node, rawQuery string, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, n.URL+"/v1/auth/callback?"+rawQuery, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cookies {
		if c != nil {
			req.AddCookie(c)
		}
	}
	res, err := noRedirectClient(nil).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res
}

func cookieByName(res *http.Response, name string) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func freezeAccounts(t *testing.T, n *node) (advance func(time.Duration)) {
	t.Helper()
	var mu sync.Mutex
	now := time.Now()
	host.SetAccountsClock(n.H, func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	})
	return func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}
}

func TestAccountsConcurrentLogins(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	jar := newJar(t)
	c := noRedirectClient(jar)
	auth1, ck1 := beginLogin(t, c, n.URL+"/v1/auth/login?return=databases")
	assertLoginCookie(t, ck1, false)
	auth2, ck2 := beginLogin(t, c, n.URL+"/v1/auth/login?return=owner")
	assertLoginCookie(t, ck2, false)
	if ck1.Name == ck2.Name || ck1.Value == ck2.Value {
		t.Fatalf("concurrent logins shared one cookie: %s %s", ck1.Name, ck2.Name)
	}
	cb, _ := url.Parse(n.URL + "/v1/auth/callback")
	var names []string
	for _, ck := range jar.Cookies(cb) {
		if strings.HasPrefix(ck.Name, "redx_oidc_") && ck.Name != "redx_oidc_idx" && ck.Name != "redx_oidc_retry" {
			names = append(names, ck.Name)
		}
	}
	if len(names) != 2 {
		t.Fatalf("jar should hold both sign-in cookies, got %v", names)
	}
	// Finish the second tab first: the first tab's cookie and PKCE state must still work.
	// The fake assigns the identity when /oauth2/authorize runs, so set it immediately before each finish.
	f.SetNext(accountsfake.Identity{Sub: "rxa_REGULAR00000000000000000002", Email: "u2@example.com", EmailVerified: true, Username: "user_two", AMR: []string{"pwd"}})
	tok2, loc2 := finishLogin(t, n, c, auth2)
	f.SetNext(regular)
	tok1, loc1 := finishLogin(t, n, c, auth1)
	if tok1 == tok2 {
		t.Fatal("two sign-ins minted one session")
	}
	if !strings.Contains(loc1, "return=databases") || !strings.Contains(loc2, "return=owner") {
		t.Fatalf("returns: %s %s", loc1, loc2)
	}
	st, b, _ := do(t, "GET", n.URL+"/v1/ui/whoami", tok1, "")
	if st != 200 || !strings.Contains(b, "regular_user") {
		t.Fatalf("first tab session: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", n.URL+"/v1/ui/whoami", tok2, "")
	if st != 200 || !strings.Contains(b, "user_two") {
		t.Fatalf("second tab session: %d %s", st, b)
	}
}

func TestAccountsCallbackAfter25Minutes(t *testing.T) {
	if 25*time.Minute >= host.AccountsLoginTTL() {
		t.Fatal("sign-in TTL must be longer than 25 minutes")
	}
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	advance := freezeAccounts(t, n)
	f.SetNext(regular)
	c := noRedirectClient(newJar(t))
	auth, ck := beginLogin(t, c, n.URL+"/v1/auth/login?return=owner")
	u, _ := url.Parse(auth)
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" || q.Get("state") != ck.Value {
		t.Fatalf("authorize request lost PKCE, nonce, or state: %s", auth)
	}
	advance(25 * time.Minute)
	tok, loc := finishLogin(t, n, c, auth)
	if strings.Contains(loc, "error=") || !strings.Contains(loc, "return=owner") {
		t.Fatalf("callback after 25m: %s", loc)
	}
	st, b, _ := do(t, "GET", n.URL+"/v1/ui/whoami", tok, "")
	if st != 200 || !strings.Contains(b, "regular_user") {
		t.Fatalf("session after 25m: %d %s", st, b)
	}
}

func TestAccountsExpiredStateRestartsOnce(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	advance := freezeAccounts(t, n)
	f.SetNext(regular)
	c := noRedirectClient(newJar(t))
	auth, ck := beginLogin(t, c, n.URL+"/v1/auth/login?return=owner")
	state := ck.Value
	if u, _ := url.Parse(auth); u.Query().Get("state") != state {
		t.Fatalf("state not in authorize URL: %s", auth)
	}
	advance(host.AccountsLoginTTL() + time.Minute)
	before := f.Tokens
	res := callbackReq(t, n, "code=stale&state="+url.QueryEscape(state), ck)
	loc := res.Header.Get("Location")
	if loc != "/v1/auth/login?return=owner" {
		t.Fatalf("expired sign-in should restart login once, got %q", loc)
	}
	if strings.Contains(loc, "://") || strings.Contains(loc, "error=") {
		t.Fatalf("restart is not an error page or an open redirect: %q", loc)
	}
	retry := cookieByName(res, "redx_oidc_retry")
	if retry == nil || retry.MaxAge != 60 || !retry.HttpOnly || retry.SameSite != http.SameSiteLaxMode || retry.Path != "/v1/auth/callback" || retry.Secure {
		t.Fatalf("retry cookie: %+v", retry)
	}
	// Only the matching state cookie is cleared.
	if cleared := cookieByName(res, ck.Name); cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("matching cookie was not cleared: %+v", cleared)
	}
	res2 := callbackReq(t, n, "code=stale&state="+url.QueryEscape(state), ck, retry)
	loc2 := res2.Header.Get("Location")
	if !strings.Contains(loc2, "error=expired") || strings.Contains(loc2, "/v1/auth/login") || strings.Contains(loc2, "handoff=") {
		t.Fatalf("second failure should show the expired error and not loop or mint a session: %q", loc2)
	}
	if f.Tokens != before {
		t.Fatalf("expired callback exchanged a code (%d -> %d)", before, f.Tokens)
	}
	// Cookie already gone (aged out): still one restart, then the existing state error, still no session.
	f.SetNext(regular)
	_, ck2 := beginLogin(t, c, n.URL+"/v1/auth/login")
	advance(host.AccountsLoginTTL() + time.Minute)
	res3 := callbackReq(t, n, "state="+url.QueryEscape(ck2.Value)+"&code=stale")
	if res3.Header.Get("Location") != "/v1/auth/login" {
		t.Fatalf("missing cookie after expiry should restart, got %q", res3.Header.Get("Location"))
	}
	retry3 := cookieByName(res3, "redx_oidc_retry")
	res4 := callbackReq(t, n, "state="+url.QueryEscape(ck2.Value)+"&code=stale", retry3)
	loc4 := res4.Header.Get("Location")
	if !strings.Contains(loc4, "error=state") || strings.Contains(loc4, "/v1/auth/login") || strings.Contains(loc4, "handoff=") || f.Tokens != before {
		t.Fatalf("second miss: %q tokens %d", loc4, f.Tokens)
	}
	// No state parameter at all restarts once, then shows error=state. A return in the query is ignored.
	res5 := callbackReq(t, n, "return=https://evil.example/phish")
	if loc := res5.Header.Get("Location"); loc != "/v1/auth/login" {
		t.Fatalf("missing state restart: %q", loc)
	}
	res6 := callbackReq(t, n, "return=https://evil.example/phish", cookieByName(res5, "redx_oidc_retry"))
	if loc := res6.Header.Get("Location"); !strings.Contains(loc, "error=state") || strings.Contains(loc, "evil.example") || strings.Contains(loc, "/v1/auth/login") {
		t.Fatalf("missing state second failure: %q", loc)
	}
}

func TestAccountsForgedStateDoesNotMintSession(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	f.SetNext(regular)
	c := noRedirectClient(newJar(t))
	auth, ck := beginLogin(t, c, n.URL+"/v1/auth/login?return=owner")
	cb := authorizeLocation(t, c, auth)
	u, _ := url.Parse(cb)
	code := u.Query().Get("code")
	state := u.Query().Get("state")
	if code == "" || state != ck.Value {
		t.Fatalf("callback from provider: %s", cb)
	}
	before := f.Tokens
	// Real code, forged state, no cookie.
	res := callbackReq(t, n, "code="+url.QueryEscape(code)+"&state=forged")
	if loc := res.Header.Get("Location"); !strings.Contains(loc, "error=state") || strings.Contains(loc, "handoff=") || strings.Contains(loc, "/v1/auth/login") {
		t.Fatalf("forged state: %q", loc)
	}
	// Real code and real state, but the cookie value does not match.
	bad := *ck
	bad.Value = strings.Repeat("x", len(ck.Value))
	res = callbackReq(t, n, "code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), &bad)
	if loc := res.Header.Get("Location"); !strings.Contains(loc, "error=state") || strings.Contains(loc, "handoff=") || strings.Contains(loc, "/v1/auth/login") {
		t.Fatalf("mismatched cookie: %q", loc)
	}
	// Live sign-in, right state, cookie omitted: still a failure (not a restart) and the sign-in is not consumed.
	res = callbackReq(t, n, "code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state))
	if loc := res.Header.Get("Location"); !strings.Contains(loc, "error=state") || strings.Contains(loc, "/v1/auth/login") || strings.Contains(loc, "handoff=") {
		t.Fatalf("state without cookie: %q", loc)
	}
	if f.Tokens != before {
		t.Fatalf("forged callbacks exchanged a code (%d)", f.Tokens)
	}
	// The original browser can still finish. A forged attempt must not have consumed the PKCE state.
	tok, _ := finishLogin(t, n, c, auth)
	// finishLogin runs authorize again, which mints a new code. The previous code was unused.
	// Completing proves the pending login was not consumed and a session is minted only now.
	if tok == "" || f.Tokens != before+1 {
		t.Fatalf("legitimate login after forged attempts: token %q exchanges %d", tok, f.Tokens)
	}
	// A callback that presents the other tab's cookie under a forged state still fails.
	f.SetNext(regular)
	_, ck2 := beginLogin(t, c, n.URL+"/v1/auth/login")
	res = callbackReq(t, n, "code=abc&state=forged-state-value", ck2)
	if loc := res.Header.Get("Location"); !strings.Contains(loc, "error=state") || strings.Contains(loc, "handoff=") {
		t.Fatalf("forged state beside a real cookie: %q", loc)
	}
	if f.Tokens != before+1 {
		t.Fatal("forged state minted a session")
	}
}

func TestAccountsOIDCCookieCap(t *testing.T) {
	_, iss := startFake(t)
	n := startAcctNode(t, iss)
	c := noRedirectClient(newJar(t))
	var first string
	for i := 0; i < 9; i++ {
		res, err := c.Get(n.URL + "/v1/auth/login")
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		var created *http.Cookie
		var cleared []string
		for _, ck := range res.Cookies() {
			if !strings.HasPrefix(ck.Name, "redx_oidc_") || ck.Name == "redx_oidc_idx" || ck.Name == "redx_oidc_retry" {
				continue
			}
			if ck.MaxAge > 0 {
				created = ck
			} else if ck.MaxAge < 0 {
				cleared = append(cleared, ck.Name)
			}
		}
		if created == nil {
			t.Fatalf("login %d set no state cookie", i)
		}
		if i == 0 {
			first = created.Name
		}
		if i < 8 && len(cleared) != 0 {
			t.Fatalf("login %d cleared %v", i, cleared)
		}
		if i == 8 {
			if len(cleared) != 1 || cleared[0] != first {
				t.Fatalf("9th login should expire the oldest cookie %s, cleared %v", first, cleared)
			}
		}
	}
}

func TestAccountsLoginCookieSecureOnHTTPS(t *testing.T) {
	_, iss := startFake(t)
	n := startNode(t, t.TempDir(), func(c *host.Config, u string) {
		c.AccountsIssuer = iss
		c.AccountsClientSecret = "test-client-secret"
		c.AccountsEventsPoll = 3600
		c.Advertise = "https://console.example"
	})
	res, err := noRedirectClient(nil).Get(n.URL + "/v1/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	got := stateSetCookies(res)
	if len(got) != 1 {
		t.Fatalf("cookies: %v", res.Cookies())
	}
	assertLoginCookie(t, got[0], true)
	idx := cookieByName(res, "redx_oidc_idx")
	if idx == nil || !idx.HttpOnly || !idx.Secure || idx.SameSite != http.SameSiteLaxMode || idx.Path != "/v1/auth" || idx.Value == "" {
		t.Fatalf("index cookie: %+v", idx)
	}
}

func loginFrom(t *testing.T, n *node, ip string, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, n.URL+"/v1/auth/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ip != "" {
		req.Header.Set("X-Forwarded-For", ip)
	}
	for _, c := range cookies {
		if c != nil {
			req.AddCookie(c)
		}
	}
	res, err := noRedirectClient(nil).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res
}

// loginPastLimit repeats a sign-in until the per-IP login limiter allows it, then returns that response.
func loginPastLimit(t *testing.T, n *node, ip string) *http.Response {
	t.Helper()
	var res *http.Response
	for i := 0; i < 4; i++ {
		res = loginFrom(t, n, ip)
		if res.StatusCode != http.StatusTooManyRequests {
			return res
		}
		time.Sleep(1100 * time.Millisecond)
	}
	t.Fatalf("%s stayed rate limited: %s", ip, res.Header.Get("Retry-After"))
	return res
}

func TestAccountsTwoIPsCannotStarvePendingCap(t *testing.T) {
	_, iss := startFake(t)
	n := startNode(t, t.TempDir(), func(c *host.Config, _ string) {
		c.AccountsIssuer = iss
		c.AccountsClientSecret = "test-client-secret"
		c.AccountsEventsPoll = 3600
		c.TrustedProxies = []string{"127.0.0.1", "::1"}
	})
	advance := freezeAccounts(t, n)
	const a, b, third = "203.0.113.1", "203.0.113.2", "203.0.113.3"
	okLogin := func(ip string) {
		t.Helper()
		res := loginFrom(t, n, ip)
		loc := res.Header.Get("Location")
		if res.StatusCode != http.StatusFound || strings.Contains(loc, "error=") {
			t.Fatalf("%s login: %d %s", ip, res.StatusCode, loc)
		}
	}
	for i := 0; i < 20; i++ {
		okLogin(a)
		okLogin(b)
	}
	okLogin(third)
	for _, ip := range []string{a, b} {
		res := loginPastLimit(t, n, ip)
		loc := res.Header.Get("Location")
		if res.StatusCode != http.StatusFound || !strings.Contains(loc, "error=busy") {
			t.Fatalf("%s should stop at its own pending cap: %d %s", ip, res.StatusCode, loc)
		}
	}
	okLogin(third)
	// At 89 minutes those sign-ins are inside the grace window and must not still fill the cap.
	advance(89 * time.Minute)
	for _, ip := range []string{a, b, third} {
		res := loginPastLimit(t, n, ip)
		loc := res.Header.Get("Location")
		if res.StatusCode != http.StatusFound || strings.Contains(loc, "error=") {
			t.Fatalf("%s at 89 minutes: %d %s", ip, res.StatusCode, loc)
		}
	}
}

func TestAccountsIPv6PrefixSharesLoginCap(t *testing.T) {
	_, iss := startFake(t)
	n := startNode(t, t.TempDir(), func(c *host.Config, _ string) {
		c.AccountsIssuer = iss
		c.AccountsClientSecret = "test-client-secret"
		c.AccountsEventsPoll = 3600
		c.TrustedProxies = []string{"127.0.0.1", "::1"}
	})
	okLogin := func(ip string) {
		t.Helper()
		res := loginFrom(t, n, ip)
		loc := res.Header.Get("Location")
		if res.StatusCode != http.StatusFound || strings.Contains(loc, "error=") {
			t.Fatalf("%s login: %d %s", ip, res.StatusCode, loc)
		}
	}
	// A full bucket answers 429 while the login limit holds, or busy once it refills and the pending cap is what stops the next sign-in.
	blocked := func(ip string) {
		t.Helper()
		res := loginFrom(t, n, ip)
		loc := res.Header.Get("Location")
		if res.StatusCode == http.StatusTooManyRequests || (res.StatusCode == http.StatusFound && strings.Contains(loc, "error=busy")) {
			return
		}
		t.Fatalf("%s was treated as a new client: %d %s", ip, res.StatusCode, loc)
	}
	for i := 1; i <= 20; i++ {
		okLogin(fmt.Sprintf("2001:db8:aaaa:1::%x", i))
	}
	blocked("2001:db8:aaaa:1::ff")
	okLogin("2001:db8:bbbb:2::1")
	// IPv4 addresses stay one bucket each.
	for i := 0; i < 20; i++ {
		okLogin("198.51.100.10")
	}
	blocked("198.51.100.10")
	blocked("::ffff:198.51.100.10")
	okLogin("198.51.100.11")
	okLogin("::ffff:198.51.100.11")
	// Once the login limit refills, the /64 is still at its pending cap.
	res := loginPastLimit(t, n, "2001:db8:aaaa:1::ee")
	if loc := res.Header.Get("Location"); res.StatusCode != http.StatusFound || !strings.Contains(loc, "error=busy") {
		t.Fatalf("same /64 after the rate limit: %d %s", res.StatusCode, loc)
	}
	okLogin("2001:db8:cccc:3::5")
}

func TestAccountsPendingCapIgnoresSpoofedForwarding(t *testing.T) {
	_, iss := startFake(t)
	n := startAcctNode(t, iss)
	for i := 0; i < 20; i++ {
		res := loginFrom(t, n, fmt.Sprintf("203.0.113.%d", i+1))
		loc := res.Header.Get("Location")
		if res.StatusCode != http.StatusFound || strings.Contains(loc, "error=") {
			t.Fatalf("login %d: %d %s", i, res.StatusCode, loc)
		}
	}
	res := loginPastLimit(t, n, "198.51.100.9")
	loc := res.Header.Get("Location")
	if res.StatusCode != http.StatusFound || !strings.Contains(loc, "error=busy") {
		t.Fatalf("a spoofed X-Forwarded-For must share the socket address cap: %d %s", res.StatusCode, loc)
	}
	res = loginPastLimit(t, n, "2001:db8:eeee:1::1")
	if loc = res.Header.Get("Location"); res.StatusCode != http.StatusFound || !strings.Contains(loc, "error=busy") {
		t.Fatalf("a spoofed IPv6 prefix must not get its own cap: %d %s", res.StatusCode, loc)
	}
}

func TestAccountsIndexCookieCannotDropAnotherSignIn(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	f.SetNext(regular)
	victim := noRedirectClient(newJar(t))
	auth, ck := beginLogin(t, victim, n.URL+"/v1/auth/login?return=owner")
	idx := strings.TrimPrefix(ck.Name, "redx_oidc_")
	for i := 0; i < 7; i++ {
		idx += "," + fmt.Sprintf("pad%013d", i)
	}
	res := loginFrom(t, n, "", &http.Cookie{Name: "redx_oidc_idx", Value: idx})
	if loc := res.Header.Get("Location"); res.StatusCode != http.StatusFound || strings.Contains(loc, "error=") {
		t.Fatalf("login with a forged index: %d %s", res.StatusCode, loc)
	}
	f.SetNext(regular)
	if tok, loc := finishLogin(t, n, victim, auth); tok == "" || strings.Contains(loc, "error=") {
		t.Fatalf("forged index dropped the other sign-in: %s", loc)
	}

	// The same index does drop the sign-in when the request also presents that sign-in's cookie.
	f.SetNext(regular)
	auth2, ck2 := beginLogin(t, victim, n.URL+"/v1/auth/login?return=owner")
	idx = strings.TrimPrefix(ck2.Name, "redx_oidc_")
	for i := 0; i < 7; i++ {
		idx += "," + fmt.Sprintf("pad%013d", i)
	}
	before := f.Tokens
	cb := authorizeLocation(t, victim, auth2)
	res = loginFrom(t, n, "", &http.Cookie{Name: "redx_oidc_idx", Value: idx}, ck2)
	if loc := res.Header.Get("Location"); res.StatusCode != http.StatusFound || strings.Contains(loc, "error=") {
		t.Fatalf("login presenting the old cookie: %d %s", res.StatusCode, loc)
	}
	fin, err := victim.Get(cb)
	if err != nil {
		t.Fatal(err)
	}
	fin.Body.Close()
	if loc := fin.Header.Get("Location"); strings.Contains(loc, "handoff=") || f.Tokens != before {
		t.Fatalf("presenting the state cookie should drop that sign-in: %s tokens %d", loc, f.Tokens)
	}
}

func TestAccountsLegacyOIDCCookie(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	f.SetNext(regular)
	c := noRedirectClient(newJar(t))
	auth, ck := beginLogin(t, c, n.URL+"/v1/auth/login?return=owner")
	res := loginFrom(t, n, "", &http.Cookie{Name: "redx_oidc", Value: "stale-legacy-value"})
	cleared := cookieByName(res, "redx_oidc")
	if cleared == nil || cleared.MaxAge >= 0 || cleared.Path != "/v1/auth/callback" || !cleared.HttpOnly {
		t.Fatalf("legacy cookie not cleared on login: %+v", cleared)
	}
	if got := stateSetCookies(res); len(got) != 1 {
		t.Fatalf("login still needs its per-state cookie: %v", res.Cookies())
	}
	if res.Header.Get("Set-Cookie") == "" || !strings.Contains(res.Header.Get("Set-Cookie"), "redx_oidc_") || strings.HasPrefix(res.Header.Get("Set-Cookie"), "redx_oidc=") {
		t.Fatalf("the per-state cookie must stay the first Set-Cookie: %s", res.Header.Get("Set-Cookie"))
	}

	cb := authorizeLocation(t, c, auth)
	before := f.Tokens
	finishLegacy := func(state string, extra ...*http.Cookie) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, cb, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: "redx_oidc", Value: state})
		for _, ck := range extra {
			req.AddCookie(ck)
		}
		out, err := noRedirectClient(nil).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		out.Body.Close()
		return out
	}
	fin := finishLegacy(ck.Value)
	loc := fin.Header.Get("Location")
	if !strings.Contains(loc, "handoff=") || strings.Contains(loc, "error=") {
		t.Fatalf("in-flight legacy sign-in: %s", loc)
	}
	if tok := handoffToken(t, n, loc); !strings.HasPrefix(tok, "rxs_") || f.Tokens != before+1 {
		t.Fatalf("legacy sign-in did not mint one session: %s tokens %d", loc, f.Tokens)
	}
	cleared = cookieByName(fin, "redx_oidc")
	if cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("legacy cookie not cleared on callback: %+v", cleared)
	}
	fin = finishLegacy(ck.Value)
	if loc = fin.Header.Get("Location"); strings.Contains(loc, "handoff=") || f.Tokens != before+1 {
		t.Fatalf("legacy cookie must not sign in twice: %s tokens %d", loc, f.Tokens)
	}

	// A forged state that only matches a legacy cookie the attacker set is still refused.
	bogus := callbackReq(t, n, "code=abc&state=forgedstatevalue1", &http.Cookie{Name: "redx_oidc", Value: "forgedstatevalue1"})
	if loc = bogus.Header.Get("Location"); !strings.Contains(loc, "error=state") || strings.Contains(loc, "handoff=") || strings.Contains(loc, "/v1/auth/login") || f.Tokens != before+1 {
		t.Fatalf("forged legacy cookie: %s", loc)
	}

	f.SetNext(regular)
	auth3, ck3 := beginLogin(t, c, n.URL+"/v1/auth/login")
	cb3 := authorizeLocation(t, c, auth3)
	bad := *ck3
	bad.Value = strings.Repeat("y", len(ck3.Value))
	req, err := http.NewRequest(http.MethodGet, cb3, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&bad)
	req.AddCookie(&http.Cookie{Name: "redx_oidc", Value: ck3.Value})
	out, err := noRedirectClient(nil).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out.Body.Close()
	if loc = out.Header.Get("Location"); !strings.Contains(loc, "error=state") || strings.Contains(loc, "handoff=") || f.Tokens != before+1 {
		t.Fatalf("legacy cookie rescued a mismatched per-state cookie: %s tokens %d", loc, f.Tokens)
	}
}
