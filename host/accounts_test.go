package host_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
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
		r := map[string]interface{}{"username": "grim_player1", "password": "Abcdefgh123!", "passwordConfirm": "Abcdefgh123!",
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
	if st != 201 || m["handle"] == nil || m["totp"] == nil {
		t.Fatalf("signup: %d %v", st, m)
	}
	if _, has := m["session"]; has {
		t.Fatal("the Red-XAI session must stay on the server")
	}
	if len(f.Signups) != 1 || f.Signups[0].App != "redx" || !f.Signups[0].AcknowledgeFalseInfo || f.Signups[0].TwoFactor != "app" {
		t.Fatalf("forwarded: %+v", f.Signups)
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
	// 2FA "none" with the risk accepted needs no setup step
	st, m = postJSON(t, A+"/signup", body(map[string]interface{}{"tosGrant": grant(), "username": "second_user", "email": "two@example.com",
		"emailConfirm": "two@example.com", "twoFactor": "none", "acceptNo2faRisk": true}))
	if st != 201 || m["handle"] != nil {
		t.Fatalf("signup none: %d %v", st, m)
	}
	// duplicate username is refused by Red-XAI Accounts and relayed
	st, m = postJSON(t, A+"/signup", body(map[string]interface{}{"tosGrant": grant(), "email": "three@example.com", "emailConfirm": "three@example.com"}))
	if st != 409 || m["error"] != "username_taken" || m["field"] != "username" {
		t.Fatalf("dup: %d %v", st, m)
	}
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
	body, _ := json.Marshal(map[string]interface{}{"username": "ip_user1", "password": "Abcdefgh123!", "passwordConfirm": "Abcdefgh123!",
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
	n := startAcctNode(t, iss)
	A := n.URL + "/v1/auth"
	_, m := postJSON(t, A+"/tos/read", `{"version":"2026-10-19"}`)
	g := m["grant"].(string)
	postJSON(t, A+"/tos/agree", `{"grant":"`+g+`"}`)
	body, _ := json.Marshal(map[string]interface{}{"username": "phone_user1", "password": "Abcdefgh123!", "passwordConfirm": "Abcdefgh123!",
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
