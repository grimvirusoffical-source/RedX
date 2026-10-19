package host

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ---- /v1/auth/*: Red-XAI Accounts sign-in and sign-up for the web console ----

func (h *Host) acctThrottle(w http.ResponseWriter, r *http.Request, bucket string, rps float64, burst int) bool {
	if ok, wait := h.acctLim.Allow(bucket+"|"+remoteIP(r), rps, burst); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
		writeJSON(w, 429, map[string]string{"error": "rate_limited", "message": "Too many tries. Wait a moment and try again."})
		return true
	}
	return false
}

func acctErr(w http.ResponseWriter, code int, errCode, msg string) {
	writeJSON(w, code, map[string]string{"error": errCode, "message": msg})
}

// readJSON decodes a small JSON body; POSTs must be application/json (a cross-site form cannot send that).
func readJSON(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		acctErr(w, 415, "bad_request", "content type must be application/json")
		return false
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(v); err != nil {
		acctErr(w, 400, "bad_request", "invalid JSON")
		return false
	}
	return true
}

func (h *Host) authRoute(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/auth/"), "/")
	if rest == "config" && r.Method == "GET" {
		h.authConfig(w)
		return
	}
	if !h.AccountsEnabled() {
		acctErr(w, 404, "not_enabled", "Red-XAI Accounts sign-in is not set up on this host. Sign in with an API key.")
		return
	}
	switch {
	case rest == "login" && r.Method == "GET":
		h.authLogin(w, r)
	case rest == "callback" && r.Method == "GET":
		h.authCallback(w, r)
	case rest == "handoff" && r.Method == "POST":
		h.authHandoff(w, r)
	case rest == "logout" && r.Method == "POST":
		h.authLogout(w, r)
	case rest == "rules" && r.Method == "GET":
		writeJSON(w, 200, h.signupRules(r.Context()))
	case rest == "tos" && r.Method == "GET":
		h.proxyGET(w, r, "/v1/tos?app="+url.QueryEscape(h.Cfg.AccountsClientID))
	case rest == "tos/read" && r.Method == "POST":
		var b struct {
			Version string `json:"version"`
		}
		if h.acctThrottle(w, r, "tos", 1, 30) || !readJSON(w, r, &b) {
			return
		}
		h.proxyPOST(w, r, "/v1/tos/read", map[string]string{"app": h.Cfg.AccountsClientID, "version": b.Version}, "")
	case rest == "tos/agree" && r.Method == "POST":
		var b struct {
			Grant string `json:"grant"`
		}
		if h.acctThrottle(w, r, "tos", 1, 30) || !readJSON(w, r, &b) {
			return
		}
		h.proxyPOST(w, r, "/v1/tos/agree", map[string]string{"grant": b.Grant}, "")
	case strings.HasPrefix(rest, "validate/") && r.Method == "POST":
		h.authValidate(w, r, strings.TrimPrefix(rest, "validate/"))
	case rest == "signup" && r.Method == "POST":
		h.authSignup(w, r)
	case rest == "email/resend" && r.Method == "POST":
		h.authEmailResend(w, r)
	case rest == "signup/2fa" && r.Method == "POST":
		h.authSignup2FA(w, r)
	case rest == "signup/2fa/resend" && r.Method == "POST":
		h.authSignupResend(w, r)
	default:
		writeErr(w, 404, "not found")
	}
}

func (h *Host) authConfig(w http.ResponseWriter) {
	if !h.AccountsEnabled() {
		writeJSON(w, 200, map[string]interface{}{"enabled": false})
		return
	}
	iss := h.Cfg.AccountsIssuer
	app := url.QueryEscape(h.Cfg.AccountsClientID)
	writeJSON(w, 200, map[string]interface{}{"enabled": true, "issuer": iss, "client_id": h.Cfg.AccountsClientID,
		"hosted_signup": iss + "/signup?app=" + app, "hosted_account": iss + "/account", "forgot_password": iss + "/forgot-password",
		"min_age": CentralMinAge, "sms_resend": h.Cfg.AccountsSMSResendPath != ""})
}

// redirectURI is the exact callback registered with Red-XAI Accounts for this host.
func (h *Host) redirectURI(r *http.Request) string {
	if h.Cfg.AccountsRedirect != "" {
		return h.Cfg.AccountsRedirect
	}
	if h.Cfg.Advertise != "" {
		return strings.TrimRight(h.Cfg.Advertise, "/") + "/v1/auth/callback"
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/v1/auth/callback"
}

// One cookie per in-flight sign-in, named from a prefix of that sign-in's state, so two tabs do not
// overwrite each other. The value is the full state and must match the callback. An index cookie
// (path /v1/auth, so /v1/auth/login can see it) remembers the order and the oldest is expired past the cap.
const (
	oidcCookiePrefix    = "redx_oidc_"
	oidcRetryCookie     = "redx_oidc_retry" // set when a missing/expired sign-in is restarted; blocks a loop
	oidcIndexCookie     = "redx_oidc_idx"
	oidcStatePrefixN    = 16
	oidcMaxStateCookies = 8
	oidcRetryTTL        = 60 * time.Second
	oidcCookiePath      = "/v1/auth/callback"
	oidcIndexPath       = "/v1/auth"
)

// authLogin starts the authorization code flow with PKCE S256 and redirects to Red-XAI Accounts.
func (h *Host) authLogin(w http.ResponseWriter, r *http.Request) {
	if h.acctThrottle(w, r, "login", 1, 20) {
		return
	}
	d, err := h.oidc.discovery(r.Context())
	if err != nil {
		h.Logf("accounts: discovery: %v", err)
		http.Redirect(w, r, "/#/signin?error=unavailable", http.StatusFound)
		return
	}
	state, nonce, verifier := randToken(""), randToken(""), randToken("")
	ret := r.URL.Query().Get("return")
	if !safeReturn(ret) {
		ret = ""
	}
	p := &acctPending{verifier: verifier, nonce: nonce, redirect: h.redirectURI(r), ret: ret}
	if err := h.accts.addPending(state, p); err != nil {
		http.Redirect(w, r, "/#/signin?error=busy", http.StatusFound)
		return
	}
	h.rememberLoginCookie(w, r, state)
	q := url.Values{"response_type": {"code"}, "client_id": {h.Cfg.AccountsClientID}, "redirect_uri": {p.redirect},
		"scope": {"openid profile email " + OwnerScope}, "state": {state}, "nonce": {nonce},
		"code_challenge": {pkceChallenge(verifier)}, "code_challenge_method": {"S256"}}
	sep := "?"
	if strings.Contains(d.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	http.Redirect(w, r, d.AuthorizationEndpoint+sep+q.Encode(), http.StatusFound)
}

func oidcCookieChar(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

func oidcStatePrefix(state string) string {
	if len(state) > oidcStatePrefixN {
		return state[:oidcStatePrefixN]
	}
	return state
}

// oidcStateCookieName is redx_oidc_<state prefix>. Reserved names and unsafe characters are refused.
func oidcStateCookieName(state string) (string, bool) {
	if state == "" || len(state) > 128 {
		return "", false
	}
	for _, c := range state {
		if !oidcCookieChar(c) {
			return "", false
		}
	}
	prefix := oidcStatePrefix(state)
	if prefix == "retry" || prefix == "idx" {
		return "", false
	}
	name := oidcCookiePrefix + prefix
	if name == oidcRetryCookie || name == oidcIndexCookie {
		return "", false
	}
	return name, true
}

func oidcPrefixOK(p string) bool {
	if p == "" || len(p) > oidcStatePrefixN || p == "retry" || p == "idx" {
		return false
	}
	for _, c := range p {
		if !oidcCookieChar(c) {
			return false
		}
	}
	return oidcCookiePrefix+p != oidcRetryCookie && oidcCookiePrefix+p != oidcIndexCookie
}

func (h *Host) authCookieSecure(r *http.Request) bool {
	return strings.HasPrefix(h.redirectURI(r), "https://")
}

func (h *Host) setAuthCookie(w http.ResponseWriter, r *http.Request, name, value, path string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: path, MaxAge: maxAge,
		HttpOnly: true, Secure: h.authCookieSecure(r), SameSite: http.SameSiteLaxMode,
	})
}

func (h *Host) clearAuthCookie(w http.ResponseWriter, r *http.Request, name, path string) {
	h.setAuthCookie(w, r, name, "", path, -1)
}

func oidcIndex(r *http.Request) []string {
	c, err := r.Cookie(oidcIndexCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, p := range strings.Split(c.Value, ",") {
		if oidcPrefixOK(p) && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func (h *Host) writeOIDCIndex(w http.ResponseWriter, r *http.Request, order []string) {
	if len(order) == 0 {
		h.clearAuthCookie(w, r, oidcIndexCookie, oidcIndexPath)
		return
	}
	h.setAuthCookie(w, r, oidcIndexCookie, strings.Join(order, ","), oidcIndexPath, int(acctLoginTTL/time.Second))
}

// rememberLoginCookie stores this sign-in's state and expires the oldest per-state cookies past the cap.
func (h *Host) rememberLoginCookie(w http.ResponseWriter, r *http.Request, state string) {
	name, ok := oidcStateCookieName(state)
	if !ok {
		return
	}
	prefix := oidcStatePrefix(state)
	var order []string
	for _, p := range oidcIndex(r) {
		if p != prefix {
			order = append(order, p)
		}
	}
	order = append(order, prefix)
	for len(order) > oidcMaxStateCookies {
		old := order[0]
		order = order[1:]
		h.clearAuthCookie(w, r, oidcCookiePrefix+old, oidcCookiePath)
		h.accts.dropByPrefix(old)
	}
	// The state cookie is set first so a client that only reads the first Set-Cookie still sees it.
	h.setAuthCookie(w, r, name, state, oidcCookiePath, int(acctLoginTTL/time.Second))
	h.writeOIDCIndex(w, r, order)
}

// forgetLoginCookie clears this sign-in's cookie and drops it from the index. Other tabs are left alone.
func (h *Host) forgetLoginCookie(w http.ResponseWriter, r *http.Request, state string) {
	name, ok := oidcStateCookieName(state)
	if !ok {
		return
	}
	h.clearAuthCookie(w, r, name, oidcCookiePath)
	prefix := oidcStatePrefix(state)
	var order []string
	for _, p := range oidcIndex(r) {
		if p != prefix {
			order = append(order, p)
		}
	}
	h.writeOIDCIndex(w, r, order)
}

// stateMatches is true when the cookie value is exactly this callback's state.
func stateMatches(cookie, state string) bool {
	if cookie == "" || len(cookie) > 128 || len(state) > 128 || len(cookie) != len(state) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie), []byte(state)) == 1
}

// restartLogin sends the browser through /v1/auth/login one time. A second miss inside the retry
// window shows code instead. The target is always this host's login path (return is the page name
// stored for this sign-in, never a URL from the query).
func (h *Host) restartLogin(w http.ResponseWriter, r *http.Request, code string) {
	if _, err := r.Cookie(oidcRetryCookie); err == nil {
		h.failSignin(w, r, code)
		return
	}
	h.setAuthCookie(w, r, oidcRetryCookie, "1", oidcCookiePath, int(oidcRetryTTL/time.Second))
	dest := "/v1/auth/login"
	if ret := h.accts.pendingReturn(r.URL.Query().Get("state")); ret != "" {
		dest += "?return=" + url.QueryEscape(ret)
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

func (h *Host) failSignin(w http.ResponseWriter, r *http.Request, code string) {
	dest := "/#/signin?error=" + url.QueryEscape(code)
	if code == "email_unverified" {
		if login := safeLoginHint(r.URL.Query().Get("login")); login != "" {
			dest += "&login=" + url.QueryEscape(login)
		}
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// safeLoginHint is an email or username the provider may echo on error=email_unverified.
// Anything else is dropped so the sign-in page cannot be turned into an open redirect.
func safeLoginHint(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > EmailMax {
		return ""
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '@' || r == '.' || r == '_' || r == '-' || r == '+' || r == '!':
		default:
			return ""
		}
	}
	return s
}

// safeReturn: a console page name such as "owner" or "databases" (never a URL).
func safeReturn(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '/') {
			return false
		}
	}
	return true
}

func (h *Host) authCallback(w http.ResponseWriter, r *http.Request) {
	if h.acctThrottle(w, r, "callback", 1, 20) {
		return
	}
	q := r.URL.Query()
	state := q.Get("state")
	// No state at all: the sign-in did not arrive. Restart once, then show the existing error.
	if state == "" {
		h.restartLogin(w, r, "state")
		return
	}
	name, nameOK := oidcStateCookieName(state)
	var c *http.Cookie
	if nameOK {
		c, _ = r.Cookie(name)
	}
	cookieOK := nameOK && c != nil && stateMatches(c.Value, state)
	if !cookieOK {
		kind := "unknown"
		if nameOK {
			kind = h.accts.pendingKind(state)
		}
		mismatched := c != nil && !stateMatches(c.Value, state)
		// A live sign-in without its cookie, an unknown state, or a cookie whose value
		// does not match is forged or mismatched: fail, and never mint a session.
		// Only an expired sign-in whose cookie has aged out is restarted.
		if mismatched || kind == "live" || kind == "unknown" || !nameOK {
			h.Audit.Log(AuditEvent{Event: "account.signin.fail", Remote: remoteIP(r), Reason: "state missing or not from this browser"})
			if mismatched {
				h.forgetLoginCookie(w, r, state)
			}
			h.failSignin(w, r, "state")
			return
		}
		h.restartLogin(w, r, "state")
		return
	}
	p, kind := h.accts.consumePending(state)
	if kind != "live" {
		h.forgetLoginCookie(w, r, state)
		h.restartLogin(w, r, "expired")
		return
	}
	fail := func(code string) {
		h.forgetLoginCookie(w, r, state)
		h.failSignin(w, r, code)
	}
	if e := q.Get("error"); e != "" {
		h.Audit.Log(AuditEvent{Event: "account.signin.fail", Remote: remoteIP(r), Reason: "provider error: " + truncate(e, 64)})
		switch e {
		case "access_denied":
			fail("access_denied")
		case "email_unverified":
			fail("email_unverified")
		default:
			fail("provider")
		}
		return
	}
	code := q.Get("code")
	if code == "" {
		fail("provider")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	tok, err := h.oidc.exchange(ctx, code, p.redirect, p.verifier, remoteIP(r))
	if err != nil {
		h.Logf("accounts: token exchange: %v", err)
		h.Audit.Log(AuditEvent{Event: "account.signin.fail", Remote: remoteIP(r), Reason: truncate(err.Error(), 120)})
		fail("exchange")
		return
	}
	cl, err := h.oidc.verifyIDToken(ctx, tok.IDToken, p.nonce)
	if err != nil {
		h.Logf("accounts: id token: %v", err)
		h.Audit.Log(AuditEvent{Event: "account.signin.fail", Remote: remoteIP(r), Reason: truncate(err.Error(), 120)})
		fail("token")
		return
	}
	// Granted scopes come from the token response (strict: an omitted scope list grants no owner scope).
	id := AccountIdentity{Sub: cl.Sub, Username: cl.PreferredUsername, Email: cl.Email, AMR: cl.AMR, AgeBand: cl.AgeBand, Scopes: strings.Fields(tok.Scope)}
	if cl.EmailVerified != nil {
		id.EmailVerified = *cl.EmailVerified
	}
	if (id.Email == "" || cl.EmailVerified == nil || id.Username == "") && tok.AccessToken != "" {
		if ui, err := h.oidc.userinfo(ctx, tok.AccessToken); err == nil && ui["sub"] == cl.Sub {
			if s, _ := ui["email"].(string); id.Email == "" {
				id.Email = s
			}
			if b, ok := ui["email_verified"].(bool); ok && cl.EmailVerified == nil {
				id.EmailVerified = b
			}
			if s, _ := ui["preferred_username"].(string); id.Username == "" {
				id.Username = s
			}
		}
	}
	owner, blocked := ownerStatus(&id, h.Cfg.OwnerEmails)
	var keep *acctTokens
	if owner { // only owner sessions keep Red-XAI tokens (in memory), for moderation calls
		keep = &acctTokens{Access: tok.AccessToken, Refresh: tok.Refresh, AccessExp: time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)}
	}
	_, handoff := h.accts.newSessionWithTokens(id, keep)
	switch {
	case owner:
		h.Audit.Log(AuditEvent{Event: "owner.signin", KeyID: "acct:" + id.Sub, Actor: id.Email, Remote: remoteIP(r), Detail: "owner sign-in with 2FA"})
	case blocked != "":
		h.Audit.Log(AuditEvent{Event: "owner.denied", KeyID: "acct:" + id.Sub, Actor: id.Email, Remote: remoteIP(r), Reason: blocked})
	default:
		h.Audit.Log(AuditEvent{Event: "account.signin", KeyID: "acct:" + id.Sub, Remote: remoteIP(r)})
	}
	h.forgetLoginCookie(w, r, state)
	h.clearAuthCookie(w, r, oidcRetryCookie, oidcCookiePath)
	dest := "/#/signin?handoff=" + url.QueryEscape(handoff)
	if p.ret != "" {
		dest += "&return=" + url.QueryEscape(p.ret)
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// accountView is what the console learns about the signed-in account.
func accountView(a *AccountIdentity) map[string]interface{} {
	if a == nil {
		return nil
	}
	return map[string]interface{}{"sub": a.Sub, "username": a.Username, "email": a.Email, "email_verified": a.EmailVerified,
		"owner": a.Owner, "owner_blocked": a.OwnerBlocked, "two_factor_used": a.used2FA(), "owner_scope": containsStr(a.Scopes, OwnerScope)}
}

// authHandoff trades the single-use code from the callback redirect for the console session token.
func (h *Host) authHandoff(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Code string `json:"code"`
	}
	if h.acctThrottle(w, r, "handoff", 1, 10) || !readJSON(w, r, &b) {
		return
	}
	token, ok := h.accts.redeemHandoff(b.Code)
	if !ok {
		acctErr(w, 401, "handoff_invalid", "That sign-in link has expired or was already used. Sign in again.")
		return
	}
	pr, _ := h.resolveAccount(token)
	writeJSON(w, 200, map[string]interface{}{"token": token, "account": accountView(pr.Account), "expires_in": int(acctSessionTTL / time.Second)})
}

func (h *Host) authLogout(w http.ResponseWriter, r *http.Request) {
	t := bearer(r)
	if strings.HasPrefix(t, acctTokenPrefix) && h.accts.endSession(t) {
		h.Audit.Log(AuditEvent{Event: "account.signout", Remote: remoteIP(r)})
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// signupRules: the contract's rules as data (GET /v1/rules), with this host's mirror as the fallback.
func (h *Host) signupRules(ctx context.Context) map[string]interface{} {
	minAge := h.appMinAge(ctx)
	return map[string]interface{}{
		"username":      map[string]interface{}{"min": UsernameMin, "max": UsernameMax, "letters": UsernameLetters, "chars": "A-Z a-z 0-9 _ . -"},
		"name":          map[string]interface{}{"max": NameMax, "chars": "letters, spaces, apostrophes, hyphens and periods"},
		"password":      map[string]interface{}{"min": PasswordMin, "max": PasswordMax, "safeSpecials": SafeSpecials},
		"email":         map[string]interface{}{"max": EmailMax},
		"dob":           map[string]interface{}{"format": "MM/DD/YYYY", "maxAge": MaxAge},
		"minAge":        minAge,
		"centralMinAge": CentralMinAge,
		"twoFactor": []map[string]interface{}{
			{"id": "phone", "label": "Phone (text message)", "available": true},
			{"id": "app", "label": "Authenticator app", "available": true},
			{"id": "redxai_auth", "label": "Red-XAI Auth", "available": false, "note": "Coming soon"},
			{"id": "none", "label": "None", "available": true, "warning": true},
		},
	}
}

// appMinAge asks Red-XAI Accounts for this app's minimum age (never below 13).
func (h *Host) appMinAge(ctx context.Context) int {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, b, err := h.oidc.call(ctx, "GET", "/v1/rules?app="+url.QueryEscape(h.Cfg.AccountsClientID), nil, "", "")
	min := CentralMinAge
	if err == nil && st == 200 {
		var rr struct {
			MinAge int `json:"minAge"` // this app's minimum age (never below the central 13)
		}
		if json.Unmarshal(b, &rr) == nil && rr.MinAge > min {
			min = rr.MinAge
		}
	}
	return min
}

func (h *Host) proxyGET(w http.ResponseWriter, r *http.Request, path string) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	st, b, err := h.oidc.call(ctx, "GET", path, nil, "", remoteIP(r))
	h.relay(w, st, b, err)
}

func (h *Host) proxyPOST(w http.ResponseWriter, r *http.Request, path string, body interface{}, bearerTok string) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	st, b, err := h.oidc.call(ctx, "POST", path, body, bearerTok, remoteIP(r))
	h.relay(w, st, b, err)
}

// relay passes a Red-XAI Accounts JSON answer through (only JSON objects; anything else becomes a 502).
func (h *Host) relay(w http.ResponseWriter, st int, b []byte, err error) {
	if err != nil {
		acctErr(w, 503, "unavailable", errAccountsUnavailable.Error())
		return
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		acctErr(w, 502, "bad_gateway", "Red-XAI Accounts sent an answer RedX could not read.")
		return
	}
	writeJSON(w, st, m)
}

// authValidate: live checks for the sign-up form. Password and date of birth are checked here only (they are
// never sent anywhere for a live check); username and email also ask Red-XAI Accounts (available, domain, disposable).
func (h *Host) authValidate(w http.ResponseWriter, r *http.Request, field string) {
	if h.acctThrottle(w, r, "validate", 5, 40) {
		return
	}
	var b map[string]string
	if !readJSON(w, r, &b) {
		return
	}
	var checks []RuleCheck
	extra := map[string]interface{}{}
	remote := ""
	switch field {
	case "username":
		checks = CheckUsername(b["username"])
		remote = "/v1/validate/username"
	case "password":
		checks = CheckPassword(b["password"])
	case "email":
		checks = CheckEmailSyntax(b["email"])
		remote = "/v1/validate/email"
	case "dob":
		var age int
		var fe *FieldError
		checks, age, fe = CheckDOB(b["dob"], time.Now(), h.appMinAge(r.Context()))
		if age >= 0 {
			extra["age"] = age // derived for the hint only; RedX never stores it
		}
		if fe != nil {
			extra["error"], extra["message"] = fe.Code, fe.Message
		}
	default:
		writeErr(w, 404, "not found")
		return
	}
	if remote != "" && firstFail(checks) == "" {
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		st, rb, err := h.oidc.call(ctx, "POST", remote, map[string]string{field: strings.TrimSpace(b[field])}, "", remoteIP(r))
		var rr struct {
			Checks  []RuleCheck `json:"checks"`
			Error   string      `json:"error"`
			Message string      `json:"message"`
		}
		if err != nil || st != 200 || json.Unmarshal(rb, &rr) != nil {
			checks = append(checks, RuleCheck{"available", false, "Could not check with Red-XAI Accounts right now"})
		} else {
			have := map[string]bool{}
			for _, c := range checks {
				have[c.ID] = true
			}
			for _, c := range rr.Checks {
				if !have[c.ID] {
					checks = append(checks, c)
				}
			}
			if rr.Error != "" {
				extra["error"], extra["message"] = rr.Error, rr.Message
			}
		}
	}
	out := map[string]interface{}{"ok": firstFail(checks) == "", "checks": checks}
	for k, v := range extra {
		out[k] = v
	}
	writeJSON(w, 200, out)
}

func (h *Host) authSignup(w http.ResponseWriter, r *http.Request) {
	if h.acctThrottle(w, r, "signup", 0.2, 30) {
		return
	}
	var req SignupRequest
	if !readJSON(w, r, &req) {
		return
	}
	req.App = h.Cfg.AccountsClientID
	req.Username = strings.TrimSpace(req.Username)
	if fe := ValidateSignup(&req, time.Now(), h.appMinAge(r.Context())); fe != nil {
		code := 400
		if fe.Code == "under_min_age" {
			code = 403
		}
		writeJSON(w, code, fe)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	st, b, err := h.oidc.call(ctx, "POST", "/v1/signup", req, "", remoteIP(r))
	if err != nil || st != 201 {
		h.relay(w, st, b, err)
		return
	}
	var res struct {
		Step           string                 `json:"step"`
		Account        map[string]interface{} `json:"account"`
		Session        string                 `json:"session"`
		Pending        []string               `json:"pending"`
		TOTP           map[string]interface{} `json:"totp"`
		EmailMasked    string                 `json:"emailMasked"`
		EmailSent      *bool                  `json:"emailSent"`
		PendingUntilMs int64                  `json:"pendingUntilMs"`
		Resumed        bool                   `json:"resumed"`
		Message        string                 `json:"message"`
	}
	if json.Unmarshal(b, &res) != nil {
		acctErr(w, 502, "bad_gateway", "Red-XAI Accounts sent an answer RedX could not read.")
		return
	}
	acct := map[string]interface{}{}
	if res.Account != nil {
		acct["username"] = res.Account["username"]
		acct["email"] = res.Account["email"]
		acct["emailVerified"] = res.Account["emailVerified"]
		for _, k := range []string{"firstName", "middleName", "lastName"} {
			if v, ok := res.Account[k]; ok {
				acct[k] = v
			}
		}
	}
	out := map[string]interface{}{"pending": res.Pending, "twoFactor": req.TwoFactor, "account": acct}
	if res.TOTP != nil {
		out["totp"] = res.TOTP // the authenticator key, so it can be saved before the email link is opened
	}
	if res.Session != "" {
		// An older Accounts server still returns a session and confirms 2FA during sign-up.
		if containsStr(res.Pending, "2fa_setup") {
			out["handle"] = h.accts.addSignup(res.Session)
		}
	} else {
		// v1.2: sign-up never signs in. The person opens the email link, then signs in.
		out["step"] = "verify_email"
		if res.Step != "" {
			out["step"] = res.Step
		}
		sent := true
		if res.EmailSent != nil {
			sent = *res.EmailSent
		}
		out["emailSent"] = sent
		if res.PendingUntilMs > 0 {
			out["pendingUntilMs"] = res.PendingUntilMs
		}
		if res.EmailMasked != "" {
			out["emailMasked"] = res.EmailMasked
		}
		if res.Message != "" {
			out["message"] = res.Message
		}
		if res.Resumed {
			out["resumed"] = true
		}
	}
	h.Audit.Log(AuditEvent{Event: "account.signup", Remote: remoteIP(r), Detail: "new Red-XAI Account via RedX (2FA: " + req.TwoFactor + ")"})
	writeJSON(w, 201, out)
}

// authEmailResend proxies POST /v1/email/resend {login}. No session: the account is not signed in yet.
func (h *Host) authEmailResend(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Login string `json:"login"`
	}
	if h.acctThrottle(w, r, "emailresend", 10.0/3600, 10) || !readJSON(w, r, &b) {
		return
	}
	login := strings.TrimSpace(b.Login)
	if login == "" || len(login) > EmailMax || strings.ContainsAny(login, "\r\n\x00") {
		acctErr(w, 400, "bad_request", "Enter the email address or username.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	st, rb, hdr, err := h.oidc.callRaw(ctx, "POST", "/v1/email/resend", map[string]string{"login": login}, "", remoteIP(r))
	if err != nil {
		acctErr(w, 503, "unavailable", errAccountsUnavailable.Error())
		return
	}
	var m map[string]interface{}
	if json.Unmarshal(rb, &m) != nil {
		acctErr(w, 502, "bad_gateway", "Red-XAI Accounts sent an answer RedX could not read.")
		return
	}
	if hdr != nil {
		if ra := strings.TrimSpace(hdr.Get("Retry-After")); ra != "" {
			w.Header().Set("Retry-After", ra)
			if sec, nerr := strconv.Atoi(ra); nerr == nil && sec > 0 {
				m["retryAfter"] = sec
			}
		}
	}
	if st == 429 {
		if m["error"] == nil || m["error"] == "" {
			m["error"] = "rate_limited"
		}
		if m["message"] == nil || m["message"] == "" {
			m["message"] = "Too many verification emails from this network. Wait and try again."
		}
	}
	h.Audit.Log(AuditEvent{Event: "account.email.resend", Remote: remoteIP(r)})
	writeJSON(w, st, m)
}

func (h *Host) authSignup2FA(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Handle string `json:"handle"`
		Code   string `json:"code"`
	}
	if h.acctThrottle(w, r, "signup2fa", 0.5, 10) || !readJSON(w, r, &b) {
		return
	}
	sess, ok := h.accts.signup(b.Handle, false)
	if !ok {
		acctErr(w, 401, "handle_invalid", "This sign-up has expired. Sign in to finish setting up two-factor authentication.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	st, rb, err := h.oidc.call(ctx, "POST", "/v1/me/2fa/confirm", map[string]string{"code": strings.TrimSpace(b.Code)}, sess, remoteIP(r))
	if err == nil && st >= 200 && st < 300 {
		h.accts.signup(b.Handle, true)
		_, _, _ = h.oidc.call(ctx, "POST", "/v1/logout", map[string]string{}, sess, remoteIP(r)) // RedX keeps no Red-XAI session
	}
	h.relay(w, st, rb, err)
}

// authSignupResend asks Red-XAI Accounts to text the sign-up 2FA code again (configurable route; off when unset).
func (h *Host) authSignupResend(w http.ResponseWriter, r *http.Request) {
	if h.Cfg.AccountsSMSResendPath == "" {
		acctErr(w, 404, "not_enabled", "Resending the text message is not available yet.")
		return
	}
	var b struct {
		Handle string `json:"handle"`
	}
	if h.acctThrottle(w, r, "smsresend", 1.0/30, 3) || !readJSON(w, r, &b) {
		return
	}
	sess, ok := h.accts.signup(b.Handle, false)
	if !ok {
		acctErr(w, 401, "handle_invalid", "This sign-up has expired. Sign in to finish setting up two-factor authentication.")
		return
	}
	h.proxyPOST(w, r, h.Cfg.AccountsSMSResendPath, map[string]string{}, sess)
}
