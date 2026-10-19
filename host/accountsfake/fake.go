// Package accountsfake is an in-memory stand-in for the Red-XAI Accounts service (v1 contract: OIDC with
// PKCE S256 and ES256 tokens, ToS grants, validation and sign-up). It is for tests and local development only
// and is never linked into redxd.
package accountsfake

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"redx/host"
)

// Identity is who the next /oauth2/authorize "signs in" as.
type Identity struct {
	Sub           string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Username      string   `json:"username"`
	AMR           []string `json:"amr"`
	AgeBand       string   `json:"age_band"`
	Error         string   `json:"error"` // e.g. access_denied: authorize redirects back with this error
}

type code struct {
	id                                           Identity
	clientID, redirect, challenge, nonce, method string
	used                                         bool
}

type grant struct {
	stage, version string
	used           bool
}

// Server is the fake. Set Issuer to the URL it is served at before use.
type Server struct {
	mu         sync.Mutex
	Issuer     string
	ClientID   string
	Redirects  []string // registered redirect URIs (empty = any)
	TOSVersion string
	TOTPCode   string // the only code /v1/me/2fa/confirm accepts
	MinAge     int
	next       Identity
	key        *ecdsa.PrivateKey
	kid        string
	codes      map[string]*code
	grants     map[string]*grant
	sessions   map[string]string // session -> account username
	taken      map[string]bool   // folded usernames and emails
	Signups    []host.SignupRequest
	Confirmed  []string
	Tokens     int // successful token exchanges
}

// New returns a fake with one ES256 signing key.
func New() *Server {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return &Server{ClientID: "redx", TOSVersion: "2026-10-19", TOTPCode: "123456", MinAge: 13, key: k, kid: "fake-1",
		codes: map[string]*code{}, grants: map[string]*grant{}, sessions: map[string]string{}, taken: map[string]bool{"takenuser1": true, "taken@example.com": true},
		next: Identity{Sub: "rxa_FAKEUSER0000000000000000001", Email: "user@example.com", EmailVerified: true, Username: "regular_user", AMR: []string{"pwd"}}}
}

// SetNext sets the identity of the next sign-in.
func (s *Server) SetNext(id Identity) { s.mu.Lock(); s.next = id; s.mu.Unlock() }

func rnd(p string) string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return p + base64.RawURLEncoding.EncodeToString(b)
}

func j(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func e(w http.ResponseWriter, code int, c, msg string) {
	j(w, code, map[string]string{"error": c, "message": msg})
}

// Handler serves the fake API.
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		j(w, 200, map[string]interface{}{"issuer": s.Issuer, "authorization_endpoint": s.Issuer + "/oauth2/authorize",
			"token_endpoint": s.Issuer + "/oauth2/token", "jwks_uri": s.Issuer + "/oauth2/jwks", "userinfo_endpoint": s.Issuer + "/oauth2/userinfo",
			"code_challenge_methods_supported": []string{"S256"}, "id_token_signing_alg_values_supported": []string{"ES256"}})
	})
	m.HandleFunc("/oauth2/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := s.key.PublicKey
		j(w, 200, map[string]interface{}{"keys": []map[string]string{{"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": s.kid,
			"x": b64(pad32(pub.X)), "y": b64(pad32(pub.Y))}}})
	})
	m.HandleFunc("/oauth2/authorize", s.authorize)
	m.HandleFunc("/oauth2/token", s.token)
	m.HandleFunc("/oauth2/userinfo", func(w http.ResponseWriter, r *http.Request) { e(w, 401, "invalid_token", "fake: use the ID token") })
	m.HandleFunc("/v1/rules", func(w http.ResponseWriter, r *http.Request) {
		j(w, 200, map[string]interface{}{"minAge": s.MinAge, "centralMinAge": 13, "safeSpecials": host.SafeSpecials})
	})
	m.HandleFunc("/v1/tos", func(w http.ResponseWriter, r *http.Request) {
		text := "Red-XAI Accounts Terms of Service (fake text for tests).\n\n"
		for i := 1; i <= 60; i++ {
			text += fmt.Sprintf("%d. This is section %d of the terms. Read every word before you agree.\n\n", i, i)
		}
		j(w, 200, map[string]interface{}{"version": s.TOSVersion, "title": "Red-XAI Accounts Terms of Service", "text": text,
			"privacyVersion": s.TOSVersion, "privacyText": "Privacy (fake).",
			"falseInfoWarning": "If you give false information, the account cannot be recovered.",
			"no2faWarning":     "Without two-factor authentication anyone with your password can take over your account."})
	})
	m.HandleFunc("/v1/tos/read", s.tosRead)
	m.HandleFunc("/v1/tos/agree", s.tosAgree)
	m.HandleFunc("/v1/validate/", s.validate)
	m.HandleFunc("/v1/signup", s.signup)
	m.HandleFunc("/v1/me/2fa/confirm", s.confirm)
	m.HandleFunc("/v1/logout", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		delete(s.sessions, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		s.mu.Unlock()
		j(w, 200, map[string]bool{"ok": true})
	})
	m.HandleFunc("/fake/next-login", func(w http.ResponseWriter, r *http.Request) {
		var id Identity
		if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&id) != nil {
			e(w, 400, "bad_request", "POST an identity")
			return
		}
		s.SetNext(id)
		j(w, 200, map[string]bool{"ok": true})
	})
	return m
}

func pad32(b *big.Int) []byte { out := make([]byte, 32); b.FillBytes(out); return out }
func b64(b []byte) string     { return base64.RawURLEncoding.EncodeToString(b) }

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redir := q.Get("redirect_uri")
	s.mu.Lock()
	defer s.mu.Unlock()
	ok := len(s.Redirects) == 0
	for _, u := range s.Redirects {
		ok = ok || u == redir
	}
	switch {
	case q.Get("client_id") != s.ClientID:
		e(w, 400, "unknown_app", "unknown client_id")
		return
	case !ok || redir == "":
		e(w, 400, "invalid_request", "redirect_uri is not registered")
		return
	case q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) < 43:
		e(w, 400, "invalid_request", "PKCE S256 is required")
		return
	}
	u, _ := url.Parse(redir)
	v := u.Query()
	v.Set("state", q.Get("state"))
	if s.next.Error != "" {
		v.Set("error", s.next.Error)
	} else {
		c := rnd("c_")
		s.codes[c] = &code{id: s.next, clientID: s.ClientID, redirect: redir, challenge: q.Get("code_challenge"), nonce: q.Get("nonce")}
		v.Set("code", c)
	}
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.ParseForm() != nil {
		e(w, 400, "invalid_request", "POST a form")
		return
	}
	f := r.PostForm
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.codes[f.Get("code")]
	sum := sha256.Sum256([]byte(f.Get("code_verifier")))
	switch {
	case f.Get("grant_type") != "authorization_code" || c == nil || c.used:
		e(w, 400, "invalid_grant", "unknown or used code")
		return
	case f.Get("client_id") != c.clientID || f.Get("redirect_uri") != c.redirect:
		e(w, 400, "invalid_grant", "client or redirect mismatch")
		return
	case b64(sum[:]) != c.challenge:
		e(w, 400, "invalid_grant", "PKCE verifier mismatch")
		return
	}
	c.used = true
	s.Tokens++
	now := time.Now().Unix()
	claims := map[string]interface{}{"iss": s.Issuer, "sub": c.id.Sub, "aud": c.clientID, "iat": now, "exp": now + 600, "auth_time": now,
		"nonce": c.nonce, "amr": c.id.AMR, "sid": rnd("sid_"), "email": c.id.Email, "email_verified": c.id.EmailVerified,
		"preferred_username": c.id.Username, "age_band": firstNonEmpty(c.id.AgeBand, "18plus"), "adult_verified": false}
	j(w, 200, map[string]interface{}{"access_token": rnd("at_"), "token_type": "Bearer", "expires_in": 600, "id_token": s.Sign(claims),
		"refresh_token": rnd("rt_"), "scope": "openid profile email"})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Sign makes an ES256 JWT with the fake's key (tests use it to forge variations).
func (s *Server) Sign(claims map[string]interface{}) string {
	return SignWith(s.key, s.kid, claims)
}

// SignWith signs claims as an ES256 JWT with any key.
func SignWith(k *ecdsa.PrivateKey, kid string, claims map[string]interface{}) string {
	hb, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": kid})
	cb, _ := json.Marshal(claims)
	in := b64(hb) + "." + b64(cb)
	sum := sha256.Sum256([]byte(in))
	rr, ss, err := ecdsa.Sign(rand.Reader, k, sum[:])
	if err != nil {
		panic(err)
	}
	return in + "." + b64(append(pad32(rr), pad32(ss)...))
}

func decode(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	if r.Method != "POST" || json.NewDecoder(r.Body).Decode(v) != nil {
		e(w, 400, "bad_request", "POST JSON")
		return false
	}
	return true
}

func (s *Server) tosRead(w http.ResponseWriter, r *http.Request) {
	var b struct{ App, Version string }
	if !decode(w, r, &b) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if b.App != s.ClientID {
		e(w, 400, "unknown_app", "unknown app")
		return
	}
	if b.Version != s.TOSVersion {
		e(w, 409, "tos_changed", "The terms changed; read the new version.")
		return
	}
	g := rnd("rxa_t_")
	s.grants[g] = &grant{stage: "read", version: b.Version}
	j(w, 200, map[string]string{"grant": g, "stage": "read"})
}

func (s *Server) tosAgree(w http.ResponseWriter, r *http.Request) {
	var b struct{ Grant string }
	if !decode(w, r, &b) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.grants[b.Grant]
	if g == nil || g.stage != "read" {
		e(w, 409, "tos_not_read", "Read the terms first.")
		return
	}
	g.stage = "agreed"
	j(w, 200, map[string]string{"grant": b.Grant, "stage": "agreed"})
}

func (s *Server) validate(w http.ResponseWriter, r *http.Request) {
	var b map[string]string
	if !decode(w, r, &b) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch strings.TrimPrefix(r.URL.Path, "/v1/validate/") {
	case "username":
		ok := !s.taken[strings.ToLower(b["username"])]
		j(w, 200, map[string]interface{}{"ok": ok, "checks": []host.RuleCheck{{ID: "available", OK: ok, Message: "Not taken yet"}}})
	case "email":
		em := strings.ToLower(strings.TrimSpace(b["email"]))
		dom := em[strings.LastIndex(em, "@")+1:]
		domOK := !strings.HasSuffix(dom, ".invalid")
		disp := dom != "mailinator.com"
		avail := !s.taken[em]
		j(w, 200, map[string]interface{}{"ok": domOK && disp && avail, "checks": []host.RuleCheck{
			{ID: "domain", OK: domOK, Message: "The domain can receive email"}, {ID: "disposable", OK: disp, Message: "Not a throw-away address"},
			{ID: "available", OK: avail, Message: "Not used by another account"}}})
	default:
		e(w, 404, "not_found", "unknown check")
	}
}

func (s *Server) signup(w http.ResponseWriter, r *http.Request) {
	var b host.SignupRequest
	if !decode(w, r, &b) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if b.App != s.ClientID {
		e(w, 400, "unknown_app", "unknown app")
		return
	}
	cp := b
	if fe := host.ValidateSignup(&cp, time.Now(), s.MinAge); fe != nil {
		code := 400
		if fe.Code == "under_min_age" {
			code = 403
		}
		j(w, code, fe)
		return
	}
	g := s.grants[b.TOSGrant]
	if g == nil || g.stage != "agreed" || g.used {
		e(w, 400, "tos_grant_invalid", "Agree to the terms again.")
		return
	}
	if s.taken[strings.ToLower(b.Username)] {
		j(w, 409, map[string]string{"error": "username_taken", "message": "That username is taken.", "field": "username"})
		return
	}
	if s.taken[strings.ToLower(b.Email)] {
		j(w, 409, map[string]string{"error": "email_taken", "message": "That email is already used.", "field": "email"})
		return
	}
	g.used = true
	s.taken[strings.ToLower(b.Username)], s.taken[strings.ToLower(b.Email)] = true, true
	b.Password, b.PasswordConfirm = "(redacted)", "(redacted)"
	s.Signups = append(s.Signups, b)
	sess := rnd("rxa_s_")
	s.sessions[sess] = b.Username
	out := map[string]interface{}{"account": map[string]interface{}{"id": rnd("rxa_"), "username": b.Username, "email": b.Email, "emailVerified": false},
		"session": sess, "pending": []string{}}
	if b.TwoFactor != "none" {
		out["pending"] = []string{"2fa_setup"}
	}
	if b.TwoFactor == "app" {
		out["totp"] = map[string]string{"secret": "JBSWY3DPEHPK3PXP", "otpauthUri": "otpauth://totp/Red-XAI:" + url.PathEscape(b.Username) + "?secret=JBSWY3DPEHPK3PXP&issuer=Red-XAI"}
	}
	j(w, 201, out)
}

func (s *Server) confirm(w http.ResponseWriter, r *http.Request) {
	var b struct{ Code string }
	if !decode(w, r, &b) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.sessions[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	if !ok {
		e(w, 401, "unauthorized", "no session")
		return
	}
	if b.Code != s.TOTPCode {
		e(w, 400, "code_invalid", "That code is not right.")
		return
	}
	s.Confirmed = append(s.Confirmed, u)
	j(w, 200, map[string]interface{}{"ok": true, "twoFactorState": "active"})
}
