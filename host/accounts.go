package host

// Red-XAI Accounts sign-in for the web console and the owner role.
//
// redxd is an OIDC relying party of the shared Red-XAI Accounts service (authorization code + PKCE S256,
// ES256 ID tokens). A finished sign-in becomes a RedX console session (an opaque "rxs_" bearer token kept in
// memory on this node). API keys keep working unchanged for SDKs and machines.
//
// Owners: an account is an owner of this host only when, at request time, its email is listed in the deploy
// config (owner_emails / REDXAI_OWNER_EMAILS), the email is verified, and this sign-in was completed with a
// second factor (amr contains "otp" or "sms"). Owners act as host admins, can see the master Red-XAI accounts
// database, every hosted database and every account, and every request they make is audit-logged with the
// acting owner. Everyone else cannot tell that the master database exists.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// OwnerScope is the OIDC scope Red-XAI Accounts grants only to owner logins; owner rights need it on the token.
const OwnerScope = "owner"

// DefaultAccountsMasterDB is the RedX database the Red-XAI Accounts service stores its records in.
const DefaultAccountsMasterDB = "redxai_accounts"

// Console session lifetimes.
const (
	acctSessionTTL  = 12 * time.Hour
	acctSessionIdle = 2 * time.Hour
	acctLoginTTL    = 10 * time.Minute
	acctHandoffTTL  = 2 * time.Minute
	acctSignupTTL   = 30 * time.Minute
	acctMaxPending  = 10000
	acctTokenPrefix = "rxs_"
)

func (c *Config) validateAccounts() error {
	c.AccountsIssuer = strings.TrimRight(strings.TrimSpace(c.AccountsIssuer), "/")
	if c.AccountsClientID == "" {
		c.AccountsClientID = "redx"
	}
	if c.AccountsMasterDB == "" {
		c.AccountsMasterDB = DefaultAccountsMasterDB
	}
	if !ValidDBName(c.AccountsMasterDB) {
		return fmt.Errorf("invalid accounts_master_db %q", c.AccountsMasterDB)
	}
	var owners []string
	for _, e := range c.OwnerEmails {
		e = foldEmail(e)
		if e == "" {
			continue
		}
		if !strings.Contains(e, "@") || strings.ContainsAny(e, " \t,") {
			return fmt.Errorf("owner_emails: %q is not an email address", e)
		}
		if !emailASCII(e) {
			return fmt.Errorf("owner_emails: %q must be ASCII (Unicode lookalikes are refused)", e)
		}
		owners = append(owners, e)
	}
	c.OwnerEmails = owners
	if c.AccountsIssuer == "" {
		return nil
	}
	if err := checkIssuerURL(c.AccountsIssuer); err != nil {
		return fmt.Errorf("accounts_issuer: %w", err)
	}
	if c.AccountsClientSecret == "" && c.AccountsClientSecretFile != "" {
		b, err := os.ReadFile(c.AccountsClientSecretFile)
		if err != nil {
			return fmt.Errorf("accounts_client_secret_file: %w", err)
		}
		c.AccountsClientSecret = strings.TrimSpace(string(b))
	}
	if c.AccountsClientSecret == "" {
		return fmt.Errorf("accounts_issuer is set but RedX has no client secret: set REDX_ACCOUNTS_CLIENT_SECRET or accounts_client_secret_file (RedX is a confidential Red-XAI Accounts client)")
	}
	if c.AccountsSMSResendPath == "" {
		c.AccountsSMSResendPath = "/v1/signup/resend-sms" // contract v1.1; set env to "off" to hide the button
	}
	if c.AccountsSMSResendPath == "off" {
		c.AccountsSMSResendPath = ""
	}
	if p := c.AccountsSMSResendPath; p != "" && (!strings.HasPrefix(p, "/v1/") || strings.ContainsAny(p, "?#") || strings.Contains(p, "..")) {
		return fmt.Errorf("accounts_sms_resend_path must be a Red-XAI Accounts path such as /v1/..., got %q", p)
	}
	if c.AccountsEventsPoll <= 0 {
		c.AccountsEventsPoll = 15
	}
	if c.AccountsRedirect != "" {
		u, err := url.Parse(c.AccountsRedirect)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Path != "/v1/auth/callback" {
			return fmt.Errorf("accounts_redirect_url must be <this host's URL>/v1/auth/callback, got %q", c.AccountsRedirect)
		}
	}
	return nil
}

// checkIssuerURL: https, or http only for a loopback host (local development and tests).
func checkIssuerURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("must be a URL such as https://accounts.red-xai.example, got %q", s)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("must use https (http is allowed only for localhost), got %q", s)
	}
	return fmt.Errorf("must use https, got %q", s)
}

// foldEmail trims and lowercases only ASCII A–Z. Unicode lookalikes (Kelvin K→k via strings.ToLower,
// fullwidth letters, etc.) must NOT match a listed owner address. Owner config is also rejected if it
// contains a non-ASCII rune (see validateAccounts).
func foldEmail(e string) string {
	e = strings.TrimSpace(e)
	b := make([]byte, len(e))
	for i := 0; i < len(e); i++ {
		c := e[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

// emailASCII reports whether s is all ASCII (owner emails must be; IdP emails with non-ASCII never match).
func emailASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

// AccountIdentity is a signed-in Red-XAI Account (claims from a verified ID token).
type AccountIdentity struct {
	Sub           string    `json:"sub"`
	Username      string    `json:"username,omitempty"`
	Email         string    `json:"email,omitempty"`
	EmailVerified bool      `json:"email_verified"`
	AMR           []string  `json:"amr,omitempty"`
	AgeBand       string    `json:"age_band,omitempty"`
	Scopes        []string  `json:"scopes,omitempty"` // scopes granted on the access token (the "owner" scope matters)
	Created       time.Time `json:"created"`
	// set per request by the authenticator (not stored)
	Owner        bool   `json:"owner"`
	OwnerBlocked string `json:"owner_blocked,omitempty"` // why an owner email is not acting as owner (e.g. owner_2fa_required)
}

// used2FA: the sign-in was completed with a second factor (Red-XAI Accounts amr values).
func (a *AccountIdentity) used2FA() bool {
	for _, m := range a.AMR {
		if m == "otp" || m == "sms" {
			return true
		}
	}
	return false
}

// ownerStatus evaluates the owner rule against the configured owner list.
func ownerStatus(a *AccountIdentity, owners []string) (owner bool, blocked string) {
	if a == nil || a.Email == "" {
		return false, ""
	}
	if !emailASCII(a.Email) {
		return false, "" // Kelvin / fullwidth / etc. never match a listed owner
	}
	e := foldEmail(a.Email)
	listed := false
	for _, o := range owners {
		if o == e {
			listed = true
			break
		}
	}
	switch {
	case !listed:
		return false, ""
	case !a.EmailVerified:
		return false, "owner_email_unverified"
	case !a.used2FA():
		return false, "owner_2fa_required"
	case !containsStr(a.Scopes, OwnerScope):
		return false, "owner_scope_missing"
	}
	return true, ""
}

type acctSession struct {
	id       AccountIdentity
	created  time.Time
	lastSeen time.Time
	// Red-XAI Accounts tokens, kept in memory only for owner sessions (moderation calls need them).
	access, refresh string
	accessExp       time.Time
}

// acctTokens are an owner session's Red-XAI Accounts tokens.
type acctTokens struct {
	Access, Refresh string
	AccessExp       time.Time
}

type acctPending struct {
	verifier, nonce, redirect, ret string
	// Hub chooses only a fixed relative callback destination: no open redirects.
	hub     bool
	created time.Time
}

type acctHandoff struct {
	token   string
	created time.Time
}

type acctSignup struct {
	session string // the Red-XAI Accounts session from /v1/signup (used only to finish 2FA setup)
	created time.Time
}

// accountStore keeps console sessions, pending logins, handoff codes and unfinished sign-ups in memory.
// Only SHA-256 hashes of the tokens are used as map keys.
type accountStore struct {
	mu       sync.Mutex
	sessions map[string]*acctSession
	pending  map[string]*acctPending
	handoff  map[string]*acctHandoff
	signups  map[string]*acctSignup
	streams  map[string]map[int]func() // session hash -> cancel funcs of its open requests (WebSockets)
	streamN  int
	now      func() time.Time
}

func newAccountStore() *accountStore {
	return &accountStore{sessions: map[string]*acctSession{}, pending: map[string]*acctPending{}, handoff: map[string]*acctHandoff{},
		signups: map[string]*acctSignup{}, streams: map[string]map[int]func(){}, now: time.Now}
}

func tokHash(t string) string { s := sha256.Sum256([]byte(t)); return hex.EncodeToString(s[:]) }

func randToken(prefix string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// gc drops expired entries. Caller holds mu.
func (s *accountStore) gcLocked() {
	now := s.now()
	for k, v := range s.sessions {
		if now.Sub(v.created) > acctSessionTTL || now.Sub(v.lastSeen) > acctSessionIdle {
			delete(s.sessions, k)
		}
	}
	for k, v := range s.pending {
		if now.Sub(v.created) > acctLoginTTL {
			delete(s.pending, k)
		}
	}
	for k, v := range s.handoff {
		if now.Sub(v.created) > acctHandoffTTL {
			delete(s.handoff, k)
		}
	}
	for k, v := range s.signups {
		if now.Sub(v.created) > acctSignupTTL {
			delete(s.signups, k)
		}
	}
}

var errTooMany = errors.New("too many sign-ins in progress; try again in a few minutes")

func (s *accountStore) addPending(state string, p *acctPending) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	if len(s.pending) >= acctMaxPending {
		return errTooMany
	}
	p.created = s.now()
	s.pending[tokHash(state)] = p
	return nil
}

func (s *accountStore) takePending(state string) *acctPending {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	k := tokHash(state)
	p := s.pending[k]
	delete(s.pending, k)
	return p
}

// newSession stores a console session and returns a single-use handoff code for the browser.
func (s *accountStore) newSession(id AccountIdentity) (token, handoff string) {
	return s.newSessionWithTokens(id, nil)
}

func (s *accountStore) newSessionWithTokens(id AccountIdentity, t *acctTokens) (token, handoff string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	now := s.now()
	id.Created = now
	id.Owner, id.OwnerBlocked = false, ""
	token = randToken(acctTokenPrefix)
	se := &acctSession{id: id, created: now, lastSeen: now}
	if t != nil {
		se.access, se.refresh, se.accessExp = t.Access, t.Refresh, t.AccessExp
	}
	s.sessions[tokHash(token)] = se
	handoff = randToken("rxh_")
	s.handoff[tokHash(handoff)] = &acctHandoff{token: token, created: now}
	return token, handoff
}

func (s *accountStore) redeemHandoff(code string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	k := tokHash(code)
	h := s.handoff[k]
	delete(s.handoff, k)
	if h == nil {
		return "", false
	}
	return h.token, true
}

func (s *accountStore) lookup(token string) (*AccountIdentity, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := tokHash(token)
	v := s.sessions[k]
	if v == nil {
		return nil, false
	}
	now := s.now()
	if now.Sub(v.created) > acctSessionTTL || now.Sub(v.lastSeen) > acctSessionIdle {
		delete(s.sessions, k)
		return nil, false
	}
	v.lastSeen = now
	id := v.id
	return &id, true
}

func (s *accountStore) endSession(token string) bool {
	s.mu.Lock()
	k := tokHash(token)
	_, ok := s.sessions[k]
	delete(s.sessions, k)
	cancels := s.takeStreamsLocked(k)
	s.mu.Unlock()
	for _, c := range cancels {
		c()
	}
	return ok
}

func (s *accountStore) takeStreamsLocked(k string) []func() {
	var out []func()
	for _, c := range s.streams[k] {
		out = append(out, c)
	}
	delete(s.streams, k)
	return out
}

// endSessionsForSub ends every console session of one Red-XAI Account and closes its open WebSockets.
func (s *accountStore) endSessionsForSub(sub string) int {
	s.mu.Lock()
	var cancels []func()
	n := 0
	for k, v := range s.sessions {
		if v.id.Sub == sub {
			delete(s.sessions, k)
			cancels = append(cancels, s.takeStreamsLocked(k)...)
			n++
		}
	}
	s.mu.Unlock()
	for _, c := range cancels {
		c()
	}
	return n
}

// trackStream registers cancel for a long-lived request (a WebSocket) made with a console session; it runs
// when the session ends. The returned func unregisters it.
func (s *accountStore) trackStream(token string, cancel func()) func() {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := tokHash(token)
	if s.streams[k] == nil {
		s.streams[k] = map[int]func(){}
	}
	s.streamN++
	id := s.streamN
	s.streams[k][id] = cancel
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if m := s.streams[k]; m != nil {
			delete(m, id)
			if len(m) == 0 {
				delete(s.streams, k)
			}
		}
	}
}

// tokens returns an owner session's Red-XAI Accounts tokens.
func (s *accountStore) tokens(token string) (acctTokens, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.sessions[tokHash(token)]
	if v == nil || v.access == "" {
		return acctTokens{}, false
	}
	return acctTokens{Access: v.access, Refresh: v.refresh, AccessExp: v.accessExp}, true
}

// setTokens stores rotated tokens (refresh tokens rotate on every use).
func (s *accountStore) setTokens(token string, t acctTokens) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v := s.sessions[tokHash(token)]; v != nil {
		v.access, v.refresh, v.accessExp = t.Access, t.Refresh, t.AccessExp
	}
}

func (s *accountStore) addSignup(accSession string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	h := randToken("rxsu_")
	s.signups[tokHash(h)] = &acctSignup{session: accSession, created: s.now()}
	return h
}

func (s *accountStore) signup(handle string, remove bool) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	k := tokHash(handle)
	v := s.signups[k]
	if v == nil {
		return "", false
	}
	if remove {
		delete(s.signups, k)
	}
	return v.session, true
}

// ---- host helpers ----

// AccountsEnabled reports whether Red-XAI Accounts sign-in is configured.
func (h *Host) AccountsEnabled() bool { return h.Cfg.AccountsIssuer != "" }

// masterDB is the protected master accounts database name, or "" when accounts are off.
func (h *Host) masterDB() string {
	if !h.AccountsEnabled() {
		return ""
	}
	return h.Cfg.AccountsMasterDB
}

// IsMasterDB reports whether db is the protected master accounts database.
func (h *Host) IsMasterDB(db string) bool { m := h.masterDB(); return m != "" && db == m }

// resolveAccount turns a console session token into a principal (called by the Authenticator).
func (h *Host) resolveAccount(token string) (*Principal, bool) {
	if h.accts == nil {
		return nil, false
	}
	id, ok := h.accts.lookup(token)
	if !ok {
		return nil, false
	}
	id.Owner, id.OwnerBlocked = ownerStatus(id, h.Cfg.OwnerEmails)
	rec := KeyRecord{ID: "acct:" + id.Sub, Label: firstNonEmpty(id.Username, id.Email, id.Sub), Kind: "account", Created: id.Created}
	if id.Owner {
		rec.Scope, rec.DB = ScopeAdmin, AllDBs
	} else {
		rec.Scope, rec.DB = "none", "-" // signed in, no database rights yet
	}
	return &Principal{Key: rec, Account: id}, true
}
