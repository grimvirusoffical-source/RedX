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
	"strings"
	"sync"
	"time"
)

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
		owners = append(owners, e)
	}
	c.OwnerEmails = owners
	if c.AccountsIssuer == "" {
		return nil
	}
	if err := checkIssuerURL(c.AccountsIssuer); err != nil {
		return fmt.Errorf("accounts_issuer: %w", err)
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

func foldEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

// AccountIdentity is a signed-in Red-XAI Account (claims from a verified ID token).
type AccountIdentity struct {
	Sub           string    `json:"sub"`
	Username      string    `json:"username,omitempty"`
	Email         string    `json:"email,omitempty"`
	EmailVerified bool      `json:"email_verified"`
	AMR           []string  `json:"amr,omitempty"`
	AgeBand       string    `json:"age_band,omitempty"`
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
	}
	return true, ""
}

type acctSession struct {
	id       AccountIdentity
	created  time.Time
	lastSeen time.Time
}

type acctPending struct {
	verifier, nonce, redirect, ret string
	created                        time.Time
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
	now      func() time.Time
}

func newAccountStore() *accountStore {
	return &accountStore{sessions: map[string]*acctSession{}, pending: map[string]*acctPending{}, handoff: map[string]*acctHandoff{},
		signups: map[string]*acctSignup{}, now: time.Now}
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	now := s.now()
	id.Created = now
	id.Owner, id.OwnerBlocked = false, ""
	token = randToken(acctTokenPrefix)
	s.sessions[tokHash(token)] = &acctSession{id: id, created: now, lastSeen: now}
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
	defer s.mu.Unlock()
	k := tokHash(token)
	_, ok := s.sessions[k]
	delete(s.sessions, k)
	return ok
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
