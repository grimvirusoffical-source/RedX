package host

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// App connect handshake (docs/connect.md; joint design GENDRAGOON-REDX.md section 2; wire format of
// Rotten Apple's docs/connect.md and connect/client.go).
//
//	POST   /v1/connect/start         host admin   the console registers the request it is showing
//	GET    /v1/connect/pending       host admin   open requests (for the consent page)
//	POST   /v1/connect/approve       host admin   consent: creates the workspace, mints a one-time code
//	POST   /v1/connect/deny          host admin   decline
//	POST   /v1/connect/exchange      none         code + PKCE verifier + state -> the scoped key (only here)
//	POST   /v1/connect/revoke        the app key  the app (or its launcher, on uninstall) revokes its own key
//	GET    /v1/connect/apps          host admin   connected apps
//	DELETE /v1/connect/apps/{id}     host admin   revoke a connection
//
// Nothing secret is kept in plain text: request ids, states, codes and provider grants are stored as
// SHA-256; the key itself is minted at the exchange and is never stored by this file. Pending requests are
// in <data>/connect/connect.json (0600, atomic rewrite) and survive a restart.
const (
	connectReqTTL      = 30 * time.Minute
	connectCodeTTL     = 5 * time.Minute
	connectMaxAttempts = 5
	connectMaxPending  = 50
	connectIPWindow    = time.Minute
	connectIPPerWindow = 20 // exchange / revoke calls per client IP per minute
	connectAPIVersion  = 1
)

var (
	reState     = regexp.MustCompile(`^[A-Za-z0-9_-]{22,128}$`)
	reChallenge = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	reVerifier  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	reProvider  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,47}$`)
	reAppID     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,154}$`)
	rePrefix    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	rePin       = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ConnectProvider is an entry of RedX's own registry. Display names come from here, never from the link.
type ConnectProvider struct {
	ID        string
	Display   string
	Callbacks []string // exact-match allow-list
	// LoopbackCallbackPath: the app receives the callback on its own loopback HTTP service on a port chosen at
	// start (RFC 8252 section 7.3): http://127.0.0.1:<port><path>, http://[::1]:<port><path> or
	// http://localhost:<port><path>, with exactly this path. Empty: the default path /redx-callback.
	LoopbackCallbackPath string
	Workspace            string // default workspace (database)
	PerApp               bool   // rottenapple-launcher: one workspace per installed app, name derived from the app id
	SingleKey            bool   // rottenapple: one active key per workspace unless the admin replaces it
	Wording              string // consent text
}

var connectProviders = map[string]ConnectProvider{
	"rottenapple": {ID: "rottenapple", Display: "Rotten Apple Store", Callbacks: []string{"rottenapple://redx-callback"}, Workspace: "ra", SingleKey: true,
		Wording: "Let Rotten Apple Store use this RedX host as its database? It will be able to use everything in the workspace it gets, and nothing else. It cannot see other databases or manage keys."},
	"rottenapple-launcher": {ID: "rottenapple-launcher", Display: "Rotten Apple launcher", Callbacks: []string{"rottenapple://redx-callback"}, PerApp: true,
		Wording: "Give one installed app its own workspace on this RedX host. The launcher keeps the key; the app never sees it. The app cannot see other databases or manage keys."},
	"gendragoon": {ID: "gendragoon", Display: "Gendragoon", Callbacks: []string{"gendragoon://redx-callback"}, Workspace: "gendragoon",
		Wording: "Let Gendragoon keep data in its own workspace on this RedX host. It cannot see other databases or manage keys."},
	"quicklaunch": {ID: "quicklaunch", Display: "QuickLaunch (developer tool)", Workspace: "quicklaunch",
		LoopbackCallbackPath: "/redx-callback",
		Wording:              "Let QuickLaunch, the developer tool on this computer, keep its project data in its own workspace on this RedX host. It cannot see other databases or manage keys."},
}

// AppWorkspaceName is Rotten Apple's per-app workspace name (connect.WorkspaceName): "ra-" + the app id in
// lower case with dots as dashes, cut to 40 characters, + "-" + 8 hex of sha256(app id).
func AppWorkspaceName(appID string) string {
	base := strings.ReplaceAll(strings.ToLower(appID), ".", "-")
	if len(base) > 40 {
		base = base[:40]
	}
	s := sha256.Sum256([]byte(appID))
	return "ra-" + base + "-" + hex.EncodeToString(s[:])[:8]
}

type connectReq struct {
	IDHash     string    `json:"id_hash"`
	Ref        string    `json:"ref"` // short public handle for lists (first 12 hex of the id hash)
	Provider   string    `json:"provider"`
	App        string    `json:"app,omitempty"`
	Name       string    `json:"name,omitempty"` // requester-supplied label, shown as such (not trusted)
	StateHash  string    `json:"state_hash"`
	Challenge  string    `json:"pkce_challenge"` // public by design
	Callback   string    `json:"callback,omitempty"`
	CallbackOK bool      `json:"callback_ok"`
	Host       string    `json:"host,omitempty"`
	Pin        string    `json:"pin,omitempty"`
	Workspace  string    `json:"workspace"`
	Scope      string    `json:"scope"`
	Prefix     string    `json:"prefix,omitempty"`
	Label      string    `json:"label,omitempty"`
	Status     string    `json:"status"` // pending | approved | exchanged | denied | expired | superseded
	Created    time.Time `json:"created"`
	Expires    time.Time `json:"expires"`
	CodeHash   string    `json:"code_hash,omitempty"`
	CodeExp    time.Time `json:"code_expires,omitempty"`
	Attempts   int       `json:"attempts"`
	Replace    bool      `json:"replace,omitempty"`
	ApprovedBy string    `json:"approved_by,omitempty"`
	KeyID      string    `json:"key_id,omitempty"`
}

// Connection is a connected app (a key minted by the exchange).
type Connection struct {
	ID        string     `json:"id"`
	Provider  string     `json:"provider"`
	Display   string     `json:"display"`
	Verified  bool       `json:"verified"`
	App       string     `json:"app,omitempty"`
	Device    string     `json:"device,omitempty"`
	DB        string     `json:"workspace"`
	KeyID     string     `json:"key_id"`
	Scope     string     `json:"scope"`
	Prefix    string     `json:"prefix,omitempty"`
	Storage   string     `json:"storage"`
	Created   time.Time  `json:"created"`
	Revoked   *time.Time `json:"revoked,omitempty"`
	RevokedBy string     `json:"revoked_by,omitempty"` // "app" or the admin key id
}

type connectFile struct {
	V           int               `json:"v"`
	Requests    []*connectReq     `json:"requests"`
	Connections []*Connection     `json:"connections"`
	Workspaces  map[string]string `json:"workspaces"`  // db -> owner ("provider/app") for workspaces this flow created
	UsedGrants  map[string]string `json:"used_grants"` // sha256(provider_grant) -> time used (one-time)
}

type connectStore struct {
	mu   sync.Mutex
	dir  string
	f    connectFile
	key  []byte // HMAC key that derives request ids (so the same (provider, app, state) gets the same id)
	now  func() time.Time
	hits map[string][]time.Time
	err  error
}

func (s *connectStore) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func openConnectStore(dataDir string) *connectStore {
	s := &connectStore{dir: filepath.Join(dataDir, "connect"), hits: map[string][]time.Time{}}
	s.f.Workspaces, s.f.UsedGrants = map[string]string{}, map[string]string{}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		s.err = err
		return s
	}
	kp := filepath.Join(s.dir, "id.key")
	if b, err := os.ReadFile(kp); err == nil && len(b) == 32 {
		s.key = b
	} else {
		s.key = make([]byte, 32)
		_, _ = rand.Read(s.key)
		if err := atomicWrite(kp, s.key); err != nil {
			s.err = err
		}
		_ = os.Chmod(kp, 0o600)
	}
	if b, err := os.ReadFile(filepath.Join(s.dir, "connect.json")); err == nil {
		if err := json.Unmarshal(b, &s.f); err != nil {
			s.err = fmt.Errorf("connect.json: %w", err)
		}
	}
	if s.f.Workspaces == nil {
		s.f.Workspaces = map[string]string{}
	}
	if s.f.UsedGrants == nil {
		s.f.UsedGrants = map[string]string{}
	}
	return s
}

func (s *connectStore) saveLocked() error {
	s.f.V = 1
	b, _ := json.MarshalIndent(&s.f, "", "  ")
	p := filepath.Join(s.dir, "connect.json")
	if err := atomicWrite(p, b); err != nil {
		return err
	}
	return os.Chmod(p, 0o600)
}

func sha(s string) string { x := sha256.Sum256([]byte(s)); return hex.EncodeToString(x[:]) }

func (s *connectStore) requestID(provider, app, state string) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(provider + "\x00" + app + "\x00" + state))
	return "rq_" + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// expireLocked moves timed-out requests to "expired" and forgets old final ones (kept 24 h for "code_used").
func (s *connectStore) expireLocked(now time.Time) bool {
	changed := false
	keep := s.f.Requests[:0]
	for _, r := range s.f.Requests {
		if (r.Status == "pending" || r.Status == "approved") && !now.Before(r.Expires) {
			r.Status, changed = "expired", true
		}
		if r.Status != "pending" && r.Status != "approved" && now.Sub(r.Expires) > 24*time.Hour {
			changed = true
			continue
		}
		keep = append(keep, r)
	}
	s.f.Requests = keep
	for g, at := range s.f.UsedGrants {
		if t, err := time.Parse(time.RFC3339, at); err == nil && now.Sub(t) > 7*24*time.Hour {
			delete(s.f.UsedGrants, g)
			changed = true
		}
	}
	return changed
}

func (s *connectStore) byID(id string) *connectReq {
	hs := sha(id)
	for _, r := range s.f.Requests {
		if subtle.ConstantTimeCompare([]byte(r.IDHash), []byte(hs)) == 1 {
			return r
		}
	}
	return nil
}

// limit is a sliding-window counter per client IP for the unauthenticated endpoints.
func (s *connectStore) limit(ip string, now time.Time) (bool, int) {
	cut := now.Add(-connectIPWindow)
	l := s.hits[ip]
	i := 0
	for i < len(l) && l[i].Before(cut) {
		i++
	}
	l = l[i:]
	if len(l) >= connectIPPerWindow {
		s.hits[ip] = l
		return false, int(l[0].Add(connectIPWindow).Sub(now)/time.Second) + 1
	}
	s.hits[ip] = append(l, now)
	if len(s.hits) > 10000 { // bound memory under a flood of addresses
		for k := range s.hits {
			delete(s.hits, k)
			break
		}
	}
	return true, 0
}

// ---- HTTP ----

func connectErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": msg, "code": code})
}

// sameOriginOK refuses requests a browser made on behalf of another site (CSRF). The console sends the
// admin key in a header (no cookies), so a foreign page cannot authenticate anyway; this is a second wall.
func sameOriginOK(r *http.Request) bool {
	if sf := r.Header.Get("Sec-Fetch-Site"); sf != "" && sf != "same-origin" && sf != "none" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || u.Host != r.Host {
			return false
		}
	}
	if r.Method == "POST" && !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		return false // forms and text/plain "simple requests" cannot reach a state change
	}
	return true
}

func isLoopbackRemote(r *http.Request) bool {
	ip := net.ParseIP(remoteIP(r))
	return ip != nil && ip.IsLoopback()
}

func (h *Host) connectRoute(w http.ResponseWriter, r *http.Request) {
	sub := strings.TrimPrefix(r.URL.Path, "/v1/connect/")
	if h.connect == nil || h.connect.err != nil {
		connectErr(w, 503, "unavailable", "the connect store could not be opened; see the redxd log")
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		if h.maybeForward(w, r) { // followers forward to the leader, like /v1/keys
			return
		}
	} else if !h.Cluster.IsLeader() {
		connectErr(w, 503, "not_leader", "connect requests live on the leader ("+h.Cluster.LeaderURL()+"); open the console there")
		return
	}
	switch {
	case sub == "exchange" && r.Method == "POST":
		h.connectExchange(w, r)
		return
	case sub == "revoke" && r.Method == "POST":
		h.connectSelfRevoke(w, r)
		return
	case sub == "claim":
		connectErr(w, 501, "not_built", "invites (/v1/connect/claim) are not built in this RedX version; start the connection from the app")
		return
	}
	pr, ok := h.authz(w, r, ScopeAdmin, AllDBs, "", true)
	if !ok {
		return
	}
	if r.Method != "GET" && !sameOriginOK(r) {
		h.Audit.Log(AuditEvent{Event: "connect.fail", KeyID: pr.Key.ID, Remote: remoteIP(r), Reason: "cross-site request refused"})
		connectErr(w, 403, "csrf", "cross-site request refused")
		return
	}
	switch {
	case sub == "start" && r.Method == "POST":
		h.connectStart(w, r, pr)
	case sub == "pending" && r.Method == "GET":
		h.connectPending(w)
	case sub == "approve" && r.Method == "POST":
		h.connectApprove(w, r, pr)
	case sub == "deny" && r.Method == "POST":
		h.connectDeny(w, r, pr)
	case sub == "apps" && r.Method == "GET":
		h.connectApps(w)
	case strings.HasPrefix(sub, "apps/") && r.Method == "DELETE":
		h.connectAdminRevoke(w, r, pr, strings.TrimPrefix(sub, "apps/"))
	default:
		connectErr(w, 404, "invalid_request", "unknown connect endpoint or method")
	}
}

type connectStartIn struct {
	V             int    `json:"v"`
	Provider      string `json:"provider"`
	App           string `json:"app"`
	Workspace     string `json:"workspace"`
	Scope         string `json:"scope"`
	Prefix        string `json:"prefix"`
	Label         string `json:"label"`
	Engines       string `json:"engines"`
	State         string `json:"state"`
	PKCEChallenge string `json:"pkce_challenge"`
	Method        string `json:"pkce_method"`
	Callback      string `json:"callback"`
	Host          string `json:"host"`
	Pin           string `json:"pin"`
	Name          string `json:"name"`
}

func providerInfo(id string) (ConnectProvider, bool) {
	p, ok := connectProviders[id]
	if !ok {
		return ConnectProvider{ID: id, Display: "Unverified app (" + id + ")"}, false
	}
	return p, true
}

func callbackOK(p ConnectProvider, verified bool, cb string) bool {
	if cb == "" {
		return false
	}
	for _, c := range p.Callbacks {
		if cb == c {
			return true
		}
	}
	path := p.LoopbackCallbackPath
	if path == "" {
		path = "/redx-callback"
	}
	return LoopbackCallbackOK(cb, path) // RFC 8252 loopback redirect, any port, fixed path
}

// LoopbackCallbackOK reports whether cb is a loopback redirect URI with exactly the given path:
// http://127.0.0.1:<port><path>, http://[::1]:<port><path> or http://localhost:<port><path>.
// Refused: other schemes (also https), user info, any other host (no DNS lookups are made, so a name that
// resolves to loopback elsewhere is refused too), a missing, zero-padded or out-of-range port, a query or
// fragment, percent-encoding, and any path other than the registered one.
func LoopbackCallbackOK(cb, path string) bool {
	if len(cb) > 200 || strings.ContainsAny(cb, "%\\ \x00\r\n\t#?@") {
		return false
	}
	var rest string
	switch {
	case strings.HasPrefix(cb, "http://127.0.0.1:"):
		rest = strings.TrimPrefix(cb, "http://127.0.0.1:")
	case strings.HasPrefix(cb, "http://[::1]:"):
		rest = strings.TrimPrefix(cb, "http://[::1]:")
	case strings.HasPrefix(cb, "http://localhost:"):
		rest = strings.TrimPrefix(cb, "http://localhost:")
	default:
		return false
	}
	i := strings.IndexByte(rest, '/')
	if i < 1 || i > 5 {
		return false
	}
	port, pth := rest[:i], rest[i:]
	if port[0] == '0' {
		return false
	}
	n := 0
	for _, ch := range port {
		if ch < '0' || ch > '9' {
			return false
		}
		n = n*10 + int(ch-'0')
	}
	if n < 1 || n > 65535 || pth != path {
		return false
	}
	// cross-check with the standard parser: it must agree on scheme, host, port and path
	u, err := url.Parse(cb)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Port() != port || u.Path != path || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	switch u.Hostname() {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

func (h *Host) connectStart(w http.ResponseWriter, r *http.Request, pr *Principal) {
	var in connectStartIn
	b := readBody(r)
	if len(b) > 4096 || json.Unmarshal(b, &in) != nil {
		connectErr(w, 400, "invalid_request", "body must be a JSON object of at most 4 KiB")
		return
	}
	switch {
	case in.V == 0 || in.V < connectAPIVersion:
		connectErr(w, 400, "client_too_old", "this RedX speaks connect v1; update the app")
		return
	case in.V > connectAPIVersion:
		connectErr(w, 400, "invalid_request", "this RedX speaks connect v1 only; update RedX")
		return
	case !reProvider.MatchString(in.Provider):
		connectErr(w, 400, "unknown_provider", "provider must be a short lower-case id")
		return
	case !reState.MatchString(in.State):
		connectErr(w, 400, "invalid_request", "state must be 22-128 characters of [A-Za-z0-9_-] (at least 128 random bits)")
		return
	case in.Method != "" && in.Method != "S256":
		connectErr(w, 400, "invalid_request", "only the S256 PKCE method is accepted")
		return
	case !reChallenge.MatchString(in.PKCEChallenge):
		connectErr(w, 400, "invalid_request", "pkce_challenge must be base64url(SHA-256(verifier)) without padding")
		return
	case in.Pin != "" && !rePin.MatchString(in.Pin):
		connectErr(w, 400, "invalid_request", "pin must be 64 lower-case hex characters")
		return
	case len(in.Name) > 80 || strings.ContainsAny(in.Name+in.Label+in.Host+in.Callback, "\x00\r\n\t"):
		connectErr(w, 400, "invalid_request", "a parameter is too long or contains control characters")
		return
	}
	if in.Host != "" {
		if u, err := url.Parse(in.Host); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || (u.Path != "" && u.Path != "/") {
			connectErr(w, 400, "invalid_request", "host must be an http(s) origin")
			return
		}
	}
	p, verified := providerInfo(in.Provider)
	ws, scope, prefix := in.Workspace, in.Scope, in.Prefix
	if scope == "" {
		scope = ScopeWrite
	}
	if scope != ScopeRead && scope != ScopeWrite {
		connectErr(w, 400, "invalid_request", "an app may ask for read or write only")
		return
	}
	if prefix != "" && !rePrefix.MatchString(prefix) {
		connectErr(w, 400, "invalid_request", "prefix must be a short lower-case name like saves")
		return
	}
	if p.PerApp {
		if !reAppID.MatchString(in.App) {
			connectErr(w, 400, "invalid_request", "app must be the app id")
			return
		}
		want := AppWorkspaceName(in.App)
		if ws != "" && ws != want {
			connectErr(w, 400, "invalid_request", "an app's workspace is "+want)
			return
		}
		ws = want
	} else if in.App != "" {
		connectErr(w, 400, "invalid_request", "app is only for the rottenapple-launcher provider")
		return
	}
	if ws == "" {
		ws = p.Workspace
	}
	if ws == "" {
		ws = in.Provider
	}
	if !ValidDBName(ws) || h.IsMasterDB(ws) {
		connectErr(w, 400, "invalid_request", "workspace must match ^[a-z0-9][a-z0-9_-]{0,62}$")
		return
	}
	label := in.Label
	if label == "" {
		label = "app:" + in.Provider
		if in.App != "" {
			label = "app:" + in.App
		}
	}
	if len(label) > 96 {
		label = label[:96]
	}
	cbOK := callbackOK(p, verified, in.Callback)
	s := h.connect
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	s.expireLocked(now)
	id := s.requestID(in.Provider, in.App, in.State)
	if q := s.byID(id); q != nil { // the same link fired again (after an install, a reload): same request
		if q.Status != "pending" && q.Status != "approved" {
			connectErr(w, 410, statusCode(q.Status), "this request is "+q.Status+"; start again from the app")
			return
		}
		writeJSON(w, 200, h.startOut(id, q, p, verified))
		return
	}
	open := 0
	for _, q := range s.f.Requests {
		if q.Status == "pending" || q.Status == "approved" {
			open++
			if q.Provider == in.Provider && q.App == in.App {
				q.Status = "superseded" // a newer request for the same app replaces the older one
			}
		}
	}
	if open >= connectMaxPending {
		connectErr(w, 429, "too_many_attempts", "too many open connect requests; deny some or wait")
		return
	}
	hs := sha(id)
	q := &connectReq{IDHash: hs, Ref: hs[:12], Provider: in.Provider, App: in.App, Name: in.Name, StateHash: sha(in.State), Challenge: in.PKCEChallenge,
		Callback: in.Callback, CallbackOK: cbOK, Host: strings.TrimRight(in.Host, "/"), Pin: in.Pin, Workspace: ws, Scope: scope, Prefix: prefix, Label: label,
		Status: "pending", Created: now.UTC().Truncate(time.Second), Expires: now.Add(connectReqTTL).UTC().Truncate(time.Second)}
	s.f.Requests = append(s.f.Requests, q)
	if err := s.saveLocked(); err != nil {
		connectErr(w, 500, "internal", "cannot store the request: "+err.Error())
		return
	}
	h.Audit.Log(AuditEvent{Event: "connect.start", KeyID: pr.Key.ID, DB: ws, Remote: remoteIP(r), Detail: "provider " + in.Provider + appSuffix(in.App)})
	writeJSON(w, 201, h.startOut(id, q, p, verified))
}

func appSuffix(app string) string {
	if app == "" {
		return ""
	}
	return " app " + app
}

func statusCode(st string) string {
	switch st {
	case "exchanged":
		return "code_used"
	case "denied":
		return "denied"
	case "superseded":
		return "superseded"
	}
	return "expired"
}

func scopeWords(scope string) []string {
	if scope == ScopeRead {
		return []string{"look at data in this workspace only"}
	}
	return []string{"read and change data in this workspace only"}
}

func (h *Host) startOut(id string, q *connectReq, p ConnectProvider, verified bool) map[string]interface{} {
	exists := h.Reg.Exists(q.Workspace)
	owner := h.connect.f.Workspaces[q.Workspace]
	return map[string]interface{}{
		"api": "v1", "request_id": id, "ref": q.Ref, "status": q.Status, "expires_at": q.Expires.Format(time.RFC3339),
		"provider": map[string]interface{}{"id": q.Provider, "display": p.Display, "verified": verified, "callback_ok": q.CallbackOK, "wording": p.Wording},
		"app":      q.App, "name": q.Name, "host": q.Host,
		"defaults": map[string]interface{}{"workspace": q.Workspace, "scope": q.Scope, "prefix": q.Prefix, "storage": "local", "workspace_fixed": p.PerApp},
		"workspace": map[string]interface{}{"exists": exists, "owned_by_this_app": owner == q.Provider+"/"+q.App,
			"other_owner": exists && owner != q.Provider+"/"+q.App},
		"can":        scopeWords(q.Scope),
		"cannot":     []string{"see your other databases", "create or delete databases", "manage keys"},
		"single_key": p.SingleKey, "active_key": h.activeConn(q.Provider, q.App, q.Workspace) != nil,
	}
}

func (h *Host) activeConn(provider, app, db string) *Connection {
	for _, c := range h.connect.f.Connections {
		if c.Revoked == nil && c.Provider == provider && c.App == app && c.DB == db {
			if _, ok := h.KS.Get(c.KeyID); ok {
				return c
			}
		}
	}
	return nil
}

func (h *Host) connectPending(w http.ResponseWriter) {
	s := h.connect
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expireLocked(s.clock()) {
		_ = s.saveLocked()
	}
	out := []map[string]interface{}{}
	for _, q := range s.f.Requests {
		if q.Status != "pending" && q.Status != "approved" {
			continue
		}
		p, verified := providerInfo(q.Provider)
		out = append(out, map[string]interface{}{"ref": q.Ref, "provider": q.Provider, "display": p.Display, "verified": verified, "app": q.App, "name": q.Name,
			"workspace": q.Workspace, "scope": q.Scope, "prefix": q.Prefix, "status": q.Status, "expires_at": q.Expires.Format(time.RFC3339)})
	}
	writeJSON(w, 200, map[string]interface{}{"requests": out})
}

type connectApproveIn struct {
	RequestID string `json:"request_id"`
	Workspace string `json:"workspace"`
	Scope     string `json:"scope"`
	Confirm   string `json:"confirm"` // unverified providers: the admin types the provider id
	Replace   bool   `json:"replace"`
	Storage   struct {
		Mode string `json:"mode"`
	} `json:"storage"`
}

func (h *Host) connectApprove(w http.ResponseWriter, r *http.Request, pr *Principal) {
	var in connectApproveIn
	if json.Unmarshal(readBody(r), &in) != nil || in.RequestID == "" {
		connectErr(w, 400, "invalid_request", `body must be {"request_id": "rq_..."}`)
		return
	}
	s := h.connect
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	if s.expireLocked(now) {
		_ = s.saveLocked()
	}
	q := s.byID(in.RequestID)
	if q == nil {
		connectErr(w, 404, "invalid_request", "no such request (it must be started by the console first)")
		return
	}
	if q.Status != "pending" && q.Status != "approved" {
		connectErr(w, 410, statusCode(q.Status), "this request is "+q.Status)
		return
	}
	p, verified := providerInfo(q.Provider)
	if !verified && in.Confirm != q.Provider {
		connectErr(w, 400, "unknown_provider", "this app is not in RedX's list of known apps; type its id ("+q.Provider+") to confirm")
		return
	}
	ws := q.Workspace
	if in.Workspace != "" && in.Workspace != ws {
		if p.PerApp {
			connectErr(w, 400, "invalid_request", "an app's workspace name is fixed")
			return
		}
		if !ValidDBName(in.Workspace) || h.IsMasterDB(in.Workspace) {
			connectErr(w, 400, "invalid_request", "workspace must match ^[a-z0-9][a-z0-9_-]{0,62}$")
			return
		}
		ws = in.Workspace
	}
	scope := q.Scope
	if in.Scope != "" {
		if in.Scope != ScopeRead && in.Scope != ScopeWrite {
			connectErr(w, 400, "invalid_request", "scope must be read or write")
			return
		}
		if in.Scope == ScopeWrite && q.Scope == ScopeRead {
			connectErr(w, 400, "invalid_request", "the app asked for read only")
			return
		}
		scope = in.Scope
	}
	owner := q.Provider + "/" + q.App
	if h.Reg.Exists(ws) && s.f.Workspaces[ws] != owner {
		connectErr(w, 409, "workspace_exists_other_owner", "a database named "+ws+" already exists and was not made for this app; pick another name")
		return
	}
	if p.SingleKey && !in.Replace && h.activeConn(q.Provider, q.App, ws) != nil {
		connectErr(w, 409, "key_exists", p.Display+" already has an active key for "+ws+"; choose Replace to revoke it when the new one is issued")
		return
	}
	if !h.Reg.Exists(ws) {
		if _, err := h.WriteCreateDB(ws); err != nil && !errors.Is(err, ErrDBExists) {
			connectErr(w, 500, "internal", "cannot create the workspace: "+err.Error())
			return
		}
		h.Audit.Log(AuditEvent{Event: "db.create", KeyID: pr.Key.ID, DB: ws, Remote: remoteIP(r), Detail: "connect workspace for " + owner})
	}
	s.f.Workspaces[ws] = owner
	code := newPairCode()
	q.Workspace, q.Scope, q.Status, q.Replace, q.ApprovedBy = ws, scope, "approved", in.Replace, pr.Key.ID
	q.CodeHash, q.CodeExp, q.Attempts = sha(code), now.Add(connectCodeTTL).UTC().Truncate(time.Second), 0
	if err := s.saveLocked(); err != nil {
		connectErr(w, 500, "internal", "cannot store the approval: "+err.Error())
		return
	}
	h.Audit.Log(AuditEvent{Event: "connect.approve", KeyID: pr.Key.ID, DB: ws, Remote: remoteIP(r), Detail: "provider " + q.Provider + appSuffix(q.App) + " scope " + scope})
	base := q.Host
	if base == "" {
		base = h.publicBase(r)
	}
	pin := h.servedPin()
	out := map[string]interface{}{"api": "v1", "code": code, "expires_at": q.CodeExp.Format(time.RFC3339), "workspace": ws, "scope": scope, "prefix": q.Prefix,
		"host": base, "pin": pin, "paste": base + " " + code, "deliver": "paste"}
	if q.CallbackOK {
		v := url.Values{}
		v.Set("code", code)
		out["deliver"] = "callback"
		// state is not stored in plain text: the console appends the state it holds (from the link). Order
		// matches Rotten Apple's parser: code, state, host, pin.
		cb := q.Callback + "?code=" + url.QueryEscape(code) + "&state={state}&host=" + url.QueryEscape(base)
		if pin != "" {
			cb += "&pin=" + pin
		}
		out["callback_template"] = cb
	}
	writeJSON(w, 200, out)
}

// publicBase is the origin the console is using for this host (what a requester on the same network uses).
func (h *Host) publicBase(r *http.Request) string {
	if a := strings.TrimRight(h.Cfg.Advertise, "/"); a != "" {
		return a
	}
	sch := "http"
	if r.TLS != nil {
		sch = "https"
	}
	return sch + "://" + r.Host
}

func (h *Host) servedPin() string {
	h.runMu.Lock()
	defer h.runMu.Unlock()
	return h.tlsFP
}

func (h *Host) connectDeny(w http.ResponseWriter, r *http.Request, pr *Principal) {
	var in struct {
		RequestID string `json:"request_id"`
		Ref       string `json:"ref"`
	}
	_ = json.Unmarshal(readBody(r), &in)
	s := h.connect
	s.mu.Lock()
	defer s.mu.Unlock()
	var q *connectReq
	if in.RequestID != "" {
		q = s.byID(in.RequestID)
	} else if len(in.Ref) == 12 {
		for _, x := range s.f.Requests {
			if x.Ref == in.Ref {
				q = x
			}
		}
	}
	if q == nil {
		connectErr(w, 404, "invalid_request", "no such request")
		return
	}
	if q.Status == "pending" || q.Status == "approved" {
		q.Status = "denied"
		_ = s.saveLocked()
	}
	h.Audit.Log(AuditEvent{Event: "connect.deny", KeyID: pr.Key.ID, DB: q.Workspace, Remote: remoteIP(r), Detail: "provider " + q.Provider + appSuffix(q.App)})
	writeJSON(w, 200, map[string]interface{}{"status": q.Status})
}

type connectExchangeIn struct {
	Code          string `json:"code"`
	PKCEVerifier  string `json:"pkce_verifier"`
	State         string `json:"state"`
	DeviceLabel   string `json:"device_label"`
	ProviderGrant string `json:"provider_grant"`
}

func (h *Host) connectExchange(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	s := h.connect
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	if ok, wait := s.limit(ip, now); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		h.Audit.Log(AuditEvent{Event: "connect.fail", Remote: ip, Reason: "rate limited"})
		connectErr(w, 429, "rate_limited", "too many connect attempts from this address; wait a minute")
		return
	}
	if r.TLS == nil && !isLoopbackRemote(r) {
		connectErr(w, 400, "insecure_transport", "the exchange returns a key: use https (or this computer's loopback address)")
		return
	}
	var in connectExchangeIn
	b := readBody(r)
	if len(b) > 4096 || json.Unmarshal(b, &in) != nil {
		connectErr(w, 400, "invalid_request", "body must be a JSON object")
		return
	}
	if s.expireLocked(now) {
		_ = s.saveLocked()
	}
	code := strings.ToUpper(strings.TrimSpace(in.Code))
	ch := sha(code)
	var q *connectReq
	for _, x := range s.f.Requests {
		if x.CodeHash != "" && subtle.ConstantTimeCompare([]byte(x.CodeHash), []byte(ch)) == 1 {
			q = x
		}
	}
	fail := func(status int, c, msg string) {
		h.authBad.Add(1)
		h.Audit.Log(AuditEvent{Event: "connect.fail", Remote: ip, Reason: c})
		connectErr(w, status, c, msg)
	}
	if q == nil {
		fail(400, "invalid_request", "unknown pairing code")
		return
	}
	switch q.Status {
	case "exchanged":
		fail(409, "code_used", "this code was already used; no second key is issued")
		return
	case "denied":
		fail(403, "denied", "the request was denied")
		return
	case "superseded":
		fail(409, "superseded", "a newer request for this app replaced this one")
		return
	case "expired":
		fail(410, "expired", "the request expired; start again from the app")
		return
	case "approved":
	default:
		fail(400, "invalid_request", "the request is not approved")
		return
	}
	if !now.Before(q.CodeExp) {
		q.Status = "expired"
		_ = s.saveLocked()
		fail(410, "expired", "the code expired (codes live 5 minutes); approve again")
		return
	}
	bad := ""
	if !reState.MatchString(in.State) || subtle.ConstantTimeCompare([]byte(sha(in.State)), []byte(q.StateHash)) != 1 {
		bad = "state_mismatch"
	} else if !reVerifier.MatchString(in.PKCEVerifier) {
		bad = "pkce_mismatch"
	} else {
		d := sha256.Sum256([]byte(in.PKCEVerifier))
		if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(d[:])), []byte(q.Challenge)) != 1 {
			bad = "pkce_mismatch"
		}
	}
	if bad != "" {
		q.Attempts++
		if q.Attempts >= connectMaxAttempts {
			q.Status = "denied"
			_ = s.saveLocked()
			fail(429, "too_many_attempts", "too many wrong attempts; the request is closed")
			return
		}
		_ = s.saveLocked()
		fail(400, bad, map[string]string{"state_mismatch": "state does not match the request", "pkce_mismatch": "PKCE verifier does not match the challenge"}[bad])
		return
	}
	storage := map[string]string{"mode": "local", "provider": "", "status": "local"}
	if in.ProviderGrant != "" {
		if len(in.ProviderGrant) > 512 {
			fail(400, "invalid_request", "provider_grant too long")
			return
		}
		gh := sha(in.ProviderGrant)
		if _, used := s.f.UsedGrants[gh]; used {
			fail(409, "grant_used", "this provider_grant was already used")
			return
		}
		s.f.UsedGrants[gh] = now.UTC().Format(time.RFC3339)
		storage = map[string]string{"mode": "provider", "provider": q.Provider, "status": "pending-provider-grant"}
	}
	device := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, in.DeviceLabel)
	if len(device) > 32 {
		device = device[:32]
	}
	label := q.Label
	if device != "" {
		label += ":" + device
	}
	if len(label) > 128 {
		label = label[:128]
	}
	// Single use: the request is final BEFORE the key exists, so a concurrent or repeated exchange can never mint twice.
	q.Status = "exchanged" // the code hash stays so a replay answers code_used
	if err := s.saveLocked(); err != nil {
		connectErr(w, 500, "internal", "cannot record the exchange: "+err.Error())
		return
	}
	if q.Replace {
		if old := h.activeConn(q.Provider, q.App, q.Workspace); old != nil {
			_, _ = h.KS.Revoke(old.KeyID)
			t := now.UTC().Truncate(time.Second)
			old.Revoked, old.RevokedBy = &t, "replaced"
			h.Audit.Log(AuditEvent{Event: "connect.revoke", KeyID: old.KeyID, DB: old.DB, Remote: ip, Detail: "replaced by a new connection"})
		}
	}
	key, rec, err := h.KS.Create(CreateSpec{DB: q.Workspace, Scope: q.Scope, Prefix: q.Prefix, Label: label})
	if err != nil {
		connectErr(w, 500, "internal", "cannot create the key: "+err.Error())
		return
	}
	p, verified := providerInfo(q.Provider)
	c := &Connection{ID: "cn_" + randHex(8), Provider: q.Provider, Display: p.Display, Verified: verified, App: q.App, Device: device, DB: q.Workspace,
		KeyID: rec.ID, Scope: rec.Scope, Prefix: rec.Prefix, Storage: storage["status"], Created: now.UTC().Truncate(time.Second)}
	q.KeyID = rec.ID
	s.f.Connections = append(s.f.Connections, c)
	_ = s.saveLocked()
	h.Audit.Log(AuditEvent{Event: "connect.exchange", KeyID: rec.ID, DB: q.Workspace, Remote: ip, Detail: "connection " + c.ID + " provider " + q.Provider + appSuffix(q.App) + " scope " + rec.Scope})
	base := h.publicBase(r)
	if r.TLS != nil || q.Host == "" {
		sch := "http"
		if r.TLS != nil {
			sch = "https"
		}
		base = sch + "://" + r.Host
	} else {
		base = q.Host
	}
	wsb := "ws" + strings.TrimPrefix(base, "http")
	name := p.Display
	if q.App != "" {
		name = q.App
	}
	writeJSON(w, 200, map[string]interface{}{
		"api": "v1", "connection_id": c.ID,
		"workspace": map[string]string{"db": q.Workspace, "name": name},
		"key":       key, "key_id": rec.ID, "scope": rec.Scope, "prefix": rec.Prefix,
		"endpoints": map[string]string{"base": base, "path": "/v1/db/" + q.Workspace + "/path/", "bx": "/v1/db/" + q.Workspace + "/bx",
			"subscribe": wsb + "/v1/db/" + q.Workspace + "/subscribe", "revoke": "/v1/connect/revoke"},
		"host":    map[string]string{"node_id": h.NodeID, "version": Version, "tls_pin": h.servedPin()},
		"storage": storage,
		"warning": "this is the only time the key is shown",
	})
}

// connectSelfRevoke: POST /v1/connect/revoke with the app's own key. Rotten Apple's launcher calls it on uninstall.
func (h *Host) connectSelfRevoke(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	h.connect.mu.Lock()
	ok, wait := h.connect.limit(ip, h.connect.clock())
	h.connect.mu.Unlock()
	if !ok {
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		connectErr(w, 429, "rate_limited", "too many requests; wait a minute")
		return
	}
	pr, _, err := h.Auth.Authenticate(r)
	if err != nil {
		h.authBad.Add(1)
		connectErr(w, 401, "unauthorized", "unauthorized")
		return
	}
	s := h.connect
	s.mu.Lock()
	defer s.mu.Unlock()
	var c *Connection
	for _, x := range s.f.Connections {
		if x.KeyID == pr.Key.ID && x.Revoked == nil {
			c = x
		}
	}
	if c == nil {
		connectErr(w, 404, "not_connected", "this key was not issued by the connect flow; revoke it under API Keys")
		return
	}
	h.revokeConnLocked(c, "app")
	h.Audit.Log(AuditEvent{Event: "connect.revoke", KeyID: c.KeyID, DB: c.DB, Remote: ip, Detail: "connection " + c.ID + " revoked by the app"})
	writeJSON(w, 200, map[string]interface{}{"revoked": true, "connection_id": c.ID, "key_id": c.KeyID})
}

func (h *Host) revokeConnLocked(c *Connection, by string) {
	_, _ = h.KS.Revoke(c.KeyID)
	t := h.connect.clock().UTC().Truncate(time.Second)
	c.Revoked, c.RevokedBy = &t, by
	_ = h.connect.saveLocked()
}

func (h *Host) connectApps(w http.ResponseWriter) {
	s := h.connect
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Connection, 0, len(s.f.Connections))
	for _, c := range s.f.Connections {
		x := *c
		if x.Revoked == nil {
			if rec, ok := h.KS.Get(x.KeyID); !ok || rec.Revoked != nil {
				t := time.Time{}
				if ok && rec.Revoked != nil {
					t = *rec.Revoked
				}
				x.Revoked, x.RevokedBy = &t, "key revoked under API Keys"
			}
		}
		out = append(out, x)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	writeJSON(w, 200, map[string]interface{}{"apps": out})
}

func (h *Host) connectAdminRevoke(w http.ResponseWriter, r *http.Request, pr *Principal, id string) {
	s := h.connect
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.f.Connections {
		if c.ID == id {
			if c.Revoked == nil {
				h.revokeConnLocked(c, pr.Key.ID)
				h.Audit.Log(AuditEvent{Event: "connect.revoke", KeyID: pr.Key.ID, DB: c.DB, Remote: remoteIP(r), Detail: "connection " + c.ID + " key " + c.KeyID})
			}
			writeJSON(w, 200, map[string]interface{}{"revoked": true, "connection_id": c.ID, "key_id": c.KeyID})
			return
		}
	}
	connectErr(w, 404, "invalid_request", "no such connection")
}
