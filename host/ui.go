package host

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"redx/box"
	"redx/engine/query"
)

// The web console: plain ES modules, CSS and icons committed under host/ui and embedded in the
// binary. It needs no build step, no CDN and no network at run time. It talks to the same /v1 API
// as the CLI, with a bearer key kept in the browser (sessionStorage unless "remember this device").
//
//go:embed ui
var uiFS embed.FS

var (
	uiFiles = map[string]uiAsset{}
)

type uiAsset struct {
	data []byte
	etag string
	ctyp string
}

func init() {
	_ = fs.WalkDir(uiFS, "ui", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, _ := uiFS.ReadFile(p)
		sum := sha256.Sum256(b)
		uiFiles[strings.TrimPrefix(p, "ui/")] = uiAsset{data: b, etag: `"` + hex.EncodeToString(sum[:8]) + `"`, ctyp: uiContentType(p)}
		return nil
	})
}

func uiContentType(p string) string {
	switch strings.ToLower(path.Ext(p)) {
	case ".html":
		return "text/html; charset=utf-8"
	case ".js", ".mjs":
		return "text/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".png":
		return "image/png"
	case ".ico":
		return "image/x-icon"
	case ".json":
		return "application/json"
	case ".webmanifest":
		return "application/manifest+json"
	case ".md":
		return "text/markdown; charset=utf-8"
	case ".txt":
		return "text/plain; charset=utf-8"
	}
	return "application/octet-stream"
}

// UIAssetNames lists the embedded console files (used by tests and the smoke script).
func UIAssetNames() []string {
	var out []string
	for k := range uiFiles {
		out = append(out, k)
	}
	return out
}

// UIAsset returns an embedded console file.
func UIAsset(name string) ([]byte, bool) {
	a, ok := uiFiles[name]
	return a.data, ok
}

// uiCSP forbids inline script and inline style attributes and any off-site connection.
const uiCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; " +
	"connect-src 'self'; manifest-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'none'; " +
	"form-action 'self'; frame-ancestors 'none'"

// billingCSP is uiCSP plus exactly what Stripe's Payment Element needs, for /ui/billing.html only.
const billingCSP = "default-src 'none'; script-src 'self' https://js.stripe.com https://*.js.stripe.com; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data: blob: https://*.stripe.com; font-src 'self'; connect-src 'self' https://api.stripe.com https://merchant-ui-api.stripe.com https://errors.stripe.com; " +
	"frame-src https://js.stripe.com https://*.js.stripe.com https://*.stripe.com https://hooks.stripe.com; manifest-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'none'; " +
	"form-action 'self'; frame-ancestors 'none'"

// isUIPath reports whether a request path is served by the console.
func isUIPath(p string) bool {
	switch p {
	case "/", "/ui", "/ui/", "/favicon.ico", "/manifest.webmanifest", "/sw.js", "/apple-touch-icon.png":
		return true
	}
	return strings.HasPrefix(p, "/ui/")
}

func (h *Host) serveUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" {
		w.Header().Set("Allow", "GET, HEAD")
		writeErr(w, 405, "method not allowed")
		return
	}
	p := r.URL.Path
	var name string
	switch p {
	case "/", "/ui/", "/ui":
		name = "index.html"
	case "/favicon.ico":
		name = "icons/favicon.ico"
	case "/manifest.webmanifest":
		name = "manifest.webmanifest"
	case "/sw.js":
		name = "sw.js"
	case "/apple-touch-icon.png":
		name = "icons/apple-touch-icon.png"
	default:
		name = strings.TrimPrefix(path.Clean(strings.TrimPrefix(p, "/ui/")), "/")
		if strings.Contains(name, "..") {
			writeErr(w, 404, "not found")
			return
		}
	}
	a, ok := uiFiles[name]
	if !ok {
		writeErr(w, 404, "not found")
		return
	}
	hd := w.Header()
	hd.Set("Content-Type", a.ctyp)
	hd.Set("Cache-Control", "no-cache") // revalidate with the ETag every time; the console is always current
	hd.Set("ETag", a.etag)
	if name == "billing.html" {
		hd.Set("Content-Security-Policy", billingCSP) // only the checkout page may load Stripe.js
	} else {
		hd.Set("Content-Security-Policy", uiCSP)
	}
	hd.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	if name == "sw.js" {
		hd.Set("Service-Worker-Allowed", "/")
	}
	if r.Header.Get("If-None-Match") == a.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(200)
	if r.Method != "HEAD" {
		_, _ = w.Write(a.data)
	}
}

// ---- first-run web setup ----

// ResolveBootstrap says how the first admin key is made for cfg: "web", "console" or "off".
func ResolveBootstrap(cfg Config) string {
	switch cfg.Bootstrap {
	case "off":
		return "off"
	case "web":
		return "web"
	case "auto":
		if IsLoopbackAddr(cfg.Listen) {
			return "web"
		}
		return "console"
	}
	return "console"
}

// WebSetupPending reports whether the browser may still create the first admin key.
func (h *Host) WebSetupPending() bool {
	return h.webSetup && h.Cluster.IsLeader() && h.KS.Count() == 0
}

func hostIsLoopbackName(hostport string) bool {
	hn := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		hn = h
	}
	hn = strings.Trim(hn, "[]")
	if hn == "localhost" {
		return true
	}
	ip := net.ParseIP(hn)
	return ip != nil && ip.IsLoopback()
}

// loopbackRequest is true only for a request that really came from this machine: loopback peer,
// a loopback Host name (defeats DNS rebinding), no proxy headers (a local reverse proxy would make
// remote clients look local), and a same-origin Origin when the browser sends one.
func loopbackRequest(r *http.Request) bool {
	ip := net.ParseIP(remoteIP(r))
	if ip == nil || !ip.IsLoopback() {
		return false
	}
	if !hostIsLoopbackName(r.Host) {
		return false
	}
	for _, hn := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "X-Real-Ip", "Via"} {
		if r.Header.Get(hn) != "" {
			return false
		}
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || u.Host != r.Host {
			return false
		}
	}
	if sf := r.Header.Get("Sec-Fetch-Site"); sf != "" && sf != "same-origin" && sf != "none" {
		return false
	}
	return true
}

func (h *Host) uiRoute(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/ui/bootstrap-status":
		if r.Method != "GET" {
			writeErr(w, 405, "method not allowed")
			return
		}
		// Only ever a bare boolean, and never true for a request that is not from this machine.
		writeJSON(w, 200, map[string]bool{"needsSetup": h.WebSetupPending() && loopbackRequest(r)})
	case "/v1/ui/bootstrap":
		h.webBootstrap(w, r)
	case "/v1/ui/validate":
		h.validateHandler(w, r)
	case "/v1/ui/whoami":
		h.whoami(w, r)
	default:
		writeErr(w, 404, "not found")
	}
}

func (h *Host) webBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeErr(w, 405, "method not allowed")
		return
	}
	// A non-local caller, or one arriving after setup, gets the same answer as an unknown route.
	if !h.WebSetupPending() || !loopbackRequest(r) {
		writeErr(w, 404, "not found")
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeErr(w, 415, "content type must be application/json")
		return
	}
	var req struct {
		Label string `json:"label"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&req)
	label := strings.TrimSpace(req.Label)
	if label == "" || len(label) > 64 {
		label = "web-admin"
	}
	h.bootMu.Lock()
	defer h.bootMu.Unlock()
	if !h.WebSetupPending() {
		writeErr(w, 404, "not found")
		return
	}
	key, rec, err := h.KS.Create(CreateSpec{DB: AllDBs, Scope: ScopeAdmin, Label: label})
	if err != nil {
		h.Logf("web bootstrap: %v", err)
		writeErr(w, 500, "internal error")
		return
	}
	h.webSetup = false
	h.Audit.Log(AuditEvent{Event: "bootstrap.web", KeyID: rec.ID, Remote: remoteIP(r), Detail: "first-run admin key created from the browser"})
	writeJSON(w, 201, map[string]interface{}{"key": key, "id": rec.ID, "warning": "this is the only time the key is shown; store it now"})
}

// validateHandler checks Box text without storing it, so the editor can show line:col errors.
//
//	POST /v1/ui/validate  {"kind": "value" | "document" | "boxql", "text": "..."}   any valid key
func (h *Host) validateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeErr(w, 405, "method not allowed")
		return
	}
	if _, wait, err := h.Auth.Authenticate(r); err != nil {
		if errors.Is(err, ErrThrottled) {
			_ = wait
			writeErr(w, 429, "rate limit exceeded")
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="redx"`)
		writeErr(w, 401, "unauthorized")
		return
	}
	var req struct {
		Kind string `json:"kind"`
		Text string `json:"text"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		writeErr(w, 400, `body must be {"kind": "value"|"document", "text": "..."}`)
		return
	}
	var err error
	switch req.Kind {
	case "document":
		_, err = box.ParseDocument(req.Text)
	case "boxql":
		_, _, err = query.Parse(req.Text)
	case "value", "":
		_, err = box.ParseValue(req.Text)
	default:
		writeErr(w, 400, `kind must be "value", "document" or "boxql"`)
		return
	}
	if err == nil {
		writeJSON(w, 200, map[string]interface{}{"ok": true})
		return
	}
	out := map[string]interface{}{"ok": false, "error": err.Error()}
	var be *box.Error
	var se *query.SyntaxError
	switch {
	case errors.As(err, &be):
		out["line"], out["col"], out["message"] = be.Line, be.Col, be.Msg
	case errors.As(err, &se):
		out["line"], out["col"], out["message"] = se.Pos.Line, se.Pos.Col, se.Msg
	}
	writeJSON(w, 200, out)
}

// whoami describes the calling key (never the key itself): the console uses it to decide which pages to offer.
//
//	GET /v1/ui/whoami   any valid key
func (h *Host) whoami(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeErr(w, 405, "method not allowed")
		return
	}
	pr, wait, err := h.Auth.Authenticate(r)
	if err != nil {
		if errors.Is(err, ErrThrottled) {
			w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
			writeErr(w, 429, "rate limit exceeded")
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="redx"`)
		writeErr(w, 401, "unauthorized")
		return
	}
	k := pr.Key
	out := map[string]interface{}{"id": k.ID, "label": k.Label, "scope": k.Scope, "db": k.DB, "prefix": k.Prefix, "roles": k.Roles,
		"host_admin": k.IsHostAdmin(), "role": roleName(h.Cluster), "version": Version, "owner": pr.IsOwner(),
		"accounts": h.AccountsEnabled(), "pages": h.consolePages(pr)}
	if pr.Account != nil {
		out["account"] = accountView(pr.Account)
	}
	writeJSON(w, 200, out)
}

// consolePages is the only list the console may use to show or open a page.
// It mirrors the server gates. owner is true only for IsOwner (verified email, 2FA, owner scope).
// Key.Owner is an account id and is never treated as the owner role.
func (h *Host) consolePages(pr *Principal) map[string]bool {
	hostAdmin := pr != nil && pr.Key.IsHostAdmin()
	owner := pr != nil && pr.IsOwner()
	adminScope := pr != nil && pr.Key.Scope == ScopeAdmin
	readScope := pr != nil && scopeRank[pr.Key.Scope] >= scopeRank[ScopeRead]
	mode, known := "none", false
	if pr != nil && pr.isTenant() {
		mode, known = h.tenantAccess(pr.Account.Sub)
	}
	keys := adminScope
	if pr != nil && pr.isTenant() && (known || mode != "none") {
		keys = true
	}
	watch := readScope || hostAdmin
	raw := adminScope
	if mode == "full" || mode == "readonly" {
		watch = true
	}
	if mode == "full" {
		raw = true
	}
	backups := hostAdmin && pr.SeesEverything()
	return map[string]bool{
		"dashboard": true,
		"databases": true,
		"data":      true,
		"studio":    true,
		"hosting":   true,
		"settings":  true,
		"help":      true,
		"keys":      keys,
		"devices":   hostAdmin,
		"apps":      hostAdmin,
		"backups":   backups,
		"watch":     watch,
		"raw":       raw,
		"policy":    raw,
		"cluster":   hostAdmin,
		"presets":   hostAdmin,
		"wizard":    hostAdmin,
		"connect":   hostAdmin,
		"updates":   hostAdmin || owner,
		"owner":     owner,
		"usage":     true,
		"logs":      true,
		"hostapps":  true,
		"deploy":    true,
		"domains":   true,
		"env":       true,
		"applogs":   true,
	}
}
