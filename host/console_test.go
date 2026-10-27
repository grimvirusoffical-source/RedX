package host_test

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"redx/host"
)

// ---- static console ----

func TestConsoleStaticServingAndHeaders(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	for _, p := range []string{"/", "/ui/", "/ui/js/main.js", "/ui/css/app.css", "/manifest.webmanifest", "/sw.js", "/favicon.ico", "/apple-touch-icon.png", "/ui/icons/redx-192.png", "/ui/icons/redx.svg"} {
		st, body, h := do(t, "GET", n.URL+p, "", "") // no key: the shell itself is public, the data is not
		if st != 200 || len(body) == 0 {
			t.Fatalf("GET %s = %d (%d bytes)", p, st, len(body))
		}
		csp := h.Get("Content-Security-Policy")
		for _, must := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'", "object-src 'none'", "connect-src 'self'"} {
			if !strings.Contains(csp, must) {
				t.Fatalf("%s: CSP lacks %q: %s", p, must, csp)
			}
		}
		for _, bad := range []string{"unsafe-inline", "unsafe-eval", "http://", "https://", "*"} {
			if strings.Contains(csp, bad) {
				t.Fatalf("%s: CSP must not contain %q: %s", p, bad, csp)
			}
		}
		if h.Get("X-Frame-Options") != "DENY" || h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: missing security headers: %v", p, h)
		}
		if h.Get("ETag") == "" || h.Get("Cache-Control") != "no-cache" {
			t.Fatalf("%s: caching headers: %v", p, h)
		}
	}
	st, body, h := do(t, "GET", n.URL+"/", "", "")
	if st != 200 || !strings.Contains(h.Get("Content-Type"), "text/html") || !strings.Contains(body, "<title>") {
		t.Fatalf("index: %d %v", st, h)
	}
	if _, _, h := do(t, "GET", n.URL+"/ui/js/main.js", "", ""); !strings.HasPrefix(h.Get("Content-Type"), "text/javascript") {
		t.Fatalf("js content type: %s", h.Get("Content-Type"))
	}
	if _, _, h := do(t, "GET", n.URL+"/manifest.webmanifest", "", ""); h.Get("Content-Type") != "application/manifest+json" {
		t.Fatalf("manifest content type: %s", h.Get("Content-Type"))
	}
	if _, _, h := do(t, "GET", n.URL+"/sw.js", "", ""); h.Get("Service-Worker-Allowed") != "/" {
		t.Fatal("sw.js must be allowed to control /")
	}
	// only the checkout page may load Stripe.js and frame Stripe's payment fields
	if _, _, h := do(t, "GET", n.URL+"/ui/billing.html", "", ""); !strings.Contains(h.Get("Content-Security-Policy"), "script-src 'self' https://js.stripe.com https://*.js.stripe.com;") ||
		!strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") || strings.Contains(h.Get("Content-Security-Policy"), "unsafe-eval") {
		t.Fatalf("billing.html CSP: %s", h.Get("Content-Security-Policy"))
	}
	if _, _, h := do(t, "GET", n.URL+"/ui/js/billing.js", "", ""); strings.Contains(h.Get("Content-Security-Policy"), "stripe") {
		t.Fatal("Stripe allowed outside the checkout page")
	}
	// conditional requests
	_, _, h = do(t, "GET", n.URL+"/ui/css/app.css", "", "")
	if st, b, _ := do(t, "GET", n.URL+"/ui/css/app.css", "", "", "If-None-Match", h.Get("ETag")); st != 304 || b != "" {
		t.Fatalf("ETag revalidation: %d %q", st, b)
	}
	// only GET/HEAD; unknown files and traversal are 404
	if st, _, _ := do(t, "POST", n.URL+"/", "", ""); st != 405 {
		t.Fatalf("POST / = %d", st)
	}
	for _, p := range []string{"/ui/nope.js", "/ui/../go.mod", "/ui/js/../../ui.go", "/ui/%2e%2e/ui.go"} {
		if st, _, _ := do(t, "GET", n.URL+p, "", ""); st != 404 && st != 301 && st != 400 {
			t.Fatalf("%s = %d", p, st)
		}
	}
	// the API is untouched and also carries the anti-framing headers
	if st, _, h := do(t, "GET", n.URL+"/healthz", "", ""); st != 200 || h.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("healthz: %d %v", st, h)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/dbs", "", ""); st != 401 {
		t.Fatalf("/v1/dbs without a key = %d", st)
	}
	if st, b, _ := do(t, "GET", n.URL+"/v1/dbs", n.Key, ""); st != 200 || !strings.Contains(b, "default") {
		t.Fatalf("/v1/dbs: %d %s", st, b)
	}
}

// Every file under host/ui must be embedded (go:embed silently skips names starting with "_" or "."),
// every module import must resolve, and the shell must stay free of inline code and off-site loads.
func TestConsoleAssetsComplete(t *testing.T) {
	embedded := map[string]bool{}
	for _, n := range host.UIAssetNames() {
		embedded[n] = true
	}
	onDisk := 0
	_ = filepath.WalkDir("ui", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		onDisk++
		rel := filepath.ToSlash(strings.TrimPrefix(p, "ui"+string(filepath.Separator)))
		if !embedded[rel] {
			t.Errorf("ui/%s is not embedded (names starting with _ or . are skipped by go:embed)", rel)
		}
		return nil
	})
	if onDisk < 30 {
		t.Fatalf("only %d console files found", onDisk)
	}
	imp := regexp.MustCompile(`(?:from\s*|import\s*\(\s*)'(\.{1,2}/[^']+\.js)'`)
	for name := range embedded {
		if !strings.HasSuffix(name, ".js") {
			continue
		}
		b, _ := host.UIAsset(name)
		for _, m := range imp.FindAllStringSubmatch(string(b), -1) {
			target := filepath.ToSlash(filepath.Join(filepath.Dir(name), m[1]))
			if !embedded[target] {
				t.Errorf("%s imports %s which is not served", name, m[1])
			}
		}
		if regexp.MustCompile(`\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function`).Match(b) {
			t.Errorf("%s uses innerHTML/eval: the console builds DOM nodes only", name)
		}
		src := string(b)
		if name == "js/checkout-engine.js" {
			// the checkout page (and only it, see billingCSP) loads Stripe.js
			src = strings.ReplaceAll(src, "https://js.stripe.com/", "")
		}
		// Customer console links to exactly these two existing first-party
		// product pages. No arbitrary off-origin scripts, APIs or redirects
		// may be introduced; the static URL audit still rejects other domains.
		// Do not add more destinations here without security review.
		src = strings.ReplaceAll(src, "https://red-xai.com/hosting", "")
		src = strings.ReplaceAll(src, "https://red-xai.com/store", "")
		if regexp.MustCompile(`https?://[a-z0-9.-]+\.[a-z]{2,}`).MatchString(strings.ReplaceAll(strings.ReplaceAll(src, "http://www.w3.org", ""), "https://127", "")) {
			if !strings.HasSuffix(name, "help.js") && !strings.HasSuffix(name, "devices.js") {
				// examples such as "https://leader:7777" have no TLD dot; a real public host would match here
				t.Errorf("%s mentions an off-site URL", name)
			}
		}
	}
	idx, _ := host.UIAsset("index.html")
	html := string(idx)
	inlineScript := false
	for _, tag := range regexp.MustCompile(`(?i)<script[^>]*>`).FindAllString(html, -1) {
		if !strings.Contains(tag, "src=") {
			inlineScript = true
		}
	}
	if inlineScript || regexp.MustCompile(`(?i)\sstyle=|\son[a-z]+=`).MatchString(html) {
		t.Fatal("index.html must not contain inline script, style attributes or event handlers")
	}
	if regexp.MustCompile(`(?i)(src|href)="https?://`).MatchString(html) {
		t.Fatal("index.html must not load anything from another origin")
	}
	for _, must := range []string{`rel="manifest"`, `apple-touch-icon`, `apple-mobile-web-app-capable`, `theme-color`} {
		if !strings.Contains(html, must) {
			t.Fatalf("index.html lacks %s", must)
		}
	}
	mf, _ := host.UIAsset("manifest.webmanifest")
	var m struct {
		Icons []struct{ Src, Sizes, Purpose string }
		Start string `json:"start_url"`
	}
	if err := json.Unmarshal(mf, &m); err != nil || len(m.Icons) < 4 {
		t.Fatalf("manifest: %v %+v", err, m)
	}
	for _, ic := range m.Icons {
		if !embedded[strings.TrimPrefix(ic.Src, "/ui/")] {
			t.Errorf("manifest icon %s is not served", ic.Src)
		}
	}
}

func TestConsoleDocsInSync(t *testing.T) {
	for _, f := range []string{"console", "boxql", "box-grammar", "hosting", "clustering", "connect"} {
		want, err := os.ReadFile(filepath.Join("..", "docs", f+".md"))
		if err != nil {
			t.Fatal(err)
		}
		got, ok := host.UIAsset("docs/" + f + ".md")
		if !ok || string(got) != string(want) {
			t.Errorf("docs/%s.md differs from the copy embedded in the console: run scripts/sync-ui-docs.sh", f)
		}
	}
}

// ---- first-run bootstrap ----

func webNode(t *testing.T, mod func(c *host.Config)) *node {
	return startNode(t, t.TempDir(), func(c *host.Config, _ string) {
		c.Bootstrap = "web"
		if mod != nil {
			mod(c)
		}
	})
}

func needsSetup(t *testing.T, n *node, hdr ...string) bool {
	t.Helper()
	st, b, _ := do(t, "GET", n.URL+"/v1/ui/bootstrap-status", "", "", hdr...)
	if st != 200 {
		t.Fatalf("bootstrap-status %d %s", st, b)
	}
	return jsonOf(t, b)["needsSetup"] == true
}

func TestWebBootstrapLoopbackOnlyAndOnce(t *testing.T) {
	n := webNode(t, nil)
	if n.Key != "" {
		t.Fatal("web mode must not print/create a key at start-up")
	}
	if !needsSetup(t, n) {
		t.Fatal("an empty keystore on loopback must offer setup")
	}
	// anything that does not look like this machine's own browser is never offered the bootstrap
	for _, tc := range [][]string{
		{"Host", "files.example.com"},
		{"Host", "rebind.attacker.test:7777"},
		{"X-Forwarded-For", "203.0.113.9"},
		{"X-Forwarded-Host", "x"},
		{"Forwarded", "for=203.0.113.9"},
		{"Via", "1.1 proxy"},
		{"Origin", "https://evil.example"},
		{"Sec-Fetch-Site", "cross-site"},
	} {
		if needsSetup(t, n, tc...) {
			t.Fatalf("bootstrap offered despite %v", tc)
		}
		if st, _, _ := do(t, "POST", n.URL+"/v1/ui/bootstrap", "", `{}`, append([]string{"Content-Type", "application/json"}, tc...)...); st != 404 {
			t.Fatalf("POST bootstrap with %v = %d, want 404 (indistinguishable from an unknown route)", tc, st)
		}
	}
	if st, _, _ := do(t, "POST", n.URL+"/v1/ui/bootstrap", "", `{}`, "Content-Type", "text/plain"); st != 415 {
		t.Fatalf("non-JSON bootstrap = %d", st)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/ui/bootstrap", "", ""); st != 405 {
		t.Fatalf("GET bootstrap = %d", st)
	}
	// same-origin browser request works and returns a host-admin key exactly once
	st, b, _ := do(t, "POST", n.URL+"/v1/ui/bootstrap", "", `{"label":"my laptop"}`, "Content-Type", "application/json", "Origin", n.URL, "Sec-Fetch-Site", "same-origin")
	if st != 201 {
		t.Fatalf("bootstrap = %d %s", st, b)
	}
	key := jsonOf(t, b)["key"].(string)
	if !strings.HasPrefix(key, "rx_live_") {
		t.Fatalf("key %q", key)
	}
	if needsSetup(t, n) {
		t.Fatal("setup must disappear for good after the first key")
	}
	if st, _, _ := do(t, "POST", n.URL+"/v1/ui/bootstrap", "", `{}`, "Content-Type", "application/json"); st != 404 {
		t.Fatalf("second bootstrap = %d", st)
	}
	st, b, _ = do(t, "GET", n.URL+"/v1/ui/whoami", key, "")
	w := jsonOf(t, b)
	if st != 200 || w["scope"] != "admin" || w["host_admin"] != true || w["label"] != "my laptop" {
		t.Fatalf("whoami %d %s", st, b)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/keys", key, ""); st != 200 {
		t.Fatalf("new key must administer keys, got %d", st)
	}
	// the key never reaches the audit log
	st, b, _ = do(t, "GET", n.URL+"/v1/admin/audit?limit=20", key, "")
	if st != 200 || strings.Contains(b, key) || !strings.Contains(b, "bootstrap.web") {
		t.Fatalf("audit: %d %s", st, b)
	}
}

func TestBootstrapModes(t *testing.T) {
	// off (REDX_NO_BOOTSTRAP=1 or --bootstrap off): neither a console key nor a web setup
	off := startNode(t, t.TempDir(), func(c *host.Config, _ string) { c.Bootstrap = "off" })
	if off.Key != "" || needsSetup(t, off) {
		t.Fatal("off must disable every bootstrap path")
	}
	if st, _, _ := do(t, "POST", off.URL+"/v1/ui/bootstrap", "", `{}`, "Content-Type", "application/json"); st != 404 {
		t.Fatalf("bootstrap while off = %d", st)
	}
	// console: the old behaviour, the key is created and handed to the caller (the CLI prints it), no web setup
	con := startNode(t, t.TempDir(), func(c *host.Config, _ string) { c.Bootstrap = "console" })
	if con.Key == "" || needsSetup(t, con) {
		t.Fatalf("console mode: key=%q needsSetup=%v", con.Key, needsSetup(t, con))
	}
	// auto: a loopback listener offers the browser; a network listener keeps the terminal path
	auto := startNode(t, t.TempDir(), func(c *host.Config, _ string) { c.Bootstrap = "auto"; c.Listen = "127.0.0.1:7777" })
	if auto.Key != "" || !needsSetup(t, auto) {
		t.Fatal("auto + loopback should use the web setup")
	}
	net := startNode(t, t.TempDir(), func(c *host.Config, _ string) { c.Bootstrap = "auto"; c.Listen = "0.0.0.0:7777" })
	if net.Key == "" || needsSetup(t, net) {
		t.Fatal("auto + network listener must never offer an unauthenticated web setup")
	}
	if st, _, _ := do(t, "POST", net.URL+"/v1/ui/bootstrap", "", `{}`, "Content-Type", "application/json"); st != 404 {
		t.Fatalf("network listener bootstrap = %d", st)
	}
	// the default config stays the terminal path so existing tests and scripts keep working
	if host.DefaultConfig().Bootstrap != "" {
		t.Fatal("DefaultConfig must keep the console behaviour")
	}
	// followers never offer a setup (their keys come from the leader)
	leader := startNode(t, t.TempDir(), nil)
	f := newFollower(t, leader, "fb")
	if needsSetup(t, f) {
		t.Fatal("a follower must not offer setup")
	}
	if st, _, _ := do(t, "POST", f.URL+"/v1/ui/bootstrap", "", `{}`, "Content-Type", "application/json"); st != 404 {
		t.Fatalf("follower bootstrap = %d", st)
	}
}

func TestBootstrapConfigPlumbing(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "redx.toml")
	os.WriteFile(f, []byte("data_dir = '"+filepath.ToSlash(dir)+"'\n"), 0o600)
	get := func(env map[string]string, args ...string) (host.Config, error) {
		return host.LoadConfig(append([]string{"--config", f}, args...), func(k string) string { return env[k] }, nil)
	}
	c, err := get(nil)
	if err != nil || c.Bootstrap != "auto" {
		t.Fatalf("CLI default should be auto: %v %q", err, c.Bootstrap)
	}
	if c, _ = get(map[string]string{"REDX_NO_BOOTSTRAP": "1"}); c.Bootstrap != "off" {
		t.Fatalf("REDX_NO_BOOTSTRAP=1 must disable the web bootstrap too, got %q", c.Bootstrap)
	}
	if c, _ = get(nil, "--bootstrap", "console"); c.Bootstrap != "console" {
		t.Fatalf("flag: %q", c.Bootstrap)
	}
	if _, err = get(nil, "--bootstrap", "banana"); err == nil {
		t.Fatal("bad bootstrap value must be rejected")
	}
	if host.ResolveBootstrap(host.Config{Bootstrap: "auto", Listen: "[::1]:7777"}) != "web" || host.ResolveBootstrap(host.Config{Bootstrap: "auto", Listen: ":7777"}) != "console" || host.ResolveBootstrap(host.Config{Bootstrap: "auto", Listen: "localhost:7777"}) != "web" {
		t.Fatal("ResolveBootstrap")
	}
}

// ---- whoami / validate ----

func TestWhoamiAndValidate(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	if st, _, _ := do(t, "GET", n.URL+"/v1/ui/whoami", "", ""); st != 401 {
		t.Fatalf("whoami anonymous = %d", st)
	}
	st, b, _ := do(t, "GET", n.URL+"/v1/ui/whoami", n.Key, "")
	w := jsonOf(t, b)
	if st != 200 || w["host_admin"] != true || strings.Contains(b, n.Key) || strings.Contains(b, "hash") {
		t.Fatalf("whoami: %d %s", st, b)
	}
	rk, _ := mkKey(t, n, map[string]interface{}{"scope": "read", "db": "default", "prefix": "a.red-xai.db:Box"})
	_, b, _ = do(t, "GET", n.URL+"/v1/ui/whoami", rk, "")
	w = jsonOf(t, b)
	if w["scope"] != "read" || w["host_admin"] != false || w["prefix"] != "a.red-xai.db:Box" {
		t.Fatalf("limited whoami: %s", b)
	}
	post := func(kind, text string) map[string]interface{} {
		body, _ := json.Marshal(map[string]string{"kind": kind, "text": text})
		st, b, _ := do(t, "POST", n.URL+"/v1/ui/validate", rk, string(body), "Content-Type", "application/json")
		if st != 200 {
			t.Fatalf("validate %d %s", st, b)
		}
		return jsonOf(t, b)
	}
	if r := post("value", `[ {Name[]} = "ann", {Level[]} = 3 ]`); r["ok"] != true {
		t.Fatalf("valid value: %v", r)
	}
	r := post("document", "{A[1]} = [ {X[]} = 1 ];\n@@ nope")
	if r["ok"] != false || r["line"] != float64(2) || r["col"] != float64(1) {
		t.Fatalf("document error position: %v", r)
	}
	if r := post("boxql", `{Get[]} = players:Player[ID=*] -> *`); r["ok"] != true {
		t.Fatalf("valid boxql: %v", r)
	}
	r = post("boxql", "{Get[]} = players:Player[Level >> 3]")
	if r["ok"] != false || r["line"] != float64(1) || r["col"] != float64(33) || !strings.Contains(r["message"].(string), "expected") {
		t.Fatalf("boxql error: %v", r)
	}
	if st, _, _ := do(t, "POST", n.URL+"/v1/ui/validate", "", `{}`, "Content-Type", "application/json"); st != 401 {
		t.Fatalf("validate anonymous = %d", st)
	}
	if st, _, _ := do(t, "POST", n.URL+"/v1/ui/validate", rk, `{"kind":"nonsense","text":"x"}`, "Content-Type", "application/json"); st != 400 {
		t.Fatalf("validate bad kind = %d", st)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/ui/validate", rk, ""); st != 405 {
		t.Fatalf("validate GET = %d", st)
	}
}

// ---- admin API: scope checks, status, audit, config ----

func TestAdminEndpointsNeedHostAdmin(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	wk, _ := mkKey(t, n, map[string]interface{}{"scope": "write", "db": "*"})
	dk, _ := mkKey(t, n, map[string]interface{}{"scope": "admin", "db": "default"})
	for _, p := range []string{"/v1/admin/status", "/v1/admin/audit", "/v1/admin/config", "/v1/admin/presets", "/v1/admin/presets/server"} {
		if st, _, _ := do(t, "GET", n.URL+p, "", ""); st != 401 {
			t.Fatalf("%s anonymous = %d", p, st)
		}
		for _, k := range []string{wk, dk} {
			if st, _, _ := do(t, "GET", n.URL+p, k, ""); st != 403 {
				t.Fatalf("%s with a non-host-admin key = %d, want 403", p, st)
			}
		}
		if st, _, _ := do(t, "GET", n.URL+p, n.Key, ""); st != 200 {
			t.Fatalf("%s as host admin = %d", p, st)
		}
	}
	if st, _, _ := do(t, "POST", n.URL+"/v1/admin/presets/server/apply", dk, `{}`, "Content-Type", "application/json"); st != 403 {
		t.Fatalf("apply as db admin = %d", st)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/admin/nope", n.Key, ""); st != 404 {
		t.Fatalf("unknown admin route = %d", st)
	}
	// the backup route keeps its old behaviour
	if st, _, _ := do(t, "GET", n.URL+"/v1/admin/backup", wk, ""); st != 403 {
		t.Fatalf("backup with write key = %d", st)
	}
	if st, _, h := do(t, "GET", n.URL+"/v1/admin/backup", n.Key, ""); st != 200 || !strings.Contains(h.Get("Content-Disposition"), "redx-backup-") {
		t.Fatalf("backup = %d %v", st, h)
	}
}

func TestAdminStatusAuditConfig(t *testing.T) {
	dir := t.TempDir()
	n := startNode(t, dir, func(c *host.Config, _ string) { c.ClusterKey = "super-secret-cluster-value" })
	do(t, "GET", n.URL+"/v1/dbs", "rx_live_"+strings.Repeat("x", 43), "") // one failed login for the audit log
	st, b, _ := do(t, "GET", n.URL+"/v1/admin/status", n.Key, "")
	s := jsonOf(t, b)
	if st != 200 || s["role"] != "leader" || s["databases"] != float64(1) || s["default_db"] != "default" || s["data_dir"] != dir {
		t.Fatalf("status: %d %s", st, b)
	}
	if s["requests"].(float64) < 2 || s["auth_failures"].(float64) < 1 {
		t.Fatalf("counters: %s", b)
	}
	st, b, _ = do(t, "GET", n.URL+"/v1/admin/audit?limit=5", n.Key, "")
	if st != 200 || !strings.Contains(b, `"events"`) || strings.Contains(b, n.Key) {
		t.Fatalf("audit: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", n.URL+"/v1/admin/config", n.Key, "")
	if st != 200 || strings.Contains(b, "super-secret-cluster-value") || !strings.Contains(b, "(set, hidden)") {
		t.Fatalf("config must redact secrets: %d %s", st, b)
	}
	cfg := jsonOf(t, b)["config"].(map[string]interface{})
	if cfg["listen"] == nil || cfg["role"] != "leader" {
		t.Fatalf("config body: %s", b)
	}
}

// ---- presets ----

func TestPresetsAPIDryRunApplyAndBackup(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "redx.toml")
	os.WriteFile(cfgPath, []byte("# my notes\nlog_level = \"warn\"\n"), 0o600)
	t.Setenv("REDX_KEYSTORE_PASSPHRASE", "")
	n := startNode(t, dir, func(c *host.Config, _ string) { c.ConfigFile = cfgPath })
	st, b, _ := do(t, "GET", n.URL+"/v1/admin/presets", n.Key, "")
	m := jsonOf(t, b)
	if st != 200 || len(m["presets"].([]interface{})) != 10 {
		t.Fatalf("presets: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", n.URL+"/v1/admin/presets/game", n.Key, "")
	g := jsonOf(t, b)
	if st != 200 || g["diff"] == nil || g["why"] == nil {
		t.Fatalf("preset detail: %d %s", st, b)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/admin/presets/nope", n.Key, ""); st != 404 {
		t.Fatalf("unknown preset = %d", st)
	}
	apply := func(name, body string) (int, map[string]interface{}) {
		st, b, _ := do(t, "POST", n.URL+"/v1/admin/presets/"+name+"/apply", n.Key, body, "Content-Type", "application/json")
		var out map[string]interface{}
		_ = json.Unmarshal([]byte(b), &out)
		if out == nil {
			out = map[string]interface{}{"raw": b}
		}
		return st, out
	}
	before, _ := os.ReadFile(cfgPath)
	if st, r := apply("game", `{"dry_run":true}`); st != 200 || r["dry_run"] != true || len(r["changes"].([]interface{})) == 0 {
		t.Fatalf("dry run: %d %v", st, r)
	}
	if after, _ := os.ReadFile(cfgPath); string(after) != string(before) {
		t.Fatal("a dry run must not write the config file")
	}
	// an edited value is honoured, keystore_encrypt is skipped (no passphrase), the old file is kept
	st, r := apply("vps", `{"overrides":{"rate_limit_rps":77}}`)
	if st != 200 || r["restart_required"] != true || r["backup"] == "" {
		t.Fatalf("apply: %d %v", st, r)
	}
	if len(r["skipped"].([]interface{})) != 1 || r["skipped"].([]interface{})[0].(map[string]interface{})["key"] != "keystore_encrypt" {
		t.Fatalf("keystore_encrypt must be reported as skipped without a passphrase: %v", r["skipped"])
	}
	written, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(written), "rate_limit_rps = 77") || !strings.Contains(string(written), `preset = "vps"`) || !strings.Contains(string(written), `log_level = "info"`) {
		t.Fatalf("written config:\n%s", written)
	}
	if strings.Contains(string(written), "keystore_encrypt") {
		t.Fatalf("keystore_encrypt must not be written without a passphrase:\n%s", written)
	}
	bak, err := os.ReadFile(r["backup"].(string))
	if err != nil || string(bak) != string(before) {
		t.Fatalf("backup: %v %q", err, bak)
	}
	// and the file we wrote loads and validates exactly as redxd would
	if _, err := host.LoadConfig([]string{"--config", cfgPath, "--data-dir", dir}, func(string) string { return "" }, nil); err != nil {
		t.Fatalf("written config does not load: %v\n%s", err, written)
	}
	// validation and safety
	if st, _ := apply("game", `{"overrides":{"data_dir":"/etc"}}`); st != 400 {
		t.Fatalf("a setting outside the presets must be refused, got %d", st)
	}
	if st, _ := apply("game", `{"overrides":{"engine_durability":"banana"}}`); st != 400 {
		t.Fatalf("an invalid value must be refused, got %d", st)
	}
	if st, r := apply("edge", `{}`); st != 400 || !strings.Contains(r["error"].(string), "join") {
		t.Fatalf("a follower preset needs a join link: %d %v", st, r)
	}
	if st, _ := apply("edge", `{"join":"not a link"}`); st != 400 {
		t.Fatalf("bad join link = %d", st)
	}
	if st, _ := apply("edge", `{"join":"http://leader.example:7777 RX-ABCDE-FGHJK","dry_run":true}`); st != 200 {
		t.Fatalf("edge with a join link (dry run) = %d", st)
	}
	if st, _, _ := do(t, "POST", n.URL+"/v1/admin/presets/game/apply", n.Key, `{`, "Content-Type", "application/json"); st != 400 {
		t.Fatalf("bad JSON = %d", st)
	}
}

// ---- files / raw / drop ----

func TestFilesAndRawEndpoints(t *testing.T) {
	dir := t.TempDir()
	n := startNode(t, dir, nil)
	db := filepath.Join(dir, "dbs", "default")
	os.MkdirAll(db, 0o755)
	policy := "{Role[1]} = [ {Name[]} = \"guest\" ];\n"
	os.WriteFile(filepath.Join(db, "policy.red-xai-sec"), []byte(policy), 0o644)
	os.WriteFile(filepath.Join(db, "stuff.red-xai-sec"), []byte(policy), 0o644)
	os.WriteFile(filepath.Join(db, "rels.red-xai-db-link"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(db, "players.red-xai.db"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(db, "players.red-xai.db.wal.1"), []byte("x"), 0o644)
	big := make([]byte, 1<<20+10)
	os.WriteFile(filepath.Join(db, "big.red-xai-code"), big, 0o644)
	st, b, _ := do(t, "GET", n.URL+"/v1/db/default/files", n.Key, "")
	if st != 200 {
		t.Fatalf("files: %d %s", st, b)
	}
	var list struct {
		Files []struct{ Name, Type, Records, Writable string }
	}
	json.Unmarshal([]byte(b), &list)
	got := map[string][2]string{}
	for _, f := range list.Files {
		got[f.Name] = [2]string{f.Type, f.Records}
	}
	for name, want := range map[string][2]string{
		"policy.red-xai-sec": {"sec", "raw"}, "rels.red-xai-db-link": {"link", "raw-readonly"}, "players.red-xai.db": {"db", "records"},
		"players.red-xai.db.wal.1": {"journal", "none"},
	} {
		if got[name] != want {
			t.Fatalf("%s classified %v, want %v (all: %v)", name, got[name], want, got)
		}
	}
	// scopes
	wk, _ := mkKey(t, n, map[string]interface{}{"scope": "write", "db": "default"})
	pk, _ := mkKey(t, n, map[string]interface{}{"scope": "admin", "db": "default", "prefix": "players.red-xai.db:Player"})
	other, _ := mkKey(t, n, map[string]interface{}{"scope": "admin", "db": "default"})
	n.H.Reg.Create("elsewhere")
	for _, k := range []string{wk, pk, ""} {
		if st, _, _ := do(t, "GET", n.URL+"/v1/db/default/files", k, ""); st != 401 && st != 403 {
			t.Fatalf("files with key %q... = %d", k[:min(len(k), 4)], st)
		}
		if st, _, _ := do(t, "GET", n.URL+"/v1/db/default/files/policy.red-xai-sec", k, ""); st != 401 && st != 403 {
			t.Fatalf("raw file with key %q... = %d", k[:min(len(k), 4)], st)
		}
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/db/elsewhere/files", other, ""); st != 403 {
		t.Fatalf("a db admin must not list another database: %d", st)
	}
	// raw text
	st, b, _ = do(t, "GET", n.URL+"/v1/db/default/files/policy.red-xai-sec", other, "")
	r := jsonOf(t, b)
	if st != 200 || r["text"] != policy || r["writable"] != true || r["type"] != "sec" {
		t.Fatalf("raw policy: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", n.URL+"/v1/db/default/files/stuff.red-xai-sec", other, "")
	if r = jsonOf(t, b); st != 200 || r["writable"] != false || r["write_via"] != "" {
		t.Fatalf("a hand-placed sec file cannot be written through the API: %s", b)
	}
	if st, b, _ = do(t, "GET", n.URL+"/v1/db/default/files/rels.red-xai-db-link", other, ""); st != 200 || jsonOf(t, b)["writable"] != false {
		t.Fatalf("link files are read-only: %d %s", st, b)
	}
	for _, p := range []string{"players.red-xai.db", "players.red-xai.db.wal.1", "nope.red-xai-sec", "..%2fkeys.red-xai-keys", "..%2f..%2fredx.toml", "%2e%2e%2fnode.id", "big.red-xai-code"} {
		if st, _, _ := do(t, "GET", n.URL+"/v1/db/default/files/"+p, other, ""); st == 200 {
			t.Fatalf("raw read of %q must be refused", p)
		}
	}
}

func TestDropDatabase(t *testing.T) {
	leader := startNode(t, t.TempDir(), nil)
	f := newFollower(t, leader, "fd")
	do(t, "POST", leader.URL+"/v1/dbs", leader.Key, `{"name":"scratch"}`, "Content-Type", "application/json")
	do(t, "PUT", leader.URL+"/v1/db/scratch/path/a.red-xai.db:Box[ID=1]", leader.Key, `[ {X[]} = 1 ]`)
	eventually(t, "db replicated", 5*time.Second, func() bool {
		st, b, _ := do(t, "GET", f.URL+"/v1/dbs", leader.Key, "")
		return st == 200 && strings.Contains(b, "scratch")
	})
	wk, _ := mkKey(t, leader, map[string]interface{}{"scope": "admin", "db": "scratch"})
	if st, _, _ := do(t, "DELETE", leader.URL+"/v1/db/scratch?confirm=scratch", wk, ""); st != 403 {
		t.Fatalf("only a host admin may delete a database, got %d", st)
	}
	if st, _, _ := do(t, "DELETE", leader.URL+"/v1/db/scratch", leader.Key, ""); st != 400 {
		t.Fatalf("delete without confirm = %d", st)
	}
	if st, _, _ := do(t, "DELETE", leader.URL+"/v1/db/scratch?confirm=other", leader.Key, ""); st != 400 {
		t.Fatalf("delete with the wrong confirm = %d", st)
	}
	if st, _, _ := do(t, "DELETE", leader.URL+"/v1/db/default?confirm=default", leader.Key, ""); st != 400 {
		t.Fatalf("the default database cannot be deleted, got %d", st)
	}
	if st, _, _ := do(t, "DELETE", leader.URL+"/v1/db/nope?confirm=nope", leader.Key, ""); st != 404 {
		t.Fatalf("unknown db = %d", st)
	}
	if st, b, _ := do(t, "DELETE", leader.URL+"/v1/db/scratch?confirm=scratch", leader.Key, ""); st != 200 {
		t.Fatalf("delete: %d %s", st, b)
	}
	if _, err := os.Stat(filepath.Join(leader.Dir, "dbs", "scratch")); err == nil {
		t.Fatal("database folder must be gone")
	}
	eventually(t, "drop replicated", 5*time.Second, func() bool {
		_, b, _ := do(t, "GET", f.URL+"/v1/dbs", leader.Key, "")
		return !strings.Contains(b, "scratch")
	})
	// a follower forwards the request to the leader (and the leader's answer wins)
	do(t, "POST", leader.URL+"/v1/dbs", leader.Key, `{"name":"scratch2"}`, "Content-Type", "application/json")
	eventually(t, "scratch2 replicated", 5*time.Second, func() bool {
		_, b, _ := do(t, "GET", f.URL+"/v1/dbs", leader.Key, "")
		return strings.Contains(b, "scratch2")
	})
	if st, b, _ := do(t, "DELETE", f.URL+"/v1/db/scratch2?confirm=scratch2", leader.Key, ""); st != 200 {
		t.Fatalf("delete through a follower: %d %s", st, b)
	}
	eventually(t, "forwarded drop applied on leader", 5*time.Second, func() bool {
		_, b, _ := do(t, "GET", leader.URL+"/v1/dbs", leader.Key, "")
		return !strings.Contains(b, "scratch2")
	})
}

// ---- pairing codes and join links ----

func TestJoinPairingCode(t *testing.T) {
	leader := startNode(t, t.TempDir(), nil)
	ctx := context.Background()
	st, b, _ := do(t, "POST", leader.URL+"/v1/cluster/join-token", leader.Key, `{"kind":"code"}`, "Content-Type", "application/json")
	r := jsonOf(t, b)
	code, _ := r["code"].(string)
	if st != 200 || !regexp.MustCompile(`^RX-[A-HJKMNP-Z2-9]{5}-[A-HJKMNP-Z2-9]{5}$`).MatchString(code) {
		t.Fatalf("code: %d %s", st, b)
	}
	if r["expires_in_seconds"] != float64(600) || r["single_use"] != true || r["scope"] != "join" || r["token"] != code {
		t.Fatalf("a code lives about 10 minutes, once, for joining only: %s", b)
	}
	if _, b, _ := do(t, "POST", leader.URL+"/v1/cluster/join-token", leader.Key, `{"kind":"code","ttl_seconds":999999}`, "Content-Type", "application/json"); jsonOf(t, b)["expires_in_seconds"] != float64(3600) {
		t.Fatalf("codes are capped at one hour: %s", b)
	}
	if st, _, _ := do(t, "POST", leader.URL+"/v1/cluster/join-token", leader.Key, `{"kind":"password"}`, "Content-Type", "application/json"); st != 400 {
		t.Fatalf("unknown kind = %d", st)
	}
	// typed in lower case, with spaces and no dashes: still redeems, exactly once
	typed := strings.ToLower(strings.ReplaceAll(code, "-", " "))
	if _, err := host.JoinLeader(ctx, leader.Srv.Client(), leader.URL, typed, "phoneish", ""); err != nil {
		t.Fatalf("normalized code must work: %v", err)
	}
	if _, err := host.JoinLeader(ctx, leader.Srv.Client(), leader.URL, code, "again", ""); err == nil {
		t.Fatal("a pairing code is single use")
	}
	// a code is not an API key: it opens nothing but the join endpoint
	_, b, _ = do(t, "POST", leader.URL+"/v1/cluster/join-token", leader.Key, `{"kind":"code"}`, "Content-Type", "application/json")
	c2 := jsonOf(t, b)["code"].(string)
	for _, p := range []string{"/v1/dbs", "/v1/admin/status", "/v1/keys", "/v1/cluster/status", "/v1/cluster/log?from=1", "/v1/cluster/snapshot"} {
		if st, _, _ := do(t, "GET", leader.URL+p, c2, "", "X-Redx-Node", "x"); st != 401 {
			t.Fatalf("a pairing code must not authenticate %s (got %d)", p, st)
		}
	}
	// a non-admin key cannot make codes
	wk, _ := mkKey(t, leader, map[string]interface{}{"scope": "write", "db": "*"})
	if st, _, _ := do(t, "POST", leader.URL+"/v1/cluster/join-token", wk, `{"kind":"code"}`, "Content-Type", "application/json"); st != 403 {
		t.Fatalf("code with write key = %d", st)
	}
	// a short ttl really expires
	_, b, _ = do(t, "POST", leader.URL+"/v1/cluster/join-token", leader.Key, `{"kind":"code","ttl_seconds":1}`, "Content-Type", "application/json")
	short := jsonOf(t, b)["code"].(string)
	time.Sleep(1200 * time.Millisecond)
	if _, err := host.JoinLeader(ctx, leader.Srv.Client(), leader.URL, short, "late", ""); err == nil {
		t.Fatal("an expired code must be refused")
	}
}

func TestJoinCodeBruteForceIsThrottled(t *testing.T) {
	leader := startNode(t, t.TempDir(), nil)
	limited := false
	for i := 0; i < 60 && !limited; i++ {
		body := `{"token":"RX-AAAAA-AAAA` + string(rune('B'+i%20)) + `","node_id":"x"}`
		st, _, _ := do(t, "POST", leader.URL+"/v1/cluster/join", "", body, "Content-Type", "application/json")
		if st == http.StatusTooManyRequests {
			limited = true
		} else if st != 401 && st != 403 {
			t.Fatalf("wrong code = %d", st)
		}
	}
	if !limited {
		t.Fatal("guessing pairing codes must be rate limited per address")
	}
}

func TestParseJoinForms(t *testing.T) {
	ok := []struct{ in, leader, secret, pin string }{
		{"https://192.168.1.5:7777/#/join?c=RX-ABCDE-FGHJK&pin=AB12", "https://192.168.1.5:7777", "RX-ABCDE-FGHJK", "ab12"},
		{"http://nas.local:7777/#/join?c=rx-abcde-fghjk", "http://nas.local:7777", "RX-ABCDE-FGHJK", ""},
		{"https://h:1 RX-ABCDE-FGHJK", "https://h:1", "RX-ABCDE-FGHJK", ""},
		{"  h:7777   rxabcdefghjk ", "http://h:7777", "RX-ABCDE-FGHJK", ""},
		{"http://x:1/#/join?t=rxj_abcdefgh", "http://x:1", "rxj_abcdefgh", ""},
		{"http://x:1/?c=RX-ABCDE-FGHJK&pin=sha256:CD", "http://x:1", "RX-ABCDE-FGHJK", "cd"},
	}
	for _, c := range ok {
		sp, err := host.ParseJoin(c.in)
		if err != nil || sp.Leader != c.leader || sp.Secret != c.secret || sp.Pin != c.pin {
			t.Fatalf("ParseJoin(%q) = %+v, %v; want %s %s %s", c.in, sp, err, c.leader, c.secret, c.pin)
		}
	}
	for _, bad := range []string{"", "   ", "just-one-word", "https://h:1/#/join", "ftp://h:1 RX-ABCDE-FGHJK", "a b c"} {
		if _, err := host.ParseJoin(bad); err == nil {
			t.Fatalf("ParseJoin(%q) should fail", bad)
		}
	}
}

// A node can join with a pairing code through RedeemJoin and then follows the leader.
func TestRedeemJoinThenFollow(t *testing.T) {
	leader := startNode(t, t.TempDir(), nil)
	_, b, _ := do(t, "POST", leader.URL+"/v1/cluster/join-token", leader.Key, `{"kind":"code"}`, "Content-Type", "application/json")
	code := jsonOf(t, b)["code"].(string)
	dir := t.TempDir()
	if host.HasJoined(dir) {
		t.Fatal("fresh dir")
	}
	sp, err := host.ParseJoin(leader.URL + "/#/join?c=" + code)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id, err := host.RedeemJoin(ctx, dir, sp, "")
	if err != nil || id == "" || !host.HasJoined(dir) {
		t.Fatalf("redeem: %q %v", id, err)
	}
	f := startNode(t, dir, func(c *host.Config, _ string) { c.Role = "follower"; c.NodeID = id })
	do(t, "PUT", leader.URL+"/v1/path/a.red-xai.db:Box[ID=1]", leader.Key, `[ {X[]} = 7 ]`)
	eventually(t, "joined node replicates", 5*time.Second, func() bool {
		st, b, _ := do(t, "GET", f.URL+"/v1/path/a.red-xai.db:Box[ID=1]", leader.Key, "")
		return st == 200 && strings.Contains(b, "7")
	})
	if st, _, _ := do(t, "GET", f.URL+"/", "", ""); st != 200 {
		t.Fatal("a follower serves the console too")
	}
	var _ = httptest.NewRecorder
}

// The console's About card carries the exact ownership copy (also in README.md).
func TestConsoleAboutCopy(t *testing.T) {
	const about = "RedX is developed and maintained by Red-XAI LLC. Red-XAI LLC is wholly owned by GRIM-VIRUS, an independent recording artist who leads development under the alias MainDirectory. © Red-XAI LLC. All rights reserved."
	b, ok := host.UIAsset("js/pages/help.js")
	if !ok {
		t.Fatal("help.js is not embedded")
	}
	if !strings.Contains(string(b), "export const ABOUT = '"+about+"';") {
		t.Error("help.js About text differs from the ownership copy")
	}
}
