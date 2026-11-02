package host

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestNativeHubConsoleRoutesRetainEmbeddedAssetsAndCSP(t *testing.T) {
	h := &Host{}
	cases := []struct {
		path    string
		status  int
		content string
	}{
		{"/v1/console", http.StatusPermanentRedirect, ""},
		{"/v1/console/", http.StatusOK, "text/html"},
		{"/v1/console/js/main.js", http.StatusOK, "text/javascript"},
		{"/v1/console/css/app.css", http.StatusOK, "text/css"},
		{"/v1/console/icons/redx-128.png", http.StatusOK, "image/png"},
		{"/v1/console/definitely-missing.js", http.StatusNotFound, ""},
		{"/v1/console/../config.json", http.StatusNotFound, ""},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://api.red-xai.com"+tc.path, nil)
			out := httptest.NewRecorder()
			h.serveHubConsole(out, req)
			if out.Code != tc.status {
				t.Fatalf("got %d wanted %d, body: %s", out.Code, tc.status, out.Body.String())
			}
			if tc.content != "" && !strings.HasPrefix(out.Header().Get("Content-Type"), tc.content) {
				t.Fatalf("unexpected asset content type: %q", out.Header().Get("Content-Type"))
			}
			if out.Code == http.StatusOK {
				if csp := out.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") ||
					strings.Contains(csp, "'unsafe-inline'") {
					t.Fatalf("CSP weakened: %q", csp)
				}
				if tc.path == "/v1/console/" {
					body := out.Body.String()
					if !strings.Contains(body, "src=\""+uiAssetPrefix("/v1/console/")+"js/main.js\"") ||
						strings.Contains(body, "forge.css") ||
						!strings.Contains(body, "href=\""+uiAssetPrefix("/v1/console/")+"css/app.css\"") {
						t.Fatalf("static overlay remains or native assets missing: %s", body)
					}
				}
			}
		})
	}
}

func consoleStaticResponse(h *Host, method, target string, headers ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://red-xai.com"+target, nil)
	for i := 0; i < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	out := httptest.NewRecorder()
	if target == "/v1/console" || strings.HasPrefix(target, "/v1/console/") {
		h.serveHubConsole(out, req)
	} else {
		h.serveUI(out, req)
	}
	return out
}

func TestConsoleVersionedHTMLReferencesAndStandaloneCompatibility(t *testing.T) {
	website := &Host{website: &websiteSessionAdapter{}}
	standalone := &Host{}
	for _, tc := range []struct {
		name, target, base string
		h                  *Host
	}{
		{"hub", "/v1/console/", "/v1/console/", standalone},
		{"website root", "/", "/ui/", website},
		{"website ui", "/ui/", "/ui/", website},
		{"website ui index", "/ui/index.html", "/ui/", website},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := consoleStaticResponse(tc.h, http.MethodGet, tc.target)
			if out.Code != http.StatusOK {
				t.Fatalf("index returned %d: %s", out.Code, out.Body.String())
			}
			prefix := uiAssetPrefix(tc.base)
			refs := regexp.MustCompile(`(?:src|href)="([^"]+)"`).FindAllStringSubmatch(out.Body.String(), -1)
			if len(refs) < 6 {
				t.Fatalf("expected the complete index asset references: %s", out.Body.String())
			}
			for _, ref := range refs {
				if !strings.HasPrefix(ref[1], prefix) {
					t.Errorf("asset %q is outside current revision %q", ref[1], prefix)
					continue
				}
				asset := consoleStaticResponse(tc.h, http.MethodGet, ref[1])
				if asset.Code != http.StatusOK || asset.Body.Len() == 0 {
					t.Errorf("index asset %q returned %d (%d bytes)", ref[1], asset.Code, asset.Body.Len())
				}
			}
			if out.Header().Get("Content-Security-Policy") != uiCSP || out.Header().Get("ETag") == uiFiles["index.html"].etag {
				t.Fatal("versioned HTML must retain CSP and use an ETag for its rewritten bytes")
			}
		})
	}
	for _, target := range []string{"/", "/ui", "/ui/", "/ui/index.html"} {
		out := consoleStaticResponse(standalone, http.MethodGet, target)
		if out.Code != http.StatusOK || out.Body.String() != string(uiFiles["index.html"].data) {
			t.Errorf("standalone %s changed its existing index: %d", target, out.Code)
		}
	}
	for _, base := range []string{"/ui/", "/v1/console/"} {
		for _, name := range []string{"js/main.js", "js/website-session.js", "js/pages/auth.js", "css/app.css"} {
			out := consoleStaticResponse(standalone, http.MethodGet, base+name)
			if out.Code != http.StatusOK || out.Body.String() != string(uiFiles[name].data) {
				t.Errorf("legacy asset %s changed or disappeared: %d", base+name, out.Code)
			}
		}
	}
}

func TestConsoleRelativeModuleGraphKeepsBundleRevision(t *testing.T) {
	h := &Host{website: &websiteSessionAdapter{}}
	for _, base := range []string{"/ui/", "/v1/console/"} {
		prefix := uiAssetPrefix(base)
		for _, edge := range []struct{ parent, specifier, target string }{
			{"js/main.js", "./website-session.js", "js/website-session.js"},
			{"js/main.js", "./pages/auth.js", "js/pages/auth.js"},
			{"js/pages/auth.js", "../api.js", "js/api.js"},
		} {
			parent := consoleStaticResponse(h, http.MethodGet, prefix+edge.parent)
			importPattern := regexp.MustCompile(`(?:from\s*|import\s*\(\s*)['"]` + regexp.QuoteMeta(edge.specifier) + `['"]`)
			if parent.Code != http.StatusOK || !importPattern.MatchString(parent.Body.String()) {
				t.Fatalf("embedded %s no longer imports %q", edge.parent, edge.specifier)
			}
			parentURL, _ := url.Parse("https://red-xai.com" + prefix + edge.parent)
			reference, _ := url.Parse(edge.specifier)
			resolved := parentURL.ResolveReference(reference).Path
			if resolved != prefix+edge.target {
				t.Fatalf("%s import %q resolved outside revision: %s", parentURL, edge.specifier, resolved)
			}
			out := consoleStaticResponse(h, http.MethodGet, resolved)
			if out.Code != http.StatusOK || out.Body.String() != string(uiFiles[edge.target].data) {
				t.Fatalf("resolved module %s returned %d or different bytes", resolved, out.Code)
			}
			if out.Header().Get("Content-Security-Policy") != uiCSP || !strings.HasPrefix(out.Header().Get("Content-Type"), "text/javascript") {
				t.Fatalf("resolved module %s changed content type or CSP", resolved)
			}
		}
	}
}

func TestConsoleVersionedAssetsRejectInvalidPathsAndKeepHTTPBehavior(t *testing.T) {
	h := &Host{website: &websiteSessionAdapter{}}
	wrongRevision := strings.Repeat("0", len(uiRevision))
	if wrongRevision == uiRevision {
		wrongRevision = strings.Repeat("1", len(uiRevision))
	}
	for _, base := range []string{"/ui/", "/v1/console/"} {
		prefix := uiAssetPrefix(base)
		for _, suffix := range []string{
			"_assets/" + wrongRevision + "/js/main.js", "_assets/", "_assets/" + uiRevision,
			"_assets//js/main.js", "_assets/" + uiRevision + "/", "_assets/" + uiRevision + "/../js/main.js",
			"_assets/" + uiRevision + "/js/../../js/main.js", "_assets/" + uiRevision + "/js\\main.js",
			"_assets/" + uiRevision + "/%2e%2e/js/main.js", "_assets/" + uiRevision + "/v1/dbs",
			"_assets/" + uiRevision + "/v1/ui/whoami", "_assets/" + uiRevision + "/definitely-missing.js",
		} {
			out := consoleStaticResponse(h, http.MethodGet, base+suffix)
			if out.Code != http.StatusNotFound {
				t.Errorf("invalid static path %s returned %d", base+suffix, out.Code)
			}
		}
		for _, name := range []string{"index.html", "js/main.js", "billing.html"} {
			target := prefix + name
			get := consoleStaticResponse(h, http.MethodGet, target)
			if get.Code != http.StatusOK || get.Body.Len() == 0 || get.Header().Get("Cache-Control") != "no-cache" {
				t.Fatalf("versioned GET %s: %d %v", target, get.Code, get.Header())
			}
			wantedCSP := uiCSP
			if name == "billing.html" {
				wantedCSP = billingCSP
			}
			if get.Header().Get("Content-Security-Policy") != wantedCSP {
				t.Fatalf("versioned %s has incorrect CSP", name)
			}
			head := consoleStaticResponse(h, http.MethodHead, target)
			if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("ETag") != get.Header().Get("ETag") {
				t.Fatalf("versioned HEAD %s differs from GET: %d %v", target, head.Code, head.Header())
			}
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				cached := consoleStaticResponse(h, method, target, "If-None-Match", get.Header().Get("ETag"))
				if cached.Code != http.StatusNotModified || cached.Body.Len() != 0 || cached.Header().Get("Content-Security-Policy") != wantedCSP {
					t.Fatalf("versioned conditional %s %s: %d %v", method, target, cached.Code, cached.Header())
				}
			}
			post := consoleStaticResponse(h, http.MethodPost, target)
			if post.Code != http.StatusMethodNotAllowed || post.Header().Get("Allow") != "GET, HEAD" {
				t.Fatalf("versioned POST %s: %d %v", target, post.Code, post.Header())
			}
		}
	}
}

func TestNativeHubConsoleRejectsPOSTToStaticResources(t *testing.T) {
	h := &Host{}
	req := httptest.NewRequest(http.MethodPost, "https://api.red-xai.com/v1/console/js/main.js", nil)
	out := httptest.NewRecorder()
	h.serveHubConsole(out, req)
	if out.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST on static UI returned %d", out.Code)
	}
}
