package host

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebsiteEmbedPolicyIsSameOriginAndOptIn(t *testing.T) {
	for _, tc := range []struct {
		name, target    string
		website, framed bool
	}{
		{"standalone", "/v1/console/?embed=site", false, false},
		{"website-default", "/v1/console/", true, false},
		{"website-unknown-mode", "/v1/console/?embed=other", true, false},
		{"website-embedded", "/v1/console/?embed=site", true, true},
		{"website-alias", "/ui/?embed=site", true, true},
		{"billing", "/v1/console/billing.html?embed=site", true, false},
		{"script", "/v1/console/js/main.js?embed=site", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Host{}
			if tc.website {
				h.website = &websiteSessionAdapter{}
			}
			r := httptest.NewRequest("GET", "https://red-xai.com"+tc.target, nil)
			w := httptest.NewRecorder()
			w.Header().Set("X-Frame-Options", "DENY") // routes() default
			if strings.HasPrefix(r.URL.Path, "/ui/") {
				h.serveUI(w, r)
			} else {
				h.serveHubConsole(w, r)
			}
			if w.Code != 200 {
				t.Fatalf("asset status %d", w.Code)
			}
			frame, ancestor := "DENY", "frame-ancestors 'none'"
			if tc.framed {
				frame, ancestor = "SAMEORIGIN", "frame-ancestors 'self'"
			}
			if got := w.Header().Get("X-Frame-Options"); got != frame {
				t.Fatalf("frame header %q", got)
			}
			csp := w.Header().Get("Content-Security-Policy")
			for _, required := range []string{ancestor, "default-src 'none'", "script-src 'self'", "object-src 'none'", "base-uri 'none'"} {
				if !strings.Contains(csp, required) {
					t.Fatalf("missing policy %q", required)
				}
			}
			if strings.Contains(csp, "frame-ancestors *") || strings.Contains(csp, "unsafe-eval") {
				t.Fatal("expanded script/framing policy")
			}
		})
	}
}
