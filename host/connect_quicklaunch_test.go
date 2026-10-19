package host_test

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"redx/host"
)

func TestLoopbackCallbackRule(t *testing.T) {
	const path = "/redx-callback"
	accept := []string{
		"http://127.0.0.1:1/redx-callback",
		"http://127.0.0.1:49152/redx-callback",
		"http://127.0.0.1:65535/redx-callback",
		"http://[::1]:8080/redx-callback",
		"http://localhost:5173/redx-callback",
	}
	reject := []string{
		"", "http://127.0.0.1/redx-callback", // no port
		"http://127.0.0.1:0/redx-callback", "http://127.0.0.1:65536/redx-callback", "http://127.0.0.1:08080/redx-callback",
		"http://127.0.0.1:99999/redx-callback", "http://127.0.0.1:12a/redx-callback", "http://127.0.0.1:/redx-callback",
		"https://127.0.0.1:8080/redx-callback", "ftp://127.0.0.1:21/redx-callback", "rottenapple://redx-callback", "javascript:alert(1)",
		"HTTP://127.0.0.1:8080/redx-callback", "http://LOCALHOST:8080/redx-callback", "http://localhost.:8080/redx-callback",
		"http://127.0.0.2:8080/redx-callback", "http://127.1:8080/redx-callback", "http://0.0.0.0:8080/redx-callback",
		"http://[::ffff:127.0.0.1]:8080/redx-callback", "http://[0:0:0:0:0:0:0:1]:8080/redx-callback", "http://2130706433:8080/redx-callback",
		"http://localtest.me:8080/redx-callback", "http://127.0.0.1.nip.io:8080/redx-callback", "http://evil.example:8080/redx-callback",
		"http://127.0.0.1:8080@evil.example/redx-callback", "http://user@127.0.0.1:8080/redx-callback", "http://user:pw@localhost:8080/redx-callback",
		"http://evil.example#@127.0.0.1:8080/redx-callback", "http://127.0.0.1:8080\\@evil.example/redx-callback",
		"http://127.0.0.1:8080/redx-callback/", "http://127.0.0.1:8080/redx-callbackX", "http://127.0.0.1:8080/REDX-CALLBACK",
		"http://127.0.0.1:8080/other", "http://127.0.0.1:8080/", "http://127.0.0.1:8080", "http://127.0.0.1:8080//redx-callback",
		"http://127.0.0.1:8080/x/../redx-callback", "http://127.0.0.1:8080/%72edx-callback", "http://127.0.0.1:8080/redx-callback?x=1",
		"http://127.0.0.1:8080/redx-callback#f", "http://127.0.0.1:8080/redx-callback\n", " http://127.0.0.1:8080/redx-callback",
		"http://127.0.0.1:8080/redx-callback ", "//127.0.0.1:8080/redx-callback",
	}
	for _, cb := range accept {
		if !host.LoopbackCallbackOK(cb, path) {
			t.Errorf("should accept %q", cb)
		}
	}
	for _, cb := range reject {
		if host.LoopbackCallbackOK(cb, path) {
			t.Errorf("should reject %q", cb)
		}
	}
	if host.LoopbackCallbackOK("http://127.0.0.1:8080/redx-callback", "/other-path") {
		t.Error("the path must match the registered path exactly")
	}
}

func TestConnectQuickLaunchProvider(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	start := func(i int, cb string, extra string) (int, map[string]interface{}) {
		p := newPKCE(i)
		return cpost(t, n, "/v1/connect/start", n.Key, fmt.Sprintf(`{"v":1,"provider":"quicklaunch","state":%q,"pkce_challenge":%q,"callback":%q%s}`, p.state, p.challenge, cb, extra))
	}
	// a loopback callback on a random port is accepted, and the provider is verified with RedX's own wording
	st, out := start(1, "http://127.0.0.1:53917/redx-callback", "")
	if st != 201 {
		t.Fatalf("start %d %v", st, out)
	}
	prov := out["provider"].(map[string]interface{})
	if prov["verified"] != true || prov["callback_ok"] != true || prov["display"] != "QuickLaunch (developer tool)" || !strings.Contains(prov["wording"].(string), "QuickLaunch") {
		t.Fatalf("provider %v", prov)
	}
	if ws := out["defaults"].(map[string]interface{})["workspace"]; ws != "quicklaunch" {
		t.Fatalf("workspace %v", ws)
	}
	// approve: the code is delivered to that exact loopback URL; exchange still needs PKCE
	ap := approve(t, n, out["request_id"].(string), "")
	tpl := ap["callback_template"].(string)
	if ap["deliver"] != "callback" || !strings.HasPrefix(tpl, "http://127.0.0.1:53917/redx-callback?code=") {
		t.Fatalf("approve %v", ap)
	}
	u, _ := url.Parse(strings.Replace(tpl, "{state}", "x", 1))
	if u.Query().Get("code") != ap["code"] {
		t.Fatalf("template %s", tpl)
	}
	if st, e := exchange(t, n, ap["code"].(string), newPKCE(99), ""); st == 200 {
		t.Fatalf("a wrong verifier/state must not exchange: %v", e)
	}
	// non-loopback, userinfo, other schemes, other paths: no callback (the code is only shown for copy and paste)
	for i, cb := range []string{"http://evil.example:8080/redx-callback", "http://127.0.0.1:8080@evil.example/redx-callback",
		"https://127.0.0.1:8080/redx-callback", "quicklaunch://redx-callback", "http://127.0.0.1:8080/other", "http://localtest.me:8080/redx-callback"} {
		st, out := start(10+i, cb, "")
		if st != 201 {
			t.Fatalf("%s: start %d %v", cb, st, out)
		}
		if out["provider"].(map[string]interface{})["callback_ok"] != false {
			t.Fatalf("%s must not be accepted as a callback", cb)
		}
		ap := approve(t, n, out["request_id"].(string), "")
		if ap["deliver"] != "paste" || ap["callback_template"] != nil {
			t.Fatalf("%s: approve %v", cb, ap)
		}
	}
	// PKCE is still required
	p := newPKCE(30)
	if st, _ := cpost(t, n, "/v1/connect/start", n.Key, fmt.Sprintf(`{"v":1,"provider":"quicklaunch","state":%q,"callback":"http://127.0.0.1:5000/redx-callback"}`, p.state)); st != 400 {
		t.Fatalf("start without pkce_challenge: %d", st)
	}
	if st, _ := cpost(t, n, "/v1/connect/start", n.Key, fmt.Sprintf(`{"v":1,"provider":"quicklaunch","state":%q,"pkce_challenge":%q,"pkce_method":"plain","callback":"http://127.0.0.1:5000/redx-callback"}`, p.state, p.challenge)); st != 400 {
		t.Fatalf("plain PKCE must be refused: %d", st)
	}
}
