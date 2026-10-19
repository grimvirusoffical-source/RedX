package host_test

import (
	"encoding/json"
	"strings"
	"testing"
)

func pairIssue(t *testing.T, n *node, body string) string {
	t.Helper()
	st, b, _ := do(t, "POST", n.URL+"/v1/keys/pairing", n.Key, body)
	if st != 201 {
		t.Fatalf("issue: %d %s", st, b)
	}
	var r struct {
		Code string `json:"code"`
		Exp  int    `json:"expires_in_seconds"`
	}
	if err := json.Unmarshal([]byte(b), &r); err != nil || !strings.HasPrefix(r.Code, "RP-") || r.Exp < 250 || r.Exp > 300 {
		t.Fatalf("bad issue reply: %s", b)
	}
	if strings.Contains(b, "rx_") {
		t.Fatalf("issuing a code must not mint or reveal a key: %s", b)
	}
	return r.Code
}

// A pairing code is exchanged once for a key with exactly the requested access; the code itself is not a key.
func TestPairingCodeExchangesOnceForALimitedKey(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	before, _, _ := do(t, "GET", n.URL+"/v1/keys", n.Key, "")
	_ = before
	code := pairIssue(t, n, `{"db":"default","scope":"read","label":"phone","ttl":"24h"}`)

	// the code is not accepted as an API key
	if st, _, _ := do(t, "GET", n.URL+"/v1/stats", code, ""); st != 401 {
		t.Fatalf("a pairing code must not authenticate API calls: %d", st)
	}
	// typing it sloppily (lower case, spaces) still works
	sloppy := strings.ToLower(strings.ReplaceAll(code, "-", " "))
	st, b, _ := do(t, "POST", n.URL+"/v1/pair/exchange", "", `{"code":"`+sloppy+`"}`)
	if st != 201 {
		t.Fatalf("exchange: %d %s", st, b)
	}
	var r struct {
		Key  string                 `json:"key"`
		Info map[string]interface{} `json:"info"`
	}
	if err := json.Unmarshal([]byte(b), &r); err != nil || !strings.HasPrefix(r.Key, "rx_") {
		t.Fatalf("no key in reply: %s", b)
	}
	if r.Info["scope"] != "read" || r.Info["label"] != "phone" {
		t.Fatalf("key does not match the request: %s", b)
	}
	// the key works for reading and cannot write
	if st, _, _ := do(t, "GET", n.URL+"/v1/stats", r.Key, ""); st != 200 {
		t.Fatalf("paired key rejected: %d", st)
	}
	if st, _, _ := do(t, "PUT", n.URL+P+"s.red-xai.db:A.B", r.Key, `1`); st != 403 {
		t.Fatalf("a read key must not write: %d", st)
	}
	// single use
	if st, _, _ := do(t, "POST", n.URL+"/v1/pair/exchange", "", `{"code":"`+code+`"}`); st != 401 {
		t.Fatalf("a used code must be rejected, got %d", st)
	}
}

func TestPairingIssueNeedsAnAdminKeyAndValidScope(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	if st, _, _ := do(t, "POST", n.URL+"/v1/keys/pairing", "", `{"scope":"read"}`); st != 401 {
		t.Fatalf("anonymous issue: %d", st)
	}
	st, b, _ := do(t, "POST", n.URL+"/v1/keys", n.Key, `{"db":"default","scope":"write","label":"w"}`)
	if st != 201 {
		t.Fatal(b)
	}
	var w struct{ Key string }
	_ = json.Unmarshal([]byte(b), &w)
	if st, _, _ := do(t, "POST", n.URL+"/v1/keys/pairing", w.Key, `{"scope":"read"}`); st != 403 {
		t.Fatalf("a non-admin key must not issue codes: %d", st)
	}
	if st, _, _ := do(t, "POST", n.URL+"/v1/keys/pairing", n.Key, `{"scope":"root"}`); st != 400 {
		t.Fatalf("bad scope: %d", st)
	}
	if st, _, _ := do(t, "POST", n.URL+"/v1/keys/pairing", n.Key, `{"scope":"read","ttl":"abc"}`); st != 400 {
		t.Fatalf("bad ttl: %d", st)
	}
}

func TestPairingWrongCodesAreThrottled(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	code := pairIssue(t, n, `{"db":"default","scope":"read"}`)
	got429 := false
	for i := 0; i < 20; i++ {
		st, _, h := do(t, "POST", n.URL+"/v1/pair/exchange", "", `{"code":"RP-AAAAA-AAAAA"}`)
		if st == 429 {
			got429 = true
			if h.Get("Retry-After") == "" {
				t.Fatal("429 without Retry-After")
			}
			break
		}
		if st != 401 {
			t.Fatalf("wrong code: %d", st)
		}
	}
	if !got429 {
		t.Fatal("repeated wrong codes were never throttled")
	}
	// while throttled even the right code waits (no oracle for brute force)
	if st, _, _ := do(t, "POST", n.URL+"/v1/pair/exchange", "", `{"code":"`+code+`"}`); st != 429 {
		t.Fatalf("throttled client got %d", st)
	}
}

// The console QR code must carry a pairing code, never a key.
func TestConsoleQRCodesCarryNoKey(t *testing.T) {
	for _, f := range []string{"js/pages/devices.js", "js/pages/keys.js", "js/main.js"} {
		js := asset(t, f)
		if strings.Contains(js, "login?key=") {
			t.Errorf("%s still builds a key-in-URL sign-in link", f)
		}
	}
	if !strings.Contains(asset(t, "js/pages/devices.js"), "login?code=") || !strings.Contains(asset(t, "js/api.js"), "/v1/pair/exchange") {
		t.Error("console must use pairing-code links")
	}
}
