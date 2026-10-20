package billing

import (
	"net/http"
	"testing"
)

// Every billing error carries a stable code, a human-readable message, and the
// legacy "error" field (equal to the code, as before).
func TestBillingErrorBodies(t *testing.T) {
	_, _, h := testService(t)
	cases := []struct {
		name, method, path, acct string
		body                     interface{}
		status                   int
		code                     string
	}{
		{"unknown route", "GET", "/v1/billing/nope", "", nil, 404, "not_found"},
		{"bad plan", "POST", "/v1/billing/checkout", "acct1", map[string]string{"plan": "nope", "interval": "month", "idempotencyKey": "abcdefgh1"}, 400, "bad_plan"},
		{"bad interval", "POST", "/v1/billing/checkout", "acct1", map[string]string{"plan": "basic", "interval": "week", "idempotencyKey": "abcdefgh2"}, 400, "bad_interval"},
		{"no billing yet", "POST", "/v1/billing/portal", "acct1", map[string]string{}, 404, "no_billing"},
		{"bad session", "GET", "/v1/billing/checkout/%20bad", "acct1", nil, 400, "bad_request"},
	}
	for _, c := range cases {
		st, out := call(t, h, c.method, c.path, c.acct, c.body)
		if st != c.status {
			t.Errorf("%s: status %d, want %d (%v)", c.name, st, c.status, out)
			continue
		}
		code, _ := out["code"].(string)
		msg, _ := out["message"].(string)
		legacy, _ := out["error"].(string)
		if code != c.code || legacy != c.code || len(msg) < 5 || msg == code {
			t.Errorf("%s: body %v, want code=error=%q and a readable message", c.name, out, c.code)
		}
	}
}

func TestBillingOffMessageExplainsWhy(t *testing.T) {
	st, _ := OpenStore("")
	s := New(Config{}, nil, st, t.Logf)
	h := s.Handler(func(w http.ResponseWriter, r *http.Request) (Identity, bool) { return Identity{Sub: "a"}, true })
	code, out := call(t, h, "POST", "/v1/billing/checkout", "a", map[string]string{"plan": "basic", "interval": "month", "idempotencyKey": "abcdefgh3"})
	if code != 503 || out["code"] != "billing_off" || out["error"] != "billing_off" {
		t.Fatalf("billing off: %d %v", code, out)
	}
	if m, _ := out["message"].(string); m == "" || m == "billing_off" {
		t.Fatalf("billing off message: %v", out)
	}
}
