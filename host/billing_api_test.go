package host_test

import (
	"encoding/json"
	"strings"
	"testing"
)

// Without Stripe keys the host still starts; plans answer "off", account routes need a Red-XAI Account
// (an API key is not enough) and the webhook refuses everything.
func TestBillingRoutesWithoutKeys(t *testing.T) {
	for _, k := range []string{"STRIPE_SECRET_KEY", "STRIPE_PUBLISHABLE_KEY", "STRIPE_WEBHOOK_SECRET"} {
		t.Setenv(k, "")
	}
	n := startNode(t, t.TempDir(), nil)
	if st, b, _ := do(t, "GET", n.URL+"/v1/billing/plans", "", ""); st != 200 || !strings.Contains(b, `"enabled":false`) || strings.Contains(b, "sk_") {
		t.Fatalf("plans: %d %s", st, b)
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/billing/me", "", ""); st != 401 {
		t.Fatalf("me without a key: %d", st)
	}
	if st, b, _ := do(t, "GET", n.URL+"/v1/billing/me", n.Key, ""); st != 403 || !strings.Contains(b, "account_required") {
		t.Fatalf("me with an API key: %d %s", st, b)
	}
	if st, _, _ := do(t, "POST", n.URL+"/v1/billing/webhook", "", `{"id":"evt_1","type":"invoice.paid"}`); st != 503 {
		t.Fatalf("webhook without a secret: %d", st)
	}
}

// Host-level billing errors (auth, no account) use the same {code, message, error} body.
func TestBillingErrorJSONShape(t *testing.T) {
	for _, k := range []string{"STRIPE_SECRET_KEY", "STRIPE_PUBLISHABLE_KEY", "STRIPE_WEBHOOK_SECRET"} {
		t.Setenv(k, "")
	}
	n := startNode(t, t.TempDir(), nil)
	check := func(name, key string, wantStatus int, wantCode, wantLegacy string) {
		t.Helper()
		st, b, _ := do(t, "GET", n.URL+"/v1/billing/me", key, "")
		var out struct{ Error, Code, Message string }
		if err := json.Unmarshal([]byte(b), &out); err != nil {
			t.Fatalf("%s: not JSON: %s", name, b)
		}
		if st != wantStatus || out.Code != wantCode || out.Error != wantLegacy || out.Message == "" || out.Message == out.Code {
			t.Fatalf("%s: %d %s", name, st, b)
		}
	}
	check("no key", "", 401, "unauthorized", "unauthorized")
	check("api key without account", n.Key, 403, "account_required", "account_required")
	st, b, _ := do(t, "POST", n.URL+"/v1/billing/checkout", n.Key, `{}`)
	if st != 403 || !strings.Contains(b, `"code":"account_required"`) {
		t.Fatalf("checkout: %d %s", st, b)
	}
}

// The shared helper keeps "error" as the old message and adds code + message.
func TestSharedErrorHelperShape(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	st, b, _ := do(t, "GET", n.URL+"/v1/dbs/nope-db/path/x", n.Key, "")
	var out struct{ Error, Code, Message string }
	_ = json.Unmarshal([]byte(b), &out)
	if st != 404 || out.Code != "not_found" || out.Error == "" || out.Message != out.Error {
		t.Fatalf("shared error: %d %s", st, b)
	}
}
