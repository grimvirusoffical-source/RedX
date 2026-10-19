package host_test

import (
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
