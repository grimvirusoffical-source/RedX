package host_test

import (
	"testing"
	"time"

	"redx/billing"
)

// Quota boundaries are covered in billing/quota tests; this checks Host.BillingUsage wiring
// stays available when billing starts without Stripe (usage store still opens).
func TestBillingUsageWithoutPlan(t *testing.T) {
	for _, k := range []string{"STRIPE_SECRET_KEY", "STRIPE_PUBLISHABLE_KEY", "STRIPE_WEBHOOK_SECRET"} {
		t.Setenv(k, "")
	}
	n := startNode(t, t.TempDir(), nil)
	if st := n.H.BillingPlan("nobody"); st != "" {
		t.Fatalf("plan: %q", st)
	}
	if _, ok := n.H.BillingUsage("nobody"); ok {
		t.Fatal("usage without a plan")
	}
}

func TestQuotaConstantsMatchDocs(t *testing.T) {
	want := map[string]billing.Quota{
		"basic":    {TrafficBytes: 10 << 30, StorageBytes: 1 << 30, HostSwitches: 2},
		"bronze":   {TrafficBytes: 50 << 30, StorageBytes: 5 << 30, HostSwitches: 5},
		"silver":   {TrafficBytes: 150 << 30, StorageBytes: 20 << 30, HostSwitches: 10},
		"gold":     {TrafficBytes: 500 << 30, StorageBytes: 50 << 30, HostSwitches: 20},
		"platinum": {TrafficBytes: 1 << 40, StorageBytes: 100 << 30, HostSwitches: 40},
		"emerald":  {TrafficBytes: 5 << 40, StorageBytes: 500 << 30, HostSwitches: billing.UnlimitedSwitches},
	}
	for k, w := range want {
		g, ok := billing.QuotaFor(k)
		if !ok || g != w {
			t.Fatalf("%s: got %+v want %+v", k, g, w)
		}
	}
	_ = time.Now
}
