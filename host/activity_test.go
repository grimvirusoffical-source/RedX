package host_test

import (
	"strings"
	"testing"
	"time"

	"redx/host"
	"redx/host/accountsfake"
)

func TestHostingActivityIsolation(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	end := time.Now().Add(30 * 24 * time.Hour)
	other := accountsfake.Identity{Sub: "rxa_OTHER000000000000000000001", Email: "other@example.com", EmailVerified: true, Username: "other_user", AMR: []string{"pwd"}}

	tokA, _ := signIn(t, n, f, regular)
	if err := host.SetPlanForTest(n.H, hostedPlan(regular.Sub, "basic", "month", "active", end)); err != nil {
		t.Fatal(err)
	}
	st, b, _ := do(t, "POST", n.URL+"/v1/dbs", tokA, `{"name":"alpha"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("create A: %d %s", st, b)
	}
	physA, _ := jsonOf(t, b)["name"].(string)
	st, b, _ = do(t, "PUT", n.URL+"/v1/db/"+physA+"/path/b:B.K", tokA, `"one"`)
	if st != 200 && st != 201 {
		t.Fatalf("put A: %d %s", st, b)
	}

	tokB, _ := signIn(t, n, f, other)
	if err := host.SetPlanForTest(n.H, hostedPlan(other.Sub, "basic", "month", "active", end)); err != nil {
		t.Fatal(err)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/dbs", tokB, `{"name":"beta"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("create B: %d %s", st, b)
	}
	physB, _ := jsonOf(t, b)["name"].(string)

	if err := host.SetPlanForTest(n.H, hostedPlan(regular.Sub, "basic", "month", "past_due", end)); err != nil {
		t.Fatal(err)
	}
	st, b, _ = do(t, "PUT", n.URL+"/v1/db/"+physA+"/path/b:B.K", tokA, `"two"`)
	if st != 402 || codeOf(t, b) != "plan_readonly" {
		t.Fatalf("readonly put: %d %s", st, b)
	}

	st, b, _ = do(t, "GET", n.URL+"/v1/hosting/activity", tokA, "")
	if st != 200 || !strings.Contains(b, physA) || !strings.Contains(b, "alpha") || strings.Contains(b, physB) || strings.Contains(b, "beta") {
		t.Fatalf("A activity: %d %s", st, b)
	}
	if !strings.Contains(b, "plan_readonly") || !strings.Contains(b, `"status":402`) {
		t.Fatalf("A denied: %s", b)
	}
	var reqs float64
	for _, row := range jsonOf(t, b)["dbs"].([]interface{}) {
		m := row.(map[string]interface{})
		if m["name"] == physA {
			reqs, _ = m["requests"].(float64)
		}
	}
	if reqs < 2 {
		t.Fatalf("A requests = %v in %s", reqs, b)
	}

	st, b, _ = do(t, "GET", n.URL+"/v1/hosting/activity", tokB, "")
	if st != 200 || strings.Contains(b, physA) || strings.Contains(b, "alpha") || strings.Contains(b, "plan_readonly") || !strings.Contains(b, "beta") {
		t.Fatalf("B activity leaked: %d %s", st, b)
	}

	st, b, _ = do(t, "GET", n.URL+"/v1/hosting/activity", n.Key, "")
	if st != 403 || codeOf(t, b) != "account_required" || strings.Contains(b, physA) || strings.Contains(b, physB) {
		t.Fatalf("non-account key: %d %s", st, b)
	}

	tokO, _ := signIn(t, n, f, ownerOK)
	st, b, _ = do(t, "GET", n.URL+"/v1/hosting/activity", tokO, "")
	if st != 200 || strings.Contains(b, physA) || strings.Contains(b, physB) || strings.Contains(b, "alpha") {
		t.Fatalf("owner activity must be only their own databases: %d %s", st, b)
	}
}
