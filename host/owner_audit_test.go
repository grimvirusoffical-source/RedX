package host_test

import (
	"strings"
	"testing"
)

func TestOwnerAuditFiltersAndPaging(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)

	tokR, _ := signIn(t, n, f, regular)
	st, b, _ := do(t, "GET", n.URL+"/v1/owner/audit", tokR, "")
	if st != 403 || strings.Contains(b, ownerB) || strings.Contains(b, "reason") {
		t.Fatalf("non-owner audit: %d %s", st, b)
	}

	tok, _ := signIn(t, n, f, ownerOK)
	if st, b, _ = do(t, "GET", n.URL+"/v1/owner/overview", tok, ""); st != 200 {
		t.Fatalf("overview: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", n.URL+"/v1/owner/audit?limit=50", tok, "")
	if st != 200 || !strings.Contains(b, `"event":"owner.read"`) || !strings.Contains(b, "/v1/owner/audit") {
		t.Fatalf("audit: %d %s", st, b)
	}
	total, _ := jsonOf(t, b)["total"].(float64)
	if total < 1 {
		t.Fatalf("total: %s", b)
	}

	st, b, _ = do(t, "GET", n.URL+"/v1/owner/audit?event=owner.read&limit=10", tok, "")
	if st != 200 || !strings.Contains(b, "owner.read") || strings.Contains(b, `"event":"auth.`) {
		t.Fatalf("event filter: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", n.URL+"/v1/owner/audit?q="+ownerA+"&limit=20", tok, "")
	if st != 200 || !strings.Contains(b, "owner.read") {
		t.Fatalf("q filter: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", n.URL+"/v1/owner/audit?event=no-such-event", tok, "")
	if st != 200 || jsonOf(t, b)["total"] != float64(0) {
		t.Fatalf("empty filter: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", n.URL+"/v1/owner/audit?limit=1&offset=0", tok, "")
	ev, _ := jsonOf(t, b)["events"].([]interface{})
	if st != 200 || len(ev) != 1 || jsonOf(t, b)["limit"] != float64(1) {
		t.Fatalf("page: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", n.URL+"/v1/owner/audit?limit=1&offset=100000", tok, "")
	ev, _ = jsonOf(t, b)["events"].([]interface{})
	if st != 200 || len(ev) != 0 || jsonOf(t, b)["offset"].(float64) < 1 {
		t.Fatalf("past end: %d %s", st, b)
	}
}
