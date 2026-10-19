package host_test

import (
	"strings"
	"testing"
)

func pagesOf(t *testing.T, body string) map[string]interface{} {
	t.Helper()
	p, _ := jsonOf(t, body)["pages"].(map[string]interface{})
	if p == nil {
		t.Fatalf("whoami has no pages: %s", body)
	}
	return p
}

func pageOn(p map[string]interface{}, id string) bool {
	v, _ := p[id].(bool)
	return v
}

func hostSurface(p map[string]interface{}) bool {
	for _, id := range []string{"usage", "logs", "hostapps", "deploy", "domains", "env", "applogs"} {
		if !pageOn(p, id) {
			return false
		}
	}
	return true
}

func TestConsolePagesFollowServerGates(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)

	tok, _ := signIn(t, n, f, regular)
	_, b, _ := do(t, "GET", n.URL+"/v1/ui/whoami", tok, "")
	if strings.Contains(b, ownerB) {
		t.Fatalf("whoami leaks another owner email: %s", b)
	}
	p := pagesOf(t, b)
	if pageOn(p, "owner") || pageOn(p, "updates") || pageOn(p, "keys") || !pageOn(p, "hosting") || !hostSurface(p) {
		t.Fatalf("regular pages: %s", b)
	}
	if jsonOf(t, b)["owner"] != false || jsonOf(t, b)["accounts"] != true {
		t.Fatalf("regular whoami: %s", b)
	}

	tok, _ = signIn(t, n, f, ownerUnverf)
	_, b, _ = do(t, "GET", n.URL+"/v1/ui/whoami", tok, "")
	acct, _ := jsonOf(t, b)["account"].(map[string]interface{})
	if acct["owner_blocked"] != "owner_email_unverified" || pageOn(pagesOf(t, b), "owner") {
		t.Fatalf("unverified owner: %s", b)
	}
	if strings.Contains(b, ownerB) {
		t.Fatalf("unverified whoami leaks the owner list: %s", b)
	}

	tok, _ = signIn(t, n, f, ownerOK)
	_, b, _ = do(t, "GET", n.URL+"/v1/ui/whoami", tok, "")
	m := jsonOf(t, b)
	if m["owner"] != true || m["host_admin"] != true || !pageOn(pagesOf(t, b), "owner") || !pageOn(pagesOf(t, b), "updates") || !pageOn(pagesOf(t, b), "backups") {
		t.Fatalf("owner pages: %s", b)
	}

	rk, _ := mkKey(t, n, map[string]interface{}{"scope": "read", "db": "default", "label": "limited"})
	_, b, _ = do(t, "GET", n.URL+"/v1/ui/whoami", rk, "")
	p = pagesOf(t, b)
	if pageOn(p, "owner") || pageOn(p, "keys") || pageOn(p, "updates") || pageOn(p, "backups") || !pageOn(p, "watch") || !pageOn(p, "hosting") || !hostSurface(p) {
		t.Fatalf("read key pages: %s", b)
	}
	if jsonOf(t, b)["owner"] != false {
		t.Fatalf("read key owner flag: %s", b)
	}

	_, b, _ = do(t, "GET", n.URL+"/v1/ui/whoami", n.Key, "")
	p = pagesOf(t, b)
	if !pageOn(p, "updates") || pageOn(p, "backups") || pageOn(p, "owner") || jsonOf(t, b)["host_admin"] != true {
		t.Fatalf("host-admin key with accounts on: %s", b)
	}

	// accounts off: a host admin sees backups (SeesEverything) and updates
	plain := startNode(t, t.TempDir(), nil)
	_, b, _ = do(t, "GET", plain.URL+"/v1/ui/whoami", plain.Key, "")
	p = pagesOf(t, b)
	if !pageOn(p, "backups") || !pageOn(p, "updates") || pageOn(p, "owner") || jsonOf(t, b)["accounts"] != false {
		t.Fatalf("accounts off: %s", b)
	}
}
