package host_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"redx/host"
	"redx/host/accountsfake"
)

// H1: host-admin BX / subscribe paths must not read the master accounts DB (authzScope + Hides).
func TestMasterDBHiddenFromAuthzScopeRoutes(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	tok, _ := signIn(t, n, f, ownerOK)
	seedMaster(t, n, tok)
	admin := n.Key // host-wide admin API key, NOT an owner

	body := `{"q":"{Get[]} = account:Record[ID=1]"}`
	st, b, _ := do(t, "POST", n.URL+"/v1/db/redxai_accounts/bx", admin, body, "Content-Type", "application/json")
	if st != 404 || strings.Contains(b, "passHash") || strings.Contains(b, "argon2id") {
		t.Fatalf("host-admin BX Get on master must 404 without secrets, got %d %s", st, b)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/db/redxai_accounts/bx", admin, `{"q":"{Get[]} = account:Record[*]"}`, "Content-Type", "application/json")
	if st != 404 || strings.Contains(b, "passHash") {
		t.Fatalf("host-admin BX scan on master must 404, got %d %s", st, b)
	}
	for _, path := range []string{
		"/v1/db/redxai_accounts/subscribe",
		"/v1/db/redxai_accounts/pulse/subscribe",
		"/v1/db/redxai_accounts/bx/watch",
	} {
		st, b, _ := do(t, "GET", n.URL+path, admin, "")
		if st == 101 || st == 200 || strings.Contains(b, "passHash") {
			t.Fatalf("%s must refuse non-owners, got %d %s", path, st, b)
		}
		if st != 404 && st != 403 {
			t.Fatalf("%s: want 404/403, got %d %s", path, st, b)
		}
	}
}

// H2: host-admin must not DELETE (or recreate) the master accounts DB.
func TestMasterDBDropRefusedForNonOwner(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	tok, _ := signIn(t, n, f, ownerOK)
	seedMaster(t, n, tok)
	admin := n.Key

	st, b, _ := do(t, "DELETE", n.URL+"/v1/db/redxai_accounts?confirm=redxai_accounts", admin, "")
	if st == 200 {
		t.Fatalf("host-admin deleted the master DB: %s", b)
	}
	if st != 403 && st != 404 {
		t.Fatalf("drop master: want 403/404, got %d %s", st, b)
	}
	// still there for the owner
	if st, _, _ := do(t, "GET", n.URL+"/v1/owner/accounts", tok, ""); st != 200 {
		t.Fatalf("master must still exist for owner after refused drop: %d", st)
	}
	// owner may drop (optional capability) — we only require non-owner refusal here
}

// H3: host-admin must not repoint the node while Accounts protects the master DB.
func TestClusterRepointOwnerOnlyWhenAccountsOn(t *testing.T) {
	_, iss := startFake(t)
	n := startAcctNode(t, iss)
	admin := n.Key
	body := `{"url":"http://127.0.0.1:9","join_token":"x"}`
	st, b, _ := do(t, "POST", n.URL+"/v1/cluster/leader", admin, body, "Content-Type", "application/json")
	if st == 200 {
		t.Fatalf("host-admin repointed while accounts on: %s", b)
	}
	if st != 403 {
		t.Fatalf("repoint: want 403, got %d %s", st, b)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/cluster/promote", admin, `{}`, "Content-Type", "application/json")
	if st == 200 {
		t.Fatalf("host-admin promote while accounts on: %s", b)
	}
	if st != 403 {
		t.Fatalf("promote: want 403, got %d %s", st, b)
	}
}

// H3b: a non-owner host-admin must not persist a join link, or change role or advertise, by applying
// a preset. The next ordinary start redeems join (cmd/redxd) and can replace the master accounts DB.
// The owner still can. The audit records the join leader URL and never the one-time secret.
func TestPresetApplyJoinOwnerOnlyWhenAccountsOn(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	admin := n.Key
	const (
		secret = "rxj_ATTACKERTOKEN"
		leader = "http://127.0.0.1:9"
	)
	joinBody := `{"join":"` + leader + " " + secret + `"}`
	cfgPath := filepath.Join(n.Dir, "redx.toml")
	apply := func(key, name, body string) (int, string) {
		t.Helper()
		st, b, _ := do(t, "POST", n.URL+"/v1/admin/presets/"+name+"/apply", key, body, "Content-Type", "application/json")
		return st, b
	}
	assertNoPersist := func() {
		t.Helper()
		b, err := os.ReadFile(cfgPath)
		if err == nil && (strings.Contains(string(b), secret) || strings.Contains(string(b), "attacker.example")) {
			t.Fatalf("preset apply persisted a cluster change:\n%s", b)
		}
	}
	denied := func(name, body string) {
		t.Helper()
		st, b := apply(admin, name, body)
		if st != 403 {
			t.Fatalf("POST presets/%s/apply as host-admin: want 403, got %d %s", name, st, b)
		}
		if !strings.Contains(b, "only an owner login can do this on this host") {
			t.Fatalf("owner-denied body: %s", b)
		}
		if strings.Contains(b, secret) {
			t.Fatalf("denial echoed the join secret: %s", b)
		}
		assertNoPersist()
	}

	denied("cluster", joinBody)
	denied("cluster", `{"join":"`+leader+" "+secret+`","dry_run":true}`)
	// join override on a leader preset: Validate would force role=follower on the next start
	denied("website", `{"overrides":{"join":"`+leader+" "+secret+`"}}`)
	denied("website", `{"overrides":{"role":"follower"},"join":"`+leader+" "+secret+`"}`)
	denied("website", `{"overrides":{"advertise":"http://attacker.example:7777"}}`)

	// unchanged role / advertise, no join: still host-admin (the preset's other settings)
	if st, b := apply(admin, "website", `{"overrides":{"role":"leader"}}`); st != 200 {
		t.Fatalf("host-admin applying a leader preset that does not change cluster settings: want 200, got %d %s", st, b)
	}
	assertNoPersist()

	tok, acct := signIn(t, n, f, ownerOK)
	if acct["owner"] != true {
		t.Fatalf("owner sign-in: %v", acct)
	}
	st, b := apply(tok, "cluster", joinBody)
	if st != 200 {
		t.Fatalf("owner applying cluster with join: want 200, got %d %s", st, b)
	}
	written, err := os.ReadFile(cfgPath)
	if err != nil || !strings.Contains(string(written), secret) || !strings.Contains(string(written), `preset = "cluster"`) {
		t.Fatalf("owner apply must persist the join link: %v\n%s", err, written)
	}
	raw, err := os.ReadFile(n.H.Cfg.AuditLog)
	if err != nil {
		t.Fatal(err)
	}
	log := string(raw)
	if !strings.Contains(log, `"reason":"owner-only on this host"`) || !strings.Contains(log, `"/v1/admin/presets/cluster/apply"`) {
		t.Fatalf("denial audit missing owner-only reason:\n%s", log)
	}
	if !strings.Contains(log, `"event":"preset.apply"`) || !strings.Contains(log, `"detail":"cluster join=`+leader+`"`) {
		t.Fatalf("apply audit must record the preset and the join leader URL:\n%s", log)
	}
	if strings.Contains(log, secret) || strings.Contains(log, "ATTACKER") {
		t.Fatalf("audit log contains the join secret:\n%s", log)
	}
}

// H4: Kelvin sign and other Unicode lookalikes must never match a listed owner email.
func TestOwnerEmailFoldRejectsKelvinAndLookalikes(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	// REDXAI_OWNER_EMAILS already has owner@example.com / support-owner@example.com (ASCII).
	// Sign in with Kelvin-K "Kate@example.com" against a host that lists kate@example.com.
	n2 := startNode(t, t.TempDir(), func(c *host.Config, u string) {
		c.AccountsIssuer = iss
		c.AccountsClientSecret = "test-client-secret"
		c.AccountsEventsPoll = 3600
		c.OwnerEmails = []string{"kate@example.com"}
	})
	kelvin := "\u212A" + "ate@example.com" // Kate@example.com
	id := accountsfake.Identity{Sub: "rxa_KELVIN00000000000000000001", Email: kelvin, EmailVerified: true,
		Username: "kelvin_spoof", AMR: []string{"pwd", "otp"}, OwnerScope: true}
	tok, acct := signIn(t, n2, f, id)
	if acct["owner"] == true || acct["owner_blocked"] != nil && acct["owner_blocked"] != "" && acct["owner"] == true {
		t.Fatalf("Kelvin spoof became owner: %v", acct)
	}
	if acct["owner"] != false {
		t.Fatalf("Kelvin spoof: %v", acct)
	}
	if st, _, _ := do(t, "GET", n2.URL+"/v1/owner/accounts", tok, ""); st != 403 {
		t.Fatalf("Kelvin spoof must not reach owner routes: %d", st)
	}
	// Config must refuse a non-ASCII owner email
	c := host.DefaultConfig()
	c.AccountsIssuer = "http://127.0.0.1:9"
	c.AccountsClientSecret = "dev"
	c.OwnerEmails = []string{kelvin}
	if err := c.Validate(); err == nil {
		t.Fatal("owner_emails with Kelvin must be refused at Validate")
	}
	_ = n
	// sanity: plain kate still works
	id2 := accountsfake.Identity{Sub: "rxa_KATE0000000000000000000001", Email: "Kate@Example.com", EmailVerified: true,
		Username: "kate_ok", AMR: []string{"pwd", "otp"}, OwnerScope: true}
	_, acct2 := signIn(t, n2, f, id2)
	if acct2["owner"] != true {
		t.Fatalf("ASCII kate must be owner: %v", acct2)
	}
}

func TestFoldEmailASCIIOnly(t *testing.T) {
	// Document the Go trap this regression guards: strings.ToLower maps Kelvin U+212A → ASCII k.
	lowered := strings.ToLower("Kate@example.com")
	if lowered != "kate@example.com" {
		t.Fatalf("expected strings.ToLower(Kelvin…) == kate@… (Go trap), got %q", lowered)
	}
}

func TestMasterDBCreateReservedForNonOwner(t *testing.T) {
	_, iss := startFake(t)
	n := startAcctNode(t, iss)
	admin := n.Key
	st, b, _ := do(t, "POST", n.URL+"/v1/dbs", admin, `{"name":"redxai_accounts"}`, "Content-Type", "application/json")
	if st == 201 {
		t.Fatalf("host-admin created master DB: %s", b)
	}
	if st != 403 {
		t.Fatalf("create master: want 403, got %d %s", st, b)
	}
}
