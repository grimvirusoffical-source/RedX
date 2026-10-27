package host_test

import (
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"redx/billing"
	"redx/host"
	"redx/host/accountsfake"
)

const lifetimeSecret = "RXSECRET-PRIVATE-ENC-CIPHERTEXT"

func certBody(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{"value": map[string]interface{}{
		"cert_id": "cert-1", "pubkey": "aabbcc", "private_enc": lifetimeSecret,
		"issued": "2026-01-01T00:00:00Z", "owner_emails": []string{ownerA}, "sig_id_prefix": "sig",
	}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func putPath(t *testing.T, n *node, db, key, path, body string) (int, string) {
	t.Helper()
	st, b, _ := do(t, "PUT", n.URL+"/v1/db/"+db+"/path/"+url.PathEscape(path), key, body, "Content-Type", "application/json")
	return st, b
}

func getPath(t *testing.T, n *node, db, key, path string) (int, string) {
	t.Helper()
	st, b, _ := do(t, "GET", n.URL+"/v1/db/"+db+"/path/"+url.PathEscape(path), key, "")
	return st, b
}

func assertNoSecret(t *testing.T, where, body string) {
	t.Helper()
	if strings.Contains(body, lifetimeSecret) {
		t.Fatalf("%s leaked private_enc: %s", where, body)
	}
}

func assertForbidden(t *testing.T, where string, st int, body string) {
	t.Helper()
	if st != 403 {
		t.Fatalf("%s: want 403, got %d %s", where, st, body)
	}
	assertNoSecret(t, where, body)
	if !strings.Contains(body, `"forbidden"`) {
		t.Fatalf("%s: denial body: %s", where, body)
	}
}

func openAccounts(t *testing.T) (*node, *accountsfake.Server, string, string) {
	t.Helper()
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	tok, acct := signIn(t, n, f, ownerOK)
	if acct["owner"] != true {
		t.Fatalf("owner: %v", acct)
	}
	if st, b, _ := do(t, "POST", n.URL+"/v1/dbs", tok, `{"name":"redxai_accounts"}`); st != 201 {
		t.Fatalf("master db: %d %s", st, b)
	}
	if st, b, _ := do(t, "POST", n.URL+"/v1/dbs", n.Key, `{"name":"game"}`); st != 201 {
		t.Fatalf("game db: %d %s", st, b)
	}
	st, b, _ := do(t, "POST", n.URL+"/v1/keys", tok, `{"db":"redxai_accounts","scope":"write","label":"red-xai-accounts service"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("service key: %d %s", st, b)
	}
	return n, f, tok, jsonOf(t, b)["key"].(string)
}

func TestLifetimeCertOwnerOnly(t *testing.T) {
	n, f, owner, svc := openAccounts(t)
	cert := `rxa-lifetime-cert.red-xai.db:Record[ID=1]`
	if st, b := putPath(t, n, "redxai_accounts", svc, cert, certBody(t)); st != 200 {
		t.Fatalf("service key stores the cert: %d %s", st, b)
	}
	// also a normal account row, so a prefix that is not the cert still returns data
	acct := `{"value":{"username":"ada","email":"ada@example.com"}}`
	if st, b := putPath(t, n, "redxai_accounts", svc, `account.red-xai.db:Record[ID=1]`, acct); st != 200 {
		t.Fatalf("account row: %d %s", st, b)
	}

	for _, p := range []string{
		cert,
		cert + ".private_enc",
		cert + ".pubkey",
		cert + ".cert_id",
		`rxa-lifetime-cert:Record[ID=1]`,
	} {
		st, b := getPath(t, n, "redxai_accounts", svc, p)
		assertForbidden(t, "service "+p, st, b)
	}
	st, b := getPath(t, n, "redxai_accounts", owner, cert)
	if st != 200 || !strings.Contains(b, lifetimeSecret) {
		t.Fatalf("owner reads the ciphertext: %d %s", st, b)
	}

	for _, q := range []string{
		`prefix:rxa-lifetime-cert.red-xai.db`,
		`prefix:rxa-lifetime-cert:`,
		`rxa-lifetime-cert.red-xai.db:Record[ID=1]`,
		`*`,
		`prefix:r`,
		`prefix:rxa`,
	} {
		st, b, _ := do(t, "POST", n.URL+"/v1/db/redxai_accounts/query", svc, q)
		assertForbidden(t, "query "+q, st, b)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/db/redxai_accounts/query", svc, `prefix:account.red-xai.db`)
	if st != 200 || strings.Contains(b, lifetimeSecret) || !strings.Contains(b, "ada") {
		t.Fatalf("account prefix: %d %s", st, b)
	}

	// host-admin cannot see the master db at all; the cert in a normal db is still owner-only
	if st, b := putPath(t, n, "game", n.Key, cert, certBody(t)); st != 200 {
		t.Fatalf("admin stores cert in game: %d %s", st, b)
	}
	if st, b := putPath(t, n, "game", n.Key, `game.red-xai.db:rxa-lifetime-cert[ID=1]`, certBody(t)); st != 200 {
		t.Fatalf("box-name form store: %d %s", st, b)
	}
	gameKey, _ := mkKey(t, n, map[string]interface{}{"scope": "write", "db": "game"})
	for _, key := range []struct{ name, k string }{{"admin", n.Key}, {"game-write", gameKey}} {
		st, b := getPath(t, n, "game", key.k, cert)
		assertForbidden(t, key.name+" cert", st, b)
		st, b = getPath(t, n, "game", key.k, cert+".private_enc")
		assertForbidden(t, key.name+" private_enc", st, b)
		st, b = getPath(t, n, "game", key.k, `game.red-xai.db:rxa-lifetime-cert[ID=1]`)
		assertForbidden(t, key.name+" box name", st, b)
		st, b, _ = do(t, "POST", n.URL+"/v1/db/game/query", key.k, `*`)
		assertForbidden(t, key.name+" star", st, b)
	}

	reg, _ := signIn(t, n, f, regular)
	st, b = getPath(t, n, "game", reg, cert)
	if st == 200 {
		t.Fatalf("regular session read the cert: %s", b)
	}
	assertNoSecret(t, "regular session", b)
	st, b = getPath(t, n, "redxai_accounts", reg, cert)
	if st == 200 {
		t.Fatalf("regular session read master cert: %s", b)
	}
	assertNoSecret(t, "regular session master", b)

	boxql := []string{
		`{Get[]} = "rxa-lifetime-cert.red-xai.db":Record[ID=1]`,
		`{Get[]} = "rxa-lifetime-cert.red-xai.db":Record[ID=1] -> pubkey`,
		`{Get[]} = rxa-lifetime-cert:Record[ID=1]`,
		`{Get[]} = "rxa-lifetime-cert.red-xai.db":*`,
		`{Get[]} = players:Player -> private_enc`,
		`{Watch[]} = "rxa-lifetime-cert.red-xai.db":Record`,
	}
	for _, q := range boxql {
		path := "/v1/db/game/bx"
		if strings.HasPrefix(q, "{Watch") {
			path = "/v1/db/game/bx/watch?q=" + url.QueryEscape(q)
			st, b, _ = do(t, "GET", n.URL+path, gameKey, "")
		} else {
			st, b, _ = do(t, "POST", n.URL+path, gameKey, q)
		}
		assertForbidden(t, "boxql "+q, st, b)
		if st == 501 {
			t.Fatalf("boxql fell through to the stub: %s", q)
		}
	}
	sub := "/v1/db/game/subscribe?path=" + url.QueryEscape(`rxa-lifetime-cert.red-xai.db:*`)
	st, b, _ = do(t, "GET", n.URL+sub, gameKey, "")
	assertForbidden(t, "subscribe", st, b)
	idx := "/v1/db/game/idx/players/ByName/query?mode=exact&field=private_enc&value=x"
	st, b, _ = do(t, "GET", n.URL+idx, gameKey, "")
	assertForbidden(t, "index", st, b)

	raw, err := os.ReadFile(n.H.Cfg.AuditLog)
	if err != nil {
		t.Fatal(err)
	}
	log := string(raw)
	assertNoSecret(t, "audit", log)
	if !strings.Contains(log, `"reason":"lifetime cert is owner-only"`) {
		t.Fatalf("audit missing the static denial reason:\n%s", log)
	}
}

func TestIDVerifiedDeployOwnerOnly(t *testing.T) {
	n, f, owner, svc := openAccounts(t)
	rec := `rxa-account.red-xai.db:Record[ID=1]`
	flag := rec + ".idVerified"
	flagMs := rec + ".idVerifiedMs"

	if st, b := putPath(t, n, "redxai_accounts", svc, flag, `{"value":true}`); st != 200 {
		t.Fatalf("service sets idVerified: %d %s", st, b)
	}
	st, b := getPath(t, n, "redxai_accounts", svc, flag)
	if st != 200 || !strings.Contains(b, "TRUE") {
		t.Fatalf("service reads the flag it set: %d %s", st, b)
	}
	if st, b := putPath(t, n, "redxai_accounts", owner, flagMs, `{"value":9}`); st != 200 {
		t.Fatalf("owner sets idVerifiedMs: %d %s", st, b)
	}
	if st, b := putPath(t, n, "redxai_accounts", svc, rec, `{"value":{"username":"ada"}}`); st != 200 {
		t.Fatalf("service replace without the flag: %d %s", st, b)
	}

	gameKey, _ := mkKey(t, n, map[string]interface{}{"scope": "write", "db": "game"})
	for _, key := range []struct{ name, k string }{{"admin", n.Key}, {"game-write", gameKey}} {
		st, b := putPath(t, n, "game", key.k, flag, `{"value":true}`)
		assertForbidden(t, key.name+" put idVerified", st, b)
		if jsonOf(t, b)["error"] != "forbidden" {
			t.Fatalf("%s body: %s", key.name, b)
		}
		st, b = putPath(t, n, "game", key.k, flagMs, `{"value":1}`)
		assertForbidden(t, key.name+" put idVerifiedMs", st, b)
		st, b = putPath(t, n, "game", key.k, rec, `{"value":{"username":"ada","idVerified":true,"idVerifiedMs":1}}`)
		assertForbidden(t, key.name+" put record", st, b)
		st, b, _ = do(t, "DELETE", n.URL+"/v1/db/game/path/"+url.PathEscape(flag), key.k, "")
		assertForbidden(t, key.name+" delete idVerified", st, b)
		q := `{Set[]} = "rxa-account.red-xai.db":Record[ID=1].idVerified = TRUE`
		st, b, _ = do(t, "POST", n.URL+"/v1/db/game/bx", key.k, q)
		assertForbidden(t, key.name+" boxql", st, b)
		st, b = getPath(t, n, "game", key.k, flag)
		if st == 200 && (strings.Contains(b, "TRUE") || strings.Contains(b, "true")) {
			t.Fatalf("%s stored idVerified: %s", key.name, b)
		}
	}
	if st, b := putPath(t, n, "game", gameKey, rec+".username", `{"value":"ada"}`); st != 200 {
		t.Fatalf("username: %d %s", st, b)
	}
	if st, b := putPath(t, n, "game", gameKey, rec, `{"value":{"username":"ada"}}`); st != 200 {
		t.Fatalf("replace without flag: %d %s", st, b)
	}
	st, b, _ = do(t, "DELETE", n.URL+"/v1/db/game/path/"+url.PathEscape(rec), gameKey, "")
	if st != 200 {
		t.Fatalf("delete whole record: %d %s", st, b)
	}
	if st, b := putPath(t, n, "game", owner, flag, `{"value":true}`); st != 200 {
		t.Fatalf("owner sets idVerified on game: %d %s", st, b)
	}
	// the service key is allowed through the flag gate; the stub has no BoxQL engine
	q := `{Set[]} = "rxa-account.red-xai.db":Record[ID=1].idVerified = TRUE`
	st, b, _ = do(t, "POST", n.URL+"/v1/db/redxai_accounts/bx", svc, q)
	if st == 403 {
		t.Fatalf("service BoxQL set of idVerified must pass the flag gate: %d %s", st, b)
	}

	// a hosted tenant is a public caller: it may store a cert and still may not read it back,
	// and it may not set idVerified
	tok, _ := signIn(t, n, f, regular)
	if err := host.SetPlanForTest(n.H, billing.Plan{
		Account: regular.Sub, Tier: "basic", Interval: "month", Status: "active",
		PeriodEnd: time.Now().Add(30 * 24 * time.Hour), Subscription: "sub_test", Customer: "cus_test", Updated: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/dbs", tok, `{"name":"game"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("tenant db: %d %s", st, b)
	}
	phys, _ := jsonOf(t, b)["name"].(string)
	if st, b := putPath(t, n, phys, tok, `rxa-lifetime-cert.red-xai.db:Record[ID=1]`, certBody(t)); st != 200 {
		t.Fatalf("tenant stores cert: %d %s", st, b)
	}
	st, b = getPath(t, n, phys, tok, `rxa-lifetime-cert.red-xai.db:Record[ID=1]`)
	assertForbidden(t, "tenant cert read", st, b)
	st, b = getPath(t, n, phys, tok, `rxa-lifetime-cert.red-xai.db:Record[ID=1].private_enc`)
	assertForbidden(t, "tenant private_enc", st, b)
	st, b = putPath(t, n, phys, tok, flag, `{"value":true}`)
	assertForbidden(t, "tenant idVerified", st, b)
	if st, b := putPath(t, n, phys, tok, rec+".username", `{"value":"ada"}`); st != 200 {
		t.Fatalf("tenant username: %d %s", st, b)
	}

	raw, err := os.ReadFile(n.H.Cfg.AuditLog)
	if err != nil {
		t.Fatal(err)
	}
	log := string(raw)
	assertNoSecret(t, "audit", log)
	if !strings.Contains(log, `"reason":"idVerified is deploy/owner only"`) {
		t.Fatalf("audit missing the flag denial:\n%s", log)
	}
}

func TestBackupHidesLifetimeCertFromNonOwners(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	tok, _ := signIn(t, n, f, ownerOK)
	if st, b, _ := do(t, "POST", n.URL+"/v1/dbs", tok, `{"name":"redxai_accounts"}`); st != 201 {
		t.Fatalf("master: %d %s", st, b)
	}
	if st, b := putPath(t, n, "redxai_accounts", tok, `rxa-lifetime-cert.red-xai.db:Record[ID=1]`, certBody(t)); st != 200 {
		t.Fatalf("owner stores cert: %d %s", st, b)
	}
	st, b, _ := do(t, "GET", n.URL+"/v1/admin/backup", n.Key, "")
	assertForbidden(t, "accounts-on admin backup", st, b)
	st, b, _ = do(t, "POST", n.URL+"/v1/keys", tok, `{"db":"redxai_accounts","scope":"admin","label":"svc-admin"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("mint: %d %s", st, b)
	}
	svc := jsonOf(t, b)["key"].(string)
	st, b, _ = do(t, "GET", n.URL+"/v1/admin/backup", svc, "")
	if st == 200 {
		t.Fatalf("service key exported a backup:\n%s", b)
	}
	assertNoSecret(t, "service backup", b)
	st, b, _ = do(t, "GET", n.URL+"/v1/admin/backup", tok, "")
	if st != 200 {
		t.Fatalf("owner backup: %d %s", st, b)
	}

	// accounts off: host-admin backup is allowed until a cert is actually stored
	off := startNode(t, t.TempDir(), nil)
	st, b, _ = do(t, "GET", off.URL+"/v1/admin/backup", off.Key, "")
	if st != 200 {
		t.Fatalf("backup with no cert: %d %s", st, b)
	}
	if st, b := putPath(t, off, "default", off.Key, `rxa-lifetime-cert.red-xai.db:Record[ID=1]`, certBody(t)); st != 200 {
		t.Fatalf("store cert: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", off.URL+"/v1/admin/backup", off.Key, "")
	assertForbidden(t, "accounts-off backup", st, b)
	if st, _, _ := do(t, "DELETE", off.URL+"/v1/db/default/path/"+url.PathEscape(`rxa-lifetime-cert.red-xai.db:Record[ID=1]`), off.Key, ""); st != 200 {
		t.Fatalf("delete cert: %d", st)
	}
	st, b, _ = do(t, "GET", off.URL+"/v1/admin/backup", off.Key, "")
	if st != 200 {
		t.Fatalf("backup after the cert is gone: %d %s", st, b)
	}
	assertNoSecret(t, "backup after delete", b)
}
