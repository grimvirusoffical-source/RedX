package host_test

import (
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"redx/host"
	"redx/host/engineadapter"
)

// The real engine resolves empty-file queries, unique no-file REST gets, and
// link expands to a cert field without the request naming the cert file.
// The accounts service key may write the cert and still must not read it back.
// An owner session may.
func TestLifetimeCertResolvedReadsOnEngine(t *testing.T) {
	const secret = "RXSECRET-PRIVATE-ENC-CIPHERTEXT"
	const pub = "pk-engine-owner-pubkey"
	f, iss := startFake(t)
	n := startEngineAccounts(t, iss)
	tok, acct := signIn(t, n, f, ownerOK)
	if acct["owner"] != true {
		t.Fatalf("owner session was not elevated: %v", acct)
	}
	if st, b, _ := do(t, "POST", n.URL+"/v1/dbs", tok, `{"name":"redxai_accounts"}`); st != 201 && st != 409 {
		t.Fatalf("master db: %d %s", st, b)
	}
	st, b, _ := do(t, "POST", n.URL+"/v1/keys", tok, `{"db":"redxai_accounts","scope":"write","label":"accounts-service"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("service key: %d %s", st, b)
	}
	svc := jsonOf(t, b)["key"].(string)
	full := "rxa-lifetime-cert.red-xai.db:Record[ID=1]"
	cert := `[ {cert_id[]} = "cert-engine", {pubkey[]} = "` + pub + `", {private_enc[]} = "` + secret + `", {issued[]} = "issued-engine", {owner_emails[]} = ;["owner-emails-engine@example.com"]:, {sig_id_prefix[]} = "sig-engine" ]`
	if st, b, _ := do(t, "PUT", enginePath(n, full), svc, cert); st != 200 || strings.Contains(b, secret) || strings.Contains(b, pub) {
		t.Fatalf("service write cert: %d %s", st, b)
	}
	player := `[ {Name[]} = "ada", {Cert[]} = "players.red-xai.db":Player[ID=1] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1] ]`
	if st, b, _ := do(t, "PUT", enginePath(n, "players.red-xai.db:Player[ID=1]"), svc, player); st != 200 {
		t.Fatalf("player: %d %s", st, b)
	}
	steal := `[ {Name[]} = "ada", {Steal[]} = "players.red-xai.db":Player[ID=3] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].private_enc ]`
	if st, b, _ := do(t, "PUT", enginePath(n, "players.red-xai.db:Player[ID=3]"), svc, steal); st != 200 {
		t.Fatalf("steal: %d %s", st, b)
	}
	q := n.URL + "/v1/db/redxai_accounts/query"
	deny := func(who, what string, st int, body string) {
		t.Helper()
		if st != 403 || strings.Contains(body, secret) || strings.Contains(body, pub) || strings.Contains(body, "cert-engine") || strings.Contains(body, "issued-engine") || strings.Contains(body, "owner-emails-engine") || strings.Contains(body, "sig-engine") {
			t.Fatalf("%s %s: %d %s", who, what, st, body)
		}
	}
	for _, query := range []string{`*.pubkey`, `*.*`, `Record[ID=1].pubkey`, `Record[ID=1].*`, `*[ID=1].owner_emails`} {
		st, b, _ := do(t, "POST", q, svc, query)
		deny("service", "query "+query, st, b)
	}
	st, b, _ = do(t, "POST", q, svc, `{"q":"*.pubkey"}`, "Content-Type", "application/json")
	deny("service", "query json", st, b)
	st, b, _ = do(t, "GET", enginePath(n, "Record[ID=1].pubkey"), svc, "")
	deny("service", "rest pubkey", st, b)
	st, b, _ = do(t, "GET", enginePath(n, "Record[ID=1].pubkey"), svc, "", "Accept", "text/plain")
	deny("service", "rest text", st, b)
	st, b, _ = do(t, "GET", enginePath(n, "Record[ID=1].pubkey"), tok, "")
	if st != 200 || !strings.Contains(b, pub) || strings.Contains(b, secret) {
		t.Fatalf("owner bare pubkey: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=1].Cert.pubkey")+"?resolve=1", svc, "")
	deny("service", "resolve pubkey", st, b)
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=1].Cert.cert_id")+"?resolve=1&depth=4", svc, "")
	deny("service", "resolve cert_id", st, b)
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=3].Steal")+"?resolve=1", svc, "", "Accept", "text/plain")
	deny("service", "resolve private_enc", st, b)
	st, b, _ = do(t, "GET", enginePath(n, "rxa-lifetime-cert.red-xai:Record[ID=1].pubkey"), svc, "")
	deny("service", "short pubkey", st, b)
	if st, b, _ := do(t, "PUT", enginePath(n, "rxa-account.red-xai.db:Record[ID=1].idVerified"), svc, `{"value":true}`, "Content-Type", "application/json"); st != 200 || strings.Contains(b, secret) {
		t.Fatalf("service idVerified: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", enginePath(n, "Record[ID=1].pubkey"), svc, "")
	if st == 200 || strings.Contains(b, secret) || strings.Contains(b, pub) {
		t.Fatalf("service sibling REST: %d %s", st, b)
	}
	st, b, _ = do(t, "POST", q, svc, `Record[ID=1].*`)
	deny("service", "query star with sibling", st, b)
	st, b, _ = do(t, "POST", q, svc, `*.Name`)
	if st != 200 || !strings.Contains(b, "ada") || strings.Contains(b, secret) || strings.Contains(b, pub) {
		t.Fatalf("service query name: %d %s", st, b)
	}

	st, b, _ = do(t, "GET", enginePath(n, full), tok, "")
	if st != 200 || !strings.Contains(b, secret) || !strings.Contains(b, pub) {
		t.Fatalf("owner record: %d %s", st, b)
	}
	st, b, _ = do(t, "POST", q, tok, `*.pubkey`)
	if st != 200 || !strings.Contains(b, pub) || strings.Contains(b, secret) {
		t.Fatalf("owner query pubkey: %d %s", st, b)
	}
	st, b, _ = do(t, "POST", q, tok, `Record[ID=1].*`)
	if st != 200 || !strings.Contains(b, secret) || !strings.Contains(b, pub) {
		t.Fatalf("owner query star: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=1].Cert.pubkey")+"?resolve=1", tok, "")
	if st != 200 || !strings.Contains(b, pub) || strings.Contains(b, secret) {
		t.Fatalf("owner resolve pubkey: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=3].Steal")+"?resolve=1", tok, "", "Accept", "text/plain")
	if st != 200 || !strings.Contains(b, secret) {
		t.Fatalf("owner resolve private_enc: %d %s", st, b)
	}
	bagPub := `[ {Name[]} = "ada", {Bag[]} = ;["players.red-xai.db":Player[ID=8] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].pubkey]: ]`
	if st, b, _ := do(t, "PUT", enginePath(n, "players.red-xai.db:Player[ID=8]"), svc, bagPub); st != 200 || strings.Contains(b, pub) {
		t.Fatalf("service array pubkey link: %d %s", st, b)
	}
	bagSec := `[ {Name[]} = "ada", {Bag[]} = ;["players.red-xai.db":Player[ID=9] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].private_enc]: ]`
	if st, b, _ := do(t, "PUT", enginePath(n, "players.red-xai.db:Player[ID=9]"), svc, bagSec); st != 200 || strings.Contains(b, secret) {
		t.Fatalf("service array secret link: %d %s", st, b)
	}
	bagNest := `[ {Name[]} = "ada", {Wrap[]} = [ {Bag[]} = ;["players.red-xai.db":Player[ID=10] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].cert_id]: ] ]`
	if st, b, _ := do(t, "PUT", enginePath(n, "players.red-xai.db:Player[ID=10]"), svc, bagNest); st != 200 || strings.Contains(b, "cert-engine") {
		t.Fatalf("service nested array link: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=8].Bag")+"?resolve=1&depth=4", svc, "")
	deny("service", "resolve array pubkey", st, b)
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=8].Bag")+"?resolve=1", svc, "", "Accept", "text/plain")
	deny("service", "resolve array pubkey text", st, b)
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=9].Bag")+"?resolve=1", svc, "", "Accept", "text/plain")
	deny("service", "resolve array private_enc", st, b)
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=10].Wrap.Bag")+"?resolve=1&depth=4", svc, "")
	deny("service", "resolve nested array", st, b)
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=8].Bag")+"?resolve=1&depth=4", tok, "")
	if st != 200 || !strings.Contains(b, pub) || strings.Contains(b, secret) {
		t.Fatalf("owner resolve array pubkey: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=9].Bag")+"?resolve=1", tok, "", "Accept", "text/plain")
	if st != 200 || !strings.Contains(b, secret) {
		t.Fatalf("owner resolve array private_enc: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=10].Wrap.Bag")+"?resolve=1&depth=4", tok, "")
	if st != 200 || !strings.Contains(b, "cert-engine") || strings.Contains(b, secret) {
		t.Fatalf("owner resolve nested array: %d %s", st, b)
	}
	idBag := `[ {Name[]} = "ada", {Bag[ID=0]} = ;["players.red-xai.db":Player[ID=17] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].pubkey]: ]`
	if st, b, _ := do(t, "PUT", enginePath(n, "players.red-xai.db:Player[ID=17]"), svc, idBag); st != 200 || strings.Contains(b, pub) {
		t.Fatalf("service id array link: %d %s", st, b)
	}
	idSteal := `[ {Name[]} = "ada", {Steal[ID=1]} = "players.red-xai.db":Player[ID=20] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].private_enc ]`
	if st, b, _ := do(t, "PUT", enginePath(n, "players.red-xai.db:Player[ID=20]"), svc, idSteal); st != 200 || strings.Contains(b, secret) {
		t.Fatalf("service id field link: %d %s", st, b)
	}
	idLower := `[ {Name[]} = "ada", {Bag[id=7]} = ;["players.red-xai.db":Player[ID=25] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].owner_emails]: ]`
	if st, b, _ := do(t, "PUT", enginePath(n, "players.red-xai.db:Player[ID=25]"), svc, idLower); st != 200 || strings.Contains(b, "owner-emails-engine") {
		t.Fatalf("service lowercase id link: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=17].Bag")+"?resolve=1&depth=4", svc, "")
	deny("service", "resolve id array pubkey", st, b)
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=17].Bag[ID=0]")+"?resolve=1", svc, "")
	deny("service", "resolve id array with id", st, b)
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=20].Steal")+"?resolve=1", svc, "", "Accept", "text/plain")
	deny("service", "resolve id private_enc", st, b)
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=25].Bag")+"?resolve=1", svc, "", "Accept", "text/plain")
	deny("service", "resolve lowercase id", st, b)
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=17].Bag")+"?resolve=1&depth=4", tok, "")
	if st != 200 || !strings.Contains(b, pub) || strings.Contains(b, secret) {
		t.Fatalf("owner resolve id array pubkey: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=20].Steal")+"?resolve=1", tok, "", "Accept", "text/plain")
	if st != 200 || !strings.Contains(b, secret) {
		t.Fatalf("owner resolve id private_enc: %d %s", st, b)
	}
	negBag := `[ {Name[]} = "ada", {Bag[ID=-1]} = ;["players.red-xai.db":Player[ID=30] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].pubkey]: ]`
	if st, b, _ := do(t, "PUT", enginePath(n, "players.red-xai.db:Player[ID=30]"), svc, negBag); st != 200 || strings.Contains(b, pub) {
		t.Fatalf("service neg array link: %d %s", st, b)
	}
	negSec := `[ {Name[]} = "ada", {Bag[ID="-5"]} = ;["players.red-xai.db":Player[ID=34] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].owner_emails]: ]`
	if st, b, _ := do(t, "PUT", enginePath(n, "players.red-xai.db:Player[ID=34]"), svc, negSec); st != 200 || strings.Contains(b, "owner-emails-engine") {
		t.Fatalf("service string neg link: %d %s", st, b)
	}
	minSteal := `[ {Name[]} = "ada", {Steal[ID=-9223372036854775808]} = "players.red-xai.db":Player[ID=47] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].private_enc ]`
	if st, b, _ := do(t, "PUT", enginePath(n, "players.red-xai.db:Player[ID=47]"), svc, minSteal); st != 200 || strings.Contains(b, secret) {
		t.Fatalf("service min int link: %d %s", st, b)
	}
	sib := `[ {Name[]} = "ada", {Bag[ID=-20]} = ;["players.red-xai.db":Player[ID=50] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].private_enc]:, {Bag[ID=20]} = ;["safe-note"]: ]`
	if st, b, _ := do(t, "PUT", enginePath(n, "players.red-xai.db:Player[ID=50]"), svc, sib); st != 200 || strings.Contains(b, secret) {
		t.Fatalf("service sibling link: %d %s", st, b)
	}
	wide := `[ {Name[]} = "ada", {Bag[ID=1e20]} = ;["players.red-xai.db":Player[ID=37] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].pubkey]: ]`
	if st, b, _ := do(t, "PUT", enginePath(n, "players.red-xai.db:Player[ID=37]"), svc, wide); st != 200 || strings.Contains(b, pub) {
		t.Fatalf("service wide id link: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=30].Bag")+"?resolve=1&depth=4", svc, "")
	deny("service", "resolve neg array pubkey", st, b)
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=34].Bag")+"?resolve=1", svc, "", "Accept", "text/plain")
	deny("service", "resolve string neg", st, b)
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=47].Steal")+"?resolve=1", svc, "", "Accept", "text/plain")
	deny("service", "resolve min int", st, b)
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=50].Bag")+"?resolve=1", svc, "", "Accept", "text/plain")
	deny("service", "resolve sibling", st, b)
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=37].Bag")+"?resolve=1", svc, "")
	deny("service", "resolve wide id", st, b)
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=30].Bag")+"?resolve=1&depth=4", tok, "")
	if st != 200 || !strings.Contains(b, pub) || strings.Contains(b, secret) {
		t.Fatalf("owner resolve neg array pubkey: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", enginePath(n, "players.red-xai.db:Player[ID=47].Steal")+"?resolve=1", tok, "", "Accept", "text/plain")
	if st != 200 || !strings.Contains(b, secret) {
		t.Fatalf("owner resolve min int: %d %s", st, b)
	}
	raw, err := os.ReadFile(n.H.Cfg.AuditLog)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatalf("audit log contains ciphertext:\n%s", raw)
	}
}

func startEngineAccounts(t *testing.T, issuer string) *node {
	t.Helper()
	n := &node{Dir: t.TempDir()}
	n.Srv = httptest.NewUnstartedServer(nil)
	n.URL = "http://" + n.Srv.Listener.Addr().String()
	cfg := baseCfg(n.Dir)
	cfg.Advertise = n.URL
	cfg.ClusterKey = "engine-lifetime-test"
	cfg.AccountsIssuer = issuer
	cfg.AccountsClientSecret = "test-client-secret"
	cfg.AccountsEventsPoll = 3600
	cfg.OwnerEmails = []string{ownerA, ownerB}
	h, err := host.New(cfg, engineadapter.Opener(engineadapter.Config{SweepMS: 50}), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	n.H = h
	n.Key = h.BootstrapKey
	n.Srv.Config.Handler = h.Handler()
	n.Srv.Start()
	t.Cleanup(n.Stop)
	return n
}

func enginePath(n *node, p string) string {
	return n.URL + "/v1/db/redxai_accounts/path/" + url.PathEscape(p)
}
