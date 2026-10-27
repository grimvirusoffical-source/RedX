package host

import (
	"encoding/json"
	"strings"
	"testing"

	"redx/engine/query"
)

const certSecret = "RXSECRET-PRIVATE-ENC-CIPHERTEXT"

func TestPathAndTextLifetimeCert(t *testing.T) {
	for _, p := range []string{
		`rxa-lifetime-cert.red-xai.db:Record[ID=1]`,
		`rxa-lifetime-cert.red-xai.db:Record[ID=1].private_enc`,
		`rxa-lifetime-cert.red-xai.db:Record[ID=1].pubkey`,
		`rxa-lifetime-cert.red-xai.db:Record[ID=1].cert_id`,
		`rxa-lifetime-cert:Record[ID=1]`,
		`"rxa-lifetime-cert.red-xai.db":Record[ID=1]`,
		`game.red-xai.db:rxa-lifetime-cert[ID=1]`,
		`players.red-xai.db:Player[ID=1].private_enc`,
		`rxa-lifetime-cert.red-xai:Record[ID=1].pubkey`,
		`rxa-lifetime-cert.red-xai:Record[ID=1].cert_id`,
		`rxa-lifetime-cert.red-xai:Record[ID=1].owner_emails`,
		`rxa-lifetime-cert.red-xai:Record[ID=1].issued`,
		`rxa-lifetime-cert.red-xai:Record[ID=1].sig_id_prefix`,
		`"rxa-lifetime-cert.red-xai":Record[ID=1]`,
	} {
		if !PathReadsLifetimeSecret(p) {
			t.Errorf("path should be a cert read: %s", p)
		}
	}
	for _, p := range []string{
		`account.red-xai.db:Record[ID=1]`,
		`rxa-account.red-xai.db:Record[ID=1]`,
		`rxa-account.red-xai.db:Record[ID=1].username`,
		`players.red-xai.db:Player[ID=1].pubkey`,
		`r`,
		`rxa:Record[ID=1].pubkey`,
		`rx:Record[ID=1].cert_id`,
		`rxa-lifetime:Record[ID=1].sig_id_prefix`,
		`rxa-lifetime-cert.red:Record[ID=1].issued`,
		`notes.red-xai.db:Note[ID=1].text`,
	} {
		if PathReadsLifetimeSecret(p) {
			t.Errorf("path should not be a cert read: %s", p)
		}
	}
	raw, err := json.Marshal(map[string]interface{}{
		"cert_id": "c1", "pubkey": "abcd", "private_enc": certSecret,
		"issued": "2026-01-01", "owner_emails": []string{"owner@example.com"}, "sig_id_prefix": "sig",
	})
	if err != nil {
		t.Fatal(err)
	}
	boxText, err := JSONToBox(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(boxText, certSecret) {
		t.Fatalf("box text lost the ciphertext: %s", boxText)
	}
	if !TextIsLifetimeCert(boxText) {
		t.Fatalf("stored box text was not recognised as a cert: %s", boxText)
	}
	if !TextIsLifetimeCert(`{"cert_id":"c1","pubkey":"aa"}`) {
		t.Fatal("json cert body without private_enc")
	}
	if !TextIsLifetimeCert(`{"user":{"private_enc":"x"}}`) {
		t.Fatal("nested private_enc")
	}
	if TextIsLifetimeCert(`{"username":"ada","pubkey":"aa"}`) || TextIsLifetimeCert(`[ {username[]} = "ada" ]`) {
		t.Fatal("ordinary record looked like a cert")
	}
	if got := redactAuditReason("bx: " + boxText); got != "lifetime cert is owner-only" || strings.Contains(got, certSecret) {
		t.Fatalf("audit redact: %s", got)
	}
	if got := redactAuditReason("script read private_enc=" + certSecret); strings.Contains(got, certSecret) || got != "lifetime cert is owner-only" {
		t.Fatalf("audit redact field: %s", got)
	}
}

func TestAccountFlagWriteForbidden(t *testing.T) {
	raw, err := JSONToBox([]byte(`{"username":"ada","idVerified":true,"idVerifiedMs":9}`))
	if err != nil {
		t.Fatal(err)
	}
	if !AccountFlagWriteForbidden(`rxa-account.red-xai.db:Record[ID=1]`, raw) {
		t.Fatal("record body carrying idVerified")
	}
	if !AccountFlagWriteForbidden(`rxa-account.red-xai.db:Record[ID=1].idVerified`, `TRUE`) {
		t.Fatal("field path")
	}
	if !AccountFlagWriteForbidden(`rxa-account:Record[ID=1].idVerifiedMs`, `1`) {
		t.Fatal("short file field path")
	}
	if !AccountFlagWriteForbidden(`rxa-account.red-xai:Record[ID=1].idVerified`, `TRUE`) {
		t.Fatal("engine prefix of the account file")
	}
	if !AccountFlagWriteForbidden(`game.red-xai.db:rxa-account[ID=1]`, `[ {profile[]} = [ {idVerified[]} = TRUE ] ]`) {
		t.Fatal("nested flag on the account box")
	}
	if AccountFlagWriteForbidden(`rxa-account.red-xai.db:Record[ID=1]`, `[ {username[]} = "ada" ]`) {
		t.Fatal("replace that omits the flag is allowed")
	}
	if AccountFlagWriteForbidden(`rxa-account.red-xai.db:Record[ID=1].username`, `"ada"`) {
		t.Fatal("username write")
	}
	if AccountFlagWriteForbidden(`players.red-xai.db:Player[ID=1]`, raw) {
		t.Fatal("flag names on another kind are not the account gate")
	}
	if !ScriptCertReadBlocked(`rxa-lifetime-cert.red-xai.db:Record[ID=1]`, "pubkey") {
		t.Fatal("script read of the cert record")
	}
	if !ScriptCertReadBlocked(`players.red-xai.db:Player[ID=1]`, "stats.private_enc") {
		t.Fatal("script read of private_enc")
	}
	if ScriptCertReadBlocked(`players.red-xai.db:Player[ID=1]`, "Name") {
		t.Fatal("ordinary script read")
	}
}

func TestGuardBoxQL(t *testing.T) {
	reads := []string{
		`{Get[]} = "rxa-lifetime-cert.red-xai.db":Record[ID=1]`,
		`{Get[]} = "rxa-lifetime-cert.red-xai.db":Record[ID=1] -> pubkey`,
		`{Get[]} = "rxa-lifetime-cert.red-xai.db":Record[ID=1] -> cert_id`,
		`{Get[]} = rxa-lifetime-cert:Record[ID=1]`,
		`{Get[]} = "rxa-lifetime-cert.red-xai.db":*`,
		`{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> pubkey`,
		`{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> owner_emails`,
		`{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> issued`,
		`{Watch[]} = "rxa-lifetime-cert.red-xai":Record`,
		`{Get[]} = players:Player -> private_enc`,
		`{Get[]} = players:Player[private_enc = "x"] -> Name`,
		`{Watch[]} = "rxa-lifetime-cert.red-xai.db":Record`,
		`{Explain[]} = [ {Get[]} = "rxa-lifetime-cert.red-xai.db":Record[ID=1] ]`,
	}
	for _, q := range reads {
		r, w := guardBoxQL(q)
		if !r || w {
			t.Errorf("want cert read: %s (read=%v write=%v)", q, r, w)
		}
	}
	writes := []string{
		`{Set[]} = "rxa-account.red-xai.db":Record[ID=1].idVerified = TRUE`,
		`{Set[]} = "rxa-account.red-xai":Record[ID=1].idVerified = TRUE`,
		`{Set[]} = "rxa-account.red-xai.db":Record[ID=1].idVerifiedMs = 1`,
		`{Set[]} = "rxa-account.red-xai.db":Record[ID=1] = [ {username[]} = "ada", {idVerified[]} = TRUE ]`,
		`{Add[]} = "rxa-account.red-xai.db":Record[ID=2] = [ {username[]} = "a", {profile[]} = [ {idVerified[]} = TRUE ] ]`,
		`{Delete[]} = "rxa-account.red-xai.db":Record[ID=1].idVerified`,
		`{Delete[]} = "rxa-account.red-xai.db":Record[ID=1].idVerifiedMs`,
	}
	for _, q := range writes {
		r, w := guardBoxQL(q)
		if r || !w {
			t.Errorf("want flag write: %s (read=%v write=%v)", q, r, w)
		}
	}
	allowed := []string{
		`{Set[]} = "rxa-lifetime-cert.red-xai.db":Record[ID=1].private_enc = "cipher"`,
		`{Set[]} = "rxa-lifetime-cert.red-xai":Record[ID=1].issued = "x"`,
		`{Set[]} = "rxa-account.red-xai.db":Record[ID=1].username = "ada"`,
		`{Set[]} = "rxa-account.red-xai.db":Record[ID=1] = [ {username[]} = "ada" ]`,
		`{Delete[]} = "rxa-account.red-xai.db":Record[ID=1]`,
		`{Get[]} = "rxa-account.red-xai.db":Record[ID=1] -> username`,
		`{Get[]} = players:Player -> Name`,
	}
	for _, q := range allowed {
		r, w := guardBoxQL(q)
		if r || w {
			t.Errorf("want neither gate: %s (read=%v write=%v)", q, r, w)
		}
	}
	if r, w := guardBoxQL(`{Get[]} = file:Record[ID=1].pubkey`); r || w {
		t.Fatalf("syntax error must stay a syntax error, not a gate: %v %v", r, w)
	}
	// parse failure is the contract; confirm the sample really does not parse
	if _, _, err := query.Parse(`{Get[]} = file:Record[ID=1].pubkey`); err == nil {
		t.Fatal("expected a syntax error")
	}
}

func TestQueryAndSubscribeCertSelectors(t *testing.T) {
	for _, q := range []string{
		`prefix:rxa-lifetime-cert.red-xai.db`,
		`prefix:rxa-lifetime-cert.red-xai.db:Record`,
		`prefix:rxa-lifetime-cert:`,
		`rxa-lifetime-cert.red-xai.db:Record[ID=1]`,
		`rxa-lifetime-cert.red-xai.db:Record[ID=1].pubkey`,
	} {
		if !queryReadsLifetimeCert(q) {
			t.Errorf("explicit cert query: %s", q)
		}
	}
	for _, q := range []string{
		`prefix:rxa-lifetime-cert.red-xai`,
		`prefix:rxa-lifetime-cert.red-xai:Record`,
		`rxa-lifetime-cert.red-xai:Record[ID=1].pubkey`,
	} {
		if !queryReadsLifetimeCert(q) {
			t.Errorf("engine prefix is a cert query: %s", q)
		}
	}
	for _, q := range []string{`*`, `prefix:`, `prefix:r`, `prefix:rxa`, `prefix:rxa-lifetime`, `prefix:account.red-xai.db`, `account.red-xai.db:Record[ID=1]`} {
		if queryReadsLifetimeCert(q) {
			t.Errorf("not an explicit cert query: %s", q)
		}
	}
	if !subscribeTargetsCert(`rxa-lifetime-cert.red-xai.db:*`) || !subscribeTargetsCert(`rxa-lifetime-cert.red-xai.db:Record[ID=*]`) ||
		!subscribeTargetsCert(`rxa-lifetime-cert.red-xai:*`) || !subscribeTargetsCert(`rxa-lifetime-cert.red-xai:Record[ID=1].pubkey`) {
		t.Fatal("subscribe to the cert kind")
	}
	if subscribeTargetsCert(`*`) || subscribeTargetsCert(`account.red-xai.db:*`) || subscribeTargetsCert(`players.red-xai.db:Player`) {
		t.Fatal("broad or other-kind subscribe")
	}
}

func TestBXResultLeakScan(t *testing.T) {
	if !bxLeaksLifetimeCert(BXResult{Columns: []string{"name", "private_enc"}}) {
		t.Fatal("column")
	}
	if !bxLeaksLifetimeCert(BXResult{Paths: []string{"rxa-lifetime-cert.red-xai.db:Record[ID=1]"}}) {
		t.Fatal("path")
	}
	if !bxLeaksLifetimeCert(BXResult{Followed: []string{"rxa-lifetime-cert.red-xai.db:Record[ID=1]"}}) {
		t.Fatal("follow target")
	}
	if !bxLeaksLifetimeCert(BXResult{Followed: []string{"rxa-lifetime-cert.red-xai:Record[ID=1]"}}) {
		t.Fatal("short follow target")
	}
	cell, _ := json.Marshal(map[string]string{"private_enc": certSecret})
	if !bxLeaksLifetimeCert(BXResult{Rows: [][]json.RawMessage{{cell}}}) {
		t.Fatal("row")
	}
	if bxLeaksLifetimeCert(BXResult{Columns: []string{"username"}, Rows: [][]json.RawMessage{{json.RawMessage(`"ada"`)}}}) {
		t.Fatal("ordinary row")
	}
}
