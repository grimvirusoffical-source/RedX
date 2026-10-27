//go:build qa

package host_test

// Independent QA harness for the rxa-lifetime-cert owner-only freeze.
// Product sources are not modified. Field material is recorded only as
// present or absent. The canary is a marker, not a key, and is never logged.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"redx/host"
	"redx/host/engineadapter"
)

const qaMarker = "QA-CANARY-PRIVATE-ENC"

const (
	qaPub    = "pk-qa-public-half"
	qaCert   = "cert-qa-id"
	qaMail   = "owner-emails-qa@example.com"
	qaIssued = "issued-qa-stamp"
	qaSig    = "sig-qa-prefix"
)

func redactQA(s string) string {
	return strings.ReplaceAll(s, qaMarker, "[private_enc]")
}

type qaHit struct {
	secret, pub, cert, mail, issued, sig bool
}

func scanQA(s string) qaHit {
	return qaHit{
		secret: strings.Contains(s, qaMarker),
		pub:    strings.Contains(s, qaPub),
		cert:   strings.Contains(s, qaCert),
		mail:   strings.Contains(s, qaMail),
		issued: strings.Contains(s, qaIssued),
		sig:    strings.Contains(s, qaSig),
	}
}

func (h qaHit) any() bool { return h.secret || h.pub || h.cert || h.mail || h.issued || h.sig }

func (h qaHit) String() string {
	yn := func(b bool) string {
		if b {
			return "present"
		}
		return "absent"
	}
	return fmt.Sprintf("secret=%s pubkey=%s cert_id=%s owner_emails=%s issued=%s sig=%s",
		yn(h.secret), yn(h.pub), yn(h.cert), yn(h.mail), yn(h.issued), yn(h.sig))
}

type qaServer struct {
	*node
	logs []string
	mu   sync.Mutex
}

func startRealQA(t *testing.T, mod func(*host.Config)) *qaServer {
	t.Helper()
	n := &node{Dir: t.TempDir()}
	n.Srv = httptest.NewUnstartedServer(nil)
	n.URL = "http://" + n.Srv.Listener.Addr().String()
	cfg := baseCfg(n.Dir)
	cfg.Advertise = n.URL
	cfg.ClusterKey = "qa-review-cluster-key"
	if mod != nil {
		mod(&cfg)
	}
	qs := &qaServer{node: n}
	h, err := host.New(cfg, engineadapter.Opener(engineadapter.Config{
		SweepMS:          50,
		CodeAllowedBoxes: []string{"*"},
	}), func(f string, a ...interface{}) {
		msg := fmt.Sprintf(f, a...)
		qs.mu.Lock()
		qs.logs = append(qs.logs, msg)
		qs.mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	n.H = h
	n.Key = h.BootstrapKey
	n.Srv.Config.Handler = h.Handler()
	n.Srv.Start()
	t.Cleanup(n.Stop)
	return qs
}

func certBox() string {
	return `[ {cert_id[]} = "` + qaCert + `", {pubkey[]} = "` + qaPub + `", {private_enc[]} = "` + qaMarker + `", {issued[]} = "` + qaIssued + `", {owner_emails[]} = ;["` + qaMail + `"]:, {sig_id_prefix[]} = "` + qaSig + `" ]`
}

type qaProbe struct {
	name, method, rawURL, key, body, mode string
	hdr                                   []string
}

func (q *qaServer) probe(t *testing.T, p qaProbe) (int, qaHit) {
	t.Helper()
	st, body, _ := do(t, p.method, p.rawURL, p.key, p.body, p.hdr...)
	hit := scanQA(body)
	class := "CLEAR"
	switch p.mode {
	case "must403":
		if hit.any() {
			class = "LEAK"
			t.Errorf("LEAK %s: status=%d %s", p.name, st, hit)
		} else if st != 403 {
			class = "OPEN"
			t.Errorf("OPEN %s: status=%d want 403 %s", p.name, st, hit)
		} else {
			class = "CLOSED"
		}
	case "hunt":
		if hit.any() {
			class = "LEAK"
			t.Errorf("LEAK %s: status=%d %s", p.name, st, hit)
		} else if st == 403 {
			class = "CLOSED"
		} else if st == 200 {
			class = "CLEAR"
		} else {
			class = "ODD"
			t.Errorf("ODD %s: status=%d %s", p.name, st, hit)
		}
	case "quiet":
		if hit.any() {
			class = "LEAK"
			t.Errorf("LEAK %s: status=%d %s", p.name, st, hit)
		} else {
			class = "QUIET"
		}
	case "owner":
		if st != 200 || !hit.secret {
			class = "OWNER-FAIL"
			t.Errorf("OWNER %s: status=%d %s", p.name, st, hit)
		} else {
			class = "OWNER-OK"
		}
	case "ownerpub":
		if st != 200 || !hit.pub || hit.secret {
			class = "OWNER-FAIL"
			t.Errorf("OWNER PUB %s: status=%d %s", p.name, st, hit)
		} else {
			class = "OWNER-OK"
		}
	case "control":
		if st != 200 || !strings.Contains(body, "ada") || hit.any() {
			class = "CONTROL-FAIL"
			t.Errorf("CONTROL %s: status=%d fields=%s ada=%v", p.name, st, hit, strings.Contains(body, "ada"))
		} else {
			class = "CONTROL-OK"
		}
	default:
		t.Fatalf("bad mode %s", p.mode)
	}
	t.Logf("QA name=%s class=%s status=%d %s", p.name, class, st, hit)
	return st, hit
}

func wsStatus(rawURL, key string) (int, string) {
	hdr := http.Header{}
	if key != "" {
		hdr.Set("Authorization", "Bearer "+key)
	}
	d := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
	c, resp, err := d.Dial(rawURL, hdr)
	if err != nil {
		if resp != nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return resp.StatusCode, string(b)
		}
		return 0, err.Error()
	}
	c.Close()
	return 101, ""
}

func TestQALifetimeCertAttack(t *testing.T) {
	shortRec := `rxa-lifetime-cert.red-xai:Record[ID=1]`
	fullRec := `rxa-lifetime-cert.red-xai.db:Record[ID=1]`
	fields := []string{"pubkey", "cert_id", "owner_emails", "issued", "sig_id_prefix", "private_enc"}

	qs := startRealQA(t, nil)
	n := qs.node
	put := func(path, body string) {
		t.Helper()
		st, b, _ := do(t, "PUT", n.URL+"/v1/path/"+url.PathEscape(path), n.Key, body)
		if st != 200 || scanQA(b).any() {
			t.Fatalf("store %s: status=%d fields=%s", path, st, scanQA(b))
		}
	}
	put(fullRec, certBox())
	player := `[ {Name[]} = "ada", {Cert[]} = "players.red-xai.db":Player[ID=1] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1] ]`
	put(`players.red-xai.db:Player[ID=1]`, player)
	put(`players.red-xai.db:Player[ID=2]`, `[ {Name[]} = "ada", {Steal[]} = "players.red-xai.db":Player[ID=2] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].pubkey ]`)
	put(`players.red-xai.db:Player[ID=3]`, `[ {Name[]} = "ada", {Steal[]} = "players.red-xai.db":Player[ID=3] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].private_enc ]`)
	put(`players.red-xai.db:Player[ID=4]`, `[ {Name[]} = "ada", {Steal[]} = "players.red-xai.db":Player[ID=4] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].cert_id ]`)
	put(`players.red-xai.db:Player[ID=5]`, `[ {Name[]} = "ada", {Steal[]} = "players.red-xai.db":Player[ID=5] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].owner_emails ]`)
	put(`players.red-xai.db:Player[ID=6]`, `[ {Name[]} = "ada", {Steal[]} = "players.red-xai.db":Player[ID=6] @> "rxa-lifetime-cert.red-xai":Record[ID=1].issued ]`)
	put(`players.red-xai.db:Player[ID=7]`, `[ {Name[]} = "ada", {Steal[]} = "players.red-xai.db":Player[ID=7] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].sig_id_prefix ]`)

	wr, _ := mkKey(t, n, map[string]interface{}{"scope": "write", "db": "default"})
	base := n.URL
	db := base + "/v1/db/default"
	path := func(p string) string { return base + "/v1/path/" + url.PathEscape(p) }
	callers := []struct{ name, key string }{{"host-admin", n.Key}, {"write-key", wr}}

	for _, c := range callers {
		qs.probe(t, qaProbe{"control name " + c.name, "GET", path(`players.red-xai.db:Player[ID=1].Name`), c.key, "", "control", nil})
		for _, f := range fields {
			mode := "must403"
			qs.probe(t, qaProbe{"rest short " + f + " " + c.name, "GET", path(shortRec + "." + f), c.key, "", mode, nil})
			qs.probe(t, qaProbe{"rest full " + f + " " + c.name, "GET", path(fullRec + "." + f), c.key, "", mode, nil})
			qs.probe(t, qaProbe{"query short " + f + " " + c.name, "POST", db + "/query", c.key, shortRec + "." + f, mode, nil})
			qs.probe(t, qaProbe{"query full " + f + " " + c.name, "POST", db + "/query", c.key, fullRec + "." + f, mode, nil})
		}
		qs.probe(t, qaProbe{"rest short record " + c.name, "GET", path(shortRec), c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"rest full record " + c.name, "GET", path(fullRec), c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"rest short pubkey text/plain " + c.name, "GET", path(shortRec + ".pubkey"), c.key, "", "must403", []string{"Accept", "text/plain"}})
		qs.probe(t, qaProbe{"rest head short pubkey " + c.name, "HEAD", path(shortRec + ".pubkey"), c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"query short json owner_emails " + c.name, "POST", db + "/query", c.key, `{"q":"` + shortRec + `.owner_emails"}`, "must403", []string{"Content-Type", "application/json"}})
		qs.probe(t, qaProbe{"query prefix full " + c.name, "POST", db + "/query", c.key, `prefix:` + fullRec, "must403", nil})
		qs.probe(t, qaProbe{"query prefix short " + c.name, "POST", db + "/query", c.key, `prefix:rxa-lifetime-cert.red-xai`, "must403", nil})
		qs.probe(t, qaProbe{"query star " + c.name, "POST", db + "/query", c.key, `*`, "must403", nil})
		qs.probe(t, qaProbe{"rest resolve link " + c.name, "GET", path(`players.red-xai.db:Player[ID=1].Cert`) + "?resolve=1", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"rest resolve record depth " + c.name, "GET", path(`players.red-xai.db:Player[ID=1]`) + "?resolve=1&depth=2", c.key, "", "must403", nil})
	}

	// Paths the name gate does not treat as the cert file. A scalar field is
	// invisible to the whole-record text check.
	hunts := []struct {
		name, method, url, body string
		hdr                     []string
	}{
		{"query star pubkey", "POST", db + "/query", `*.pubkey`, nil},
		{"query star cert_id", "POST", db + "/query", `*.cert_id`, nil},
		{"query star owner_emails", "POST", db + "/query", `*.owner_emails`, nil},
		{"query star issued", "POST", db + "/query", `*.issued`, nil},
		{"query star sig", "POST", db + "/query", `*.sig_id_prefix`, nil},
		{"query star private_enc", "POST", db + "/query", `*.private_enc`, nil},
		{"query star star", "POST", db + "/query", `*.*`, nil},
		{"query record pubkey", "POST", db + "/query", `Record[ID=1].pubkey`, nil},
		{"query record cert_id", "POST", db + "/query", `Record[ID=1].cert_id`, nil},
		{"query record owner_emails", "POST", db + "/query", `Record[ID=1].owner_emails`, nil},
		{"query record issued", "POST", db + "/query", `Record[ID=1].issued`, nil},
		{"query record sig", "POST", db + "/query", `Record[ID=1].sig_id_prefix`, nil},
		{"query record private_enc", "POST", db + "/query", `Record[ID=1].private_enc`, nil},
		{"query record star", "POST", db + "/query", `Record[ID=1].*`, nil},
		{"query record any pubkey", "POST", db + "/query", `Record[ID=*].pubkey`, nil},
		{"query wild id pubkey", "POST", db + "/query", `*[ID=1].pubkey`, nil},
		{"query json star pubkey", "POST", db + "/query", `{"q":"*.pubkey"}`, []string{"Content-Type", "application/json"}},
		{"query json record star", "POST", db + "/query", `{"q":"Record[ID=1].*"}`, []string{"Content-Type", "application/json"}},
		{"rest bare pubkey", "GET", path(`Record[ID=1].pubkey`), "", nil},
		{"rest bare cert_id", "GET", path(`Record[ID=1].cert_id`), "", nil},
		{"rest bare owner_emails", "GET", path(`Record[ID=1].owner_emails`), "", nil},
		{"rest bare issued", "GET", path(`Record[ID=1].issued`), "", nil},
		{"rest bare sig", "GET", path(`Record[ID=1].sig_id_prefix`), "", nil},
		{"rest bare private_enc", "GET", path(`Record[ID=1].private_enc`), "", nil},
		{"rest bare pubkey text/plain", "GET", path(`Record[ID=1].pubkey`), "", []string{"Accept", "text/plain"}},
		{"rest bare record", "GET", path(`Record[ID=1]`), "", nil},
		{"rest not-a-prefix", "GET", path(`rxa-lifetime-cert.red-xai.d:Record[ID=1].pubkey`), "", nil},
		{"rest stem red", "GET", path(`rxa-lifetime-cert.red:Record[ID=1].issued`), "", nil},
		{"resolve dotted pubkey", "GET", path(`players.red-xai.db:Player[ID=1].Cert.pubkey`) + "?resolve=1", "", nil},
		{"resolve dotted cert_id", "GET", path(`players.red-xai.db:Player[ID=1].Cert.cert_id`) + "?resolve=1", "", nil},
		{"resolve dotted owner_emails", "GET", path(`players.red-xai.db:Player[ID=1].Cert.owner_emails`) + "?resolve=1", "", nil},
		{"resolve dotted issued", "GET", path(`players.red-xai.db:Player[ID=1].Cert.issued`) + "?resolve=1", "", nil},
		{"resolve dotted sig", "GET", path(`players.red-xai.db:Player[ID=1].Cert.sig_id_prefix`) + "?resolve=1", "", nil},
		{"resolve dotted private_enc", "GET", path(`players.red-xai.db:Player[ID=1].Cert.private_enc`) + "?resolve=1", "", nil},
		{"resolve dotted pubkey text/plain", "GET", path(`players.red-xai.db:Player[ID=1].Cert.pubkey`) + "?resolve=1", "", []string{"Accept", "text/plain"}},
		{"resolve dotted pubkey depth", "GET", path(`players.red-xai.db:Player[ID=1].Cert.pubkey`) + "?resolve=1&depth=4", "", nil},
		{"resolve field link pubkey", "GET", path(`players.red-xai.db:Player[ID=2].Steal`) + "?resolve=1", "", nil},
		{"resolve field link private_enc", "GET", path(`players.red-xai.db:Player[ID=3].Steal`) + "?resolve=1", "", nil},
		{"resolve field link cert_id", "GET", path(`players.red-xai.db:Player[ID=4].Steal`) + "?resolve=1", "", nil},
		{"resolve field link owner_emails", "GET", path(`players.red-xai.db:Player[ID=5].Steal`) + "?resolve=1", "", nil},
		{"resolve field link issued short", "GET", path(`players.red-xai.db:Player[ID=6].Steal`) + "?resolve=1", "", nil},
		{"resolve field link sig", "GET", path(`players.red-xai.db:Player[ID=7].Steal`) + "?resolve=1", "", nil},
		{"rest no-resolve field link pubkey", "GET", path(`players.red-xai.db:Player[ID=2].Steal`), "", nil},
	}
	for _, c := range callers {
		for _, h := range hunts {
			mode := "hunt"
			// A stem the engine must not select, and a link literal that is not a field value.
			if h.name == "rest not-a-prefix" || h.name == "rest stem red" || h.name == "rest no-resolve field link pubkey" {
				mode = "quiet"
			}
			body := h.body
			qs.probe(t, qaProbe{h.name + " " + c.name, h.method, h.url, c.key, body, mode, h.hdr})
		}
	}

	boxql := []struct{ name, q, mode string }{
		{"full pubkey", `{Get[]} = "rxa-lifetime-cert.red-xai.db":Record[ID=1] -> pubkey`, "must403"},
		{"short pubkey", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> pubkey`, "must403"},
		{"short cert_id", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> cert_id`, "must403"},
		{"short owner_emails", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> owner_emails`, "must403"},
		{"short issued", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> issued`, "must403"},
		{"short sig", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> sig_id_prefix`, "must403"},
		{"short private_enc", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> private_enc`, "must403"},
		{"short star", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> *`, "must403"},
		{"link pubkey", `{Get[]} = players:Player[ID=1] -> [Name, Cert.pubkey] @> Cert`, "must403"},
		{"link cert_id", `{Get[]} = players:Player[ID=1] -> [Name, Cert.cert_id] @> Cert`, "must403"},
		{"link owner_emails", `{Get[]} = players:Player[ID=1] -> [Name, Cert.owner_emails] @> Cert`, "must403"},
		{"link issued", `{Get[]} = players:Player[ID=1] -> [Name, Cert.issued] @> Cert`, "must403"},
		{"link sig", `{Get[]} = players:Player[ID=1] -> [Name, Cert.sig_id_prefix] @> Cert`, "must403"},
		{"link private_enc", `{Get[]} = players:Player[ID=1] -> Cert.private_enc @> Cert`, "must403"},
		{"link whole", `{Get[]} = players:Player[ID=1] -> Cert @> Cert`, "must403"},
		{"link min pubkey", `{Get[]} = players:Player[ID=1] -> [Min(Cert.pubkey)] @> Cert`, "must403"},
		{"link left pubkey", `{Get[]} = players:Player[ID=1] -> [Name, Cert.pubkey] @> Cert ?`, "must403"},
		{"link filter pubkey", `{Get[]} = players:Player[Cert.pubkey = "` + qaPub + `"] -> Name @> Cert`, "must403"},
		{"link filter miss", `{Get[]} = players:Player[Cert.pubkey = "no-such-half"] -> Name @> Cert`, "must403"},
		{"field link pubkey", `{Get[]} = players:Player[ID=2] -> Steal @> Steal`, "must403"},
		{"field link private_enc", `{Get[]} = players:Player[ID=3] -> Steal @> Steal`, "must403"},
		{"bare record pubkey", `{Get[]} = Record[ID=1] -> pubkey`, "must403"},
		{"bare record star", `{Get[]} = Record[ID=1] -> *`, "must403"},
		{"explain short pubkey", `{Explain[]} = [ {Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> pubkey ]`, "must403"},
		{"explain follow pubkey", `{Explain[]} = [ {Get[]} = players:Player[ID=1] -> [Name, Cert.pubkey] @> Cert ]`, "hunt"},
		{"tx short pubkey", `{Tx[]} = [ {Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> pubkey ]`, "must403"},
	}
	for _, c := range callers {
		for _, q := range boxql {
			qs.probe(t, qaProbe{"boxql " + q.name + " " + c.name, "POST", db + "/bx", c.key, q.q, q.mode, nil})
		}
	}

	// A second Record box must not make the field query safe: query walks every file.
	put(`account.red-xai.db:Record[ID=1]`, `[ {username[]} = "ada" ]`)
	for _, c := range callers {
		qs.probe(t, qaProbe{"query record pubkey with sibling " + c.name, "POST", db + "/query", c.key, `Record[ID=1].pubkey`, "hunt", nil})
		qs.probe(t, qaProbe{"query record star with sibling " + c.name, "POST", db + "/query", c.key, `Record[ID=1].*`, "hunt", nil})
		qs.probe(t, qaProbe{"rest bare pubkey with sibling " + c.name, "GET", path(`Record[ID=1].pubkey`), c.key, "", "quiet", nil})
		qs.probe(t, qaProbe{"boxql bare pubkey with sibling " + c.name, "POST", db + "/bx", c.key, `{Get[]} = Record[ID=1] -> pubkey`, "quiet", nil})
	}

	idx := `{ByCert[]} = [ {File[]} = "rxa-lifetime-cert.red-xai.db", {Box[]} = "Record", {Fields[]} = ;["cert_id"]:, {Kind[]} = "exact" ];
{ByPub[]} = [ {File[]} = "rxa-lifetime-cert.red-xai.db", {Box[]} = "Record", {Fields[]} = ;["pubkey"]:, {Kind[]} = "exact" ];
{ByPriv[]} = [ {File[]} = "rxa-lifetime-cert.red-xai.db", {Box[]} = "Record", {Fields[]} = ;["private_enc"]:, {Kind[]} = "exact" ];
{ByMail[]} = [ {File[]} = "rxa-lifetime-cert.red-xai.db", {Box[]} = "Record", {Fields[]} = ;["owner_emails"]:, {Kind[]} = "exact" ];`
	if st, b, _ := do(t, "PUT", db+"/idx/certs", n.Key, idx); st != 200 || scanQA(b).any() {
		t.Fatalf("index define: status=%d %s", st, scanQA(b))
	}
	for _, iq := range []struct{ name, index, field, value, extra string }{
		{"cert_id", "ByCert", "cert_id", qaCert, ""},
		{"pubkey", "ByPub", "pubkey", qaPub, ""},
		{"private_enc", "ByPriv", "private_enc", qaMarker, ""},
		{"owner_emails", "ByMail", "owner_emails", qaMail, ""},
		{"pubkey record", "ByPub", "pubkey", qaPub, "&record=1"},
		{"cert_id record", "ByCert", "cert_id", qaCert, "&record=1"},
	} {
		u := db + "/idx/certs/" + iq.index + "/query?mode=exact&field=" + url.QueryEscape(iq.field) + "&value=" + url.QueryEscape(iq.value) + iq.extra
		qs.probe(t, qaProbe{"index " + iq.name, "GET", u, wr, "", "must403", nil})
	}
	qs.probe(t, qaProbe{"index check", "GET", db + "/idx/certs/check", n.Key, "", "quiet", nil})
	qs.probe(t, qaProbe{"index list", "GET", db + "/idx", n.Key, "", "quiet", nil})

	src := `{Script[1]} = [
    {Name[]} = "readfield",
    {Params[]} = ;["target", "field"]:,
    {Uses[]} = ;["db_get"]:,
    {Source[]} = "return db_get(target, field);"
];`
	if st, b, _ := do(t, "PUT", db+"/code/file/steal", n.Key, src); st != 200 || scanQA(b).any() {
		t.Fatalf("script define: status=%d %s", st, scanQA(b))
	}
	run := func(label, target, field, key, mode string) {
		t.Helper()
		body, _ := json.Marshal(map[string]interface{}{"args": []interface{}{target, field}})
		qs.probe(t, qaProbe{"script " + label + " " + field, "POST", db + "/code/run/readfield", key, string(body), mode, []string{"Content-Type", "application/json"}})
	}
	for _, f := range fields {
		run("full write-key", fullRec, f, wr, "must403")
		run("short write-key", shortRec, f, wr, "must403")
		run("bare write-key", `Record[ID=1]`, f, wr, "hunt")
		run("dotted write-key", `players.red-xai.db:Player[ID=1]`, "Cert."+f, wr, "hunt")
	}
	run("link field write-key", `players.red-xai.db:Player[ID=1]`, "Cert", wr, "quiet")
	run("name control write-key", `players.red-xai.db:Player[ID=1]`, "Name", wr, "control")

	// Host-admin pulse rule copies a cert field into an ordinary note.
	rule := `{StealPub[ON="notes.red-xai.db:Note[ID=1].text"]} = [
    {When[]} = "== \"go\"",
    {SetTarget[]} = "\"notes.red-xai.db\":Note[ID=9].text = \"rxa-lifetime-cert.red-xai.db\":Record[ID=1].pubkey"
];
{StealSec[ON="notes.red-xai.db:Note[ID=2].text"]} = [
    {When[]} = "== \"go\"",
    {SetTarget[]} = "\"notes.red-xai.db\":Note[ID=8].text = \"rxa-lifetime-cert.red-xai.db\":Record[ID=1].private_enc"
];
{StealID[ON="notes.red-xai.db:Note[ID=3].text"]} = [
    {When[]} = "== \"go\"",
    {SetTarget[]} = "\"notes.red-xai.db\":Note[ID=7].text = \"rxa-lifetime-cert.red-xai\":Record[ID=1].cert_id"
];
`
	st, b, _ := do(t, "PUT", db+"/pulse", n.Key, rule)
	if scanQA(b).any() {
		t.Errorf("LEAK pulse define ack: status=%d %s", st, scanQA(b))
	}
	t.Logf("QA name=pulse define class=STATUS status=%d %s", st, scanQA(b))
	if st == 200 {
		put(`notes.red-xai.db:Note[ID=1].text`, `"go"`)
		put(`notes.red-xai.db:Note[ID=2].text`, `"go"`)
		put(`notes.red-xai.db:Note[ID=3].text`, `"go"`)
		for _, c := range callers {
			qs.probe(t, qaProbe{"pulse copy pubkey " + c.name, "GET", path(`notes.red-xai.db:Note[ID=9].text`), c.key, "", "quiet", nil})
			qs.probe(t, qaProbe{"pulse copy private_enc " + c.name, "GET", path(`notes.red-xai.db:Note[ID=8].text`), c.key, "", "quiet", nil})
			qs.probe(t, qaProbe{"pulse copy cert_id " + c.name, "GET", path(`notes.red-xai.db:Note[ID=7].text`), c.key, "", "quiet", nil})
		}
	}
	qs.probe(t, qaProbe{"pulse define write-key", "PUT", db + "/pulse", wr, rule, "quiet", nil})

	wsBase := "ws" + strings.TrimPrefix(n.URL, "http")
	for _, p := range []struct{ name, path string }{
		{"full star", `rxa-lifetime-cert.red-xai.db:*`},
		{"short star", `rxa-lifetime-cert.red-xai:*`},
		{"short pubkey", shortRec + ".pubkey"},
		{"short record", shortRec},
	} {
		u := wsBase + "/v1/db/default/subscribe?path=" + url.QueryEscape(p.path)
		st, body := wsStatus(u, wr)
		hit := scanQA(body)
		if hit.any() || st != 403 {
			t.Errorf("OPEN subscribe %s: status=%d %s", p.name, st, hit)
		}
		t.Logf("QA name=subscribe %s class=%s status=%d %s", p.name, map[bool]string{true: "LEAK", false: "CLOSED"}[hit.any() || st != 403], st, hit)
	}
	for _, q := range []string{
		`{Watch[]} = "rxa-lifetime-cert.red-xai.db":Record`,
		`{Watch[]} = "rxa-lifetime-cert.red-xai":Record`,
	} {
		u := wsBase + "/v1/db/default/bx/watch?q=" + url.QueryEscape(q)
		st, body := wsStatus(u, wr)
		hit := scanQA(body)
		class := "CLOSED"
		if hit.any() {
			class = "LEAK"
			t.Errorf("LEAK watch: status=%d %s", st, hit)
		} else if st == 101 {
			class = "UPGRADED"
			t.Errorf("OPEN watch upgraded with no field in the handshake")
		} else if st != 403 {
			class = "OPEN"
			t.Errorf("OPEN watch: status=%d %s", st, hit)
		}
		t.Logf("QA name=watch %s class=%s status=%d %s", q, class, st, hit)
	}

	hdr := http.Header{"Authorization": {"Bearer " + wr}}
	noteWS := wsBase + "/v1/db/default/subscribe?path=" + url.QueryEscape(`notes.red-xai.db:*`)
	c, resp, err := websocket.DefaultDialer.Dial(noteWS, hdr)
	if err != nil {
		t.Fatalf("note subscribe: %v", err)
	}
	put(`notes.red-xai.db:Note[ID=4].text`, `"hello-qa"`)
	put(fullRec+".issued", `"`+qaIssued+`"`)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	var frames []string
	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			break
		}
		frames = append(frames, string(msg))
		if len(frames) > 30 {
			break
		}
	}
	c.Close()
	joined := strings.Join(frames, "\n")
	hit := scanQA(joined)
	if hit.any() || strings.Contains(joined, "rxa-lifetime-cert") {
		t.Errorf("LEAK subscribe note-stream: frames=%d %s certpath=%v", len(frames), hit, strings.Contains(joined, "rxa-lifetime-cert"))
	}
	t.Logf("QA name=subscribe note-stream class=%s status=101 frames=%d %s", map[bool]string{true: "LEAK", false: "CLOSED"}[hit.any()], len(frames), hit)
	_ = resp

	st, b, _ = do(t, "GET", n.URL+"/v1/admin/backup", n.Key, "")
	raw := b
	if st == 200 {
		if zr, err := gzip.NewReader(strings.NewReader(b)); err == nil {
			buf, _ := io.ReadAll(io.LimitReader(zr, 8<<20))
			zr.Close()
			raw = string(buf)
		}
	}
	bhit := scanQA(raw)
	if st != 403 || bhit.any() {
		t.Errorf("LEAK backup: status=%d %s", st, bhit)
	}
	t.Logf("QA name=backup class=%s status=%d %s", map[bool]string{true: "LEAK", false: "CLOSED"}[st != 403 || bhit.any()], st, bhit)

	for _, p := range []qaProbe{
		{"console audit", "GET", n.URL + "/v1/admin/audit?limit=50", n.Key, "", "quiet", nil},
		{"console files", "GET", db + "/files", n.Key, "", "quiet", nil},
		{"console file text", "GET", db + "/files/" + url.PathEscape("rxa-lifetime-cert.red-xai.db"), n.Key, "", "quiet", nil},
		{"cluster log", "GET", n.URL + "/v1/cluster/log", n.Key, "", "quiet", nil},
		{"stats", "GET", db + "/stats", n.Key, "", "quiet", nil},
	} {
		qs.probe(t, p)
	}

	// Accounts service key: write allowed, read-back forbidden, including the
	// channels that do not name the cert file.
	f, iss := startFake(t)
	acc := startRealQA(t, func(c *host.Config) {
		c.AccountsIssuer = iss
		c.AccountsClientSecret = "test-client-secret"
		c.AccountsEventsPoll = 3600
		c.OwnerEmails = []string{ownerA}
	})
	tok, acct := signIn(t, acc.node, f, ownerOK)
	if acct["owner"] != true {
		t.Fatalf("owner session was not elevated")
	}
	if st, _, _ := do(t, "POST", acc.URL+"/v1/dbs", tok, `{"name":"redxai_accounts"}`); st != 201 && st != 409 {
		t.Fatalf("master db: status=%d", st)
	}
	st, b, _ = do(t, "POST", acc.URL+"/v1/keys", tok, `{"db":"redxai_accounts","scope":"write","label":"accounts-service"}`, "Content-Type", "application/json")
	if st != 201 || scanQA(b).any() {
		t.Fatalf("service key: status=%d %s", st, scanQA(b))
	}
	svc := jsonOf(t, b)["key"].(string)
	mp := func(p string) string {
		return acc.URL + "/v1/db/redxai_accounts/path/" + url.PathEscape(p)
	}
	mst := acc.URL + "/v1/db/redxai_accounts"
	if st, b, _ := do(t, "PUT", mp(fullRec), svc, certBox()); st != 200 || scanQA(b).any() {
		t.Fatalf("service write cert: status=%d %s", st, scanQA(b))
	} else {
		t.Logf("QA name=service write cert class=QUIET status=%d %s", st, scanQA(b))
	}
	if st, hit := acc.probe(t, qaProbe{"service set idVerified", "PUT", mp(`rxa-account.red-xai.db:Record[ID=1].idVerified`), svc, `{"value":true}`, "quiet", []string{"Content-Type", "application/json"}}); st != 200 || hit.any() {
		t.Errorf("service idVerified write: status=%d %s", st, hit)
	}
	plink := `[ {Name[]} = "ada", {Cert[]} = "players.red-xai.db":Player[ID=1] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1] ]`
	if st, b, _ := do(t, "PUT", mp(`players.red-xai.db:Player[ID=1]`), svc, plink); st != 200 || scanQA(b).any() {
		t.Fatalf("service player link: status=%d %s", st, scanQA(b))
	}
	if st, b, _ := do(t, "PUT", mp(`players.red-xai.db:Player[ID=3]`), svc, `[ {Name[]} = "ada", {Steal[]} = "players.red-xai.db":Player[ID=3] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].private_enc ]`); st != 200 || scanQA(b).any() {
		t.Fatalf("service field link: status=%d %s", st, scanQA(b))
	}

	for _, f := range fields {
		acc.probe(t, qaProbe{"service rest short " + f, "GET", mp(shortRec + "." + f), svc, "", "must403", nil})
		acc.probe(t, qaProbe{"service query short " + f, "POST", mst + "/query", svc, shortRec + "." + f, "must403", nil})
	}
	acc.probe(t, qaProbe{"service rest short record", "GET", mp(shortRec), svc, "", "must403", nil})
	acc.probe(t, qaProbe{"service rest full record", "GET", mp(fullRec), svc, "", "must403", nil})
	acc.probe(t, qaProbe{"service boxql short pubkey", "POST", mst + "/bx", svc, `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> pubkey`, "must403", nil})
	acc.probe(t, qaProbe{"service boxql follow pubkey", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=1] -> [Name, Cert.pubkey] @> Cert`, "must403", nil})
	acc.probe(t, qaProbe{"service boxql follow cert_id", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=1] -> Cert.cert_id @> Cert`, "must403", nil})
	acc.probe(t, qaProbe{"service boxql follow owner_emails", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=1] -> Cert.owner_emails @> Cert`, "must403", nil})
	acc.probe(t, qaProbe{"service boxql follow private_enc", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=1] -> Cert.private_enc @> Cert`, "must403", nil})
	for _, h := range []struct{ name, body string }{
		{"service query star pubkey", `*.pubkey`},
		{"service query star cert_id", `*.cert_id`},
		{"service query star owner_emails", `*.owner_emails`},
		{"service query star issued", `*.issued`},
		{"service query star sig", `*.sig_id_prefix`},
		{"service query star private_enc", `*.private_enc`},
		{"service query star star", `*.*`},
		{"service query record pubkey", `Record[ID=1].pubkey`},
		{"service query record star", `Record[ID=1].*`},
		{"service query json star pubkey", `{"q":"*.pubkey"}`},
	} {
		hdr := []string(nil)
		body := h.body
		if strings.HasPrefix(body, "{") {
			hdr = []string{"Content-Type", "application/json"}
		}
		acc.probe(t, qaProbe{h.name, "POST", mst + "/query", svc, body, "hunt", hdr})
	}
	acc.probe(t, qaProbe{"service resolve dotted pubkey", "GET", mp(`players.red-xai.db:Player[ID=1].Cert.pubkey`) + "?resolve=1", svc, "", "hunt", nil})
	acc.probe(t, qaProbe{"service resolve dotted cert_id", "GET", mp(`players.red-xai.db:Player[ID=1].Cert.cert_id`) + "?resolve=1", svc, "", "hunt", nil})
	acc.probe(t, qaProbe{"service resolve dotted private_enc", "GET", mp(`players.red-xai.db:Player[ID=1].Cert.private_enc`) + "?resolve=1", svc, "", "hunt", nil})
	acc.probe(t, qaProbe{"service resolve field link private_enc", "GET", mp(`players.red-xai.db:Player[ID=3].Steal`) + "?resolve=1", svc, "", "hunt", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"service explain follow", "POST", mst + "/bx", svc, `{Explain[]} = [ {Get[]} = players:Player[ID=1] -> Cert.pubkey @> Cert ]`, "hunt", nil})
	acc.probe(t, qaProbe{"owner full record", "GET", mp(fullRec), tok, "", "owner", nil})
	acc.probe(t, qaProbe{"owner short pubkey", "GET", mp(shortRec + ".pubkey"), tok, "", "ownerpub", nil})

	if st, b, _ := do(t, "PUT", mst+"/code/file/steal", tok, src); st != 200 || scanQA(b).any() {
		t.Fatalf("owner script define: status=%d %s", st, scanQA(b))
	}
	for _, f := range []string{"pubkey", "cert_id", "owner_emails", "private_enc"} {
		body, _ := json.Marshal(map[string]interface{}{"args": []interface{}{shortRec, f}})
		acc.probe(t, qaProbe{"service script short " + f, "POST", mst + "/code/run/readfield", svc, string(body), "must403", []string{"Content-Type", "application/json"}})
		body, _ = json.Marshal(map[string]interface{}{"args": []interface{}{`Record[ID=1]`, f}})
		acc.probe(t, qaProbe{"service script bare " + f, "POST", mst + "/code/run/readfield", svc, string(body), "hunt", []string{"Content-Type", "application/json"}})
	}

	st, b, _ = do(t, "GET", acc.URL+"/v1/admin/backup", acc.Key, "")
	raw = b
	if st == 200 {
		if zr, err := gzip.NewReader(bytes.NewReader([]byte(b))); err == nil {
			buf, _ := io.ReadAll(io.LimitReader(zr, 8<<20))
			zr.Close()
			raw = string(buf)
		}
	}
	bhit = scanQA(raw)
	if st == 200 || bhit.any() {
		t.Errorf("LEAK accounts-on admin backup: status=%d %s", st, bhit)
	}
	t.Logf("QA name=accounts-on admin backup class=%s status=%d %s", map[bool]string{true: "LEAK", false: "CLOSED"}[st == 200 || bhit.any()], st, bhit)

	scanLogs(t, qs)
	scanLogs(t, acc)
}

func scanLogs(t *testing.T, qs *qaServer) {
	t.Helper()
	qs.mu.Lock()
	logs := strings.Join(qs.logs, "\n")
	nlines := len(qs.logs)
	qs.mu.Unlock()
	lh := scanQA(logs)
	pem := strings.Contains(logs, "PRIVATE KEY") || strings.Contains(logs, "-----BEGIN")
	if lh.any() || pem {
		t.Errorf("server log leak %s pem=%v", lh, pem)
	}
	t.Logf("QA name=server-log class=%s lines=%d %s pem=%v", map[bool]string{true: "LEAK", false: "CLOSED"}[lh.any() || pem], nlines, lh, pem)

	auditHits := 0
	dataHits := 0
	pemHits := 0
	_ = filepath.Walk(qs.Dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || fi.Size() > 8<<20 {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(qs.Dir, p)
		text := string(b)
		isAudit := strings.Contains(rel, "audit")
		if isAudit && (strings.Contains(text, "-----BEGIN") || strings.Contains(text, "PRIVATE KEY")) {
			pemHits++
		}
		if !strings.Contains(text, qaMarker) {
			return nil
		}
		if isAudit {
			auditHits++
			t.Errorf("audit file contains ciphertext marker: %s", rel)
		} else {
			dataHits++
		}
		return nil
	})
	t.Logf("QA name=leak-scan audit_files_with_ciphertext=%d pem_or_key_headers=%d data_files_with_stored_ciphertext=%d", auditHits, pemHits, dataHits)
}
