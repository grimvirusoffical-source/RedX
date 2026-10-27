package host_test

// Independent QA harness for the rxa-lifetime-cert schema freeze.
// It does not change product behavior. Findings are reported as
// present/absent; ciphertext values are never written to the log.

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

// Canary stored in private_enc. Not a key. Never print it.
const qaMarker = "QA-CANARY-PRIVATE-ENC"

const (
	qaPub    = "pk-qa-public-half"
	qaCert   = "cert-qa-id"
	qaMail   = "owner-emails-qa@example.com"
	qaIssued = "issued-qa-stamp"
	qaSig    = "sig-qa-prefix"
)

func redactQA(s string) string {
	s = strings.ReplaceAll(s, qaMarker, "[private_enc]")
	return s
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
	name   string
	method string
	url    string
	key    string
	body   string
	hdr    []string
	// deny: non-owner read of the cert. 200 or any record field is a miss.
	// owner: owner read. 200 and secret present is the positive control.
	// quiet: write or unrelated call. record fields must be absent.
	mode string
}

func (q *qaServer) probe(t *testing.T, p qaProbe) (int, qaHit) {
	t.Helper()
	st, body, _ := do(t, p.method, p.url, p.key, p.body, p.hdr...)
	hit := scanQA(body)
	switch p.mode {
	case "strict":
		// Canonical read of a record that exists: 403 and no record material.
		if st != 403 || hit.any() {
			t.Errorf("MISS %s: status=%d %s", p.name, st, hit)
		}
	case "deny":
		// Attack probe. Any record field is a leak. 200 with no field is noted.
		if hit.any() {
			t.Errorf("LEAK %s: status=%d %s", p.name, st, hit)
		} else if st == 200 {
			t.Logf("NOTE %s returned 200 with no record fields", p.name)
		}
	case "owner":
		if st != 200 || !hit.secret {
			t.Errorf("OWNER %s: status=%d %s", p.name, st, hit)
		}
	case "ownerpub":
		if st != 200 || !hit.pub || hit.secret {
			t.Errorf("OWNER PUB %s: status=%d %s", p.name, st, hit)
		}
	case "quiet":
		if hit.any() {
			t.Errorf("ECHO %s: status=%d %s", p.name, st, hit)
		}
	default:
		t.Fatalf("bad mode %s", p.mode)
	}
	t.Logf("%s status=%d %s", p.name, st, hit)
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
		return 0, ""
	}
	c.Close()
	return 101, ""
}

func TestQALifetimeCertAttack(t *testing.T) {
	shortRec := `rxa-lifetime-cert.red-xai:Record[ID=1]`
	fullRec := `rxa-lifetime-cert.red-xai.db:Record[ID=1]`
	if host.PathReadsLifetimeSecret(shortRec + ".pubkey") {
		t.Log("gate flags shortened pubkey path")
	} else {
		t.Log("gate does not flag shortened pubkey path")
	}
	if host.PathReadsLifetimeSecret(shortRec + ".private_enc") {
		t.Log("gate flags shortened private_enc path")
	} else {
		t.Log("gate does not flag shortened private_enc path")
	}
	if host.ScriptCertReadBlocked(shortRec, "pubkey") {
		t.Log("script gate flags shortened pubkey")
	} else {
		t.Log("script gate does not flag shortened pubkey")
	}
	if host.ScriptCertReadBlocked(shortRec, "cert_id") {
		t.Log("script gate flags shortened cert_id")
	} else {
		t.Log("script gate does not flag shortened cert_id")
	}

	qs := startRealQA(t, nil)
	n := qs.node
	st, b, _ := do(t, "PUT", n.URL+"/v1/path/"+url.PathEscape(fullRec), n.Key, certBox())
	if st != 200 {
		t.Fatalf("store cert: %d %s", st, redactQA(b))
	}
	if scanQA(b).secret {
		t.Errorf("write ack echoed ciphertext")
	}
	player := `[ {Name[]} = "ada", {Cert[]} = "players.red-xai.db":Player[ID=1] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1] ]`
	if st, b, _ := do(t, "PUT", n.URL+"/v1/path/"+url.PathEscape(`players.red-xai.db:Player[ID=1]`), n.Key, player); st != 200 {
		t.Fatalf("store link: %d %s", st, redactQA(b))
	}
	wr, _ := mkKey(t, n, map[string]interface{}{"scope": "write", "db": "default"})

	base := n.URL
	db := base + "/v1/db/default"
	path := func(p string) string { return base + "/v1/path/" + url.PathEscape(p) }

	// Canonical paths and the channels the freeze names. Short file prefix is
	// the engine's unique-prefix match for rxa-lifetime-cert.red-xai.db.
	reads := []qaProbe{
		{"rest full record", "GET", path(fullRec), n.Key, "", nil, "strict"},
		{"rest full private_enc", "GET", path(fullRec + ".private_enc"), n.Key, "", nil, "strict"},
		{"rest full pubkey", "GET", path(fullRec + ".pubkey"), n.Key, "", nil, "strict"},
		{"rest full cert_id", "GET", path(fullRec + ".cert_id"), n.Key, "", nil, "strict"},
		{"rest full owner_emails", "GET", path(fullRec + ".owner_emails"), n.Key, "", nil, "strict"},
		{"rest head full", "HEAD", path(fullRec), n.Key, "", nil, "strict"},
		{"rest box accept", "GET", path(fullRec), n.Key, "", []string{"Accept", "text/x-redx-box"}, "strict"},
		{"rest short record", "GET", path(shortRec), n.Key, "", nil, "deny"},
		{"rest short private_enc", "GET", path(shortRec + ".private_enc"), n.Key, "", nil, "deny"},
		{"rest short pubkey", "GET", path(shortRec + ".pubkey"), n.Key, "", nil, "deny"},
		{"rest short cert_id", "GET", path(shortRec + ".cert_id"), n.Key, "", nil, "deny"},
		{"rest short owner_emails", "GET", path(shortRec + ".owner_emails"), n.Key, "", nil, "deny"},
		{"rest short issued", "GET", path(shortRec + ".issued"), n.Key, "", nil, "deny"},
		{"rest short sig", "GET", path(shortRec + ".sig_id_prefix"), n.Key, "", nil, "deny"},
		{"rest short pubkey write-key", "GET", path(shortRec + ".pubkey"), wr, "", nil, "deny"},
		{"rest short box accept", "GET", path(shortRec + ".pubkey"), n.Key, "", []string{"Accept", "text/plain"}, "deny"},
		{"rest resolve link", "GET", path(`players.red-xai.db:Player[ID=1].Cert`) + "?resolve=1", n.Key, "", nil, "deny"},
		{"rest resolve record", "GET", path(`players.red-xai.db:Player[ID=1]`) + "?resolve=1&depth=2", n.Key, "", nil, "deny"},
		{"query full", "POST", db + "/query", n.Key, fullRec, nil, "strict"},
		{"query full pubkey", "POST", db + "/query", n.Key, fullRec + ".pubkey", nil, "strict"},
		{"query star", "POST", db + "/query", n.Key, `*`, nil, "deny"},
		{"query short record", "POST", db + "/query", n.Key, shortRec, nil, "deny"},
		{"query short pubkey", "POST", db + "/query", n.Key, shortRec + ".pubkey", nil, "deny"},
		{"query short cert_id", "POST", db + "/query", n.Key, shortRec + ".cert_id", nil, "deny"},
		{"query short private_enc", "POST", db + "/query", n.Key, shortRec + ".private_enc", nil, "deny"},
		{"query short json", "POST", db + "/query", n.Key, `{"q":"` + shortRec + `.owner_emails"}`, []string{"Content-Type", "application/json"}, "deny"},
		{"query prefix file", "POST", db + "/query", n.Key, `prefix:rxa-lifetime-cert.red-xai.db`, nil, "strict"},
		{"query prefix short", "POST", db + "/query", wr, `prefix:rxa-lifetime-cert.red-xai`, nil, "deny"},
	}
	for _, p := range reads {
		qs.probe(t, p)
	}

	boxql := []struct{ name, q, mode string }{
		{"full record", `{Get[]} = "rxa-lifetime-cert.red-xai.db":Record[ID=1]`, "strict"},
		{"full pubkey", `{Get[]} = "rxa-lifetime-cert.red-xai.db":Record[ID=1] -> pubkey`, "strict"},
		{"full cert_id", `{Get[]} = "rxa-lifetime-cert.red-xai.db":Record[ID=1] -> cert_id`, "strict"},
		{"full private_enc", `{Get[]} = "rxa-lifetime-cert.red-xai.db":Record[ID=1] -> private_enc`, "strict"},
		{"full star", `{Get[]} = "rxa-lifetime-cert.red-xai.db":Record[ID=1] -> *`, "strict"},
		{"short record", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1]`, "deny"},
		{"short pubkey", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> pubkey`, "deny"},
		{"short cert_id", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> cert_id`, "deny"},
		{"short owner_emails", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> owner_emails`, "deny"},
		{"short issued", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> issued`, "deny"},
		{"short sig", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> sig_id_prefix`, "deny"},
		{"short private_enc", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> private_enc`, "strict"},
		{"short star", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> *`, "deny"},
		{"short alias private_enc", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> [leak = private_enc]`, "strict"},
		{"short filter pubkey", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[cert_id = "` + qaCert + `"] -> pubkey`, "deny"},
		{"link pubkey", `{Get[]} = players:Player[ID=1] -> [Name, Cert.pubkey] @> Cert`, "deny"},
		{"link cert_id", `{Get[]} = players:Player[ID=1] -> [Name, Cert.cert_id] @> Cert`, "deny"},
		{"link owner_emails", `{Get[]} = players:Player[ID=1] -> [Name, Cert.owner_emails] @> Cert`, "deny"},
		{"link private_enc", `{Get[]} = players:Player[ID=1] -> Cert.private_enc @> Cert`, "strict"},
		{"link whole", `{Get[]} = players:Player[ID=1] -> Cert @> Cert`, "deny"},
		{"explain short pubkey", `{Explain[]} = [ {Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> pubkey ]`, "deny"},
		{"tx short pubkey", `{Tx[]} = [ {Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> pubkey ]`, "deny"},
	}
	for _, q := range boxql {
		qs.probe(t, qaProbe{"boxql " + q.name, "POST", db + "/bx", wr, q.q, nil, q.mode})
	}

	// Index on the cert file, then query each field and the whole record.
	idx := `{ByCert[]} = [ {File[]} = "rxa-lifetime-cert.red-xai.db", {Box[]} = "Record", {Fields[]} = ;["cert_id"]:, {Kind[]} = "exact" ];
{ByPub[]} = [ {File[]} = "rxa-lifetime-cert.red-xai.db", {Box[]} = "Record", {Fields[]} = ;["pubkey"]:, {Kind[]} = "exact" ];
{ByPriv[]} = [ {File[]} = "rxa-lifetime-cert.red-xai.db", {Box[]} = "Record", {Fields[]} = ;["private_enc"]:, {Kind[]} = "exact" ];
{ByMail[]} = [ {File[]} = "rxa-lifetime-cert.red-xai.db", {Box[]} = "Record", {Fields[]} = ;["owner_emails"]:, {Kind[]} = "exact" ];`
	if st, b, _ := do(t, "PUT", db+"/idx/certs", n.Key, idx); st != 200 {
		t.Fatalf("index define: %d %s", st, redactQA(b))
	}
	for _, iq := range []struct{ name, index, field, value, extra, mode string }{
		{"cert_id", "ByCert", "cert_id", qaCert, "", "deny"},
		{"pubkey", "ByPub", "pubkey", qaPub, "", "deny"},
		{"private_enc", "ByPriv", "private_enc", qaMarker, "", "strict"},
		{"owner_emails", "ByMail", "owner_emails", qaMail, "", "deny"},
		{"cert_id record", "ByCert", "cert_id", qaCert, "&record=1", "deny"},
		{"pubkey record", "ByPub", "pubkey", qaPub, "&record=1", "deny"},
	} {
		u := db + "/idx/certs/" + iq.index + "/query?mode=exact&field=" + url.QueryEscape(iq.field) + "&value=" + url.QueryEscape(iq.value) + iq.extra
		qs.probe(t, qaProbe{"index " + iq.name, "GET", u, wr, "", nil, iq.mode})
	}
	qs.probe(t, qaProbe{"index check", "GET", db + "/idx/certs/check", n.Key, "", nil, "quiet"})
	qs.probe(t, qaProbe{"index list", "GET", db + "/idx", n.Key, "", nil, "quiet"})

	// Scripts. Sandbox allows every box so the cert gate is what must refuse.
	src := `{Script[1]} = [
    {Name[]} = "readfield",
    {Params[]} = ;["target", "field"]:,
    {Uses[]} = ;["db_get"]:,
    {Source[]} = "return db_get(target, field);"
];`
	if st, b, _ := do(t, "PUT", db+"/code/file/steal", n.Key, src); st != 200 {
		t.Fatalf("script define: %d %s", st, redactQA(b))
	}
	run := func(label, target, field, mode string) {
		t.Helper()
		body, _ := json.Marshal(map[string]interface{}{"args": []interface{}{target, field}})
		qs.probe(t, qaProbe{"script " + label + " " + field, "POST", db + "/code/run/readfield", wr, string(body), []string{"Content-Type", "application/json"}, mode})
	}
	for _, f := range []string{"private_enc", "pubkey", "cert_id", "owner_emails", "issued", "sig_id_prefix"} {
		run("full", fullRec, f, "strict")
		mode := "deny"
		if f == "private_enc" {
			mode = "strict"
		}
		run("short", shortRec, f, mode)
	}
	linkBody, _ := json.Marshal(map[string]interface{}{"args": []interface{}{`players.red-xai.db:Player[ID=1]`, "Cert"}})
	qs.probe(t, qaProbe{"script link field", "POST", db + "/code/run/readfield", wr, string(linkBody), []string{"Content-Type", "application/json"}, "quiet"})

	// Subscribe: explicit cert paths must 403 before the upgrade.
	wsBase := "ws" + strings.TrimPrefix(n.URL, "http")
	for _, p := range []struct{ name, path string }{
		{"full star", `rxa-lifetime-cert.red-xai.db:*`},
		{"full record", `rxa-lifetime-cert.red-xai.db:Record[ID=1]`},
		{"short star", `rxa-lifetime-cert.red-xai:*`},
		{"short record", `rxa-lifetime-cert.red-xai:Record[ID=1]`},
		{"short pubkey", shortRec + ".pubkey"},
		{"watch full", ""},
	} {
		if p.name == "watch full" {
			u := wsBase + "/v1/db/default/bx/watch?q=" + url.QueryEscape(`{Watch[]} = "rxa-lifetime-cert.red-xai.db":Record`)
			st, body := wsStatus(u, wr)
			hit := scanQA(body)
			if st == 101 || hit.any() || st != 403 {
				t.Errorf("MISS watch full: status=%d %s", st, hit)
			}
			t.Logf("watch full status=%d %s", st, hit)
			u = wsBase + "/v1/db/default/bx/watch?q=" + url.QueryEscape(`{Watch[]} = "rxa-lifetime-cert.red-xai":Record`)
			wc, wresp, werr := websocket.DefaultDialer.Dial(u, http.Header{"Authorization": {"Bearer " + wr}})
			if werr != nil {
				wb := ""
				wst := 0
				if wresp != nil {
					raw, _ := io.ReadAll(wresp.Body)
					wresp.Body.Close()
					wb = string(raw)
					wst = wresp.StatusCode
				}
				wh := scanQA(wb)
				if wh.any() {
					t.Errorf("LEAK watch short handshake: status=%d %s", wst, wh)
				}
				t.Logf("watch short status=%d %s", wst, wh)
				continue
			}
			do(t, "PUT", n.URL+"/v1/path/"+url.PathEscape(fullRec+".issued"), n.Key, `"`+qaIssued+`"`)
			_ = wc.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
			var wframes []string
			for {
				_, msg, err := wc.ReadMessage()
				if err != nil {
					break
				}
				wframes = append(wframes, string(msg))
				if len(wframes) > 20 {
					break
				}
			}
			wc.Close()
			wj := strings.Join(wframes, "\n")
			wh := scanQA(wj)
			if wh.any() || strings.Contains(wj, "rxa-lifetime-cert") {
				t.Errorf("LEAK watch short frames: n=%d %s certpath=%v", len(wframes), wh, strings.Contains(wj, "rxa-lifetime-cert"))
			}
			t.Logf("watch short upgraded frames=%d %s certpath=%v", len(wframes), wh, strings.Contains(wj, "rxa-lifetime-cert"))
			continue
		}
		u := wsBase + "/v1/db/default/subscribe?path=" + url.QueryEscape(p.path)
		st, body := wsStatus(u, wr)
		hit := scanQA(body)
		if st == 101 || hit.any() || st != 403 {
			t.Errorf("MISS subscribe %s: status=%d %s", p.name, st, hit)
		}
		t.Logf("subscribe %s status=%d %s", p.name, st, hit)
	}

	// Live change stream. A note is delivered. A cert write must not be.
	hdr := http.Header{"Authorization": {"Bearer " + wr}}
	noteWS := wsBase + "/v1/db/default/subscribe?path=" + url.QueryEscape(`notes.red-xai.db:*`)
	c, resp, err := websocket.DefaultDialer.Dial(noteWS, hdr)
	if err != nil {
		b := ""
		if resp != nil {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			b = string(raw)
		}
		t.Fatalf("note subscribe: %v %s", err, redactQA(b))
	}
	do(t, "PUT", n.URL+"/v1/path/"+url.PathEscape(`notes.red-xai.db:Note[ID=1].text`), n.Key, `"hello-qa"`)
	do(t, "PUT", n.URL+"/v1/path/"+url.PathEscape(fullRec+".issued"), n.Key, `"`+qaIssued+`"`)
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
	t.Logf("subscribe note-stream frames=%d %s", len(frames), hit)

	pulseURL := wsBase + "/v1/db/default/pulse/subscribe?changes=1&topic=change*"
	pc, presp, err := websocket.DefaultDialer.Dial(pulseURL, hdr)
	if err != nil {
		b := ""
		if presp != nil {
			raw, _ := io.ReadAll(presp.Body)
			presp.Body.Close()
			b = string(raw)
		}
		t.Fatalf("pulse subscribe: %v %s", err, redactQA(b))
	}
	do(t, "PUT", n.URL+"/v1/path/"+url.PathEscape(`notes.red-xai.db:Note[ID=2].text`), n.Key, `"pulse-qa"`)
	do(t, "PUT", n.URL+"/v1/path/"+url.PathEscape(fullRec), n.Key, certBox())
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	frames = nil
	for {
		_, msg, err := pc.ReadMessage()
		if err != nil {
			break
		}
		frames = append(frames, string(msg))
		if len(frames) > 30 {
			break
		}
	}
	pc.Close()
	joined = strings.Join(frames, "\n")
	hit = scanQA(joined)
	if hit.any() || strings.Contains(joined, "rxa-lifetime-cert") {
		t.Errorf("LEAK pulse changes: frames=%d %s certpath=%v", len(frames), hit, strings.Contains(joined, "rxa-lifetime-cert"))
	}
	t.Logf("pulse changes frames=%d %s note=%v", len(frames), hit, strings.Contains(joined, "pulse-qa"))

	// Backup and console. Accounts are off, so host-admin backup is open
	// until a cert is stored.
	st, b, _ = do(t, "GET", n.URL+"/v1/admin/backup", n.Key, "")
	raw := b
	if st == 200 {
		if zr, err := gzip.NewReader(strings.NewReader(b)); err == nil {
			buf, _ := io.ReadAll(io.LimitReader(zr, 32<<20))
			zr.Close()
			raw = string(buf)
		}
	}
	bhit := scanQA(raw)
	if st != 403 || bhit.any() {
		t.Errorf("LEAK backup: status=%d %s", st, bhit)
	}
	t.Logf("backup status=%d %s", st, bhit)

	for _, p := range []qaProbe{
		{"console audit", "GET", n.URL + "/v1/admin/audit?limit=200", n.Key, "", nil, "quiet"},
		{"console status", "GET", n.URL + "/v1/admin/status", n.Key, "", nil, "quiet"},
		{"console config", "GET", n.URL + "/v1/admin/config", n.Key, "", nil, "quiet"},
		{"console files", "GET", db + "/files", n.Key, "", nil, "quiet"},
		{"console file text", "GET", db + "/files/" + url.PathEscape("rxa-lifetime-cert.red-xai.db"), n.Key, "", nil, "quiet"},
		{"console whoami", "GET", n.URL + "/v1/ui/whoami", n.Key, "", nil, "quiet"},
		{"console owner overview", "GET", n.URL + "/v1/owner/overview", n.Key, "", nil, "deny"},
		{"console owner accounts", "GET", n.URL + "/v1/owner/accounts", wr, "", nil, "deny"},
		{"cluster log", "GET", n.URL + "/v1/cluster/log", n.Key, "", nil, "quiet"},
		{"cluster snapshot", "GET", n.URL + "/v1/cluster/snapshot", n.Key, "", nil, "quiet"},
		{"stats", "GET", db + "/stats", n.Key, "", nil, "quiet"},
		{"normal player", "GET", path(`players.red-xai.db:Player[ID=1].Name`), wr, "", nil, "quiet"},
	} {
		qs.probe(t, p)
	}

	// Service-key write, no read-back, on an accounts-enabled real engine.
	// Owner session is the positive control.
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
	if st, b, _ := do(t, "POST", acc.URL+"/v1/dbs", tok, `{"name":"redxai_accounts"}`); st != 201 && st != 409 {
		t.Fatalf("master db: %d %s", st, redactQA(b))
	}
	st, b, _ = do(t, "POST", acc.URL+"/v1/keys", tok, `{"db":"redxai_accounts","scope":"write","label":"accounts-service"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("service key: %d %s", st, redactQA(b))
	}
	svc := jsonOf(t, b)["key"].(string)
	mp := func(p string) string {
		return acc.URL + "/v1/db/redxai_accounts/path/" + url.PathEscape(p)
	}
	masterPath := mp(fullRec)
	acc.probe(t, qaProbe{"service write cert", "PUT", masterPath, svc, certBox(), nil, "quiet"})
	if st, _, _ := do(t, "PUT", masterPath, svc, certBox()); st != 200 {
		t.Fatalf("service key rewrite: %d", st)
	}
	flag := `rxa-account.red-xai.db:Record[ID=1].idVerified`
	if st, hit := acc.probe(t, qaProbe{"service set idVerified", "PUT", mp(flag), svc, `{"value":true}`, []string{"Content-Type", "application/json"}, "quiet"}); st != 200 || hit.any() {
		t.Errorf("service idVerified write: status=%d %s", st, hit)
	}
	for _, p := range []qaProbe{
		{"service full record", "GET", masterPath, svc, "", nil, "strict"},
		{"service full private_enc", "GET", mp(fullRec + ".private_enc"), svc, "", nil, "strict"},
		{"service short pubkey", "GET", mp(shortRec + ".pubkey"), svc, "", nil, "deny"},
		{"service short cert_id", "GET", mp(shortRec + ".cert_id"), svc, "", nil, "deny"},
		{"service short record", "GET", mp(shortRec), svc, "", nil, "deny"},
		{"service query short pubkey", "POST", acc.URL + "/v1/db/redxai_accounts/query", svc, shortRec + ".pubkey", nil, "deny"},
		{"service boxql short pubkey", "POST", acc.URL + "/v1/db/redxai_accounts/bx", svc, `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> pubkey`, nil, "deny"},
		{"service boxql full", "POST", acc.URL + "/v1/db/redxai_accounts/bx", svc, `{Get[]} = "rxa-lifetime-cert.red-xai.db":Record[ID=1]`, nil, "deny"},
		{"owner full record", "GET", masterPath, tok, "", nil, "owner"},
		{"owner full private_enc", "GET", mp(fullRec + ".private_enc"), tok, "", nil, "owner"},
		{"owner short pubkey", "GET", mp(shortRec + ".pubkey"), tok, "", nil, "ownerpub"},
	} {
		acc.probe(t, p)
	}
	// Host-admin must not read the master cert (hidden db) and must not export it.
	st, b, _ = do(t, "GET", acc.URL+"/v1/admin/backup", acc.Key, "")
	raw = b
	if st == 200 {
		if zr, err := gzip.NewReader(bytes.NewReader([]byte(b))); err == nil {
			buf, _ := io.ReadAll(io.LimitReader(zr, 32<<20))
			zr.Close()
			raw = string(buf)
		}
	}
	bhit = scanQA(raw)
	if st == 200 || bhit.any() {
		t.Errorf("LEAK accounts-on admin backup: status=%d %s", st, bhit)
	}
	t.Logf("accounts-on admin backup status=%d %s", st, bhit)
	st, b, _ = do(t, "GET", acc.URL+"/v1/admin/backup", tok, "")
	if st != 200 {
		t.Errorf("owner backup: status=%d", st)
	} else {
		plain := b
		if zr, err := gzip.NewReader(strings.NewReader(b)); err == nil {
			buf, _ := io.ReadAll(io.LimitReader(zr, 32<<20))
			zr.Close()
			plain = string(buf)
		}
		oh := scanQA(plain)
		if !oh.secret {
			t.Errorf("owner backup missing ciphertext (present/absent): %s", oh)
		}
		t.Logf("owner backup status=%d %s", st, oh)
	}

	scanLogs(t, qs)
	scanLogs(t, acc)
}

func scanLogs(t *testing.T, qs *qaServer) {
	t.Helper()
	qs.mu.Lock()
	logs := strings.Join(qs.logs, "\n")
	qs.mu.Unlock()
	lh := scanQA(logs)
	if lh.any() || strings.Contains(logs, "PRIVATE KEY") || strings.Contains(logs, "-----BEGIN") {
		t.Errorf("server log leak %s pem=%v", lh, strings.Contains(logs, "-----BEGIN") || strings.Contains(logs, "PRIVATE KEY"))
	}
	t.Logf("server log lines=%d %s", len(qs.logs), lh)

	auditHits := 0
	dataHits := 0
	pemHits := 0
	_ = filepath.Walk(qs.Dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || fi.Size() > 32<<20 {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(qs.Dir, p)
		text := string(b)
		isAudit := strings.HasPrefix(rel, "audit.log")
		if isAudit && (strings.Contains(text, "-----BEGIN") || strings.Contains(text, "PRIVATE KEY")) {
			pemHits++
		}
		if !strings.Contains(text, qaMarker) {
			return nil
		}
		if isAudit {
			auditHits++
			t.Errorf("audit file contains ciphertext: %s", rel)
		} else {
			dataHits++
		}
		return nil
	})
	t.Logf("leak-scan audit_files_with_ciphertext=%d pem_or_key_headers=%d data_files_with_stored_ciphertext=%d", auditHits, pemHits, dataHits)
}
