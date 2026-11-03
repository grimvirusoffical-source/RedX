package host_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"redx/box"
	"redx/host"
	"redx/host/engineadapter"
	"redx/host/internal/stubstore"
)

const recordTestPath = "rxa-bridge-platform.red-xai.db:Record[ID=42]"

// Route real HTTP requests through the real Host.Handler without opening any
// sockets. These source tests run in restricted/offline environments as well.
type recordTestNetwork struct {
	mu       sync.RWMutex
	handlers map[string]http.Handler
	next     uint64
}

func (n *recordTestNetwork) RoundTrip(r *http.Request) (*http.Response, error) {
	n.mu.RLock()
	handler := n.handlers[r.URL.Scheme+"://"+r.URL.Host]
	n.mu.RUnlock()
	if handler == nil {
		return nil, fmt.Errorf("unregistered fixture origin")
	}
	req := r.Clone(r.Context())
	req.RemoteAddr = "127.0.0.1:54321"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	result := response.Result()
	result.Request = r
	return result, nil
}
func recordNetwork(t *testing.T) *recordTestNetwork {
	t.Helper()
	if n, ok := http.DefaultTransport.(*recordTestNetwork); ok {
		return n
	}
	prior := http.DefaultTransport
	n := &recordTestNetwork{handlers: map[string]http.Handler{}, next: 18000}
	http.DefaultTransport = n
	t.Cleanup(func() { http.DefaultTransport = prior })
	return n
}
func (n *recordTestNetwork) register(handler http.Handler) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.next++
	origin := fmt.Sprintf("http://127.0.0.1:%d", n.next)
	n.handlers[origin] = handler
	return origin
}

func startRecordNode(t *testing.T, dir, durability string) *node {
	t.Helper()
	n := &node{Dir: dir}
	network := recordNetwork(t)
	n.URL = network.register(http.NotFoundHandler())
	cfg := baseCfg(dir)
	cfg.Advertise, cfg.RateRPS, cfg.RateBurst = n.URL, 1000, 1000
	opener := engineadapter.Opener(engineadapter.Config{Durability: durability})
	if durability == "stub" {
		opener = stubstore.Open
	}
	h, err := host.New(cfg, opener, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	n.H, n.Key = h, h.BootstrapKey
	network.mu.Lock()
	network.handlers[n.URL] = h.Handler()
	network.mu.Unlock()
	t.Cleanup(n.Stop)
	return n
}

func recordURL(n *node, db, path string) string {
	return n.URL + "/v1/db/" + db + "/record-cas/" + url.PathEscape(path)
}
func recordBody(expected uint64, key, payload string) string {
	b, _ := json.Marshal(map[string]interface{}{"expected_revision": expected, "record": host.CASRecord{Key: key, Revision: expected + 1, Payload: payload}})
	return string(b)
}
func readRecord(t *testing.T, n *node, key string) host.CASRecord {
	t.Helper()
	status, body, _ := do(t, "GET", recordURL(n, "default", recordTestPath), key, "")
	var response struct {
		Record host.CASRecord `json:"record"`
	}
	if status != 200 || json.Unmarshal([]byte(body), &response) != nil {
		t.Fatalf("read record: %d %s", status, body)
	}
	return response.Record
}

func TestRecordCASHTTPLifecycleAndNativeEnvelope(t *testing.T) {
	n := startRecordNode(t, t.TempDir(), "group")
	u := recordURL(n, "default", recordTestPath)
	if status, body, headers := do(t, "GET", u, n.Key, ""); status != 404 || codeOf(t, body) != "record_not_found" || headers.Get("X-Redx-Record-CAS") != "1" {
		t.Fatalf("absent: %d %s", status, body)
	}
	payload := "{\"key\":\"bridge-platform-v1\",\"schema\":1,\"revision\":1,\"message\":\"quoted \\\" text 雪\\n\"}"
	status, body, headers := do(t, "POST", u, n.Key, recordBody(0, "bridge-platform-v1", payload), "Content-Type", "application/json")
	seq, _ := jsonOf(t, body)["seq"].(float64)
	if status != 200 || jsonOf(t, body)["revision"] != float64(1) || jsonOf(t, body)["ok"] != true || seq <= 0 || seq > float64(host.MaxRecordRevision) || headers.Get("X-Redx-Record-CAS") != "1" {
		t.Fatalf("create: %d %s", status, body)
	}
	r := readRecord(t, n, n.Key)
	if r.Key != "bridge-platform-v1" || r.Revision != 1 || r.Payload != payload {
		t.Fatalf("typed round trip: %+v", r)
	}
	var state map[string]interface{}
	if err := json.Unmarshal([]byte(r.Payload), &state); err != nil || state["revision"] != float64(1) {
		t.Fatalf("payload JSON: %v %v", state, err)
	}
	status, raw, _ := do(t, "GET", n.URL+"/v1/db/default/path/"+url.PathEscape(recordTestPath), n.Key, "")
	value, err := box.ParseValue(jsonOf(t, raw)["value"].(string))
	if status != 200 || err != nil || value.Kind != box.KindBox {
		t.Fatalf("native envelope: %d %s %v", status, raw, err)
	}
	if e := value.Box.Lookup(box.Seg{Name: "payload"}); e == nil || e.Value.Str != payload {
		t.Fatal("native Box string decoded incorrectly")
	}
	for _, b := range []string{recordBody(0, "bridge-platform-v1", "duplicate"), recordBody(1, "other-namespace", "collision")} {
		if s, b, _ := do(t, "POST", u, n.Key, b); s != 409 || codeOf(t, b) != "record_conflict" || strings.Contains(b, payload) {
			t.Fatalf("conflict: %d %s", s, b)
		}
	}
	if s, b, _ := do(t, "POST", u, n.Key, recordBody(1, "bridge-platform-v1", "next")); s != 200 {
		t.Fatalf("replace: %d %s", s, b)
	}
	oldKey, dir := n.Key, n.Dir
	n.Stop()
	n = startRecordNode(t, dir, "group")
	r = readRecord(t, n, oldKey)
	if r.Revision != 2 || r.Payload != "next" {
		t.Fatalf("restart lost state: %+v", r)
	}
}

func TestRecordCASHTTPConcurrentFirstWriteHasOneWinner(t *testing.T) {
	n := startRecordNode(t, t.TempDir(), "sync")
	var wins atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			s, b, _ := do(t, "POST", recordURL(n, "default", recordTestPath), n.Key, recordBody(0, "bridge-platform-v1", "one"))
			if s == 200 {
				wins.Add(1)
			} else if s != 409 || codeOf(t, b) != "record_conflict" {
				t.Errorf("concurrent writer: %d %s", s, b)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 || readRecord(t, n, n.Key).Revision != 1 {
		t.Fatalf("successful creators: %d", wins.Load())
	}
}

func TestRecordCASHTTPRejectsUnsafeInputScopeAndPolicy(t *testing.T) {
	n := startRecordNode(t, t.TempDir(), "sync")
	u := recordURL(n, "default", recordTestPath)
	if s, _, _ := do(t, "POST", u, "", recordBody(0, "bridge-platform-v1", "secret")); s != 401 {
		t.Fatalf("unsigned: %d", s)
	}
	ro, _ := mkKey(t, n, map[string]interface{}{"scope": "read", "db": "default"})
	wrong, _ := mkKey(t, n, map[string]interface{}{"scope": "write", "db": "default", "prefix": "elsewhere.red-xai.db"})
	other, _ := mkKey(t, n, map[string]interface{}{"scope": "write", "db": "other"})
	for _, key := range []string{ro, wrong, other} {
		if s, _, _ := do(t, "POST", u, key, recordBody(0, "bridge-platform-v1", "secret")); s != 403 {
			t.Fatalf("ACL write: %d", s)
		}
	}
	for _, p := range []string{"Record[ID=42]", "rxa-bridge-platform:Record[ID=42]", recordTestPath + ".payload", "rxa-bridge-platform.red-xai.db:Record[ID=*]", "rxa-bridge-platform.red-xai.db:Record[ID=042]", "rxa-bridge-platform.red-xai-db-qs:Record[ID=42]"} {
		if s, _, _ := do(t, "POST", recordURL(n, "default", p), n.Key, recordBody(0, "bridge-platform-v1", "secret")); s != 400 {
			t.Fatalf("path %q: %d", p, s)
		}
	}
	for _, body := range []string{`{}`, `{"expected_revision":null,"record":{"key":"abc","revision":1,"payload":"x"}}`, `{"expected_revision":0,"record":{"key":"abc","revision":2,"payload":"x"}}`, `{"expected_revision":9007199254740991,"record":{"key":"abc","revision":9007199254740992,"payload":"x"}}`, recordBody(0, "bridge-platform-v1", "x") + `{}`, `{"expected_revision":0,"record":{"key":"abc","revision":1,"payload":"x","role":"owner"}}`} {
		if s, _, _ := do(t, "POST", u, n.Key, body); s != 400 {
			t.Fatalf("malformed body %q: %d", body, s)
		}
	}
	if s, b, _ := do(t, "POST", u, n.Key, recordBody(0, "bridge-platform-v1", "secret")); s != 200 {
		t.Fatalf("seed: %d %s", s, b)
	}
	if r := readRecord(t, n, ro); r.Payload != "secret" {
		t.Fatal("read scope did not work")
	}
	guest, _ := mkKey(t, n, map[string]interface{}{"scope": "write", "db": "default", "roles": []string{"guest"}, "prefix": "rxa-bridge-platform.red-xai.db:Record"})
	policy := `{Role[1]} = [ {Name[]} = "guest" ]; {Rule[1]} = [ {Effect[]} = "deny", {Who[]} = ;["role:guest"]:, {Actions[]} = "*", {Resource[]} = "rxa-bridge-platform.red-xai.db:Record.payload" ];`
	if s, b, _ := do(t, "PUT", n.URL+"/v1/db/default/sec", n.Key, policy); s != 200 {
		t.Fatalf("policy: %d %s", s, b)
	}
	for _, method := range []string{"GET", "POST"} {
		if s, b, _ := do(t, method, u, guest, recordBody(1, "bridge-platform-v1", "forged")); s != 403 || strings.Contains(b, "secret") {
			t.Fatalf("policy %s: %d %s", method, s, b)
		}
	}
	if r := readRecord(t, n, n.Key); r.Revision != 1 || r.Payload != "secret" {
		t.Fatal("denied write changed record")
	}
}

func TestRecordCASHTTPRefusesAsyncRulesAndUnsupportedBackend(t *testing.T) {
	n := startRecordNode(t, t.TempDir(), "async")
	if s, _, _ := do(t, "POST", recordURL(n, "default", recordTestPath), n.Key, recordBody(0, "bridge-platform-v1", "x")); s != 503 {
		t.Fatalf("async: %d", s)
	}
	stub := startRecordNode(t, t.TempDir(), "stub")
	if s, _, _ := do(t, "POST", recordURL(stub, "default", recordTestPath), stub.Key, recordBody(0, "bridge-platform-v1", "x")); s != 501 {
		t.Fatalf("unsupported: %d", s)
	}
	n = startRecordNode(t, t.TempDir(), "sync")
	// Existing Pulse grammar; the rule need not target the ledger to require
	// explicit refusal rather than silently bypassing the rule engine.
	rule := `{PlayerDeath[ON="players.red-xai.db:Player[ID=*].Health"]} = [ {When[]} = "<= 0", {SetTarget[]} = "Player.IsDead = TRUE", {Emit[]} = "player.died" ];`
	if s, b, _ := do(t, "PUT", n.URL+"/v1/db/default/pulse", n.Key, rule); s != 200 {
		t.Fatalf("rules fixture: %d %s", s, b)
	}
	if s, _, _ := do(t, "POST", recordURL(n, "default", recordTestPath), n.Key, recordBody(0, "bridge-platform-v1", "x")); s != 503 {
		t.Fatalf("rules bypassed: %d", s)
	}
}

func TestRecordCASHTTPWebsiteTenantCSRFAndMasterGates(t *testing.T) {
	network := recordNetwork(t)
	authorityURL := network.register(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("redx_session")
		if err != nil || c.Value != "alpha" && c.Value != "beta" {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"account": map[string]interface{}{"id": "canonical-" + c.Value, "email": "fixture@example.invalid", "roles": []string{"user"}}, "amr": []string{"pwd", "otp"}, "expiresMs": time.Now().Add(time.Hour).UnixMilli()})
	}))
	n := startRecordNode(t, t.TempDir(), "group")
	host.SetWebsiteAuthorityForTest(n.H, authorityURL, n.URL, &http.Client{Transport: network}, nil)
	for _, sub := range []string{"canonical-alpha", "canonical-beta"} {
		if err := host.SetPlanForTest(n.H, hostedPlan(sub, "basic", "month", "active", time.Now().Add(time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	call := func(method, path, cookie, origin, body string) (int, string) {
		return rawReq(t, method, n.URL+path, "", body, "Cookie", "redx_session="+cookie, "Origin", origin, "Content-Type", "application/json")
	}
	s, b := call("POST", "/v1/dbs", "alpha", n.URL, `{"name":"bridge"}`)
	if s != 201 {
		t.Fatalf("tenant database: %d %s", s, b)
	}
	db := jsonOf(t, b)["name"].(string)
	p := "/v1/db/" + db + "/record-cas/" + url.PathEscape(recordTestPath)
	if s, b = call("POST", p, "alpha", "https://foreign.invalid", recordBody(0, "bridge-platform-v1", "x")); s != 403 {
		t.Fatalf("cross-origin: %d %s", s, b)
	}
	if s, b = call("POST", p, "alpha", n.URL, recordBody(0, "bridge-platform-v1", "tenant-only")); s != 200 {
		t.Fatalf("tenant write: %d %s", s, b)
	}
	for _, method := range []string{"GET", "POST"} {
		if s, b = call(method, p, "beta", n.URL, recordBody(1, "bridge-platform-v1", "bad")); s != 404 || strings.Contains(b, "tenant-only") {
			t.Fatalf("other tenant %s: %d %s", method, s, b)
		}
	}
	if err := host.SetPlanForTest(n.H, hostedPlan("canonical-alpha", "basic", "month", "past_due", time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if s, b = call("POST", p, "alpha", n.URL, recordBody(1, "bridge-platform-v1", "bad")); s != 402 {
		t.Fatalf("billing gate: %d %s", s, b)
	}
	master := "/v1/db/" + n.H.Cfg.AccountsMasterDB + "/record-cas/" + url.PathEscape(recordTestPath)
	if s, b, _ = do(t, "GET", n.URL+master, n.Key, ""); s != 404 {
		t.Fatalf("master hidden from host key: %d %s", s, b)
	}
	log, err := os.ReadFile(n.H.Cfg.AuditLog)
	if err != nil || strings.Contains(string(log), "tenant-only") {
		t.Fatalf("record payload leaked to audit: %v", err)
	}
}

func TestRecordCASHTTPRejectsMalformedStoredEnvelopeWithoutOverwrite(t *testing.T) {
	n := startRecordNode(t, t.TempDir(), "sync")
	path := n.URL + "/v1/db/default/path/" + url.PathEscape(recordTestPath)
	if s, b, _ := do(t, "PUT", path, n.Key, `[ {key[]} = "bridge-platform-v1", {revision[]} = 1, {payload[]} = "keep", {unexpected[]} = TRUE ]`); s != 200 {
		t.Fatalf("legacy fixture: %d %s", s, b)
	}
	u := recordURL(n, "default", recordTestPath)
	for _, method := range []string{"GET", "POST"} {
		if s, b, _ := do(t, method, u, n.Key, recordBody(1, "bridge-platform-v1", "overwrite")); s != 500 || strings.Contains(b, "keep") {
			t.Fatalf("malformed stored %s: %d %s", method, s, b)
		}
	}
	if s, b, _ := do(t, "GET", path, n.Key, ""); s != 200 || !strings.Contains(b, "unexpected") || strings.Contains(b, "overwrite") {
		t.Fatalf("malformed envelope was modified: %d %s", s, b)
	}
}

type blockedRecordBody struct {
	ready   chan struct{}
	release chan struct{}
	once    sync.Once
	reader  io.Reader
}

func (b *blockedRecordBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.ready) })
	<-b.release
	return b.reader.Read(p)
}
func (*blockedRecordBody) Close() error { return nil }

func TestRecordCASHTTPDoesNotHoldHostLocksWhileReadingBody(t *testing.T) {
	n := startRecordNode(t, t.TempDir(), "sync")
	u := recordURL(n, "default", recordTestPath)
	if s, b, _ := do(t, "POST", u, n.Key, recordBody(0, "bridge-platform-v1", "one")); s != 200 {
		t.Fatalf("seed: %d %s", s, b)
	}
	body := &blockedRecordBody{ready: make(chan struct{}), release: make(chan struct{}), reader: strings.NewReader(recordBody(1, "bridge-platform-v1", "two"))}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(body.release) }) }
	defer release()
	r, _ := http.NewRequest("POST", u, body)
	r.Header.Set("Authorization", "Bearer "+n.Key)
	writeDone := make(chan error, 1)
	go func() {
		response, err := http.DefaultClient.Do(r)
		if err == nil {
			response.Body.Close()
			if response.StatusCode != 200 {
				err = fmt.Errorf("status %d", response.StatusCode)
			}
		}
		writeDone <- err
	}()
	<-body.ready
	readDone := make(chan int, 1)
	go func() {
		response, err := http.DefaultClient.Get(u)
		if err != nil {
			readDone <- 0
			return
		}
		defer response.Body.Close()
		readDone <- response.StatusCode
	}()
	// The unsigned read proves authentication is not held, but use a signed
	// read too so this exercises the actual database/configuration locks.
	if s := <-readDone; s != 401 {
		t.Fatalf("unsigned read: %d", s)
	}
	signedDone := make(chan int, 1)
	go func() {
		request, _ := http.NewRequest("GET", u, nil)
		request.Header.Set("Authorization", "Bearer "+n.Key)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			signedDone <- 0
			return
		}
		defer response.Body.Close()
		signedDone <- response.StatusCode
	}()
	select {
	case s := <-signedDone:
		if s != 200 {
			t.Fatalf("read while body blocked: %d", s)
		}
	case <-time.After(time.Second):
		t.Fatal("unread request body held host database locks")
	}
	// Release exactly once; do not leave the writer running beyond this test.
	release()
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}

func TestRecordCASHTTPRechecksFencingAfterPendingBody(t *testing.T) {
	n := startRecordNode(t, t.TempDir(), "sync")
	u := recordURL(n, "default", recordTestPath)
	if s, b, _ := do(t, "POST", u, n.Key, recordBody(0, "bridge-platform-v1", "before-fence")); s != 200 {
		t.Fatalf("seed: %d %s", s, b)
	}
	member, err := host.JoinLeader(context.Background(), http.DefaultClient, n.URL, joinToken(t, n), "promoted-fixture", "")
	if err != nil {
		t.Fatal(err)
	}
	prior := status(t, n)
	body := &blockedRecordBody{ready: make(chan struct{}), release: make(chan struct{}), reader: strings.NewReader(recordBody(1, "bridge-platform-v1", "must-not-commit"))}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(body.release) }) }
	defer release()
	request, _ := http.NewRequest("POST", u, body)
	request.Header.Set("Authorization", "Bearer "+n.Key)
	type outcome struct {
		status int
		err    error
	}
	finished := make(chan outcome, 1)
	go func() {
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			finished <- outcome{err: err}
			return
		}
		defer response.Body.Close()
		io.Copy(io.Discard, response.Body)
		finished <- outcome{status: response.StatusCode}
	}()
	select {
	case <-body.ready:
	case <-time.After(time.Second):
		t.Fatal("pending body never reached read")
	}
	fence, _ := json.Marshal(map[string]string{"leader_url": "http://127.0.0.1:19999", "replication_id": "promoted-fixture-history", "parent_id": prior.ReplID})
	if s, b, _ := do(t, "POST", n.URL+"/v1/cluster/superseded", member.NodeSecret, string(fence), "X-Redx-Node", "promoted-fixture"); s != 200 || jsonOf(t, b)["fenced"] != true {
		t.Fatalf("authenticated fence: %d %s", s, b)
	}
	release()
	select {
	case result := <-finished:
		if result.err != nil || result.status != 503 {
			t.Fatalf("pending write after fence: status%d err%v", result.status, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending write did not stop after fence")
	}
	if s, _, _ := do(t, "GET", u, n.Key, ""); s != 503 {
		t.Fatalf("fenced former leader returned authoritative record: %d", s)
	}
	// Legacy inspection remains available; verify the already-authorized body
	// did not advance the ledger or replace its payload after fencing.
	raw, err := n.H.ReadGet("default", recordTestPath)
	if err != nil {
		t.Fatal(err)
	}
	value, err := box.ParseValue(raw)
	if err != nil || value.Box.Lookup(box.Seg{Name: "revision"}).Value.Num != 1 || value.Box.Lookup(box.Seg{Name: "payload"}).Value.Str != "before-fence" {
		t.Fatalf("fenced write changed the stored record: %v", err)
	}
}
