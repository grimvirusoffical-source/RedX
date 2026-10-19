package host_test

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"redx/host"
	"redx/host/accountsfake"
)

func zipBytes(files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			panic(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			panic(err)
		}
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func storedZip(name string, payload []byte) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	h := &zip.FileHeader{Name: name, Method: zip.Store}
	w, err := zw.CreateHeader(h)
	if err != nil {
		panic(err)
	}
	if _, err := w.Write(payload); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func appField(t *testing.T, body, key string) string {
	t.Helper()
	s, _ := jsonOf(t, body)[key].(string)
	return s
}

func runtimeArgs(t *testing.T, body string) string {
	t.Helper()
	rt, _ := jsonOf(t, body)["runtime"].(map[string]interface{})
	if rt == nil {
		t.Fatalf("no runtime spec: %s", body)
	}
	raw, _ := json.Marshal(rt["args"])
	return string(raw)
}

func TestHostedAppsIsolation(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	n.H.Cfg.AppsLimits = map[string]host.AppLimit{"basic": {Domains: 8}}
	end := time.Now().Add(30 * 24 * time.Hour)
	tokA, _ := signIn(t, n, f, regular)
	secret := "s3cret-value-9f3a-not-returned"

	st, b, _ := do(t, "POST", n.URL+"/v1/hosted/apps", tokA, `{"name":"site","kind":"static"}`, "Content-Type", "application/json")
	if st != 402 || codeOf(t, b) != "plan_required" {
		t.Fatalf("no plan create: %d %s", st, b)
	}
	if st, b, _ = do(t, "GET", n.URL+"/v1/hosted/apps", tokA, ""); st != 403 {
		t.Fatalf("no plan list: %d %s", st, b)
	}

	if err := host.SetPlanForTest(n.H, hostedPlan(regular.Sub, "basic", "month", "active", end)); err != nil {
		t.Fatal(err)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/dbs", tokA, `{"name":"game"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("db: %d %s", st, b)
	}
	physA := appField(t, b, "name")

	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps", tokA, `{"name":"site","kind":"static","db":"game"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	idA := appField(t, b, "id")
	hostA := appField(t, b, "host")
	if !strings.HasPrefix(hostA, "site-") || !strings.HasSuffix(hostA, ".host.rottenapplestore.org") {
		t.Fatalf("default host: %s", hostA)
	}
	if strings.Contains(b, secret) {
		t.Fatal("create response leaked a secret")
	}

	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps", tokA, `{"name":"extra","kind":"static"}`, "Content-Type", "application/json")
	if st != 402 || codeOf(t, b) != "quota_exceeded" || jsonOf(t, b)["limit"] != "app_quota" {
		t.Fatalf("app quota: %d %s", st, b)
	}

	for _, db := range []string{"default", "redxai_accounts", "admin"} {
		st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps", tokA, `{"name":"nope","kind":"static","db":"`+db+`"}`, "Content-Type", "application/json")
		if st != 400 && st != 404 && st != 409 {
			t.Fatalf("bind %s: %d %s", db, st, b)
		}
	}

	other := accountsfake.Identity{Sub: "rxa_OTHER000000000000000000001", Email: "other@example.com", EmailVerified: true, Username: "other_user", AMR: []string{"pwd"}}
	tokB, _ := signIn(t, n, f, other)
	if err := host.SetPlanForTest(n.H, hostedPlan(other.Sub, "gold", "month", "active", end)); err != nil {
		t.Fatal(err)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/dbs", tokB, `{"name":"game"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("other db: %d %s", st, b)
	}
	physB := appField(t, b, "name")
	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps", tokA, `{"name":"site","kind":"static","db":"`+physB+`"}`, "Content-Type", "application/json")
	if st != 404 || !strings.Contains(b, "database not found") {
		t.Fatalf("cross db bind: %d %s", st, b)
	}

	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps", tokB, `{"name":"shop","kind":"container"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("other app: %d %s", st, b)
	}
	idB := appField(t, b, "id")

	if st, b, _ = do(t, "GET", n.URL+"/v1/hosted/apps/"+idB, tokA, ""); st != 404 {
		t.Fatalf("cross get: %d %s", st, b)
	}
	if st, b, _ = do(t, "GET", n.URL+"/v1/hosted/apps", tokA, ""); st != 200 || strings.Contains(b, idB) || strings.Contains(b, "shop") {
		t.Fatalf("list hides the other tenant: %d %s", st, b)
	}

	arch := zipBytes(map[string]string{"index.html": "<h1>site</h1>"})
	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+idA+"/archive", tokA, string(arch))
	if st != 201 {
		t.Fatalf("archive: %d %s", st, b)
	}
	args := runtimeArgs(t, b)
	for _, flag := range []string{"--userns=keep-id:uid=", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--security-opt=seccomp=", "--read-only", "--network=pasta:--no-map-gw", "127.0.0.1:", "--memory=", "--cpus=", "--pids-limit=", "--cgroup-parent", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--env-file"} {
		if !strings.Contains(args, flag) {
			t.Fatalf("runtime spec missing %s: %s", flag, args)
		}
	}
	for _, bad := range []string{"--network=host", "--privileged", "docker.sock", "keys.red-xai-keys", "master.key", ":7777", ":7780", "STRIPE", secret} {
		if strings.Contains(args, bad) {
			t.Fatalf("runtime spec contains %s: %s", bad, args)
		}
	}
	if strings.Contains(b, secret) {
		t.Fatal("deploy response leaked secret")
	}
	if !strings.Contains(b, `"user":"rxapp-`) || !strings.Contains(b, `"egress":"internet"`) || !strings.Contains(b, "127.0.0.0/8") {
		t.Fatalf("sandbox identity: %s", b)
	}
	dep := appField(t, b, "deploy")
	st, man, hdr := do(t, "GET", n.URL+"/v1/hosted/apps/"+idA+"/deploys/"+dep+"/manifest", tokA, "")
	if st != 200 || !strings.Contains(man, "redx.update-manifest/v1") {
		t.Fatalf("manifest: %d %s", st, man)
	}
	sig := hdr.Get("X-RedX-Signature")
	rawSig, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sig, "ed25519:"))
	pub := ed25519.PublicKey(host.UpdatePublicKeyForTest(n.H))
	if err != nil || !ed25519.Verify(pub, []byte(man), rawSig) {
		t.Fatalf("manifest signature: %v %s", err, sig)
	}

	if st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+idA+"/start", tokA, ""); st != 200 || jsonOf(t, b)["running"] != true {
		t.Fatalf("start: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", n.URL+"/", "", "", "Host", hostA)
	if st != 200 || !strings.Contains(b, "<h1>site</h1>") {
		t.Fatalf("public site: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", n.URL+"/v1/hosted/apps", tokA, "", "Host", hostA)
	if strings.Contains(b, idB) || strings.Contains(b, physA) && strings.Contains(b, `"apps"`) {
		t.Fatalf("app host must not serve the API: %d %s", st, b)
	}

	ask := func(domain, remote string, header ...string) (int, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/v1/hosted/tls/ask?domain="+domain, nil)
		req.RemoteAddr = remote
		req.Host = "127.0.0.1"
		for i := 0; i+1 < len(header); i += 2 {
			req.Header.Set(header[i], header[i+1])
		}
		rr := httptest.NewRecorder()
		n.H.Handler().ServeHTTP(rr, req)
		return rr.Code, rr.Body.String()
	}
	if st, b := ask("not-ours.example", "127.0.0.1:9"); st != 403 {
		t.Fatalf("unverified ask: %d %s", st, b)
	}
	if st, b := ask(hostA, "203.0.113.5:443"); st != 403 {
		t.Fatalf("non-loopback ask: %d %s", st, b)
	}
	if st, b := ask(hostA, "127.0.0.1:9"); st != 200 || !strings.Contains(b, "allow") {
		t.Fatalf("default host ask: %d %s", st, b)
	}

	st, b, _ = do(t, "POST", n.URL+"/v1/keys", tokA, `{"db":"`+physA+`","scope":"read","label":"ro"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("read key: %d %s", st, b)
	}
	readKey := appField(t, b, "key")
	if st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps", readKey, `{"name":"nope","kind":"static"}`, "Content-Type", "application/json"); st != 403 {
		t.Fatalf("read key create: %d %s", st, b)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/keys", tokA, `{"db":"`+physA+`","scope":"write","label":"rw"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("write key: %d %s", st, b)
	}
	writeKey := appField(t, b, "key")
	if st, b, _ = do(t, "GET", n.URL+"/v1/hosted/apps/"+idA, writeKey, ""); st != 200 || strings.Contains(b, secret) {
		t.Fatalf("own key: %d %s", st, b)
	}
	if st, b, _ = do(t, "GET", n.URL+"/v1/hosted/apps/"+idB, writeKey, ""); st != 404 {
		t.Fatalf("key cross: %d %s", st, b)
	}
	if st, b, _ = do(t, "GET", n.URL+"/v1/hosted/caddy", tokA, ""); st != 403 {
		t.Fatalf("tenant caddy: %d %s", st, b)
	}

	tokO, _ := signIn(t, n, f, ownerOK)
	if st, b, _ = do(t, "GET", n.URL+"/v1/hosted/apps", tokO, ""); st != 200 || !strings.Contains(b, idA) || !strings.Contains(b, idB) || strings.Contains(b, secret) {
		t.Fatalf("owner list: %d %s", st, b)
	}
	audit, err := os.ReadFile(n.H.Cfg.AuditLog)
	if err != nil || !strings.Contains(string(audit), `"event":"owner.read"`) || !strings.Contains(string(audit), "Owner@Example.com") {
		t.Fatalf("owner audit: %v", err)
	}
	var ch http.Header
	st, b, ch = do(t, "GET", n.URL+"/v1/hosted/caddy", tokO, "")
	if st != 200 || !strings.Contains(b, "on_demand_tls") || strings.Contains(ch.Get("Content-Type"), "json") {
		t.Fatalf("caddy: %d %s %s", st, ch.Get("Content-Type"), b)
	}
}

func TestHostedAppsPlanAndQuota(t *testing.T) {
	f, iss := startFake(t)
	n := startNode(t, t.TempDir(), func(c *host.Config, u string) {
		c.AccountsIssuer = iss
		c.AccountsClientSecret = "test-client-secret"
		c.AccountsEventsPoll = 3600
		c.OwnerEmails = []string{ownerA, ownerB}
		c.AppsLimits = map[string]host.AppLimit{"basic": {DiskMB: 1}}
	})
	end := time.Now().Add(30 * 24 * time.Hour)
	tok, _ := signIn(t, n, f, regular)
	if err := host.SetPlanForTest(n.H, hostedPlan(regular.Sub, "basic", "month", "active", end)); err != nil {
		t.Fatal(err)
	}
	st, b, _ := do(t, "POST", n.URL+"/v1/hosted/apps", tok, `{"name":"site","kind":"static"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	id := appField(t, b, "id")
	big := storedZip("index.html", bytes.Repeat([]byte("x"), 2<<20))
	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+id+"/archive", tok, string(big))
	if st != 402 || codeOf(t, b) != "quota_exceeded" || jsonOf(t, b)["limit"] != "app_disk_quota" {
		t.Fatalf("disk: %d %s", st, b)
	}
	small := zipBytes(map[string]string{"index.html": "ok"})
	if st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+id+"/archive", tok, string(small)); st != 201 {
		t.Fatalf("small: %d %s", st, b)
	}
	if st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+id+"/start", tok, ""); st != 200 {
		t.Fatalf("start: %d %s", st, b)
	}
	if st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+id+"/start", tok, ""); st != 200 {
		t.Fatalf("start again: %d %s", st, b)
	}
	if st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+id+"/stop", tok, ""); st != 200 || jsonOf(t, b)["running"] != false {
		t.Fatalf("stop: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", n.URL+"/", "", "", "Host", appField(t, b, "host"))
	if st != 503 {
		t.Fatalf("stopped site: %d %s", st, b)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+id+"/start", tok, "")
	if st != 402 || jsonOf(t, b)["limit"] != "host_switch_quota" {
		t.Fatalf("switch cap: %d %s", st, b)
	}

	if err := host.SetPlanForTest(n.H, hostedPlan(regular.Sub, "basic", "month", "past_due", end)); err != nil {
		t.Fatal(err)
	}
	if st, b, _ = do(t, "GET", n.URL+"/v1/hosted/apps/"+id, tok, ""); st != 200 || jsonOf(t, b)["readonly"] != true {
		t.Fatalf("readonly get: %d %s", st, b)
	}
	if st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+id+"/deploy", tok, `{"source":"image","image":"example.com/app:1"}`, "Content-Type", "application/json"); st != 402 || codeOf(t, b) != "plan_readonly" {
		t.Fatalf("readonly write: %d %s", st, b)
	}

	if err := host.SetPlanForTest(n.H, hostedPlan(regular.Sub, "basic", "month", "canceled", time.Now().Add(-10*24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if st, b, _ = do(t, "GET", n.URL+"/v1/hosted/apps", tok, ""); st != 200 || jsonOf(t, b)["suspended"] != true {
		t.Fatalf("suspended list: %d %s", st, b)
	}
	if st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+id+"/stop", tok, ""); st != 402 || codeOf(t, b) != "plan_required" {
		t.Fatalf("suspended write: %d %s", st, b)
	}
}

func TestHostedAppsRollout(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	host.SetHostedFetchForTest(n.H, func(repo, ref string) ([]byte, error) {
		if repo == "acme/site" && ref == "v1" {
			return zipBytes(map[string]string{"index.html": "<p>v1</p>", "Dockerfile": "FROM scratch\n"}), nil
		}
		if repo == "acme/site" && ref == "v2" {
			return zipBytes(map[string]string{"public/index.html": "<p>v2</p>"}), nil
		}
		return nil, os.ErrNotExist
	})
	st, b, _ := do(t, "POST", n.URL+"/v1/hosted/apps", n.Key, `{"name":"web","kind":"static"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	id := appField(t, b, "id")
	hostName := appField(t, b, "host")
	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+id+"/deploy", n.Key, `{"source":"github","repo":"acme/site","ref":"v1","strategy":"direct"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("v1: %d %s", st, b)
	}
	first := appField(t, b, "deploy")
	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+id+"/deploy", n.Key, `{"source":"github","repo":"acme/site","ref":"v2","strategy":"canary","canaryPct":100}`, "Content-Type", "application/json")
	if st != 201 || jsonOf(t, b)["canary"] == "" {
		t.Fatalf("canary: %d %s", st, b)
	}
	if st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+id+"/start", n.Key, ""); st != 200 {
		t.Fatalf("start: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", n.URL+"/", "", "", "Host", hostName)
	if st != 200 || !strings.Contains(b, "v2") {
		t.Fatalf("canary traffic: %d %s", st, b)
	}
	if st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+id+"/promote", n.Key, ""); st != 200 || jsonOf(t, b)["current"] == first || jsonOf(t, b)["canary"] != "" {
		t.Fatalf("promote: %d %s", st, b)
	}
	if st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+id+"/rollback", n.Key, `{"deploy":"`+first+`"}`, "Content-Type", "application/json"); st != 200 || jsonOf(t, b)["current"] != first {
		t.Fatalf("rollback: %d %s", st, b)
	}
	st, b, _ = do(t, "GET", n.URL+"/", "", "", "Host", hostName)
	if st != 200 || !strings.Contains(b, "v1") {
		t.Fatalf("rolled back site: %d %s", st, b)
	}

	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps", n.Key, `{"name":"job","kind":"container"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("container: %d %s", st, b)
	}
	cid := appField(t, b, "id")
	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+cid+"/deploy", n.Key, `{"source":"image","image":"docker.io/library/caddy:2"}`, "Content-Type", "application/json")
	if st != 201 || !strings.Contains(runtimeArgs(t, b), "docker.io/library/caddy:2") {
		t.Fatalf("image: %d %s", st, b)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+id+"/deploy", n.Key, `{"source":"image","image":"docker.io/library/caddy:2"}`, "Content-Type", "application/json")
	if st != 400 {
		t.Fatalf("static image: %d %s", st, b)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+cid+"/deploy", n.Key, `{"source":"dockerfile","repo":"acme/site","ref":"v1"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("dockerfile: %d %s", st, b)
	}
	rt := jsonOf(t, b)["runtime"].(map[string]interface{})
	built, _ := json.Marshal(rt["buildArgs"])
	if !strings.Contains(string(built), "Dockerfile") || !strings.Contains(string(built), "localhost/redx-") {
		t.Fatalf("build args: %s", built)
	}
}

func TestHostedTLSAskSecret(t *testing.T) {
	n := startNode(t, t.TempDir(), func(c *host.Config, u string) {
		c.AppsTLSAskSecret = "caddy-ask-secret"
	})
	st, b, _ := do(t, "POST", n.URL+"/v1/hosted/apps", n.Key, `{"name":"site","kind":"static"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	hostName := appField(t, b, "host")
	req := httptest.NewRequest(http.MethodGet, "/v1/hosted/tls/ask?domain="+hostName, nil)
	req.RemoteAddr = "203.0.113.9:443"
	rr := httptest.NewRecorder()
	n.H.Handler().ServeHTTP(rr, req)
	if rr.Code != 403 {
		t.Fatalf("missing secret: %d %s", rr.Code, rr.Body.String())
	}
	req.Header.Set("X-RedX-Caddy-Ask", "nope")
	rr = httptest.NewRecorder()
	n.H.Handler().ServeHTTP(rr, req)
	if rr.Code != 403 {
		t.Fatalf("wrong secret: %d", rr.Code)
	}
	req.Header.Set("X-RedX-Caddy-Ask", "caddy-ask-secret")
	rr = httptest.NewRecorder()
	n.H.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("good secret: %d %s", rr.Code, rr.Body.String())
	}
	req.URL.RawQuery = "domain=not-ours.example"
	rr = httptest.NewRecorder()
	n.H.Handler().ServeHTTP(rr, req)
	if rr.Code != 403 {
		t.Fatalf("unknown domain: %d %s", rr.Code, rr.Body.String())
	}
}

func TestHostedHealthRollback(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	end := time.Now().Add(30 * 24 * time.Hour)
	tok, _ := signIn(t, n, f, regular)
	if err := host.SetPlanForTest(n.H, hostedPlan(regular.Sub, "basic", "month", "active", end)); err != nil {
		t.Fatal(err)
	}
	st, b, _ := do(t, "POST", n.URL+"/v1/hosted/apps", tok, `{"name":"site","kind":"static"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	id := appField(t, b, "id")
	arch := zipBytes(map[string]string{"index.html": "<h1>one</h1>"})
	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+id+"/archive", tok, string(arch))
	if st != 201 {
		t.Fatalf("first: %d %s", st, b)
	}
	first := appField(t, b, "deploy")
	host.SetHostedProbeForTest(n.H, func(string) (string, string) { return "unhealthy", "boom" })
	arch = zipBytes(map[string]string{"index.html": "<h1>two</h1>"})
	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+id+"/archive", tok, string(arch))
	if st != 201 || jsonOf(t, b)["rolledBack"] != true || jsonOf(t, b)["current"] != first {
		t.Fatalf("rollback: %d %s", st, b)
	}
	if !strings.Contains(b, `"status":"unhealthy"`) {
		t.Fatalf("failed deploy should be unhealthy: %s", b)
	}
}

func TestHostedDomainQuotaAndCNAME(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	end := time.Now().Add(30 * 24 * time.Hour)
	tok, _ := signIn(t, n, f, regular)
	if err := host.SetPlanForTest(n.H, hostedPlan(regular.Sub, "basic", "month", "active", end)); err != nil {
		t.Fatal(err)
	}
	st, b, _ := do(t, "POST", n.URL+"/v1/hosted/apps", tok, `{"name":"site","kind":"static"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	id := appField(t, b, "id")
	def := appField(t, b, "host")
	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+id+"/domains", tok, `{"domain":"one.example.com","method":"cname"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("cname add: %d %s", st, b)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+id+"/domains", tok, `{"domain":"two.example.com"}`, "Content-Type", "application/json")
	if st != 402 || codeOf(t, b) != "quota_exceeded" || jsonOf(t, b)["limit"] != "domain_quota" {
		t.Fatalf("domain quota: %d %s", st, b)
	}
	host.SetHostedCNAMEForTest(n.H, func(name string) (string, error) {
		if name == "one.example.com" {
			return def + ".", nil
		}
		return "", os.ErrNotExist
	})
	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+id+"/domains/one.example.com/verify", tok, "")
	if st != 200 || !strings.Contains(b, `"verified":true`) {
		t.Fatalf("cname verify: %d %s", st, b)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/hosted/tls/ask?domain=one.example.com", nil)
	req.RemoteAddr = "127.0.0.1:9"
	rr := httptest.NewRecorder()
	n.H.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("verified cname ask: %d %s", rr.Code, rr.Body.String())
	}
}

func TestHostedDomainClaim(t *testing.T) {
	f, iss := startFake(t)
	n := startAcctNode(t, iss)
	n.H.Cfg.AppsLimits = map[string]host.AppLimit{"basic": {Domains: 8}}
	end := time.Now().Add(30 * 24 * time.Hour)
	tokA, _ := signIn(t, n, f, regular)
	if err := host.SetPlanForTest(n.H, hostedPlan(regular.Sub, "basic", "month", "active", end)); err != nil {
		t.Fatal(err)
	}
	st, b, _ := do(t, "POST", n.URL+"/v1/hosted/apps", tokA, `{"name":"site","kind":"static"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	idA := appField(t, b, "id")
	other := accountsfake.Identity{Sub: "rxa_OTHER000000000000000000001", Email: "other@example.com", EmailVerified: true, Username: "other_user", AMR: []string{"pwd"}}
	tokB, _ := signIn(t, n, f, other)
	if err := host.SetPlanForTest(n.H, hostedPlan(other.Sub, "gold", "month", "active", end)); err != nil {
		t.Fatal(err)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps", tokB, `{"name":"shop","kind":"static"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("other: %d %s", st, b)
	}
	idB := appField(t, b, "id")
	if st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+idB+"/domains", tokA, `{"domain":"stolen.example.com"}`, "Content-Type", "application/json"); st != 404 {
		t.Fatalf("cross domain: %d %s", st, b)
	}
	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+idA+"/domains", tokA, `{"domain":"shop.example.com","method":"txt"}`, "Content-Type", "application/json")
	dom, _ := jsonOf(t, b)["domain"].(map[string]interface{})
	if st != 201 || dom == nil || dom["verified"] != false {
		t.Fatalf("add: %d %s", st, b)
	}
	token, _ := dom["token"].(string)
	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+idB+"/domains", tokB, `{"domain":"shop.example.com"}`, "Content-Type", "application/json")
	if st != 409 || codeOf(t, b) != "domain_taken" {
		t.Fatalf("claim: %d %s", st, b)
	}
	if st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+idA+"/domains", tokA, `{"domain":"evil.host.rottenapplestore.org"}`, "Content-Type", "application/json"); st != 400 {
		t.Fatalf("zone: %d %s", st, b)
	}
	host.SetHostedDNSForTest(n.H, func(name string) ([]string, error) {
		if name == "_redx-challenge.shop.example.com" {
			return []string{token}, nil
		}
		return nil, os.ErrNotExist
	})
	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+idA+"/domains/shop.example.com/verify", tokA, "")
	if st != 200 || !strings.Contains(b, `"verified":true`) {
		t.Fatalf("verify: %d %s", st, b)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/hosted/tls/ask?domain=shop.example.com", nil)
	req.RemoteAddr = "127.0.0.1:9"
	rr := httptest.NewRecorder()
	n.H.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("ask: %d %s", rr.Code, rr.Body.String())
	}
	req.RemoteAddr = "203.0.113.5:443"
	rr = httptest.NewRecorder()
	n.H.Handler().ServeHTTP(rr, req)
	if rr.Code != 403 {
		t.Fatalf("remote ask: %d", rr.Code)
	}
}

func TestHostedPodmanIntegration(t *testing.T) {
	if os.Getenv("REDX_APPS_PODMAN_TEST") != "1" {
		t.Skip("container runtime integration is skipped unless REDX_APPS_PODMAN_TEST=1 (rootless podman on PATH)")
	}
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman is not on PATH")
	}
	t.Setenv("REDX_APPS_APPLY", "1")
	n := startNode(t, t.TempDir(), func(c *host.Config, u string) {
		c.AppsRuntime = "podman"
	})
	st, b, _ := do(t, "POST", n.URL+"/v1/hosted/apps", n.Key, `{"name":"box","kind":"container"}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	id := appField(t, b, "id")
	st, b, _ = do(t, "POST", n.URL+"/v1/hosted/apps/"+id+"/deploy", n.Key, `{"source":"image","image":"docker.io/library/busybox:latest","command":["sleep","30"]}`, "Content-Type", "application/json")
	if st != 201 {
		t.Fatalf("deploy: %d %s", st, b)
	}
	if jsonOf(t, b)["runtimeStatus"] != "applied" {
		t.Fatalf("podman did not apply: %s", b)
	}
}
