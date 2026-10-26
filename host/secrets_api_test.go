package host_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"redx/host"
)

const (
	secretsPW     = "correct-horse-battery"
	secretsWrong  = "wrong-horse-battery-xx"
	secretsMarker = "PLAINTEXT-MARKER-SECRET"
)

func secretsNode(t *testing.T) *node {
	t.Helper()
	return startNode(t, t.TempDir(), func(c *host.Config, _ string) {
		c.SecretsKDFOverride = &host.SecretsKDFCost{T: 1, MKiB: 32, P: 1}
	})
}

func secretsPost(t *testing.T, n *node, key, action, body string) (int, string) {
	t.Helper()
	st, b, _ := do(t, "POST", n.URL+"/v1/db/default/secrets/"+action, key, body, "Content-Type", "application/json")
	return st, b
}

func TestSecretsSealAndOpenDoNotWrite(t *testing.T) {
	n := secretsNode(t)
	if host.MatchDangerous("POST", "/v1/db/default/secrets/seal") != nil || host.MatchDangerous("POST", "/v1/db/default/secrets/open") != nil {
		t.Fatal("seal and open must not require X-RedX-Confirm")
	}
	path := "players.red-xai.db:Player[ID=1]"
	original := `[ {Name[]} = "` + secretsMarker + `" ]`
	put := `{"box":` + jsonString(original) + `}`
	if st, b, _ := do(t, "PUT", n.URL+"/v1/db/default/path/"+path, n.Key, put, "Content-Type", "application/json"); st != 200 {
		t.Fatalf("put record: %d %s", st, b)
	}

	st, body, _ := do(t, "GET", n.URL+"/v1/db/default/secrets", n.Key, "")
	if st != 200 {
		t.Fatalf("status: %d %s", st, body)
	}
	info := jsonOf(t, body)
	for _, k := range []string{"cgo", "js_binding", "migrates", "touches_existing"} {
		if info[k] != false {
			t.Fatalf("status %s = %v, want false (%s)", k, info[k], body)
		}
	}
	if info["engine"] != "red-secretsxai" || info["binding"] != "pure-go" || info["pin"] == "" {
		t.Fatalf("status identity: %s", body)
	}

	st, body = secretsPost(t, n, n.Key, "seal", `{"password":"`+secretsPW+`","plaintext":"`+secretsMarker+`","path":"`+path+`"}`)
	if st != 200 || !strings.Contains(body, `"stored":false`) || !strings.Contains(body, "red-xai-encrypt/rsxc1") {
		t.Fatalf("seal: %d %s", st, body)
	}
	env := jsonOf(t, body)["box"].(string)
	if st, b, _ := do(t, "GET", n.URL+"/v1/db/default/path/"+path, n.Key, "", "Accept", "text/x-redx-box"); st != 200 || !strings.Contains(b, secretsMarker) || strings.Contains(b, "rsxc1") {
		t.Fatalf("seal wrote or dropped the record: %d %s", st, b)
	}

	st, body = secretsPost(t, n, n.Key, "open", `{"password":"`+secretsPW+`","box":`+jsonString(env)+`,"path":"`+path+`"}`)
	if st != 200 || !strings.Contains(body, secretsMarker) || !strings.Contains(body, `"stored":false`) {
		t.Fatalf("open: %d %s", st, body)
	}
	if st, b, _ := do(t, "GET", n.URL+"/v1/db/default/path/"+path, n.Key, "", "Accept", "text/x-redx-box"); st != 200 || b != original && !strings.Contains(b, secretsMarker) || strings.Contains(b, "rsxc1") {
		t.Fatalf("open wrote the record: %d %q", st, b)
	}

	st, body = secretsPost(t, n, n.Key, "open", `{"password":"`+secretsWrong+`","box":`+jsonString(env)+`,"path":"`+path+`"}`)
	if st != 422 || strings.Contains(body, secretsMarker) {
		t.Fatalf("wrong password: %d %s", st, body)
	}
	st, body = secretsPost(t, n, n.Key, "open", `{"password":"`+secretsPW+`","box":`+jsonString(env)+`,"path":"players.red-xai.db:Player[ID=2]"}`)
	if st != 422 {
		t.Fatalf("path mismatch: %d %s", st, body)
	}
	tampered := env
	if i := strings.Index(tampered, "Blob"); i < 0 {
		t.Fatal("envelope has no Blob")
	} else {
		j := strings.IndexByte(tampered[i:], 'A')
		if j < 0 {
			t.Fatal("no A in blob to flip")
		}
		at := i + j
		tampered = tampered[:at] + "B" + tampered[at+1:]
	}
	st, body = secretsPost(t, n, n.Key, "open", `{"password":"`+secretsPW+`","box":`+jsonString(tampered)+`,"path":"`+path+`"}`)
	if st != 422 && st != 400 {
		t.Fatalf("tamper: %d %s", st, body)
	}
	if strings.Contains(body, secretsMarker) {
		t.Fatalf("tamper returned plaintext: %s", body)
	}

	st, body = secretsPost(t, n, "", "seal", `{"password":"`+secretsPW+`","plaintext":"hello-there","path":"`+path+`"}`)
	if st != 401 {
		t.Fatalf("no key: %d %s", st, body)
	}
	rk, _ := mkKey(t, n, map[string]interface{}{"db": "default", "scope": "read", "label": "reader"})
	st, body = secretsPost(t, n, rk, "seal", `{"password":"`+secretsPW+`","plaintext":"hello-there","path":"`+path+`"}`)
	if st != 403 {
		t.Fatalf("read key seal: %d %s", st, body)
	}
	st, body = secretsPost(t, n, rk, "open", `{"password":"`+secretsPW+`","box":`+jsonString(env)+`,"path":"`+path+`"}`)
	if st != 200 || !strings.Contains(body, secretsMarker) {
		t.Fatalf("read key open: %d %s", st, body)
	}
	pk, _ := mkKey(t, n, map[string]interface{}{"db": "default", "scope": "write", "prefix": "players.red-xai.db:", "label": "prefixed"})
	st, body = secretsPost(t, n, pk, "seal", `{"password":"`+secretsPW+`","plaintext":"hello-there","path":""}`)
	if st != 403 {
		t.Fatalf("empty path on prefix key: %d %s", st, body)
	}
	st, body = secretsPost(t, n, pk, "seal", `{"password":"`+secretsPW+`","plaintext":"hello-there","path":"`+path+`"}`)
	if st != 200 {
		t.Fatalf("prefix key seal: %d %s", st, body)
	}
	st, body = secretsPost(t, n, n.Key, "seal", `{"password":"short","plaintext":"hello-there","path":"`+path+`"}`)
	if st != 400 {
		t.Fatalf("short password: %d %s", st, body)
	}
	st, body = secretsPost(t, n, n.Key, "seal", `{"password":"`+secretsPW+`","plaintext":`+jsonString(env)+`,"path":"`+path+`"}`)
	if st != 400 || !strings.Contains(body, "existing ciphertext") {
		t.Fatalf("rewrap refused: %d %s", st, body)
	}
	st, body = secretsPost(t, n, n.Key, "open", `{"password":"`+secretsPW+`","box":"not-an-envelope","path":"`+path+`"}`)
	if st != 400 || !strings.Contains(body, "rewritten") {
		t.Fatalf("non-envelope: %d %s", st, body)
	}
	st, body = secretsPost(t, n, n.Key, "open", `{"password":"`+secretsPW+`","box":"[ {Name[]} = \"x\" ]","path":"`+path+`"}`)
	if st != 400 || !strings.Contains(strings.ToLower(body), "pack") || !strings.Contains(body, "unchanged") {
		t.Fatalf("foreign box: %d %s", st, body)
	}
	if st, b, _ := do(t, "GET", n.URL+"/v1/db/default/path/"+path, n.Key, "", "Accept", "text/x-redx-box"); st != 200 || strings.Contains(b, "rsxc1") || !strings.Contains(b, secretsMarker) {
		t.Fatalf("record changed after refusals: %d %s", st, b)
	}

	lim, _ := mkKey(t, n, map[string]interface{}{"db": "default", "scope": "read", "label": "limit"})
	for i := 0; i < 8; i++ {
		st, body = secretsPost(t, n, lim, "open", `{"password":"`+secretsWrong+`","box":`+jsonString(env)+`,"path":"`+path+`"}`)
		if st != 422 {
			t.Fatalf("fail %d: %d %s", i, st, body)
		}
	}
	st, body = secretsPost(t, n, lim, "open", `{"password":"`+secretsWrong+`","box":`+jsonString(env)+`,"path":"`+path+`"}`)
	if st != 429 || strings.Contains(body, secretsMarker) {
		t.Fatalf("ninth open: %d %s", st, body)
	}

	raw, err := os.ReadFile(n.Dir + "/audit.log")
	if err != nil {
		t.Fatal(err)
	}
	audit := string(raw)
	for _, secret := range []string{secretsPW, secretsWrong, secretsMarker} {
		if strings.Contains(audit, secret) {
			t.Fatalf("audit log contains %q", secret)
		}
	}
	if !strings.Contains(audit, "secrets.seal") || !strings.Contains(audit, "secrets.open") || !strings.Contains(audit, "stored=false") {
		t.Fatalf("audit missing seal/open lines: %s", audit)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
