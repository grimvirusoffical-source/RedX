package host_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"redx/host"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
}

// Every danger:"dangerous" op in the spec must be in host.DangerousOps (and vice versa).
func TestDangerousOpsMatchSpec(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "api", "redx-api.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Operations []struct {
			ID          string `json:"id"`
			Method      string `json:"method"`
			Path        string `json:"path"`
			Danger      string `json:"danger"`
			HostConfirm string `json:"hostConfirm"`
		} `json:"operations"`
	}
	if err := json.Unmarshal(b, &spec); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct{ Method, Path, HostConfirm string }{}
	for _, o := range spec.Operations {
		if o.Danger == "dangerous" {
			want[o.ID] = struct{ Method, Path, HostConfirm string }{o.Method, o.Path, o.HostConfirm}
		}
	}
	got := map[string]struct{ Method, Path, HostConfirm string }{}
	for _, o := range host.DangerousOps() {
		got[o.ID] = struct{ Method, Path, HostConfirm string }{o.Method, o.PathPattern, o.HostConfirm}
	}
	if len(got) != len(want) {
		t.Fatalf("dangerous ops: host has %d, spec has %d", len(got), len(want))
	}
	for id, w := range want {
		g, ok := got[id]
		if !ok {
			t.Errorf("spec dangerous op %s missing from host", id)
			continue
		}
		if g.Method != w.Method || g.Path != w.Path || g.HostConfirm != w.HostConfirm {
			t.Errorf("%s: host=%+v spec=%+v", id, g, w)
		}
	}
}

func TestDangerousOpsRequireConfirm(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	// seed a second database and a key so revoke/rotate/delete have something to act on
	do(t, "POST", n.URL+"/v1/dbs", n.Key, `{"name":"scratch"}`, "Content-Type", "application/json")
	kid := ""
	{
		st, body, _ := do(t, "POST", n.URL+"/v1/keys", n.Key, `{"db":"scratch","scope":"read","label":"t"}`,
			"Content-Type", "application/json", host.ConfirmHeader, "createKey")
		if st != 201 {
			t.Fatalf("seed createKey: %d %s", st, body)
		}
		kid = jsonOf(t, body)["id"].(string)
	}
	type case_ struct {
		name, method, path, body string
		op                       string
		hostConfirmVal           string // if set, ?confirm=<this> alone must succeed (deleteDatabase)
		okStatus                 int    // status when confirmed (0 = any 2xx/3xx/4xx that is NOT 428)
	}
	cases := []case_{
		{"createKey", "POST", "/v1/keys", `{"db":"scratch","scope":"read","label":"x"}`, "createKey", "", 201},
		{"revokeKey", "DELETE", "/v1/keys/" + kid, "", "revokeKey", "", 200},
		{"rotateKey", "POST", "/v1/keys/" + kid, `{"grace":"0s"}`, "rotateKey", "", 0}, // may 404 after revoke; recreate below
		{"createPairingCode", "POST", "/v1/keys/pairing", `{"db":"scratch","scope":"read"}`, "createPairingCode", "", 201},
		{"putPolicy", "PUT", "/v1/db/scratch/sec", `roles {}`, "putPolicy", "", 0},
		{"deletePolicy", "DELETE", "/v1/db/scratch/sec", "", "deletePolicy", "", 0},
		{"createJoinToken", "POST", "/v1/cluster/join-token", `{"kind":"token"}`, "createJoinToken", "", 200},
		{"promote", "POST", "/v1/cluster/promote", "", "promote", "", 0}, // leader promote may fail; still not 428
		{"repoint", "POST", "/v1/cluster/leader", `{"url":"http://127.0.0.1:1","join_token":"x"}`, "repoint", "", 0},
		{"connectApprove", "POST", "/v1/connect/approve", `{"request_id":"nope"}`, "connectApprove", "", 0},
		{"connectRevokeApp", "DELETE", "/v1/connect/apps/nope", "", "connectRevokeApp", "", 0},
		{"deleteDatabase", "DELETE", "/v1/db/scratch", "", "deleteDatabase", "scratch", 200},
	}
	// recreate a key for rotate (revoke above consumed the seed)
	st, body, _ := do(t, "POST", n.URL+"/v1/keys", n.Key, `{"db":"scratch","scope":"read","label":"rot"}`,
		"Content-Type", "application/json", host.ConfirmHeader, "createKey")
	if st != 201 {
		t.Fatalf("recreate key: %d %s", st, body)
	}
	kid2 := jsonOf(t, body)["id"].(string)
	for i := range cases {
		if cases[i].op == "rotateKey" {
			cases[i].path = "/v1/keys/" + kid2 + "/rotate"
			cases[i].okStatus = 200
		}
	}

	for _, c := range cases {
		t.Run(c.name+"/no-confirm", func(t *testing.T) {
			// empty ConfirmHeader opts out of the test helper's auto-confirm
			hdr := []string{host.ConfirmHeader, ""}
			if c.body != "" && (c.method == "POST" || c.method == "PUT") {
				hdr = append(hdr, "Content-Type", "application/json")
			}
			st, b, _ := do(t, c.method, n.URL+c.path, n.Key, c.body, hdr...)
			if st != 428 {
				t.Fatalf("want 428, got %d %s", st, b)
			}
			var m map[string]string
			_ = json.Unmarshal([]byte(b), &m)
			if m["code"] != host.ConfirmRequired {
				t.Fatalf("code=%q body=%s", m["code"], b)
			}
			if !strings.Contains(m["error"], c.op) {
				t.Fatalf("error should name the op: %s", m["error"])
			}
		})
		t.Run(c.name+"/wrong-op-id", func(t *testing.T) {
			hdr := []string{host.ConfirmHeader, "not-" + c.op}
			if c.body != "" && (c.method == "POST" || c.method == "PUT") {
				hdr = append(hdr, "Content-Type", "application/json")
			}
			st, b, _ := do(t, c.method, n.URL+c.path, n.Key, c.body, hdr...)
			if st != 428 {
				t.Fatalf("wrong op-id must be refused: %d %s", st, b)
			}
		})
		t.Run(c.name+"/header-confirm", func(t *testing.T) {
			hdr := []string{host.ConfirmHeader, c.op}
			if c.body != "" && (c.method == "POST" || c.method == "PUT") {
				hdr = append(hdr, "Content-Type", "application/json")
			}
			// deleteDatabase also needs ?confirm=<db> at the handler layer
			url := n.URL + c.path
			if c.op == "deleteDatabase" {
				url += "?confirm=scratch"
			}
			st, b, _ := do(t, c.method, url, n.Key, c.body, hdr...)
			if st == 428 {
				t.Fatalf("confirmed call still got 428: %s", b)
			}
			if c.okStatus != 0 && st != c.okStatus {
				// soft: some ops return business errors; never 428
				t.Logf("status %d (wanted %d): %s", st, c.okStatus, b)
			}
		})
		if c.hostConfirmVal != "" {
			t.Run(c.name+"/legacy-query-confirm", func(t *testing.T) {
				// recreate scratch if deleted
				do(t, "POST", n.URL+"/v1/dbs", n.Key, `{"name":"scratch"}`, "Content-Type", "application/json")
				st, b, _ := do(t, c.method, n.URL+c.path+"?confirm="+c.hostConfirmVal, n.Key, c.body)
				if st == 428 {
					t.Fatalf("legacy ?confirm=<db> must still work: %s", b)
				}
			})
		}
	}
}
