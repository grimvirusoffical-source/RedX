package engineadapter_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"redx/host"
	"redx/host/engineadapter"
)

// TestConsoleRecordEditRoundTrip is the Data Explorer contract: create, list,
// BoxQL, read Box text, edit, read back. It uses a new database in a temp dir.
func TestConsoleRecordEditRoundTrip(t *testing.T) {
	n := startFull(t, engineadapter.Config{}, nil)
	D := n.url + "/v1/db/default"
	path := "players.red-xai.db:Player[ID=1]"
	boxText := "[\n    {Name[]} = \"Ann\",\n    {Level[]} = 7\n]"
	body, _ := json.Marshal(map[string]string{"box": boxText})
	if st, b, _ := req(t, "PUT", D+"/path/"+path, n.key, body, "Content-Type", "application/json"); st != 200 {
		t.Fatalf("create: %d %s", st, b)
	}
	st, b, _ := req(t, "GET", D+"/files", n.key, nil)
	if st != 200 || !strings.Contains(string(b), `"name":"players.red-xai.db"`) || !strings.Contains(string(b), `"records":"records"`) {
		t.Fatalf("files: %d %s", st, b)
	}
	if st, o, raw := bx(t, n, n.key, "", `{Get[]} = "players.red-xai.db":*[ID=*] -> [ID], Limit = 2000`); st != 200 || len(o.Paths) != 1 {
		t.Fatalf("tree query: %d %s", st, raw)
	}
	if st, o, raw := bx(t, n, n.key, "", `{Get[]} = "players.red-xai.db":Player[ID=*] -> *, Limit = 25, Offset = 0`); st != 200 || o.Count != 1 {
		t.Fatalf("page query: %d %s", st, raw)
	}
	if st, o, raw := bx(t, n, n.key, "", `{Get[]} = "players.red-xai.db":Player[ID=*] -> [n = Count()]`); st != 200 || o.Count != 1 {
		t.Fatalf("count query: %d %s", st, raw)
	}
	st, b, _ = req(t, "GET", D+"/path/"+path, n.key, nil, "Accept", "text/x-redx-box")
	if st != 200 || !strings.Contains(string(b), "Ann") {
		t.Fatalf("get box: %d %s", st, b)
	}
	edited := "[\n    {Name[]} = \"Bea\",\n    {Level[]} = 8\n]"
	body, _ = json.Marshal(map[string]string{"box": edited})
	if st, b, _ = req(t, "PUT", D+"/path/"+path, n.key, body, "Content-Type", "application/json"); st != 200 {
		t.Fatalf("edit: %d %s", st, b)
	}
	st, b, _ = req(t, "GET", D+"/path/"+path, n.key, nil, "Accept", "text/x-redx-box")
	if st != 200 || !strings.Contains(string(b), "Bea") || strings.Contains(string(b), "Ann") {
		t.Fatalf("edited box: %d %s", st, b)
	}
}

// TestSecretsCallsLeaveEncryptedPacksUntouched creates a new AES pack, then
// calls the Red-SecretsXAI API. The pack directory, the policy file, and the
// master key file must keep the same bytes. The test does not rewrap or
// overwrite that pack.
func TestSecretsCallsLeaveEncryptedPacksUntouched(t *testing.T) {
	kf := filepath.Join(t.TempDir(), "master.key")
	if err := engineadapter.GenerateKeyFile(kf, "main-2026"); err != nil {
		t.Fatal(err)
	}
	ring, err := engineadapter.LoadKeyFile(kf)
	if err != nil {
		t.Fatal(err)
	}
	n := startFull(t, engineadapter.Config{Keyring: ring}, nil)
	n.h.Cfg.SecretsKDFOverride = &host.SecretsKDFCost{T: 1, MKiB: 32, P: 1}
	D := n.url + "/v1/db/default"
	rule := `{Encrypt[1]} = [ {File[]} = "vault*", {Key[]} = "main-2026" ];`
	if st, b, _ := req(t, "PUT", D+"/sec", n.key, []byte(rule)); st != 200 {
		t.Fatalf("policy: %d %s", st, b)
	}
	secret := bytes.Repeat([]byte("PACK-CIPHERTEXT-MUST-STAY "), 4000)
	if st, b, _ := req(t, "PUT", D+"/pack/vault/file/plans/launch.txt", n.key, secret); st != 201 || !strings.Contains(string(b), `"encrypted":true`) {
		t.Fatalf("put pack: %d %s", st, b)
	}
	dbDir := filepath.Join(n.h.Cfg.DataDir, "dbs", "default")
	packDir := filepath.Join(dbDir, "vault.red-xai-pack")
	before := map[string]string{}
	for k, v := range treeHashes(t, packDir) {
		before["pack/"+k] = v
	}
	before["policy"] = fileHash(t, filepath.Join(dbDir, "policy.red-xai-sec"))
	before["master"] = fileHash(t, kf)

	plain := "NEW-RECORD-NOT-A-PACK"
	sealBody, _ := json.Marshal(map[string]string{
		"password":  "correct-horse-battery",
		"plaintext": plain,
		"path":      "notes.red-xai.db:Note[ID=1]",
	})
	st, b, _ := req(t, "POST", D+"/secrets/seal", n.key, sealBody, "Content-Type", "application/json")
	if st != 200 || !strings.Contains(string(b), `"stored":false`) {
		t.Fatalf("seal: %d %s", st, b)
	}
	var sealed struct {
		Box string `json:"box"`
	}
	if err := json.Unmarshal(b, &sealed); err != nil || !strings.Contains(sealed.Box, "red-xai-encrypt/rsxc1") {
		t.Fatalf("seal body: %v %s", err, b)
	}
	openBody, _ := json.Marshal(map[string]string{
		"password": "correct-horse-battery",
		"box":      sealed.Box,
		"path":     "notes.red-xai.db:Note[ID=1]",
	})
	st, b, _ = req(t, "POST", D+"/secrets/open", n.key, openBody, "Content-Type", "application/json")
	if st != 200 || !strings.Contains(string(b), plain) {
		t.Fatalf("open: %d %s", st, b)
	}
	// Storing the new envelope is a new record. It must not be a rewrite of the pack.
	put, _ := json.Marshal(map[string]string{"box": sealed.Box})
	if st, b, _ = req(t, "PUT", D+"/path/notes.red-xai.db:Note[ID=1]", n.key, put, "Content-Type", "application/json"); st != 200 {
		t.Fatalf("save new envelope: %d %s", st, b)
	}

	after := map[string]string{}
	for k, v := range treeHashes(t, packDir) {
		after["pack/"+k] = v
	}
	after["policy"] = fileHash(t, filepath.Join(dbDir, "policy.red-xai-sec"))
	after["master"] = fileHash(t, kf)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("encrypted pack, policy, or master key bytes changed\nbefore %#v\nafter %#v", before, after)
	}
	st, b, _ = req(t, "GET", D+"/pack/vault/file/plans/launch.txt", n.key, nil)
	if st != 200 || !bytes.Equal(b, secret) {
		t.Fatalf("pack download changed: %d len=%d", st, len(b))
	}
}

func treeHashes(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		out[rel] = fileHash(t, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("no files hashed under " + root)
	}
	return out
}

func fileHash(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
