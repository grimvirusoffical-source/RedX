package host_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"redx/host"
)

func copyFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/legacy/" + name)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// keys_plain_v1.json was written by the pre-migration RedX (d1f2122), whose API-key
// hashes came from x/crypto Argon2id. The Red-SecretsXAI Argon2id must verify them
// unchanged (same algorithm and parameters), and reject a wrong key.
func TestKeystoreOldArgon2HashesStillVerify(t *testing.T) {
	p := copyFixture(t, "keys_plain_v1.json")
	key, err := os.ReadFile("testdata/legacy/keys_plain_v1.apikey.txt")
	if err != nil || len(key) == 0 {
		t.Fatal("fixture key missing", err)
	}
	ks, err := host.OpenKeystore(p, host.KeystoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := ks.Verify(strings.TrimSpace(string(key)))
	if err != nil || rec.Label != "fixture" {
		t.Fatalf("old hash: %v %+v", err, rec)
	}
	bad := []byte(strings.TrimSpace(string(key)))
	bad[len(bad)-1] ^= 1
	if _, err := ks.Verify(string(bad)); err == nil {
		t.Fatal("wrong key accepted")
	}
}

// An AES-GCM encrypted keystore (REDXKS1) from the old RedX is refused at open with
// ErrLegacyKeystore, even with the right passphrase, and the file is left as is.
func TestKeystoreLegacyREDXKS1Refused(t *testing.T) {
	p := copyFixture(t, "keys_redxks1.bin")
	before, _ := os.ReadFile(p)
	_, err := host.OpenKeystore(p, host.KeystoreOptions{Passphrase: "legacy ks passphrase"})
	if !errors.Is(err, host.ErrLegacyKeystore) || !strings.Contains(err.Error(), "unsupported legacy encrypted keystore") {
		t.Fatalf("REDXKS1: %v", err)
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("refused keystore was modified")
	}
}

// New encrypted keystores are REDXKS2 (ChaCha20-Poly1305), round-trip, need the
// passphrase and detect tampering.
func TestKeystoreREDXKS2(t *testing.T) {
	p := filepath.Join(t.TempDir(), "keys.json")
	o := host.KeystoreOptions{Passphrase: "ks2 passphrase", ArgonMem: 64, ArgonTime: 1}
	ks, err := host.OpenKeystore(p, o)
	if err != nil {
		t.Fatal(err)
	}
	key, _, err := ks.Create(host.CreateSpec{Scope: host.ScopeAdmin, DB: host.AllDBs, Label: "n"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	if !bytes.HasPrefix(raw, []byte("REDXKS2\n")) || bytes.Contains(raw, []byte(`"keys"`)) {
		t.Fatalf("not an encrypted REDXKS2 file: %q", raw[:16])
	}
	ks2, err := host.OpenKeystore(p, o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks2.Verify(key); err != nil {
		t.Fatal(err)
	}
	if _, err := host.OpenKeystore(p, host.KeystoreOptions{Passphrase: "wrong"}); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if _, err := host.OpenKeystore(p, host.KeystoreOptions{}); err == nil {
		t.Fatal("encrypted keystore opened without a passphrase")
	}
	raw[len(raw)-1] ^= 1
	q := filepath.Join(t.TempDir(), "keys.json")
	_ = os.WriteFile(q, raw, 0o600)
	if _, err := host.OpenKeystore(q, o); err == nil {
		t.Fatal("tampered keystore accepted")
	}
}
