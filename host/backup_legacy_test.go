package host_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"redx/host"
)

// testdata/legacy/rxbk1_*.bin were written by the pre-migration RedX (d1f2122):
// RXBK1 = engine/sec v1 (AES-256-GCM) with an Argon2id passphrase or the host key.
// They must still restore, through the Red-SecretsXAI migration readers, and the
// restored host must serve the data that was in them.
func TestLegacyRXBK1BackupsRestore(t *testing.T) {
	hk, _ := os.ReadFile("testdata/legacy/rxbk1_hostkey.key")
	key, _ := os.ReadFile("testdata/legacy/key.txt")
	for _, c := range []struct {
		file string
		keys host.BackupKeys
	}{
		{"rxbk1_hostkey.bin", host.BackupKeys{HostKey: hk}},
		{"rxbk1_passphrase.bin", host.BackupKeys{Passphrase: "legacy passphrase 1"}},
	} {
		raw, err := os.ReadFile("testdata/legacy/" + c.file)
		if err != nil || !bytes.HasPrefix(raw, []byte("RXBK1\n")) {
			t.Fatalf("%s: fixture missing or not RXBK1", c.file)
		}
		dir := t.TempDir()
		if _, err := restore(dir, raw, host.RestoreOptions{Keys: c.keys}); err != nil {
			t.Fatalf("%s: restore: %v", c.file, err)
		}
		n := startNode(t, dir, nil)
		st, b, _ := do(t, "GET", n.URL+P+"b:B.K", strings.TrimSpace(string(key)), "")
		if st != 200 || !strings.Contains(b, "legacy-value-rxbk1") {
			t.Fatalf("%s: restored value: %d %s", c.file, st, b)
		}
		n.Stop()
		// wrong secret and a flipped byte are refused, and nothing is installed
		wrong := c.keys
		if wrong.Passphrase != "" {
			wrong.Passphrase += "x"
		} else {
			wrong.HostKey = bytes.Repeat([]byte{1}, 32)
		}
		if _, err := restore(t.TempDir(), raw, host.RestoreOptions{Keys: wrong}); err == nil {
			t.Fatalf("%s: wrong secret accepted", c.file)
		}
		bad := append([]byte(nil), raw...)
		bad[len(bad)-20] ^= 1
		d2 := t.TempDir()
		if _, err := restore(d2, bad, host.RestoreOptions{Keys: c.keys}); err == nil {
			t.Fatalf("%s: tampered archive accepted", c.file)
		}
	}
}

// New backups are RXBK2 (Red-SecretsXAI RSX3 v2) and a truncated one never restores.
func TestRXBK2HeaderAndTruncation(t *testing.T) {
	dir := t.TempDir()
	n := startNode(t, dir, nil)
	do(t, "PUT", n.URL+P+"b:B.K", n.Key, `"v2"`)
	raw := onlineBackup(t, n)
	n.Stop()
	if !bytes.HasPrefix(raw, []byte("RXBK2\n")) || !bytes.Contains(raw[:200], []byte(`"cipher":"rsx3-v2"`)) {
		t.Fatalf("header: %q", raw[:120])
	}
	k := host.BackupKeys{HostKey: hostBackupKey(t, dir)}
	if _, err := restore(t.TempDir(), raw, host.RestoreOptions{Keys: k}); err != nil {
		t.Fatal(err)
	}
	for _, cut := range []int{1, 19, 200} {
		if _, err := restore(t.TempDir(), raw[:len(raw)-cut], host.RestoreOptions{Keys: k}); err == nil {
			t.Fatalf("archive cut by %d bytes restored", cut)
		}
	}
	// header tampering (mode/KDF line is authenticated)
	bad := bytes.Replace(raw, []byte(`"v":2`), []byte(`"v":2 `), 1)
	if _, err := restore(t.TempDir(), bad, host.RestoreOptions{Keys: k}); err == nil {
		t.Fatal("changed header accepted")
	}
}
