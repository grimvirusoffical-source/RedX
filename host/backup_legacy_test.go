package host_test

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"redx/host"
)

// testdata/legacy/rxbk1_*.bin were written by the pre-migration RedX (d1f2122):
// RXBK1 = engine/sec v1 (AES-256-GCM). They are no longer supported: restore
// must refuse them with ErrLegacyBackup even with the right secret, before any
// decryption, and install nothing.
func TestLegacyRXBK1BackupsRefused(t *testing.T) {
	hk, err := os.ReadFile("testdata/legacy/rxbk1_hostkey.bin.hostkey")
	if err != nil || len(hk) != 32 {
		t.Fatal("fixture host key missing", err)
	}
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
		_, err = restore(dir, raw, host.RestoreOptions{Keys: c.keys})
		if !errors.Is(err, host.ErrLegacyBackup) || !strings.Contains(err.Error(), "unsupported legacy backup format; create a new backup with this version") {
			t.Fatalf("%s: %v", c.file, err)
		}
		if left := installed(dir); len(left) != 0 {
			t.Fatalf("%s: refused restore left %v", c.file, left)
		}
		if _, _, err := host.OpenBackup(bytes.NewReader(raw), c.keys); !errors.Is(err, host.ErrLegacyBackup) {
			t.Fatalf("%s: OpenBackup: %v", c.file, err)
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
