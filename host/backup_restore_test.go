package host_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"redx/host"
)

// onlineBackup returns the raw (encrypted) online backup and the host backup key used.
func onlineBackup(t *testing.T, n *node, hdr ...string) []byte {
	t.Helper()
	st, b, _ := do(t, "GET", n.URL+"/v1/admin/backup", n.Key, "", hdr...)
	if st != 200 {
		t.Fatalf("online backup %d %s", st, b)
	}
	return []byte(b)
}

func hostBackupKey(t *testing.T, dir string) []byte {
	t.Helper()
	k, err := os.ReadFile(filepath.Join(dir, "backup.key"))
	if err != nil || len(k) != 32 {
		t.Fatalf("backup.key: %v (%d bytes)", err, len(k))
	}
	return k
}

type tarEntry struct {
	hdr  *tar.Header
	body []byte
}

// plainEntries decrypts an encrypted backup and returns its tar entries.
func plainEntries(t *testing.T, raw []byte, k host.BackupKeys) []tarEntry {
	t.Helper()
	pr, hdr, err := host.OpenBackup(bytes.NewReader(raw), k)
	if err != nil || hdr == nil {
		t.Fatalf("open backup: %v (hdr %v)", err, hdr)
	}
	gz, err := gzip.NewReader(pr)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var out []tarEntry
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out = append(out, tarEntry{h, b})
	}
}

func packTGZ(t *testing.T, ents []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range ents {
		h := *e.hdr
		h.Size = int64(len(e.body))
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		tw.Write(e.body)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

// testBackupKeys seals hand-built archives: restore only accepts RXBK2.
var testBackupKeys = host.BackupKeys{HostKey: bytes.Repeat([]byte{0x5c}, 32)}

func sealTGZ(t *testing.T, tgz []byte) []byte {
	t.Helper()
	s, err := host.NewBackupSealer(testBackupKeys)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	w, err := s.Seal(&out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(tgz); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// installed lists what a restore put in dir, ignoring the redxd.lock it takes.
func installed(dir string) []string {
	var out []string
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if e.Name() != "redxd.lock" {
			out = append(out, e.Name())
		}
	}
	return out
}

func restore(dir string, raw []byte, o host.RestoreOptions) (*host.RestoreResult, error) {
	return host.OfflineRestore(dir, bytes.NewReader(raw), o)
}

// Board restore finding #1 (HIGH): connect grants were lost on restore.
func TestRestoreKeepsConnectGrants(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	p := newPKCE(70)
	app := `,"provider":"rottenapple-launcher","app":"com.acme.restore","prefix":"saves"`
	id := startConnect(t, n, p, app)["request_id"].(string)
	st, x := exchange(t, n, approve(t, n, id, "")["code"].(string), p, "")
	if st != 200 {
		t.Fatalf("exchange %d %v", st, x)
	}
	appKey, ws := x["key"].(string), x["workspace"].(map[string]interface{})["db"].(string)
	if st, _, _ := do(t, "PUT", n.URL+"/v1/db/"+ws+"/path/saves.red-xai.db:S[ID=1].A", appKey, `"before"`); st != 200 {
		t.Fatal("app write before backup")
	}
	raw := onlineBackup(t, n)
	bk := hostBackupKey(t, n.Dir)
	n.Stop()

	dir2 := t.TempDir()
	if _, err := restore(dir2, raw, host.RestoreOptions{}); err == nil || !strings.Contains(err.Error(), "backup key") {
		t.Fatalf("restore without the backup key must fail clearly, got %v", err)
	}
	res, err := restore(dir2, raw, host.RestoreOptions{Keys: host.BackupKeys{HostKey: bk}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("a current encrypted backup must restore without warnings: %v", res.Warnings)
	}
	n2 := startNode(t, dir2, nil)
	n2.Key = n.Key
	st, b, _ := do(t, "GET", n2.URL+"/v1/connect/apps", n2.Key, "")
	if st != 200 || !strings.Contains(b, x["key_id"].(string)) || !strings.Contains(b, "com.acme.restore") {
		t.Fatalf("connected apps after restore: %d %s", st, b)
	}
	if st, b, _ := do(t, "GET", n2.URL+"/v1/db/"+ws+"/path/saves.red-xai.db:S[ID=1].A", appKey, ""); st != 200 || !strings.Contains(b, "before") {
		t.Fatalf("app key after restore: %d %s", st, b)
	}
	// the app can still revoke itself (it was orphaned before the fix)
	if st, out := cpost(t, n2, "/v1/connect/revoke", appKey, ""); st != 200 || out["revoked"] != true {
		t.Fatalf("self revoke after restore: %d %v", st, out)
	}
	// and connect again to its own workspace
	p2 := newPKCE(71)
	id2 := startConnect(t, n2, p2, app)["request_id"].(string)
	if st, x2 := exchange(t, n2, approve(t, n2, id2, "")["code"].(string), p2, ""); st != 200 || x2["workspace"].(map[string]interface{})["db"] != ws {
		t.Fatalf("reconnect after restore: %d %v", st, x2)
	}
}

func TestBackupIsEncryptedAndPassphraseWorks(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	do(t, "PUT", n.URL+P+"b:B.K", n.Key, `"secretvalue-123"`)
	raw := onlineBackup(t, n)
	if bytes.HasPrefix(raw, []byte{0x1f, 0x8b}) || !bytes.HasPrefix(raw, []byte("RXBK2\n")) {
		t.Fatal("backup must be the encrypted RXBK format, not plain tar.gz")
	}
	seed, _ := os.ReadFile(filepath.Join(n.Dir, "updates", "signing.key"))
	for _, s := range []string{"keys.json", "tenants.json", "signing.key", "secretvalue-123", strings.TrimSpace(string(seed))} {
		if s != "" && bytes.Contains(raw, []byte(s)) {
			t.Fatalf("encrypted backup leaks %q", s)
		}
	}
	// the decrypted archive does hold the signing key and keys.json
	names := map[string]bool{}
	for _, e := range plainEntries(t, raw, host.BackupKeys{HostKey: hostBackupKey(t, n.Dir)}) {
		names[e.hdr.Name] = true
	}
	if !names["keys.json"] || !names["manifest.json"] || (len(seed) > 0 && !names["updates/signing.key"]) {
		t.Fatalf("archive entries: %v", names)
	}

	pass := "correct horse battery staple"
	praw := onlineBackup(t, n, host.BackupPassphraseHeader, pass)
	if !bytes.Contains(praw[:200], []byte(`"mode":"passphrase"`)) {
		t.Fatalf("passphrase header must give a passphrase backup: %q", praw[:120])
	}
	if st, _, _ := do(t, "GET", n.URL+"/v1/admin/backup", n.Key, "", host.BackupPassphraseHeader, "short"); st != 400 {
		t.Fatalf("short passphrase: want 400, got %d", st)
	}
	n.Stop()
	if _, err := restore(t.TempDir(), praw, host.RestoreOptions{Keys: host.BackupKeys{Passphrase: "wrong passphrase!!"}}); err == nil || !strings.Contains(err.Error(), "wrong passphrase") {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if _, err := restore(t.TempDir(), praw, host.RestoreOptions{}); err == nil || !strings.Contains(err.Error(), "REDX_BACKUP_PASSPHRASE") {
		t.Fatalf("missing passphrase: %v", err)
	}
	dir2 := t.TempDir()
	if _, err := restore(dir2, praw, host.RestoreOptions{Keys: host.BackupKeys{Passphrase: pass}}); err != nil {
		t.Fatal(err)
	}
	n2 := startNode(t, dir2, nil)
	if st, b, _ := do(t, "GET", n2.URL+P+"b:B.K", n.Key, ""); st != 200 || !strings.Contains(b, "secretvalue-123") {
		t.Fatalf("restored value: %d %s", st, b)
	}
	if _, err := restore(t.TempDir(), praw[:len(praw)-17], host.RestoreOptions{Keys: host.BackupKeys{Passphrase: pass}}); err == nil {
		t.Fatal("a truncated backup must be refused")
	}
	wrong := make([]byte, 32)
	if _, err := restore(t.TempDir(), raw, host.RestoreOptions{Keys: host.BackupKeys{HostKey: wrong}}); err == nil || !strings.Contains(err.Error(), "backup key") {
		t.Fatalf("wrong host key: %v", err)
	}
	// a flipped ciphertext byte is refused before anything is restored
	bad := append([]byte(nil), praw...)
	bad[len(bad)-40] ^= 1
	dir3 := t.TempDir()
	if _, err := restore(dir3, bad, host.RestoreOptions{Keys: host.BackupKeys{Passphrase: pass}}); err == nil {
		t.Fatal("tampered ciphertext must be refused")
	}
	if ents, _ := os.ReadDir(filepath.Join(dir3, "dbs")); len(ents) != 0 {
		t.Fatal("a refused restore must not leave databases behind")
	}
}

// helper: a decrypted copy of a real backup, as plain tar.gz entries (for tamper tests).
func sampleEntries(t *testing.T) []tarEntry {
	n := startNode(t, t.TempDir(), nil)
	do(t, "PUT", n.URL+P+"b:B.K", n.Key, `"orig"`)
	raw := onlineBackup(t, n)
	k := hostBackupKey(t, n.Dir)
	n.Stop()
	return plainEntries(t, raw, host.BackupKeys{HostKey: k})
}

// Board restore finding #2: integrity is checked before anything is moved into place.
func TestRestoreRefusesChangedFileBeforeInstall(t *testing.T) {
	ents := sampleEntries(t)
	changed := false
	for i, e := range ents {
		if strings.HasPrefix(e.hdr.Name, "dbs/") && e.hdr.Typeflag == tar.TypeReg && len(e.body) > 0 {
			b := append([]byte(nil), e.body...)
			b[len(b)/2] ^= 0x01
			ents[i].body = b
			changed = true
			break
		}
	}
	if !changed {
		t.Fatal("no database file to change")
	}
	dir := t.TempDir()
	_, err := restore(dir, sealTGZ(t, packTGZ(t, ents)), host.RestoreOptions{Keys: testBackupKeys})
	if err == nil || !strings.Contains(err.Error(), "integrity check failed") {
		t.Fatalf("want integrity failure, got %v", err)
	}
	if ents, _ := os.ReadDir(filepath.Join(dir, "dbs")); len(ents) != 0 {
		t.Fatal("nothing may be installed when the integrity check fails")
	}
	if _, err := os.Stat(filepath.Join(dir, "keys.red-xai-keys")); err == nil {
		t.Fatal("keystore must not be written when the integrity check fails")
	}
	// a file missing from the archive but listed in the manifest is refused too
	var dropped []tarEntry
	for _, e := range sampleEntries(t) {
		if e.hdr.Name != "ttl.json" {
			dropped = append(dropped, e)
		}
	}
	if _, err := restore(t.TempDir(), sealTGZ(t, packTGZ(t, dropped)), host.RestoreOptions{Keys: testBackupKeys}); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing entry: %v", err)
	}
}

// Board restore finding #3: unknown archive / keys.json versions are refused.
func TestRestoreVersionChecks(t *testing.T) {
	ents := sampleEntries(t)
	bump := func(name string, f func(m map[string]interface{})) []tarEntry {
		out := make([]tarEntry, len(ents))
		copy(out, ents)
		for i, e := range out {
			if e.hdr.Name == name {
				var m map[string]interface{}
				json.Unmarshal(e.body, &m)
				f(m)
				out[i].body, _ = json.Marshal(m)
			}
		}
		return out
	}
	if _, err := restore(t.TempDir(), sealTGZ(t, packTGZ(t, bump("manifest.json", func(m map[string]interface{}) { m["version"] = 99 }))), host.RestoreOptions{Keys: testBackupKeys}); err == nil || !strings.Contains(err.Error(), "version 99") {
		t.Fatalf("manifest version 99: %v", err)
	}
	// keys.json version 99, with the manifest updated to match so only the version check can refuse it
	k99 := bump("keys.json", func(m map[string]interface{}) { m["version"] = 99 })
	var kb []byte
	for _, e := range k99 {
		if e.hdr.Name == "keys.json" {
			kb = e.body
		}
	}
	k99 = func() []tarEntry {
		for i, e := range k99 {
			if e.hdr.Name == "manifest.json" {
				var m struct {
					Format  string                            `json:"format"`
					Version int                               `json:"version"`
					Created string                            `json:"created"`
					Entries map[string]map[string]interface{} `json:"entries"`
				}
				json.Unmarshal(e.body, &m)
				m.Entries["keys.json"]["sha256"] = sha256hex(kb)
				m.Entries["keys.json"]["size"] = len(kb)
				k99[i].body, _ = json.Marshal(m)
			}
		}
		return k99
	}()
	if _, err := restore(t.TempDir(), sealTGZ(t, packTGZ(t, k99)), host.RestoreOptions{Keys: testBackupKeys}); err == nil || !strings.Contains(err.Error(), "keys.json version 99") {
		t.Fatalf("keys.json version 99: %v", err)
	}
}

// Board restore finding #4: a bare dbs/ directory entry (plain `tar czf`) is accepted.
func TestRestoreAcceptsBareDirEntries(t *testing.T) {
	ents := sampleEntries(t)
	dirHdr := &tar.Header{Name: "dbs/", Typeflag: tar.TypeDir, Mode: 0o700}
	ents = append([]tarEntry{{dirHdr, nil}}, ents...)
	if _, err := restore(t.TempDir(), sealTGZ(t, packTGZ(t, ents)), host.RestoreOptions{Keys: testBackupKeys}); err != nil {
		t.Fatalf("bare dbs/ entry: %v", err)
	}
}

// Board restore finding #5: --force moves stale connect/, hosted/ and audit.log aside.
func TestRestoreForceMovesStaleStateAside(t *testing.T) {
	ents := sampleEntries(t)
	dir := t.TempDir()
	for _, p := range []string{"dbs/old/x.red-xai.db", "connect/connect.json", "hosted/apps.json", "audit.log"} {
		os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o700)
		os.WriteFile(filepath.Join(dir, p), []byte("stale"), 0o600)
	}
	if _, err := restore(dir, sealTGZ(t, packTGZ(t, ents)), host.RestoreOptions{Keys: testBackupKeys}); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("non-empty dir without --force: %v", err)
	}
	res, err := restore(dir, sealTGZ(t, packTGZ(t, ents)), host.RestoreOptions{Keys: testBackupKeys, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.MovedAside) != 4 {
		t.Fatalf("moved aside: %v", res.MovedAside)
	}
	for _, m := range res.MovedAside {
		if !strings.Contains(m, ".pre-restore-") {
			t.Fatalf("moved to %s", m)
		}
		if _, err := os.Stat(m); err != nil {
			t.Fatalf("moved-aside state must be kept: %v", err)
		}
	}
	for _, p := range []string{"hosted/apps.json", "audit.log", "dbs/old"} {
		if _, err := os.Stat(filepath.Join(dir, p)); err == nil {
			t.Fatalf("stale %s still in place after --force", p)
		}
	}
	var want []byte
	for _, e := range ents {
		if e.hdr.Name == "connect/connect.json" {
			want = e.body
		}
	}
	got, err := os.ReadFile(filepath.Join(dir, "connect", "connect.json"))
	if want == nil {
		if err == nil {
			t.Fatalf("archive had no connect.json, but one is in place: %q", got)
		}
	} else if !bytes.Equal(got, want) {
		t.Fatal("connect.json must come from the archive, not the stale copy")
	}
}

// Old plaintext .tgz backups are refused before anything is unpacked.
func TestRestoreRefusesLegacyPlaintextArchive(t *testing.T) {
	for _, ents := range [][]tarEntry{sampleEntries(t), nil} {
		dir := t.TempDir()
		_, err := restore(dir, packTGZ(t, ents), host.RestoreOptions{Keys: testBackupKeys, Force: true})
		if !errors.Is(err, host.ErrLegacyBackup) || !strings.Contains(err.Error(), "unsupported legacy backup format; create a new backup with this version") {
			t.Fatalf("plain tgz: %v", err)
		}
		if left := installed(dir); len(left) != 0 {
			t.Fatalf("refused restore left files behind: %v", left)
		}
	}
}

// The offline path with redxd running: the daemon's answer is encrypted on disk too.
func TestOfflineBackupWhileRunningIsEncrypted(t *testing.T) {
	dir := t.TempDir()
	n := startNode(t, dir, nil)
	do(t, "PUT", n.URL+P+"b:B.K", n.Key, `"live"`)
	var buf bytes.Buffer
	pass := "offline passphrase 1"
	if err := host.OfflineBackup(dir, &buf, host.BackupOptions{Keys: host.BackupKeys{Passphrase: pass}}); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("RXBK2\n")) || bytes.Contains(buf.Bytes(), []byte("keys.json")) {
		t.Fatal("offline backup must be encrypted")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "backup", "out-*")); len(left) != 0 {
		t.Fatalf("daemon answer left on disk: %v", left)
	}
	n.Stop()
	if _, err := restore(t.TempDir(), buf.Bytes(), host.RestoreOptions{Keys: host.BackupKeys{Passphrase: pass}}); err != nil {
		t.Fatal(err)
	}
}

func sha256hex(b []byte) string { return fmt.Sprintf("%x", sha256sum(b)) }

func sha256sum(b []byte) [32]byte { return sha256.Sum256(b) }
