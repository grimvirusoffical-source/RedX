package host

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

// Snapshot layout (tar.gz): dbs/<name>/** (database files), keys.json (key
// records: hashes only), ttl.json (TTL deadlines). Used for `redx backup`,
// the online admin backup endpoint and follower full-resync.
//
// Consistency: the snapshot is taken with all host-level writes paused, so it
// is a write-quiescent file copy. It relies on the engine's own WAL recovery
// for any background checkpoint that happens concurrently (the engine
// interface has no explicit flush hook). For a guaranteed-clean copy use the
// offline backup with the daemon stopped.

type archiveWriter struct {
	tw  *tar.Writer
	man map[string]manifestEntry
}

func (a *archiveWriter) addFile(name string, path string, fi os.FileInfo) error {
	hdr, err := tar.FileInfoHeader(fi, "")
	if err != nil {
		return err
	}
	hdr.Name = name
	if err := a.tw.WriteHeader(hdr); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(a.tw, h), f)
	if err != nil {
		return err
	}
	if n != hdr.Size {
		return fmt.Errorf("snapshot: %s changed size while being copied", name)
	}
	a.man[name] = manifestEntry{SHA256: hex.EncodeToString(h.Sum(nil)), Size: n}
	return nil
}

func (a *archiveWriter) addBytes(name string, b []byte) error {
	if err := a.tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), ModTime: time.Now()}); err != nil {
		return err
	}
	if _, err := a.tw.Write(b); err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	a.man[name] = manifestEntry{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(b))}
	return nil
}

// snapshotExtra is included in a host backup (online or offline) and omitted
// from a cluster replication snapshot, which must not carry the signing key.
type snapshotExtra struct {
	signingKey  []byte
	signingMeta []byte
	tenants     []byte
	connect     map[string][]byte // file name under connect/ -> contents (grants, workspaces, id key)
}

// Archive manifest (format version 2). It is the last entry and lists the
// SHA-256 and size of every other file entry, so a restore verifies the whole
// archive before anything is moved into place.
const (
	archiveFormat  = "redx-backup"
	archiveVersion = 2
	manifestName   = "manifest.json"
)

type archiveManifest struct {
	Format  string                   `json:"format"`
	Version int                      `json:"version"`
	Created string                   `json:"created"`
	Entries map[string]manifestEntry `json:"entries"`
}

type manifestEntry struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// connectFiles lists what a host backup carries from <data>/connect.
var connectFiles = []string{"connect.json", "id.key"}

func readConnectFiles(dir string) map[string][]byte {
	out := map[string][]byte{}
	for _, n := range connectFiles {
		if b, err := os.ReadFile(filepath.Join(dir, n)); err == nil {
			out[n] = b
		}
	}
	return out
}

// WriteSnapshot writes the tar.gz to w. dbsRoot is <data>/dbs.
// Cluster replication uses this form: databases, key hashes and TTL only.
func WriteSnapshot(w io.Writer, dbsRoot string, keys []KeyRecord, ttlJSON []byte) error {
	return writeSnapshot(w, dbsRoot, keys, ttlJSON, nil)
}

func writeSnapshot(w io.Writer, dbsRoot string, keys []KeyRecord, ttlJSON []byte, extra *snapshotExtra) error {
	gz := gzip.NewWriter(w)
	a := &archiveWriter{tw: tar.NewWriter(gz), man: map[string]manifestEntry{}}
	err := filepath.Walk(dbsRoot, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dbsRoot, p)
		if rel == "." {
			return nil
		}
		name := "dbs/" + filepath.ToSlash(rel)
		if fi.IsDir() {
			return a.tw.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: 0o700, ModTime: fi.ModTime()})
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		return a.addFile(name, p, fi)
	})
	if err != nil {
		return err
	}
	kb, _ := json.Marshal(keystoreFile{Version: 1, Keys: ptrs(keys)})
	if err := a.addBytes("keys.json", kb); err != nil {
		return err
	}
	if ttlJSON == nil {
		ttlJSON = []byte("[]")
	}
	if err := a.addBytes("ttl.json", ttlJSON); err != nil {
		return err
	}
	if extra != nil {
		if len(extra.signingKey) > 0 {
			if err := a.addBytes("updates/signing.key", extra.signingKey); err != nil {
				return err
			}
		}
		if len(extra.signingMeta) > 0 {
			if err := a.addBytes("updates/signing.key.meta", extra.signingMeta); err != nil {
				return err
			}
		}
		if len(extra.tenants) > 0 {
			if err := a.addBytes("tenants.json", extra.tenants); err != nil {
				return err
			}
		}
		for _, n := range connectFiles {
			if b, ok := extra.connect[n]; ok {
				if err := a.addBytes("connect/"+n, b); err != nil {
					return err
				}
			}
		}
	}
	mb, _ := json.Marshal(archiveManifest{Format: archiveFormat, Version: archiveVersion, Created: time.Now().UTC().Format(time.RFC3339), Entries: a.man})
	if err := a.tw.WriteHeader(&tar.Header{Name: manifestName, Mode: 0o600, Size: int64(len(mb)), ModTime: time.Now()}); err != nil {
		return err
	}
	if _, err := a.tw.Write(mb); err != nil {
		return err
	}
	if err := a.tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func ptrs(k []KeyRecord) []*KeyRecord {
	out := make([]*KeyRecord, len(k))
	for i := range k {
		out[i] = &k[i]
	}
	return out
}

// SnapshotContents is what ExtractSnapshot found.
type SnapshotContents struct {
	Keys        []KeyRecord
	TTL         []byte
	SigningKey  []byte
	SigningMeta []byte
	Tenants     []byte
	Connect     map[string][]byte
	// Version is the archive format version: 2 with a manifest, 1 for older archives.
	Version  int
	Warnings []string
}

// hashedRead reads an in-memory entry up to limit and records its digest.
func hashedRead(tr io.Reader, limit int64, name string, seen map[string]manifestEntry) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(tr, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("snapshot: %s is too large", name)
	}
	sum := sha256.Sum256(b)
	seen[name] = manifestEntry{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(b))}
	return b, nil
}

func ExtractSnapshot(r io.Reader, destDBs string) (*SnapshotContents, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	sc := &SnapshotContents{Version: 1}
	if err := os.MkdirAll(destDBs, 0o700); err != nil {
		return nil, err
	}
	seen := map[string]manifestEntry{}
	var man *archiveManifest
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if man != nil {
			return nil, fmt.Errorf("snapshot: entry %q after the manifest", hdr.Name)
		}
		name := strings.TrimSuffix(hdr.Name, "/")
		connectName := strings.TrimPrefix(name, "connect/")
		switch {
		case hdr.Typeflag == tar.TypeDir && (name == "dbs" || name == "connect" || name == "updates"):
			// bare directory entries, as plain `tar czf` writes them
		case name == manifestName:
			b, err := io.ReadAll(io.LimitReader(tr, 64<<20))
			if err != nil {
				return nil, err
			}
			man = &archiveManifest{}
			if err := json.Unmarshal(b, man); err != nil {
				return nil, fmt.Errorf("snapshot: bad manifest: %v", err)
			}
			if man.Format != archiveFormat {
				return nil, fmt.Errorf("snapshot: manifest format %q is not a RedX backup", man.Format)
			}
			if man.Version < 2 || man.Version > archiveVersion {
				return nil, fmt.Errorf("snapshot: archive format version %d is not supported by this RedX (supports up to %d); upgrade RedX to restore it", man.Version, archiveVersion)
			}
		case name == "keys.json":
			b, err := hashedRead(tr, 64<<20, hdr.Name, seen)
			if err != nil {
				return nil, err
			}
			var f keystoreFile
			if err := json.Unmarshal(b, &f); err != nil {
				return nil, err
			}
			if f.Version != 1 {
				return nil, fmt.Errorf("snapshot: keys.json version %d is not supported (expected 1)", f.Version)
			}
			for _, k := range f.Keys {
				if k == nil {
					return nil, errors.New("snapshot: keys.json has an empty key record")
				}
				sc.Keys = append(sc.Keys, *k)
			}
		case name == "ttl.json":
			if sc.TTL, err = hashedRead(tr, 256<<20, hdr.Name, seen); err != nil {
				return nil, err
			}
		case name == "updates/signing.key":
			if sc.SigningKey, err = hashedRead(tr, 1<<20, hdr.Name, seen); err != nil {
				return nil, err
			}
		case name == "updates/signing.key.meta":
			if sc.SigningMeta, err = hashedRead(tr, 1<<20, hdr.Name, seen); err != nil {
				return nil, err
			}
		case name == "tenants.json":
			if sc.Tenants, err = hashedRead(tr, 32<<20, hdr.Name, seen); err != nil {
				return nil, err
			}
		case strings.HasPrefix(name, "connect/") && (connectName == "connect.json" || connectName == "id.key") && hdr.Typeflag == tar.TypeReg:
			b, err := hashedRead(tr, 32<<20, hdr.Name, seen)
			if err != nil {
				return nil, err
			}
			if sc.Connect == nil {
				sc.Connect = map[string][]byte{}
			}
			sc.Connect[connectName] = b
		case strings.HasPrefix(name, "dbs/"):
			rel := strings.TrimPrefix(name, "dbs/")
			if rel == "" || strings.HasPrefix(rel, "/") || strings.Contains(rel, "..") || strings.Contains(rel, `\`) || filepath.IsAbs(rel) {
				return nil, fmt.Errorf("snapshot: unsafe path %q", hdr.Name)
			}
			target := filepath.Join(destDBs, filepath.FromSlash(rel))
			switch hdr.Typeflag {
			case tar.TypeDir:
				if err := os.MkdirAll(target, 0o700); err != nil {
					return nil, err
				}
			case tar.TypeReg:
				if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
					return nil, err
				}
				f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
				if err != nil {
					return nil, err
				}
				h := sha256.New()
				n, err := io.Copy(io.MultiWriter(f, h), tr)
				if err != nil {
					f.Close()
					return nil, err
				}
				if err := f.Close(); err != nil {
					return nil, err
				}
				seen[hdr.Name] = manifestEntry{SHA256: hex.EncodeToString(h.Sum(nil)), Size: n}
			default:
				return nil, fmt.Errorf("snapshot: unsupported entry type for %q", hdr.Name)
			}
		default:
			return nil, fmt.Errorf("snapshot: unexpected entry %q", hdr.Name)
		}
	}
	if man == nil {
		sc.Warnings = append(sc.Warnings, "archive has no manifest (made by an older RedX): file contents could not be verified before restore")
		return sc, nil
	}
	for n, want := range man.Entries {
		got, ok := seen[n]
		if !ok {
			return nil, fmt.Errorf("snapshot: %s is listed in the manifest but missing from the archive", n)
		}
		if got != want {
			return nil, fmt.Errorf("snapshot: integrity check failed for %s (the archive was changed or damaged)", n)
		}
	}
	for n := range seen {
		if _, ok := man.Entries[n]; !ok {
			return nil, fmt.Errorf("snapshot: %s is not listed in the manifest", n)
		}
	}
	sc.Version = man.Version
	return sc, nil
}

// buildSnapshot pauses writes, records the log offset and writes a snapshot to a temp file.
func (h *Host) buildSnapshot() (path string, offset uint64, err error) {
	f, err := os.CreateTemp(h.Cfg.DataDir, ".snapshot-*.tgz")
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h.pause.Lock()
	defer h.pause.Unlock()
	h.checkpointAll()
	offset = h.Cluster.Offset() // offset BEFORE exporting keys: see note in docs
	_ = h.Tracker.Save()
	ttl, _ := os.ReadFile(filepath.Join(h.Cfg.DataDir, "cluster", "ttl.json"))
	if err := WriteSnapshot(f, h.Reg.Root(), h.KS.List(), ttl); err != nil {
		os.Remove(f.Name())
		return "", 0, err
	}
	return f.Name(), offset, nil
}

func (h *Host) serveFile(w http.ResponseWriter, path string, offset uint64, name string) {
	h.serveFileAs(w, path, offset, name, "application/gzip")
}

func (h *Host) serveFileAs(w http.ResponseWriter, path string, offset uint64, name, ctype string) {
	defer os.Remove(path)
	f, err := os.Open(path)
	if err != nil {
		writeErr(w, 500, "snapshot failed")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("X-Redx-Snapshot-Offset", strconv.FormatUint(offset, 10))
	h.Cluster.mu.Lock()
	rid := h.Cluster.meta.ReplID
	h.Cluster.mu.Unlock()
	w.Header().Set("X-Redx-Replid", rid)
	_, _ = io.Copy(w, f)
}

func (c *Cluster) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.nodeAuth(w, r); !ok {
		return
	}
	if !c.IsLeader() {
		writeErr(w, http.StatusMisdirectedRequest, "not the leader")
		return
	}
	p, off, err := c.h.buildSnapshot()
	if err != nil {
		writeErr(w, 500, "snapshot failed")
		c.h.Logf("snapshot: %v", err)
		return
	}
	c.h.serveFile(w, p, off, "redx-snapshot.tgz")
}

// installSnapshot downloads and installs a full snapshot from the leader.
// client is the connection pullOnce snapshotted under c.mu, so a concurrent Repoint cannot swap it mid-download.
func (c *Cluster) installSnapshot(ctx context.Context, leader string, client *http.Client) error {
	h := c.h
	req, _ := http.NewRequestWithContext(ctx, "GET", leader+"/v1/cluster/snapshot", nil)
	c.nodeHeaders(req)
	cl := &http.Client{Transport: client.Transport} // no overall timeout: large transfers
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("snapshot refused (%d)", resp.StatusCode)
	}
	off, err := strconv.ParseUint(resp.Header.Get("X-Redx-Snapshot-Offset"), 10, 64)
	if err != nil {
		return errors.New("snapshot: missing offset header")
	}
	rid := resp.Header.Get("X-Redx-Replid")
	tmp, err := os.MkdirTemp(h.Cfg.DataDir, ".snap-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	sc, err := ExtractSnapshot(resp.Body, filepath.Join(tmp, "dbs"))
	if err != nil {
		return err
	}
	h.pause.Lock()
	defer h.pause.Unlock()
	c.mu.Lock()
	still := c.st.Role == "follower" && c.st.LeaderURL == leader
	c.mu.Unlock()
	if !still || ctx.Err() != nil { // promoted or repointed while downloading: this snapshot no longer applies
		return errors.New("snapshot: node was promoted or repointed meanwhile; discarded")
	}
	// Close, move aside and replace atomically under the registry lock: a read racing
	// the install must not reopen the pre-snapshot tree and keep serving it (0.4.4
	// Windows CI: a discarded write stayed readable after the snapshot was installed).
	if err := h.Reg.SwapRoot(filepath.Join(tmp, "dbs")); err != nil {
		return err
	}
	if err := h.KS.ReplaceAll(sc.Keys); err != nil {
		return err
	}
	if sc.TTL != nil {
		_ = os.WriteFile(filepath.Join(c.dir, "ttl.json"), sc.TTL, 0o600)
	}
	h.Tracker.Reload()
	if err := c.log.Reset(off); err != nil {
		return err
	}
	c.mu.Lock()
	c.meta.ReplID = rid
	c.snaps++
	_ = c.saveMeta()
	c.mu.Unlock()
	h.Logf("replication: full snapshot installed, resuming at offset %d", off+1)
	return nil
}

// BackupPassphraseHeader carries an online backup passphrase (TLS or loopback only).
const BackupPassphraseHeader = "X-RedX-Backup-Passphrase"

func (h *Host) handleBackup(w http.ResponseWriter, r *http.Request, p *Principal) {
	keys, err := h.onlineBackupKeys(r)
	if err != nil {
		writeErrCode(w, http.StatusBadRequest, "backup_passphrase", err.Error())
		return
	}
	path, off, err := h.buildHostBackup(keys)
	if err != nil {
		writeErr(w, 500, "backup failed")
		h.Logf("backup: %v", err)
		return
	}
	h.Audit.Log(AuditEvent{Event: "admin.backup", KeyID: p.Key.ID, Remote: remoteIP(r)})
	w.Header().Set("X-Redx-Backup-Encryption", map[bool]string{true: "passphrase", false: "hostkey"}[keys.Passphrase != ""])
	h.serveFileAs(w, path, off, "redx-backup-"+time.Now().UTC().Format("20060102-150405")+".rxbk", "application/octet-stream")
}

// onlineBackupKeys: the request's passphrase header, else REDX_BACKUP_PASSPHRASE
// on the daemon, else the host backup key (<data>/backup.key, created on first use).
func (h *Host) onlineBackupKeys(r *http.Request) (BackupKeys, error) {
	if pp := r.Header.Get(BackupPassphraseHeader); pp != "" {
		if ip := net.ParseIP(socketIP(r)); r.TLS == nil && (ip == nil || !ip.IsLoopback()) {
			return BackupKeys{}, errors.New("refusing a backup passphrase over plain http from a non-loopback client; use TLS")
		}
		if len(pp) < 12 {
			return BackupKeys{}, errors.New("backup passphrase must be at least 12 characters")
		}
		return BackupKeys{Passphrase: pp}, nil
	}
	if pp := os.Getenv("REDX_BACKUP_PASSPHRASE"); pp != "" {
		return BackupKeys{Passphrase: pp}, nil
	}
	k, err := loadOrCreateBackupKey(h.Cfg.DataDir)
	if err != nil {
		return BackupKeys{}, err
	}
	return BackupKeys{HostKey: k}, nil
}

func (h *Host) buildHostBackup(keys BackupKeys) (path string, offset uint64, err error) {
	f, err := os.CreateTemp(h.Cfg.DataDir, ".backup-*.rxbk")
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	if err := h.writeSealedHostArchive(f, keys); err != nil {
		os.Remove(f.Name())
		return "", 0, err
	}
	return f.Name(), h.Cluster.Offset(), nil
}

// writeSealedHostArchive writes the host archive encrypted with keys. The
// plaintext only exists in memory on its way through the sealer.
func (h *Host) writeSealedHostArchive(w io.Writer, keys BackupKeys) error {
	s, err := NewBackupSealer(keys)
	if err != nil {
		return err
	}
	sw, err := s.Seal(w)
	if err != nil {
		return err
	}
	if err := h.writeHostArchive(sw); err != nil {
		_ = sw.Close()
		return err
	}
	return sw.Close()
}

func (h *Host) writeHostArchive(w io.Writer) error {
	extra := &snapshotExtra{}
	extra.signingKey, extra.signingMeta = h.signingKeyMaterial()
	if h.tenants != nil {
		extra.tenants = h.tenants.bytes()
	}
	h.pause.Lock()
	defer h.pause.Unlock()
	h.checkpointAll()
	_ = h.Tracker.Save()
	if h.connect != nil {
		h.connect.mu.Lock()
		extra.connect = readConnectFiles(h.connect.dir)
		h.connect.mu.Unlock()
	}
	ttl, _ := os.ReadFile(filepath.Join(h.Cfg.DataDir, "cluster", "ttl.json"))
	return writeSnapshot(w, h.Reg.Root(), h.KS.List(), ttl, extra)
}

func (h *Host) signingKeyMaterial() (key, meta []byte) {
	if h != nil && h.upd != nil {
		h.upd.mu.Lock()
		priv := h.upd.priv
		until := h.upd.notAfter
		h.upd.mu.Unlock()
		if len(priv) == ed25519.PrivateKeySize {
			key = []byte(base64.StdEncoding.EncodeToString(priv.Seed()) + "\n")
			b, err := json.Marshal(map[string]string{"not_after": until.UTC().Format(time.RFC3339)})
			if err == nil {
				meta = append(b, '\n')
			}
			return key, meta
		}
	}
	dir := ""
	if h != nil {
		dir = filepath.Join(h.Cfg.DataDir, "updates")
	}
	key, _ = os.ReadFile(filepath.Join(dir, "signing.key"))
	meta, _ = os.ReadFile(filepath.Join(dir, "signing.key.meta"))
	return key, meta
}

// ---- offline backup / restore (used by the CLI) ----

// backupWait is how long an offline backup waits for the running daemon to
// write a consistent archive. The daemon pauses writes, so the copy is safe
// while redxd is up and no API key is required.
const backupWait = 30 * time.Second

// BackupOptions control an offline backup.
type BackupOptions struct {
	KeystorePassphrase string     // REDX_KEYSTORE_PASSPHRASE: opens an encrypted keystore
	Keys               BackupKeys // archive encryption; empty HostKey + Passphrase uses <data>/backup.key
	Force              bool       // copy even if the running daemon does not answer (may be inconsistent)
}

// OfflineBackup snapshots dataDir into w as an encrypted archive. When redxd is stopped
// the copy is taken directly. When redxd is running, a request file asks that process to
// pause writes and produce the archive, encrypted under a one-time key that only the
// request file holds; this process then re-encrypts it under opts.Keys. --force is the
// inconsistent fallback used only if the running daemon does not answer.
func OfflineBackup(dataDir string, w io.Writer, opts BackupOptions) error {
	keys := opts.Keys
	if keys.Passphrase == "" && len(keys.HostKey) == 0 {
		k, err := loadOrCreateBackupKey(dataDir)
		if err != nil {
			return err
		}
		keys.HostKey = k
	}
	s, err := NewBackupSealer(keys)
	if err != nil {
		return err
	}
	sw, err := s.Seal(w)
	if err != nil {
		return err
	}
	if err := offlineBackupPlain(dataDir, sw, opts); err != nil {
		_ = sw.Close()
		return err
	}
	return sw.Close()
}

func offlineBackupPlain(dataDir string, w io.Writer, opts BackupOptions) error {
	l := flock.New(filepath.Join(dataDir, "redxd.lock"))
	ok, err := l.TryLock()
	if err != nil {
		return err
	}
	if ok {
		defer l.Unlock()
		return offlineCopy(dataDir, w, opts.KeystorePassphrase)
	}
	if err := requestLiveBackup(dataDir, w); err != nil {
		if !opts.Force {
			return err
		}
		return offlineCopy(dataDir, w, opts.KeystorePassphrase)
	}
	return nil
}

func offlineCopy(dataDir string, w io.Writer, pass string) error {
	var keys []KeyRecord
	if _, err := os.Stat(filepath.Join(dataDir, "keys.red-xai-keys")); err == nil {
		ks, err := OpenKeystore(filepath.Join(dataDir, "keys.red-xai-keys"), KeystoreOptions{Passphrase: pass})
		if err != nil {
			return err
		}
		keys = ks.List()
	}
	ttl, _ := os.ReadFile(filepath.Join(dataDir, "cluster", "ttl.json"))
	key, _ := os.ReadFile(filepath.Join(dataDir, "updates", "signing.key"))
	meta, _ := os.ReadFile(filepath.Join(dataDir, "updates", "signing.key.meta"))
	tenants, _ := os.ReadFile(filepath.Join(dataDir, "tenants.json"))
	return writeSnapshot(w, filepath.Join(dataDir, "dbs"), keys, ttl, &snapshotExtra{signingKey: key, signingMeta: meta, tenants: tenants, connect: readConnectFiles(filepath.Join(dataDir, "connect"))})
}

func requestLiveBackup(dataDir string, w io.Writer) error {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return err
	}
	id := hex.EncodeToString(buf[:])
	// One-time key: the daemon encrypts its answer under it, so the archive is never
	// written to disk in plaintext. Only the 0600 request file holds it, and it is removed.
	ek := make([]byte, 32)
	if _, err := rand.Read(ek); err != nil {
		return err
	}
	dir := filepath.Join(dataDir, "backup")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	req := filepath.Join(dir, "req-"+id)
	if err := os.WriteFile(req, []byte(hex.EncodeToString(ek)+"\n"), 0o600); err != nil {
		return err
	}
	defer os.Remove(req)
	out := filepath.Join(dir, "out-"+id+".rxbk")
	errf := filepath.Join(dir, "err-"+id)
	deadline := time.Now().Add(backupWait)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(errf); err == nil {
			os.Remove(errf)
			msg := strings.TrimSpace(string(b))
			if msg == "" {
				msg = "backup failed"
			}
			return errors.New(msg)
		}
		f, err := os.Open(out)
		if err == nil {
			plain, _, err := OpenBackup(f, BackupKeys{HostKey: ek})
			if err == nil {
				_, err = io.Copy(w, plain)
			}
			f.Close()
			os.Remove(out)
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("redxd is running on this data dir and did not produce a backup within 30s; stop it, or pass --force for an inconsistent copy")
}

// pollLocalBackup serves `redx backup --offline` while this process holds the
// data-dir lock. The archive is written with writes paused.
func (h *Host) pollLocalBackup() {
	if h == nil {
		return
	}
	dir := filepath.Join(h.Cfg.DataDir, "backup")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "req-") {
			continue
		}
		id := strings.TrimPrefix(name, "req-")
		if !backupIDOK(id) {
			continue
		}
		reqBody, _ := os.ReadFile(filepath.Join(dir, name))
		ek, kerr := hex.DecodeString(strings.TrimSpace(string(reqBody)))
		if kerr != nil || len(ek) != 32 {
			// An older redx CLI asks for a plaintext archive; refuse rather than write secrets in clear.
			_ = os.WriteFile(filepath.Join(dir, "err-"+id), []byte("this redxd writes encrypted backups only; upgrade the redx CLI\n"), 0o600)
			os.Remove(filepath.Join(dir, name))
			continue
		}
		out := filepath.Join(dir, "out-"+id+".rxbk")
		tmp := out + ".tmp"
		f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			continue
		}
		err = h.writeSealedHostArchive(f, BackupKeys{HostKey: ek})
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			os.Remove(tmp)
			_ = os.WriteFile(filepath.Join(dir, "err-"+id), []byte(err.Error()+"\n"), 0o600)
		} else if err := os.Rename(tmp, out); err != nil {
			os.Remove(tmp)
			_ = os.WriteFile(filepath.Join(dir, "err-"+id), []byte(err.Error()+"\n"), 0o600)
		}
		os.Remove(filepath.Join(dir, name))
	}
}

func backupIDOK(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// RestoreOptions control an offline restore.
type RestoreOptions struct {
	KeystorePassphrase string
	Keys               BackupKeys // passphrase and/or backup key; when empty, <data>/backup.key is tried
	Force              bool
}

// RestoreResult reports what a restore did besides installing the archive.
type RestoreResult struct {
	MovedAside []string // paths the old state was moved to (--force)
	Warnings   []string
}

// OfflineRestore verifies and restores a backup into dataDir. It refuses if redxd is
// running or the data dir already has databases (unless Force, which moves the old
// databases, connect grants, hosted apps and audit log aside; nothing is deleted).
// The whole archive is decrypted, verified against its manifest and extracted to a
// temporary directory before anything in dataDir changes.
func OfflineRestore(dataDir string, r io.Reader, opts RestoreOptions) (*RestoreResult, error) {
	res := &RestoreResult{}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	l := flock.New(filepath.Join(dataDir, "redxd.lock"))
	if ok, _ := l.TryLock(); !ok {
		return nil, errors.New("redxd is running on this data dir; stop it first")
	}
	defer l.Unlock()
	dbs := filepath.Join(dataDir, "dbs")
	if ents, _ := os.ReadDir(dbs); len(ents) > 0 && !opts.Force {
		return nil, errors.New("data dir already contains databases; use --force (they are moved aside, not deleted)")
	}
	keys := opts.Keys
	if len(keys.HostKey) == 0 {
		if b, err := os.ReadFile(filepath.Join(dataDir, backupKeyFile)); err == nil && len(b) == 32 {
			keys.HostKey = b
		}
	}
	plain, hdr, err := OpenBackup(r, keys)
	if err != nil {
		return nil, err
	}
	if hdr == nil {
		res.Warnings = append(res.Warnings, "this is an unencrypted backup from an older RedX: it stores the signing key, keys.json and tenants.json in plaintext. Restore it, then take a new (encrypted) backup and destroy this file")
	}
	tmp, err := os.MkdirTemp(dataDir, ".restore-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	sc, err := ExtractSnapshot(plain, filepath.Join(tmp, "dbs"))
	if err != nil {
		return nil, err
	}
	res.Warnings = append(res.Warnings, sc.Warnings...)
	if hdr != nil && sc.Version < 2 {
		return nil, errors.New("snapshot: encrypted backup without a manifest; refusing")
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	// State that belongs to the old data set is moved aside (never deleted) so it cannot
	// refer to keys or databases that no longer exist: databases (only reached with
	// --force when non-empty), app-connect grants, hosted apps and the audit log.
	for _, n := range []string{"dbs", "connect", "hosted", "audit.log"} {
		p := filepath.Join(dataDir, n)
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		to := p + ".pre-restore-" + stamp
		if err := os.Rename(p, to); err != nil {
			return res, err
		}
		res.MovedAside = append(res.MovedAside, to)
	}
	if err := os.Rename(filepath.Join(tmp, "dbs"), dbs); err != nil {
		return res, err
	}
	ks, err := OpenKeystore(filepath.Join(dataDir, "keys.red-xai-keys"), KeystoreOptions{Passphrase: opts.KeystorePassphrase})
	if err != nil {
		return res, err
	}
	if err := ks.ReplaceAll(sc.Keys); err != nil {
		return res, err
	}
	// New history: drop the replication log; a fresh replid is generated on next start.
	cdir := filepath.Join(dataDir, "cluster")
	_ = os.Remove(filepath.Join(cdir, "oplog.jsonl"))
	_ = os.Remove(filepath.Join(cdir, "repl.json"))
	if sc.TTL != nil {
		_ = os.MkdirAll(cdir, 0o700)
		_ = os.WriteFile(filepath.Join(cdir, "ttl.json"), sc.TTL, 0o600)
	}
	if len(sc.SigningKey) > 0 {
		udir := filepath.Join(dataDir, "updates")
		if err := os.MkdirAll(udir, 0o700); err != nil {
			return res, err
		}
		if err := os.WriteFile(filepath.Join(udir, "signing.key"), sc.SigningKey, 0o600); err != nil {
			return res, err
		}
		if len(sc.SigningMeta) > 0 {
			_ = os.WriteFile(filepath.Join(udir, "signing.key.meta"), sc.SigningMeta, 0o600)
		}
	}
	if len(sc.Tenants) > 0 {
		if err := os.WriteFile(filepath.Join(dataDir, "tenants.json"), sc.Tenants, 0o600); err != nil {
			return res, err
		}
	}
	if len(sc.Connect) > 0 {
		cd := filepath.Join(dataDir, "connect")
		if err := os.MkdirAll(cd, 0o700); err != nil {
			return res, err
		}
		for n, b := range sc.Connect {
			if err := os.WriteFile(filepath.Join(cd, n), b, 0o600); err != nil {
				return res, err
			}
		}
	} else if sc.Version < 2 {
		res.Warnings = append(res.Warnings, "archive has no app-connect state (older RedX): connected apps must be connected again, and their old app keys should be revoked")
	}
	// Keep the host backup key with the data so the next backups use the same key.
	if hdr != nil && hdr.Mode == "hostkey" {
		kp := filepath.Join(dataDir, backupKeyFile)
		if _, err := os.Stat(kp); err != nil {
			_ = os.WriteFile(kp, keys.HostKey, 0o600)
		}
	}
	return res, nil
}
