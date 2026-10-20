package host

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

func addFile(tw *tar.Writer, name string, path string, fi os.FileInfo) error {
	hdr, err := tar.FileInfoHeader(fi, "")
	if err != nil {
		return err
	}
	hdr.Name = name
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

func addBytes(tw *tar.Writer, name string, b []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), ModTime: time.Now()}); err != nil {
		return err
	}
	_, err := tw.Write(b)
	return err
}

// snapshotExtra is included in a host backup (online or offline) and omitted
// from a cluster replication snapshot, which must not carry the signing key.
type snapshotExtra struct {
	signingKey  []byte
	signingMeta []byte
	tenants     []byte
}

// WriteSnapshot writes the tar.gz to w. dbsRoot is <data>/dbs.
// Cluster replication uses this form: databases, key hashes and TTL only.
func WriteSnapshot(w io.Writer, dbsRoot string, keys []KeyRecord, ttlJSON []byte) error {
	return writeSnapshot(w, dbsRoot, keys, ttlJSON, nil)
}

func writeSnapshot(w io.Writer, dbsRoot string, keys []KeyRecord, ttlJSON []byte, extra *snapshotExtra) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
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
			return tw.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: 0o700, ModTime: fi.ModTime()})
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		return addFile(tw, name, p, fi)
	})
	if err != nil {
		return err
	}
	kb, _ := json.Marshal(keystoreFile{Version: 1, Keys: ptrs(keys)})
	if err := addBytes(tw, "keys.json", kb); err != nil {
		return err
	}
	if ttlJSON == nil {
		ttlJSON = []byte("[]")
	}
	if err := addBytes(tw, "ttl.json", ttlJSON); err != nil {
		return err
	}
	if extra != nil {
		if len(extra.signingKey) > 0 {
			if err := addBytes(tw, "updates/signing.key", extra.signingKey); err != nil {
				return err
			}
		}
		if len(extra.signingMeta) > 0 {
			if err := addBytes(tw, "updates/signing.key.meta", extra.signingMeta); err != nil {
				return err
			}
		}
		if len(extra.tenants) > 0 {
			if err := addBytes(tw, "tenants.json", extra.tenants); err != nil {
				return err
			}
		}
	}
	if err := tw.Close(); err != nil {
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
}

// ExtractSnapshot unpacks a snapshot: db files go under destDBs; keys/ttl are returned.
// Rejects absolute paths, "..", links and anything outside the known layout.
func ExtractSnapshot(r io.Reader, destDBs string) (*SnapshotContents, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	sc := &SnapshotContents{}
	if err := os.MkdirAll(destDBs, 0o700); err != nil {
		return nil, err
	}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		name := strings.TrimSuffix(hdr.Name, "/")
		switch {
		case name == "keys.json":
			b, err := io.ReadAll(io.LimitReader(tr, 64<<20))
			if err != nil {
				return nil, err
			}
			var f keystoreFile
			if err := json.Unmarshal(b, &f); err != nil {
				return nil, err
			}
			for _, k := range f.Keys {
				sc.Keys = append(sc.Keys, *k)
			}
		case name == "ttl.json":
			if sc.TTL, err = io.ReadAll(io.LimitReader(tr, 256<<20)); err != nil {
				return nil, err
			}
		case name == "updates/signing.key":
			if sc.SigningKey, err = io.ReadAll(io.LimitReader(tr, 1<<20)); err != nil {
				return nil, err
			}
		case name == "updates/signing.key.meta":
			if sc.SigningMeta, err = io.ReadAll(io.LimitReader(tr, 1<<20)); err != nil {
				return nil, err
			}
		case name == "tenants.json":
			if sc.Tenants, err = io.ReadAll(io.LimitReader(tr, 32<<20)); err != nil {
				return nil, err
			}
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
				if _, err := io.Copy(f, tr); err != nil {
					f.Close()
					return nil, err
				}
				if err := f.Close(); err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("snapshot: unsupported entry type for %q", hdr.Name)
			}
		default:
			return nil, fmt.Errorf("snapshot: unexpected entry %q", hdr.Name)
		}
	}
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
	defer os.Remove(path)
	f, err := os.Open(path)
	if err != nil {
		writeErr(w, 500, "snapshot failed")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/gzip")
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

// handleBackup streams an online snapshot (owner only). It includes the update
// signing key and the tenant map; a cluster snapshot does not.
func (h *Host) handleBackup(w http.ResponseWriter, r *http.Request, p *Principal) {
	path, off, err := h.buildHostBackup()
	if err != nil {
		writeErr(w, 500, "backup failed")
		h.Logf("backup: %v", err)
		return
	}
	h.Audit.Log(AuditEvent{Event: "admin.backup", KeyID: p.Key.ID, Remote: remoteIP(r)})
	h.serveFile(w, path, off, "redx-backup-"+time.Now().UTC().Format("20060102-150405")+".tgz")
}

// buildHostBackup pauses writes and writes a consistent host archive, including
// the update signing key and tenants.json. Cluster replication uses buildSnapshot.
func (h *Host) buildHostBackup() (path string, offset uint64, err error) {
	f, err := os.CreateTemp(h.Cfg.DataDir, ".backup-*.tgz")
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	if err := h.writeHostArchive(f); err != nil {
		os.Remove(f.Name())
		return "", 0, err
	}
	return f.Name(), h.Cluster.Offset(), nil
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

// OfflineBackup snapshots dataDir into w. When redxd is stopped the copy is
// taken directly. When redxd is running, a request file asks that process to
// pause writes and produce the archive (databases, key hashes, TTL, the tenant
// map and the update signing key). --force is the inconsistent fallback used
// only if the running daemon does not answer.
func OfflineBackup(dataDir string, w io.Writer, pass string, force bool) error {
	l := flock.New(filepath.Join(dataDir, "redxd.lock"))
	ok, err := l.TryLock()
	if err != nil {
		return err
	}
	if ok {
		defer l.Unlock()
		return offlineCopy(dataDir, w, pass)
	}
	if err := requestLiveBackup(dataDir, w); err != nil {
		if !force {
			return err
		}
		return offlineCopy(dataDir, w, pass)
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
	return writeSnapshot(w, filepath.Join(dataDir, "dbs"), keys, ttl, &snapshotExtra{signingKey: key, signingMeta: meta, tenants: tenants})
}

func requestLiveBackup(dataDir string, w io.Writer) error {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return err
	}
	id := hex.EncodeToString(buf[:])
	dir := filepath.Join(dataDir, "backup")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	req := filepath.Join(dir, "req-"+id)
	if err := os.WriteFile(req, []byte("1\n"), 0o600); err != nil {
		return err
	}
	out := filepath.Join(dir, "out-"+id+".tgz")
	errf := filepath.Join(dir, "err-"+id)
	deadline := time.Now().Add(backupWait)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(errf); err == nil {
			os.Remove(req)
			os.Remove(errf)
			msg := strings.TrimSpace(string(b))
			if msg == "" {
				msg = "backup failed"
			}
			return errors.New(msg)
		}
		f, err := os.Open(out)
		if err == nil {
			_, copyErr := io.Copy(w, f)
			f.Close()
			os.Remove(out)
			os.Remove(req)
			return copyErr
		}
		time.Sleep(50 * time.Millisecond)
	}
	os.Remove(req)
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
		out := filepath.Join(dir, "out-"+id+".tgz")
		tmp := out + ".tmp"
		f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			continue
		}
		err = h.writeHostArchive(f)
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

// OfflineRestore restores a snapshot into dataDir. Refuses if redxd is running
// or the data dir already has databases (unless force, which moves them aside).
func OfflineRestore(dataDir string, r io.Reader, pass string, force bool) (movedTo string, err error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return "", err
	}
	l := flock.New(filepath.Join(dataDir, "redxd.lock"))
	if ok, _ := l.TryLock(); !ok {
		return "", errors.New("redxd is running on this data dir; stop it first")
	}
	defer l.Unlock()
	dbs := filepath.Join(dataDir, "dbs")
	if ents, _ := os.ReadDir(dbs); len(ents) > 0 && !force {
		return "", errors.New("data dir already contains databases; use --force (they are moved aside, not deleted)")
	}
	tmp, err := os.MkdirTemp(dataDir, ".restore-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	sc, err := ExtractSnapshot(r, filepath.Join(tmp, "dbs"))
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(dbs); err == nil {
		movedTo = dbs + ".pre-restore-" + time.Now().UTC().Format("20060102-150405")
		if err := os.Rename(dbs, movedTo); err != nil {
			return "", err
		}
	}
	if err := os.Rename(filepath.Join(tmp, "dbs"), dbs); err != nil {
		return movedTo, err
	}
	ks, err := OpenKeystore(filepath.Join(dataDir, "keys.red-xai-keys"), KeystoreOptions{Passphrase: pass})
	if err != nil {
		return movedTo, err
	}
	if err := ks.ReplaceAll(sc.Keys); err != nil {
		return movedTo, err
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
			return movedTo, err
		}
		if err := os.WriteFile(filepath.Join(udir, "signing.key"), sc.SigningKey, 0o600); err != nil {
			return movedTo, err
		}
		if len(sc.SigningMeta) > 0 {
			_ = os.WriteFile(filepath.Join(udir, "signing.key.meta"), sc.SigningMeta, 0o600)
		}
	}
	if len(sc.Tenants) > 0 {
		if err := os.WriteFile(filepath.Join(dataDir, "tenants.json"), sc.Tenants, 0o600); err != nil {
			return movedTo, err
		}
	}
	return movedTo, nil
}
