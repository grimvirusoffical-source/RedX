package host

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	updateSnapshotSchema = "redx.update-snapshot/v1"
	updateSnapshotKeep   = 5
)

// appSnapDoc is the only host state an update snapshot is allowed to restore:
// this app's version pointer, its update policy, and (separately) its own database files.
// The keystore and the master accounts database are never in the archive.
type appSnapDoc struct {
	Schema     string             `json:"schema"`
	App        string             `json:"app"`
	Version    string             `json:"version"`
	Sequence   int64              `json:"sequence"`
	Source     string             `json:"source"`
	SourcePref string             `json:"source_pref"`
	Policy     updatePolicy       `json:"policy"`
	Nodes      map[string]nodeVer `json:"nodes"`
}

func (u *updater) takeSnapshot(app, version string) (*snapMeta, error) {
	u.mu.Lock()
	fail := u.snapFail
	a := u.st.Apps[app]
	doc := appSnapDoc{Schema: updateSnapshotSchema, App: app, Version: version, Nodes: map[string]nodeVer{}}
	if a != nil {
		doc.SourcePref = a.SourcePref
		doc.Policy = a.Policy
		if nv, ok := a.Nodes[u.h.NodeID]; ok {
			doc.Sequence = nv.Sequence
			doc.Source = nv.Source
		}
		doc.Nodes = cloneNodes(a.Nodes)
	}
	u.mu.Unlock()
	if fail {
		return nil, errors.New("snapshot failed")
	}
	if u.h.IsMasterDB(app) {
		return nil, errors.New("refusing to snapshot the master accounts database")
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	if err := writeTarBytes(tw, "meta.json", raw); err != nil {
		return nil, err
	}
	u.h.pause.Lock()
	u.h.checkpointAll()
	// App ids and database names share one namespace: this archive includes the
	// database whose name equals the app id, and restore writes that database back.
	// hosted_apps must not name a customer database. The master accounts database
	// is refused above. Phase 1 keeps this shared namespace.
	dbDir := filepath.Join(u.h.Reg.Root(), app)
	if !u.h.IsMasterDB(app) {
		if st, err := os.Stat(dbDir); err == nil && st.IsDir() {
			if err := writeTarDir(tw, "db", dbDir); err != nil {
				u.h.pause.Unlock()
				return nil, err
			}
		}
	}
	u.h.pause.Unlock()
	blobRoot := filepath.Join(u.dir, "blobs", app)
	if st, err := os.Stat(blobRoot); err == nil && st.IsDir() {
		if err := writeTarDir(tw, "binary", blobRoot); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	b := buf.Bytes()
	id := newUpdateID("snap_")
	dest := filepath.Join(u.dir, "snapshots")
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return nil, err
	}
	final := filepath.Join(dest, id+".tgz")
	if err := os.WriteFile(final, b, 0o600); err != nil {
		return nil, err
	}
	meta := &snapMeta{ID: id, App: app, Version: version, CreatedAt: time.Now().UTC(), Size: int64(len(b)), SHA256: sha256Hex(b), Path: final}
	u.mu.Lock()
	u.st.Snaps[id] = meta
	u.pruneSnapsLocked(app)
	_ = u.saveLocked()
	u.mu.Unlock()
	return meta, nil
}

func writeTarBytes(tw *tar.Writer, name string, b []byte) error {
	hdr := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), ModTime: time.Now().UTC()}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(b)
	return err
}

func writeTarDir(tw *tar.Writer, prefix, root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if strings.Contains(rel, "..") {
			return errors.New("snapshot path escaped")
		}
		name := prefix + "/" + rel
		if info.IsDir() {
			return tw.WriteHeader(&tar.Header{Name: name + "/", Mode: 0o700, Typeflag: tar.TypeDir, ModTime: info.ModTime()})
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return writeTarBytes(tw, name, b)
	})
}

func (u *updater) pruneSnapsLocked(app string) {
	var list []*snapMeta
	for _, s := range u.st.Snaps {
		if s != nil && s.App == app {
			list = append(list, s)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.After(list[j].CreatedAt) })
	keep := map[string]bool{}
	for _, ro := range u.st.Rollouts {
		if ro.App == app && ro.SnapshotID != "" && (ro.State == "canary" || ro.State == "promoting" || ro.State == "scheduled" || ro.State == "snapshotting") {
			keep[ro.SnapshotID] = true
		}
	}
	n := 0
	for _, s := range list {
		if keep[s.ID] {
			continue
		}
		if n < updateSnapshotKeep {
			keep[s.ID] = true
			n++
		}
	}
	for _, s := range list {
		if keep[s.ID] {
			continue
		}
		_ = os.Remove(s.Path)
		delete(u.st.Snaps, s.ID)
	}
}

// installAppSnap checks the archive hash, then restores only this app's database directory.
// It never reads a keystore and never replaces another database.
func (u *updater) installAppSnap(path, wantSum, app string) (*appSnapDoc, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if wantSum == "" || sha256Hex(b) != wantSum {
		return nil, errors.New("snapshot hash mismatch")
	}
	doc, files, bins, err := readAppSnapshot(b, app, u.h.masterDB())
	if err != nil {
		return nil, err
	}
	if err := u.h.restoreAppDB(app, files); err != nil {
		return nil, err
	}
	if err := u.restoreAppBlobs(app, bins); err != nil {
		return nil, err
	}
	return doc, nil
}

func readAppSnapshot(b []byte, app, master string) (*appSnapDoc, map[string][]byte, map[string][]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, nil, nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var doc *appSnapDoc
	files := map[string][]byte{}
	bins := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, nil, err
		}
		name := hdr.Name
		if strings.Contains(name, "..") || strings.HasPrefix(name, "/") || strings.Contains(strings.ToLower(name), "keys") {
			return nil, nil, nil, errors.New("snapshot contains a forbidden path")
		}
		if master != "" && strings.Contains(name, master) {
			return nil, nil, nil, errors.New("snapshot contains the master accounts database")
		}
		body, err := io.ReadAll(io.LimitReader(tr, 64<<20))
		if err != nil {
			return nil, nil, nil, err
		}
		switch {
		case name == "meta.json":
			var d appSnapDoc
			if json.Unmarshal(body, &d) != nil || d.Schema != updateSnapshotSchema || d.App != app {
				return nil, nil, nil, errors.New("snapshot metadata does not match the app")
			}
			doc = &d
		case strings.HasPrefix(name, "db/") && !strings.HasSuffix(name, "/"):
			rel := strings.TrimPrefix(name, "db/")
			if rel == "" || strings.Contains(rel, "..") {
				return nil, nil, nil, errors.New("snapshot database path is invalid")
			}
			files[rel] = body
		case strings.HasPrefix(name, "binary/") && !strings.HasSuffix(name, "/"):
			rel := strings.TrimPrefix(name, "binary/")
			if rel == "" || strings.Contains(rel, "..") {
				return nil, nil, nil, errors.New("snapshot binary path is invalid")
			}
			bins[rel] = body
		default:
			if name != "db/" && name != "binary/" && !strings.HasPrefix(name, "binary/") && !strings.HasPrefix(name, "db/") {
				return nil, nil, nil, errors.New("snapshot contains an unexpected entry")
			}
		}
	}
	if doc == nil {
		return nil, nil, nil, errors.New("snapshot has no metadata")
	}
	return doc, files, bins, nil
}

func (u *updater) restoreAppBlobs(app string, files map[string][]byte) error {
	if len(files) == 0 || !validAppID(app) || u.h.IsMasterDB(app) {
		return nil
	}
	root := filepath.Join(u.dir, "blobs", app)
	for rel, b := range files {
		target := filepath.Join(root, filepath.FromSlash(rel))
		if !strings.HasPrefix(target, root+string(os.PathSeparator)) {
			return errors.New("snapshot binary path escaped")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(target, b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (h *Host) restoreAppDB(app string, files map[string][]byte) error {
	if h.IsMasterDB(app) || !ValidDBName(app) {
		return errors.New("refusing to restore this database")
	}
	if len(files) == 0 {
		return nil
	}
	h.pause.Lock()
	defer h.pause.Unlock()
	if err := h.Reg.CloseOne(app); err != nil {
		return err
	}
	dest := filepath.Join(h.Reg.Root(), app)
	tmp := dest + ".new"
	_ = os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return err
	}
	for rel, b := range files {
		target := filepath.Join(tmp, filepath.FromSlash(rel))
		if !strings.HasPrefix(target, tmp+string(os.PathSeparator)) && target != tmp {
			_ = os.RemoveAll(tmp)
			return errors.New("snapshot database path escaped")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			_ = os.RemoveAll(tmp)
			return err
		}
		if err := os.WriteFile(target, b, 0o600); err != nil {
			_ = os.RemoveAll(tmp)
			return err
		}
	}
	old := dest + ".old"
	_ = os.RemoveAll(old)
	had := false
	if st, err := os.Stat(dest); err == nil && st.IsDir() {
		had = true
		if err := os.Rename(dest, old); err != nil {
			_ = os.RemoveAll(tmp)
			return err
		}
	}
	if err := os.Rename(tmp, dest); err != nil {
		if had {
			_ = os.Rename(old, dest)
		}
		_ = os.RemoveAll(tmp)
		return err
	}
	_ = os.RemoveAll(old)
	return nil
}
