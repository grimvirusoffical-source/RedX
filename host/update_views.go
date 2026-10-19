package host

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type verRef struct {
	Version  string `json:"version"`
	Sequence int64  `json:"sequence"`
}

type availDTO struct {
	Version string   `json:"version"`
	Channel string   `json:"channel"`
	Outcome Outcome  `json:"outcome"`
	Sources []string `json:"sources"`
	seq     int64
}

func (u *updater) status(app string) map[string]interface{} {
	u.mu.Lock()
	defer u.mu.Unlock()
	a := u.st.Apps[app]
	hosted := false
	pref := "github"
	var installed interface{} = nil
	if a != nil {
		hosted = a.Hosted
		pref = u.sourcePref(a)
		if nv, ok := a.Nodes[u.h.NodeID]; ok && nv.Version != "" {
			installed = verRef{Version: nv.Version, Sequence: nv.Sequence}
		}
	}
	type slot struct {
		m   Manifest
		src string
	}
	byVer := map[string]*availDTO{}
	var hostLatest, gitLatest *verRef
	installedVer := ""
	if a != nil {
		if nv, ok := a.Nodes[u.h.NodeID]; ok {
			installedVer = nv.Version
		}
	}
	for key, sm := range u.st.Manifests {
		if sm == nil || len(key) < len(app)+1 || key[:len(app)+1] != app+"|" {
			continue
		}
		if u.verify(sm.Body, sm.Sig) != nil {
			continue
		}
		var m Manifest
		if json.Unmarshal(sm.Body, &m) != nil || m.App != app {
			continue
		}
		if installedVer != "" {
			cmp, ok := semverCmp(m.Version, installedVer)
			if !ok || cmp < 0 {
				continue
			}
		}
		row := byVer[m.Version]
		if row == nil {
			row = &availDTO{Version: m.Version, Channel: m.Channel, Outcome: m.Outcome, seq: m.Sequence}
			byVer[m.Version] = row
		}
		row.Sources = append(row.Sources, m.Source.Kind)
		if m.Sequence >= row.seq {
			row.seq = m.Sequence
			row.Outcome = m.Outcome
			row.Channel = m.Channel
		}
		ref := verRef{Version: m.Version, Sequence: m.Sequence}
		if m.Source.Kind == "host" && newerRef(ref, hostLatest) {
			cp := ref
			hostLatest = &cp
		}
		if m.Source.Kind == "github" && newerRef(ref, gitLatest) {
			cp := ref
			gitLatest = &cp
		}
	}
	avail := make([]availDTO, 0, len(byVer))
	for _, row := range byVer {
		sort.Strings(row.Sources)
		avail = append(avail, *row)
	}
	sort.Slice(avail, func(i, j int) bool {
		cmp, ok := semverCmp(avail[i].Version, avail[j].Version)
		if ok && cmp != 0 {
			return cmp > 0
		}
		return avail[i].Version < avail[j].Version
	})
	// drop the unexported seq from JSON by re-marshalling through a public struct
	pub := make([]struct {
		Version string   `json:"version"`
		Channel string   `json:"channel"`
		Outcome Outcome  `json:"outcome"`
		Sources []string `json:"sources"`
	}, len(avail))
	for i := range avail {
		if avail[i].Sources == nil {
			avail[i].Sources = []string{}
		}
		pub[i].Version = avail[i].Version
		pub[i].Channel = avail[i].Channel
		pub[i].Outcome = avail[i].Outcome
		pub[i].Sources = avail[i].Sources
	}
	return map[string]interface{}{
		"app": app, "hosted": hosted, "source_pref": pref, "installed": installed,
		"latest":    map[string]interface{}{"host": hostLatest, "github": gitLatest},
		"available": pub,
	}
}

func (u *updater) history(app string) []historyItem {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := []historyItem{}
	for _, it := range u.st.History {
		if it.App == app {
			out = append(out, it)
		}
	}
	return out
}

func (u *updater) snapshots(app string) []map[string]interface{} {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := []map[string]interface{}{}
	for _, s := range u.st.Snaps {
		if s.App != app {
			continue
		}
		out = append(out, map[string]interface{}{
			"id": s.ID, "version": s.Version, "created_at": s.CreatedAt.UTC().Format(time.RFC3339),
			"size": s.Size, "sha256": s.SHA256,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["id"].(string) < out[j]["id"].(string) })
	return out
}

func (u *updater) setSource(app, source string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	a := u.appLocked(app)
	if (source == "host" || source == "both") && !a.Hosted {
		return errNotHosted
	}
	a.SourcePref = source
	return u.saveLocked()
}

func (u *updater) setPolicy(app, auto, channel, window string) error {
	switch auto {
	case "off", "security", "all":
	default:
		return errString("auto_apply must be off, security or all")
	}
	switch channel {
	case "stable", "beta":
	default:
		return errString("channel must be stable or beta")
	}
	if window != "" && !cronMatches(window, time.Now().UTC()) && !cronShape(window) {
		return errString("window must be a 5-field cron expression or null")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	a := u.appLocked(app)
	a.Policy = updatePolicy{AutoApply: auto, Channel: channel, Window: window}
	return u.saveLocked()
}

func cronShape(expr string) bool {
	return len(splitFields(expr)) == 5
}

func splitFields(s string) []string {
	out := []string{}
	cur := ""
	for _, r := range s {
		if r == ' ' || r == '\t' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

type errString string

func (e errString) Error() string { return string(e) }

func (u *updater) blob(app, version, source, id string) ([]byte, error) {
	u.mu.Lock()
	rel := u.st.Blobs[blobKey(app, version, source, id)]
	u.mu.Unlock()
	if rel == "" {
		return nil, os.ErrNotExist
	}
	b, err := os.ReadFile(filepath.Join(u.dir, rel))
	if err != nil {
		return nil, os.ErrNotExist
	}
	return b, nil
}

func (u *updater) rolloutApp(id string) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if ro := u.st.Rollouts[id]; ro != nil {
		return ro.App
	}
	return ""
}

func newerRef(next verRef, cur *verRef) bool {
	if cur == nil {
		return true
	}
	cmp, ok := semverCmp(next.Version, cur.Version)
	if !ok {
		return next.Sequence > cur.Sequence
	}
	return cmp > 0
}

func (u *updater) rolloutView(id string) (map[string]interface{}, error) {
	u.mu.Lock()
	ro := u.st.Rollouts[id]
	if ro == nil {
		u.mu.Unlock()
		return nil, os.ErrNotExist
	}
	pct := 0.0
	if ro.Total > 0 {
		pct = float64(len(ro.Updated)) * 100 / float64(ro.Total)
	}
	if ro.State == "done" {
		pct = 100
	}
	view := map[string]interface{}{
		"rollout_id": ro.ID, "app": ro.App, "version": ro.Version, "source": ro.Source,
		"state": ro.State, "snapshot_id": ro.SnapshotID,
		"strategy": ro.Effective,
		"progress": map[string]interface{}{"updated": len(ro.Updated), "total": ro.Total, "percent": pct},
	}
	u.mu.Unlock()
	view["health"] = u.measureHealth()
	return view, nil
}

func (u *updater) snapshotVersion(app, id string) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	s := u.st.Snaps[id]
	if s == nil || s.App != app {
		return ""
	}
	return s.Version
}

func (u *updater) snapshotExists(app, id string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	s := u.st.Snaps[id]
	return s != nil && s.App == app
}

func (u *updater) restoreApp(app, snapID, reason string) error {
	u.mu.Lock()
	meta := u.st.Snaps[snapID]
	if meta == nil || meta.App != app {
		u.mu.Unlock()
		return os.ErrNotExist
	}
	u.mu.Unlock()
	return u.restoreSnap(snapID, reason, "")
}

func (u *updater) listApps() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]string, 0, len(u.st.Apps))
	for n := range u.st.Apps {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
