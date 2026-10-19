package host

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type applyInput struct {
	App        string
	Version    string
	Source     string
	Strategy   string
	Percent    int
	MinMinutes int
	ScheduleAt *time.Time
	DryRun     bool
}

func newUpdateID(prefix string) string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return prefix + hex.EncodeToString(buf)
}

func (u *updater) apply(in applyInput) (roID, snapID string, err error) {
	if !validVersion(in.Version) {
		return "", "", errors.New("invalid version")
	}
	if in.Source != "host" && in.Source != "github" {
		return "", "", errors.New("source must be host or github")
	}
	switch in.Strategy {
	case "", "direct":
		in.Strategy = "direct"
	case "canary", "blue_green":
	default:
		return "", "", errors.New("strategy must be canary, blue_green or direct")
	}
	members := u.membersOf()
	effective := in.Strategy
	if len(members) < 2 {
		effective = "direct"
	}
	if in.Percent <= 0 {
		in.Percent = 10
	}
	if in.Percent > 100 {
		in.Percent = 100
	}
	if in.Strategy == "canary" && in.MinMinutes < 0 {
		return "", "", errors.New("min_minutes must be >= 0")
	}

	u.mu.Lock()
	a := u.appLocked(in.App)
	if in.Source == "host" && !a.Hosted {
		u.mu.Unlock()
		return "", "", errNotHosted
	}
	pref := u.sourcePref(a)
	if pref == "github" && in.Source == "host" {
		u.mu.Unlock()
		return "", "", errNotHosted
	}
	if u.activeRollout(in.App) != nil {
		u.mu.Unlock()
		return "", "", errRolloutConflict
	}
	cur := a.Nodes[u.h.NodeID]
	u.mu.Unlock()

	m, _, _, err := u.loadManifest(in.App, in.Version, in.Source)
	if err != nil {
		return "", "", err
	}
	if err := checkSequence(cur.Sequence, m.Sequence); err != nil && cur.Sequence > 0 {
		return "", "", errSeq
	}

	u.mu.Lock()
	a = u.appLocked(in.App)
	if u.activeRollout(in.App) != nil {
		u.mu.Unlock()
		return "", "", errRolloutConflict
	}
	cur = a.Nodes[u.h.NodeID]
	ro := &rollout{
		ID: newUpdateID("ro_"), App: in.App, Version: in.Version, Source: in.Source,
		Strategy: in.Strategy, Effective: effective, State: "snapshotting",
		Created: time.Now().UTC(), CanaryPct: in.Percent, MinMinutes: in.MinMinutes,
		ScheduleAt: in.ScheduleAt, DryRun: in.DryRun, Total: len(members),
		PrevNodes: cloneNodes(a.Nodes), TargetSeq: m.Sequence,
	}
	u.st.Rollouts[ro.ID] = ro
	if err := u.saveLocked(); err != nil {
		u.mu.Unlock()
		return "", "", err
	}
	u.mu.Unlock()

	meta, err := u.takeSnapshot(in.App, cur.Version)
	if err != nil {
		u.mu.Lock()
		ro.State = "failed"
		ro.Reason = "snapshot failed"
		_ = u.saveLocked()
		u.mu.Unlock()
		return ro.ID, "", errSnap
	}
	u.mu.Lock()
	ro.SnapshotID = meta.ID
	ro.SnapshotOff = meta.Offset
	u.addHistoryLocked(historyItem{Kind: "snapshot", At: meta.CreatedAt, App: in.App, Version: cur.Version, SnapshotID: meta.ID, RolloutID: ro.ID})
	if in.ScheduleAt != nil && time.Now().Before(*in.ScheduleAt) {
		ro.State = "scheduled"
		_ = u.saveLocked()
		id, sid := ro.ID, ro.SnapshotID
		u.mu.Unlock()
		u.emit(UpdateEvent{Type: "rollout.state", App: in.App, Version: in.Version, Source: in.Source, RolloutID: id, State: "scheduled"})
		return id, sid, nil
	}
	u.advanceLocked(ro, members, m)
	_ = u.saveLocked()
	id, sid, state := ro.ID, ro.SnapshotID, ro.State
	u.mu.Unlock()
	u.emit(UpdateEvent{Type: "rollout.state", App: in.App, Version: in.Version, Source: in.Source, RolloutID: id, State: state})
	u.maybeAutoRollback(id)
	return id, sid, nil
}

func cloneNodes(in map[string]nodeVer) map[string]nodeVer {
	out := map[string]nodeVer{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

var (
	errRolloutConflict = errors.New("rollout already in progress")
	errNotHosted       = errors.New("app is not hosted with Red-XAI")
	errSnap            = errors.New("snapshot failed")
)

func (u *updater) takeSnapshot(app, version string) (*snapMeta, error) {
	u.mu.Lock()
	fail := u.snapFail
	u.mu.Unlock()
	if fail {
		return nil, errors.New("snapshot failed")
	}
	path, off, err := u.h.buildSnapshot()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		os.Remove(path)
		return nil, err
	}
	id := newUpdateID("snap_")
	dest := filepath.Join(u.dir, "snapshots")
	if err := os.MkdirAll(dest, 0o700); err != nil {
		os.Remove(path)
		return nil, err
	}
	final := filepath.Join(dest, id+".tgz")
	if err := os.Rename(path, final); err != nil {
		if werr := os.WriteFile(final, b, 0o600); werr != nil {
			os.Remove(path)
			return nil, err
		}
		os.Remove(path)
	}
	meta := &snapMeta{ID: id, App: app, Version: version, CreatedAt: time.Now().UTC(), Size: int64(len(b)), SHA256: sha256Hex(b), Offset: off, Path: final}
	u.mu.Lock()
	u.st.Snaps[id] = meta
	_ = u.saveLocked()
	u.mu.Unlock()
	return meta, nil
}

func (u *updater) advanceLocked(ro *rollout, members []string, m *Manifest) {
	if ro.DryRun {
		ro.State = "done"
		ro.Updated = nil
		u.addHistoryLocked(historyItem{Kind: "apply", At: time.Now().UTC(), App: ro.App, Version: ro.Version, Source: ro.Source, Sequence: ro.TargetSeq, SnapshotID: ro.SnapshotID, RolloutID: ro.ID, Outcome: &m.Outcome, Reason: "dry_run"})
		return
	}
	var n int
	switch ro.Effective {
	case "direct":
		n = len(members)
	case "blue_green":
		n = blueGreenCount(len(members))
	default:
		n = canaryCount(len(members), ro.CanaryPct)
	}
	if n > len(members) {
		n = len(members)
	}
	ro.Updated = append([]string(nil), members[:n]...)
	ro.Total = len(members)
	a := u.appLocked(ro.App)
	nv := nodeVer{Version: ro.Version, Sequence: ro.TargetSeq, Source: ro.Source}
	for _, id := range ro.Updated {
		a.Nodes[id] = nv
	}
	if ro.Effective == "direct" || n == len(members) {
		ro.State = "done"
		u.addHistoryLocked(historyItem{Kind: "apply", At: time.Now().UTC(), App: ro.App, Version: ro.Version, Source: ro.Source, Sequence: ro.TargetSeq, SnapshotID: ro.SnapshotID, RolloutID: ro.ID, Outcome: &m.Outcome})
		return
	}
	ro.State = "canary"
	ro.CanarySince = time.Now().UTC()
	u.addHistoryLocked(historyItem{Kind: "apply", At: ro.CanarySince, App: ro.App, Version: ro.Version, Source: ro.Source, Sequence: ro.TargetSeq, SnapshotID: ro.SnapshotID, RolloutID: ro.ID, Outcome: &m.Outcome, Reason: ro.Effective})
}

func (u *updater) maybeAutoRollback(id string) {
	u.mu.Lock()
	ro := u.st.Rollouts[id]
	if ro == nil || (ro.State != "canary" && ro.State != "promoting") {
		u.mu.Unlock()
		return
	}
	h := u.health
	bad := h.ErrorRate > updateMaxErrorRate || h.P95MS > updateMaxP95MS
	u.mu.Unlock()
	if !bad {
		return
	}
	_ = u.rollbackRollout(id, "health threshold")
}

var errHealth = errors.New("health threshold")

func (u *updater) promote(id string) error {
	members := u.membersOf()
	u.mu.Lock()
	ro := u.st.Rollouts[id]
	if ro == nil {
		u.mu.Unlock()
		return os.ErrNotExist
	}
	if ro.State != "canary" {
		state := ro.State
		u.mu.Unlock()
		return fmt.Errorf("rollout is %s", state)
	}
	if ro.MinMinutes > 0 && !ro.CanarySince.IsZero() && time.Since(ro.CanarySince) < time.Duration(ro.MinMinutes)*time.Minute {
		u.mu.Unlock()
		return errRolloutConflict
	}
	h := u.health
	if h.ErrorRate > updateMaxErrorRate || h.P95MS > updateMaxP95MS {
		u.mu.Unlock()
		_ = u.rollbackRollout(id, "health threshold")
		return errHealth
	}
	ro.State = "promoting"
	a := u.appLocked(ro.App)
	nv := nodeVer{Version: ro.Version, Sequence: ro.TargetSeq, Source: ro.Source}
	ro.Updated = append([]string(nil), members...)
	ro.Total = len(members)
	for _, nid := range members {
		a.Nodes[nid] = nv
	}
	ro.State = "done"
	u.addHistoryLocked(historyItem{Kind: "apply", At: time.Now().UTC(), App: ro.App, Version: ro.Version, Source: ro.Source, Sequence: ro.TargetSeq, SnapshotID: ro.SnapshotID, RolloutID: ro.ID, Reason: "promote"})
	if err := u.saveLocked(); err != nil {
		u.mu.Unlock()
		return err
	}
	app, ver, src := ro.App, ro.Version, ro.Source
	u.mu.Unlock()
	u.emit(UpdateEvent{Type: "rollout.state", App: app, Version: ver, Source: src, RolloutID: id, State: "done"})
	return nil
}

func (u *updater) rollbackRollout(id, reason string) error {
	u.mu.Lock()
	ro := u.st.Rollouts[id]
	if ro == nil {
		u.mu.Unlock()
		return os.ErrNotExist
	}
	switch ro.State {
	case "done", "rolled_back", "failed":
		u.mu.Unlock()
		return fmt.Errorf("rollout is %s", ro.State)
	}
	snapID := ro.SnapshotID
	app, ver, src := ro.App, ro.Version, ro.Source
	u.mu.Unlock()
	if err := u.restoreSnap(snapID, reason, id); err != nil {
		return err
	}
	u.emit(UpdateEvent{Type: "rollback.done", App: app, Version: ver, Source: src, RolloutID: id, State: "rolled_back"})
	u.emit(UpdateEvent{Type: "rollout.state", App: app, Version: ver, Source: src, RolloutID: id, State: "rolled_back"})
	return nil
}

func (u *updater) restoreSnap(id, reason, rolloutID string) error {
	u.mu.Lock()
	meta := u.st.Snaps[id]
	if meta == nil {
		u.mu.Unlock()
		return os.ErrNotExist
	}
	path, off, app, captured := meta.Path, meta.Offset, meta.App, meta.Version
	var prev map[string]nodeVer
	if rolloutID != "" {
		if ro := u.st.Rollouts[rolloutID]; ro != nil {
			prev = cloneNodes(ro.PrevNodes)
		}
	}
	u.mu.Unlock()
	if err := u.h.installUpdateSnapshot(path, off); err != nil {
		return errSnap
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	a := u.appLocked(app)
	if prev != nil {
		a.Nodes = prev
	}
	if rolloutID != "" {
		if ro := u.st.Rollouts[rolloutID]; ro != nil {
			ro.State = "rolled_back"
			ro.Reason = reason
		}
	}
	for _, ro := range u.st.Rollouts {
		if rolloutID != "" && ro.ID == rolloutID {
			continue
		}
		if ro.App == app && (ro.State == "canary" || ro.State == "promoting" || ro.State == "scheduled" || ro.State == "snapshotting") {
			ro.State = "rolled_back"
			ro.Reason = reason
			if ro.PrevNodes != nil {
				a.Nodes = cloneNodes(ro.PrevNodes)
			}
		}
	}
	if rolloutID == "" && prev == nil {
		if captured == "" {
			a.Nodes = map[string]nodeVer{}
		} else {
			for id := range a.Nodes {
				nv := a.Nodes[id]
				nv.Version = captured
				a.Nodes[id] = nv
			}
			if len(a.Nodes) == 0 {
				a.Nodes[u.h.NodeID] = nodeVer{Version: captured}
			}
		}
	}
	ver := captured
	if nv, ok := a.Nodes[u.h.NodeID]; ok && nv.Version != "" {
		ver = nv.Version
	}
	u.addHistoryLocked(historyItem{Kind: "rollback", At: time.Now().UTC(), App: app, Version: ver, SnapshotID: id, RolloutID: rolloutID, Reason: reason})
	return u.saveLocked()
}

func (h *Host) tickUpdates(now time.Time) {
	if h == nil || h.upd == nil {
		return
	}
	h.upd.tick(now)
}

func (u *updater) tick(now time.Time) {
	u.mu.Lock()
	var due []string
	var watch []string
	for id, ro := range u.st.Rollouts {
		if ro.State == "scheduled" && ro.ScheduleAt != nil && !now.Before(*ro.ScheduleAt) {
			due = append(due, id)
		}
		if ro.State == "canary" || ro.State == "promoting" {
			watch = append(watch, id)
		}
	}
	u.mu.Unlock()
	for _, id := range due {
		u.startScheduled(id)
	}
	for _, id := range watch {
		u.maybeAutoRollback(id)
		u.emitHealth(id)
	}
}

func (u *updater) emitHealth(id string) {
	u.mu.Lock()
	ro := u.st.Rollouts[id]
	if ro == nil {
		u.mu.Unlock()
		return
	}
	ev := UpdateEvent{Type: "rollout.health", App: ro.App, Version: ro.Version, Source: ro.Source, RolloutID: id, State: ro.State}
	u.mu.Unlock()
	u.emit(ev)
}

// installUpdateSnapshot unpacks a snapshot taken by buildSnapshot and swaps it
// in with the same pause / rename / key-replace path the cluster uses.
func (h *Host) installUpdateSnapshot(path string, offset uint64) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	tmp, err := os.MkdirTemp(h.Cfg.DataDir, ".upd-snap-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	sc, err := ExtractSnapshot(f, filepath.Join(tmp, "dbs"))
	if err != nil {
		return err
	}
	h.pause.Lock()
	defer h.pause.Unlock()
	if err := h.Reg.CloseAll(); err != nil {
		h.Logf("update snapshot: closing dbs: %v", err)
	}
	old := h.Reg.Root() + ".old-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := os.Rename(h.Reg.Root(), old); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(tmp, "dbs"), h.Reg.Root()); err != nil {
		_ = os.Rename(old, h.Reg.Root())
		return err
	}
	_ = os.RemoveAll(old)
	if err := h.KS.ReplaceAll(sc.Keys); err != nil {
		return err
	}
	if sc.TTL != nil {
		cdir := filepath.Join(h.Cfg.DataDir, "cluster")
		_ = os.MkdirAll(cdir, 0o700)
		_ = os.WriteFile(filepath.Join(cdir, "ttl.json"), sc.TTL, 0o600)
	}
	h.Tracker.Reload()
	if h.Cluster != nil && h.Cluster.log != nil {
		if err := h.Cluster.log.Reset(offset); err != nil {
			return err
		}
	}
	return nil
}

func (u *updater) startScheduled(id string) {
	u.mu.Lock()
	ro := u.st.Rollouts[id]
	if ro == nil || ro.State != "scheduled" {
		u.mu.Unlock()
		return
	}
	app, ver, src := ro.App, ro.Version, ro.Source
	u.mu.Unlock()
	m, _, _, err := u.loadManifest(app, ver, src)
	if err != nil {
		u.mu.Lock()
		ro.State = "failed"
		ro.Reason = err.Error()
		_ = u.saveLocked()
		u.mu.Unlock()
		return
	}
	members := u.membersOf()
	u.mu.Lock()
	if ro.State != "scheduled" {
		u.mu.Unlock()
		return
	}
	u.advanceLocked(ro, members, m)
	_ = u.saveLocked()
	state := ro.State
	u.mu.Unlock()
	u.emit(UpdateEvent{Type: "rollout.state", App: app, Version: ver, Source: src, RolloutID: id, State: state})
	u.maybeAutoRollback(id)
}
