package host

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"redx/internal/rsx"
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
	Internal   bool
	Permit     string
	KeyID      string
}

func newUpdateID(prefix string) string {
	buf := make([]byte, 8)
	if err := rsx.Random(buf); err != nil {
		panic(err)
	}
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
	if !sourceAccepted(pref, in.Source) {
		u.mu.Unlock()
		return "", "", errNotHosted
	}
	if u.activeRollout(in.App) != nil {
		u.mu.Unlock()
		return "", "", errRolloutConflict
	}
	cur := a.Nodes[u.h.NodeID]
	u.mu.Unlock()

	m, err := u.preflightApply(in, cur)
	if err != nil {
		return "", "", err
	}
	if !in.Internal {
		if err := u.consumePermit(in.Permit, updatePermit{Action: "updateApply", App: in.App, Version: in.Version, Source: in.Source, KeyID: in.KeyID}); err != nil {
			return "", "", err
		}
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

func (u *updater) preflightApply(in applyInput, cur nodeVer) (*Manifest, error) {
	m, _, _, err := u.loadManifest(in.App, in.Version, in.Source)
	if err != nil {
		return nil, err
	}
	if _, ok := parseSemver(m.Version); !ok {
		return nil, errors.New("version must be semver")
	}
	if cur.Version != "" {
		cmp, ok := semverCmp(m.Version, cur.Version)
		if !ok || cmp < 0 {
			return nil, errDowngrade
		}
	}
	if m.Requires.MinFrom != "" {
		if cur.Version == "" {
			return nil, errMinFrom
		}
		cmp, ok := semverCmp(cur.Version, m.Requires.MinFrom)
		if !ok || cmp < 0 {
			return nil, errMinFrom
		}
	}
	if err := checkSequence(cur.Sequence, m.Sequence); err != nil && cur.Sequence > 0 {
		return nil, errSeq
	}
	return m, nil
}

// prepareApply is the read-only check a plan or dry-run uses. It does not snapshot or install.
func (u *updater) prepareApply(in applyInput) (*Manifest, error) {
	if !validVersion(in.Version) {
		return nil, errors.New("invalid version")
	}
	if in.Source != "host" && in.Source != "github" {
		return nil, errors.New("source must be host or github")
	}
	u.mu.Lock()
	a := u.appLocked(in.App)
	hosted := a.Hosted
	pref := u.sourcePref(a)
	conflict := u.activeRollout(in.App) != nil
	cur := a.Nodes[u.h.NodeID]
	u.mu.Unlock()
	if in.Source == "host" && !hosted {
		return nil, errNotHosted
	}
	if !sourceAccepted(pref, in.Source) {
		return nil, errNotHosted
	}
	if conflict {
		return nil, errRolloutConflict
	}
	return u.preflightApply(in, cur)
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
	updated := append([]string(nil), ro.Updated...)
	u.mu.Unlock()
	if u.measureHealth(updated).Status != "bad" {
		return
	}
	_ = u.rollbackRollout(id, "health threshold")
}

var errHealth = errors.New("health threshold")

func (u *updater) rolloutVersion(id string) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if ro := u.st.Rollouts[id]; ro != nil {
		return ro.Version
	}
	return ""
}

func (u *updater) promotePreflight(id string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	ro := u.st.Rollouts[id]
	if ro == nil {
		return os.ErrNotExist
	}
	if ro.State != "canary" {
		return fmt.Errorf("rollout is %s", ro.State)
	}
	if ro.MinMinutes > 0 && !ro.CanarySince.IsZero() && time.Since(ro.CanarySince) < time.Duration(ro.MinMinutes)*time.Minute {
		return errRolloutConflict
	}
	return nil
}

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
	updated := append([]string(nil), ro.Updated...)
	u.mu.Unlock()
	if u.measureHealth(updated).Status == "bad" {
		_ = u.rollbackRollout(id, "health threshold")
		return errHealth
	}
	u.mu.Lock()
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
	path, sum, app, captured := meta.Path, meta.SHA256, meta.App, meta.Version
	u.mu.Unlock()
	doc, err := u.installAppSnap(path, sum, app)
	if err != nil {
		return errSnap
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	a := u.appLocked(app)
	if doc != nil && doc.Nodes != nil {
		a.Nodes = doc.Nodes
		if doc.SourcePref != "" {
			a.SourcePref = doc.SourcePref
		}
		if doc.Policy.AutoApply != "" {
			a.Policy = doc.Policy
		}
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
			if ro.PrevNodes != nil && (doc == nil || doc.Nodes == nil) {
				a.Nodes = cloneNodes(ro.PrevNodes)
			}
		}
	}
	if rolloutID == "" && (doc == nil || doc.Nodes == nil) {
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
