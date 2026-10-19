package host

import "time"

// ValidPackPathForTest exposes validPackPath to the external test package.
func ValidPackPathForTest(p string) bool { return validPackPath(p, false) }

// ParseRangeForTest exposes parseRange.
func ParseRangeForTest(h string, size int64) (off, n int64, ok, unsat bool) {
	return parseRange(h, size)
}

// PartitionFenceNotify stops promoted nodes from telling the old leader (a network partition) for one test.
func PartitionFenceNotify(t interface{ Cleanup(func()) }) {
	fenceNotifyOff.Store(true)
	t.Cleanup(func() { fenceNotifyOff.Store(false) })
}

// SetConnectClock replaces the connect store's clock (expiry tests).
func SetConnectClock(h *Host, now func() time.Time) {
	h.connect.mu.Lock()
	h.connect.now = now
	h.connect.mu.Unlock()
}

// SetUpdateMembers replaces the cluster member list the rollout planner sees.
func SetUpdateMembers(h *Host, ids []string) {
	h.upd.mu.Lock()
	h.upd.members = append([]string(nil), ids...)
	h.upd.mu.Unlock()
}

// SetUpdateHealth sets the error rate (0..1) and p95 latency the rollout health gate reads.
func SetUpdateHealth(h *Host, errorRate, p95 float64) {
	h.upd.mu.Lock()
	h.upd.health = Health{ErrorRate: errorRate, P95MS: p95}
	h.upd.healthSet = true
	h.upd.mu.Unlock()
}

// ClearUpdateHealth clears the test override so rollouts read the host's own metrics.
func ClearUpdateHealth(h *Host) {
	h.upd.mu.Lock()
	h.upd.healthSet = false
	h.upd.mu.Unlock()
}

// ResetUpdateMetrics drops recorded request samples so health is unknown.
func ResetUpdateMetrics(h *Host) { h.resetRequestMetrics() }

// SetUpdatePermitTTL sets how long a plan confirmation stays valid.
func SetUpdatePermitTTL(h *Host, d time.Duration) {
	h.upd.mu.Lock()
	h.upd.permitTTL = d
	h.upd.mu.Unlock()
}

// SetUpdateSnapshotFail makes the next apply refuse with snapshot_failed.
func SetUpdateSnapshotFail(h *Host, fail bool) {
	h.upd.mu.Lock()
	h.upd.snapFail = fail
	h.upd.mu.Unlock()
}

// SetUpdateGitHubAPI points release publishing at a test server.
func SetUpdateGitHubAPI(h *Host, base string) {
	h.upd.mu.Lock()
	h.upd.githubAPI = base
	h.upd.mu.Unlock()
}

// SetUpdateAllowLoopback lets artifact downloads use a loopback URL (tests only).
func SetUpdateAllowLoopback(h *Host, on bool) {
	h.upd.mu.Lock()
	h.upd.allowLoopback = on
	h.upd.mu.Unlock()
}

// SetBeforeApplyHook runs fn after a follower fetched an entry and before it applies it, for one test.
func SetBeforeApplyHook(t interface{ Cleanup(func()) }, fn func()) {
	beforeApplyHook.Store(&fn)
	t.Cleanup(func() { beforeApplyHook.Store(nil) })
}
