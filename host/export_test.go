package host

import (
	"errors"
	"strings"
	"time"

	"redx/billing"
)

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

// NoteUpdateSample records one served request in the health window (tests).
func NoteUpdateSample(h *Host, status int, ms float64) {
	h.noteRequest(status, time.Duration(ms*float64(time.Millisecond)))
}

// UpdateMinHealthSamples is how many qualifying samples a verdict needs.
func UpdateMinHealthSamples() int { return updateMinHealthSamples }

// UpdateRolloutNodes returns the node ids serving the new version.
func UpdateRolloutNodes(h *Host, id string) []string {
	if h == nil || h.upd == nil {
		return nil
	}
	h.upd.mu.Lock()
	defer h.upd.mu.Unlock()
	ro := h.upd.st.Rollouts[id]
	if ro == nil {
		return nil
	}
	return append([]string(nil), ro.Updated...)
}

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

// SetPlanForTest stores a hosted plan row without Stripe. Tests use it to
// exercise the tenant gate.
func SetPlanForTest(h *Host, p billing.Plan) error {
	if h == nil || h.billing == nil {
		return errors.New("billing is not open")
	}
	return h.billing.PutPlan(p)
}

// AddTrafficForTest adds bytes to the account's current traffic counter.
func AddTrafficForTest(h *Host, account string, n int64) error {
	if h == nil || h.billing == nil {
		return errors.New("billing is not open")
	}
	p, ok := h.billing.ActivePlan(account)
	if !ok {
		return errors.New("no active plan")
	}
	q, _ := billing.QuotaFor(p.Tier)
	return h.billing.Usage().AddTraffic(account, q, n, time.Now(), p.PeriodEnd)
}

// SetHostedFetchForTest replaces the GitHub archive fetch used by app deploys.
func SetHostedFetchForTest(h *Host, fn func(repo, ref string) ([]byte, error)) {
	h.apps.mu.Lock()
	h.apps.fetch = fn
	h.apps.mu.Unlock()
}

// SetHostedDNSForTest replaces TXT lookups for custom-domain verification.
func SetHostedDNSForTest(h *Host, fn func(name string) ([]string, error)) {
	h.apps.mu.Lock()
	h.apps.txt = fn
	h.apps.mu.Unlock()
}

// SetHostedCNAMEForTest replaces CNAME lookups for custom-domain verification.
func SetHostedCNAMEForTest(h *Host, fn func(name string) (string, error)) {
	h.apps.mu.Lock()
	h.apps.cname = fn
	h.apps.mu.Unlock()
}

// SetHostedProbeForTest replaces the post-deploy health probe.
func SetHostedProbeForTest(h *Host, fn func(id string) (string, string)) {
	h.apps.mu.Lock()
	h.apps.probe = fn
	h.apps.mu.Unlock()
}

// SetHostedHTTPForTest replaces the HTTP-01 fetch for custom-domain verification.
func SetHostedHTTPForTest(h *Host, fn func(rawURL string) (int, string, error)) {
	h.apps.mu.Lock()
	h.apps.httpGet = fn
	h.apps.mu.Unlock()
}

// AgeHostedDomainForTest moves a domain claim into the past so a stale unverified name can be taken.
func AgeHostedDomainForTest(h *Host, name string, age time.Duration) {
	h.apps.mu.Lock()
	defer h.apps.mu.Unlock()
	name = strings.ToLower(name)
	for _, a := range h.apps.apps {
		for i := range a.Domains {
			if a.Domains[i].Name == name {
				a.Domains[i].Added = time.Now().Add(-age)
			}
		}
	}
}

// UpdatePublicKeyForTest is the Ed25519 public key that signs hosted deploy manifests.
func UpdatePublicKeyForTest(h *Host) []byte {
	if h == nil || h.upd == nil {
		return nil
	}
	return append([]byte(nil), h.upd.pub...)
}
