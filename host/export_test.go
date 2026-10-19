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
