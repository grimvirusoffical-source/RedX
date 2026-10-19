package billing

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// UnlimitedSwitches marks a tier with no monthly host on↔off cap (Emerald).
const UnlimitedSwitches = -1

// Quota is the monthly allowance for one Hosted tier. Annual and monthly billing
// share the same quotas; traffic and switches reset each month on the billing cycle.
type Quota struct {
	TrafficBytes int64 `json:"trafficBytes"` // bytes of HTTP traffic / month
	StorageBytes int64 `json:"storageBytes"` // stored data cap
	HostSwitches int   `json:"hostSwitches"` // on↔off / create↔drop; -1 = unlimited
}

// QuotaFor returns the quota for a tier key, or false if unknown.
func QuotaFor(tier string) (Quota, bool) {
	t, ok := tierOf(tier)
	if !ok {
		return Quota{}, false
	}
	return t.Quota, true
}

// Usage is one account's counters for the current monthly quota window.
type Usage struct {
	Account      string    `json:"account"`
	CycleStart   time.Time `json:"cycleStart"`
	TrafficBytes int64     `json:"trafficBytes"`
	StorageBytes int64     `json:"storageBytes"`
	HostSwitches int       `json:"hostSwitches"`
	HostedOn     bool      `json:"hostedOn,omitempty"`
	Updated      time.Time `json:"updated"`
}

// UsageStatus is what /v1/billing/me and owners see.
type UsageStatus struct {
	Tier         string    `json:"tier"`
	Interval     string    `json:"interval,omitempty"` // month | year
	Quota        Quota     `json:"quota"`
	TrafficBytes int64     `json:"trafficBytes"`
	StorageBytes int64     `json:"storageBytes"`
	HostSwitches int       `json:"hostSwitches"`
	HostedOn     bool      `json:"hostedOn"`
	CycleStart   time.Time `json:"cycleStart"`
	CycleEnd     time.Time `json:"cycleEnd"`
}

// ErrQuota is a refused hosted-plan action (storage / traffic / switches).
type ErrQuota struct {
	Code    string // storage_quota | traffic_quota | host_switch_quota
	Message string
	HTTP    int // 402 or 429
}

func (e *ErrQuota) Error() string { return e.Message }

func errStorage() *ErrQuota {
	return &ErrQuota{Code: "storage_quota", HTTP: 402,
		Message: "This write would go past your RedX Hosted storage limit. Upgrade your plan at /ui/billing.html."}
}
func errTraffic() *ErrQuota {
	return &ErrQuota{Code: "traffic_quota", HTTP: 429,
		Message: "This account has used its RedX Hosted traffic for this month. Upgrade your plan at /ui/billing.html."}
}
func errSwitches() *ErrQuota {
	return &ErrQuota{Code: "host_switch_quota", HTTP: 402,
		Message: "This account has used its RedX Hosted on/off switches for this month. Upgrade your plan at /ui/billing.html."}
}

// UsageStore keeps per-account usage under the data dir (0600 JSON).
type UsageStore struct {
	mu    sync.Mutex
	path  string
	Usage map[string]Usage `json:"usage"`
}

// OpenUsageStore loads (or starts) the usage file. path "" keeps everything in memory.
func OpenUsageStore(path string) (*UsageStore, error) {
	s := &UsageStore{path: path, Usage: map[string]Usage{}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(b, s); err != nil {
			return nil, err
		}
		if s.Usage == nil {
			s.Usage = map[string]Usage{}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *UsageStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func clampDay(y int, m time.Month, d int) int {
	last := time.Date(y, m+1, 0, 0, 0, 0, 0, time.UTC).Day()
	if d < 1 {
		d = 1
	}
	if d > last {
		return last
	}
	return d
}

func addMonths(t time.Time, n int) time.Time {
	y, m, _ := t.Date()
	m = time.Month(int(m) + n)
	for m > 12 {
		y++
		m -= 12
	}
	for m < 1 {
		y--
		m += 12
	}
	return time.Date(y, m, clampDay(y, m, t.Day()), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
}

// cycleWindow returns [start, end) for the monthly quota window containing now.
// The day-of-month (and time) come from periodEnd when set, otherwise from now.
func cycleWindow(now, periodEnd time.Time) (start, end time.Time) {
	now = now.UTC()
	anchorDay := now.Day()
	hour, min, sec := now.Clock()
	if !periodEnd.IsZero() {
		pe := periodEnd.UTC()
		anchorDay = pe.Day()
		hour, min, sec = pe.Clock()
	}
	y, m, _ := now.Date()
	start = time.Date(y, m, clampDay(y, m, anchorDay), hour, min, sec, 0, time.UTC)
	if start.After(now) {
		start = addMonths(start, -1)
	}
	end = addMonths(start, 1)
	return start, end
}

// ensureLocked resets traffic + switches when the monthly window rolled over.
// Storage and HostedOn carry across windows (capacity is continuous).
func (s *UsageStore) ensureLocked(account string, now, periodEnd time.Time) Usage {
	u := s.Usage[account]
	start, _ := cycleWindow(now, periodEnd)
	if u.Account == "" || u.CycleStart.IsZero() || !u.CycleStart.Equal(start) {
		hosted, storage := u.HostedOn, u.StorageBytes
		if u.Account == "" {
			storage = 0
			hosted = false
		}
		u = Usage{Account: account, CycleStart: start, StorageBytes: storage, HostedOn: hosted, Updated: now.UTC()}
		s.Usage[account] = u
	}
	return u
}

// Status builds the public usage view for an active plan.
func (s *UsageStore) Status(account string, tier, interval string, q Quota, now, periodEnd time.Time) UsageStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.ensureLocked(account, now, periodEnd)
	_, end := cycleWindow(now, periodEnd)
	return UsageStatus{
		Tier: tier, Interval: interval, Quota: q,
		TrafficBytes: u.TrafficBytes, StorageBytes: u.StorageBytes, HostSwitches: u.HostSwitches,
		HostedOn: u.HostedOn, CycleStart: u.CycleStart, CycleEnd: end,
	}
}

// SetStorage records the account's current stored bytes (absolute).
func (s *UsageStore) SetStorage(account string, bytes int64, now, periodEnd time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.ensureLocked(account, now, periodEnd)
	if bytes < 0 {
		bytes = 0
	}
	u.StorageBytes = bytes
	u.Updated = now.UTC()
	s.Usage[account] = u
	return s.saveLocked()
}

// CheckWrite reports whether adding deltaBytes of new stored data is allowed.
func (s *UsageStore) CheckWrite(account string, q Quota, deltaBytes int64, now, periodEnd time.Time) error {
	if q.StorageBytes <= 0 || deltaBytes <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.ensureLocked(account, now, periodEnd)
	if u.StorageBytes+deltaBytes > q.StorageBytes {
		return errStorage()
	}
	return nil
}

// AddStorage increases the stored-bytes counter after a successful write.
func (s *UsageStore) AddStorage(account string, deltaBytes int64, now, periodEnd time.Time) error {
	if deltaBytes == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.ensureLocked(account, now, periodEnd)
	u.StorageBytes += deltaBytes
	if u.StorageBytes < 0 {
		u.StorageBytes = 0
	}
	u.Updated = now.UTC()
	s.Usage[account] = u
	return s.saveLocked()
}

// CheckTraffic refuses when the account is already at or over its monthly traffic cap.
func (s *UsageStore) CheckTraffic(account string, q Quota, now, periodEnd time.Time) error {
	if q.TrafficBytes <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.ensureLocked(account, now, periodEnd)
	if u.TrafficBytes >= q.TrafficBytes {
		return errTraffic()
	}
	return nil
}

// AddTraffic meters request+response bytes after a request is allowed through.
func (s *UsageStore) AddTraffic(account string, q Quota, bytes int64, now, periodEnd time.Time) error {
	if bytes <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.ensureLocked(account, now, periodEnd)
	u.TrafficBytes += bytes
	u.Updated = now.UTC()
	s.Usage[account] = u
	_ = q
	return s.saveLocked()
}

// TryHostSwitch counts one on↔off against the monthly budget when the desired
// state differs from the last known HostedOn. A no-op (already in that state) is free.
func (s *UsageStore) TryHostSwitch(account string, q Quota, wantOn bool, now, periodEnd time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.ensureLocked(account, now, periodEnd)
	if u.HostedOn == wantOn {
		return nil
	}
	if q.HostSwitches != UnlimitedSwitches && u.HostSwitches >= q.HostSwitches {
		return errSwitches()
	}
	u.HostSwitches++
	u.HostedOn = wantOn
	u.Updated = now.UTC()
	s.Usage[account] = u
	return s.saveLocked()
}

// ForceHostSwitch always consumes one switch (create/drop), even if HostedOn is unchanged.
func (s *UsageStore) ForceHostSwitch(account string, q Quota, now, periodEnd time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.ensureLocked(account, now, periodEnd)
	if q.HostSwitches != UnlimitedSwitches && u.HostSwitches >= q.HostSwitches {
		return errSwitches()
	}
	u.HostSwitches++
	u.Updated = now.UTC()
	s.Usage[account] = u
	return s.saveLocked()
}

// Get returns a copy of stored usage (after ensuring the cycle window).
func (s *UsageStore) Get(account string, now, periodEnd time.Time) Usage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ensureLocked(account, now, periodEnd)
}

// Clear removes usage for tests.
func (s *UsageStore) Clear(account string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.Usage, account)
	_ = s.saveLocked()
}

// ErrNoUsage is reserved for callers that require a row.
var ErrNoUsage = errors.New("no usage")
