package host

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	updateMaxErrorRate = 0.05
	updateMaxP95MS     = 2000
)

// Health is the live signal a rollout watches. error_rate is 0..1.
type Health struct {
	ErrorRate float64 `json:"error_rate"`
	P95MS     float64 `json:"p95_ms"`
}

type nodeVer struct {
	Version  string `json:"version"`
	Sequence int64  `json:"sequence"`
	Source   string `json:"source"`
}

type appState struct {
	Hosted     bool               `json:"hosted"`
	SourcePref string             `json:"source_pref,omitempty"`
	Policy     updatePolicy       `json:"policy"`
	Nodes      map[string]nodeVer `json:"nodes,omitempty"`
	LastSeq    int64              `json:"last_seq"`
	GitHubRepo string             `json:"github_repo,omitempty"`
}

type updatePolicy struct {
	AutoApply string `json:"auto_apply"`
	Channel   string `json:"channel"`
	Window    string `json:"window,omitempty"`
}

type storedManifest struct {
	Body []byte `json:"body"`
	Sig  string `json:"sig"`
}

type snapMeta struct {
	ID        string    `json:"id"`
	App       string    `json:"app"`
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	Offset    uint64    `json:"offset"`
	Path      string    `json:"path"`
}

type rollout struct {
	ID          string             `json:"id"`
	App         string             `json:"app"`
	Version     string             `json:"version"`
	Source      string             `json:"source"`
	Strategy    string             `json:"strategy"`
	Effective   string             `json:"effective"`
	State       string             `json:"state"`
	SnapshotID  string             `json:"snapshot_id"`
	SnapshotOff uint64             `json:"snapshot_off"`
	Created     time.Time          `json:"created"`
	CanaryPct   int                `json:"canary_percent"`
	MinMinutes  int                `json:"min_minutes"`
	CanarySince time.Time          `json:"canary_since,omitempty"`
	ScheduleAt  *time.Time         `json:"schedule_at,omitempty"`
	DryRun      bool               `json:"dry_run"`
	Updated     []string           `json:"updated,omitempty"`
	Total       int                `json:"total"`
	PrevNodes   map[string]nodeVer `json:"prev_nodes,omitempty"`
	Reason      string             `json:"reason,omitempty"`
	TargetSeq   int64              `json:"target_seq"`
}

type historyItem struct {
	Kind       string    `json:"kind"`
	At         time.Time `json:"at"`
	App        string    `json:"app"`
	Version    string    `json:"version,omitempty"`
	Source     string    `json:"source,omitempty"`
	Sequence   int64     `json:"sequence,omitempty"`
	SnapshotID string    `json:"snapshot_id,omitempty"`
	RolloutID  string    `json:"rollout_id,omitempty"`
	Outcome    *Outcome  `json:"outcome,omitempty"`
	Reason     string    `json:"reason,omitempty"`
}

type diskState struct {
	Apps       map[string]*appState       `json:"apps"`
	Manifests  map[string]*storedManifest `json:"manifests"` // app|version|source
	Snaps      map[string]*snapMeta       `json:"snapshots"`
	Rollouts   map[string]*rollout        `json:"rollouts"`
	History    []historyItem              `json:"history"`
	Blobs      map[string]string          `json:"blobs"`                // app|version|source|id -> relative path
	Deliveries map[string]int64           `json:"deliveries,omitempty"` // X-GitHub-Delivery -> unix nano
}

// updatePermit is a single-use confirmation issued by a plan or dry-run call.
type updatePermit struct {
	Action     string
	App        string
	Version    string
	Source     string
	SnapshotID string
	RolloutID  string
	Expires    time.Time
}

// healthView is what a rollout reports. Rates are nil when status is unknown.
type healthView struct {
	Status    string   `json:"status"`
	ErrorRate *float64 `json:"error_rate"`
	P95MS     *float64 `json:"p95_ms"`
	LiveNodes int      `json:"live_nodes,omitempty"`
	Nodes     int      `json:"nodes,omitempty"`
}

type updater struct {
	h        *Host
	mu       sync.Mutex
	st       diskState
	dir      string
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
	kid      string
	notAfter time.Time

	members       []string
	health        Health
	healthSet     bool
	snapFail      bool
	githubAPI     string
	allowLoopback bool
	permits       map[string]updatePermit
	permitTTL     time.Duration
	subs          map[int]chan UpdateEvent
	subN          int
}

func manifestKey(app, version, source string) string {
	return app + "|" + version + "|" + source
}

func blobKey(app, version, source, id string) string {
	return app + "|" + version + "|" + source + "|" + id
}

func openUpdater(h *Host) (*updater, error) {
	dir := filepath.Join(h.Cfg.DataDir, "updates")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	priv, notAfter, err := loadSigningKey(h, dir)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	u := &updater{
		h: h, dir: dir, priv: priv, pub: pub, notAfter: notAfter,
		kid: hex.EncodeToString(sum[:8]),
		st: diskState{
			Apps: map[string]*appState{}, Manifests: map[string]*storedManifest{},
			Snaps: map[string]*snapMeta{}, Rollouts: map[string]*rollout{},
			Blobs: map[string]string{},
		},
		subs: map[int]chan UpdateEvent{}, permits: map[string]updatePermit{},
	}
	if b, err := os.ReadFile(filepath.Join(dir, "state.json")); err == nil && len(b) > 0 {
		if err := json.Unmarshal(b, &u.st); err != nil {
			return nil, fmt.Errorf("updates state: %w", err)
		}
	}
	if u.st.Apps == nil {
		u.st.Apps = map[string]*appState{}
	}
	if u.st.Manifests == nil {
		u.st.Manifests = map[string]*storedManifest{}
	}
	if u.st.Snaps == nil {
		u.st.Snaps = map[string]*snapMeta{}
	}
	if u.st.Rollouts == nil {
		u.st.Rollouts = map[string]*rollout{}
	}
	if u.st.Blobs == nil {
		u.st.Blobs = map[string]string{}
	}
	if u.st.Deliveries == nil {
		u.st.Deliveries = map[string]int64{}
	}
	changed := false
	for _, ro := range u.st.Rollouts {
		if ro.State == "snapshotting" {
			ro.State = "failed"
			ro.Reason = "interrupted"
			changed = true
		}
	}
	for _, name := range h.Cfg.HostedApps {
		name = strings.TrimSpace(name)
		if !validAppID(name) {
			continue
		}
		a := u.appLocked(name)
		if !a.Hosted {
			a.Hosted = true
			changed = true
		}
	}
	if changed {
		if err := u.saveLocked(); err != nil {
			return nil, err
		}
	}
	return u, nil
}

func (u *updater) appLocked(name string) *appState {
	a := u.st.Apps[name]
	if a == nil {
		a = &appState{Policy: updatePolicy{AutoApply: "off", Channel: "stable"}}
		u.st.Apps[name] = a
	}
	if a.Policy.AutoApply == "" {
		a.Policy.AutoApply = "off"
	}
	if a.Policy.Channel == "" {
		a.Policy.Channel = "stable"
	}
	if a.Nodes == nil {
		a.Nodes = map[string]nodeVer{}
	}
	return a
}

func (u *updater) saveLocked() error {
	b, err := json.MarshalIndent(&u.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(u.dir, "state.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(u.dir, "state.json"))
}

func (u *updater) publicKeys() (kid, pub string, notAfter time.Time) {
	return u.kid, base64.StdEncoding.EncodeToString(u.pub), u.notAfter
}

func (u *updater) verify(body []byte, sig string) error {
	return verifyManifestBytes(u.pub, body, sig)
}

func loadSigningKey(h *Host, dir string) (ed25519.PrivateKey, time.Time, error) {
	if s := strings.TrimSpace(os.Getenv("REDX_UPDATE_SIGNING_KEY")); s != "" {
		k, err := parseSigningKey(s)
		if err != nil {
			return nil, time.Time{}, err
		}
		return k, time.Now().UTC().AddDate(10, 0, 0).Truncate(time.Second), nil
	}
	path := h.Cfg.UpdateSigningKeyFile
	if path == "" {
		path = os.Getenv("REDX_UPDATE_SIGNING_KEY_FILE")
	}
	if path != "" {
		return readSigningKeyFile(path, true)
	}
	path = filepath.Join(dir, "signing.key")
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		return readSigningKeyFile(path, true)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, time.Time{}, err
	}
	notAfter := time.Now().UTC().AddDate(10, 0, 0).Truncate(time.Second)
	seed := priv.Seed()
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(seed)+"\n"), 0o600); err != nil {
		return nil, time.Time{}, err
	}
	meta, _ := json.Marshal(map[string]string{"not_after": notAfter.Format(time.RFC3339)})
	_ = os.WriteFile(path+".meta", meta, 0o600)
	return priv, notAfter, nil
}

func readSigningKeyFile(path string, checkMode bool) (ed25519.PrivateKey, time.Time, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	if checkMode && os.PathSeparator == '/' && st.Mode().Perm()&0o077 != 0 {
		return nil, time.Time{}, fmt.Errorf("update signing key file %s has mode %04o: it must not be readable by group or others (chmod 600)", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	k, err := parseSigningKey(string(b))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("update signing key file: %w", err)
	}
	notAfter := time.Now().UTC().AddDate(10, 0, 0).Truncate(time.Second)
	if mb, err := os.ReadFile(path + ".meta"); err == nil {
		var m struct {
			NotAfter string `json:"not_after"`
		}
		if json.Unmarshal(mb, &m) == nil && m.NotAfter != "" {
			if t, err := time.Parse(time.RFC3339, m.NotAfter); err == nil {
				notAfter = t.UTC()
			}
		}
	}
	return k, notAfter, nil
}

func parseSigningKey(s string) (ed25519.PrivateKey, error) {
	s = strings.TrimSpace(s)
	var raw []byte
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		raw = b
	} else if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		raw = b
	} else if b, err := hex.DecodeString(s); err == nil {
		raw = b
	} else {
		return nil, errors.New("could not decode the signing key")
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, errors.New("signing key must be 32 or 64 bytes")
	}
}

func (u *updater) membersOf() []string {
	u.mu.Lock()
	inj := append([]string(nil), u.members...)
	u.mu.Unlock()
	if len(inj) > 0 {
		sort.Strings(inj)
		return inj
	}
	st := u.h.Cluster.Status()
	ids := make([]string, 0, len(st.Members))
	for _, m := range st.Members {
		if m.ID != "" {
			ids = append(ids, m.ID)
		}
	}
	if len(ids) == 0 && u.h.NodeID != "" {
		ids = []string{u.h.NodeID}
	}
	sort.Strings(ids)
	return ids
}

func canaryCount(n, percent int) int {
	if n <= 1 {
		return n
	}
	if percent < 1 {
		percent = 1
	}
	if percent > 100 {
		percent = 100
	}
	k := int(math.Ceil(float64(n) * float64(percent) / 100.0))
	if k < 1 {
		k = 1
	}
	if percent < 100 && k >= n {
		k = n - 1
	}
	return k
}

func blueGreenCount(n int) int {
	if n <= 1 {
		return n
	}
	k := (n + 1) / 2
	if k >= n {
		k = n - 1
	}
	return k
}

func (u *updater) sourcePref(a *appState) string {
	if a.SourcePref != "" {
		return a.SourcePref
	}
	if a.Hosted {
		return "both"
	}
	return "github"
}

func (u *updater) emit(ev UpdateEvent) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, ch := range u.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (u *updater) subscribe() (<-chan UpdateEvent, func()) {
	u.mu.Lock()
	defer u.mu.Unlock()
	id := u.subN
	u.subN++
	ch := make(chan UpdateEvent, 32)
	u.subs[id] = ch
	return ch, func() {
		u.mu.Lock()
		delete(u.subs, id)
		u.mu.Unlock()
	}
}

// putManifest signs a manifest. Sequence is bound to (app, version): the same version
// keeps the sequence it was first signed with, and a new version is accepted only when
// it is strictly newer (semver) than every version already signed. created is false when
// this source already had an immutable manifest.
func (u *updater) putManifest(m *Manifest) (body []byte, sig string, created bool, err error) {
	if m.Schema == "" {
		m.Schema = updateManifestSchema
	}
	if m.Schema != updateManifestSchema {
		return nil, "", false, errors.New("unknown manifest schema")
	}
	if !validAppID(m.App) || !validVersion(m.Version) {
		return nil, "", false, errors.New("invalid app or version")
	}
	if _, ok := parseSemver(m.Version); !ok {
		return nil, "", false, errors.New("version must be semver")
	}
	switch m.Channel {
	case "stable", "beta", "security":
	default:
		return nil, "", false, errors.New("channel must be stable, beta or security")
	}
	switch m.Source.Kind {
	case "host", "github":
	default:
		return nil, "", false, errors.New("source.kind must be host or github")
	}
	if err := validateOutcomeTags(m.Outcome.Tags); err != nil {
		return nil, "", false, err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	a := u.appLocked(m.App)
	key := manifestKey(m.App, m.Version, m.Source.Kind)
	if sm := u.st.Manifests[key]; sm != nil {
		return sm.Body, sm.Sig, false, nil
	}
	if seq, ok := u.seqForVersionLocked(m.App, m.Version); ok {
		m.Sequence = seq
	} else {
		if err := u.newerThanAllLocked(m.App, m.Version); err != nil {
			return nil, "", false, err
		}
		m.Sequence = a.LastSeq + 1
		if m.Sequence < 1 {
			m.Sequence = 1
		}
		a.LastSeq = m.Sequence
	}
	body, err = marshalManifest(m)
	if err != nil {
		return nil, "", false, err
	}
	sig = signManifestBytes(u.priv, body)
	u.st.Manifests[key] = &storedManifest{Body: body, Sig: sig}
	u.addHistoryLocked(historyItem{Kind: "publish", At: time.Now().UTC(), App: m.App, Version: m.Version, Source: m.Source.Kind, Sequence: m.Sequence, Outcome: &m.Outcome})
	if err := u.saveLocked(); err != nil {
		return nil, "", false, err
	}
	return body, sig, true, nil
}

func (u *updater) seqForVersionLocked(app, version string) (int64, bool) {
	for key, sm := range u.st.Manifests {
		if sm == nil || !strings.HasPrefix(key, app+"|"+version+"|") {
			continue
		}
		var m Manifest
		if json.Unmarshal(sm.Body, &m) != nil || m.Version != version {
			continue
		}
		if m.Sequence > 0 {
			return m.Sequence, true
		}
	}
	return 0, false
}

func (u *updater) newerThanAllLocked(app, version string) error {
	for key, sm := range u.st.Manifests {
		if sm == nil || !strings.HasPrefix(key, app+"|") {
			continue
		}
		var m Manifest
		if json.Unmarshal(sm.Body, &m) != nil || m.App != app {
			continue
		}
		cmp, ok := semverCmp(version, m.Version)
		if !ok || cmp <= 0 {
			return errDowngrade
		}
	}
	return nil
}

func (u *updater) installedVersionLocked(app string) string {
	a := u.st.Apps[app]
	if a == nil {
		return ""
	}
	return a.Nodes[u.h.NodeID].Version
}

func (u *updater) hasVersionLocked(app, version string) bool {
	_, ok := u.seqForVersionLocked(app, version)
	return ok
}

var (
	errSeq       = errors.New("sequence regression")
	errDowngrade = errors.New("version is lower than one already signed")
	errMinFrom   = errors.New("installed version is below min_from")
	errConfirm   = errors.New("update confirmation required")
	errSkip      = errors.New("skipped")
	errRepo      = errors.New("repository is not allowlisted for this app")
	errReplay    = errors.New("replayed github delivery")
)

const updatePermitTTL = 2 * time.Minute

func (u *updater) issuePermit(p updatePermit) (string, time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.permits == nil {
		u.permits = map[string]updatePermit{}
	}
	now := time.Now()
	for id, cur := range u.permits {
		if now.After(cur.Expires) {
			delete(u.permits, id)
		}
	}
	ttl := u.permitTTL
	if ttl <= 0 {
		ttl = updatePermitTTL
	}
	p.Expires = now.Add(ttl)
	id := newUpdateID("uc_")
	u.permits[id] = p
	return id, p.Expires
}

func (u *updater) consumePermit(id string, want updatePermit) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	p, ok := u.permits[id]
	if !ok || time.Now().After(p.Expires) {
		delete(u.permits, id)
		return errConfirm
	}
	if p.Action != want.Action || p.App != want.App || p.Version != want.Version {
		return errConfirm
	}
	if p.Source != "" && want.Source != "" && p.Source != want.Source {
		return errConfirm
	}
	if p.SnapshotID != "" && p.SnapshotID != want.SnapshotID {
		return errConfirm
	}
	if p.RolloutID != "" && p.RolloutID != want.RolloutID {
		return errConfirm
	}
	delete(u.permits, id)
	return nil
}

func (u *updater) claimDelivery(id string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.st.Deliveries == nil {
		u.st.Deliveries = map[string]int64{}
	}
	if _, ok := u.st.Deliveries[id]; ok {
		return false
	}
	now := time.Now().UnixNano()
	u.st.Deliveries[id] = now
	if len(u.st.Deliveries) > 2048 {
		var oldest string
		var when int64
		for k, v := range u.st.Deliveries {
			if oldest == "" || v < when {
				oldest, when = k, v
			}
		}
		delete(u.st.Deliveries, oldest)
	}
	_ = u.saveLocked()
	return true
}

func (u *updater) releaseDelivery(id string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.st.Deliveries, id)
	_ = u.saveLocked()
}

func (u *updater) measureHealth() healthView {
	u.mu.Lock()
	forced := u.healthSet
	h := u.health
	u.mu.Unlock()
	if forced {
		view := healthView{Status: "ok", ErrorRate: &h.ErrorRate, P95MS: &h.P95MS}
		if h.ErrorRate > updateMaxErrorRate || h.P95MS > updateMaxP95MS {
			view.Status = "bad"
		}
		return view
	}
	if u.h == nil {
		return healthView{Status: "unknown"}
	}
	return u.h.liveHealth()
}

func (u *updater) nextSequence(app string) int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.appLocked(app).LastSeq + 1
}

func (u *updater) loadManifest(app, version, source string) (*Manifest, []byte, string, error) {
	u.mu.Lock()
	sm := u.st.Manifests[manifestKey(app, version, source)]
	u.mu.Unlock()
	if sm == nil {
		return nil, nil, "", os.ErrNotExist
	}
	if err := u.verify(sm.Body, sm.Sig); err != nil {
		return nil, nil, "", errBadSig
	}
	var m Manifest
	if err := json.Unmarshal(sm.Body, &m); err != nil {
		return nil, nil, "", err
	}
	return &m, sm.Body, sm.Sig, nil
}

var errBadSig = errors.New("bad signature")

func (u *updater) chooseSource(app, version, want string) (string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	has := func(s string) bool { return u.st.Manifests[manifestKey(app, version, s)] != nil }
	switch want {
	case "host", "github":
		if !has(want) {
			return "", os.ErrNotExist
		}
		return want, nil
	case "":
		h, g := has("host"), has("github")
		switch {
		case h && g:
			pref := u.sourcePref(u.appLocked(app))
			if pref == "github" {
				return "github", nil
			}
			if pref == "host" || pref == "both" {
				if h {
					return "host", nil
				}
			}
			return "host", nil
		case h:
			return "host", nil
		case g:
			return "github", nil
		default:
			return "", os.ErrNotExist
		}
	default:
		return "", errors.New("source must be host or github")
	}
}

func (u *updater) addHistoryLocked(it historyItem) {
	u.st.History = append(u.st.History, it)
	if len(u.st.History) > 500 {
		u.st.History = u.st.History[len(u.st.History)-500:]
	}
}

func (u *updater) activeRollout(app string) *rollout {
	for _, ro := range u.st.Rollouts {
		if ro.App != app {
			continue
		}
		switch ro.State {
		case "scheduled", "snapshotting", "canary", "promoting":
			return ro
		}
	}
	return nil
}
