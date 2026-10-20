package host

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"redx/billing"
)

// Hosted apps are tenant sites and processes on this machine. They are not the
// update-system app ids (those share the database namespace). Files live under
// <data>/hosted and never inside a customer database.

const (
	appsZoneDefault    = "host.rottenapplestore.org"
	appsSeccompDefault = "/usr/share/containers/seccomp.json"
	appsNetworkDefault = "pasta"
	appsRedXURLDefault = "http://host.containers.internal:7777"
	appsListenPort     = 8080
	appsSecretMask     = "••••••••"
	appsClaimTTL       = 7 * 24 * time.Hour
	appsMaxFiles       = 10000
	appsEnvMax         = 64
	appsSecretMax      = 32 << 10
)

// AppLimit is the per-tier ceiling for hosted apps. Zero fields in an override
// keep the built-in value. Storage across apps still counts toward the plan's
// storage quota; DiskMB is the per-app ceiling.
type AppLimit struct {
	MaxApps  int     `toml:"max_apps" json:"maxApps"`
	CPU      float64 `toml:"cpu" json:"cpu"`
	MemoryMB int     `toml:"memory_mb" json:"memoryMB"`
	DiskMB   int     `toml:"disk_mb" json:"diskMB"`
	LogDays  int     `toml:"log_days" json:"logDays"`
	Pids     int     `toml:"pids" json:"pids"`
	Domains  int     `toml:"domains" json:"domains"`
}

func builtinAppLimit(tier string) (AppLimit, bool) {
	switch tier {
	case "basic":
		return AppLimit{MaxApps: 1, CPU: 0.25, MemoryMB: 256, DiskMB: 512, LogDays: 1, Pids: 64, Domains: 1}, true
	case "bronze":
		return AppLimit{MaxApps: 2, CPU: 0.5, MemoryMB: 512, DiskMB: 2048, LogDays: 3, Pids: 128, Domains: 2}, true
	case "silver":
		return AppLimit{MaxApps: 4, CPU: 1, MemoryMB: 1024, DiskMB: 8192, LogDays: 7, Pids: 256, Domains: 4}, true
	case "gold":
		return AppLimit{MaxApps: 8, CPU: 2, MemoryMB: 2048, DiskMB: 20480, LogDays: 14, Pids: 512, Domains: 8}, true
	case "platinum":
		return AppLimit{MaxApps: 16, CPU: 4, MemoryMB: 4096, DiskMB: 40960, LogDays: 30, Pids: 1024, Domains: 16}, true
	case "emerald":
		return AppLimit{MaxApps: 32, CPU: 8, MemoryMB: 8192, DiskMB: 102400, LogDays: 90, Pids: 2048, Domains: 32}, true
	default:
		return AppLimit{}, false
	}
}

func mergeLimit(base, over AppLimit) AppLimit {
	if over.MaxApps != 0 {
		base.MaxApps = over.MaxApps
	}
	if over.CPU != 0 {
		base.CPU = over.CPU
	}
	if over.MemoryMB != 0 {
		base.MemoryMB = over.MemoryMB
	}
	if over.DiskMB != 0 {
		base.DiskMB = over.DiskMB
	}
	if over.LogDays != 0 {
		base.LogDays = over.LogDays
	}
	if over.Pids != 0 {
		base.Pids = over.Pids
	}
	if over.Domains != 0 {
		base.Domains = over.Domains
	}
	return base
}

func (c *Config) applyAppLimits(raw string) error {
	var m map[string]AppLimit
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return fmt.Errorf("REDX_APPS_LIMITS: %w", err)
	}
	if c.AppsLimits == nil {
		c.AppsLimits = map[string]AppLimit{}
	}
	for k, v := range m {
		c.AppsLimits[k] = mergeLimit(c.AppsLimits[k], v)
	}
	return nil
}

func (h *Host) appLimitFor(tier string) AppLimit {
	base, ok := builtinAppLimit(tier)
	if !ok {
		base, _ = builtinAppLimit("basic")
	}
	if h != nil && h.Cfg.AppsLimits != nil {
		if over, ok := h.Cfg.AppsLimits[tier]; ok {
			base = mergeLimit(base, over)
		}
	}
	return base
}

func (h *Host) appLimit(pr *Principal) AppLimit {
	if pr != nil {
		if sub := pr.tenantSub(); sub != "" && h.billing != nil {
			if p, ok := h.billing.StoredPlan(sub); ok && p.Tier != "" {
				return h.appLimitFor(p.Tier)
			}
		}
	}
	return h.appLimitFor("emerald")
}

func errAppQuota(max int) error {
	return &billing.ErrQuota{Code: "app_quota", HTTP: 402,
		Message: fmt.Sprintf("This plan allows %d hosted app(s). Upgrade your plan at /ui/billing.html.", max)}
}

func errAppDisk() error {
	return &billing.ErrQuota{Code: "app_disk_quota", HTTP: 402,
		Message: "This deploy would go past the per-app disk limit for your plan. Upgrade your plan at /ui/billing.html."}
}

func errDomainQuota(max int) error {
	return &billing.ErrQuota{Code: "domain_quota", HTTP: 402,
		Message: fmt.Sprintf("This plan allows %d custom domain(s). Upgrade your plan at /ui/billing.html.", max)}
}

type hostedSecret struct {
	Name    string    `json:"name"`
	Nonce   []byte    `json:"nonce"`
	CT      []byte    `json:"ct"`
	Updated time.Time `json:"updated"`
}

type hostedDomain struct {
	Name       string    `json:"name"`
	Kind       string    `json:"kind"` // default | custom
	Verified   bool      `json:"verified"`
	Method     string    `json:"method,omitempty"` // txt | cname | http
	Token      string    `json:"token,omitempty"`
	Added      time.Time `json:"added"`
	VerifiedAt time.Time `json:"verifiedAt,omitempty"`
}

type hostedSnap struct {
	ID       string    `json:"id"`
	DeployID string    `json:"deployId"`
	Version  string    `json:"version"`
	Created  time.Time `json:"created"`
	SHA256   string    `json:"sha256"`
	Size     int64     `json:"size"`
}

type hostedDeploy struct {
	ID         string    `json:"id"`
	Version    string    `json:"version"`
	Sequence   int64     `json:"sequence"`
	Created    time.Time `json:"created"`
	Source     string    `json:"source"`
	Strategy   string    `json:"strategy"`
	Status     string    `json:"status"`
	Image      string    `json:"image,omitempty"`
	Repo       string    `json:"repo,omitempty"`
	Ref        string    `json:"ref,omitempty"`
	SHA256     string    `json:"sha256,omitempty"`
	SnapshotID string    `json:"snapshotId,omitempty"`
	Manifest   []byte    `json:"manifest,omitempty"`
	Signature  string    `json:"signature,omitempty"`
	Runtime    string    `json:"runtime,omitempty"`
	Error      string    `json:"error,omitempty"`
	CanaryPct  int       `json:"canaryPct,omitempty"`
	Command    []string  `json:"command,omitempty"`
	Dockerfile string    `json:"dockerfile,omitempty"`
}

type hostedApp struct {
	ID            string            `json:"id"`
	Account       string            `json:"account"`
	Name          string            `json:"name"`
	Kind          string            `json:"kind"`
	DB            string            `json:"db,omitempty"`
	DBLogical     string            `json:"dbLogical,omitempty"`
	DBKeyID       string            `json:"dbKeyId,omitempty"`
	Created       time.Time         `json:"created"`
	Updated       time.Time         `json:"updated"`
	Running       bool              `json:"running"`
	HostPort      int               `json:"hostPort"`
	UID           int               `json:"uid,omitempty"`
	Health        string            `json:"health,omitempty"`
	NeedsRedeploy bool              `json:"needsRedeploy,omitempty"`
	Current       string            `json:"current,omitempty"`
	Canary        string            `json:"canary,omitempty"`
	CanaryPct     int               `json:"canaryPct,omitempty"`
	Standby       string            `json:"standby,omitempty"`
	Env           map[string]string `json:"env,omitempty"`
	Secrets       []hostedSecret    `json:"secrets,omitempty"`
	Domains       []hostedDomain    `json:"domains"`
	Deploys       []hostedDeploy    `json:"deploys"`
	Snaps         []hostedSnap      `json:"snaps"`
	Seq           int64             `json:"seq"`
}

type hostedFile struct {
	NextPort int                   `json:"nextPort"`
	Apps     map[string]*hostedApp `json:"apps"`
}

type appStore struct {
	mu        sync.Mutex
	path      string
	root      string
	zone      string
	basePort  int
	seccomp   string
	network   string
	redxURL   string
	runtime   string
	podmanBin string
	publicIP  string
	apply     bool
	uidBase   int
	uidSpan   int
	nextPort  int
	key       []byte
	apps      map[string]*hostedApp
	fetch     func(repo, ref string) ([]byte, error)
	txt       func(name string) ([]string, error)
	cname     func(name string) (string, error)
	httpGet   func(rawURL string) (int, string, error)
	probe     func(id string) (string, string)
}

func openApps(h *Host) (*appStore, error) {
	root := filepath.Join(h.Cfg.DataDir, "hosted")
	if err := os.MkdirAll(filepath.Join(root, "apps"), 0o700); err != nil {
		return nil, err
	}
	key, err := loadAppsKey(h.Cfg, root)
	if err != nil {
		return nil, err
	}
	s := &appStore{
		path: filepath.Join(root, "apps.json"), root: root, key: key,
		zone: h.Cfg.AppsHost, basePort: h.Cfg.AppsBasePort, seccomp: h.Cfg.AppsSeccomp,
		network: h.Cfg.AppsNetwork, redxURL: h.Cfg.AppsRedXURL, runtime: h.Cfg.AppsRuntime,
		podmanBin: h.Cfg.AppsPodmanBin, publicIP: h.Cfg.AppsPublicIP,
		uidBase: h.Cfg.AppsUIDBase, uidSpan: h.Cfg.AppsUIDSpan,
		apply: h.Cfg.AppsRuntime == "podman" && os.Getenv("REDX_APPS_APPLY") != "0",
		apps:  map[string]*hostedApp{},
	}
	if s.podmanBin == "" {
		s.podmanBin = "podman"
	}
	b, err := os.ReadFile(s.path)
	if err == nil && len(bytes.TrimSpace(b)) > 0 {
		var f hostedFile
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("hosted apps: %w", err)
		}
		if f.Apps != nil {
			s.apps = f.Apps
		}
		s.nextPort = f.NextPort
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if s.nextPort < s.basePort {
		s.nextPort = s.basePort
	}
	return s, nil
}

func loadAppsKey(cfg Config, root string) ([]byte, error) {
	if v := strings.TrimSpace(os.Getenv("REDX_APPS_SECRET_KEY")); v != "" {
		k, err := decodeAppsKey(v)
		if err != nil {
			return nil, fmt.Errorf("REDX_APPS_SECRET_KEY: %w", err)
		}
		return k, nil
	}
	path := cfg.AppsSecretKeyFile
	if path == "" {
		path = filepath.Join(root, "secret.key")
	}
	if b, err := os.ReadFile(path); err == nil {
		k, err := decodeAppsKey(string(b))
		if err != nil {
			return nil, fmt.Errorf("apps secret key: %w", err)
		}
		return k, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	enc := base64.StdEncoding.EncodeToString(buf)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(enc+"\n"), 0o600); err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	return buf, nil
}

func decodeAppsKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, errors.New("want 32 bytes, base64 or hex")
}

func (s *appStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(hostedFile{NextPort: s.nextPort, Apps: s.apps}, "", " ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *appStore) seal(account, appID, name string, plain []byte) (hostedSecret, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return hostedSecret{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return hostedSecret{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return hostedSecret{}, err
	}
	aad := appsAAD(account, appID, name)
	ct := gcm.Seal(nil, nonce, plain, aad)
	return hostedSecret{Name: name, Nonce: nonce, CT: ct, Updated: time.Now().UTC()}, nil
}

func (s *appStore) open(account, appID string, sec hostedSecret) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sec.Nonce) != gcm.NonceSize() {
		return nil, errors.New("bad secret")
	}
	return gcm.Open(nil, sec.Nonce, sec.CT, appsAAD(account, appID, sec.Name))
}

func appsAAD(account, appID, name string) []byte {
	return []byte("redx-hosted-secret/v1\x00" + account + "\x00" + appID + "\x00" + name)
}

func validAppName(name string) bool {
	if len(name) < 1 || len(name) > 40 {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' && i > 0 && i < len(name)-1:
		default:
			return false
		}
	}
	return true
}

func validEnvName(name string) bool {
	if len(name) < 1 || len(name) > 64 {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'A' && r <= 'Z', r == '_':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

func validImageRef(s string) bool {
	if len(s) < 1 || len(s) > 200 || strings.ContainsAny(s, " \t\r\n;|&$`'\"\\") {
		return false
	}
	return true
}

func validDockerfile(s string) bool {
	if s == "" || len(s) > 200 || strings.Contains(s, "..") || strings.ContainsAny(s, "\\") || strings.HasPrefix(s, "/") {
		return false
	}
	clean := path.Clean(s)
	return clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}

func validRepo(s string) bool {
	parts := strings.Split(s, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, p := range parts {
		if len(p) > 100 {
			return false
		}
		for _, r := range p {
			switch {
			case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			default:
				return false
			}
		}
	}
	return true
}

func validDomain(name, zone string) error {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" || len(name) > 253 || strings.Contains(name, "*") || net.ParseIP(name) != nil {
		return errors.New("invalid domain")
	}
	if strings.ContainsAny(name, " /\\@:") || strings.Contains(name, "..") {
		return errors.New("invalid domain")
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return errors.New("invalid domain")
	}
	for _, l := range labels {
		if len(l) < 1 || len(l) > 63 {
			return errors.New("invalid domain")
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return errors.New("invalid domain")
		}
		for _, r := range l {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			default:
				return errors.New("invalid domain")
			}
		}
	}
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	if name == zone || strings.HasSuffix(name, "."+zone) {
		return errors.New("that name is inside the hosting zone")
	}
	switch {
	case name == "localhost", strings.HasSuffix(name, ".localhost"), strings.HasSuffix(name, ".local"), strings.HasSuffix(name, ".internal"):
		return errors.New("invalid domain")
	}
	return nil
}

func tenantHostLabel(account string) string {
	if account == "" {
		account = "operator"
	}
	sum := sha256.Sum256([]byte("redx-tenant/v1\x00" + account))
	return hex.EncodeToString(sum[:5])
}

func defaultAppHost(name, account, zone string) string {
	return name + "-" + tenantHostLabel(account) + "." + zone
}

func (s *appStore) diskOf(account string) int64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for _, a := range s.apps {
		if account == "" || a.Account == account {
			n += dirBytes(filepath.Join(s.root, "apps", a.ID))
		}
	}
	return n
}

func (s *appStore) allocUID(account string) int {
	used := map[int]string{}
	for _, a := range s.apps {
		if a.UID != 0 {
			used[a.UID] = a.Account
		}
	}
	id := tenantUnixID(account, s.uidBase, s.uidSpan)
	for step := 0; step < 64; step++ {
		owner := used[id]
		if owner == "" || owner == account {
			return id
		}
		id++
	}
	return id
}

func (s *appStore) count(account string) int {
	n := 0
	for _, a := range s.apps {
		if a.Account == account {
			n++
		}
	}
	return n
}

func (s *appStore) byName(account, name string) *hostedApp {
	for _, a := range s.apps {
		if a.Account == account && a.Name == name {
			return a
		}
	}
	return nil
}

func (s *appStore) domainOwner(name string) (appID string, d hostedDomain, ok bool) {
	name = strings.ToLower(name)
	for _, a := range s.apps {
		for _, dom := range a.Domains {
			if dom.Name == name {
				return a.ID, dom, true
			}
		}
	}
	return "", hostedDomain{}, false
}

func (a *hostedApp) deploy(id string) *hostedDeploy {
	for i := range a.Deploys {
		if a.Deploys[i].ID == id {
			return &a.Deploys[i]
		}
	}
	return nil
}

func (a *hostedApp) defaultDomain() string {
	for _, d := range a.Domains {
		if d.Kind == "default" {
			return d.Name
		}
	}
	return ""
}

// runtimeSpec is the sandbox redxd would hand to rootless podman.
// Args is the podman argv, without the binary. Secrets are not in Args.
type runtimeSpec struct {
	Engine       string   `json:"engine"`
	Rootless     bool     `json:"rootless"`
	Applied      bool     `json:"applied"`
	Network      string   `json:"network"`
	Seccomp      string   `json:"seccomp"`
	MemoryMB     int      `json:"memoryMB"`
	CPU          float64  `json:"cpu"`
	Pids         int      `json:"pids"`
	Publish      string   `json:"publish"`
	Volume       string   `json:"volume,omitempty"`
	Image        string   `json:"image,omitempty"`
	Command      []string `json:"command,omitempty"`
	Args         []string `json:"args"`
	BuildArgs    []string `json:"buildArgs,omitempty"`
	RunAs        []string `json:"runAs,omitempty"`
	UID          int      `json:"uid"`
	User         string   `json:"user"`
	CgroupParent string   `json:"cgroupParent"`
	DiskMB       int      `json:"diskMB"`
	Egress       string   `json:"egress"`
	Deny         []string `json:"deny"`
	Note         string   `json:"note,omitempty"`
}

type specInput struct {
	AppID     string
	DeployID  string
	Kind      string
	Image     string
	Command   []string
	HostPort  int
	Volume    string
	EnvFile   string
	Limit     AppLimit
	Seccomp   string
	Network   string
	BuildCtx  string
	BuildFile string
	Canary    bool
	UID       int
	User      string
	DiskMB    int
}

func podmanRunArgs(in specInput) (runtimeSpec, error) {
	if in.Network == "" {
		in.Network = appsNetworkDefault
	}
	if in.Network != "pasta" && in.Network != "slirp4netns" {
		return runtimeSpec{}, errors.New("network must be pasta or slirp4netns")
	}
	if in.Seccomp == "" {
		in.Seccomp = appsSeccompDefault
	}
	if strings.Contains(in.Seccomp, ",") || strings.ContainsAny(in.Seccomp, " \t") {
		return runtimeSpec{}, errors.New("bad seccomp path")
	}
	if in.Limit.MemoryMB <= 0 || in.Limit.CPU <= 0 || in.Limit.Pids <= 0 {
		return runtimeSpec{}, errors.New("bad limits")
	}
	image := in.Image
	if image == "" {
		image = "docker.io/library/caddy:2"
	}
	if !validImageRef(image) {
		return runtimeSpec{}, errors.New("invalid image")
	}
	cmd := in.Command
	if len(cmd) == 0 && (in.Kind == "static" || image == "docker.io/library/caddy:2") {
		cmd = []string{"caddy", "file-server", "--root", "/srv", "--listen", ":8080"}
	}
	port := in.HostPort
	if in.Canary {
		port++
	}
	publish := fmt.Sprintf("127.0.0.1:%d:%d", port, appsListenPort)
	netArg := sandboxNet(in.Network)
	user := in.User
	if user == "" {
		user = "rxapp-tenant"
	}
	if in.UID <= 0 {
		return runtimeSpec{}, errors.New("tenant uid is required")
	}
	cgroup := "redx-tenant-" + strings.TrimPrefix(user, "rxapp-") + ".slice"
	// The publish address is how Caddy reaches the app. It is not a route the
	// app can use to reach redxd: pasta does not map the host gateway, and the
	// tenant uid is denied to loopback and the host's own service ports.
	args := []string{
		"run", "--rm", "-d",
		"--name", containerName(in.AppID, in.Canary),
		"--userns=keep-id:uid=" + strconv.Itoa(in.UID) + ",gid=" + strconv.Itoa(in.UID),
		"--user", strconv.Itoa(in.UID) + ":" + strconv.Itoa(in.UID),
		"--cgroup-parent", cgroup,
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--security-opt=seccomp=" + in.Seccomp,
		"--read-only",
		"--pids-limit=" + strconv.Itoa(in.Limit.Pids),
		"--memory=" + strconv.Itoa(in.Limit.MemoryMB) + "m",
		"--cpus=" + strconv.FormatFloat(in.Limit.CPU, 'f', -1, 64),
		"--network=" + netArg,
		"-p", publish,
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
	}
	if in.DiskMB > 0 {
		args = append(args, "--storage-opt", "size="+strconv.Itoa(in.DiskMB)+"m")
	}
	if in.Volume != "" {
		args = append(args, "-v", in.Volume+":/srv:ro,Z")
	}
	if in.EnvFile != "" {
		args = append(args, "--env-file", in.EnvFile)
	}
	args = append(args, image)
	args = append(args, cmd...)
	spec := runtimeSpec{
		Engine: "podman", Rootless: true, Network: netArg, Seccomp: in.Seccomp,
		MemoryMB: in.Limit.MemoryMB, CPU: in.Limit.CPU, Pids: in.Limit.Pids,
		Publish: publish, Volume: in.Volume, Image: image, Command: append([]string(nil), cmd...),
		Args: args, RunAs: []string{"sudo", "-n", "-u", user, "--", "podman"},
		UID: in.UID, User: user, CgroupParent: cgroup, DiskMB: in.DiskMB,
		Egress: "internet", Deny: sandboxDeny(),
		Note: "one unprivileged uid per tenant, cgroup v2 limits, pasta without a host gateway, no route to redxd",
	}
	if in.BuildCtx != "" {
		file := in.BuildFile
		if file == "" {
			file = "Dockerfile"
		}
		tag := "localhost/redx-" + in.AppID + ":" + in.DeployID
		spec.Image = tag
		spec.BuildArgs = []string{"build", "-f", file, "-t", tag, in.BuildCtx}
		// The run image is the tag we just built, not a registry pull.
		for i := range spec.Args {
			if spec.Args[i] == image {
				spec.Args[i] = tag
				break
			}
		}
	}
	return spec, nil
}

func sandboxNet(network string) string {
	if network == "slirp4netns" {
		return "slirp4netns:allow_host_loopback=false"
	}
	return "pasta:--no-map-gw"
}

// sandboxDeny is the set the host firewall must reject for every tenant uid.
// 127.0.0.1 inside the container is the container itself. These entries are the
// host's loopback and the ports redxd, accounts, and ra-core use on this VPS.
func sandboxDeny() []string {
	return []string{
		"127.0.0.0/8",
		"::1",
		"169.254.0.0/16",
		"tcp/7777",
		"tcp/7780",
	}
}

func tenantUnixID(account string, base, span int) int {
	if base == 0 {
		base = 200000
	}
	if span <= 0 {
		span = 20000
	}
	sum := sha256.Sum256([]byte("redx-app-uid/v1\x00" + account))
	n := binary.BigEndian.Uint32(sum[:4]) % uint32(span)
	return base + int(n)
}

func tenantUnixUser(account string) string {
	return "rxapp-" + tenantHostLabel(account)
}

func containerName(appID string, canary bool) string {
	name := "redxha-" + strings.TrimPrefix(appID, "ha_")
	if canary {
		name += "-canary"
	}
	return name
}

func (h *Host) signHostedManifest(m *Manifest) ([]byte, string, error) {
	normalizeManifest(m)
	body, err := json.Marshal(m)
	if err != nil {
		return nil, "", err
	}
	if h.upd == nil || len(h.upd.priv) == 0 {
		return body, "", errors.New("no update signing key")
	}
	return body, signManifestBytes(h.upd.priv, body), nil
}

func buildHostedManifest(app *hostedApp, d *hostedDeploy, sha string) Manifest {
	src := ManifestSource{Kind: "host", Host: &HostOrigin{BuildID: d.ID}}
	if d.Source == "github" || d.Source == "dockerfile" {
		src = ManifestSource{Kind: "github", GitHub: &GitHubOrigin{Repo: d.Repo, Tag: d.Ref}}
	}
	arts := []Artifact{}
	if sha != "" {
		arts = append(arts, Artifact{
			ID: "release", Label: d.Source, Kind: d.Source, Filename: d.ID,
			SHA256: sha, Size: 0, Mirrors: []string{},
		})
	}
	return Manifest{
		Schema: updateManifestSchema, App: app.ID, Version: d.Version, Channel: "stable",
		PublishedAt: d.Created.UTC().Format(time.RFC3339), Sequence: d.Sequence,
		Source:    src,
		Outcome:   Outcome{Tags: []string{"capability"}, Summary: "Deploy " + app.Name + " from " + d.Source, ChangelogMD: ""},
		Requires:  Requires{Restart: true},
		Artifacts: arts,
	}
}

func extractArchive(b []byte, dest string, maxBytes int64) error {
	if len(b) < 4 {
		return errors.New("archive is empty")
	}
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}
	var err error
	switch {
	case b[0] == 0x1f && b[1] == 0x8b:
		err = extractTar(b, dest, maxBytes, true)
	case b[0] == 'P' && b[1] == 'K':
		err = extractZip(b, dest, maxBytes)
	default:
		err = extractTar(b, dest, maxBytes, false)
	}
	if err != nil {
		return err
	}
	return flattenSingleRoot(dest)
}

// flattenSingleRoot lifts a GitHub-style wrapper directory so index.html sits
// at the release root. A tree that already has files at the root is left alone.
func flattenSingleRoot(dest string) error {
	entries, err := os.ReadDir(dest)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		return err
	}
	sub := filepath.Join(dest, entries[0].Name())
	kids, err := os.ReadDir(sub)
	if err != nil {
		return err
	}
	for _, k := range kids {
		if err := os.Rename(filepath.Join(sub, k.Name()), filepath.Join(dest, k.Name())); err != nil {
			return err
		}
	}
	return os.Remove(sub)
}

func extractTar(b []byte, dest string, maxBytes int64, gz bool) error {
	var r io.Reader = bytes.NewReader(b)
	if gz {
		gr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return err
		}
		defer gr.Close()
		r = gr
	}
	tr := tar.NewReader(r)
	var wrote int64
	nfiles := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := stripTop(hdr.Name)
		if name == "" || strings.HasSuffix(hdr.Name, "/") && name == "" {
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			full, err := safeJoin(dest, name)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(full, 0o700); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if hdr.Size < 0 || (maxBytes > 0 && wrote+hdr.Size > maxBytes) {
				return errors.New("archive exceeds the disk limit")
			}
			nfiles++
			if nfiles > appsMaxFiles {
				return errors.New("too many files")
			}
			full, err := safeJoin(dest, name)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
				return err
			}
			f, err := os.OpenFile(full, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			n, err := io.Copy(f, io.LimitReader(tr, hdr.Size))
			cerr := f.Close()
			wrote += n
			if err != nil {
				return err
			}
			if cerr != nil {
				return cerr
			}
		case tar.TypeSymlink, tar.TypeLink:
			return errors.New("links in archives are refused")
		case tar.TypeXHeader, tar.TypeXGlobalHeader, tar.TypeGNULongName, tar.TypeGNULongLink:
			if _, err := io.Copy(io.Discard, tr); err != nil {
				return err
			}
		default:
			return errors.New("unsupported archive entry")
		}
	}
}

func extractZip(b []byte, dest string, maxBytes int64) error {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return err
	}
	var wrote int64
	nfiles := 0
	for _, f := range zr.File {
		name := stripTop(f.Name)
		if name == "" {
			continue
		}
		if f.FileInfo().IsDir() {
			full, err := safeJoin(dest, name)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(full, 0o700); err != nil {
				return err
			}
			continue
		}
		if f.Mode()&os.ModeSymlink != 0 {
			return errors.New("links in archives are refused")
		}
		if maxBytes > 0 && wrote+int64(f.UncompressedSize64) > maxBytes {
			return errors.New("archive exceeds the disk limit")
		}
		nfiles++
		if nfiles > appsMaxFiles {
			return errors.New("too many files")
		}
		full, err := safeJoin(dest, name)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(full, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			rc.Close()
			return err
		}
		n, err := io.Copy(out, io.LimitReader(rc, int64(f.UncompressedSize64)))
		cerr := out.Close()
		rc.Close()
		wrote += n
		if err != nil {
			return err
		}
		if cerr != nil {
			return cerr
		}
	}
	return nil
}

func stripTop(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimPrefix(name, "./")
	return strings.TrimPrefix(name, "/")
}

func safeJoin(root, name string) (string, error) {
	name = strings.ReplaceAll(name, "\\", "/")
	if name == "" || strings.Contains(name, "\x00") || strings.HasPrefix(name, "/") {
		return "", errors.New("bad path")
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", errors.New("bad path")
	}
	full := filepath.Join(root, filepath.FromSlash(clean))
	rel, err := filepath.Rel(root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("bad path")
	}
	return full, nil
}

func (h *Host) snapshotRelease(app *hostedApp, deployID, version, dir string) (*hostedSnap, error) {
	if dir == "" {
		return nil, nil
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return nil, nil
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	meta := map[string]string{
		"schema": updateSnapshotSchema, "app": app.ID, "version": version, "deploy": deployID,
	}
	raw, _ := json.Marshal(meta)
	if err := writeTarBytes(tw, "meta.json", raw); err != nil {
		return nil, err
	}
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi == nil || !fi.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return writeTarBytes(tw, path.Join("files", filepath.ToSlash(rel)), b)
	})
	if err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	blob := buf.Bytes()
	id := newUpdateID("hs_")
	dest := filepath.Join(h.apps.root, "apps", app.ID, "snapshots")
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dest, id+".tgz"), blob, 0o600); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(blob)
	return &hostedSnap{ID: id, DeployID: deployID, Version: version, Created: time.Now().UTC(), SHA256: hex.EncodeToString(sum[:]), Size: int64(len(blob))}, nil
}

func (s *appStore) appDir(id string) string {
	return filepath.Join(s.root, "apps", id)
}

func releaseWebRoot(dir string) string {
	pub := filepath.Join(dir, "public")
	if st, err := os.Stat(pub); err == nil && st.IsDir() {
		if _, err := os.Stat(filepath.Join(pub, "index.html")); err == nil {
			return pub
		}
	}
	return dir
}

func (s *appStore) releaseDir(appID, deployID string) string {
	return filepath.Join(s.appDir(appID), "releases", deployID, "public")
}

func (s *appStore) appendLog(appID, kind, msg string) {
	msg = strings.ReplaceAll(msg, "\n", " ")
	msg = strings.ReplaceAll(msg, "\r", " ")
	line := time.Now().UTC().Format(time.RFC3339) + "\t" + kind + "\t" + msg + "\n"
	dir := filepath.Join(s.appDir(appID), "logs")
	_ = os.MkdirAll(dir, 0o700)
	name := "runtime.log"
	if kind == "access" {
		name = "access.log"
	}
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = f.WriteString(line)
	_ = f.Close()
}

func (h *Host) readAppLog(app *hostedApp, kind string, tail int, limit AppLimit) string {
	if tail <= 0 || tail > 2000 {
		tail = 200
	}
	name := "runtime.log"
	if kind == "access" {
		name = "access.log"
	}
	b, err := os.ReadFile(filepath.Join(h.apps.appDir(app.ID), "logs", name))
	if err != nil {
		return ""
	}
	cut := time.Time{}
	if limit.LogDays > 0 {
		cut = time.Now().UTC().Add(-time.Duration(limit.LogDays) * 24 * time.Hour)
	}
	lines := strings.Split(string(b), "\n")
	var kept []string
	for _, ln := range lines {
		if ln == "" {
			continue
		}
		if !cut.IsZero() {
			ts, _, _ := strings.Cut(ln, "\t")
			if t, err := time.Parse(time.RFC3339, ts); err == nil && t.Before(cut) {
				continue
			}
		}
		kept = append(kept, ln)
	}
	if len(kept) > tail {
		kept = kept[len(kept)-tail:]
	}
	return strings.Join(kept, "\n")
}

func (h *Host) writeEnvFile(app *hostedApp) (string, error) {
	dir := h.apps.appDir(app.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	var b strings.Builder
	write := func(k, v string) {
		v = strings.ReplaceAll(v, "\n", "")
		v = strings.ReplaceAll(v, "\r", "")
		fmt.Fprintf(&b, "%s=%s\n", k, v)
	}
	for k, v := range app.Env {
		if k == "REDX_KEY" || k == "REDX_URL" || guestURLBlocked(v) {
			continue
		}
		write(k, v)
	}
	if app.DB != "" {
		write("REDX_DB", app.DB)
	}
	for _, sec := range app.Secrets {
		if sec.Name == "REDX_KEY" || sec.Name == "REDX_URL" {
			continue
		}
		plain, err := h.apps.open(app.Account, app.ID, sec)
		if err != nil {
			return "", err
		}
		if guestURLBlocked(string(plain)) {
			continue
		}
		write(sec.Name, string(plain))
	}
	path := filepath.Join(dir, "env")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return "", err
	}
	_ = os.Chmod(path, 0o600)
	return path, nil
}

// guestURLBlocked reports whether a user-supplied value is a URL that would
// point the guest at this host. Plain strings are not URLs and are kept.
func guestURLBlocked(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return false
	}
	return blocksGuestURL(raw)
}

func blocksGuestURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	host := u.Hostname()
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".local") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
		return true
	}
	switch u.Port() {
	case "7777", "7780":
		return true
	}
	return false
}

func secretEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
