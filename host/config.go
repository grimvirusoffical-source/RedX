package host

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config is the redxd configuration. Precedence: defaults < file < env < flags.
type Config struct {
	DataDir          string   `toml:"data_dir"`
	Listen           string   `toml:"listen"`         // default 127.0.0.1:7777
	NodeID           string   `toml:"node_id"`        // default: persisted random id
	Role             string   `toml:"role"`           // leader (default, alias standalone) | follower
	Peers            []string `toml:"peers"`          // follower: peers[0] is the leader URL
	Advertise        string   `toml:"advertise"`      // URL other nodes use to reach this node
	ClusterKey       string   `toml:"cluster_secret"` // optional shared secret for static clusters
	DefaultDB        string   `toml:"default_db"`     // db served at /v1/path/... (default "default")
	TLS              string   `toml:"tls"`            // off | auto | files
	TLSCert          string   `toml:"tls_cert"`
	TLSKey           string   `toml:"tls_key"`
	TLSHosts         []string `toml:"tls_hosts"`        // extra SANs for the auto cert
	RateRPS          float64  `toml:"rate_limit_rps"`   // per key default (0 => 100)
	RateBurst        int      `toml:"rate_limit_burst"` // per key default (0 => 2*rps)
	KeystoreEnc      bool     `toml:"keystore_encrypt"` // encrypt keystore at rest (needs REDX_KEYSTORE_PASSPHRASE)
	AuditLog         string   `toml:"audit_log"`        // default <data>/audit.log
	AuditOK          bool     `toml:"audit_success"`    // also log successful auths
	GRPCListen       string   `toml:"grpc_listen"`      // reserved: logged and ignored
	LogLevel         string   `toml:"log_level"`        // info | debug | quiet
	Heartbeat        int      `toml:"heartbeat_seconds"`
	MaxBodyMB        int      `toml:"max_body_mb"`
	MaxUploadMB      int      `toml:"max_upload_mb"`      // pack file uploads (PUT .../pack/.../file/...)
	EngineDurability string   `toml:"engine_durability"`  // sync | group (default) | async
	EngineDefaultTTL int      `toml:"engine_default_ttl"` // seconds applied to .red-xai-db-qs writes without TTL (0 = reject)
	ReplLogMax       int      `toml:"repl_log_max"`       // replication log entries retained (default 1,000,000)
	ArgonMemKiB      uint32   `toml:"argon_memory_kib"`   // keystore hashing cost (default 19456)
	ArgonTime        uint32   `toml:"argon_time"`

	// MasterKeyFile is a file holding the .red-xai-sec master key(s) (see `redxd keygen`). Only
	// the PATH may be configured; the key itself is never read from the environment or flags.
	// Default <data_dir>/master.key (loaded when it exists). Must not be group/world accessible.
	MasterKeyFile string `toml:"master_key_file"`
	// CodeAllowedBoxes limits which boxes .red-xai-code scripts may touch at all, as
	// "file:Box" globs ("players.red-xai.db:Player", "*.red-xai.db:Quest*"). Empty = scripts
	// cannot read or write any record. This is on top of the key's scope and the .red-xai-sec policy.
	CodeAllowedBoxes []string `toml:"code_allowed_boxes"`

	// Preset names a bundled settings profile (see host/presets and docs/console.md). Its values sit
	// between the built-in defaults and the config file, so anything written in the file wins.
	Preset string `toml:"preset"`
	// Bootstrap decides how the first admin key is made on an empty keystore:
	// "auto" (web setup screen when listening on loopback, console key otherwise), "web", "console", "off".
	// "" (the library default, used by tests and embedders) behaves like "console".
	Bootstrap string `toml:"bootstrap"`
	// Join is a one-time join link/code from the leader's "Add a device" page ("URL CODE" or a full link).
	// It is redeemed once at start-up (when this node has no cluster.json yet) and the node becomes a follower.
	Join string `toml:"join"`

	// Red-XAI Accounts sign-in for the web console (OIDC with PKCE). Empty issuer = off; API keys always work.
	AccountsIssuer   string `toml:"accounts_issuer"`       // e.g. https://accounts.red-xai.example
	AccountsClientID string `toml:"accounts_client_id"`    // OAuth client id registered for this host (default "redx")
	AccountsRedirect string `toml:"accounts_redirect_url"` // default <advertise>/v1/auth/callback
	// AccountsMasterDB is the RedX database holding the master Red-XAI accounts DB (default "redxai_accounts").
	// While accounts are on, only owner logins (and keys scoped to exactly that database) can see it.
	AccountsMasterDB string `toml:"accounts_master_db"`
	// OwnerEmails lists the owner logins (deploy config or REDXAI_OWNER_EMAILS only; never commit real addresses).
	// An owner must also have a verified email and have finished this sign-in with 2FA.
	OwnerEmails []string `toml:"owner_emails"`
	// AccountsClientSecret is read from REDX_ACCOUNTS_CLIENT_SECRET only (confidential clients); never from a file or flag.
	AccountsClientSecret string `toml:"-"`

	ConfigFile string `toml:"-"`
}

// DefaultDataDir returns a per-OS default that a normal (non-administrator) user can write, because the installers
// and the one-click launcher run as the signed-in user:
//
//	Windows  %LOCALAPPDATA%\RedX\data   (an existing %ProgramData%\RedX\data from an older install is kept)
//	macOS    ~/Library/Application Support/RedX/data   (an existing /usr/local/var/redx is kept; root uses it)
//	Linux    ~/.redx/data   (/var/lib/redx for root and for the systemd service)
func DefaultDataDir() string {
	return defaultDataDir(runtime.GOOS, os.Getenv, os.Geteuid(), os.UserHomeDir, func(p string) bool { _, err := os.Stat(p); return err == nil })
}

func defaultDataDir(goos string, env func(string) string, euid int, home func() (string, error), exists func(string) bool) string {
	switch goos {
	case "windows":
		if pd := env("ProgramData"); pd != "" {
			if old := filepath.Join(pd, "RedX", "data"); exists(old) {
				return old
			}
		}
		if la := env("LOCALAPPDATA"); la != "" {
			return filepath.Join(la, "RedX", "data")
		}
		if pd := env("ProgramData"); pd != "" {
			return filepath.Join(pd, "RedX", "data")
		}
	case "darwin":
		const legacy = "/usr/local/var/redx"
		if euid == 0 || exists(legacy) {
			return legacy
		}
		if h, err := home(); err == nil {
			return filepath.Join(h, "Library", "Application Support", "RedX", "data")
		}
	default:
		if euid == 0 {
			return "/var/lib/redx"
		}
	}
	if h, err := home(); err == nil {
		return filepath.Join(h, ".redx", "data")
	}
	return "./redx-data"
}

// DefaultConfig returns the built-in defaults.
func DefaultConfig() Config {
	return Config{
		DataDir:   DefaultDataDir(),
		Listen:    "127.0.0.1:7777",
		Role:      "leader",
		DefaultDB: "default",
		TLS:       "off",
		LogLevel:  "info",
		Heartbeat: 3,
		MaxBodyMB: 16, MaxUploadMB: 1024,
	}
}

// RegisterFlags binds flags onto cfg. Flags only override when explicitly set.
func (c *Config) RegisterFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.ConfigFile, "config", c.ConfigFile, "path to config file (TOML)")
	fs.StringVar(&c.DataDir, "data-dir", c.DataDir, "data directory")
	fs.StringVar(&c.Listen, "listen", c.Listen, "listen address")
	fs.StringVar(&c.NodeID, "node-id", c.NodeID, "node id (default: generated and persisted)")
	fs.StringVar(&c.Role, "role", c.Role, "leader|follower")
	fs.Var((*csv)(&c.Peers), "peers", "comma separated peer URLs (follower: first is the leader)")
	fs.StringVar(&c.Advertise, "advertise", c.Advertise, "URL other nodes use to reach this node")
	fs.StringVar(&c.TLS, "tls", c.TLS, "off|auto|files")
	fs.StringVar(&c.TLSCert, "tls-cert", c.TLSCert, "TLS certificate file (tls=files)")
	fs.StringVar(&c.TLSKey, "tls-key", c.TLSKey, "TLS key file (tls=files)")
	fs.StringVar(&c.DefaultDB, "default-db", c.DefaultDB, "database served by /v1/path/...")
	fs.BoolVar(&c.KeystoreEnc, "keystore-encrypt", c.KeystoreEnc, "encrypt keystore at rest (REDX_KEYSTORE_PASSPHRASE)")
	fs.StringVar(&c.MasterKeyFile, "master-key-file", c.MasterKeyFile, "file with the .red-xai-sec master key (default <data-dir>/master.key if present)")
	fs.Var((*csv)(&c.CodeAllowedBoxes), "code-allowed-boxes", "comma separated file:Box globs scripts may touch")
	fs.StringVar(&c.LogLevel, "log-level", c.LogLevel, "info|debug|quiet")
	fs.StringVar(&c.Preset, "preset", c.Preset, "settings profile: "+strings.Join(PresetNames(), "|"))
	fs.StringVar(&c.Bootstrap, "bootstrap", c.Bootstrap, "first admin key: auto|web|console|off")
	SecretVar(fs, &c.Join, "join", "one-time join link or 'URL CODE' from the leader (becomes a follower); never printed", "$REDX_JOIN or redx.toml")
}

type csv []string

func (c *csv) String() string { return strings.Join(*c, ",") }
func (c *csv) Set(s string) error {
	*c = nil
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*c = append(*c, p)
		}
	}
	return nil
}

// ApplyFile loads a TOML file over cfg (missing explicit file is an error).
func (c *Config) ApplyFile(path string, mustExist bool) error {
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) && !mustExist {
			return nil
		}
		return err
	}
	md, err := toml.DecodeFile(path, c)
	if err != nil {
		return fmt.Errorf("config %s: %w", path, err)
	}
	if u := md.Undecoded(); len(u) > 0 {
		return fmt.Errorf("config %s: unknown keys: %v", path, u)
	}
	return nil
}

// ApplyEnv overlays REDX_* environment variables.
func (c *Config) ApplyEnv(get func(string) string) error {
	s := func(name string, dst *string) {
		if v := get(name); v != "" {
			*dst = v
		}
	}
	s("REDX_DATA_DIR", &c.DataDir)
	s("REDX_LISTEN", &c.Listen)
	s("REDX_NODE_ID", &c.NodeID)
	s("REDX_ROLE", &c.Role)
	s("REDX_ADVERTISE", &c.Advertise)
	s("REDX_CLUSTER_SECRET", &c.ClusterKey)
	s("REDX_DEFAULT_DB", &c.DefaultDB)
	s("REDX_TLS", &c.TLS)
	s("REDX_TLS_CERT", &c.TLSCert)
	s("REDX_TLS_KEY", &c.TLSKey)
	s("REDX_LOG_LEVEL", &c.LogLevel)
	s("REDX_AUDIT_LOG", &c.AuditLog)
	s("REDX_GRPC_LISTEN", &c.GRPCListen)
	s("REDX_ENGINE_DURABILITY", &c.EngineDurability)
	s("REDX_MASTER_KEY_FILE", &c.MasterKeyFile) // a path, never the key
	s("REDX_PRESET", &c.Preset)
	s("REDX_BOOTSTRAP", &c.Bootstrap)
	s("REDX_JOIN", &c.Join)
	s("REDX_ACCOUNTS_ISSUER", &c.AccountsIssuer)
	s("REDX_ACCOUNTS_CLIENT_ID", &c.AccountsClientID)
	s("REDX_ACCOUNTS_REDIRECT_URL", &c.AccountsRedirect)
	s("REDX_ACCOUNTS_MASTER_DB", &c.AccountsMasterDB)
	s("REDX_ACCOUNTS_CLIENT_SECRET", &c.AccountsClientSecret)
	if v := get("REDXAI_OWNER_EMAILS"); v != "" {
		_ = (*csv)(&c.OwnerEmails).Set(v)
	}
	if get("REDX_NO_BOOTSTRAP") != "" {
		c.Bootstrap = "off"
	}
	if v := get("REDX_CODE_ALLOWED_BOXES"); v != "" {
		_ = (*csv)(&c.CodeAllowedBoxes).Set(v)
	}
	if v := get("REDX_PEERS"); v != "" {
		_ = (*csv)(&c.Peers).Set(v)
	}
	if v := get("REDX_TLS_HOSTS"); v != "" {
		_ = (*csv)(&c.TLSHosts).Set(v)
	}
	if v := get("REDX_KEYSTORE_ENCRYPT"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("REDX_KEYSTORE_ENCRYPT: %w", err)
		}
		c.KeystoreEnc = b
	}
	if v := get("REDX_RATE_LIMIT_RPS"); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return fmt.Errorf("REDX_RATE_LIMIT_RPS: %w", err)
		}
		c.RateRPS = f
	}
	return nil
}

// Validate normalises and checks the configuration.
func (c *Config) Validate() error {
	if c.Role == "standalone" || c.Role == "" {
		c.Role = "leader"
	}
	switch c.Bootstrap {
	case "", "auto", "web", "console", "off":
	default:
		return fmt.Errorf("bootstrap must be auto|web|console|off, got %q", c.Bootstrap)
	}
	if c.Preset != "" {
		if _, err := GetPreset(c.Preset); err != nil {
			return err
		}
	}
	if c.Join != "" {
		c.Role = "follower"
	}
	if c.Role != "leader" && c.Role != "follower" {
		return fmt.Errorf("role must be leader or follower, got %q", c.Role)
	}
	if c.Role == "follower" && len(c.Peers) == 0 && c.Join == "" {
		// A follower may also be configured purely via cluster.json (written by `redx node join`).
		if _, err := os.Stat(filepath.Join(c.DataDir, "cluster", "cluster.json")); err != nil {
			return fmt.Errorf("role=follower needs peers[0] (leader URL) or a cluster.json from `redx node join`")
		}
	}
	if !ValidDBName(c.DefaultDB) {
		return fmt.Errorf("invalid default_db %q", c.DefaultDB)
	}
	switch c.EngineDurability {
	case "", "sync", "group", "async":
	default:
		return fmt.Errorf("engine_durability must be sync|group|async, got %q", c.EngineDurability)
	}
	switch c.LogLevel {
	case "", "info", "debug", "quiet":
	default:
		return fmt.Errorf("log_level must be info|debug|quiet, got %q", c.LogLevel)
	}
	switch c.TLS {
	case "", "off":
		c.TLS = "off"
	case "auto":
	case "files":
		if c.TLSCert == "" || c.TLSKey == "" {
			return fmt.Errorf("tls=files needs tls_cert and tls_key")
		}
	default:
		return fmt.Errorf("tls must be off|auto|files, got %q", c.TLS)
	}
	if c.DataDir == "" {
		return fmt.Errorf("data_dir is required")
	}
	if err := validListen("listen", c.Listen); err != nil {
		return err
	}
	if c.GRPCListen != "" {
		if err := validListen("grpc_listen", c.GRPCListen); err != nil {
			return err
		}
	}
	if c.Advertise != "" {
		if u, err := url.Parse(c.Advertise); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("advertise must be a URL such as http://192.168.1.20:7777, got %q", c.Advertise)
		}
	}
	if c.RateRPS == 0 {
		c.RateRPS = 100
	}
	if c.RateBurst == 0 {
		c.RateBurst = int(c.RateRPS * 2)
	}
	if c.Heartbeat <= 0 {
		c.Heartbeat = 3
	}
	if c.MaxUploadMB <= 0 {
		c.MaxUploadMB = 1024
	}
	if c.MaxBodyMB <= 0 {
		c.MaxBodyMB = 16
	}
	if c.AuditLog == "" {
		c.AuditLog = filepath.Join(c.DataDir, "audit.log")
	}
	if c.ArgonMemKiB == 0 {
		c.ArgonMemKiB = 19456
	}
	if c.ArgonTime == 0 {
		c.ArgonTime = 2
	}
	return c.validateAccounts()
}

// LoadConfig builds a Config from defaults, preset, file, env and flags (in that order, later wins). Precedence, highest first:
//
//	command-line flags  >  REDX_* environment variables  >  redx.toml  >  the preset  >  built-in defaults
//
// The file is --config, else REDX_CONFIG, else <data dir>/redx.toml for the data dir given by --data-dir, REDX_DATA_DIR or
// the default (in that order); a missing default file is fine, a missing explicit one is an error.
// args are command line arguments without the program name.
func LoadConfig(args []string, getenv func(string) string, fs *flag.FlagSet) (Config, error) {
	cfg := DefaultConfig()
	cfg.Bootstrap = "auto" // production default; DefaultConfig() itself stays "console" for embedders and tests
	if fs == nil {
		fs = flag.NewFlagSet("redxd", flag.ContinueOnError)
	}
	// First pass: find --config so the file can sit below env+flags in precedence.
	pre := flag.NewFlagSet("pre", flag.ContinueOnError)
	pre.SetOutput(discard{})
	cf := pre.String("config", "", "")
	pf := pre.String("preset", "", "")
	ddFlag := pre.String("data-dir", "", "")
	for _, n := range []string{"listen", "node-id", "role", "peers", "advertise", "tls", "tls-cert", "tls-key", "default-db", "master-key-file", "code-allowed-boxes", "log-level", "bootstrap", "join"} {
		pre.String(n, "", "")
	}
	pre.Bool("keystore-encrypt", false, "")
	_ = pre.Parse(args)
	file := *cf
	if file == "" {
		file = getenv("REDX_CONFIG")
	}
	explicit := file != ""
	// Without --config / REDX_CONFIG the file is <data dir>/redx.toml, where the data dir is the one the host will actually
	// use: --data-dir, else REDX_DATA_DIR, else the default. (Presets written by the console or `redx preset apply` go there.)
	if !explicit {
		dd := cfg.DataDir
		if v := getenv("REDX_DATA_DIR"); v != "" {
			dd = v
		}
		if *ddFlag != "" {
			dd = *ddFlag
		}
		file = filepath.Join(dd, "redx.toml")
	}
	// The preset name may come from the file, the environment or --preset (last one wins);
	// its settings are applied first so file, environment and flags all override them.
	name := ""
	if file != "" {
		if _, err := os.Stat(file); err == nil {
			var peek struct {
				Preset string `toml:"preset"`
			}
			_, _ = toml.DecodeFile(file, &peek)
			name = peek.Preset
		}
	}
	if v := getenv("REDX_PRESET"); v != "" {
		name = v
	}
	if *pf != "" {
		name = *pf
	}
	if name != "" {
		p, err := GetPreset(name)
		if err != nil {
			return cfg, err
		}
		if err := p.ApplyTo(&cfg); err != nil {
			return cfg, err
		}
		cfg.Preset = p.Name
	}
	if err := cfg.ApplyFile(file, explicit); err != nil {
		return cfg, err
	}
	if err := cfg.ApplyEnv(getenv); err != nil {
		return cfg, err
	}
	cfg.RegisterFlags(fs)
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	return cfg, cfg.Validate()
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// validListen checks a host:port listen address ("127.0.0.1:7777", ":7777", "[::1]:7777", "localhost:0").
func validListen(name, addr string) error {
	if addr == "" {
		return fmt.Errorf("%s is required, for example 127.0.0.1:7777", name)
	}
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s %q is not a host:port address (for example 127.0.0.1:7777 or 0.0.0.0:7777): %v", name, addr, err)
	}
	if n, err := strconv.Atoi(p); err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("%s %q: the port must be a number from 0 to 65535", name, addr)
	}
	if strings.ContainsAny(h, " /\\") {
		return fmt.Errorf("%s %q: invalid host part", name, addr)
	}
	return nil
}
