package host

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Console support endpoints (all host-admin unless noted). They only report and edit what the CLI
// can already do; nothing here widens what an admin key may do.
//
//	GET    /v1/admin/status                    host status for the dashboard
//	GET    /v1/admin/audit?limit=N             newest audit events (never contain keys)
//	GET    /v1/admin/config                    effective configuration, secrets redacted
//	GET    /v1/admin/presets                   all presets (settings, reasons, guidance)
//	GET    /v1/admin/presets/{name}            one preset with a diff against this host's current settings
//	POST   /v1/admin/presets/{name}/apply      write the preset into the config file (restart to take effect)
//	                                            join, role and advertise changes are owner-only while Accounts is on
//	GET    /v1/db/{db}/files                   files of a database with type and size    admin on the db
//	GET    /v1/db/{db}/files/{name}            raw text of a definition file (sec, code, pulse, idx, link)
//	DELETE /v1/db/{db}?confirm={db}            delete a database (leader; replicated)  host admin

func (h *Host) adminRoute(w http.ResponseWriter, r *http.Request) {
	pr, ok := h.authz(w, r, ScopeAdmin, AllDBs, "", true)
	if !ok {
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/admin/"), "/")
	switch {
	case rest == "status" && r.Method == "GET":
		h.adminStatus(w, r, pr)
	case rest == "audit" && r.Method == "GET":
		h.adminAudit(w, r)
	case rest == "config" && r.Method == "GET":
		writeJSON(w, 200, h.effectiveConfig())
	case rest == "presets" && r.Method == "GET":
		out := []map[string]interface{}{}
		for _, p := range AllPresets() {
			out = append(out, presetView(p, h.Cfg, false))
		}
		writeJSON(w, 200, map[string]interface{}{"presets": out, "active": h.Cfg.Preset, "keys": presetKeyOrder()})
	case strings.HasPrefix(rest, "presets/"):
		name, verb, _ := strings.Cut(strings.TrimPrefix(rest, "presets/"), "/")
		p, err := GetPreset(name)
		if err != nil {
			writeErr(w, 404, err.Error())
			return
		}
		switch {
		case verb == "" && r.Method == "GET":
			writeJSON(w, 200, presetView(p, h.Cfg, true))
		case verb == "apply" && r.Method == "POST":
			h.applyPresetHandler(w, r, p, pr)
		default:
			writeErr(w, 405, "method not allowed")
		}
	default:
		writeErr(w, 404, "not found")
	}
}

func presetKeyOrder() []string {
	seen := map[string]bool{}
	var out []string
	pri := []string{"role", "listen", "tls", "engine_durability", "engine_default_ttl", "rate_limit_rps", "rate_limit_burst",
		"keystore_encrypt", "audit_success", "log_level", "heartbeat_seconds", "repl_log_max", "argon_memory_kib", "max_body_mb", "max_upload_mb", "bootstrap"}
	for _, k := range pri {
		seen[k] = true
		out = append(out, k)
	}
	var rest []string
	for _, p := range AllPresets() {
		for k := range p.Settings {
			if !seen[k] {
				seen[k] = true
				rest = append(rest, k)
			}
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

func presetView(p *Preset, cfg Config, withDiff bool) map[string]interface{} {
	v := map[string]interface{}{
		"name": p.Name, "title": p.Title, "summary": p.Summary, "audience": p.Audience, "needs": p.Needs,
		"guidance": p.Guidance, "warnings": p.Warnings, "why": p.Why, "files": p.Files, "settings": p.Settings,
	}
	if v["needs"] == nil {
		v["needs"] = []string{}
	}
	if withDiff {
		v["diff"] = p.Diff(cfg)
	}
	return v
}

func (h *Host) dataSize() int64 {
	h.diskMu.Lock()
	defer h.diskMu.Unlock()
	if time.Since(h.diskAt) < 10*time.Second && !h.diskAt.IsZero() {
		return h.diskBytes
	}
	var n int64
	_ = filepath.Walk(h.Cfg.DataDir, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			n += fi.Size()
		}
		return nil
	})
	h.diskAt, h.diskBytes = time.Now(), n
	return n
}

func (h *Host) adminStatus(w http.ResponseWriter, r *http.Request, pr *Principal) {
	h.runMu.Lock()
	listen, scheme, fp := h.listenAt, h.scheme, h.tlsFP
	h.runMu.Unlock()
	if listen == "" {
		listen, scheme = h.Cfg.Listen, "http"
	}
	dbs := h.visibleDBs(pr)
	ci := h.certInfo()
	writeJSON(w, 200, map[string]interface{}{
		"tls_cert": ci, "tls_warning": ci.Message,
		"version": Version, "node_id": h.NodeID, "role": roleName(h.Cluster), "uptime_seconds": int(time.Since(h.started).Seconds()),
		"started": h.started.UTC().Format(time.RFC3339), "listen": listen, "scheme": scheme, "tls": h.Cfg.TLS, "tls_fingerprint": fp,
		"databases": len(dbs), "default_db": h.Cfg.DefaultDB, "requests": h.reqs.Load(), "auth_failures": h.authBad.Load(),
		"keys": h.KS.Count(), "replication_offset": h.Cluster.Offset(), "ttl_tracked": h.Tracker.Len(),
		"os": runtime.GOOS, "arch": runtime.GOARCH, "go": runtime.Version(), "data_dir": h.Cfg.DataDir,
		"data_bytes": h.dataSize(), "preset": h.Cfg.Preset, "advertise": h.Cfg.Advertise, "config_file": h.configPath(),
		"keystore_encrypted": h.Cfg.KeystoreEnc, "web_setup_pending": h.WebSetupPending(),
	})
}

func (h *Host) adminAudit(w http.ResponseWriter, r *http.Request) {
	limit := 50
	fmt.Sscanf(r.URL.Query().Get("limit"), "%d", &limit)
	if limit < 1 {
		limit = 1
	}
	if limit > 500 {
		limit = 500
	}
	events := []map[string]interface{}{}
	f, err := os.Open(h.Cfg.AuditLog)
	if err == nil {
		defer f.Close()
		st, _ := f.Stat()
		const tail = 512 << 10
		off := int64(0)
		if st != nil && st.Size() > tail {
			off = st.Size() - tail
		}
		_, _ = f.Seek(off, io.SeekStart)
		br := bufio.NewReader(f)
		if off > 0 {
			_, _ = br.ReadString('\n') // drop the partial first line
		}
		for {
			line, err := br.ReadBytes('\n')
			if len(bytes.TrimSpace(line)) > 0 {
				var m map[string]interface{}
				if json.Unmarshal(line, &m) == nil {
					events = append(events, m)
				}
			}
			if err != nil {
				break
			}
		}
	}
	if len(events) > limit {
		events = events[len(events)-limit:]
	}
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	writeJSON(w, 200, map[string]interface{}{"events": events})
}

// effectiveConfig is the running configuration with secrets redacted.
func (h *Host) effectiveConfig() map[string]interface{} {
	vals := ConfigValues(h.Cfg)
	if h.Cfg.ClusterKey != "" {
		vals["cluster_secret"] = "(set, hidden)"
	}
	if h.Cfg.Join != "" {
		vals["join"] = "(set, hidden)"
	}
	if h.Cfg.AccountsClientSecretFile != "" {
		vals["accounts_client_secret_file"] = "(set, hidden)"
	}
	if n := len(h.Cfg.OwnerEmails); n > 0 {
		vals["owner_emails"] = fmt.Sprintf("(%d set, hidden)", n)
	}
	_, mkErr := os.Stat(filepath.Join(h.Cfg.DataDir, "master.key"))
	return map[string]interface{}{
		"config": vals, "config_file": h.configPath(), "config_file_exists": fileExists(h.configPath()),
		"keystore_passphrase_in_env": os.Getenv("REDX_KEYSTORE_PASSPHRASE") != "",
		"master_key_present":         h.Cfg.MasterKeyFile != "" || mkErr == nil,
		"env_overrides":              envOverrides(),
	}
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

var envKeys = map[string]string{
	"REDX_LISTEN": "listen", "REDX_TLS": "tls", "REDX_ROLE": "role", "REDX_LOG_LEVEL": "log_level", "REDX_ENGINE_DURABILITY": "engine_durability",
	"REDX_KEYSTORE_ENCRYPT": "keystore_encrypt", "REDX_RATE_LIMIT_RPS": "rate_limit_rps", "REDX_PRESET": "preset", "REDX_DATA_DIR": "data_dir",
	"REDX_ADVERTISE": "advertise", "REDX_AUDIT_LOG": "audit_log", "REDX_PEERS": "peers", "REDX_BOOTSTRAP": "bootstrap",
	"REDX_ACCOUNTS_ISSUER": "accounts_issuer", "REDX_ACCOUNTS_CLIENT_ID": "accounts_client_id", "REDX_ACCOUNTS_REDIRECT_URL": "accounts_redirect_url",
	"REDX_ACCOUNTS_MASTER_DB": "accounts_master_db", "REDXAI_OWNER_EMAILS": "owner_emails",
}

// envOverrides lists settings currently pinned by environment variables (they beat the config file).
func envOverrides() []string {
	out := []string{} // never nil: the JSON must be [] and not null
	for env, key := range envKeys {
		if os.Getenv(env) != "" {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

func (h *Host) configPath() string {
	if h.Cfg.ConfigFile != "" {
		return h.Cfg.ConfigFile
	}
	return filepath.Join(h.Cfg.DataDir, "redx.toml")
}

// ---- applying a preset ----

type skipped struct {
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

func applyKeys() map[string]bool {
	m := map[string]bool{"join": true, "advertise": true}
	for _, p := range AllPresets() {
		for k := range p.Settings {
			m[k] = true
		}
	}
	return m
}

func (h *Host) applyPresetHandler(w http.ResponseWriter, r *http.Request, p *Preset, pr *Principal) {
	var req struct {
		Overrides map[string]interface{} `json:"overrides"` // edited values, same keys as the settings
		Join      string                 `json:"join"`
		DryRun    bool                   `json:"dry_run"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil && err != io.EOF {
		writeErr(w, 400, "invalid JSON")
		return
	}
	allowed := applyKeys()
	vals := map[string]interface{}{}
	for k, v := range p.Settings {
		vals[k] = v
	}
	for k, v := range req.Overrides {
		if !allowed[k] {
			writeErr(w, 400, "setting "+k+" cannot be changed from the console")
			return
		}
		if f, ok := v.(float64); ok && f == float64(int64(f)) {
			v = int64(f) // JSON numbers arrive as float64; the config wants whole numbers
		}
		vals[k] = v
	}
	var skip []skipped
	if v, _ := vals["keystore_encrypt"].(bool); v && os.Getenv("REDX_KEYSTORE_PASSPHRASE") == "" && !h.Cfg.KeystoreEnc {
		delete(vals, "keystore_encrypt")
		skip = append(skip, skipped{"keystore_encrypt", "needs the REDX_KEYSTORE_PASSPHRASE environment variable on this host, which the console cannot set. Set it in the service environment, then add keystore_encrypt = true to the config file."})
	}
	// A join link, a role change (follower takes the leader's snapshot) or an advertise change is
	// redeemed on the next ordinary start. While Accounts protects the master DB, that is the same
	// class of operation as POST /v1/cluster/leader: owner only. Accounts off: ownerOnlyOK allows
	// any host admin, which is the previous behaviour.
	if h.presetAffectsCluster(vals, req.Join) && !h.ownerOnlyOK(w, r, pr) {
		return
	}
	if role, _ := vals["role"].(string); role == "follower" {
		if strings.TrimSpace(req.Join) == "" {
			writeErr(w, 400, "this preset makes the host a follower of another RedX host. Paste a join link from the leader's Add a device page (or use the Server preset to stay a leader)")
			return
		}
		if _, err := ParseJoin(req.Join); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		vals["join"] = strings.TrimSpace(req.Join)
	}
	// Build the new file: keep the existing keys, replace the preset's keys, record the preset name.
	path := h.configPath()
	cur := map[string]interface{}{}
	if b, err := os.ReadFile(path); err == nil {
		if _, err := toml.Decode(string(b), &cur); err != nil {
			writeErr(w, 409, "the existing config file cannot be parsed ("+err.Error()+"); fix it in the Raw editor or the terminal first")
			return
		}
	}
	for k, v := range vals {
		cur[k] = v
	}
	cur["preset"] = p.Name
	var buf bytes.Buffer
	buf.WriteString("# Written by the RedX console (preset \"" + p.Name + "\"). Edit freely; the previous file is kept next to it as .bak.\n")
	if err := toml.NewEncoder(&buf).Encode(cur); err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	// Validate exactly as the host would at start-up.
	test := DefaultConfig()
	test.DataDir = h.Cfg.DataDir
	if _, err := toml.Decode(buf.String(), &test); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := test.Validate(); err != nil {
		writeErr(w, 400, "the result would not start: "+err.Error())
		return
	}
	// "What changed": compare with how this host is configured right now.
	now := ConfigValues(h.Cfg)
	var changes []SettingChange
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k == "join" {
			continue
		}
		ch := SettingChange{Key: k, From: normalize(now[k]), To: normalize(vals[k]), Why: p.Why[k]}
		ch.Changed = fmt.Sprint(ch.From) != fmt.Sprint(ch.To)
		changes = append(changes, ch)
	}
	resp := map[string]interface{}{"preset": p.Name, "path": path, "changes": changes, "skipped": skip, "restart_required": true,
		"env_overrides": envOverrides(), "text": buf.String(), "dry_run": req.DryRun}
	if !req.DryRun {
		backup := ""
		if b, err := os.ReadFile(path); err == nil {
			backup = path + ".bak-" + time.Now().UTC().Format("20060102-150405")
			if err := os.WriteFile(backup, b, 0o600); err != nil {
				writeErr(w, 500, "cannot write backup: "+err.Error())
				return
			}
		}
		if err := atomicWrite(path, buf.Bytes()); err != nil {
			writeErr(w, 500, "cannot write "+path+": "+err.Error())
			return
		}
		_ = os.Chmod(path, 0o600)
		resp["backup"] = backup
		h.Audit.Log(AuditEvent{Event: "preset.apply", KeyID: pr.Key.ID, Actor: auditActor(pr), Remote: remoteIP(r), Detail: presetApplyDetail(p.Name, joinSetting(vals))})
	}
	writeJSON(w, 200, resp)
}

// presetAffectsCluster reports whether this apply would set a join link or change role or advertise.
// Those are the settings the next start uses to follow another host. A join is "set" when the body
// carries one (the join field or an override), even if it repeats the current value: rewriting it
// is what the next start redeems. Role and advertise count only when the value would change.
func (h *Host) presetAffectsCluster(vals map[string]interface{}, reqJoin string) bool {
	if strings.TrimSpace(reqJoin) != "" {
		return true
	}
	if v, ok := vals["join"]; ok && asSettingString(v) != "" {
		return true
	}
	if v, ok := vals["role"]; ok && normPresetRole(asSettingString(v)) != normPresetRole(h.Cfg.Role) {
		return true
	}
	if v, ok := vals["advertise"]; ok && asSettingString(v) != strings.TrimSpace(h.Cfg.Advertise) {
		return true
	}
	return false
}

func normPresetRole(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "standalone" {
		return "leader"
	}
	return s
}

func asSettingString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}

func joinSetting(vals map[string]interface{}) string {
	v, ok := vals["join"]
	if !ok {
		return ""
	}
	return asSettingString(v)
}

// presetApplyDetail is the audit detail for a preset apply. When a join link was written, the
// leader URL is included and the one-time secret (code, rxj_ token, userinfo, pin) is not.
func presetApplyDetail(name, join string) string {
	join = strings.TrimSpace(join)
	if join == "" {
		return name
	}
	sp, err := ParseJoin(join)
	if err != nil || sp.Leader == "" || (sp.Secret != "" && strings.Contains(sp.Leader, sp.Secret)) {
		return name
	}
	return name + " join=" + sp.Leader
}

// ---- database files ----

// FileInfo describes one entry of a database folder.
type FileInfo struct {
	Name     string    `json:"name"`
	Type     string    `json:"type"`     // db, qs, qs-ls, link, pulse, idx, sec, code, pack, media, journal, system
	Label    string    `json:"label"`    // plain-English name
	Size     int64     `json:"size"`     // bytes (a folder: everything inside)
	Modified time.Time `json:"modified"` //
	Dir      bool      `json:"dir,omitempty"`
	Records  string    `json:"records"` // how to edit: "records" (Data Explorer), "raw" (Raw editor, saved through the API), "raw-readonly", "none"
	Writable string    `json:"writable,omitempty"`
	Note     string    `json:"note,omitempty"`
}

func classifyFile(name string, dir bool) (typ, label, records, note string) {
	switch {
	case strings.HasSuffix(name, ".red-xai-db-qs-ls"):
		return "qs-ls", "Quick store with journal (qs-ls)", "records", "Hot counters; journaled so they survive a restart."
	case strings.HasSuffix(name, ".red-xai-db-qs"):
		return "qs", "Quick store (qs)", "records", "In-memory, every record expires."
	case strings.HasSuffix(name, ".red-xai.db"), strings.HasSuffix(name, ".red-xai-db"):
		return "db", "Data file (db)", "records", "Durable records."
	case strings.HasSuffix(name, ".red-xai-db-link"):
		return "link", "Links", "raw-readonly", "Link edges. The API cannot write this file type."
	case strings.HasSuffix(name, ".red-xai-db-pulse"):
		return "pulse", "Pulse rules", "raw", "Live rules and timers."
	case strings.HasSuffix(name, ".red-xai-db-idx"):
		return "idx", "Search index definition", "raw", "Index sets."
	case strings.HasSuffix(name, ".red-xai-sec"):
		return "sec", "Security policy", "raw", "Access and encryption policy."
	case strings.HasSuffix(name, ".red-xai-code"):
		return "code", "Code scripts", "raw", "Sandboxed scripts."
	case dir && strings.HasSuffix(name, ".red-xai-pack"):
		return "pack", "File pack", "none", "Large files; use the CLI or the pack API."
	case dir && strings.HasSuffix(name, ".red-xai-media"):
		return "media", "Media library", "none", "Images, audio and video."
	case strings.Contains(name, ".wal.") || strings.Contains(name, ".ckpt") || strings.HasSuffix(name, ".wal"):
		return "journal", "Write-ahead log", "none", "Engine-managed; never edit."
	}
	return "system", "Engine file", "none", "Engine-managed."
}

// writableVia says which API stores a raw text file, or "" when none can.
func writableVia(name, typ string) string {
	switch typ {
	case "sec":
		if name == "policy.red-xai-sec" {
			return "PUT /v1/db/{db}/sec"
		}
	case "pulse":
		if name == "rules.red-xai-db-pulse" {
			return "PUT /v1/db/{db}/pulse"
		}
	case "code":
		return "PUT /v1/db/{db}/code/file/" + strings.TrimSuffix(name, ".red-xai-code")
	case "idx":
		return "PUT /v1/db/{db}/idx/" + strings.TrimSuffix(name, ".red-xai-db-idx")
	}
	return ""
}

func dirSize(p string) (n int64, mod time.Time) {
	_ = filepath.Walk(p, func(_ string, fi os.FileInfo, err error) error {
		if err == nil {
			if fi.Mode().IsRegular() {
				n += fi.Size()
			}
			if fi.ModTime().After(mod) {
				mod = fi.ModTime()
			}
		}
		return nil
	})
	return
}

func (h *Host) filesRoute(w http.ResponseWriter, r *http.Request, db, rest string) {
	if r.Method != "GET" {
		writeErr(w, 405, "method not allowed")
		return
	}
	if _, ok := h.authz(w, r, ScopeAdmin, db, "", false); !ok {
		return
	}
	if !h.Reg.Exists(db) {
		writeErr(w, 404, "database not found")
		return
	}
	dir := filepath.Join(h.Reg.Root(), db)
	if rest == "" {
		ents, err := os.ReadDir(dir)
		if err != nil {
			h.mapErr(w, err)
			return
		}
		out := []FileInfo{}
		for _, e := range ents {
			fi, err := e.Info()
			if err != nil {
				continue
			}
			typ, label, rec, note := classifyFile(e.Name(), e.IsDir())
			f := FileInfo{Name: e.Name(), Type: typ, Label: label, Size: fi.Size(), Modified: fi.ModTime().UTC(), Dir: e.IsDir(), Records: rec, Note: note}
			if e.IsDir() {
				f.Size, f.Modified = dirSize(filepath.Join(dir, e.Name()))
				f.Modified = f.Modified.UTC()
			}
			if rec == "raw" {
				if wv := writableVia(e.Name(), typ); wv == "" {
					f.Records = "raw-readonly"
					f.Note = "Placed by hand: the API can read this file but not write it. Edit it on disk."
				} else {
					f.Writable = wv
				}
			}
			out = append(out, f)
		}
		writeJSON(w, 200, map[string]interface{}{"db": db, "files": out})
		return
	}
	// raw text of one definition file
	if strings.ContainsAny(rest, `/\`) || strings.HasPrefix(rest, ".") {
		writeErr(w, 400, "bad file name")
		return
	}
	typ, label, rec, _ := classifyFile(rest, false)
	if rec != "raw" && rec != "raw-readonly" {
		writeErr(w, 400, "only definition files (policy, code, pulse, index, link) can be read as text; use the Data Explorer for records")
		return
	}
	p := filepath.Join(dir, rest)
	st, err := os.Stat(p)
	if err != nil || !st.Mode().IsRegular() {
		writeErr(w, 404, "not found")
		return
	}
	if st.Size() > 1<<20 {
		writeErr(w, 413, "file is larger than 1 MiB")
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		h.mapErr(w, err)
		return
	}
	wv := writableVia(rest, typ)
	writeJSON(w, 200, map[string]interface{}{"name": rest, "type": typ, "label": label, "text": string(b), "writable": wv != "", "write_via": wv, "modified": st.ModTime().UTC()})
}

func (h *Host) dropDBHandler(w http.ResponseWriter, r *http.Request, db string) {
	pr, ok := h.authz(w, r, ScopeAdmin, AllDBs, "", true)
	if !ok {
		return
	}
	if !h.refuseMasterMutation(w, r, pr, db) {
		return
	}
	if h.maybeForward(w, r) {
		return
	}
	if r.URL.Query().Get("confirm") != db {
		writeErr(w, 400, "deleting a database is permanent: repeat its name as ?confirm="+db)
		return
	}
	if !h.checkHostSwitchQuota(w, pr) {
		return
	}
	seq, err := h.WriteDropDB(db)
	switch {
	case errors.Is(err, ErrNoDB):
		writeErr(w, 404, "database not found")
	case err != nil:
		h.mapErr(w, err)
	default:
		h.Audit.Log(AuditEvent{Event: "db.drop", DB: db, Remote: remoteIP(r)})
		writeJSON(w, 200, map[string]interface{}{"ok": true, "name": db, "seq": seq})
	}
}
