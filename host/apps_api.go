package host

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"redx/billing"
)

// hostedRoute is the tenant app API: create, deploy, domains, secrets, logs.
// Followers proxy to the leader, which is where the runtime and the store live.
func (h *Host) hostedRoute(w http.ResponseWriter, r *http.Request) {
	if h.maybeForward(w, r) {
		return
	}
	if h.apps == nil {
		writeErr(w, 503, "hosted apps are not available")
		return
	}
	p := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/hosted"), "/")
	if p == "tls/ask" && r.Method == http.MethodGet {
		h.hostedTLSAsk(w, r)
		return
	}
	parts := []string{}
	if p != "" {
		parts = strings.Split(p, "/")
	}
	if len(parts) == 1 && parts[0] == "caddy" && r.Method == http.MethodGet {
		h.hostedCaddy(w, r)
		return
	}
	if len(parts) == 0 || parts[0] != "apps" {
		writeErr(w, 404, "not found")
		return
	}
	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		h.hostedList(w, r)
	case len(parts) == 1 && r.Method == http.MethodPost:
		h.hostedCreate(w, r)
	case len(parts) == 2 && r.Method == http.MethodGet:
		h.hostedGet(w, r, parts[1])
	case len(parts) == 2 && r.Method == http.MethodDelete:
		h.hostedDelete(w, r, parts[1])
	case len(parts) == 3 && parts[2] == "deploy" && r.Method == http.MethodPost:
		h.hostedDeploy(w, r, parts[1], nil)
	case len(parts) == 3 && parts[2] == "archive" && r.Method == http.MethodPost:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeErr(w, 400, "invalid archive")
			return
		}
		h.hostedDeploy(w, r, parts[1], body)
	case len(parts) == 3 && parts[2] == "deploys" && r.Method == http.MethodGet:
		h.hostedDeploys(w, r, parts[1])
	case len(parts) == 5 && parts[2] == "deploys" && parts[4] == "manifest" && r.Method == http.MethodGet:
		h.hostedManifest(w, r, parts[1], parts[3])
	case len(parts) == 3 && parts[2] == "rollback" && r.Method == http.MethodPost:
		h.hostedRollback(w, r, parts[1])
	case len(parts) == 3 && parts[2] == "promote" && r.Method == http.MethodPost:
		h.hostedPromote(w, r, parts[1])
	case len(parts) == 3 && parts[2] == "start" && r.Method == http.MethodPost:
		h.hostedPower(w, r, parts[1], true)
	case len(parts) == 3 && parts[2] == "stop" && r.Method == http.MethodPost:
		h.hostedPower(w, r, parts[1], false)
	case len(parts) == 3 && parts[2] == "domains" && r.Method == http.MethodGet:
		h.hostedDomains(w, r, parts[1])
	case len(parts) == 3 && parts[2] == "domains" && r.Method == http.MethodPost:
		h.hostedAddDomain(w, r, parts[1])
	case len(parts) == 4 && parts[2] == "domains" && r.Method == http.MethodDelete:
		h.hostedDelDomain(w, r, parts[1], parts[3])
	case len(parts) == 5 && parts[2] == "domains" && parts[4] == "verify" && r.Method == http.MethodPost:
		h.hostedVerifyDomain(w, r, parts[1], parts[3])
	case len(parts) == 3 && parts[2] == "env" && r.Method == http.MethodGet:
		h.hostedGetEnv(w, r, parts[1])
	case len(parts) == 3 && parts[2] == "env" && r.Method == http.MethodPut:
		h.hostedPutEnv(w, r, parts[1])
	case len(parts) == 3 && parts[2] == "secrets" && r.Method == http.MethodGet:
		h.hostedSecrets(w, r, parts[1])
	case len(parts) == 4 && parts[2] == "secrets" && r.Method == http.MethodPut:
		h.hostedPutSecret(w, r, parts[1], parts[3])
	case len(parts) == 4 && parts[2] == "secrets" && r.Method == http.MethodDelete:
		h.hostedDelSecret(w, r, parts[1], parts[3])
	case len(parts) == 3 && parts[2] == "logs" && r.Method == http.MethodGet:
		h.hostedLogs(w, r, parts[1], false)
	case len(parts) == 4 && parts[2] == "logs" && parts[3] == "download" && r.Method == http.MethodGet:
		h.hostedLogs(w, r, parts[1], true)
	case len(parts) == 3 && parts[2] == "usage" && r.Method == http.MethodGet:
		h.hostedUsage(w, r, parts[1])
	case len(parts) == 3 && parts[2] == "health" && r.Method == http.MethodGet:
		h.hostedHealth(w, r, parts[1])
	default:
		writeErr(w, 404, "not found")
	}
}

type appActor struct {
	pr    *Principal
	sub   string
	all   bool
	mode  string
	known bool
}

func (a appActor) sees(app *hostedApp) bool {
	if app == nil {
		return false
	}
	if a.all {
		return true
	}
	return a.sub != "" && app.Account == a.sub
}

func (a appActor) account() string {
	if a.sub != "" {
		return a.sub
	}
	return "operator"
}

func (h *Host) appActor(w http.ResponseWriter, r *http.Request, write bool) (appActor, bool) {
	need := ScopeRead
	if write {
		need = ScopeWrite
	}
	pr, wait, err := h.Auth.Authenticate(r)
	switch {
	case errors.Is(err, ErrThrottled):
		w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
		writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
		return appActor{}, false
	case err != nil:
		h.authBad.Add(1)
		w.Header().Set("WWW-Authenticate", `Bearer realm="redx"`)
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return appActor{}, false
	}
	act := appActor{pr: pr}
	if pr.IsOwner() || pr.Key.IsHostAdmin() {
		act.all = true
		act.mode = "full"
	} else if sub := pr.tenantSub(); sub != "" {
		act.sub = sub
		act.mode, act.known = h.tenantAccess(sub)
		if !pr.isTenant() && scopeRank[pr.Key.Scope] < scopeRank[need] {
			h.Audit.Log(AuditEvent{Event: "auth.denied", KeyID: pr.Key.ID, Remote: remoteIP(r), Method: r.Method, Route: r.URL.Path, Reason: "scope/db/prefix"})
			writeErr(w, http.StatusForbidden, "forbidden")
			return appActor{}, false
		}
		if write && refusePlan(w, act.mode, true) {
			return appActor{}, false
		}
	} else {
		h.Audit.Log(AuditEvent{Event: "auth.denied", KeyID: pr.Key.ID, Remote: remoteIP(r), Method: r.Method, Route: r.URL.Path, Reason: "scope/db/prefix"})
		writeErr(w, http.StatusForbidden, "forbidden")
		return appActor{}, false
	}
	if !h.checkTrafficQuota(w, pr) {
		return appActor{}, false
	}
	h.notePrincipal(r, pr)
	allowHealth(r)
	if act.all {
		h.auditApp(r, pr, "app.admin", r.URL.Path)
	}
	return act, true
}

func (h *Host) auditApp(r *http.Request, pr *Principal, event, detail string) {
	if h.Audit == nil || pr == nil {
		return
	}
	h.Audit.Log(AuditEvent{Event: event, KeyID: pr.Key.ID, Actor: auditActor(pr), Remote: remoteIP(r), Method: r.Method, Route: r.URL.Path, Detail: detail})
}

func (h *Host) hostedList(w http.ResponseWriter, r *http.Request) {
	act, ok := h.appActor(w, r, false)
	if !ok {
		return
	}
	if !act.all && !act.known && act.mode == "none" {
		h.Audit.Log(AuditEvent{Event: "auth.denied", KeyID: act.pr.Key.ID, Remote: remoteIP(r), Method: r.Method, Route: r.URL.Path, Reason: "scope"})
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	lim := h.appLimit(act.pr)
	h.apps.mu.Lock()
	defer h.apps.mu.Unlock()
	out := []any{}
	var disk int64
	running := 0
	for _, a := range h.apps.apps {
		if !act.sees(a) {
			continue
		}
		out = append(out, h.appSummary(a))
		disk += dirBytes(h.apps.appDir(a.ID))
		if a.Running {
			running++
		}
	}
	body := map[string]any{
		"apps": out, "limits": lim, "usage": map[string]any{"apps": len(out), "diskBytes": disk, "running": running},
		"access": act.mode,
	}
	if act.all && act.sub == "" {
		body["access"] = "operator"
	}
	if act.mode == "none" && act.known {
		body["suspended"] = true
	}
	if act.mode == "readonly" {
		body["readonly"] = true
	}
	writeJSON(w, 200, body)
}

func (h *Host) hostedCreate(w http.ResponseWriter, r *http.Request) {
	act, ok := h.appActor(w, r, true)
	if !ok {
		return
	}
	var req struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
		DB   string `json:"db"`
	}
	if jsonUnmarshal(readBody(r), &req) != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	name := strings.ToLower(strings.TrimSpace(req.Name))
	if !validAppName(name) {
		writeErr(w, 400, "invalid app name")
		return
	}
	kind := req.Kind
	if kind == "" {
		kind = "static"
	}
	if kind != "static" && kind != "container" && kind != "process" {
		writeErr(w, 400, "kind must be static, container or process")
		return
	}
	account := act.account()
	var phys, logical string
	if req.DB != "" {
		var bound bool
		phys, logical, bound = h.bindAppDB(w, r, act, req.DB)
		if !bound {
			return
		}
	}
	lim := h.appLimit(act.pr)
	h.apps.mu.Lock()
	defer h.apps.mu.Unlock()
	if h.apps.count(account) >= lim.MaxApps {
		writeQuotaErr(w, errAppQuota(lim.MaxApps))
		return
	}
	if h.apps.byName(account, name) != nil {
		writeErrCode(w, http.StatusConflict, "name_unavailable", "that app name is not available")
		return
	}
	id := newUpdateID("ha_")
	host := defaultAppHost(name, account, h.apps.zone)
	if _, _, taken := h.apps.domainOwner(host); taken {
		writeErrCode(w, http.StatusConflict, "name_unavailable", "that app name is not available")
		return
	}
	now := time.Now().UTC()
	app := &hostedApp{
		ID: id, Account: account, Name: name, Kind: kind, DB: phys, DBLogical: logical,
		UID:     h.apps.allocUID(account),
		Created: now, Updated: now, HostPort: h.apps.nextPort, Env: map[string]string{},
		Domains: []hostedDomain{{Name: host, Kind: "default", Verified: true, Added: now, VerifiedAt: now}},
	}
	h.apps.nextPort++
	h.apps.apps[id] = app
	if err := h.apps.saveLocked(); err != nil {
		delete(h.apps.apps, id)
		writeErr(w, 500, "internal error")
		return
	}
	h.auditApp(r, act.pr, "app.create", id+" "+name)
	writeJSON(w, http.StatusCreated, h.appView(app, lim))
}

func (h *Host) bindAppDB(w http.ResponseWriter, r *http.Request, act appActor, logical string) (phys, shown string, ok bool) {
	logical = strings.ToLower(strings.TrimSpace(logical))
	if act.sub != "" {
		name, err := TenantPhysicalName(act.sub, logical)
		if err != nil || h.reservedName(logical) {
			writeErr(w, 400, "invalid database name")
			return "", "", false
		}
		if h.IsMasterDB(name) || !h.refuseMasterMutation(w, r, act.pr, name) {
			if h.IsMasterDB(name) {
				h.refuseMasterMutation(w, r, act.pr, name)
			}
			return "", "", false
		}
		handled, allowed := h.allowTenant(w, r, act.pr, ScopeWrite, name, "", false)
		if !allowed {
			if !handled {
				writeErr(w, http.StatusNotFound, "database not found")
			}
			return "", "", false
		}
		if !h.refuseHiddenDB(w, r, act.pr, name) {
			return "", "", false
		}
		if !h.Reg.Exists(name) {
			writeErr(w, http.StatusNotFound, "database not found")
			return "", "", false
		}
		return name, logical, true
	}
	if !ValidDBName(logical) || h.reservedName(logical) {
		writeErr(w, 400, "invalid database name")
		return "", "", false
	}
	if !h.refuseHiddenDB(w, r, act.pr, logical) || !h.refuseMasterMutation(w, r, act.pr, logical) {
		return "", "", false
	}
	if !h.Reg.Exists(logical) {
		writeErr(w, http.StatusNotFound, "database not found")
		return "", "", false
	}
	return logical, logical, true
}

func (h *Host) hostedGet(w http.ResponseWriter, r *http.Request, id string) {
	act, ok := h.appActor(w, r, false)
	if !ok {
		return
	}
	if !act.all && act.mode == "none" && !act.known {
		writeErr(w, http.StatusNotFound, "app not found")
		return
	}
	h.apps.mu.Lock()
	defer h.apps.mu.Unlock()
	app := h.apps.apps[id]
	if !act.sees(app) {
		writeErr(w, http.StatusNotFound, "app not found")
		return
	}
	view := h.appView(app, h.appLimit(act.pr))
	if act.mode == "readonly" {
		view["readonly"] = true
	}
	if act.mode == "none" && act.known {
		view["suspended"] = true
	}
	writeJSON(w, 200, view)
}

func (h *Host) hostedDelete(w http.ResponseWriter, r *http.Request, id string) {
	act, ok := h.appActor(w, r, true)
	if !ok {
		return
	}
	if requireDangerConfirm(w, r) {
		return
	}
	h.apps.mu.Lock()
	app := h.apps.apps[id]
	if !act.sees(app) {
		h.apps.mu.Unlock()
		writeErr(w, http.StatusNotFound, "app not found")
		return
	}
	keyID := app.DBKeyID
	acct := app.Account
	delete(h.apps.apps, id)
	if err := h.apps.saveLocked(); err != nil {
		h.apps.apps[id] = app
		h.apps.mu.Unlock()
		writeErr(w, 500, "internal error")
		return
	}
	h.apps.mu.Unlock()
	h.stopRuntime(acct, id)
	if keyID != "" {
		_, _ = h.KS.Revoke(keyID)
	}
	_ = os.RemoveAll(h.apps.appDir(id))
	h.auditApp(r, act.pr, "app.delete", id)
	writeJSON(w, 200, map[string]any{"ok": true, "id": id})
}

type deployBody struct {
	Source     string   `json:"source"`
	Image      string   `json:"image"`
	Repo       string   `json:"repo"`
	Ref        string   `json:"ref"`
	Dockerfile string   `json:"dockerfile"`
	Strategy   string   `json:"strategy"`
	CanaryPct  int      `json:"canaryPct"`
	Command    []string `json:"command"`
}

func (h *Host) hostedDeploy(w http.ResponseWriter, r *http.Request, id string, archive []byte) {
	act, ok := h.appActor(w, r, true)
	if !ok {
		return
	}
	var body deployBody
	if archive == nil {
		if jsonUnmarshal(readBody(r), &body) != nil {
			writeErr(w, 400, "invalid JSON")
			return
		}
	} else {
		body.Source = "archive"
		body.Strategy = r.URL.Query().Get("strategy")
		if p := r.URL.Query().Get("canaryPct"); p != "" {
			body.CanaryPct, _ = strconv.Atoi(p)
		}
	}
	if body.Strategy == "" {
		body.Strategy = "direct"
	}
	switch body.Strategy {
	case "direct", "canary", "blue_green":
	default:
		writeErr(w, 400, "strategy must be direct, canary or blue_green")
		return
	}
	if body.Strategy == "canary" {
		if body.CanaryPct == 0 {
			body.CanaryPct = 10
		}
		if body.CanaryPct < 1 || body.CanaryPct > 100 {
			writeErr(w, 400, "canaryPct must be 1..100")
			return
		}
	}
	for _, c := range body.Command {
		if c == "" || strings.ContainsAny(c, "\r\n") || len(c) > 200 {
			writeErr(w, 400, "invalid command")
			return
		}
	}
	lim := h.appLimit(act.pr)
	maxDisk := int64(lim.DiskMB) << 20

	h.apps.mu.Lock()
	app := h.apps.apps[id]
	if !act.sees(app) {
		h.apps.mu.Unlock()
		writeErr(w, http.StatusNotFound, "app not found")
		return
	}
	account, kind, db := app.Account, app.Kind, app.DB
	h.apps.mu.Unlock()

	var blob []byte
	var sha, image, repo, ref, source string
	switch {
	case archive != nil:
		source = "archive"
		blob = archive
		sha = sha256Hex(blob)
	case body.Source == "image":
		source = "image"
		if kind == "static" {
			writeErr(w, 400, "a static app takes an archive or a repository, not an image")
			return
		}
		if !validImageRef(body.Image) {
			writeErr(w, 400, "invalid image")
			return
		}
		image = body.Image
		sha = sha256Hex([]byte(image))
		blob = []byte(image + "\n")
	case body.Source == "github" || body.Source == "dockerfile":
		source = body.Source
		if !validRepo(body.Repo) || body.Ref == "" || strings.ContainsAny(body.Ref, " /\\?") {
			writeErr(w, 400, "invalid repository")
			return
		}
		repo, ref = body.Repo, body.Ref
		if body.Source == "dockerfile" {
			file := body.Dockerfile
			if file == "" {
				file = "Dockerfile"
			}
			if !validDockerfile(file) {
				writeErr(w, 400, "invalid dockerfile")
				return
			}
			body.Dockerfile = file
		}
		var err error
		blob, err = h.fetchRepo(repo, ref)
		if err != nil {
			writeErr(w, 400, "could not fetch the repository")
			return
		}
		sha = sha256Hex(blob)
		if source == "dockerfile" {
			image = "localhost/redx-" + id
		}
	default:
		writeErr(w, 400, "source must be archive, github, image or dockerfile")
		return
	}
	if maxDisk > 0 && int64(len(blob)) > maxDisk {
		writeQuotaErr(w, errAppDisk())
		return
	}
	if !h.checkStorageQuota(w, act.pr, int64(len(blob))) {
		return
	}
	if db != "" && account != "operator" && account != "" {
		if !h.tenants.owns(account, db) {
			writeErr(w, http.StatusNotFound, "database not found")
			return
		}
		if !h.refuseHiddenDB(w, r, act.pr, db) || !h.refuseMasterMutation(w, r, act.pr, db) {
			return
		}
	}

	depID := newUpdateID("hd_")
	dest := h.apps.releaseDir(id, depID)
	if source == "image" {
		if err := os.MkdirAll(dest, 0o700); err != nil {
			writeErr(w, 500, "internal error")
			return
		}
		if err := os.WriteFile(filepath.Join(dest, "image.txt"), blob, 0o600); err != nil {
			writeErr(w, 500, "internal error")
			return
		}
	} else if err := extractArchive(blob, dest, maxDisk); err != nil {
		_ = os.RemoveAll(filepath.Join(h.apps.appDir(id), "releases", depID))
		writeErr(w, 400, err.Error())
		return
	}

	now := time.Now().UTC()
	h.apps.mu.Lock()
	app = h.apps.apps[id]
	if !act.sees(app) {
		h.apps.mu.Unlock()
		_ = os.RemoveAll(filepath.Join(h.apps.appDir(id), "releases", depID))
		writeErr(w, http.StatusNotFound, "app not found")
		return
	}
	used := dirBytes(h.apps.appDir(id))
	if maxDisk > 0 && used > maxDisk {
		h.apps.mu.Unlock()
		_ = os.RemoveAll(filepath.Join(h.apps.appDir(id), "releases", depID))
		writeQuotaErr(w, errAppDisk())
		return
	}
	app.Seq++
	dep := hostedDeploy{
		ID: depID, Version: strconv.FormatInt(app.Seq, 10), Sequence: app.Seq, Created: now,
		Source: source, Strategy: body.Strategy, Status: "active", Image: image, Repo: repo, Ref: ref,
		SHA256: sha, CanaryPct: body.CanaryPct, Command: body.Command, Dockerfile: body.Dockerfile, Runtime: "spec-only",
	}
	var snap *hostedSnap
	var err error
	if app.Current != "" {
		snap, err = h.snapshotRelease(app, app.Current, dep.Version, h.apps.releaseDir(id, app.Current))
		if err != nil {
			h.apps.mu.Unlock()
			writeErr(w, 500, "snapshot failed")
			return
		}
		if snap != nil {
			dep.SnapshotID = snap.ID
			app.Snaps = append(app.Snaps, *snap)
		}
	}
	switch body.Strategy {
	case "canary":
		dep.Status = "canary"
		app.Canary = depID
		app.CanaryPct = body.CanaryPct
	case "blue_green":
		dep.Status = "standby"
		app.Standby = depID
	default:
		for i := range app.Deploys {
			if app.Deploys[i].Status == "active" {
				app.Deploys[i].Status = "previous"
			}
		}
		app.Current = depID
		app.Canary, app.CanaryPct, app.Standby = "", 0, ""
	}
	man := buildHostedManifest(app, &dep, sha)
	raw, sig, err := h.signHostedManifest(&man)
	if err != nil {
		h.apps.mu.Unlock()
		writeErr(w, 500, "manifest failed")
		return
	}
	dep.Manifest, dep.Signature = raw, sig
	envPath, err := h.writeEnvFile(app)
	if err != nil {
		h.apps.mu.Unlock()
		writeErr(w, 500, "internal error")
		return
	}
	spec, err := h.specFor(app, &dep, envPath, lim)
	if err != nil {
		h.apps.mu.Unlock()
		writeErr(w, 400, err.Error())
		return
	}
	app.Deploys = append(app.Deploys, dep)
	app.Updated = now
	if err := h.apps.saveLocked(); err != nil {
		h.apps.mu.Unlock()
		writeErr(w, 500, "internal error")
		return
	}
	wasRunning := app.Running
	acct := app.Account
	h.apps.mu.Unlock()

	applied, runErr := h.applyRuntime(spec, containerName(id, dep.Status == "canary"))
	var status, detail string
	if runErr == nil {
		h.apps.mu.Lock()
		var copy hostedApp
		if cur := h.apps.apps[id]; cur != nil {
			copy = *cur
			if applied {
				copy.Running = true
			}
		}
		h.apps.mu.Unlock()
		status, detail = h.probeRelease(&copy)
	}
	h.apps.mu.Lock()
	rolled := false
	app = h.apps.apps[id]
	if app != nil && body.Strategy == "direct" && (runErr != nil || status != "healthy") {
		if d := app.deploy(depID); d != nil {
			d.Status = "unhealthy"
			if detail != "" {
				d.Error = detail
			}
		}
		if restorePreviousDeploy(app, depID) != "" {
			rolled = true
			app.Running = wasRunning
			app.Health = "healthy"
		} else if status != "" {
			app.Health = status
		} else {
			app.Health = "unhealthy"
		}
	} else if app != nil && runErr == nil {
		app.Health = status
		if status == "healthy" && body.Strategy == "direct" {
			app.NeedsRedeploy = false
		}
	}
	if app != nil {
		if d := app.deploy(depID); d != nil {
			if runErr != nil {
				d.Runtime, d.Error = "failed", truncate(runErr.Error(), 300)
			} else if applied && !rolled {
				d.Runtime = "applied"
				app.Running = true
			} else if applied {
				d.Runtime = "applied"
			} else {
				d.Runtime = "spec-only"
			}
		}
		_ = h.apps.saveLocked()
	}
	view := map[string]any{}
	if app != nil {
		view = h.appView(app, lim)
	}
	h.apps.mu.Unlock()
	if rolled && applied {
		h.stopRuntime(acct, id)
	}
	h.noteStorage(act.pr, int64(len(blob)))
	h.apps.appendLog(id, "runtime", "deploy "+depID+" "+source+" "+body.Strategy)
	h.auditApp(r, act.pr, "app.deploy", id+" "+depID+" "+body.Strategy)
	view["deploy"] = depID
	view["runtimeStatus"] = "spec-only"
	if applied {
		view["runtimeStatus"] = "applied"
	}
	if runErr != nil {
		view["runtimeStatus"] = "failed"
		view["runtimeError"] = truncate(runErr.Error(), 300)
	}
	if rolled {
		view["rolledBack"] = true
		view["runtimeStatus"] = "rolled_back"
	}
	writeJSON(w, http.StatusCreated, view)
}

func restorePreviousDeploy(app *hostedApp, failed string) string {
	prev := ""
	prevIdx := -1
	for i := range app.Deploys {
		d := &app.Deploys[i]
		if d.ID == failed {
			continue
		}
		if d.Status == "previous" || d.Status == "active" {
			prev = d.ID
			prevIdx = i
		}
	}
	if prevIdx < 0 {
		return ""
	}
	app.Deploys[prevIdx].Status = "active"
	app.Current = prev
	return prev
}

func (h *Host) fetchRepo(repo, ref string) ([]byte, error) {
	if h.apps.fetch != nil {
		return h.apps.fetch(repo, ref)
	}
	u := "https://codeload.github.com/" + repo + "/tar.gz/" + url.PathEscape(ref)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "redx-hosted")
	if tok := os.Getenv("REDX_GITHUB_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("repository fetch failed")
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

func (h *Host) specFor(app *hostedApp, dep *hostedDeploy, envPath string, lim AppLimit) (runtimeSpec, error) {
	uid := app.UID
	if uid == 0 {
		uid = tenantUnixID(app.Account, h.apps.uidBase, h.apps.uidSpan)
	}
	in := specInput{
		AppID: app.ID, DeployID: dep.ID, Kind: app.Kind, Image: dep.Image, Command: dep.Command,
		HostPort: app.HostPort, EnvFile: envPath, Limit: lim, Seccomp: h.apps.seccomp, Network: h.apps.network,
		Volume: h.apps.releaseDir(app.ID, dep.ID),
		UID:    uid, User: tenantUnixUser(app.Account), DiskMB: lim.DiskMB,
	}
	if dep.Source == "dockerfile" {
		in.BuildCtx = h.apps.releaseDir(app.ID, dep.ID)
		in.BuildFile = dep.Dockerfile
		if in.BuildFile == "" {
			in.BuildFile = "Dockerfile"
		}
		in.Image = ""
	}
	if dep.Status == "canary" {
		in.Canary = true
	}
	return podmanRunArgs(in)
}

func (h *Host) hostedDeploys(w http.ResponseWriter, r *http.Request, id string) {
	act, app, lim, ok := h.readApp(w, r, id)
	if !ok {
		return
	}
	_ = act
	out := []any{}
	for _, d := range app.Deploys {
		out = append(out, deployView(d))
	}
	writeJSON(w, 200, map[string]any{"deploys": out, "current": app.Current, "canary": app.Canary, "standby": app.Standby, "limits": lim})
}

func (h *Host) hostedManifest(w http.ResponseWriter, r *http.Request, id, depID string) {
	_, app, _, ok := h.readApp(w, r, id)
	if !ok {
		return
	}
	d := app.deploy(depID)
	if d == nil || len(d.Manifest) == 0 {
		writeErr(w, http.StatusNotFound, "deploy not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if d.Signature != "" {
		w.Header().Set("X-RedX-Signature", d.Signature)
	}
	w.WriteHeader(200)
	_, _ = w.Write(d.Manifest)
}

func (h *Host) hostedRollback(w http.ResponseWriter, r *http.Request, id string) {
	act, ok := h.appActor(w, r, true)
	if !ok {
		return
	}
	var req struct {
		Deploy   string `json:"deploy"`
		Snapshot string `json:"snapshot"`
	}
	_ = jsonUnmarshal(readBody(r), &req)
	h.apps.mu.Lock()
	defer h.apps.mu.Unlock()
	app := h.apps.apps[id]
	if !act.sees(app) {
		writeErr(w, http.StatusNotFound, "app not found")
		return
	}
	target := req.Deploy
	if target == "" && req.Snapshot != "" {
		for _, s := range app.Snaps {
			if s.ID == req.Snapshot {
				target = s.DeployID
				break
			}
		}
	}
	d := app.deploy(target)
	if d == nil {
		writeErr(w, http.StatusNotFound, "deploy not found")
		return
	}
	if app.Current != "" && app.Current != target {
		if snap, err := h.snapshotRelease(app, app.Current, d.Version, h.apps.releaseDir(id, app.Current)); err == nil && snap != nil {
			app.Snaps = append(app.Snaps, *snap)
		}
	}
	for i := range app.Deploys {
		if app.Deploys[i].ID == target {
			app.Deploys[i].Status = "active"
		} else if app.Deploys[i].Status == "active" || app.Deploys[i].Status == "canary" || app.Deploys[i].Status == "standby" {
			app.Deploys[i].Status = "rolled_back"
		}
	}
	app.Current = target
	app.Canary, app.CanaryPct, app.Standby = "", 0, ""
	app.Updated = time.Now().UTC()
	if err := h.apps.saveLocked(); err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	h.apps.appendLog(id, "runtime", "rollback to "+target)
	h.auditApp(r, act.pr, "app.rollback", id+" "+target)
	writeJSON(w, 200, h.appView(app, h.appLimit(act.pr)))
}

func (h *Host) hostedPromote(w http.ResponseWriter, r *http.Request, id string) {
	act, ok := h.appActor(w, r, true)
	if !ok {
		return
	}
	h.apps.mu.Lock()
	defer h.apps.mu.Unlock()
	app := h.apps.apps[id]
	if !act.sees(app) {
		writeErr(w, http.StatusNotFound, "app not found")
		return
	}
	next := app.Canary
	if next == "" {
		next = app.Standby
	}
	if next == "" {
		writeErr(w, 409, "nothing to promote")
		return
	}
	if app.Current != "" {
		if snap, err := h.snapshotRelease(app, app.Current, "promote", h.apps.releaseDir(id, app.Current)); err == nil && snap != nil {
			app.Snaps = append(app.Snaps, *snap)
		}
	}
	for i := range app.Deploys {
		switch app.Deploys[i].ID {
		case next:
			app.Deploys[i].Status = "active"
		default:
			if app.Deploys[i].Status == "active" {
				app.Deploys[i].Status = "previous"
			}
		}
	}
	app.Current = next
	app.Canary, app.CanaryPct, app.Standby = "", 0, ""
	app.Updated = time.Now().UTC()
	if err := h.apps.saveLocked(); err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	h.auditApp(r, act.pr, "app.promote", id+" "+next)
	writeJSON(w, 200, h.appView(app, h.appLimit(act.pr)))
}

func (h *Host) hostedPower(w http.ResponseWriter, r *http.Request, id string, on bool) {
	act, ok := h.appActor(w, r, true)
	if !ok {
		return
	}
	h.apps.mu.Lock()
	app := h.apps.apps[id]
	if !act.sees(app) {
		h.apps.mu.Unlock()
		writeErr(w, http.StatusNotFound, "app not found")
		return
	}
	if app.Running == on && !(on && app.NeedsRedeploy) {
		view := h.appView(app, h.appLimit(act.pr))
		h.apps.mu.Unlock()
		writeJSON(w, 200, view)
		return
	}
	h.apps.mu.Unlock()
	if !h.checkHostSwitchQuota(w, act.pr) {
		return
	}
	h.apps.mu.Lock()
	defer h.apps.mu.Unlock()
	app = h.apps.apps[id]
	if !act.sees(app) {
		writeErr(w, http.StatusNotFound, "app not found")
		return
	}
	app.Running = on
	app.Updated = time.Now().UTC()
	_ = h.apps.saveLocked()
	if on {
		if env, err := h.writeEnvFile(app); err == nil && app.Current != "" {
			if d := app.deploy(app.Current); d != nil {
				if spec, err := h.specFor(app, d, env, h.appLimit(act.pr)); err == nil {
					h.apps.mu.Unlock()
					applied, runErr := h.applyRuntime(spec, containerName(id, false))
					h.apps.mu.Lock()
					app = h.apps.apps[id]
					if app != nil {
						if d := app.deploy(app.Current); d != nil {
							if runErr != nil {
								d.Runtime, d.Error = "failed", truncate(runErr.Error(), 300)
							} else if applied {
								d.Runtime = "applied"
							}
						}
						app.NeedsRedeploy = false
						_ = h.apps.saveLocked()
					}
				}
			}
		}
		h.apps.appendLog(id, "runtime", "start")
		h.auditApp(r, act.pr, "app.start", id)
	} else {
		acct := app.Account
		h.apps.mu.Unlock()
		h.stopRuntime(acct, id)
		h.apps.mu.Lock()
		h.apps.appendLog(id, "runtime", "stop")
		h.auditApp(r, act.pr, "app.stop", id)
	}
	if app = h.apps.apps[id]; app != nil {
		writeJSON(w, 200, h.appView(app, h.appLimit(act.pr)))
	}
}

func (h *Host) probeRelease(app *hostedApp) (string, string) {
	if app == nil {
		return "unhealthy", "no app"
	}
	if h.apps != nil && h.apps.probe != nil {
		return h.apps.probe(app.ID)
	}
	depID := app.Current
	if depID == "" {
		depID = app.Canary
	}
	if depID == "" {
		return "unhealthy", "no deploy"
	}
	root := releaseWebRoot(h.apps.releaseDir(app.ID, depID))
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		return "unhealthy", "release missing"
	}
	if app.Kind != "static" && app.Running && h.apps.runtime == "podman" && h.apps.apply {
		port := app.HostPort
		if depID == app.Canary {
			port++
		}
		cli := &http.Client{Timeout: 3 * time.Second}
		resp, err := cli.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
		if err != nil {
			return "unhealthy", "health check failed"
		}
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			return "unhealthy", "health check status " + resp.Status
		}
	}
	return "healthy", ""
}

func (h *Host) hostedHealth(w http.ResponseWriter, r *http.Request, id string) {
	_, app, _, ok := h.readApp(w, r, id)
	if !ok {
		return
	}
	status, detail := h.probeRelease(app)
	h.apps.mu.Lock()
	if cur := h.apps.apps[id]; cur != nil {
		cur.Health = status
		_ = h.apps.saveLocked()
	}
	h.apps.mu.Unlock()
	writeJSON(w, 200, map[string]any{"id": id, "health": status, "detail": detail})
}

func (h *Host) hostedUsage(w http.ResponseWriter, r *http.Request, id string) {
	act, app, lim, ok := h.readApp(w, r, id)
	if !ok {
		return
	}
	disk := dirBytes(h.apps.appDir(app.ID))
	out := map[string]any{"id": app.ID, "diskBytes": disk, "limits": lim, "running": app.Running, "deploys": len(app.Deploys)}
	if act.sub != "" && h.billing != nil {
		if st, ok := h.billing.UsageStatusFor(act.sub); ok {
			out["plan"] = st
		}
	}
	writeJSON(w, 200, out)
}

func (h *Host) readApp(w http.ResponseWriter, r *http.Request, id string) (appActor, *hostedApp, AppLimit, bool) {
	act, ok := h.appActor(w, r, false)
	if !ok {
		return appActor{}, nil, AppLimit{}, false
	}
	if !act.all && act.mode == "none" && !act.known {
		writeErr(w, http.StatusNotFound, "app not found")
		return appActor{}, nil, AppLimit{}, false
	}
	h.apps.mu.Lock()
	defer h.apps.mu.Unlock()
	app := h.apps.apps[id]
	if !act.sees(app) {
		writeErr(w, http.StatusNotFound, "app not found")
		return appActor{}, nil, AppLimit{}, false
	}
	return act, app, h.appLimit(act.pr), true
}

func (h *Host) hostedTLSAsk(w http.ResponseWriter, r *http.Request) {
	if !h.tlsAskAllowed(r) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.URL.Query().Get("domain")), "."))
	if host, _, err := net.SplitHostPort(domain); err == nil {
		domain = host
	}
	if domain == "" || strings.Contains(domain, "*") {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	h.apps.mu.Lock()
	_, dom, ok := h.apps.domainOwner(domain)
	h.apps.mu.Unlock()
	if !ok || !dom.Verified {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, 200, map[string]any{"allow": true})
}

func (h *Host) tlsAskAllowed(r *http.Request) bool {
	secret := h.Cfg.AppsTLSAskSecret
	if secret != "" {
		return secretEqual(r.Header.Get("X-RedX-Caddy-Ask"), secret)
	}
	ip := net.ParseIP(socketIP(r))
	return ip != nil && ip.IsLoopback()
}

func (h *Host) hostedCaddy(w http.ResponseWriter, r *http.Request) {
	act, ok := h.appActor(w, r, false)
	if !ok {
		return
	}
	if !act.pr.IsOwner() && !act.pr.Key.IsHostAdmin() {
		if !h.ownerOnlyOK(w, r, act.pr) {
			return
		}
	}
	h.apps.mu.Lock()
	defer h.apps.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "# generated by redxd for %s\n", h.apps.zone)
	b.WriteString("{\n\ton_demand_tls {\n\t\task http://127.0.0.1:7777/v1/hosted/tls/ask\n\t}\n}\n\n")
	b.WriteString("http:// {\n\tredir https://{host}{uri}\n\thandle /.well-known/redx-challenge/* {\n\t\treverse_proxy 127.0.0.1:7777\n\t}\n}\n\n")
	b.WriteString("https:// {\n\ttls {\n\t\ton_demand\n\t}\n\treverse_proxy 127.0.0.1:7777\n}\n")
	b.WriteString("\n# verified names this host will answer for:\n")
	for _, a := range h.apps.apps {
		for _, d := range a.Domains {
			if d.Verified {
				fmt.Fprintf(&b, "# %s -> %s (%s)\n", d.Name, a.ID, a.Account)
			}
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	_, _ = io.WriteString(w, b.String())
}

func (h *Host) serveIfAppHost(w http.ResponseWriter, r *http.Request) bool {
	if h.apps == nil {
		return false
	}
	name := requestHost(r)
	if name == "" || strings.EqualFold(name, "127.0.0.1") || name == "localhost" {
		return false
	}
	h.apps.mu.Lock()
	id, dom, ok := h.apps.domainOwner(name)
	var app *hostedApp
	if ok {
		app = h.apps.apps[id]
	}
	h.apps.mu.Unlock()
	if !ok || app == nil {
		return false
	}
	if h.Cluster != nil && !h.Cluster.IsLeader() {
		h.maybeForward(w, r)
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/.well-known/redx-challenge/") {
		h.serveChallenge(w, r, dom)
		return true
	}
	if !dom.Verified {
		writeErr(w, http.StatusNotFound, "not found")
		return true
	}
	if app.Account != "" && app.Account != "operator" {
		mode, _ := h.tenantAccess(app.Account)
		if mode == "none" {
			writeErrCode(w, http.StatusPaymentRequired, "plan_required", "This RedX Hosted plan is suspended.")
			return true
		}
		if !h.billingTrafficOK(app.Account) {
			writeQuotaErr(w, &billing.ErrQuota{Code: "traffic_quota", HTTP: 429, Message: "This account has used its RedX Hosted traffic for this month."})
			return true
		}
	}
	h.serveAppContent(w, r, app)
	return true
}

func (h *Host) billingTrafficOK(account string) bool {
	if h.billing == nil {
		return true
	}
	p, ok := h.billing.StoredPlan(account)
	if !ok {
		return true
	}
	q, ok := billing.QuotaFor(p.Tier)
	if !ok {
		return true
	}
	return h.billing.Usage().CheckTraffic(account, q, time.Now(), p.PeriodEnd) == nil
}

func (h *Host) serveChallenge(w http.ResponseWriter, r *http.Request, dom hostedDomain) {
	got := strings.TrimPrefix(r.URL.Path, "/.well-known/redx-challenge/")
	got = strings.Trim(got, "/")
	if dom.Token == "" || !secretEqual(got, dom.Token) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	_, _ = io.WriteString(w, dom.Token)
}

func (h *Host) serveAppContent(w http.ResponseWriter, r *http.Request, app *hostedApp) {
	depID := app.Current
	if app.Canary != "" && app.CanaryPct > 0 && canaryHit(r, app.CanaryPct) {
		depID = app.Canary
	}
	if depID == "" {
		writeErr(w, http.StatusServiceUnavailable, "app has no deploy")
		return
	}
	if !app.Running {
		writeErr(w, http.StatusServiceUnavailable, "app is stopped")
		return
	}
	cw := &countWriter{ResponseWriter: w}
	h.apps.appendLog(app.ID, "access", r.Method+" "+r.URL.Path)
	if app.Kind != "static" {
		port := app.HostPort
		if depID == app.Canary {
			port++
		}
		target, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
		if err != nil {
			writeErr(w, 502, "bad upstream")
			return
		}
		httputil.NewSingleHostReverseProxy(target).ServeHTTP(cw, r)
		h.meterApp(app.Account, cw.n)
		return
	}
	root := releaseWebRoot(h.apps.releaseDir(app.ID, depID))
	serveTree(cw, r, root)
	h.meterApp(app.Account, cw.n)
}

type countWriter struct {
	http.ResponseWriter
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	c.n += int64(n)
	return n, err
}

func (c *countWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func canaryHit(r *http.Request, pct int) bool {
	if pct >= 100 {
		return true
	}
	if pct <= 0 {
		return false
	}
	sum := sha256.Sum256([]byte(socketIP(r) + " " + r.URL.Path))
	return int(sum[0])%100 < pct
}

func serveTree(w http.ResponseWriter, r *http.Request, root string) {
	up := strings.TrimPrefix(pathClean(r.URL.Path), "/")
	if up == "" {
		up = "index.html"
	}
	full, err := safeJoin(root, up)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	st, err := os.Stat(full)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if st.IsDir() {
		full, err = safeJoin(root, strings.TrimPrefix(pathClean(r.URL.Path+"/index.html"), "/"))
		if err != nil {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
	}
	http.ServeFile(w, r, full)
}

func pathClean(p string) string {
	if p == "" {
		return "/"
	}
	return "/" + strings.TrimPrefix(strings.ReplaceAll(p, "\\", "/"), "/")
}

func (h *Host) meterApp(account string, n int64) {
	if h.billing == nil || account == "" || account == "operator" || n <= 0 {
		return
	}
	p, ok := h.billing.StoredPlan(account)
	if !ok {
		return
	}
	q, _ := billing.QuotaFor(p.Tier)
	_ = h.billing.Usage().AddTraffic(account, q, n, time.Now(), p.PeriodEnd)
}

func (h *Host) applyRuntime(spec runtimeSpec, name string) (bool, error) {
	if h.apps.runtime != "podman" || !h.apps.apply {
		return false, nil
	}
	if _, err := exec.LookPath(h.apps.podmanBin); err != nil {
		return false, nil
	}
	if len(spec.RunAs) > 0 {
		if _, err := exec.LookPath(spec.RunAs[0]); err != nil {
			return false, fmt.Errorf("sandbox user switch needs %s on PATH", spec.RunAs[0])
		}
		_ = h.ensureTenantUser(spec)
	}
	run := func(args []string) ([]byte, error) {
		cmd := h.podmanCmd(spec, args...)
		cmd.Env = podmanEnv()
		return cmd.CombinedOutput()
	}
	if len(spec.BuildArgs) > 0 {
		out, err := run(spec.BuildArgs)
		if err != nil {
			return false, fmt.Errorf("build: %v: %s", err, truncate(string(out), 240))
		}
	}
	_, _ = run([]string{"rm", "-f", name})
	out, err := run(spec.Args)
	if err != nil {
		return false, fmt.Errorf("run: %v: %s", err, truncate(string(out), 240))
	}
	return true, nil
}

func (h *Host) podmanCmd(spec runtimeSpec, args ...string) *exec.Cmd {
	if len(spec.RunAs) == 0 {
		return exec.Command(h.apps.podmanBin, args...)
	}
	argv := append(append([]string{}, spec.RunAs[1:]...), args...)
	return exec.Command(spec.RunAs[0], argv...)
}

func (h *Host) ensureTenantUser(spec runtimeSpec) error {
	if spec.User == "" || spec.UID <= 0 {
		return nil
	}
	cmd := exec.Command("sudo", "-n", "/usr/local/sbin/redx-app-user", spec.User, strconv.Itoa(spec.UID))
	cmd.Env = podmanEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tenant user: %v: %s", err, truncate(string(out), 200))
	}
	return nil
}

func (h *Host) stopRuntime(account, id string) {
	if h.apps.runtime != "podman" || !h.apps.apply {
		return
	}
	if _, err := exec.LookPath(h.apps.podmanBin); err != nil {
		return
	}
	spec := runtimeSpec{RunAs: []string{"sudo", "-n", "-u", tenantUnixUser(account), "--", h.apps.podmanBin}}
	_, _ = h.podmanCmd(spec, "rm", "-f", containerName(id, false)).CombinedOutput()
	_, _ = h.podmanCmd(spec, "rm", "-f", containerName(id, true)).CombinedOutput()
}

func podmanEnv() []string {
	var out []string
	for _, k := range []string{"PATH", "HOME", "USER", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} {
		if v, ok := os.LookupEnv(k); ok {
			out = append(out, k+"="+v)
		}
	}
	return out
}

func (h *Host) appSummary(a *hostedApp) map[string]any {
	return map[string]any{
		"id": a.ID, "name": a.Name, "account": a.Account, "kind": a.Kind, "running": a.Running,
		"host": a.defaultDomain(), "db": a.DBLogical, "current": a.Current, "created": a.Created,
		"health": a.Health, "uid": a.UID,
	}
}

func (h *Host) appView(a *hostedApp, lim AppLimit) map[string]any {
	deps := []any{}
	var spec map[string]any
	for _, d := range a.Deploys {
		deps = append(deps, deployView(d))
		if d.ID == a.Current || (a.Current == "" && d.ID == a.Canary) {
			if s, err := h.specFor(a, &d, filepath.Join(h.apps.appDir(a.ID), "env"), lim); err == nil {
				s.Applied = d.Runtime == "applied"
				spec = specMap(s)
			}
		}
	}
	return map[string]any{
		"id": a.ID, "name": a.Name, "account": a.Account, "kind": a.Kind, "running": a.Running,
		"host": a.defaultDomain(), "db": a.DBLogical, "dbBound": a.DB != "", "hostPort": a.HostPort,
		"current": a.Current, "canary": a.Canary, "canaryPct": a.CanaryPct, "standby": a.Standby,
		"health": a.Health, "uid": a.UID, "needsRedeploy": a.NeedsRedeploy,
		"created": a.Created, "updated": a.Updated, "deploys": deps, "snapshots": a.Snaps,
		"domains": domainViews(a, h.apps.publicIP), "env": envView(a, h.apps.redxURL),
		"secrets": secretViews(a), "limits": lim, "runtime": spec,
		"diskBytes": dirBytes(h.apps.appDir(a.ID)),
	}
}

func specMap(s runtimeSpec) map[string]any {
	if s.Args == nil {
		s.Args = []string{}
	}
	return map[string]any{
		"engine": s.Engine, "rootless": s.Rootless, "applied": s.Applied, "network": s.Network,
		"seccomp": s.Seccomp, "memoryMB": s.MemoryMB, "cpu": s.CPU, "pids": s.Pids,
		"publish": s.Publish, "image": s.Image, "command": s.Command, "args": s.Args,
		"buildArgs": s.BuildArgs, "runAs": s.RunAs, "uid": s.UID, "user": s.User,
		"cgroupParent": s.CgroupParent, "diskMB": s.DiskMB, "egress": s.Egress, "deny": s.Deny,
		"note": s.Note,
	}
}

func deployView(d hostedDeploy) map[string]any {
	return map[string]any{
		"id": d.ID, "version": d.Version, "sequence": d.Sequence, "created": d.Created,
		"source": d.Source, "strategy": d.Strategy, "status": d.Status, "image": d.Image,
		"repo": d.Repo, "ref": d.Ref, "sha256": d.SHA256, "snapshotId": d.SnapshotID,
		"signature": d.Signature, "runtime": d.Runtime, "error": d.Error, "canaryPct": d.CanaryPct,
	}
}

func domainViews(a *hostedApp, ip string) []any {
	def := a.defaultDomain()
	out := []any{}
	for _, d := range a.Domains {
		out = append(out, domainView(d, def, ip))
	}
	return out
}

func domainView(d hostedDomain, def, ip string) map[string]any {
	v := map[string]any{"name": d.Name, "kind": d.Kind, "verified": d.Verified, "method": d.Method}
	if d.Kind == "custom" {
		recs := []any{
			map[string]string{"type": "CNAME", "name": d.Name, "value": def},
			map[string]string{"type": "TXT", "name": "_redx-challenge." + d.Name, "value": d.Token},
		}
		if ip != "" {
			recs = append(recs, map[string]string{"type": "A", "name": d.Name, "value": ip})
		}
		v["records"] = recs
		v["http"] = map[string]string{"path": "/.well-known/redx-challenge/" + d.Token, "body": d.Token}
		v["token"] = d.Token
	}
	return v
}

func envView(a *hostedApp, redxURL string) map[string]string {
	out := map[string]string{}
	for k, v := range a.Env {
		if k == "REDX_KEY" {
			continue
		}
		out[k] = v
	}
	if redxURL != "" && !blocksGuestURL(redxURL) {
		out["REDX_URL"] = redxURL
	}
	if a.DB != "" {
		out["REDX_DB"] = a.DB
	}
	return out
}

func secretViews(a *hostedApp) []any {
	out := []any{}
	for _, s := range a.Secrets {
		out = append(out, map[string]any{"name": s.Name, "set": true, "value": appsSecretMask, "updated": s.Updated})
	}
	return out
}

func dropDomain(in []hostedDomain, name string) []hostedDomain {
	out := in[:0]
	for _, d := range in {
		if d.Name != name {
			out = append(out, d)
		}
	}
	return out
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func requestHost(r *http.Request) string {
	h := r.Host
	if h == "" {
		h = r.URL.Host
	}
	if name, _, err := net.SplitHostPort(h); err == nil {
		h = name
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
}
