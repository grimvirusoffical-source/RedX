package host

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"redx/internal/rsx"
	"sort"
	"strings"
	"sync"
	"time"
)

// Tenant databases are named t<10 hex of sha256(account)>_<logical> so two
// accounts can both ask for "game" and neither learns that the other did.
// Reserved logical names are refused with the same response as a name this
// account cannot take, which does not say whether that name exists.
const tenantNameMax = 50

// reservedLogical are names a tenant may not claim. System databases and the
// words for host-only routes are in this set so a tenant database cannot be
// confused with them. The configured default and the master accounts database
// are reserved as well (see reservedName).
var reservedLogical = map[string]struct{}{
	"default": {}, "admin": {}, "audit": {}, "update": {}, "owner": {},
	"billing": {}, "system": {}, "redx": {}, "keys": {}, "cluster": {},
	"connect": {}, "auth": {}, "master": {}, "redxai_accounts": {},
}

// TenantPhysicalName is the on-disk database name for one account's logical name.
func TenantPhysicalName(account, logical string) (string, error) {
	logical = strings.ToLower(strings.TrimSpace(logical))
	if account == "" || !ValidDBName(logical) || len(logical) > tenantNameMax {
		return "", errors.New("invalid database name")
	}
	sum := rsx.Sha256([]byte("redx-tenant/v1\x00" + account))
	name := "t" + hex.EncodeToString(sum[:5]) + "_" + logical
	if !ValidDBName(name) {
		return "", errors.New("invalid database name")
	}
	return name, nil
}

func (h *Host) reservedName(logical string) bool {
	logical = strings.ToLower(strings.TrimSpace(logical))
	if _, ok := reservedLogical[logical]; ok {
		return true
	}
	if h == nil {
		return false
	}
	if logical == h.Cfg.DefaultDB || logical == h.masterDB() || logical == DefaultAccountsMasterDB {
		return true
	}
	return false
}

// isTenant is a signed-in Red-XAI Account that is not an owner of this host.
// Console sessions only. API keys carry the account on Key.Owner; use tenantSub.
func (p *Principal) isTenant() bool {
	return p != nil && p.Account != nil && p.Account.Sub != "" && !p.IsOwner()
}

// tenantSub is the hosted account this caller belongs to.
// A console session uses Account.Sub. An API key minted for that account uses
// Key.Owner. Owners and host-admin keys are not tenants: an empty result means
// the ordinary key ACL applies and hosted quotas are not enforced.
func (p *Principal) tenantSub() string {
	if p == nil || p.IsOwner() || p.Key.IsHostAdmin() {
		return ""
	}
	if p.Account != nil && p.Account.Sub != "" {
		return p.Account.Sub
	}
	return p.Key.Owner
}

type tenantRec struct {
	Account string    `json:"account"`
	Logical string    `json:"logical"`
	Created time.Time `json:"created"`
}

type tenantFile struct {
	DBs map[string]tenantRec `json:"dbs"`
}

// tenantStore maps physical database name → owning account. Mode 0600.
type tenantStore struct {
	mu   sync.Mutex
	path string
	dbs  map[string]tenantRec
}

func openTenants(path string) (*tenantStore, error) {
	s := &tenantStore{path: path, dbs: map[string]tenantRec{}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if err == nil {
		var f tenantFile
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, err
		}
		if f.DBs != nil {
			s.dbs = f.DBs
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *tenantStore) saveLocked() error {
	if s == nil || s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(tenantFile{DBs: s.dbs}, "", " ")
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

func (s *tenantStore) owns(account, db string) bool {
	if s == nil || account == "" || db == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.dbs[db]
	return ok && r.Account == account
}

func (s *tenantStore) ownerOf(db string) (string, bool) {
	if s == nil {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.dbs[db]
	if !ok {
		return "", false
	}
	return r.Account, true
}

func (s *tenantStore) list(account string) []string {
	out := []string{}
	if s == nil {
		return out
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, r := range s.dbs {
		if r.Account == account {
			out = append(out, name)
		}
	}
	sortStrings(out)
	return out
}

func (s *tenantStore) logical(account string) map[string]string {
	out := map[string]string{}
	if s == nil {
		return out
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, r := range s.dbs {
		if r.Account == account && r.Logical != "" {
			out[name] = r.Logical
		}
	}
	return out
}

func (s *tenantStore) put(name string, r tenantRec) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dbs[name] = r
	return s.saveLocked()
}

func (s *tenantStore) bytes() []byte {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.dbs) == 0 {
		return nil
	}
	b, err := json.MarshalIndent(tenantFile{DBs: s.dbs}, "", " ")
	if err != nil {
		return nil
	}
	return b
}

func (s *tenantStore) forget(name string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.dbs, name)
	_ = s.saveLocked()
}

func sortStrings(a []string) { sort.Strings(a) }

// tenantAccess reports how a signed-in account may use hosted databases.
// known is true when Stripe has a plan row for them (including a lapsed one).
func (h *Host) tenantAccess(account string) (mode string, known bool) {
	if h == nil || h.billing == nil || account == "" {
		return "none", false
	}
	mode = h.billing.AccessFor(account)
	if mode != "none" {
		return mode, true
	}
	return "none", h.billing.KnownAccount(account)
}

// allowTenant authorises a database call made by a hosted tenant.
// A console session with no plan row is not handled (the normal key checks
// then refuse it). An API key whose Owner is a tenant is always handled: a
// lapsed or missing plan is enforced, never skipped. When handled, ok means
// the call may proceed; otherwise the response is already written.
// An API key still has to pass its own scope, database and prefix. The plan
// gate does not widen it to every database the account owns.
func (h *Host) allowTenant(w http.ResponseWriter, r *http.Request, pr *Principal, need, db, path string, hostLevel bool) (handled, ok bool) {
	sub := pr.tenantSub()
	if sub == "" {
		return false, false
	}
	session := pr.isTenant()
	mode, known := h.tenantAccess(sub)
	if session && !known && mode == "none" {
		return false, false
	}
	if hostLevel || db == AllDBs {
		h.Audit.Log(AuditEvent{Event: "auth.denied", KeyID: pr.Key.ID, DB: db, Remote: remoteIP(r), Method: r.Method, Route: routeOf(r), Reason: "tenant is not a host admin"})
		writeErr(w, http.StatusForbidden, "forbidden")
		return true, false
	}
	if !session && !tenantKeyAllows(pr, need, db, path) {
		h.Audit.Log(AuditEvent{Event: "auth.denied", KeyID: pr.Key.ID, DB: db, Remote: remoteIP(r), Method: r.Method, Route: routeOf(r), Reason: "scope/db/prefix"})
		writeErr(w, http.StatusForbidden, "forbidden")
		return true, false
	}
	if db == "" || !h.tenants.owns(sub, db) {
		// Same body as a missing database: do not confirm another tenant's name.
		writeErr(w, http.StatusNotFound, "database not found")
		return true, false
	}
	write := need != ScopeRead && need != ""
	if refusePlan(w, mode, write) {
		return true, false
	}
	if write && !h.checkStorageQuota(w, pr, requestBytes(r, h.Cfg.MaxBodyMB)) {
		return true, false
	}
	return true, true
}

// tenantKeyAllows is the key ACL for a hosted API key. An empty path skips the
// prefix check so authzScope can keep filtering results itself.
func tenantKeyAllows(pr *Principal, need, db, path string) bool {
	if pr == nil {
		return false
	}
	if scopeRank[pr.Key.Scope] < scopeRank[need] {
		return false
	}
	if pr.Key.DB != AllDBs && pr.Key.DB != db {
		return false
	}
	if path != "" && pr.Key.Prefix != "" && !PathHasPrefix(path, pr.Key.Prefix) {
		return false
	}
	return true
}

// refusePlan writes 402 when a hosted account may not perform this call.
// A missing or suspended plan is a refusal, not a reason to skip the gate.
// Returns true when the response was written.
func refusePlan(w http.ResponseWriter, mode string, write bool) bool {
	switch mode {
	case "full":
		return false
	case "readonly":
		if !write {
			return false
		}
		writeErrCode(w, http.StatusPaymentRequired, "plan_readonly",
			"This RedX Hosted plan is read-only until billing is current. Databases are kept.")
		return true
	default:
		writeErrCode(w, http.StatusPaymentRequired, "plan_required",
			"This RedX Hosted plan is suspended. Databases are kept and work again when the plan is active.")
		return true
	}
}

func (h *Host) tenantMayMutate(w http.ResponseWriter, r *http.Request, pr *Principal, db string, delta int64) bool {
	sub := pr.tenantSub()
	if sub == "" {
		return true
	}
	mode, _ := h.tenantAccess(sub)
	if !h.tenants.owns(sub, db) {
		writeErr(w, http.StatusNotFound, "database not found")
		return false
	}
	if refusePlan(w, mode, true) {
		return false
	}
	return h.checkStorageQuota(w, pr, delta)
}

// refuseTenantKeyChange is the plan gate for console key create, revoke and
// rotate. Readonly and suspended plans use the same codes as data-plane writes.
func refuseTenantKeyChange(w http.ResponseWriter, mode string, known, creating bool) bool {
	if mode == "full" {
		return false
	}
	if mode == "readonly" {
		writeErrCode(w, http.StatusPaymentRequired, "plan_readonly",
			"This RedX Hosted plan is read-only until billing is current. Databases are kept.")
		return true
	}
	if known {
		writeErrCode(w, http.StatusPaymentRequired, "plan_required",
			"This RedX Hosted plan is suspended. Databases are kept and work again when the plan is active.")
		return true
	}
	msg := "Choose a RedX Hosted plan to change API keys. Existing databases are kept."
	if creating {
		msg = "Choose a RedX Hosted plan to create an API key. Existing databases are kept."
	}
	writeErrCode(w, http.StatusPaymentRequired, "plan_required", msg)
	return true
}

// tenantKeyMutateOK is the plan gate for key create, revoke, rotate and pairing
// done with a tenant API key. Console sessions use tenantKeys. Host-admin keys
// (no Owner) are unchanged.
func (h *Host) tenantKeyMutateOK(w http.ResponseWriter, pr *Principal) bool {
	sub := pr.tenantSub()
	if sub == "" || pr.isTenant() {
		return true
	}
	mode, _ := h.tenantAccess(sub)
	return !refusePlan(w, mode, true)
}

func (h *Host) accountStorage(account string) int64 {
	if h == nil || h.tenants == nil || account == "" {
		return 0
	}
	var n int64
	root := ""
	if h.Reg != nil {
		root = h.Reg.Root()
	}
	for _, name := range h.tenants.list(account) {
		n += dirBytes(filepath.Join(root, name))
	}
	if h.apps != nil {
		n += h.apps.diskOf(account)
	}
	return n
}

func dirBytes(root string) int64 {
	var n int64
	_ = filepath.Walk(root, func(_ string, fi os.FileInfo, err error) error {
		if err != nil || fi == nil || !fi.Mode().IsRegular() {
			return nil
		}
		n += fi.Size()
		return nil
	})
	return n
}

// ---- create / list / drop / keys for a paying account ----

func (h *Host) tenantCreateDB(w http.ResponseWriter, r *http.Request, pr *Principal) {
	mode, _ := h.tenantAccess(pr.Account.Sub)
	if mode != "full" {
		if mode == "readonly" {
			writeErrCode(w, http.StatusPaymentRequired, "plan_readonly",
				"This RedX Hosted plan is read-only until billing is current. Databases are kept.")
			return
		}
		writeErrCode(w, http.StatusPaymentRequired, "plan_required",
			"Choose a RedX Hosted plan to create a database. Existing databases are kept.")
		return
	}
	if h.maybeForward(w, r) {
		return
	}
	var b struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(readBody(r), &b) != nil || strings.TrimSpace(b.Name) == "" {
		writeErr(w, 400, `body must be {"name": "..."}`)
		return
	}
	logical := strings.ToLower(strings.TrimSpace(b.Name))
	phys, err := TenantPhysicalName(pr.Account.Sub, logical)
	if err != nil {
		writeErr(w, 400, "invalid database name")
		return
	}
	if h.reservedName(logical) || h.IsMasterDB(phys) || phys == h.Cfg.DefaultDB {
		writeErrCode(w, http.StatusConflict, "name_unavailable", "that database name is not available")
		return
	}
	if h.Reg.Exists(phys) {
		if h.tenants.owns(pr.Account.Sub, phys) {
			writeErr(w, http.StatusConflict, "database already exists")
			return
		}
		writeErrCode(w, http.StatusConflict, "name_unavailable", "that database name is not available")
		return
	}
	// Creating a database is not in the dangerous-operation table. The host
	// switch budget is the gate, and it is consumed only when the name is usable.
	if !h.checkHostSwitchQuota(w, pr) {
		return
	}
	if err := h.tenants.put(phys, tenantRec{Account: pr.Account.Sub, Logical: logical, Created: time.Now().UTC()}); err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	seq, err := h.WriteCreateDB(phys)
	if err != nil {
		h.tenants.forget(phys)
		if errors.Is(err, ErrDBExists) {
			writeErrCode(w, http.StatusConflict, "name_unavailable", "that database name is not available")
			return
		}
		h.mapErr(w, err)
		return
	}
	h.Audit.Log(AuditEvent{Event: "db.create", KeyID: pr.Key.ID, Actor: pr.Account.Sub, DB: phys, Remote: remoteIP(r), Detail: "logical " + logical})
	writeJSON(w, http.StatusCreated, map[string]interface{}{"ok": true, "name": phys, "logical": logical, "seq": seq})
}

func (h *Host) tenantListDBs(w http.ResponseWriter, r *http.Request, pr *Principal) {
	mode, known := h.tenantAccess(pr.Account.Sub)
	if !known && mode == "none" {
		h.Audit.Log(AuditEvent{Event: "auth.denied", KeyID: pr.Key.ID, DB: AllDBs, Remote: remoteIP(r), Method: r.Method, Route: routeOf(r), Reason: "scope"})
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if !h.checkTrafficQuota(w, pr) {
		return
	}
	names := h.tenants.list(pr.Account.Sub)
	out := map[string]interface{}{"dbs": names, "logical": h.tenants.logical(pr.Account.Sub)}
	if mode == "none" {
		out["suspended"] = true
	}
	if mode == "readonly" {
		out["readonly"] = true
	}
	allowHealth(r)
	h.notePrincipal(r, pr)
	writeJSON(w, 200, out)
}

func (h *Host) tenantDropDB(w http.ResponseWriter, r *http.Request, pr *Principal, db string) {
	if !h.tenants.owns(pr.Account.Sub, db) {
		writeErr(w, http.StatusNotFound, "database not found")
		return
	}
	mode, known := h.tenantAccess(pr.Account.Sub)
	if mode != "full" {
		if mode == "readonly" {
			writeErrCode(w, http.StatusPaymentRequired, "plan_readonly",
				"This RedX Hosted plan is read-only until billing is current. Databases are kept.")
		} else if known {
			writeErrCode(w, http.StatusPaymentRequired, "plan_required",
				"This RedX Hosted plan is suspended. Databases are kept and are not deleted.")
		} else {
			writeErrCode(w, http.StatusPaymentRequired, "plan_required",
				"Choose a RedX Hosted plan to create a database. Existing databases are kept.")
		}
		return
	}
	if requireDangerConfirm(w, r) {
		return
	}
	if r.URL.Query().Get("confirm") != db {
		writeErr(w, 400, "deleting a database is permanent: repeat its name as ?confirm="+db)
		return
	}
	if h.maybeForward(w, r) {
		return
	}
	if !h.checkHostSwitchQuota(w, pr) {
		return
	}
	seq, err := h.WriteDropDB(db)
	if err != nil {
		if errors.Is(err, ErrNoDB) {
			h.tenants.forget(db)
			writeErr(w, 404, "database not found")
			return
		}
		h.mapErr(w, err)
		return
	}
	h.tenants.forget(db)
	h.Audit.Log(AuditEvent{Event: "db.drop", KeyID: pr.Key.ID, Actor: pr.Account.Sub, DB: db, Remote: remoteIP(r)})
	writeJSON(w, 200, map[string]interface{}{"ok": true, "name": db, "seq": seq})
}

func (h *Host) tenantKeys(w http.ResponseWriter, r *http.Request, pr *Principal) {
	mode, known := h.tenantAccess(pr.Account.Sub)
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/keys"), "/")
	creating := rest == "" && r.Method == "POST"
	if !creating && !known && mode == "none" {
		h.Audit.Log(AuditEvent{Event: "auth.denied", KeyID: pr.Key.ID, Remote: remoteIP(r), Route: r.URL.Path, Reason: "admin required"})
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	allowHealth(r)
	h.notePrincipal(r, pr)
	now := time.Now()
	ownsKey := func(k KeyRecord) bool {
		if k.DB == AllDBs || k.IsHostAdmin() {
			return false
		}
		if k.Owner != "" && k.Owner != pr.Account.Sub {
			return false
		}
		return h.tenants.owns(pr.Account.Sub, k.DB)
	}
	switch {
	case rest == "" && r.Method == "GET":
		out := []KeyView{}
		for _, k := range h.KS.List() {
			if ownsKey(k) {
				out = append(out, viewOf(k, now))
			}
		}
		writeJSON(w, 200, map[string]interface{}{"keys": out})
	case rest == "" && r.Method == "POST":
		if refuseTenantKeyChange(w, mode, known, true) {
			return
		}
		var req createKeyReq
		if json.Unmarshal(readBody(r), &req) != nil {
			writeErr(w, 400, "invalid JSON")
			return
		}
		if req.DB == "" {
			mine := h.tenants.list(pr.Account.Sub)
			if len(mine) == 1 {
				req.DB = mine[0]
			}
		}
		if req.DB == "" || req.DB == AllDBs || !h.tenants.owns(pr.Account.Sub, req.DB) {
			writeErr(w, http.StatusNotFound, "database not found")
			return
		}
		if req.Scope != ScopeRead && req.Scope != ScopeWrite && req.Scope != ScopeAdmin {
			writeErr(w, 400, "scope must be read|write|admin")
			return
		}
		if requireDangerConfirm(w, r) {
			return
		}
		ttl, err := ParseTTL(req.TTL)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		if h.maybeForward(w, r) {
			return
		}
		key, rec, err := h.KS.Create(CreateSpec{DB: req.DB, Scope: req.Scope, Prefix: req.Prefix, Label: req.Label, Roles: req.Roles, TTL: ttl, RateRPS: req.RateRPS, RateBurst: req.RateBurst, Owner: pr.Account.Sub})
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		h.Audit.Log(AuditEvent{Event: "key.create", KeyID: pr.Key.ID, Actor: pr.Account.Sub, DB: rec.DB, Remote: remoteIP(r), Detail: "new key " + rec.ID + " scope " + rec.Scope})
		writeJSON(w, http.StatusCreated, map[string]interface{}{"key": key, "id": rec.ID, "info": viewOf(rec, now), "warning": "this is the only time the key is shown; store it now"})
	case rest == "pairing" && r.Method == "POST":
		writeErr(w, http.StatusForbidden, "forbidden")
	default:
		parts := strings.Split(rest, "/")
		id := parts[0]
		target, found := h.KS.Get(id)
		if !found || !ownsKey(target) {
			writeErr(w, 404, "key not found")
			return
		}
		if len(parts) == 1 && r.Method == "GET" {
			writeJSON(w, 200, viewOf(target, now))
			return
		}
		if refuseTenantKeyChange(w, mode, known, false) {
			return
		}
		if requireDangerConfirm(w, r) {
			return
		}
		switch {
		case len(parts) == 1 && r.Method == "DELETE":
			if h.maybeForward(w, r) {
				return
			}
			rec, err := h.KS.Revoke(id)
			if err != nil {
				writeErr(w, 500, "internal error")
				return
			}
			h.Audit.Log(AuditEvent{Event: "key.revoke", KeyID: pr.Key.ID, Actor: pr.Account.Sub, DB: rec.DB, Remote: remoteIP(r), Detail: "revoked " + id})
			writeJSON(w, 200, viewOf(rec, now))
		case len(parts) == 2 && parts[1] == "rotate" && r.Method == "POST":
			var req struct {
				Grace string `json:"grace"`
			}
			_ = json.Unmarshal(readBody(r), &req)
			grace, err := ParseTTL(req.Grace)
			if err != nil {
				writeErr(w, 400, err.Error())
				return
			}
			if h.maybeForward(w, r) {
				return
			}
			key, rec, err := h.KS.Rotate(id, grace)
			if err != nil {
				writeErr(w, 409, err.Error())
				return
			}
			h.Audit.Log(AuditEvent{Event: "key.rotate", KeyID: pr.Key.ID, Actor: pr.Account.Sub, DB: rec.DB, Remote: remoteIP(r), Detail: "rotated " + id + " -> " + rec.ID})
			writeJSON(w, http.StatusCreated, map[string]interface{}{"key": key, "id": rec.ID, "info": viewOf(rec, now), "replaces": id, "warning": "this is the only time the key is shown; store it now"})
		default:
			writeErr(w, 405, "method not allowed")
		}
	}
}
