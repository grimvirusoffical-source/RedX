package host

// Lifetime certificates and identity-verification flags.
//
// Red-XAI Accounts stores kind rxa-lifetime-cert as the file
// rxa-lifetime-cert.red-xai.db (box Record), the same "<kind>.red-xai.db" shape
// readMasterKind already uses. A box named rxa-lifetime-cert is treated as the
// same kind. Fields: cert_id, pubkey, private_enc, issued, owner_emails,
// sig_id_prefix. private_enc is Red-SecretsXAI ciphertext. It is still a secret:
// responses, audit lines and error text never carry it or any other field of
// the record.
//
// Reads of the whole record are owner-only. An owner is an authenticated
// console session that ownerStatus accepts (REDXAI_OWNER_EMAILS, verified
// email, 2FA, owner scope). The host has no signature-verification path that
// reads pubkey or cert_id, so those fields are not carved out for other
// callers. Keys scoped to the master database (the accounts service) may write
// the record and still may not read it back.
//
// idVerified and idVerifiedMs live on kind rxa-account. Public callers, tenant
// sessions and host-admin keys cannot set or clear them. An owner session can.
// So can the accounts deploy key: an API key (not a console session) whose
// database is exactly the master accounts database.

import (
	"encoding/json"
	"net/http"
	"strings"

	"redx/box"
	"redx/engine/query"
)

const (
	kindLifetimeCert  = "rxa-lifetime-cert"
	kindAccount       = "rxa-account"
	fieldPrivateEnc   = "private_enc"
	fieldIDVerified   = "idVerified"
	fieldIDVerifiedMs = "idVerifiedMs"
)

func kindFile(kind string) string { return kind + ".red-xai.db" }

// namesKind reports whether a BoxQL source or engine path names kind, either as
// the file (short name or "<kind>.red-xai.db") or as the box.
func namesKind(file, boxName, kind string) bool {
	file = strings.Trim(strings.TrimSpace(file), `"`)
	if boxName == kind {
		return true
	}
	return file == kind || file == kindFile(kind)
}

func parsedPath(p string) (box.Path, bool) {
	pp, err := box.ParsePath(strings.TrimSpace(p))
	if err != nil || len(pp.Segs) == 0 && pp.File == "" {
		return box.Path{}, false
	}
	return pp, true
}

func pathNamesKind(p, kind string) bool {
	if pp, ok := parsedPath(p); ok {
		boxName := ""
		if len(pp.Segs) > 0 {
			boxName = pp.Segs[0].Name
		}
		if namesKind(pp.File, boxName, kind) {
			return true
		}
	}
	p = strings.TrimSpace(p)
	return p == kindFile(kind) || strings.HasPrefix(p, kindFile(kind)+":") ||
		p == kind || strings.HasPrefix(p, kind+":") || strings.HasPrefix(p, kind+".red-xai.db")
}

// PathReadsLifetimeSecret reports whether an engine path addresses the
// lifetime-cert kind or the private_enc field.
func PathReadsLifetimeSecret(p string) bool {
	if pathNamesKind(p, kindLifetimeCert) {
		return true
	}
	pp, ok := parsedPath(p)
	if !ok {
		return false
	}
	for _, s := range pp.Segs {
		if s.Name == fieldPrivateEnc {
			return true
		}
	}
	return false
}

func pathNamesAccountFlag(p string) bool {
	if !pathNamesKind(p, kindAccount) {
		return false
	}
	pp, ok := parsedPath(p)
	if !ok {
		return false
	}
	for i, s := range pp.Segs {
		if i == 0 {
			continue
		}
		if s.Name == fieldIDVerified || s.Name == fieldIDVerifiedMs {
			return true
		}
	}
	return false
}

func valueHasKey(v box.Value, keys ...string) bool {
	switch v.Kind {
	case box.KindBox:
		if v.Box == nil {
			return false
		}
		for _, e := range v.Box.Entries() {
			for _, k := range keys {
				if e.Key == k {
					return true
				}
			}
			if valueHasKey(e.Value, keys...) {
				return true
			}
		}
	case box.KindArray:
		for _, e := range v.Arr {
			if valueHasKey(e, keys...) {
				return true
			}
		}
	}
	return false
}

func valueIsLifetimeCert(v box.Value) bool {
	if v.Kind == box.KindArray {
		for _, e := range v.Arr {
			if valueIsLifetimeCert(e) {
				return true
			}
		}
		return false
	}
	if v.Kind != box.KindBox || v.Box == nil {
		return false
	}
	if v.Box.Get(fieldPrivateEnc, 0, false) != nil {
		return true
	}
	if v.Box.Get("cert_id", 0, false) != nil && v.Box.Get("pubkey", 0, false) != nil {
		return true
	}
	for _, e := range v.Box.Entries() {
		if valueIsLifetimeCert(e.Value) {
			return true
		}
	}
	return false
}

func jsonValueHasCert(v interface{}) bool {
	switch t := v.(type) {
	case map[string]interface{}:
		if _, ok := t[fieldPrivateEnc]; ok {
			return true
		}
		if _, ok := t["cert_id"]; ok {
			if _, ok := t["pubkey"]; ok {
				return true
			}
		}
		for _, c := range t {
			if jsonValueHasCert(c) {
				return true
			}
		}
	case []interface{}:
		for _, c := range t {
			if jsonValueHasCert(c) {
				return true
			}
		}
	}
	return false
}

func jsonValueHasAccountFlag(v interface{}) bool {
	switch t := v.(type) {
	case map[string]interface{}:
		if _, ok := t[fieldIDVerified]; ok {
			return true
		}
		if _, ok := t[fieldIDVerifiedMs]; ok {
			return true
		}
		for _, c := range t {
			if jsonValueHasAccountFlag(c) {
				return true
			}
		}
	case []interface{}:
		for _, c := range t {
			if jsonValueHasAccountFlag(c) {
				return true
			}
		}
	}
	return false
}

// TextIsLifetimeCert reports whether s is a lifetime-cert record (or JSON/Box
// text that carries private_enc, or both cert_id and pubkey).
func TextIsLifetimeCert(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if v, err := box.ParseValue(s); err == nil && valueIsLifetimeCert(v) {
		return true
	}
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		var v interface{}
		if json.Unmarshal([]byte(s), &v) == nil && jsonValueHasCert(v) {
			return true
		}
	}
	return false
}

func textHasAccountFlag(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if v, err := box.ParseValue(s); err == nil && valueHasKey(v, fieldIDVerified, fieldIDVerifiedMs) {
		return true
	}
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		var v interface{}
		if json.Unmarshal([]byte(s), &v) == nil && jsonValueHasAccountFlag(v) {
			return true
		}
	}
	return false
}

// AccountFlagWriteForbidden reports whether path/value would set idVerified or
// idVerifiedMs on an rxa-account record.
func AccountFlagWriteForbidden(path, value string) bool {
	if !pathNamesKind(path, kindAccount) {
		return false
	}
	if pathNamesAccountFlag(path) {
		return true
	}
	return textHasAccountFlag(value)
}

// isAccountsDeploy is the Red-XAI Accounts service key: bound to the master
// accounts database, not a console session and not a tenant.
func (h *Host) isAccountsDeploy(pr *Principal) bool {
	if pr == nil || pr.Account != nil || pr.isTenant() {
		return false
	}
	m := h.masterDB()
	return m != "" && pr.Key.DB == m
}

// mayMutateAccountFlags is the deploy/owner path for idVerified and idVerifiedMs.
func (h *Host) mayMutateAccountFlags(pr *Principal) bool {
	return pr != nil && (pr.IsOwner() || h.isAccountsDeploy(pr))
}

// lifetimeCertVisible is false when a non-owner would see the cert kind or private_enc.
func lifetimeCertVisible(pr *Principal, path, value string) bool {
	if pr != nil && pr.IsOwner() {
		return true
	}
	return !PathReadsLifetimeSecret(path) && !TextIsLifetimeCert(value)
}

// redactAuditReason drops any reason that would carry a lifetime-cert body.
// Callers pass static text; this is the backstop for engine errors.
func redactAuditReason(s string) string {
	if strings.Contains(s, fieldPrivateEnc) || TextIsLifetimeCert(s) {
		return "lifetime cert is owner-only"
	}
	return s
}

func (h *Host) denyLifetimeCert(w http.ResponseWriter, r *http.Request, pr *Principal, db string) {
	id := ""
	if pr != nil {
		id = pr.Key.ID
	}
	h.Audit.Log(AuditEvent{Event: "auth.denied", KeyID: id, DB: db, Remote: remoteIP(r), Method: r.Method, Route: routeOf(r), Reason: "lifetime cert is owner-only"})
	writeErr(w, http.StatusForbidden, "forbidden")
}

func (h *Host) denyAccountFlag(w http.ResponseWriter, r *http.Request, pr *Principal, db string) {
	id := ""
	if pr != nil {
		id = pr.Key.ID
	}
	h.Audit.Log(AuditEvent{Event: "auth.denied", KeyID: id, DB: db, Remote: remoteIP(r), Method: r.Method, Route: routeOf(r), Reason: "idVerified is deploy/owner only"})
	writeErr(w, http.StatusForbidden, "forbidden")
}

// queryReadsLifetimeCert is true when a path query explicitly addresses the cert
// kind. A bare "*" is not explicit; callers still scan the rows.
func queryReadsLifetimeCert(q string) bool {
	q = strings.TrimSpace(q)
	if rest, ok := strings.CutPrefix(q, "prefix:"); ok {
		return prefixSelectsCert(strings.TrimSpace(rest))
	}
	if q == "" || q == "*" {
		return false
	}
	return PathReadsLifetimeSecret(q)
}

func prefixSelectsCert(rest string) bool {
	if rest == "" || rest == "*" {
		return false
	}
	rest = strings.TrimSuffix(rest, "*")
	file := kindFile(kindLifetimeCert)
	switch {
	case rest == file || rest == kindLifetimeCert:
		return true
	case strings.HasPrefix(rest, file):
		return true
	case strings.HasPrefix(rest, kindLifetimeCert+":"), strings.HasPrefix(rest, kindLifetimeCert+"."):
		return true
	default:
		return PathReadsLifetimeSecret(rest)
	}
}

// subscribeTargetsCert is true for a subscription aimed at the cert kind.
// A pattern of "*" is not aimed at it; events from that stream are filtered.
func subscribeTargetsCert(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" || path == "*" {
		return false
	}
	if file, _, ok := strings.Cut(path, ":"); ok && namesKind(file, "", kindLifetimeCert) {
		return true
	}
	return prefixSelectsCert(path)
}

func sourceIsKind(s query.Source, kind string) bool {
	return namesKind(s.File, s.Box, kind)
}

func fieldNames(f *query.Field, name string) bool {
	if f == nil {
		return false
	}
	for _, s := range f.Segs {
		if s.Name == name {
			return true
		}
	}
	return false
}

func fieldIsAccountFlag(f *query.Field) bool {
	return fieldNames(f, fieldIDVerified) || fieldNames(f, fieldIDVerifiedMs)
}

func exprReadsPrivateEnc(e query.Expr) bool {
	if e == nil {
		return false
	}
	switch x := e.(type) {
	case *query.Field:
		return fieldNames(x, fieldPrivateEnc)
	case *query.Unary:
		return exprReadsPrivateEnc(x.X)
	case *query.Not:
		return exprReadsPrivateEnc(x.X)
	case *query.Binary:
		return exprReadsPrivateEnc(x.L) || exprReadsPrivateEnc(x.R)
	case *query.In:
		if exprReadsPrivateEnc(x.X) {
			return true
		}
		for _, i := range x.List {
			if exprReadsPrivateEnc(i) {
				return true
			}
		}
	case *query.Starts:
		return exprReadsPrivateEnc(x.X) || exprReadsPrivateEnc(x.Pat)
	case *query.InRange:
		return exprReadsPrivateEnc(x.X) || exprReadsPrivateEnc(x.Lo) || exprReadsPrivateEnc(x.Hi)
	case *query.IsNell:
		return exprReadsPrivateEnc(x.X)
	case *query.Match:
		return fieldNames(x.Field, fieldPrivateEnc) || exprReadsPrivateEnc(x.Terms)
	case *query.ArrLit:
		for _, i := range x.Items {
			if exprReadsPrivateEnc(i) {
				return true
			}
		}
	case *query.RecLit:
		for _, en := range x.Entries {
			if exprReadsPrivateEnc(en.Value) {
				return true
			}
		}
	case *query.Agg:
		return exprReadsPrivateEnc(x.Arg)
	}
	return false
}

func exprHasAccountFlagKey(e query.Expr) bool {
	if e == nil {
		return false
	}
	switch x := e.(type) {
	case *query.RecLit:
		for _, en := range x.Entries {
			if en.Key == fieldIDVerified || en.Key == fieldIDVerifiedMs || exprHasAccountFlagKey(en.Value) {
				return true
			}
		}
	case *query.ArrLit:
		for _, i := range x.Items {
			if exprHasAccountFlagKey(i) {
				return true
			}
		}
	case *query.Unary:
		return exprHasAccountFlagKey(x.X)
	case *query.Not:
		return exprHasAccountFlagKey(x.X)
	case *query.Binary:
		return exprHasAccountFlagKey(x.L) || exprHasAccountFlagKey(x.R)
	}
	return false
}

func projsReadPrivateEnc(items []query.Proj) bool {
	for _, it := range items {
		if exprReadsPrivateEnc(it.Expr) {
			return true
		}
	}
	return false
}

// stmtReadsLifetimeCert reports whether a BoxQL command would read the cert kind
// or the private_enc field. Writes that store the ciphertext are not reads.
func stmtReadsLifetimeCert(st query.Stmt) bool {
	switch s := st.(type) {
	case *query.Get:
		if sourceIsKind(s.From, kindLifetimeCert) || exprReadsPrivateEnc(s.Where) || projsReadPrivateEnc(s.Items) {
			return true
		}
		for _, f := range s.Follows {
			if fieldNames(f.Via, fieldPrivateEnc) {
				return true
			}
		}
		for _, g := range s.Group {
			if exprReadsPrivateEnc(g) {
				return true
			}
		}
		for _, sk := range s.Sort {
			if exprReadsPrivateEnc(sk.Expr) {
				return true
			}
		}
	case *query.Require:
		return sourceIsKind(s.Target, kindLifetimeCert) || exprReadsPrivateEnc(s.Where)
	case *query.Watch:
		if s.Pulse {
			return false
		}
		return sourceIsKind(s.Target, kindLifetimeCert) || exprReadsPrivateEnc(s.Where)
	case *query.Explain:
		return stmtReadsLifetimeCert(s.Inner)
	case *query.Tx:
		for _, c := range s.Stmts {
			if stmtReadsLifetimeCert(c) {
				return true
			}
		}
	case *query.Set:
		if exprReadsPrivateEnc(s.Where) || exprReadsPrivateEnc(s.Replace) {
			return true
		}
		for _, a := range s.Assigns {
			if exprReadsPrivateEnc(a.Value) {
				return true
			}
		}
	case *query.Delete:
		return exprReadsPrivateEnc(s.Where)
	}
	return false
}

// stmtWritesAccountFlag reports whether a BoxQL command would set or clear
// idVerified / idVerifiedMs on rxa-account.
func stmtWritesAccountFlag(st query.Stmt) bool {
	switch s := st.(type) {
	case *query.Set:
		if !sourceIsKind(s.Target, kindAccount) {
			return false
		}
		if exprHasAccountFlagKey(s.Replace) {
			return true
		}
		for _, a := range s.Assigns {
			if fieldIsAccountFlag(a.Target) || exprHasAccountFlagKey(a.Value) {
				return true
			}
		}
	case *query.Add:
		return sourceIsKind(s.Target, kindAccount) && exprHasAccountFlagKey(s.Rec)
	case *query.Delete:
		return sourceIsKind(s.Target, kindAccount) && fieldIsAccountFlag(s.Path)
	case *query.Tx:
		for _, c := range s.Stmts {
			if stmtWritesAccountFlag(c) {
				return true
			}
		}
	}
	return false
}

func guardBoxQL(q string) (readsCert, writesFlag bool) {
	st, _, err := query.Parse(q)
	if err != nil {
		return false, false
	}
	return stmtReadsLifetimeCert(st), stmtWritesAccountFlag(st)
}

func bxLeaksLifetimeCert(res BXResult) bool {
	for _, p := range res.Paths {
		if PathReadsLifetimeSecret(p) {
			return true
		}
	}
	for _, p := range res.Cascaded {
		if PathReadsLifetimeSecret(p) {
			return true
		}
	}
	for _, c := range res.Columns {
		if c == fieldPrivateEnc || strings.HasSuffix(c, "."+fieldPrivateEnc) {
			return true
		}
	}
	for _, row := range res.RowsBox {
		for _, cell := range row {
			if TextIsLifetimeCert(cell) {
				return true
			}
		}
	}
	for _, row := range res.Rows {
		for _, cell := range row {
			if TextIsLifetimeCert(string(cell)) {
				return true
			}
		}
	}
	for _, sub := range res.Results {
		if bxLeaksLifetimeCert(sub) {
			return true
		}
	}
	return false
}

// ScriptCertReadBlocked reports whether a script db_get of record.field would
// read the lifetime cert or private_enc.
func ScriptCertReadBlocked(record, field string) bool {
	if PathReadsLifetimeSecret(record) || PathReadsLifetimeSecret(record+"."+field) {
		return true
	}
	return field == fieldPrivateEnc || strings.HasSuffix(field, "."+fieldPrivateEnc)
}

// holdsLifetimeCert reports whether any open database currently stores the
// lifetime-cert kind. Used so a non-owner backup cannot export it.
func (h *Host) holdsLifetimeCert() bool {
	if h == nil || h.Reg == nil {
		return false
	}
	for _, name := range h.Reg.List() {
		b, err := h.Reg.Get(name)
		if err != nil {
			continue
		}
		if backendHoldsLifetimeCert(b) {
			return true
		}
	}
	return false
}

func backendHoldsLifetimeCert(b Backend) bool {
	queries := []struct {
		q        string
		explicit bool
	}{
		{kindFile(kindLifetimeCert) + ":Record[ID=*]", true},
		{kindFile(kindLifetimeCert) + ":*", true},
		{kindLifetimeCert + "[ID=*]", true},
		{"prefix:" + kindFile(kindLifetimeCert), false},
		{"prefix:" + kindLifetimeCert + ":", false},
	}
	for _, q := range queries {
		vals, err := b.Query(q.q)
		if err != nil || len(vals) == 0 {
			continue
		}
		if q.explicit {
			return true
		}
		for _, v := range vals {
			if TextIsLifetimeCert(v) {
				return true
			}
		}
	}
	return false
}

// codePrincipal is the policy principal plus the owner and accounts-deploy bits
// a script needs. Scripts do not run as an owner unless this session is one.
func (h *Host) codePrincipal(pr *Principal) SecPrincipal {
	sp := secPrincipal(&pr.Key)
	if pr == nil {
		return sp
	}
	sp.Owner = pr.IsOwner()
	sp.AccountsDeploy = h.isAccountsDeploy(pr)
	return sp
}
