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
// The request string is not enough. An empty-file query (*.pubkey, Record[ID=1].*)
// and a no-file REST get (Record[ID=1].pubkey, while that box is unique) resolve
// to the cert file without naming it. Link expand (?resolve=1) can return one
// field of the cert, or the ciphertext, from a path that only names the link.
// Those reads are owner-only when the stored file, box, or followed target is
// the cert kind. A single field string is not a cert body, so the gate uses
// the resolved path, not TextIsLifetimeCert alone.
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

// fileNamesKind reports whether a file name is kind under the engine's own
// resolution. route and resolveFile pick a stored file when the name is exact
// or the stored name starts with "<name>.". The canonical file is
// "<kind>.red-xai.db", so both rxa-lifetime-cert and rxa-lifetime-cert.red-xai
// address that file (the next character in the stored name is a dot). A stem
// the engine would not select, such as rxa-lifetime or rxa-lifetime-cert.red,
// does not.
func fileNamesKind(file, kind string) bool {
	file = strings.Trim(strings.TrimSpace(file), `"`)
	if file == "" {
		return false
	}
	if file == kind || file == kindFile(kind) {
		return true
	}
	return strings.HasPrefix(kindFile(kind), file+".")
}

// namesKind reports whether a BoxQL source or engine path names kind, either as
// the file (including an engine prefix of "<kind>.red-xai.db") or as the box.
func namesKind(file, boxName, kind string) bool {
	if boxName == kind {
		return true
	}
	return fileNamesKind(file, kind)
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
	file := strings.TrimSpace(p)
	if i := strings.IndexByte(file, ':'); i >= 0 {
		file = file[:i]
	}
	return fileNamesKind(file, kind)
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

// certExpandFeeds reports whether a link substituted at field path from
// (dot-separated entry keys, "" for the record value itself) is part of the
// value selected by sub. One path being a prefix of the other counts: reading
// Cert.pubkey uses the link at Cert, and reading the whole record uses every link.
//
// An array element is recorded as Name[0] (and Name[0][1] when that element is
// itself an array). An entry that carries an ID is recorded as Name[ID=n], and
// an array element under it as Name[ID=n][0]. The HTTP path names the field,
// so Bag selects Bag[0] and Bag[ID=n][0], and Wrap.Bag selects Wrap[ID=n].Bag[0].
func certExpandFeeds(sub []box.Seg, from string) bool {
	if from == "" {
		return true
	}
	parts := strings.Split(from, ".")
	n := len(sub)
	if len(parts) < n {
		n = len(parts)
	}
	for i := 0; i < n; i++ {
		if !expandStepMatches(sub[i], parts[i]) {
			return false
		}
	}
	return true
}

// expandStepMatches reports whether a request segment selects a recorded
// expand step. Equality is the box-field case. A numeric [n] suffix (one or
// more) is an array index inside that field, not a different name. Lookup of
// a bare field name still returns an entry stored as Name[ID=n], so that
// attribute is part of the same field. A request that already names an ID
// selects only that ID.
func expandStepMatches(seg box.Seg, part string) bool {
	label := seg.String()
	if label == part {
		return true
	}
	if label == "" || !strings.HasPrefix(part, label) {
		return false
	}
	rest := part[len(label):]
	if !seg.HasID && !seg.AnyID {
		if trimmed, ok := stripRecordedID(rest); ok {
			rest = trimmed
		}
	}
	return onlyNumericIndexes(rest)
}

// stripRecordedID removes one leading [ID=n] entry attribute. The expander
// records keys with EKey.String, which writes ID in that form. A lowercase
// id= attribute in the step counts the same way.
func stripRecordedID(rest string) (string, bool) {
	if len(rest) < 5 || rest[0] != '[' {
		return "", false
	}
	end := strings.IndexByte(rest, ']')
	if end < 0 {
		return "", false
	}
	inner := rest[1:end]
	key, val, ok := strings.Cut(inner, "=")
	if !ok || !strings.EqualFold(key, "ID") || val == "" {
		return "", false
	}
	for _, c := range val {
		if c < '0' || c > '9' {
			return "", false
		}
	}
	return rest[end+1:], true
}

// onlyNumericIndexes reports whether rest is empty or a sequence of [n] array
// indexes and nothing else.
func onlyNumericIndexes(rest string) bool {
	for len(rest) > 0 {
		if rest[0] != '[' {
			return false
		}
		end := strings.IndexByte(rest, ']')
		if end < 2 {
			return false
		}
		for _, c := range rest[1:end] {
			if c < '0' || c > '9' {
				return false
			}
		}
		rest = rest[end+1:]
	}
	return true
}

// resolveReadsCert reports whether a resolve expansion copied a cert field
// into the value the request selected.
func resolveReadsCert(request string, reads []ResolvedRead) bool {
	var sub []box.Seg
	if pp, ok := parsedPath(request); ok && len(pp.Segs) > 1 {
		sub = pp.Segs[1:]
	}
	for _, rd := range reads {
		if certExpandFeeds(sub, rd.Path) && PathReadsLifetimeSecret(rd.Target) {
			return true
		}
	}
	return false
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
	file := rest
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		file = rest[:i]
	}
	if fileNamesKind(file, kindLifetimeCert) {
		return true
	}
	return PathReadsLifetimeSecret(rest)
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
	for _, p := range res.Followed {
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
