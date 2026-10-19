package host

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"redx/box"
)

// ---- /v1/owner/*: the owner's view of everything on this host ----
//
// Only owner logins get past ownerAuth. Every request is audit-logged as owner.read (with the acting owner)
// by the authenticator before anything is read. Everyone else gets 403 and nothing about the master database.

func (h *Host) ownerAuth(w http.ResponseWriter, r *http.Request) (*Principal, bool) {
	pr, wait, err := h.Auth.Authenticate(r)
	switch {
	case errors.Is(err, ErrThrottled):
		w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
		writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
		return nil, false
	case err != nil:
		h.authBad.Add(1)
		w.Header().Set("WWW-Authenticate", `Bearer realm="redx"`)
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return nil, false
	}
	if !pr.IsOwner() {
		h.Audit.Log(AuditEvent{Event: "auth.denied", KeyID: pr.Key.ID, Remote: remoteIP(r), Method: r.Method, Route: r.URL.Path, Reason: "not an owner login"})
		if pr.Account != nil && pr.Account.OwnerBlocked != "" {
			// only someone signed in with an owner email ever sees why
			writeJSON(w, 403, map[string]string{"error": "forbidden", "reason": pr.Account.OwnerBlocked,
				"message": "Owner access needs a verified email and a sign-in finished with two-factor authentication."})
			return nil, false
		}
		writeErr(w, 403, "forbidden")
		return nil, false
	}
	return pr, true
}

func (h *Host) ownerRoute(w http.ResponseWriter, r *http.Request) {
	pr, ok := h.ownerAuth(w, r)
	if !ok {
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/owner/"), "/")
	if r.Method == "POST" && strings.HasPrefix(rest, "accounts/") {
		id, action, _ := strings.Cut(strings.TrimPrefix(rest, "accounts/"), "/")
		h.ownerModerate(w, r, pr, id, action)
		return
	}
	if r.Method != "GET" {
		writeErr(w, 405, "method not allowed")
		return
	}
	switch {
	case rest == "overview":
		h.ownerOverview(w, pr)
	case rest == "dbs":
		writeJSON(w, 200, map[string]interface{}{"dbs": h.ownerDBs()})
	case rest == "accounts":
		h.ownerAccounts(w, r, pr)
	case strings.HasPrefix(rest, "accounts/"):
		h.ownerAccount(w, r, pr, strings.TrimPrefix(rest, "accounts/"))
	case rest == "audit":
		h.ownerAudit(w, r)
	default:
		writeErr(w, 404, "not found")
	}
}

type ownerDB struct {
	Name   string             `json:"name"`
	Master bool               `json:"master,omitempty"`
	Stats  map[string]float64 `json:"stats,omitempty"`
}

func (h *Host) ownerDBs() []ownerDB {
	out := []ownerDB{}
	for _, n := range h.Reg.List() {
		d := ownerDB{Name: n, Master: h.IsMasterDB(n)}
		if b, err := h.Reg.Get(n); err == nil {
			d.Stats = b.Stats()
		}
		out = append(out, d)
	}
	return out
}

func (h *Host) ownerOverview(w http.ResponseWriter, pr *Principal) {
	m := h.masterDB()
	accts, _, err := h.readMasterKind("account")
	n := len(accts)
	if err != nil {
		n = -1
	}
	writeJSON(w, 200, map[string]interface{}{"owner": accountView(pr.Account), "master_db": m, "master_exists": h.Reg.Exists(m),
		"accounts": n, "databases": len(h.Reg.List()), "owners_configured": len(h.Cfg.OwnerEmails), "issuer": h.Cfg.AccountsIssuer})
}

// readMasterKind reads every record of one Red-XAI Accounts kind ("<kind>.red-xai.db":Record[ID=*]) from the
// master database and returns them as JSON objects. unreadable counts records that are not boxes.
func (h *Host) readMasterKind(kind string) ([]map[string]interface{}, int, error) {
	db := h.masterDB()
	if db == "" || !h.Reg.Exists(db) {
		return nil, 0, ErrNoDB
	}
	b, err := h.Reg.Get(db)
	if err != nil {
		return nil, 0, err
	}
	file := kind + ".red-xai.db"
	vals, err := b.Query(file + ":Record[ID=*]")
	if errors.Is(err, ErrInvalid) { // engines without the path grammar (the test store) list by prefix
		vals, err = b.Query("prefix:" + file + ":Record")
	}
	if errors.Is(err, ErrNotFound) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	out := make([]map[string]interface{}, 0, len(vals))
	bad := 0
	for _, s := range vals {
		v, err := box.ParseValue(s)
		if err != nil {
			bad++
			continue
		}
		j, err := json.Marshal(v)
		var m map[string]interface{}
		if err != nil || json.Unmarshal(j, &m) != nil || m == nil {
			bad++
			continue
		}
		out = append(out, m)
	}
	return out, bad, nil
}

// ownerAccountFields are the account fields the owner page shows. Secrets (password hash, TOTP secret,
// encrypted phone) are never sent; the date of birth is replaced by the derived age and age band.
var ownerAccountFields = []string{"key", "username", "email", "emailVerified", "roles", "status", "bannedUntilMs", "banReason",
	"twoFactor", "twoFactorState", "phoneMasked", "adultVerified", "adultVerifiedMs", "tosVersion", "tosAcceptedMs", "tosApp",
	"signupApp", "falseInfoWarnedMs", "no2faAckMs", "failedLogins", "lockedUntilMs", "createdMs", "updatedMs"}

func ownerAccountView(m map[string]interface{}, now time.Time) map[string]interface{} {
	out := map[string]interface{}{}
	for _, f := range ownerAccountFields {
		if v, ok := m[f]; ok {
			out[f] = v
		}
	}
	if s, ok := m["dob"].(string); ok { // stored as YYYY-MM-DD by Red-XAI Accounts
		if t, err := time.Parse("2006-01-02", s); err == nil {
			age := AgeOn(t, now)
			out["age"] = age
			if age >= 18 {
				out["ageBand"] = "18plus"
			} else {
				out["ageBand"] = "13to17"
			}
		}
	}
	return out
}

func (h *Host) ownerAccounts(w http.ResponseWriter, r *http.Request, pr *Principal) {
	recs, bad, err := h.readMasterKind("account")
	if errors.Is(err, ErrNoDB) {
		writeJSON(w, 200, map[string]interface{}{"accounts": []interface{}{}, "total": 0, "master_exists": false})
		return
	}
	if err != nil {
		h.mapErr(w, err)
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	now := time.Now()
	var list []map[string]interface{}
	for _, m := range recs {
		v := ownerAccountView(m, now)
		if q != "" {
			hay := strings.ToLower(str(v["key"]) + " " + str(v["username"]) + " " + str(v["email"]))
			if !strings.Contains(hay, q) {
				continue
			}
		}
		list = append(list, v)
	}
	sort.Slice(list, func(i, j int) bool { return num(list[i]["createdMs"]) > num(list[j]["createdMs"]) })
	total := len(list)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := list[offset:end]
	if page == nil {
		page = []map[string]interface{}{}
	}
	h.Audit.Log(AuditEvent{Event: "owner.read", KeyID: pr.Key.ID, Actor: pr.Account.Email, Target: "accounts q=" + truncate(q, 64), Remote: remoteIP(r),
		Detail: strconv.Itoa(len(page)) + " accounts shown"})
	writeJSON(w, 200, map[string]interface{}{"accounts": page, "total": total, "unreadable": bad, "master_exists": true})
}

func (h *Host) ownerAccount(w http.ResponseWriter, r *http.Request, pr *Principal, id string) {
	recs, _, err := h.readMasterKind("account")
	if err != nil && !errors.Is(err, ErrNoDB) {
		h.mapErr(w, err)
		return
	}
	for _, m := range recs {
		if str(m["key"]) == id {
			h.Audit.Log(AuditEvent{Event: "owner.read", KeyID: pr.Key.ID, Actor: pr.Account.Email, Target: "account " + truncate(id, 64), Remote: remoteIP(r)})
			writeJSON(w, 200, ownerAccountView(m, time.Now()))
			return
		}
	}
	writeErr(w, 404, "account not found")
}

// ownerAudit lists the owner trail (owner.* events) from this host's audit log, newest first.
func (h *Host) ownerAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var events []map[string]interface{}
	for _, p := range []string{h.Cfg.AuditLog + ".1", h.Cfg.AuditLog} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var m map[string]interface{}
			if json.Unmarshal(sc.Bytes(), &m) == nil && strings.HasPrefix(str(m["event"]), "owner.") {
				events = append(events, m)
			}
		}
	}
	if len(events) > limit {
		events = events[len(events)-limit:]
	}
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	if events == nil {
		events = []map[string]interface{}{}
	}
	writeJSON(w, 200, map[string]interface{}{"events": events})
}

func str(v interface{}) string { s, _ := v.(string); return s }
func num(v interface{}) float64 {
	f, _ := v.(float64)
	return f
}

var accountIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ownerModerate kicks, bans or terminates a Red-XAI Account through the Red-XAI Accounts owner API, using this
// owner's own access token (granted the "owner" scope). Local console sessions of the account end at once.
//
//	POST /v1/owner/accounts/{id}/kick      {reason}
//	POST /v1/owner/accounts/{id}/ban       {reason, untilMs}   untilMs 0 = forever
//	POST /v1/owner/accounts/{id}/terminate {reason, confirm: "TERMINATE"}
func (h *Host) ownerModerate(w http.ResponseWriter, r *http.Request, pr *Principal, id, action string) {
	if action != "kick" && action != "ban" && action != "terminate" {
		writeErr(w, 404, "not found")
		return
	}
	if !accountIDRe.MatchString(id) {
		writeErr(w, 400, "bad account id")
		return
	}
	var b struct {
		Reason  string `json:"reason"`
		UntilMs int64  `json:"untilMs"`
		Confirm string `json:"confirm"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	b.Reason = strings.TrimSpace(b.Reason)
	switch {
	case b.Reason == "" || len(b.Reason) > 500:
		acctErr(w, 400, "reason_required", "Give a reason (up to 500 characters); the person sees it.")
		return
	case action == "ban" && b.UntilMs < 0, action == "ban" && b.UntilMs != 0 && b.UntilMs < time.Now().UnixMilli():
		acctErr(w, 400, "until_invalid", "The ban must end in the future (or 0 for forever).")
		return
	case action == "terminate" && b.Confirm != "TERMINATE":
		// Red-XAI Accounts only needs {reason}; RedX still requires a typed confirm so the console cannot mis-click.
		acctErr(w, 400, "confirm_required", `Terminating deletes the account in every app: send confirm "TERMINATE".`)
		return
	}
	access, ok := h.ownerAccessToken(r)
	if !ok {
		acctErr(w, 401, "owner_reauth", "Your owner sign-in has expired for moderation. Sign out and sign in again.")
		return
	}
	body := map[string]interface{}{"reason": b.Reason}
	if action == "ban" {
		body["untilMs"] = b.UntilMs
	}
	h.Audit.Log(AuditEvent{Event: "owner.write", KeyID: pr.Key.ID, Actor: pr.Account.Email, Target: action + " account " + id, Remote: remoteIP(r), Detail: truncate(b.Reason, 200)})
	ctx := r.Context()
	st, rb, err := h.oidc.call(ctx, "POST", "/v1/owner/accounts/"+id+"/"+action, body, access, remoteIP(r))
	if err == nil && st >= 200 && st < 300 {
		n := h.accts.endSessionsForSub(id)
		h.Audit.Log(AuditEvent{Event: "account." + action, KeyID: pr.Key.ID, Actor: pr.Account.Email, Target: "account " + id, Detail: strconv.Itoa(n) + " console session(s) ended here"})
	}
	h.relay(w, st, rb, err)
}

// ownerAccessToken returns this owner session's Red-XAI access token, refreshing it when it is about to expire.
func (h *Host) ownerAccessToken(r *http.Request) (string, bool) {
	tok := bearer(r)
	t, ok := h.accts.tokens(tok)
	if !ok {
		return "", false
	}
	if time.Until(t.AccessExp) > 30*time.Second {
		return t.Access, true
	}
	if t.Refresh == "" {
		return "", false
	}
	nt, err := h.oidc.refresh(r.Context(), t.Refresh, remoteIP(r))
	if err != nil || !containsStr(strings.Fields(nt.Scope), OwnerScope) {
		return "", false
	}
	if nt.Refresh == "" {
		nt.Refresh = t.Refresh
	}
	h.accts.setTokens(tok, acctTokens{Access: nt.AccessToken, Refresh: nt.Refresh, AccessExp: time.Now().Add(time.Duration(nt.ExpiresIn) * time.Second)})
	return nt.AccessToken, true
}
