package host

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// activityLog counts requests against the databases one account owns.
// It never stores another account's names. Denied reasons are short and contain no secrets.
type activityLog struct {
	mu sync.Mutex
	by map[string]map[string]*dbActivity // account sub → physical db
}

type dbActivity struct {
	requests int64
	errors   int64
	denied   []deniedRec
}

type deniedRec struct {
	Time   time.Time `json:"time"`
	Status int       `json:"status"`
	Method string    `json:"method"`
	Path   string    `json:"path"`
	Reason string    `json:"reason,omitempty"`
}

func newActivityLog() *activityLog {
	return &activityLog{by: map[string]map[string]*dbActivity{}}
}

// activitySub is the hosted account this caller may see activity for.
// An empty result is not an account (host-admin keys included) and the route refuses it.
func activitySub(pr *Principal) string {
	if pr == nil {
		return ""
	}
	if pr.Account != nil && pr.Account.Sub != "" {
		return pr.Account.Sub
	}
	return pr.Key.Owner
}

func dbFromRequestPath(p string) string {
	const prefix = "/v1/db/"
	if !strings.HasPrefix(p, prefix) {
		return ""
	}
	name, _, _ := strings.Cut(strings.TrimPrefix(p, prefix), "/")
	if !ValidDBName(name) {
		return ""
	}
	return name
}

func cleanActivityReason(s string) string {
	if len(s) > 200 {
		s = s[:200]
	}
	low := strings.ToLower(s)
	if strings.Contains(s, "rxs_") || strings.Contains(s, "rxk_") || strings.Contains(low, "bearer ") || strings.Contains(low, "secret") {
		return ""
	}
	return s
}

func (h *Host) recordActivity(r *http.Request, pr *Principal, cap *statusCapture) {
	if h == nil || h.activity == nil || r == nil || pr == nil || h.tenants == nil {
		return
	}
	sub := activitySub(pr)
	db := ""
	if r.URL != nil {
		db = dbFromRequestPath(r.URL.Path)
	}
	if sub == "" || db == "" || !h.tenants.owns(sub, db) {
		return
	}
	code := 200
	reason := ""
	if cap != nil {
		if cap.code != 0 {
			code = cap.code
		}
		reason = cleanActivityReason(cap.reason)
	}
	path := ""
	if r.URL != nil {
		path = r.URL.Path
		if len(path) > 300 {
			path = path[:300]
		}
	}
	h.activity.add(sub, db, code, r.Method, path, reason)
}

func (a *activityLog) add(sub, db string, status int, method, path, reason string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	per := a.by[sub]
	if per == nil {
		per = map[string]*dbActivity{}
		a.by[sub] = per
	}
	st := per[db]
	if st == nil {
		st = &dbActivity{}
		per[db] = st
	}
	st.requests++
	if status >= 400 {
		st.errors++
	}
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusPaymentRequired, http.StatusTooManyRequests:
		st.denied = append(st.denied, deniedRec{
			Time: time.Now().UTC(), Status: status, Method: method, Path: path, Reason: reason,
		})
		if len(st.denied) > 20 {
			st.denied = append([]deniedRec(nil), st.denied[len(st.denied)-20:]...)
		}
	}
}

func (a *activityLog) copy(sub, db string) (int64, int64, []deniedRec) {
	if a == nil {
		return 0, 0, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.by[sub][db]
	if st == nil {
		return 0, 0, nil
	}
	denied := append([]deniedRec(nil), st.denied...)
	return st.requests, st.errors, denied
}

// hostingActivity is GET /v1/hosting/activity. Only the caller's own databases are returned.
func (h *Host) hostingActivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	pr, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	sub := activitySub(pr)
	if sub == "" {
		writeErrCode(w, http.StatusForbidden, "account_required", "Sign in with your Red-XAI Account to see database activity.")
		return
	}
	allowHealth(r)
	h.notePrincipal(r, pr)
	names := []string{}
	logical := map[string]string{}
	if h.tenants != nil {
		names = h.tenants.list(sub)
		logical = h.tenants.logical(sub)
	}
	dbs := make([]map[string]interface{}, 0, len(names))
	for _, name := range names {
		reqs, errs, denied := h.activity.copy(sub, name)
		if denied == nil {
			denied = []deniedRec{}
		}
		dbs = append(dbs, map[string]interface{}{
			"name": name, "logical": logical[name], "requests": reqs, "errors": errs, "denied": denied,
		})
	}
	writeJSON(w, 200, map[string]interface{}{"dbs": dbs})
}
