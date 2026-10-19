package host

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Pairing codes sign another device in to the console without putting a key in a QR code, a link or a screenshot.
//
//	POST /v1/keys/pairing   (admin key)  {db, scope, label, ttl, ...}  ->  {code, expires_in_seconds}
//	POST /v1/pair/exchange  (no key)     {code}                         ->  {key, id, info}
//
// A code is random (50 bits), lives for 5 minutes, works once, and exists only in this process's memory (only a SHA-256
// of it is kept). The key is created when the code is redeemed, so an unused code leaves nothing behind to revoke. The
// leader issues and redeems codes (a follower answers 409). Failed redemptions are rate limited per client and overall.
const (
	pairTTL        = 5 * time.Minute
	pairMaxPending = 20
	pairFailWindow = time.Minute
	pairFailPerIP  = 8
	pairFailTotal  = 40
	signinAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no 0/O/1/I
)

type pairEntry struct {
	spec    CreateSpec
	by      string // issuing key id
	expires time.Time
}

type pairStore struct {
	mu      sync.Mutex
	pending map[[32]byte]pairEntry
	fails   map[string][]time.Time // client -> recent failures
	all     []time.Time
	now     func() time.Time
}

func (p *pairStore) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

func newSignInCode() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, 0, 13)
	for i, c := range b {
		if i == 5 {
			out = append(out, '-')
		}
		out = append(out, signinAlphabet[int(c)%len(signinAlphabet)])
	}
	return "RP-" + string(out), nil
}

// normPairCode accepts what a person types: any case, spaces, a missing prefix or dashes.
func normPairCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.NewReplacer(" ", "", "-", "", "_", "").Replace(s)
	s = strings.TrimPrefix(s, "RP")
	if len(s) != 10 {
		return ""
	}
	return "RP-" + s[:5] + "-" + s[5:]
}

func (p *pairStore) prune(now time.Time) {
	for k, e := range p.pending {
		if !now.Before(e.expires) {
			delete(p.pending, k)
		}
	}
	cut := now.Add(-pairFailWindow)
	trim := func(in []time.Time) []time.Time {
		i := 0
		for i < len(in) && in[i].Before(cut) {
			i++
		}
		return in[i:]
	}
	p.all = trim(p.all)
	for c, l := range p.fails {
		if l = trim(l); len(l) == 0 {
			delete(p.fails, c)
		} else {
			p.fails[c] = l
		}
	}
}

// issue stores a pending spec and returns its code.
func (p *pairStore) issue(spec CreateSpec, by string) (string, time.Time, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.clock()
	if p.pending == nil {
		p.pending = map[[32]byte]pairEntry{}
	}
	p.prune(now)
	if len(p.pending) >= pairMaxPending {
		return "", time.Time{}, false
	}
	code, err := newSignInCode()
	if err != nil {
		return "", time.Time{}, false
	}
	e := pairEntry{spec: spec, by: by, expires: now.Add(pairTTL)}
	p.pending[sha256.Sum256([]byte(code))] = e
	return code, e.expires, true
}

type pairResult int

const (
	pairOK pairResult = iota
	pairBad
	pairThrottled
)

// redeem consumes a code. The entry is deleted before the key is made, so a code can never be used twice.
func (p *pairStore) redeem(code, client string) (pairEntry, pairResult) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.clock()
	p.prune(now)
	if len(p.fails[client]) >= pairFailPerIP || len(p.all) >= pairFailTotal {
		return pairEntry{}, pairThrottled
	}
	if n := normPairCode(code); n != "" {
		k := sha256.Sum256([]byte(n))
		if e, ok := p.pending[k]; ok {
			delete(p.pending, k)
			return e, pairOK
		}
	}
	if p.fails == nil {
		p.fails = map[string][]time.Time{}
	}
	p.fails[client] = append(p.fails[client], now)
	p.all = append(p.all, now)
	return pairEntry{}, pairBad
}

func (p *pairStore) pendingCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prune(p.clock())
	return len(p.pending)
}

// pairingIssue handles POST /v1/keys/pairing for an authenticated admin (the caller has already checked the scope).
func (h *Host) pairingIssue(w http.ResponseWriter, r *http.Request, pr *Principal) {
	var req createKeyReq
	if json.Unmarshal(readBody(r), &req) != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	if req.DB == "" {
		req.DB = pr.Key.DB
	}
	if !canManage(pr, req.DB) {
		h.Audit.Log(AuditEvent{Event: "auth.denied", KeyID: pr.Key.ID, DB: req.DB, Remote: remoteIP(r), Reason: "cannot manage that db"})
		writeErr(w, 403, "forbidden")
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
	if !h.Cluster.IsLeader() {
		writeErr(w, 409, "pairing codes are made on the leader ("+h.Cluster.LeaderURL()+"); open the console there")
		return
	}
	spec := CreateSpec{DB: req.DB, Scope: req.Scope, Prefix: req.Prefix, Label: req.Label, Roles: req.Roles, TTL: ttl, RateRPS: req.RateRPS, RateBurst: req.RateBurst}
	if spec.Label == "" {
		spec.Label = "paired device"
	}
	// Validate the spec now so a bad scope/db fails here, not when the code is redeemed.
	if err := validatePairSpec(spec); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	code, exp, ok := h.pair.issue(spec, pr.Key.ID)
	if !ok {
		writeErr(w, 429, "too many unused pairing codes; wait for them to expire")
		return
	}
	h.Audit.Log(AuditEvent{Event: "pair.create", KeyID: pr.Key.ID, DB: spec.DB, Remote: remoteIP(r), Detail: "pairing code for scope " + spec.Scope})
	writeJSON(w, 201, map[string]interface{}{"code": code, "expires_in_seconds": int(time.Until(exp).Round(time.Second) / time.Second), "scope": spec.Scope, "db": spec.DB,
		"note": "single use; the key is created when the code is redeemed"})
}

func validatePairSpec(spec CreateSpec) error {
	switch spec.Scope {
	case ScopeRead, ScopeWrite, ScopeAdmin:
	default:
		return errBadScope
	}
	if spec.DB != AllDBs && !ValidDBName(spec.DB) {
		return errBadDB
	}
	return nil
}

// pairExchange handles POST /v1/pair/exchange: no key needed, the code is the credential.
func (h *Host) pairExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		writeErr(w, 405, "method not allowed")
		return
	}
	if !h.Cluster.IsLeader() {
		writeErr(w, 409, "this node is a follower; open the pairing link on the leader ("+h.Cluster.LeaderURL()+")")
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(readBody(r), &req) != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	ip := remoteIP(r)
	e, res := h.pair.redeem(req.Code, ip)
	switch res {
	case pairThrottled:
		w.Header().Set("Retry-After", "60")
		h.Audit.Log(AuditEvent{Event: "pair.throttled", Remote: ip, Reason: "too many bad codes"})
		writeErr(w, 429, "too many wrong codes; wait a minute")
		return
	case pairBad:
		h.authBad.Add(1)
		h.Audit.Log(AuditEvent{Event: "pair.fail", Remote: ip, Reason: "unknown, used or expired code"})
		writeErr(w, 401, "that pairing code is not valid (it may have expired or been used); make a new one")
		return
	}
	key, rec, err := h.KS.Create(e.spec)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	h.Audit.Log(AuditEvent{Event: "pair.redeem", KeyID: e.by, DB: rec.DB, Remote: ip, Detail: "new key " + rec.ID + " scope " + rec.Scope})
	writeJSON(w, 201, map[string]interface{}{"key": key, "id": rec.ID, "info": viewOf(rec, time.Now()), "warning": "this is the only time the key is shown; store it now"})
}

var (
	errBadScope = pairErr("scope must be read, write or admin")
	errBadDB    = pairErr("invalid database name")
)

type pairErr string

func (e pairErr) Error() string { return string(e) }
