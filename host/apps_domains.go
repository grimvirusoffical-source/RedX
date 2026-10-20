package host

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (h *Host) hostedDomains(w http.ResponseWriter, r *http.Request, id string) {
	_, app, _, ok := h.readApp(w, r, id)
	if !ok {
		return
	}
	writeJSON(w, 200, map[string]any{"domains": domainViews(app, h.apps.publicIP)})
}

func (h *Host) hostedAddDomain(w http.ResponseWriter, r *http.Request, id string) {
	act, ok := h.appActor(w, r, true)
	if !ok {
		return
	}
	var req struct {
		Domain string `json:"domain"`
		Method string `json:"method"`
	}
	if jsonUnmarshal(readBody(r), &req) != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(req.Domain), "."))
	if err := validDomain(name, h.apps.zone); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	method := req.Method
	if method == "" {
		method = "txt"
	}
	if method != "txt" && method != "cname" && method != "http" {
		writeErr(w, 400, "method must be txt, cname or http")
		return
	}
	h.apps.mu.Lock()
	defer h.apps.mu.Unlock()
	app := h.apps.apps[id]
	if !act.sees(app) {
		writeErr(w, http.StatusNotFound, "app not found")
		return
	}
	if owner, dom, taken := h.apps.domainOwner(name); taken && owner != id {
		if dom.Verified || time.Since(dom.Added) < appsClaimTTL {
			writeErrCode(w, http.StatusConflict, "domain_taken", "that domain is not available")
			return
		}
		if other := h.apps.apps[owner]; other != nil {
			other.Domains = dropDomain(other.Domains, name)
		}
	}
	lim := h.appLimit(act.pr)
	custom := 0
	replacing := false
	for _, d := range app.Domains {
		if d.Kind != "custom" {
			continue
		}
		if d.Name == name {
			replacing = true
			continue
		}
		custom++
	}
	if !replacing && lim.Domains >= 0 && custom >= lim.Domains {
		writeQuotaErr(w, errDomainQuota(lim.Domains))
		return
	}
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	token := hex.EncodeToString(buf)
	now := time.Now().UTC()
	updated := false
	for i := range app.Domains {
		if app.Domains[i].Name == name {
			app.Domains[i].Method = method
			app.Domains[i].Token = token
			app.Domains[i].Verified = false
			updated = true
		}
	}
	if !updated {
		app.Domains = append(app.Domains, hostedDomain{Name: name, Kind: "custom", Method: method, Token: token, Added: now})
	}
	app.Updated = now
	if err := h.apps.saveLocked(); err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	h.auditApp(r, act.pr, "app.domain.add", id+" "+name)
	writeJSON(w, http.StatusCreated, map[string]any{"domain": domainView(hostedDomain{Name: name, Kind: "custom", Method: method, Token: token, Added: now}, app.defaultDomain(), h.apps.publicIP)})
}

func (h *Host) hostedVerifyDomain(w http.ResponseWriter, r *http.Request, id, name string) {
	act, ok := h.appActor(w, r, true)
	if !ok {
		return
	}
	name = strings.ToLower(name)
	h.apps.mu.Lock()
	app := h.apps.apps[id]
	if !act.sees(app) {
		h.apps.mu.Unlock()
		writeErr(w, http.StatusNotFound, "app not found")
		return
	}
	var dom *hostedDomain
	for i := range app.Domains {
		if app.Domains[i].Name == name && app.Domains[i].Kind == "custom" {
			dom = &app.Domains[i]
			break
		}
	}
	if dom == nil {
		h.apps.mu.Unlock()
		writeErr(w, http.StatusNotFound, "domain not found")
		return
	}
	token, method, expect := dom.Token, dom.Method, app.defaultDomain()
	h.apps.mu.Unlock()
	okVerify, err := h.checkDomain(name, method, token, expect)
	if err != nil || !okVerify {
		writeErr(w, 400, "domain verification failed")
		return
	}
	h.apps.mu.Lock()
	defer h.apps.mu.Unlock()
	app = h.apps.apps[id]
	if !act.sees(app) {
		writeErr(w, http.StatusNotFound, "app not found")
		return
	}
	for i := range app.Domains {
		if app.Domains[i].Name == name {
			app.Domains[i].Verified = true
			app.Domains[i].VerifiedAt = time.Now().UTC()
			dom = &app.Domains[i]
		}
	}
	app.Updated = time.Now().UTC()
	if err := h.apps.saveLocked(); err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	h.auditApp(r, act.pr, "app.domain.verify", id+" "+name)
	writeJSON(w, 200, map[string]any{"domain": domainView(*dom, app.defaultDomain(), h.apps.publicIP), "verified": true})
}

func (h *Host) checkDomain(name, method, token, expectCNAME string) (bool, error) {
	if method == "cname" {
		got, err := h.apps.lookupCNAME(name)
		if err != nil {
			return false, err
		}
		got = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(got)), ".")
		return got != "" && got == strings.ToLower(expectCNAME), nil
	}
	if method == "http" {
		raw := "http://" + name + "/.well-known/redx-challenge/" + token
		code, body, err := h.apps.fetchHTTP(raw)
		if err != nil || code != 200 {
			return false, err
		}
		return secretEqual(strings.TrimSpace(body), token), nil
	}
	recs, err := h.apps.lookupTXT("_redx-challenge." + name)
	if err != nil {
		return false, err
	}
	for _, rec := range recs {
		if secretEqual(strings.Trim(strings.TrimSpace(rec), `"`), token) {
			return true, nil
		}
	}
	return false, nil
}

func (s *appStore) lookupTXT(name string) ([]string, error) {
	if s.txt != nil {
		return s.txt(name)
	}
	return net.LookupTXT(name)
}

func (s *appStore) lookupCNAME(name string) (string, error) {
	if s.cname != nil {
		return s.cname(name)
	}
	return net.LookupCNAME(name)
}

func (s *appStore) fetchHTTP(raw string) (int, string, error) {
	if s.httpGet != nil {
		return s.httpGet(raw)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return 0, "", errors.New("bad url")
	}
	host := u.Hostname()
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return 0, "", err
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return 0, "", errors.New("refusing a private address")
		}
	}
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return 0, "", err
	}
	cli := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cli.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, string(b), nil
}

func (h *Host) hostedDelDomain(w http.ResponseWriter, r *http.Request, id, name string) {
	act, ok := h.appActor(w, r, true)
	if !ok {
		return
	}
	name = strings.ToLower(name)
	h.apps.mu.Lock()
	defer h.apps.mu.Unlock()
	app := h.apps.apps[id]
	if !act.sees(app) {
		writeErr(w, http.StatusNotFound, "app not found")
		return
	}
	found := false
	for _, d := range app.Domains {
		if d.Name == name && d.Kind == "custom" {
			found = true
		}
	}
	if !found {
		writeErr(w, http.StatusNotFound, "domain not found")
		return
	}
	app.Domains = dropDomain(app.Domains, name)
	app.Updated = time.Now().UTC()
	if err := h.apps.saveLocked(); err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	h.auditApp(r, act.pr, "app.domain.delete", id+" "+name)
	writeJSON(w, 200, map[string]any{"ok": true})
}
