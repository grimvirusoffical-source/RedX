package host

// Optional first-party HTTP authentication. The custom engine, BoxQL, key ACLs,
// tenant ownership and billing gates are unchanged. This mode is suitable only
// on the same origin as the existing Red-XAI website account service.
import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"
)

const websiteCookie = "redx_session"

type websiteSessionAdapter struct {
	authority, origin string
	client            *http.Client
	ownerIDs          map[string]bool
	now               func() time.Time
	watchInterval     time.Duration
	realms            bool
}

func websiteSessionFromEnv() *websiteSessionAdapter {
	if os.Getenv("REDX_WEBSITE_SESSION") != "true" {
		return nil
	}
	owners := map[string]bool{}
	for _, id := range strings.Split(os.Getenv("REDX_WEBSITE_OWNER_ACCOUNT_IDS"), ",") {
		if id = strings.TrimSpace(id); id != "" {
			owners[id] = true
		}
	}
	if os.Getenv("REDX_WEBSITE_SESSION_REALMS") != "" {
		panic("realm consumer prototype is not approved for runtime activation; persistent ownership namespace proof is pending")
	}
	return &websiteSessionAdapter{
		authority: "http://127.0.0.1:4200/api/accounts/me", origin: "https://red-xai.com",
		client:   &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		ownerIDs: owners, now: time.Now, watchInterval: 15 * time.Second,
	}
}

type websiteProfile struct {
	Account struct {
		ID                string   `json:"id"`
		Email             string   `json:"email"`
		Username          string   `json:"username"`
		Roles             []string `json:"roles"`
		Active            *bool    `json:"active"`
		Disabled          bool     `json:"disabled"`
		Banned            bool     `json:"banned"`
		Deleted           bool     `json:"deleted"`
		Status            string   `json:"status"`
		State             string   `json:"state"`
		EmailVerified     *bool    `json:"emailVerified"`
		EmailVerifiedOIDC *bool    `json:"email_verified"`
	} `json:"account"`
	AMR           []string              `json:"amr"`
	ExpiresMs     int64                 `json:"expiresMs"`
	Active        *bool                 `json:"active"`
	IdentityRealm *websiteRealmEnvelope `json:"identityRealm"`
}

func websiteSessionCookie(r *http.Request) (*http.Cookie, bool) {
	var selected *http.Cookie
	for _, c := range r.Cookies() {
		if c.Name != websiteCookie {
			continue
		}
		if selected != nil || len(c.Value) == 0 || len(c.Value) > 8192 {
			return nil, false
		}
		selected = c
	}
	return selected, selected != nil
}

func (s *websiteSessionAdapter) identity(r *http.Request) (*AccountIdentity, bool) {
	cookies, ok := s.cookieHeader(r)
	if !ok {
		return nil, false
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, s.authority, nil)
	if err != nil {
		return nil, false
	}
	// Only the existing opaque account cookie crosses the loopback boundary.
	// Never forward caller Authorization, identity headers or unrelated cookies.
	req.Header.Set("Cookie", cookies)
	req.Header.Set("Accept", "application/json")
	response, err := s.client.Do(req)
	if err != nil {
		return nil, false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 32769))
	if err != nil || len(data) > 32768 {
		return nil, false
	}
	var p websiteProfile
	if json.Unmarshal(data, &p) != nil {
		return nil, false
	}
	legacyRealm := true
	if s.realms {
		var valid bool
		legacyRealm, valid = websiteRealmProfile(p)
		if !valid {
			return nil, false
		}
	} else if p.IdentityRealm != nil {
		return nil, false
	}
	a := p.Account
	badID := a.ID == "" || len(a.ID) > 256 || strings.IndexFunc(a.ID, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }) >= 0
	negative := func(v *bool) bool { return v != nil && !*v }
	active := func(v string) bool { return v == "" || v == "active" || v == "activated" }
	if badID || len(a.Email) > 254 || !strings.Contains(a.Email, "@") || len(p.AMR) == 0 || p.ExpiresMs <= s.now().UnixMilli() ||
		negative(p.Active) || negative(a.Active) || a.Disabled || a.Banned || a.Deleted || !active(a.Status) || !active(a.State) ||
		negative(a.EmailVerified) || negative(a.EmailVerifiedOIDC) {
		return nil, false
	}
	id := &AccountIdentity{Sub: a.ID, Username: a.Username, Email: a.Email, AMR: p.AMR}
	// Omitted verification metadata stays unknown/false. It is never fabricated.
	id.EmailVerified = (a.EmailVerified != nil && *a.EmailVerified) || (a.EmailVerifiedOIDC != nil && *a.EmailVerifiedOIDC)
	mfa := false
	for _, method := range p.AMR {
		switch method {
		case "otp", "totp", "sms", "call", "mfa", "webauthn":
			mfa = true
		}
	}
	// This opt-in website owner policy binds an immutable account ID to the
	// authoritative owner role and MFA. Email is display/audit metadata, not the
	// owner lookup key. The existing OIDC verified-email policy is unchanged.
	id.Owner = legacyRealm && s.ownerIDs[id.Sub] && containsStr(a.Roles, "owner") && mfa
	if !id.Owner && (id.Sub == "owner" || id.Sub == "__unassigned__") {
		return nil, false
	}
	return id, true
}

func (h *Host) resolveWebsiteAccount(r *http.Request) (*Principal, bool) {
	if h.website == nil {
		return nil, false
	}
	id, ok := h.website.identity(r)
	if !ok {
		return nil, false
	}
	rec := KeyRecord{ID: "acct:" + id.Sub, Label: firstNonEmpty(id.Username, id.Email, id.Sub), Kind: "account", Scope: "none", DB: "-"}
	if id.Owner {
		rec.Scope, rec.DB = ScopeAdmin, AllDBs
	}
	return &Principal{Key: rec, Account: id}, true
}

// Cookie authentication needs CSRF checks even when older API routes were
// written for explicit Bearer credentials. Existing API-key clients keep their
// normal native authorization path and are not converted to account identities.
func (h *Host) websiteBoundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.website == nil || bearer(r) != "" {
			next.ServeHTTP(w, r)
			return
		}
		_, cookie := h.website.cookieHeader(r)
		ws := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
		if cookie && (ws || (r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS")) && r.Header.Get("Origin") != h.website.origin {
			writeErr(w, http.StatusForbidden, "same-origin website request required")
			return
		}
		if cookie {
			w.Header().Set("Cache-Control", "no-store")
		}
		if !cookie || !ws {
			next.ServeHTTP(w, r)
			return
		}
		identity, ok := h.website.identity(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		r = r.WithContext(ctx)
		go func() {
			ticker := time.NewTicker(h.website.watchInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					current, ok := h.website.identity(r)
					if !ok || current.Sub != identity.Sub || current.Owner != identity.Owner {
						cancel()
						return
					}
				}
			}
		}()
		next.ServeHTTP(w, r)
	})
}
