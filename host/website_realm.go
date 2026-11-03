package host

// HTTP/RBAC integration prototype only. No engine, BoxQL, on-disk record or
// native API-key/OIDC client format is changed. Activation is separately blocked
// until persistent namespace enforcement or issuer-aware ownership is proved.
import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

const websiteLegacyIssuer = "urn:redxai:legacy-site"
const websiteFreshIssuer = "urn:redxai:fresh-normal-prototype:v1"
const websiteFreshPrefix = "rxf1_"
const websiteFreshCookie = "redx_fresh_normal_prototype_session"
const websiteRealmAuthority = "http://127.0.0.1:14330/__prototype/identity"

type websiteRealmEnvelope struct {
	Version     int    `json:"version"`
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	CanonicalID string `json:"canonicalId"`
}

func websiteCanonicalSubject(issuer, subject string) (string, bool) {
	if (issuer != websiteLegacyIssuer && issuer != websiteFreshIssuer) || subject == "" || len(subject) > 200 || !utf8.ValidString(subject) ||
		strings.IndexFunc(subject, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", false
	}
	if issuer == websiteLegacyIssuer {
		if strings.HasPrefix(subject, websiteFreshPrefix) {
			return "", false
		}
		return subject, true
	}
	sum := sha256.Sum256([]byte(issuer + "\x00" + subject))
	return websiteFreshPrefix + hex.EncodeToString(sum[:]), true
}

func websiteRealmProfile(p websiteProfile) (legacy, ok bool) {
	r := p.IdentityRealm
	if r == nil || r.Version != 1 {
		return false, false
	}
	for _, method := range p.AMR {
		if method == "" || len(method) > 40 {
			return false, false
		}
	}
	canonical, ok := websiteCanonicalSubject(r.Issuer, r.Subject)
	if !ok || canonical != r.CanonicalID || canonical != p.Account.ID {
		return false, false
	}
	legacy = r.Issuer == websiteLegacyIssuer
	if !legacy && (p.Active == nil || !*p.Active || p.Account.Active == nil || !*p.Account.Active ||
		p.Account.EmailVerified == nil || !*p.Account.EmailVerified || len(p.Account.Roles) != 1 || p.Account.Roles[0] != "user") {
		return false, false
	}
	return legacy, true
}

func (s *websiteSessionAdapter) cookieHeader(r *http.Request) (string, bool) {
	if !s.realms {
		c, ok := websiteSessionCookie(r)
		if !ok {
			return "", false
		}
		return c.String(), true
	}
	var values []string
	for _, name := range []string{websiteCookie, websiteFreshCookie} {
		var found *http.Cookie
		for _, c := range r.Cookies() {
			if c.Name != name {
				continue
			}
			if found != nil || len(c.Value) == 0 || len(c.Value) > 8192 || strings.IndexFunc(c.Value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
				return "", false
			}
			found = c
		}
		if found != nil {
			values = append(values, found.String())
		}
	}
	// Both cookies go to the fixed resolver and must be denied there as 409.
	// No caller header selects a realm and no failed resolver falls back.
	return strings.Join(values, "; "), len(values) > 0
}
