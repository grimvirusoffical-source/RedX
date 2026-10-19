package host

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// oidcClient is the Red-XAI Accounts OIDC relying party: discovery, JWKS (ES256), the code exchange with
// PKCE and ID token verification. It also carries the plain JSON calls the sign-up page needs.
type oidcClient struct {
	issuer, clientID, secret string
	hc                       *http.Client
	now                      func() time.Time

	mu     sync.Mutex
	disc   *oidcDiscovery
	discAt time.Time
	keys   map[string]*ecdsa.PublicKey
	keysAt time.Time
}

type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

func newOIDCClient(cfg Config) *oidcClient {
	return &oidcClient{issuer: cfg.AccountsIssuer, clientID: cfg.AccountsClientID, secret: cfg.AccountsClientSecret,
		hc:  &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		now: time.Now}
}

var errAccountsUnavailable = errors.New("Red-XAI Accounts cannot be reached right now; try again in a minute")

func (c *oidcClient) getJSON(ctx context.Context, u string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	res, err := c.hc.Do(req)
	if err != nil {
		return errAccountsUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("%w (GET %s: %d)", errAccountsUnavailable, u, res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(out)
}

// discovery fetches and caches /.well-known/openid-configuration (1 hour). The document's issuer must be
// exactly the configured issuer and every endpoint must pass the same https rule as the issuer.
func (c *oidcClient) discovery(ctx context.Context) (*oidcDiscovery, error) {
	c.mu.Lock()
	if c.disc != nil && c.now().Sub(c.discAt) < time.Hour {
		d := c.disc
		c.mu.Unlock()
		return d, nil
	}
	c.mu.Unlock()
	var d oidcDiscovery
	if err := c.getJSON(ctx, c.issuer+"/.well-known/openid-configuration", &d); err != nil {
		return nil, err
	}
	if strings.TrimRight(d.Issuer, "/") != c.issuer {
		return nil, fmt.Errorf("Red-XAI Accounts discovery names issuer %q, expected %q", d.Issuer, c.issuer)
	}
	for _, e := range []string{d.AuthorizationEndpoint, d.TokenEndpoint, d.JWKSURI} {
		if e == "" || checkIssuerURL(e) != nil {
			return nil, fmt.Errorf("Red-XAI Accounts discovery has an unusable endpoint %q", e)
		}
	}
	if d.UserinfoEndpoint != "" && checkIssuerURL(d.UserinfoEndpoint) != nil {
		d.UserinfoEndpoint = ""
	}
	c.mu.Lock()
	c.disc, c.discAt = &d, c.now()
	c.mu.Unlock()
	return &d, nil
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

func parseECJWK(k jwk) (*ecdsa.PublicKey, error) {
	if k.Kty != "EC" || k.Crv != "P-256" || (k.Alg != "" && k.Alg != "ES256") || (k.Use != "" && k.Use != "sig") {
		return nil, errors.New("not an ES256 signing key")
	}
	x, err1 := base64.RawURLEncoding.DecodeString(k.X)
	y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
	if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
		return nil, errors.New("bad EC coordinates")
	}
	raw := append(append([]byte{4}, x...), y...)
	if _, err := ecdh.P256().NewPublicKey(raw); err != nil { // rejects points that are not on the curve
		return nil, err
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
}

// key returns the ES256 key for kid, refreshing the JWKS when the kid is unknown (at most every 30 s).
func (c *oidcClient) key(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	c.mu.Lock()
	k := c.keys[kid]
	fresh := c.now().Sub(c.keysAt) < 30*time.Second
	c.mu.Unlock()
	if k != nil {
		return k, nil
	}
	if fresh {
		return nil, errors.New("ID token signed with an unknown key")
	}
	d, err := c.discovery(ctx)
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := c.getJSON(ctx, d.JWKSURI, &set); err != nil {
		return nil, err
	}
	m := map[string]*ecdsa.PublicKey{}
	for _, j := range set.Keys {
		if pk, err := parseECJWK(j); err == nil {
			m[j.Kid] = pk
		}
	}
	c.mu.Lock()
	c.keys, c.keysAt = m, c.now()
	c.mu.Unlock()
	if k = m[kid]; k == nil {
		return nil, errors.New("ID token signed with an unknown key")
	}
	return k, nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	IDToken     string `json:"id_token"`
	Refresh     string `json:"refresh_token"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// ClientIPHeader carries the end user's IP on every sign-up and sign-in call RedX forwards to Red-XAI Accounts.
const ClientIPHeader = "X-RedXAI-Client-IP"

// exchange trades the authorization code (with the PKCE verifier) for tokens.
func (c *oidcClient) exchange(ctx context.Context, code, redirect, verifier, clientIP string) (*tokenResponse, error) {
	f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "client_id": {c.clientID}, "code_verifier": {verifier}}
	t, err := c.tokenCall(ctx, f, clientIP)
	if err == nil && t.IDToken == "" {
		return nil, errors.New("the sign-in could not be completed (no ID token)")
	}
	return t, err
}

// refresh rotates a refresh token (confidential client).
func (c *oidcClient) refresh(ctx context.Context, refreshToken, clientIP string) (*tokenResponse, error) {
	return c.tokenCall(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {c.clientID}}, clientIP)
}

func (c *oidcClient) tokenCall(ctx context.Context, f url.Values, clientIP string) (*tokenResponse, error) {
	d, err := c.discovery(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", d.TokenEndpoint, strings.NewReader(f.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	c.clientAuth(req)
	if clientIP != "" {
		req.Header.Set(ClientIPHeader, clientIP)
	}
	res, err := c.hc.Do(req)
	if err != nil {
		return nil, errAccountsUnavailable
	}
	defer res.Body.Close()
	var t tokenResponse
	_ = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&t)
	if res.StatusCode != 200 || t.AccessToken == "" {
		if t.Error == "" {
			t.Error = fmt.Sprintf("status %d", res.StatusCode)
		}
		return nil, fmt.Errorf("the sign-in could not be completed (%s)", t.Error)
	}
	if !strings.EqualFold(t.TokenType, "bearer") {
		return nil, errors.New("the sign-in could not be completed (unexpected token type)")
	}
	return &t, nil
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*a = []string{s}
		return nil
	}
	var l []string
	if err := json.Unmarshal(b, &l); err != nil {
		return err
	}
	*a = l
	return nil
}

type idClaims struct {
	Iss               string   `json:"iss"`
	Sub               string   `json:"sub"`
	Aud               audience `json:"aud"`
	Azp               string   `json:"azp"`
	Exp               float64  `json:"exp"`
	Iat               float64  `json:"iat"`
	Nbf               float64  `json:"nbf"`
	Nonce             string   `json:"nonce"`
	AMR               []string `json:"amr"`
	Email             string   `json:"email"`
	EmailVerified     *bool    `json:"email_verified"`
	PreferredUsername string   `json:"preferred_username"`
	AgeBand           string   `json:"age_band"`
}

// verifyIDToken checks an ES256 ID token: signature, issuer, audience, expiry and nonce.
func (c *oidcClient) verifyIDToken(ctx context.Context, raw, nonce string) (*idClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed ID token")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &hdr) != nil {
		return nil, errors.New("malformed ID token header")
	}
	if hdr.Alg != "ES256" {
		return nil, fmt.Errorf("ID token algorithm %q is not allowed (ES256 only)", hdr.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, errors.New("malformed ID token signature")
	}
	pk, err := c.key(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pk, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, errors.New("ID token signature is not valid")
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed ID token claims")
	}
	var cl idClaims
	if err := json.Unmarshal(cb, &cl); err != nil {
		return nil, errors.New("malformed ID token claims")
	}
	now := float64(c.now().Unix())
	const skew = 60
	switch {
	case strings.TrimRight(cl.Iss, "/") != c.issuer:
		return nil, errors.New("ID token from the wrong issuer")
	case !containsStr(cl.Aud, c.clientID):
		return nil, errors.New("ID token is not for this RedX host")
	case len(cl.Aud) > 1 && cl.Azp != c.clientID:
		return nil, errors.New("ID token authorized party mismatch")
	case cl.Exp == 0 || now > cl.Exp+skew:
		return nil, errors.New("ID token expired")
	case cl.Nbf != 0 && now+skew < cl.Nbf:
		return nil, errors.New("ID token not valid yet")
	case cl.Iat != 0 && cl.Iat > now+skew:
		return nil, errors.New("ID token issued in the future")
	case nonce == "" || cl.Nonce != nonce:
		return nil, errors.New("ID token nonce mismatch")
	case cl.Sub == "":
		return nil, errors.New("ID token has no subject")
	}
	return &cl, nil
}

func containsStr(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

// userinfo fills email/username claims missing from the ID token (Bearer access token).
func (c *oidcClient) userinfo(ctx context.Context, access string) (map[string]interface{}, error) {
	d, err := c.discovery(ctx)
	if err != nil || d.UserinfoEndpoint == "" {
		return nil, errors.New("no userinfo endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", d.UserinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Accept", "application/json")
	res, err := c.hc.Do(req)
	if err != nil {
		return nil, errAccountsUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("userinfo: status %d", res.StatusCode)
	}
	var m map[string]interface{}
	return m, json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&m)
}

// call makes a JSON request to the Red-XAI Accounts API (path relative to the issuer), with the end user's IP
// in X-RedXAI-Client-IP. It returns the status and raw JSON body; errAccountsUnavailable when unreachable.
func (c *oidcClient) call(ctx context.Context, method, path string, body interface{}, bearer, clientIP string) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.issuer+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if clientIP != "" {
		req.Header.Set(ClientIPHeader, clientIP)
	}
	res, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, errAccountsUnavailable
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return res.StatusCode, b, nil
}

// clientAuth adds HTTP Basic client authentication (RFC 6749 2.3.1: both parts form-encoded).
func (c *oidcClient) clientAuth(req *http.Request) {
	if c.secret != "" {
		req.SetBasicAuth(url.QueryEscape(c.clientID), url.QueryEscape(c.secret))
	}
}

// backChannel makes an app back-channel call (HTTP Basic client authentication) and returns status and body.
func (c *oidcClient) backChannel(ctx context.Context, method, path string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.issuer+path, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	c.clientAuth(req)
	res, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, errAccountsUnavailable
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	return res.StatusCode, b, nil
}

func pkceChallenge(verifier string) string {
	s := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(s[:])
}
