package host

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func signES256(t *testing.T, k *ecdsa.PrivateKey, hdr, claims map[string]interface{}) string {
	t.Helper()
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	in := b64u(hb) + "." + b64u(cb)
	sum := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, k, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return in + "." + b64u(sig)
}

func TestVerifyIDToken(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var iss string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": iss, "authorization_endpoint": iss + "/a", "token_endpoint": iss + "/t", "jwks_uri": iss + "/k"})
	})
	mux.HandleFunc("/k", func(w http.ResponseWriter, r *http.Request) {
		x, y := make([]byte, 32), make([]byte, 32)
		key.X.FillBytes(x)
		key.Y.FillBytes(y)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []map[string]string{
			{"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "x": b64u(x), "y": b64u(y)},
			{"kty": "EC", "crv": "P-256", "kid": "bad", "x": b64u(make([]byte, 32)), "y": b64u(make([]byte, 32))}, // not on the curve
		}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	iss = srv.URL
	c := newOIDCClient(Config{AccountsIssuer: iss, AccountsClientID: "redx"})
	now := time.Now().Unix()
	good := func() map[string]interface{} {
		return map[string]interface{}{"iss": iss, "sub": "rxa_1", "aud": "redx", "exp": now + 600, "iat": now, "nonce": "n1", "amr": []string{"pwd", "otp"}}
	}
	hdr := map[string]interface{}{"alg": "ES256", "kid": "k1"}
	ctx := context.Background()
	cl, err := c.verifyIDToken(ctx, signES256(t, key, hdr, good()), "n1")
	if err != nil || cl.Sub != "rxa_1" {
		t.Fatalf("valid token: %v", err)
	}
	mod := func(k string, v interface{}) map[string]interface{} { m := good(); m[k] = v; return m }
	cases := map[string]string{
		"wrong issuer": signES256(t, key, hdr, mod("iss", "https://evil.example")),
		"wrong aud":    signES256(t, key, hdr, mod("aud", "other-app")),
		"multi aud":    signES256(t, key, hdr, mod("aud", []string{"redx", "other"})),
		"expired":      signES256(t, key, hdr, mod("exp", now-3600)),
		"future iat":   signES256(t, key, hdr, mod("iat", now+3600)),
		"nonce":        signES256(t, key, hdr, mod("nonce", "n2")),
		"no sub":       signES256(t, key, hdr, mod("sub", "")),
		"other key":    signES256(t, other, hdr, good()),
		"unknown kid":  signES256(t, key, map[string]interface{}{"alg": "ES256", "kid": "zz"}, good()),
		"off-curve":    signES256(t, key, map[string]interface{}{"alg": "ES256", "kid": "bad"}, good()),
		"alg none":     b64u([]byte(`{"alg":"none","kid":"k1"}`)) + "." + b64u([]byte(`{"iss":"`+iss+`"}`)) + ".",
		"alg HS256":    signES256(t, key, map[string]interface{}{"alg": "HS256", "kid": "k1"}, good()),
		"garbage":      "a.b",
	}
	for name, tok := range cases {
		if _, err := c.verifyIDToken(ctx, tok, "n1"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// tampered claims with the original signature
	parts := strings.Split(signES256(t, key, hdr, good()), ".")
	cb, _ := json.Marshal(mod("sub", "rxa_admin"))
	if _, err := c.verifyIDToken(ctx, parts[0]+"."+b64u(cb)+"."+parts[2], "n1"); err == nil {
		t.Error("tampered token accepted")
	}
}

func TestOwnerStatus(t *testing.T) {
	owners := []string{"owner@example.com", "support-owner@example.com"}
	for _, c := range []struct {
		id      AccountIdentity
		owner   bool
		blocked string
	}{
		{AccountIdentity{Email: "OWNER@example.com", EmailVerified: true, AMR: []string{"pwd", "otp"}, Scopes: []string{"owner"}}, true, ""},
		{AccountIdentity{Email: "support-owner@example.com", EmailVerified: true, AMR: []string{"sms"}, Scopes: []string{"openid", "owner"}}, true, ""},
		{AccountIdentity{Email: "owner@example.com", EmailVerified: true, AMR: []string{"pwd", "otp"}}, false, "owner_scope_missing"},
		{AccountIdentity{Email: "owner@example.com", EmailVerified: true, AMR: []string{"pwd"}}, false, "owner_2fa_required"},
		{AccountIdentity{Email: "owner@example.com", EmailVerified: true, AMR: []string{"mfa"}}, false, "owner_2fa_required"},
		{AccountIdentity{Email: "owner@example.com", EmailVerified: false, AMR: []string{"otp"}, Scopes: []string{"owner"}}, false, "owner_email_unverified"},
		{AccountIdentity{Email: "someone@example.com", EmailVerified: true, AMR: []string{"otp"}, Scopes: []string{"owner"}}, false, ""},
		{AccountIdentity{Email: "", EmailVerified: true, AMR: []string{"otp"}}, false, ""},
	} {
		id := c.id
		o, b := ownerStatus(&id, owners)
		if o != c.owner || b != c.blocked {
			t.Errorf("%+v: got %v %q", c.id, o, b)
		}
		if o2, _ := ownerStatus(&id, nil); o2 {
			t.Error("no configured owners means no owners")
		}
	}
}

func TestAccountStoreExpiry(t *testing.T) {
	s := newAccountStore()
	now := time.Now()
	s.now = func() time.Time { return now }
	tok, ho := s.newSession(AccountIdentity{Sub: "a"})
	if got, ok := s.redeemHandoff(ho); !ok || got != tok {
		t.Fatal("handoff")
	}
	if _, ok := s.redeemHandoff(ho); ok {
		t.Fatal("handoff reuse")
	}
	if _, ok := s.lookup(tok); !ok {
		t.Fatal("lookup")
	}
	now = now.Add(acctSessionIdle + time.Minute)
	if _, ok := s.lookup(tok); ok {
		t.Fatal("idle session must expire")
	}
	_, ho2 := s.newSession(AccountIdentity{Sub: "b"})
	now = now.Add(acctHandoffTTL + time.Second)
	if _, ok := s.redeemHandoff(ho2); ok {
		t.Fatal("handoff must expire")
	}
	for k := range s.sessions {
		if strings.HasPrefix(k, acctTokenPrefix) {
			t.Fatal("tokens must be stored hashed")
		}
	}
}

func TestSignupRules(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	ok := func(c []RuleCheck) bool { return firstFail(c) == "" }
	for u, want := range map[string]bool{"grim_player1": true, "abc12345": true, "ab123456": false, "short1a": false, "has space1": false,
		"emoji😀abcdefg": false, "a<b>cdefgh": false, strings.Repeat("a", 32): true, strings.Repeat("a", 33): false, "x.y-z_abc": true} {
		if ok(CheckUsername(u)) != want {
			t.Errorf("username %q: want %v", u, want)
		}
	}
	for p, want := range map[string]bool{"Abcdefgh123!": true, "abcdefgh123!": false, "ABCDEFGH123!": false, "Abcdefghijk!": false,
		"Abcdefgh1234": false, "Abc 1234567!": false, `Abcdefgh123"`: false, "Abcdefgh123<": false, "Abcdefgh123`": false,
		"Abcde1!": false, "Aa1!" + strings.Repeat("x", 661): true, "Aa1!" + strings.Repeat("x", 662): false} {
		if ok(CheckPassword(p)) != want {
			t.Errorf("password %q: want %v", p, want)
		}
	}
	for e, want := range map[string]bool{"a@b.com": true, "first.last+tag@sub.example.org": true, "a@b": false, "a b@c.com": false,
		"@c.com": false, "a@.com": false, "a..b@c.com": false, "": false, strings.Repeat("a", 250) + "@b.com": false} {
		if ok(CheckEmailSyntax(e)) != want {
			t.Errorf("email %q: want %v", e, want)
		}
	}
	for _, c := range []struct {
		dob  string
		code string
		age  int
	}{
		{"07/04/2001", "", 25},
		{"10/19/2013", "", 13},              // 13th birthday today
		{"10/20/2013", "under_min_age", 12}, // one day short
		{"01/01/2020", "under_min_age", 6},
		{"10/19/1926", "", 100},
		{"10/18/1925", "dob_range", 101},
		{"02/30/2001", "dob_invalid", -1},
		{"01/01/2030", "dob_invalid", -1},
		{"2001-07-04", "dob_format", -1},
		{"7/4/2001", "dob_format", -1},
		{"", "dob_required", -1},
	} {
		_, age, fe := CheckDOB(c.dob, now, 13)
		code := ""
		if fe != nil {
			code = fe.Code
		}
		if code != c.code || age != c.age {
			t.Errorf("dob %q: got %q age %d, want %q age %d", c.dob, code, age, c.code, c.age)
		}
	}
	if _, _, fe := CheckDOB("10/19/2010", now, 18); fe == nil || fe.Code != "under_min_age" {
		t.Error("an app minimum above 13 must apply")
	}
	if _, _, fe := CheckDOB("10/19/2014", now, 5); fe == nil || fe.Code != "under_min_age" {
		t.Error("the central minimum 13 can never be lowered")
	}
}
