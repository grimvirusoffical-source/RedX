package host

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func generatedAuditKey(t *testing.T, spec CreateSpec) (*Keystore, string, KeyRecord) {
	t.Helper()
	ks, err := OpenKeystore(filepath.Join(t.TempDir(), "keys.red-xai-keys"), KeystoreOptions{ArgonMem: 64, ArgonTime: 1})
	if err != nil {
		t.Fatal(err)
	}
	key, rec, err := ks.Create(spec)
	if err != nil {
		t.Fatal(err)
	}
	return ks, key, rec
}

func globalAuditClasses() []CreateSpec {
	var specs []CreateSpec
	for _, scope := range []string{ScopeRead, ScopeWrite, ScopeAdmin} {
		for _, prefix := range []string{"", "private.red-xai.db:Box"} {
			for _, owner := range []string{"", "synthetic-owner-metadata"} {
				specs = append(specs, CreateSpec{DB: AllDBs, Scope: scope, Prefix: prefix, Owner: owner, Label: "synthetic-human-label"})
			}
		}
	}
	return specs
}

func globalAuditRequest(key string) *http.Request {
	r := httptest.NewRequest(http.MethodPut, "/v1/db/fixture/path/private.red-xai.db:Box.Secret?token=synthetic-query-secret", strings.NewReader("synthetic-body-secret"))
	r.Header.Set("Authorization", "Bearer "+key)
	return r
}

func TestWebsiteGlobalKeyAuditAllScopesPrefixesAndOwnerMetadata(t *testing.T) {
	for i, spec := range globalAuditClasses() {
		ks, key, rec := generatedAuditKey(t, spec)
		path := filepath.Join(t.TempDir(), "audit.log")
		au, err := NewAuditor(path)
		if err != nil {
			t.Fatal(err)
		}
		auth := NewAuthenticator(ks, au, 1000, 1000, i%2 == 0)
		auth.websiteMode = func() bool { return true }
		pr, wait, err := auth.Authenticate(globalAuditRequest(key))
		if err != nil || wait != 0 || pr == nil || pr.Key.ID != rec.ID || pr.Account != nil {
			t.Fatalf("global class %d failed verified-key authentication", i)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var ev AuditEvent
		if json.Unmarshal(data, &ev) != nil || ev.Event != "global_key.access_attempt" || ev.KeyID != rec.ID || ev.Actor != "" || ev.Time.IsZero() || ev.Method != http.MethodPut || ev.Target != "db:fixture path" || ev.Route != "/v1/db/…" {
			t.Fatalf("global class %d lacks one complete, normalized key-only attempt", i)
		}
		for _, secret := range []string{key, rec.Hash, rec.Salt, "synthetic-body-secret", "synthetic-query-secret", "private.red-xai.db:Box.Secret", spec.Label, "synthetic-owner-metadata"} {
			if strings.Contains(string(data), secret) {
				t.Fatalf("global class %d leaked secret/data or invented human attribution", i)
			}
		}
		_ = au.Close()
		// Every class, including prefix/owner-labelled read-only keys, must
		// fail closed even when ordinary successful-auth auditing is off.
		if pr, wait, err = auth.Authenticate(globalAuditRequest(key)); !errors.Is(err, ErrAuditUnavailable) || pr != nil || wait != 0 {
			t.Fatalf("global class %d bypassed unavailable required audit", i)
		}
	}
}

func TestWebsiteGlobalKeyAuditNormalizesLegacyTarget(t *testing.T) {
	ks, key, _ := generatedAuditKey(t, CreateSpec{DB: AllDBs, Scope: ScopeRead})
	path := filepath.Join(t.TempDir(), "audit.log")
	au, err := NewAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	defer au.Close()
	auth := NewAuthenticator(ks, au, 1000, 1000, false)
	auth.websiteMode = func() bool { return true }
	r := httptest.NewRequest(http.MethodGet, "/v1/path/private.red-xai.db:Secret.Value?access_token=synthetic-query-secret", nil)
	r.Header.Set("Authorization", "Bearer "+key)
	if _, _, err := auth.Authenticate(r); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	var ev AuditEvent
	if err != nil || json.Unmarshal(data, &ev) != nil || ev.Target != "/v1/path/…" || ev.Route != "/v1/path/…" || ev.Method != http.MethodGet || strings.Contains(string(data), "private.red-xai.db") || strings.Contains(string(data), "synthetic-query-secret") {
		t.Fatal("legacy target leaked record path/query instead of normalized route")
	}
}

func TestWebsiteGlobalKeyAuditFailureDoesNotCountAsBadLogin(t *testing.T) {
	ks, key, _ := generatedAuditKey(t, CreateSpec{DB: AllDBs, Scope: ScopeAdmin})
	for _, tc := range []struct {
		name string
		sink *Auditor
	}{
		{"nil", nil}, {"disabled", &Auditor{}},
		{"short", &Auditor{f: failingAuditSink{short: true}, maxSize: 1 << 20}},
		{"write", &Auditor{f: failingAuditSink{writeErr: errors.New("synthetic write failure")}, maxSize: 1 << 20}},
		{"sync", &Auditor{f: failingAuditSink{syncErr: errors.New("synthetic sync failure")}, maxSize: 1 << 20}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := NewAuthenticator(ks, tc.sink, 1000, 1000, false)
			auth.websiteMode = func() bool { return true }
			r := globalAuditRequest(key)
			for i := 0; i < 25; i++ {
				pr, wait, err := auth.Authenticate(r)
				if !errors.Is(err, ErrAuditUnavailable) || pr != nil || wait != 0 {
					t.Fatal("audit failure granted a principal or became a bad-login throttle")
				}
			}
			if len(auth.fails.m) != 0 {
				t.Fatal("required audit failure incremented bad-login state")
			}
		})
	}
}

func TestWebsiteGlobalKeyAuditLeavesConcreteDatabaseAndStandaloneKeysUnchanged(t *testing.T) {
	for _, spec := range []CreateSpec{
		{DB: "owned-project", Scope: ScopeAdmin, Owner: "synthetic-owner"},
		{DB: "owned-project", Scope: ScopeRead, Prefix: "shared.red-xai.db:Box", Owner: "synthetic-owner"},
		{DB: "accounts-master", Scope: ScopeAdmin},
	} {
		ks, key, rec := generatedAuditKey(t, spec)
		auth := NewAuthenticator(ks, nil, 1000, 1000, false)
		auth.websiteMode = func() bool { return true }
		pr, _, err := auth.Authenticate(globalAuditRequest(key))
		if err != nil || pr == nil || pr.Key.ID != rec.ID || pr.Account != nil {
			t.Fatal("concrete project/service key incorrectly required global auditing")
		}
	}
	ks, key, _ := generatedAuditKey(t, CreateSpec{DB: AllDBs, Scope: ScopeAdmin})
	auth := NewAuthenticator(ks, nil, 1000, 1000, false)
	// Host wires this resolver even in standalone mode; it is not a mode flag.
	auth.website = func(*http.Request) (*Principal, bool) { return nil, false }
	if pr, _, err := auth.Authenticate(globalAuditRequest(key)); err != nil || pr == nil {
		t.Fatal("always-wired resolver incorrectly enabled required global audit")
	}
	enabled := false
	auth.websiteMode = func() bool { return enabled }
	for _, active := range []bool{false, true, false} {
		enabled = active
		pr, _, err := auth.Authenticate(globalAuditRequest(key))
		if active {
			if !errors.Is(err, ErrAuditUnavailable) || pr != nil {
				t.Fatal("active adapter bypassed global audit")
			}
		} else if err != nil || pr == nil {
			t.Fatal("inactive adapter changed standalone key behavior")
		}
	}
}
